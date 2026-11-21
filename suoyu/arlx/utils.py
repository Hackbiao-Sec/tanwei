"""通用工具集：域名解析、URL 归一化、CDN 判定、黑名单、指纹。

对应 ARL 的 app/utils/*，去掉对 massdns / phantomjs 等 Linux 二进制的依赖，
改用纯 Python 异步 DNS 与 requests/httpx。
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import ipaddress
import json
import re
from typing import Any
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse, urlunparse

import sys

import tldextract

from .config import ROOT


def _tld_kwargs() -> dict:
    """离线后缀快照位置。

    PyInstaller 把数据文件解到 sys._MEIPASS，tldextract 默认只在自己包目录找
    .tld_set_snapshot；不显式指过去，root_domain() 会在解压进程里直接抛
    SuffixListNotFound，整个任务在 P1 阶段异常退出。
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return {}
    snap = Path(base) / "tldextract" / ".tld_set_snapshot"
    return {"cache_dir": snap.parent} if snap.exists() else {}


# 不联网也能用的 tldextract（首次会用内置快照）
_tld = tldextract.TLDExtract(suffix_list_urls=(), **_tld_kwargs())

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=[a-z0-9\-]{1,63}\.)[a-z0-9\-]+(?:\.[a-z0-9\-]+)+$", re.I)

# 常见「文件名后缀」，避免 index.html / slide.js 被当成域名
FILE_SUFFIXES = {
    "html", "htm", "shtml", "xhtml", "php", "jsp", "asp", "aspx", "do", "action",
    "js", "mjs", "css", "map", "json", "xml", "txt", "png", "jpg", "jpeg", "gif",
    "svg", "ico", "webp", "woff", "woff2", "ttf", "otf", "pdf", "md", "yaml", "yml",
}

# tldextract 内置快照里的真实后缀；只认这份，能挡掉把文件名当 TLD 的情况
_KNOWN_SUFFIXES: frozenset[str] | None = None


def known_suffixes() -> frozenset[str]:
    global _KNOWN_SUFFIXES
    if _KNOWN_SUFFIXES is None:
        try:
            raw = _tld.tlds(include_private=False)
        except Exception:
            raw = ()
        _KNOWN_SUFFIXES = frozenset(str(s).lower() for s in raw)
    return _KNOWN_SUFFIXES


_ALL_SUFFIXES: frozenset[str] | None = None


def all_suffixes() -> frozenset[str]:
    """含私有段的后缀全集。

    用来识别「这个字符串本身就是一条后缀」：包里常见自带一份公共后缀库
    （如 chromium 的 PublicSuffixDatabase），整份当正文扫会吐上千条假域名。
    """
    global _ALL_SUFFIXES
    if _ALL_SUFFIXES is None:
        try:
            raw = _tld.tlds(include_private=True)
        except Exception:
            raw = ()
        _ALL_SUFFIXES = frozenset(str(s).lower() for s in raw)
    return _ALL_SUFFIXES


def is_suffix_only(domain: str) -> bool:
    """整串是否就是一条公共后缀（不是可挖的业务域名）。"""
    d = (domain or "").strip().strip(".").lower()
    return bool(d) and "." in d and d in all_suffixes()


def is_ip(text: str) -> bool:
    if not text:
        return False
    try:
        ipaddress.ip_address(text.strip())
        return True
    except ValueError:
        return False


def is_public_ip(text: str) -> bool:
    """地址是否值得当资产去探。

    子域解析偶尔会落到 `127.0.0.1`（内网占位）、`169.254.254.254`（CDN 离线占位）
    或 `10.x`（内网 DNS 泄漏）。这些进 IP 资产表后会被端口扫描和存活探测排队，
    白占扫不到的配额；真实情报价值是「这个子域指内网」，记在域名上就够。
    """
    try:
        ip = ipaddress.ip_address((text or "").strip())
    except ValueError:
        return False
    # `is_global` 对组播段会返回 True，所以几个特殊段单独挡一道
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    return bool(ip.is_global)


def is_ip_network(text: str) -> bool:
    try:
        ipaddress.ip_network(text.strip(), strict=False)
        return "/" in text.strip()
    except ValueError:
        return False


def ip_in_network(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    d = (domain or "").strip().strip(".").lower()
    return bool(DOMAIN_RE.match(d))


def idn_ascii(host: str) -> str:
    """中文域名转 punycode：``mi.中国`` → ``mi.xn--fiqs8s``。

    备案库会把「小米科技有限责任公司.中国」这种登记名原样给出，而 DNS、httpx、
    证书校验只认 ASCII 写法。不转就在候选池里被当成脏值丢掉 —— 这条备案确实存在，
    只是查不动。转不了的原样返回，合法性仍交给调用方判断。
    """
    h = (host or "").strip().strip(".").lower()
    if not h or h.isascii():
        return h
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return h


def clean_host(text: str) -> str:
    """把抓来的 host 收拾成纯主机名：去掉协议、端口、路径、查询串。

    采集源里常见的脏值：``www.a.com?from=xx``、``a.com?x=1&amp;y=2``、
    ``item.headimg``（JS 里没解析的变量）。这里只做清理，合法性交给调用方。
    """
    h = (text or "").strip().strip("\"'").lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    for sep in ("/", "?", "#", " ", "\t"):
        h = h.split(sep, 1)[0]
    if h.startswith("[") and "]" in h:
        return h[1:h.index("]")]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.strip(".")


def root_domain(domain: str) -> str:
    """取可注册根域；拿不准的脏值直接返回空串。

    原实现只让 tldextract 猜，``index.html``、``slide.js``、``item.headimg``、
    ``${url}`` 都会被当成一级域 + 后缀，最后在资产组里冒出一堆假根域。
    """
    d = clean_host(domain)
    if not d or len(d) > 253:
        return ""
    if is_ip(d):
        return ""
    if not re.fullmatch(r"[a-z0-9\-]+(?:\.[a-z0-9\-]+)+", d):
        return ""
    labels = d.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return ""
    # 后缀必须是纯字母，否则是文件名 / 变量 / 版本号之类
    if not labels[-1].isalpha():
        return ""
    # 「页面/脚本名.后缀」不是域名：index.html、slide.js、data.json 都会命中 tldextract
    if labels[-1] in FILE_SUFFIXES:
        return ""
    suffixes = known_suffixes()
    if suffixes and labels[-1] not in suffixes:
        return ""
    ext = _tld(d)
    if not ext.domain or not ext.suffix:
        return ""
    # tldextract 不认二级后缀 co.ltd（拆出 domain="co" / suffix="ltd"）：会把 co.ltd
    # 本身当可注册域，把 site.co.ltd 错并成 co.ltd。这里按"域名 + 后缀"重新对齐。
    return f"{ext.domain}.{ext.suffix}"



def subdomain_part(domain: str) -> str:
    return _tld(domain.lower()).subdomain


def same_site(domain: str, root: str) -> bool:
    d = domain.strip(".").lower()
    return d == root.lower() or d.endswith("." + root.lower())


def normalize_url(url: str, default_scheme: str = "") -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        if default_scheme:
            u = f"{default_scheme}://{u}"
        else:
            return ""
    try:
        p = urlparse(u)
        # `.port` 只在取值时才校验，坏端口（爬到的链接里出现过 :blank）会在这里抛
        # ValueError，只包 urlparse 拦不住，整个站点爬取会被这一条链接带崩。
        port = p.port
    except ValueError:
        return ""
    host = (p.hostname or "").lower()
    if not host:
        return ""
    # 采集源会把带查询串的主机原样塞进来，hostname 会保留 ?from=x 之后的部分
    host = clean_host(host)
    if not host:
        return ""
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    path = p.path or "/"
    return urlunparse((p.scheme.lower(), netloc, path, "", p.query, ""))


def host_of(url: str) -> str:
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def port_of(url: str) -> int | None:
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        if p.port:
            return p.port
        return {"http": 80, "https": 443}.get(p.scheme)
    except ValueError:
        return None


def url_key(url: str) -> str:
    """资产去重键：host:port/path?query（不含脆弱参数顺序差异）"""
    n = normalize_url(url)
    return n or url.strip()


def dns_reverse(ip: str, timeout: float = 2.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".").lower()
    except Exception:
        return ""


# ─────────────── 阻塞调用线程池 ───────────────
# 全项目唯一的阻塞线程池。以前各处都用 run_in_executor(None, …) 借默认池，
# 那个默认池每个进程只开 min(32, CPU+4) 条线程、而且共用；实测 11 月那轮瑞幸咖啡
# 任务里 socket.gethostbyname / 证书握手 / TCP 指纹 / 子进程验密 全是几十秒起步的
# 阻塞调用，一次性并发几百个，默认池被占满后连 credential、mobile 的解包线程也排不上，
# 服务整体像卡死（/api/status 都要等半分钟以上）。
# 这里单开两个池：
#   arlx-block  — 普通阻塞调用（DNS、证书、TCP 指纹、解包），并发高
#   arlx-slow   — 子进程类（验密脚本），每条要开一次 Python 解释器、吃满 CPU 几秒，
#                 全部塞普通池会把 DNS/证书挤到没线程，所以要单独封顶。
BLOCKING_THREADS = 96
SLOW_THREADS = 8
_BLOCKING_POOL: Any = None
_BLOCKING_LOCK = threading.Lock()


def blocking_pool() -> Any:
    """阻塞线程池单例；首次调用时创建。"""
    global _BLOCKING_POOL
    if _BLOCKING_POOL is None:
        with _BLOCKING_LOCK:
            if _BLOCKING_POOL is None:
                from concurrent.futures import ThreadPoolExecutor
                _BLOCKING_POOL = ThreadPoolExecutor(
                    max_workers=BLOCKING_THREADS, thread_name_prefix="arlx-block")
    return _BLOCKING_POOL


async def run_blocking(fn: Callable[..., Any], *args: Any, timeout: float | None = None) -> Any:
    """把阻塞函数丢进专用池并 await。

    超时只作用于「等结果」，被取消的那条线程仍会把手里的调用跑完；调用方要保证
    fn 自带超时（socket 超时、subprocess timeout），别让线程永久挂住。
    """
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(blocking_pool(), functools.partial(fn, *args))
    if timeout is None:
        return await fut
    return await asyncio.wait_for(fut, timeout=timeout)


_SLOW_POOL: Any = None


def slow_pool() -> Any:
    """子进程类阻塞调用专用池；首次调用时创建。"""
    global _SLOW_POOL
    if _SLOW_POOL is None:
        with _BLOCKING_LOCK:
            if _SLOW_POOL is None:
                from concurrent.futures import ThreadPoolExecutor
                _SLOW_POOL = ThreadPoolExecutor(
                    max_workers=SLOW_THREADS, thread_name_prefix="arlx-slow")
    return _SLOW_POOL


async def run_blocking_slow(fn: Callable[..., Any], *args: Any,
                            timeout: float | None = None) -> Any:
    """同上，但跑在子进程池里，别和 DNS/证书抢线程。"""
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(slow_pool(), functools.partial(fn, *args))
    if timeout is None:
        return await fut
    return await asyncio.wait_for(fut, timeout=timeout)


def resolve(domain: str, timeout: float = 3.0) -> list[str]:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(domain, None)
        ips = []
        for info in infos:
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
        return ips
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(old)


def resolve_reverse(ip: str) -> list[str]:
    """PTR → 多个域名（通过 PTR 的 CNAME 链意义不大，这里返回 PTR 本身）"""
    r = dns_reverse(ip)
    return [r] if r else []


# ───────────────────────── CDN / 黑名单 ─────────────────────────
class CdnDetector:
    """ARL dicts/cdn_info.json：cname_domain 后缀 + ip_cidr 网段双向判定"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (ROOT / "arlx" / "dicts" / "cdn_info.json")
        self.rules: list[dict] = []
        self._nets: list[tuple[Any, str]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        if not isinstance(data, list):
            return
        self.rules = data
        for item in data:
            name = item.get("name", "cdn")
            for cidr in item.get("ip_cidr", []) or []:
                try:
                    self._nets.append((ipaddress.ip_network(cidr, strict=False), name))
                except ValueError:
                    continue

    def detect_by_cname(self, cnames: Iterable[str]) -> str:
        for cname in cnames or []:
            c = (cname or "").lower().rstrip(".")
            for item in self.rules:
                for suffix in item.get("cname_domain", []) or []:
                    if c.endswith(suffix.lower()):
                        return item.get("name", "cdn")
        return ""

    def detect_by_ip(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        for net, name in self._nets:
            if addr in net:
                return name
        return ""

    def detect(self, cnames: Iterable[str] = (), ips: Iterable[str] = ()) -> str:
        hit = self.detect_by_cname(cnames)
        if hit:
            return hit
        for ip in ips or []:
            hit = self.detect_by_ip(ip)
            if hit:
                return hit
        return ""


class NameList:
    """文本清单（黑名单、和谐域名、资产黑名单）"""

    def __init__(self, path: Path | None = None) -> None:
        self.items: list[str] = []
        self.path = path
        if path and path.exists():
            self.items = [
                line.strip().lower()
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.startswith("#")
            ]

    def hit(self, text: str) -> str:
        t = (text or "").lower()
        for item in self.items:
            if t == item or t.endswith("." + item):
                return item
        return ""


# 和谐/备案黑名单（与 ARL 一致：这些后缀默认不纳入资产）
def load_blacklists() -> tuple[NameList, NameList, NameList]:
    base = ROOT / "arlx" / "dicts"
    return (
        NameList(base / "blackdomain.txt"),
        NameList(base / "blackhexie.txt"),
        NameList(base / "black_asset_site.txt"),
    )


# ───────────────────────── 指纹 ─────────────────────────
class FingerPrint:
    """ARL webapp.json 指纹（headers/html/title/favicon 关键字），纯本地匹配。"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (ROOT / "arlx" / "dicts" / "webapp.json")
        self.apps: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        if isinstance(data, dict):
            self.apps = {k: v for k, v in data.items() if isinstance(v, dict)}

    @staticmethod
    def _any(patterns, blob: str) -> str:
        for p in patterns or []:
            p = (p or "").strip().lower()
            if p and p in blob:
                return p
        return ""

    def match(self, headers: dict, body: str, title: str = "",
              favicon_hash: str = "") -> list[str]:
        header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
        # 键为响应头名时只比对头名（ARL 原始语义：headers 规则是 header 名列表）
        header_names = "|".join((k or "").lower() for k in (headers or {}))
        body_blob = (body or "")[:300000].lower()
        title_blob = (title or "").lower()
        # 部分 webapp.json 规则只给了 favicon hash（ARL 原字段 favicon 是 hash 列表）
        icon_blob = f" {str(favicon_hash or '').strip()} "
        hits: list[str] = []
        for name, rule in self.apps.items():
            head_rules = [h.lower() for h in (rule.get("headers") or []) if h]
            if any(h in header_names for h in head_rules):
                hits.append(name)
                continue
            if self._any(rule.get("html"), body_blob):
                hits.append(name)
                continue
            if title_blob and self._any(rule.get("title"), title_blob):
                hits.append(name)
                continue
            if icon_blob.strip() and any(str(x).strip() and f" {str(x).strip()} " in icon_blob
                                         for x in (rule.get("favicon") or [])):
                hits.append(name)
        return sorted(set(hits))

    def fofa_rule(self, name: str) -> str:
        return (self.apps.get(name) or {}).get("fofa_rule", "")


def mmh3_favicon(content: bytes) -> str:
    """FOFA icon_hash 同算法：mmh3.hash(每次取 256 字节 codec 转义后的 base64)"""
    import base64

    try:
        import mmh3

        buf = base64.encodebytes(content)
        parts = [mmh3.hash(buf[i:i + 256]) for i in range(0, len(buf), 256)]
        if not parts:
            return ""
        if len(parts) == 1:
            return str(parts[0])
        return str(sum(parts) % (2 ** 32))
    except Exception:
        return ""


def sha256_text(text: str | bytes) -> str:
    if isinstance(text, str):
        text = text.encode("utf-8", "ignore")
    return hashlib.sha256(text).hexdigest()


def now() -> float:
    return time.time()


def human_time(ts: float | None) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


# 端口服务字典（默认值，命中后可扩展）
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 512: "rexec", 513: "rlogin",
    514: "rshell", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 3000: "http", 3306: "mysql",
    3389: "rdp", 4440: "rundeck", 4848: "glassfish", 5000: "http", 5432: "postgres",
    5601: "kibana", 5672: "rabbitmq", 5900: "vnc", 6379: "redis", 7001: "weblogic",
    8000: "http", 8009: "ajp", 8080: "http", 8081: "http", 8088: "http", 8161: "activemq",
    8443: "https", 8888: "http", 9000: "http", 9090: "http", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 27017: "mongodb", 27018: "mongodb",
}


def service_of(port: int) -> str:
    return PORT_SERVICE.get(port, "")
