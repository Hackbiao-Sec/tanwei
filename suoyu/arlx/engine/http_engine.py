"""HTTP 探测引擎（httpx 异步版）。

能力：
  * 存活探测（状态码 / 标题 / 长度 / 跳转链 / 响应头 / 指纹 / favicon hash）
  * 证书采集（CN / 签发机构 / 有效期 / SAN / SHA256 / PEM）
  * 数据源抓取（JSON / 文本），支持代理与重试
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..config import config
from ..utils import CdnDetector, FingerPrint, host_of, mmh3_favicon, normalize_url, sha256_text

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# 盾页 / 反代错误页 / 本机抓包代理占位页：这三种页面「有响应」，但正文与站点本身无关。
# 电信 CT2-WAAP、云 WAF、Yakit、某云 502 都长这样，混进资产表就是脏数据。
_BLOCK_TITLE_RE = re.compile(
    r"nwaf|安全防护|访问拦截|网站防火墙|云防护|人机验证|正在验证|请稍候|"
    r"bad gateway|service (?:temporarily )?unavailable|gateway time|not allowed|"
    r"access denied|request blocked|yakit|mitmproxy|fiddler",
    re.I)
_BLOCK_BODY_RE = re.compile(
    r"网站安全防护|安全防护服务|潜在的?安全风险|已被?拦截|访问被拒绝|"
    r"<title>\s*Yakit\b|Yakit MITM|403\s*Forbidden\s*-\s*nginx",
    re.I)
_BLOCK_SERVER_RE = re.compile(r"waap|waf|yakit|safeline|cloudwaf|yunsuo", re.I)
# 反代 / 网关自己的默认错误页：标题只有一句「出错了」，没有业务内容。
# 这类页不构成站点，进资产表只会把 IP 直连的空壳灌进来。
_ERROR_PAGE_TITLE_RE = re.compile(
    r"^(?:出错了|发生了?错误|服务器错误|系统错误|页面出错|error|oops|not found|"
    r"404\s*not\s*found|403\s*forbidden|500\s*internal\s*server\s*error|"
    r"service unavailable|bad gateway)$", re.I)


def block_kind(info: "HttpInfo", body: str = "") -> str:
    """判定这份响应是不是盾/错误页，是则返回原因，否则空串。

    只看能确认的三种证据：标题是盾页、正文写着拦截词、或 Server 头是 WAF/抓包代理。
    正常业务站的 401/403 登录墙标题里没有这些词，不会被误伤。
    """
    if info is not None and info.error and not info.status:
        return ""
    title = (getattr(info, "title", "") or "")
    if title and _BLOCK_TITLE_RE.search(title):
        return f"拦截页({title[:30]})"
    server = (getattr(info, "server", "") or "")
    if server and _BLOCK_SERVER_RE.search(server):
        return f"防护/代理页({server[:30]})"
    head = (body or "")[:4000]
    if head and _BLOCK_BODY_RE.search(head):
        return "拦截页(正文含安全防护提示)"
    # 空正文却报网关错：请求根本没到源站（出口代理 / 链路占位页）。
    # 这种响应既不能当站点存活，也不能当业务页存进资产表。
    if (getattr(info, "length", 0) or 0) == 0 and (body or "") == "" \
            and (getattr(info, "status", 0) or 0) >= 500:
        return "网关占位页(空响应)"
    return ""


def is_error_page(status: int, title: str) -> bool:
    """网关默认错误页：状态码 ≥ 400 且标题就是一句「出错了 / 404 / Error」。

    业务站点即使挂了错误模板，标题里也会带自己的站名，所以只认「标题等于
    错误词本身」这一种，避免把 Login / 首页误杀。
    """
    t = (title or "").strip()
    if not t:
        return False
    if status and status < 400:
        return False
    return bool(_ERROR_PAGE_TITLE_RE.match(t))


@dataclass
class HttpInfo:
    url: str = ""
    final_url: str = ""
    status: int = 0
    title: str = ""
    length: int = 0
    headers: dict = field(default_factory=dict)
    server: str = ""
    fingerprint: list[str] = field(default_factory=list)
    web_fingerprint: list[str] = field(default_factory=list)
    web_fp_detail: list[dict] = field(default_factory=list)
    favicon_hash: int = 0
    cert: dict = field(default_factory=dict)
    redirect: str = ""
    body_hash: str = ""
    error: str = ""
    body: str = ""          # 正文片段；只给需要正文的分析（AI 指纹建议等）用，不入库
    cdn: str = ""          # CDN 供应商名；空 = 未判定（IP 直连目标不参与判定）
    alt_exit: bool = False  # 来自备用出口（代理）的探测结果


# httpx 的 verify=True 会为每个客户端新建上下文，Windows 上加载系统证书库要 650ms，
# 而 web 存活探测是每 URL 一个客户端、全在事件循环线程里建，几百个 URL 就把健康检查
# 饿死（看门狗判死重启，任务停在 web 阶段）。上下文与客户端无关，按开关缓存一份即可。
_SSL_CTX: dict[bool, ssl.SSLContext] = {}


def _ssl_ctx(verify: bool) -> ssl.SSLContext:
    ctx = _SSL_CTX.get(verify)
    if ctx is None:
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        _SSL_CTX[verify] = ctx
    return ctx


def _client(*, via_proxy: bool | None = None, timeout: float | None = None,
            headers: dict | None = None, follow: bool = True) -> httpx.AsyncClient:
    use_proxy = config.get("proxy", "scan_via_proxy") if via_proxy is None else via_proxy
    proxy = config.get("proxy", "url") if use_proxy else None
    t = float(timeout or config.get("http", "timeout") or 10)
    ua = config.get("http", "user_agent")
    h = {"User-Agent": ua, "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.9"}
    if headers:
        h.update(headers)
    # trust_env=False：不读系统 HTTP_PROXY，否则配置的显式代理会和环境代理叠加成 502
    return httpx.AsyncClient(timeout=t, proxy=proxy or None, trust_env=False,
                             verify=_ssl_ctx(bool(config.get("http", "verify"))),
                             follow_redirects=follow, headers=h)


def _cert_from_ssl_object(ssl_obj) -> dict:
    """从 SSLSocket 提取证书字段（httpx 的 getpeercert() 默认返回空 dict，须取 DER 解析）"""
    if ssl_obj is None:
        return {}
    try:
        der = ssl_obj.getpeercert(binary_form=True) or b""
    except Exception:
        der = b""
    if not der:
        return {}
    info: dict = {"sha256": hashlib.sha256(der).hexdigest(), "subject_cn": "", "issuer": "",
                  "not_before": "", "not_after": "", "san": [], "pem": "", "der_b64": "",
                  "org": "", "error": ""}
    info["der_b64"] = base64.b64encode(der).decode()
    try:
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der)
        info["pem"] = cert.public_bytes(serialization.Encoding.PEM).decode()
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        iss = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if cn:
            info["subject_cn"] = cn[0].value
        info["org"] = org[0].value if org else ""
        info["issuer"] = iss[0].value if iss else cert.issuer.rfc4514_string()[:120]
        info["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d")
        info["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info["san"] = san.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
    except Exception:
        pass
    return info


def _cert_of(stream) -> dict:
    try:
        return _cert_from_ssl_object(stream.get_extra_info("ssl_object"))
    except Exception:
        return {}


def extract_title(html: str) -> str:
    if not html:
        return ""
    m = TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


_FP: FingerPrint | None = None
_WEBFP = None
_CDN: CdnDetector | None = None


def fingerprint_engine() -> FingerPrint:
    global _FP
    if _FP is None:
        _FP = FingerPrint()
    return _FP


def webfp_engine():
    """nuclei 风格模板指纹（1.1 万条）。加载失败时返回 None，不影响主流程。"""
    global _WEBFP
    if _WEBFP is None:
        try:
            from .collectors import webfp
            _WEBFP = webfp.engine()
        except Exception:
            _WEBFP = False
    return _WEBFP or None


def cdn_detector() -> CdnDetector:
    global _CDN
    if _CDN is None:
        _CDN = CdnDetector()
    return _CDN


_DNS_CACHE: dict[str, tuple[float, list]] = {}
_DNS_TTL_OK = 300.0
_DNS_TTL_FAIL = 30.0


async def _resolve_infos(host: str, port: int, timeout: float = 4.0) -> list:
    """异步 DNS + 短 TTL 缓存。

    socket.getaddrinfo 是阻塞调用，直接在协程里调会把整个事件循环钉死：所有并发探测、
    HTTP 接口、SSE 一起停摆（曾经表现为 API 掉监听但流水线还在跑）。
    """
    key = "%s|%d" % (host, port)
    now = time.time()
    hit = _DNS_CACHE.get(key)
    if hit and hit[0] > now:
        return hit[1]
    infos: list = []
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP), timeout=timeout)
    except Exception:
        infos = []
    if len(_DNS_CACHE) > 8192:
        _DNS_CACHE.clear()
    _DNS_CACHE[key] = (now + (_DNS_TTL_OK if infos else _DNS_TTL_FAIL), list(infos or []))
    return infos


async def _pinned_url(url: str) -> tuple[str, dict]:
    """把域名换成已解析的 IP，Host 头保留原域名。

    部分目标（境内银行、政务、CDN 回源）对出口 IP 段做了 ACL，域名解析得到同一个 IP 也能被掐；
    先按系统 DNS 拿到的地址直连一次，能过的目标不会被这一步影响，过不了的还能靠 IP:端口 那条路打。
    """
    parts = urlparse(url)
    host = parts.hostname or ""
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return url, {}
    try:
        # 坏端口（:blank）到取 .port 才抛 ValueError，钉 IP 这一步直接放弃
        port_num = parts.port
    except ValueError:
        port_num = None
    infos = await _resolve_infos(host, port_num or (443 if parts.scheme == "https" else 80))
    if not infos:
        return url, {}
    ip = infos[0][4][0]
    port = f":{port_num}" if port_num else ""
    netloc = f"[{ip}]" if ":" in ip else ip
    return f"{parts.scheme}://{netloc}{port}{parts.path or '/'}", {"Host": host}


def _safe_encoding(raw: bytes, declared: str = "") -> str:
    """按字节判编码：头里写 UTF-8 但正文是 GBK 的站很多，标题会整片乱码。"""
    head = (raw or b"")[:2048].decode("latin-1", "ignore").lower()
    m = re.search(r"charset\s*=\s*[\"']?\s*([\w\-]+)", head)
    cands = [declared, m.group(1) if m else ""]
    for enc in cands:
        e = (enc or "").strip().lower()
        if not e:
            continue
        if e.startswith("gb") or e in ("iso-8859-1", "latin-1", "gb2312"):
            e = "gb18030"
        try:
            raw.decode(e)
            return e
        except (UnicodeDecodeError, LookupError):
            continue
    return "gb18030"


async def _fetch_once(url: str, info: HttpInfo, *, want_body: bool, want_cert: bool,
                      follow: bool, timeout: float | None, headers: dict | None,
                      via_proxy: bool | None = None) -> str:
    """单次 HTTP 取回，结果写进 info；返回正文（取不到返回空串）。"""
    max_body = int(config.get("http", "max_body") or 300000)
    async with _client(via_proxy=via_proxy, timeout=timeout, headers=headers, follow=follow) as client:
        async with client.stream("GET", url) as resp:
            raw = await resp.aread()
            encoding = resp.encoding or "utf-8"
            info.status = resp.status_code
            info.final_url = str(resp.url)
            info.headers = {k: v for k, v in resp.headers.items()}
            info.server = resp.headers.get("server", "")
            if want_cert and url.startswith("https"):
                info.cert = _cert_of(resp.extensions.get("network_stream"))
            info.length = len(raw)
            info.body_hash = sha256_text(raw[:100000]) if isinstance(raw, bytes) else ""
            if resp.history:
                info.redirect = " -> ".join(str(r.url) for r in resp.history)
            body = raw[:max_body].decode(_safe_encoding(raw, encoding), "replace") if want_body else ""
            info.body = body[:20000]
            return body


async def probe_alt(host: str, port: int, timeout: float = 15.0) -> HttpInfo:
    """curl 失败时换出口再试一次：本机抓包代理会把直连回成自己的 502 页。

    只有「直连拿到的是代理占位页 / 连不上」而配置了代理时才走这里，避免每个站都多打一轮。
    返回的 info 带 alt_exit=True，调用方据此判定这个站的真实状态。
    """
    from ..utils import is_ip

    url = f"http://{host}/" if port == 80 else (
        f"https://{host}:{port}/" if port == 443 else f"http://{host}:{port}/")
    info = HttpInfo(url=url)
    if not (host and 1 <= port <= 65535):
        info.error = "invalid target"
        return info
    hdrs = {"Referer": f"https://www.baidu.com/s?wd={host}"} if not is_ip(host) else {}
    try:
        body = await _fetch_once(normalize_url(url), info, want_body=True, want_cert=True,
                                 follow=True, timeout=timeout, headers=hdrs, via_proxy=True)
    except Exception as e:
        info.status = 0
        info.error = f"{type(e).__name__}: {e}"[:200]
        return info
    info.alt_exit = True
    if body:
        info.title = extract_title(body)
    return info


async def probe(url: str, want_body: bool = True, want_cert: bool = True,
                follow: bool | None = None, timeout: float | None = None,
                headers: dict | None = None) -> HttpInfo:
    """单 URL 探测：状态码 + 标题 + 指纹 + favicon + 证书"""
    url = normalize_url(url)
    info = HttpInfo(url=url)
    if not url:
        info.error = "invalid url"
        return info
    follow = config.get("http", "follow_redirects") if follow is None else follow
    body = ""
    try:
        try:
            body = await _fetch_once(url, info, want_body=want_body, want_cert=want_cert,
                                     follow=bool(follow), timeout=timeout, headers=headers)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            # 域名直连被掐（DNS 通、TCP 不通）时按解析到的 IP 重试一次
            pinned, extra = await _pinned_url(url)
            if pinned == url:
                raise
            hdrs = dict(headers or {})
            hdrs.update(extra)
            body = await _fetch_once(pinned, info, want_body=want_body, want_cert=want_cert,
                                     follow=bool(follow), timeout=timeout, headers=hdrs)
    except Exception as e:
        info.error = f"{type(e).__name__}: {e}"[:200]
        # 记录兜底尝试过的地址，便于排查「域活着但一个站都没探到」
        if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout)):
            pinned, _ = await _pinned_url(url)
            if pinned != url:
                info.error = f"{info.error} | 已按解析IP重试 {host_of(pinned)} 仍失败"[:300]
        return info
    if body:
        info.title = extract_title(body)
        m = re.search(r'<link[^>]+rel=["\']?(?:shortcut )?icon["\']?[^>]+href=["\']([^"\']+)', body, re.I)
        if m:
            icon = urljoin(info.final_url or url, m.group(1))
            try:
                info.favicon_hash = await favicon_hash(icon)
            except Exception:
                pass
        info.fingerprint = fingerprint_engine().match(
            info.headers, body, info.title,
            favicon_hash=str(info.favicon_hash or ""))
        # 模板指纹：补 webapp.json 认不出的国产 OA / 路由器 / 摄像头 / 工控面板
        eng = webfp_engine()
        if eng is not None:
            try:
                cert_txt = ""
                if isinstance(info.cert, dict):
                    cert_txt = " ".join(str(v) for v in info.cert.values() if v)
                elif info.cert:
                    cert_txt = str(info.cert)
                hits = eng.match(headers=info.headers, body=body, title=info.title,
                                 cert=cert_txt, favicon_hash=info.favicon_hash)
                info.web_fingerprint = [h["name"] for h in hits]
                info.web_fp_detail = hits[:30]
                merged = list(dict.fromkeys(info.fingerprint + info.web_fingerprint))
                info.fingerprint = merged
            except Exception:
                pass
    return info


async def favicon_hash(url: str) -> int:
    try:
        async with _client() as client:
            r = await client.get(url, timeout=8)
            if r.status_code == 200 and r.content:
                return mmh3_favicon(r.content)
    except Exception:
        pass
    return 0


async def probe_many(urls: list[str], concurrent: int = 100, want_body: bool = True,
                     want_cert: bool = True) -> list[HttpInfo]:
    sem = asyncio.Semaphore(max(1, concurrent))

    async def one(u: str) -> HttpInfo:
        async with sem:
            return await probe(u, want_body=want_body, want_cert=want_cert)

    return list(await asyncio.gather(*[one(u) for u in urls], return_exceptions=False))


async def fetch_text(url: str, *, params: dict | None = None, headers: dict | None = None,
                     timeout: float = 15, via_proxy: bool = False, retry: int = 2) -> str:
    last = ""
    for _ in range(retry + 1):
        try:
            async with _client(via_proxy=via_proxy, timeout=timeout, headers=headers) as client:
                r = await client.get(url, params=params)
                if r.status_code >= 400:
                    return ""
                return r.text
        except Exception as e:
            last = str(e)
    _ = last
    return ""


async def fetch_json(url: str, *, params: dict | None = None, headers: dict | None = None,
                     timeout: float = 15, via_proxy: bool = False, retry: int = 1, auth=None):
    for _ in range(retry + 1):
        try:
            async with _client(via_proxy=via_proxy, timeout=timeout, headers=headers) as client:
                r = await client.get(url, params=params, auth=auth)
                if r.status_code >= 400:
                    continue
                return r.json()
        except Exception:
            continue
    return None


async def detect_cdn(url_or_host: str) -> str:
    """探测 HTTPS 证书 CNAME/IP 归属 CDN 厂商"""
    host = host_of(url_or_host) or url_or_host
    info = await probe(f"https://{host}", want_body=False, want_cert=True)
    ips = []
    infos = await _resolve_infos(host, 443)
    ips = [a[4][0] for a in infos if a[4]]
    cnames = []
    cn = (info.cert or {}).get("subject_cn")
    if cn and cn != host:
        cnames.append(cn)
    return cdn_detector().detect(cnames=cnames, ips=ips)


def parse_ports_from_url(url: str) -> int:
    try:
        # 坏端口（如抓到的 :blank）在取 .port 时才抛 ValueError
        return urlparse(url).port or (443 if url.startswith("https") else 80)
    except ValueError:
        return 443 if url.startswith("https") else 80


async def fetch_bytes(url: str, *, timeout: float = 10, headers: dict | None = None,
                      via_proxy: bool = False, max_size: int = 200000):
    """取原始字节：返回 (status, body, content_type)，失败 None（不做文本解码，便于字节级软404比对）"""
    try:
        async with _client(via_proxy=via_proxy, timeout=timeout, headers=headers) as client:
            r = await client.get(url)
            return r.status_code, r.content[:max_size], r.headers.get("content-type", "")
    except Exception:
        return None
