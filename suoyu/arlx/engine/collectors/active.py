"""主动收集模块。

  * 域名爆破（多字典 + 泛解析剔除）
  * dnsgen 变体（ARL altDNS 的跨平台实现）
  * 站点爬虫 + JS 接口/域名/AK 提取（WIH 规则）
  * 敏感文件探测（ARL fileLeak 的跨平台实现）
  * vhost 碰撞（Host 头差异判定）
  * 同 IP 旁站 / C 段反查
"""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlsplit, urlunsplit

import yaml

from ...config import DATA_DIR, ROOT
from ...utils import is_ip, is_valid_domain, normalize_url, root_domain
from ..dns_engine import DnsEngine
from ..http_engine import probe
from . import ownership

DICT_DIR = ROOT / "arlx" / "dicts"
# 界面上改过的字典落这里，同名时覆盖内置那份；打包后也能持久化
USER_DICT_DIR = DATA_DIR / "dicts"


# ─────────────── 域名爆破 ───────────────
async def load_dict(name: str) -> list[str]:
    p = USER_DICT_DIR / name
    if not p.exists():
        p = DICT_DIR / name
    if not p.exists():
        return []
    return [w.strip() for w in p.read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]


async def brute_subdomains(domain: str, dict_name: str = "domain_2w.txt", concurrent: int = 300,
                           dns: DnsEngine | None = None) -> tuple[dict[str, list[str]], set[str]]:
    dns = dns or DnsEngine(concurrent=concurrent)
    words = await load_dict(dict_name)
    if not words:
        return {}, set()
    wildcard = await dns.detect_wildcard(domain)
    candidates = list(dict.fromkeys(f"{w}.{domain}".lower() for w in words))
    results = await dns.resolve_many(candidates)
    found: dict[str, list[str]] = {}
    for name, res in results.items():
        ips = [ip for ip in res.ips if ip not in wildcard]
        if ips:
            found[name] = ips
    return found, wildcard


# ─────────────── dnsgen 变体（对齐 ARL altDNS）───────────────
NUM_PAT = re.compile(r"^(?P<prefix>[a-z\-]+?)(?P<num>\d+)$")
ENV_PAT = re.compile(r"^(?P<env>dev|test|stage|uat|prod|pre|sit|beta|demo)(?P<rest>[\-.]?.*)$")
ENVS = ("dev", "test", "stage", "uat", "prod", "pre", "sit", "beta", "demo")
SUFFIXES = ("api", "admin", "static", "old", "new", "bak", "test")


def dnsgen_variants(subdomains: list[str], base: str, words: list[str] | None = None) -> list[str]:
    words = words or ["dev", "test", "stage", "uat", "prod", "beta", "demo", "admin", "api", "app",
                      "static", "img", "cdn", "m", "wap", "mail", "oa", "vpn", "git", "jenkins"]
    out: set[str] = set()

    def level_variants(parts: list[str]) -> set[str]:
        variants: set[str] = set()
        for i, part in enumerate(parts):
            others = parts[:i] + parts[i + 1:]
            m = NUM_PAT.match(part)
            if m:
                n = int(m.group("num"))
                for delta in (-2, -1, 1, 2):
                    if n + delta > 0:
                        variants.add(".".join(others[:i] + [f"{m.group('prefix')}{n + delta}"] + others[i:]))
            m2 = ENV_PAT.match(part)
            if m2:
                for env in ENVS:
                    if env != m2.group("env"):
                        variants.add(".".join(others[:i] + [f"{env}{m2.group('rest')}"] + others[i:]))
            for env in ("dev", "test", "uat", "pre", "sit"):
                variants.add(".".join(others[:i] + [f"{env}-{part}"] + others[i:]))
            for suf in SUFFIXES:
                variants.add(".".join(others[:i] + [f"{part}-{suf}"] + others[i:]))
        if len(parts) <= 2:
            for w in words:
                variants.add(".".join([w] + parts))
        return variants

    for sub in subdomains:
        sub = sub.lower()
        if not sub.endswith(base) or sub == base:
            continue
        parts = sub[: -(len(base) + 1)].split(".")
        if not parts or parts == [""]:
            continue
        for v in level_variants(parts):
            cand = f"{v}.{base}".lower()
            if len(cand) < 253:
                out.add(cand)
    return sorted(out)[:20000]


async def alt_dns_brute(domain: str, known_subdomains: list[str], concurrent: int = 1500,
                        dns: DnsEngine | None = None) -> dict[str, list[str]]:
    dns = dns or DnsEngine(concurrent=concurrent)
    word_list = await load_dict("altdnsdict.txt")
    variants = dnsgen_variants(known_subdomains, domain, word_list)
    if not variants:
        return {}
    wildcard = await dns.detect_wildcard(domain)
    results = await dns.resolve_many(variants)
    out = {}
    for name, res in results.items():
        ips = [ip for ip in res.ips if ip not in wildcard]
        if ips:
            out[name] = ips
    return out


# ─────────────── 搜索引擎爬虫（子域扩展）───────────────
async def search_engine_spider(domain: str) -> set[str]:
    from ..sources.passive import src_bing, src_duckduckgo

    out: set[str] = set()
    for fn in (src_bing, src_duckduckgo):
        res = await fn(domain)
        out |= res.subdomains
    return out


# ─────────────── 站点爬虫 + JS 提取 ───────────────
LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.I)
JS_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
API_RE = re.compile(r"""["'`]((?:/|https?://)[a-zA-Z0-9_\-./{}$:?=&%#@~+\[\]]{3,120})["'`]""")

# 静态目录（图片/CSS/编辑器资源）在页面脚本里被拼成几百条路径，端点价值为零
STATIC_DIRS = {"static", "assets", "asset", "public", "res", "resources", "images", "image", "img",
               "css", "js", "fonts", "font", "media", "upload", "uploads", "files", "file", "lib",
               "libs", "vendor", "plugins", "plugin", "themes", "theme", "skin", "skins", "dist",
               "node_modules", "htmledition", "cache", "tmp"}
STATIC_EXT_RE = re.compile(    r"\.(?:png|jpe?g|gif|bmp|webp|svg|ico|css|less|scss|js|map|woff2?|ttf|eot|otf|mp3|mp4|avi|"
    r"swf|flv|zip|rar|7z|gz|tar|exe|msi|dmg|apk|ipa|psd|docx?|xlsx?|pptx?)$", re.I)


def api_like(path: str) -> bool:
    """这个路径像不像一个真接口：静态资源目录、带文件后缀的一律不算。"""
    p = (path or "").split("?", 1)[0].split("#", 1)[0]
    if len(p) < 4:
        return False
    if STATIC_EXT_RE.search(p):
        return False
    segs = [s for s in p.strip("/").split("/") if s]
    if not segs:
        return False
    # 首段是静态目录名（/images/x、/htmledition/js/y）整条丢掉
    if segs[0].lower() in STATIC_DIRS:
        return False
    # 末段没有参数、也不像动作名（全是小写单词的目录式路径，如 /zh_CN/htmledition/js/）
    last = segs[-1]
    if "/" in p and "." not in last and "_" not in last and not re.search(r"[A-Z]", last) \
            and sum(c in "?=&" for c in path) == 0 and any(s.lower() in STATIC_DIRS for s in segs):
        return False
    return True


def host_filter(host: str, own_roots: set[str] | None = None) -> bool:
    """返回 True 表示该主机不该进自家资产表：文件名误判、第三方托管、搜索引擎自身。"""
    return ownership.is_non_domain(host) or ownership.is_foreign(host, own_roots)

WIH_DEFAULT_RULES = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}",
    "ak": r"(?:AKID|AccessKeyId)[\"'\s:=]+([A-Za-z0-9]{16,32})",
    "sk": r"(?:SecretKey|secret_key|access_key_secret)[\"'\s:=]+([A-Za-z0-9/+=]{20,64})",
    "jwt": r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
    "phone": r"\b1[3-9]\d{9}\b",
}
# 邮箱本地部分只认可直接书写的人名格式；转义残片（%22、u0022、\x40）一律不算
EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*")
# 源码里用 Unicode / 百分号转义拼 @ 会留下这些残片，它们不是邮箱
EMAIL_ESCAPE_RE = re.compile(r"(?:^|[^0-9a-z])u00[0-9a-f]{2}|%[0-9a-f]{2}|\\x[0-9a-f]{2}", re.I)


def load_wih_rules() -> dict:
    p = DICT_DIR / "wih_rules.yml"
    if not p.exists():
        return WIH_DEFAULT_RULES
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return WIH_DEFAULT_RULES
    rules = {}
    for item in (data.get("rules") or []) if isinstance(data, dict) else []:
        name = item.get("name")
        pattern = item.get("rule") or item.get("regex")
        if name and pattern:
            rules[name] = pattern
    return rules or WIH_DEFAULT_RULES


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def charset_of(raw: bytes, declared: str = "") -> str:
    """实际字节推编码：国内政企站大量是 GBK，按声明的 UTF-8 解会成一片问号。"""
    head = (raw or b"")[:4096].decode("latin-1", "ignore").lower()
    m = re.search(r"charset\s*=\s*[\"']?\s*([\w\-]+)", head)
    cands = [declared, m.group(1) if m else "", "utf-8"]
    for enc in cands:
        e = (enc or "").strip().lower()
        if not e:
            continue
        if e in ("gb2312", "gbk", "gb18030", "iso-8859-1", "latin-1"):
            e = "gb18030" if e.startswith("gb") else "gb18030"
        try:
            return raw.decode(e) and e
        except (UnicodeDecodeError, LookupError):
            continue
    return "gb18030"


async def fetch_page(url: str, timeout: float = 10) -> tuple[str, str]:
    """取页面并按真实字节解码；返回（正文, 实际编码）。标题乱码就出在这里。"""
    html, enc, _blocked = await fetch_page_ex(url, timeout=timeout)
    return html, enc


async def fetch_page_ex(url: str, timeout: float = 10) -> tuple[str, str, str]:
    """同 fetch_page，多返回一层「这页为什么拿不到正文」。

    WAF 拦截页（405 + NWAF）、反代错误页、本机抓包代理占位页都是「有响应但没内容」：
    以前一律返回空串，整站就只剩一条没有正文的 site 记录，日志里也看不出是被挡住了。
    这里把拦截原因带出去，交给调用方记进日志与资源备注。
    """
    from ..http_engine import HttpInfo, _client, block_kind

    try:
        async with _client(timeout=timeout) as client:
            r = await client.get(url)
            raw = r.content or b""
            enc = charset_of(raw, r.charset_encoding or "")
            html = raw.decode(enc, "replace")
            head = HttpInfo(url=url, status=r.status_code, title=extract_title(html),
                            server=r.headers.get("server", ""))
            why = block_kind(head, html)
            if why:
                return "", enc, why
            if r.status_code >= 400:
                return "", enc, ""
            return html, enc, ""
    except Exception as e:
        return "", "", f"{type(e).__name__}"


async def crawl_site(url: str, max_pages: int = 15, root: str = "") -> dict:
    """抓取站点内链与 JS，提取接口路径、外链域、敏感信息"""
    from ..http_engine import fetch_text

    def _host_plain(u: str) -> str:
        try:
            from urllib.parse import urlparse

            return (urlparse(u).hostname or "").strip().lower()
        except Exception:
            return ""

    norm = normalize_url(url)
    if not norm:
        return {"urls": [], "js": [], "apis": [], "domains": [], "secrets": [], "blocked": ""}
    scheme = norm.split("://")[0]
    base_host = norm.split("://")[-1].split("/")[0]
    # 自家根：判定第三方时要放行本任务的域，否则自家根刚好挂在大厂托管的域会被误砍
    own_roots: set[str] = set()
    for cand in (root or "", base_host):
        if cand and not is_ip(cand):
            r = root_domain(cand) or cand
            if r:
                own_roots.add(r.lower())
    queue = [norm]
    seen: set[str] = set()
    urls: set[str] = set()
    js_urls: set[str] = set()
    js_done: set[str] = set()
    apis: set[str] = set()
    domains: set[str] = set()
    secrets: list[dict] = []
    rules = load_wih_rules()
    started = time.time()
    blocked = ""
    # 每页都重抓同一批 JS 会让单页开销翻十倍以上，整轮爬虫还会无限拖长；
    # 总时长也得上限，否则一个慢站能把后面所有阶段卡死。
    budget = max(30.0, 15.0 * max_pages)

    async def _scan_text(text: str, where: str, host: str = "", third_party: bool = False) -> None:
        # 页面里夹带的第三方脚本按脚本自己的主机算，免得把邮箱服务商登录页的
        # cgi-bin 接口全记到自家站名下
        here = {host} if host and host not in own_roots else set()
        for m in API_RE.findall(text):
            if m.startswith("//"):
                # 协议相对地址 //host/path 指到的是别人家的接口，不能挂成本站路径；
                # 主机名单独归档，路径丢掉，免得资产表里出现 host//third-party
                ext = _host_plain("http:" + m)
                if ext and ext != host and (is_valid_domain(ext) or is_ip(ext)):
                    domains.add(ext)
                continue
            if third_party:
                continue
            if "://" in m:
                # 绝对地址里的相对路径（自己站点拼出来的）当本站路径，别人家的只留域名
                page_host = _host_plain(where)
                if m.startswith(("http://" + page_host, "https://" + page_host)):
                    m = "/" + m.split("://", 1)[1].split("/", 1)[-1] if "/" in m.split("://", 1)[1] else "/"
                else:
                    continue
            if not api_like(m):
                continue
            apis.add(m)
        for name, pattern in rules.items():
            try:
                for hit in re.findall(pattern, text, re.I):
                    val = hit if isinstance(hit, str) else (hit[0] if hit else "")
                    if not val or len(val) >= 300:
                        continue
                    # 域名规则没有左边界，会把 `document.write`、`favicon.ico`、
                    # `Math.random` 一并当域收进敏感表。这里按同一套口径挡掉。
                    if name == "domain":
                        if ownership.is_non_domain(val) or host_filter(val, here | own_roots):
                            continue
                    elif name == "email":
                        # 本地部分按未加引号的邮箱字面量校验：源码里拼出来的
                        # %22@xmaj.com、u0022@xmaj.com 这类转义残片不是邮箱
                        local = val.rsplit("@", 1)[0].strip('"\'`')
                        if not EMAIL_LOCAL_RE.fullmatch(local) \
                                or EMAIL_ESCAPE_RE.search(local) \
                                or ownership.is_non_domain(val.rsplit("@", 1)[-1]):
                            continue
                        # 第三方脚本里的邮箱是人家客服/作者的，不算本站线索
                        if third_party:
                            continue
                    secrets.append({"type": name, "value": val, "where": where})
            except re.error:
                continue

    while queue and len(seen) < max_pages:
        if blocked and not urls:
            # 首页即拦截：没有内链可跟，直接收口
            break
        if time.time() - started > budget:
            break
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        html, _enc, why = await fetch_page_ex(cur, timeout=10)
        if why and not blocked:
            # 首页就被拦在盾外：后面的内链 / JS 一律拿不到，再爬只是空耗预算
            blocked = why
        if not html:
            continue
        for src in JS_SRC_RE.findall(html):
            full_js = src if src.startswith("http") else normalize_url(src, scheme)
            if full_js:
                js_urls.add(full_js)
        for link in LINK_RE.findall(html):
            if link.startswith(("javascript:", "#", "mailto:", "tel:", "data:")):
                continue
            full = link if link.startswith("http") else normalize_url(link, scheme)
            if not full:
                continue
            urls.add(full)
            host = _host_plain(full)
            if not host:
                continue
            if host == base_host and full not in seen and len(queue) < max_pages * 4:
                queue.append(full)
            elif host != base_host:
                # 相对路径解析出来的 host 常是 js / css / images 这类目录名，
                # 直接当域名入库会污染资产表；只收真域名和 IP。邮箱服务商、
                # 微信登录、验证码、统计这类第三方域也不进自家清单。
                if (is_valid_domain(host) or is_ip(host)) and not host_filter(host, own_roots):
                    domains.add(host)
        # 页面正文里的接口和密钥只算本页所在站的；第三方脚本另走下面按脚本自身主机算
        page_host = _host_plain(cur)
        await _scan_text(html, cur, page_host)
        # 全站 JS 只抓一次：抽出来的路径和密钥本来就不随页面变化
        todo = [u for u in sorted(js_urls) if u not in js_done and u not in seen][:8]
        for js in todo:
            js_done.add(js)
            js_host = _host_plain(js)
            text, _e = await fetch_page(js, timeout=10)
            if text:
                # 别人家的脚本（CDN、统计、第三方 SDK）里的路径是他们的接口，
                # 只从里面捞域名，不把它的 path 记成本站接口
                await _scan_text(text, js, js_host, third_party=bool(js_host and js_host != page_host))
    return {
        "urls": sorted(urls)[:2000],
        "js": sorted(u for u in js_urls if u)[:500],
        "apis": sorted(apis)[:2000],
        "domains": sorted(domains)[:500],
        "secrets": secrets[:500],
        "blocked": blocked,
    }


# ─────────────── 敏感文件探测 ───────────────
SOFT404_LEN_GAP = 120     # 软 404：命中与随机路径长度过近即判废
SOFT404_SIM = 0.92        # 正文相似度阈值


def _leak_base(url: str) -> str:
    """敏感文件探测的挂载点：去掉查询串与锚点，目标是文件时退到其所在目录。

    拿 ``/login?next=...`` 这类带参页面当基点，路径会被拼到查询串后面，服务端
    照样回 200，结果全是假命中。
    """
    u = normalize_url(url).rstrip("/")
    if not u:
        return ""
    p = urlsplit(u)
    path = p.path.rstrip("/")
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        path = path[: -len(last)].rstrip("/")
    return urlunsplit((p.scheme, p.netloc, path, "", ""))


def _soft404_similar(a: bytes, b: bytes) -> bool:
    """截断比较：结构相同（同前缀）或长度接近且尾部相同 → 判定为软 404 页面"""
    if not a or not b:
        return False
    n = min(len(a), len(b), 3000)
    same_prefix = a[:n] == b[:n]
    tail = a[-200:] == b[-200:] if len(a) > 200 and len(b) > 200 else False
    return same_prefix or (tail and abs(len(a) - len(b)) <= SOFT404_LEN_GAP)


async def file_leak(url: str, dict_name: str = "file_top_200.txt", concurrent: int = 20) -> list[dict]:
    from ..http_engine import fetch_bytes

    base = _leak_base(url)
    if not base:
        return []
    words = await load_dict(dict_name)
    sem = asyncio.Semaphore(concurrent)
    # 先打一个必然不存在的路径，拿软 404 基线（ARL fileLeak 的 exclude rule 思路）
    import random
    import string

    rand_word = "".join(random.choices(string.ascii_lowercase, k=18))
    baseline = await fetch_bytes(f"{base}/{rand_word}.html", timeout=8)
    base_status = baseline[0] if baseline else 404
    base_body = baseline[1] if baseline else b""
    hits: list[dict] = []

    async def one(w: str):
        async with sem:
            u = f"{base}/{w.lstrip('/')}"
            res = await fetch_bytes(u, timeout=8)
            if res is None:
                return
            status, body, ct = res
            if status not in (200, 206) or len(body) < 30:
                return
            if "text/html" in ct and b"<title>404" in body[:3000]:
                return
            # 字典里是非 HTML 的敏感文件，回 HTML 只能是兜底页或登录页，不是泄露
            if "text/html" in ct and not w.lower().endswith((".html", ".htm")):
                return
            # 软 404：与随机基线同结构/近长度，或状态与基线一致且正文几乎一样
            if baseline and _soft404_similar(body, base_body):
                return
            hits.append({"url": u, "status": status, "length": len(body), "content_type": ct})

    await asyncio.gather(*[one(w) for w in words])
    if base_status == 200 and base_body:
        # 站点所有路径都 200（泛 200）：只保留正文与基线明显不同的
        hits = [h for h in hits if abs(h["length"] - len(base_body)) > SOFT404_LEN_GAP]
    # 同状态同长度的命中扎堆，说明这是站点的兜底页：整簇丢掉
    if hits:
        same: dict[tuple[int, int], int] = {}
        for h in hits:
            k = (h["status"], h["length"])
            same[k] = same.get(k, 0) + 1
        crowd = max(3, len(hits) // 5)
        hits = [h for h in hits if same[(h["status"], h["length"])] < crowd]
    return hits


# ─────────────── vhost 碰撞 ───────────────
async def vhost_collision(ip: str, domains: list[str], ports: tuple[int, ...] = (80, 443),
                          *, concurrent: int = 8) -> list[dict]:
    from ..sources.passive import _get

    hits: list[dict] = []
    sem = asyncio.Semaphore(max(1, concurrent))

    async def one(port: int, scheme: str, d: str, base_status: int, base_len: int,
                  base_title: str) -> None:
        async with sem:
            # 单个 Host 头探测失败只丢这一条，不该把整个 IP 的碰撞结果带走
            try:
                r = await _get(f"{scheme}://{ip}:{port}/", headers={"Host": d}, timeout=4)
            except Exception:
                return
            if r is None:
                return
            t = extract_title(r.text)
            if (r.status_code != base_status) or (t and t != base_title) or abs(len(r.content) - base_len) > 200:
                hits.append({"ip": ip, "port": port, "host": d, "status": r.status_code,
                             "title": t, "length": len(r.content)})

    for port in ports:
        scheme = "https" if port == 443 else "http"
        try:
            base = await _get(f"{scheme}://{ip}:{port}/", timeout=6)
        except Exception:
            continue
        if base is None:
            continue
        base_len, base_title = len(base.content), extract_title(base.text)
        base_status = base.status_code
        # 原来逐条 await，80 个域名 × 6 秒超时能卡十几分钟；并发探测把最坏耗时压到分钟级
        await asyncio.gather(*[one(port, scheme, d, base_status, base_len, base_title)
                               for d in domains[:80]])
    return hits


# ─────────────── 旁站 / C 段 ───────────────
async def ip_siblings(ip: str) -> dict:
    dns = DnsEngine()
    ptrs = await dns.resolve_ptr(ip)
    return {"ip": ip, "ptr": ptrs}


async def c_segment_scan(ip: str, size: int = 255, ports: tuple[int, ...] = (80, 443),
                         concurrent: int = 100, want_title: bool = True) -> list[dict]:
    """扫同 C 段 80/443。

    端口开着不算旁站：云主机默认页、抓包代理占位页、盾页都会应答，一台机器能贡献几百条
    噪声把真资产埋掉。want_title=True 时要真正拿到带标题的业务页才收，并带上标题。
    """
    from ..portscan import scan_port

    base = ip.rsplit(".", 1)[0]
    sem = asyncio.Semaphore(concurrent)
    hosts: list[dict] = []

    async def one(n: int):
        target = f"{base}.{n}"
        for port in ports:
            async with sem:
                res = await scan_port(target, port, timeout=1.2, detect=False)
            if not res.open:
                continue
            row = {"ip": target, "port": port, "title": ""}
            if want_title:
                scheme = "https" if port == 443 else "http"
                html, _enc, why = await fetch_page_ex(f"{scheme}://{target}:{port}/", timeout=6)
                if why or not html:
                    continue
                title = extract_title(html)
                if not title:
                    continue
                row["title"] = title
            hosts.append(row)

    await asyncio.gather(*[one(n) for n in range(1, min(size, 255) + 1)])
    return hosts


# ─────────────── 证书采集 ───────────────
async def cert_collect(url: str) -> dict:
    info = await probe(url, want_body=False, want_cert=True)
    return info.cert if info else {}
