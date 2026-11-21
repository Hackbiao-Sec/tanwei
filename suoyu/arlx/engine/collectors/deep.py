"""深度挖掘模块（对齐天鉴·索舆 P5 阶段）。

  * 代码 / 文档泄露：Bing、Sourcegraph、grep.app、GitHub 代码搜索，捞配置、密钥、内网地址、接口文档
  * 邮箱 / 联系人：站点抓取 + 搜索引擎 + Hunter 域名接口
  * 邮件 DNS：MX / SPF / DMARC / DKIM selector 探测（判断企业真实邮件域名与第三方托管）
  * 截图：Playwright（替代 ARL 的 phantomjs，跨平台）
  * nuclei：调用本机 nuclei 做高危模板复核
  * 云存储桶：S3 / OSS / COS 命名规则枚举
  * Git 泄露：/.git/HEAD、/config、/index 探测
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import quote

from ...config import config, src_base
from ...utils import is_ip, root_domain
from ..sources.passive import _get

# 左边必须是分隔符，否则 `//cdn…/a@b.com` 这类长 URL 会从中间咬出假邮箱
EMAIL_RE = re.compile(r"(?<![\w.%+\-/])[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}")
# 邮箱本地部分只认直接书写的人名格式；源码/搜索结果里 %22@、u0022@ 这类转义残片不是邮箱
EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*")
EMAIL_ESCAPE_RE = re.compile(r"(?:^|[^0-9a-z])u00[0-9a-f]{2}|%[0-9a-f]{2}|\\x[0-9a-f]{2}", re.I)


def email_ok(addr: str) -> bool:
    """这个字符串是不是一个能当线索用的邮箱地址。"""
    a = (addr or "").strip().lower()
    if "@" not in a:
        return False
    local = a.rsplit("@", 1)[0].strip('"\'`')
    if not EMAIL_LOCAL_RE.fullmatch(local) or EMAIL_ESCAPE_RE.search(local):
        return False
    return not a.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".css", ".js", ".ico"))
SECRET_KEYWORDS = ("password", "passwd", "pwd=", "secret", "api_key", "apikey", "accesskey",
                   "access_key", "accessToken", "jdbc:", "mongodb://", "redis://", "mysql://",
                   "aws_secret", "private_key", "BEGIN RSA")

# 代码泄露搜索：每个引擎返回 (url, 描述)
async def search_code_leak(domain: str, max_items: int = 200) -> list[dict]:
    out: list[dict] = []
    queries = [f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret',
               f'"{domain}" jdbc', f'"{domain}" .env', f'site:github.com "{domain}"']

    async def sourcegraph() -> None:
        for q in queries[:4]:
            r = await _get("https://sourcegraph.com/.api/search/stream",
                           {"q": f"{q} count:30", "v": "V3", "t": "standard", "display": "30"},
                           headers={"Accept": "text/event-stream"}, timeout=25)
            if r is None or r.status_code != 200:
                continue
            for m in re.finditer(r'"repository":"([^"]+)".*?collections\.MergeFileContents', r.text):
                out.append({"engine": "sourcegraph", "repo": m.group(1), "query": q})

    async def grep_app() -> None:
        for q in queries[:4]:
            r = await _get("https://grep.app/api/search", {"q": q, "regexp": "false"}, timeout=20)
            if r is None or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            for hit in ((data.get("hits") or {}).get("hits") or [])[:20]:
                out.append({"engine": "grep.app", "repo": hit.get("repo", {}).get("raw") if isinstance(hit.get("repo"), dict) else hit.get("repo"),
                            "path": (hit.get("path") or {}).get("raw") if isinstance(hit.get("path"), dict) else hit.get("path"),
                            "query": q})

    async def github() -> None:
        token = config.get("sources", "github", "token")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for q in (f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret'):
            r = await _get(src_base("github", "https://api.github.com") + "/search/code", {"q": q, "per_page": 50},
                           headers=headers, timeout=25)
            if r is None or r.status_code != 200:
                continue
            try:
                for item in (r.json() or {}).get("items") or []:
                    out.append({"engine": "github",
                                "repo": (item.get("repository") or {}).get("full_name"),
                                "path": item.get("path"), "url": item.get("html_url"), "query": q})
            except Exception:
                continue

    async def bing() -> None:
        for q in (f'site:github.com "{domain}" password', f'"{domain}" jdbc OR apikey'):
            r = await _get("https://www.bing.com/search", {"q": q, "count": 30}, timeout=20)
            if r is None or r.status_code != 200:
                continue
            for m in re.finditer(r'<h2><a href="(https?://[^"]+)"[^>]*>(.*?)</a>', r.text):
                t = re.sub(r"<[^>]+>", "", m.group(2)).strip()
                if domain.split(".")[0][:6].lower() in (m.group(1) + t).lower():
                    out.append({"engine": "bing", "url": m.group(1), "title": t, "query": q})

    await asyncio.gather(sourcegraph(), grep_app(), github(), bing(), return_exceptions=True)
    seen, uniq = set(), []
    for item in out:
        key = (item.get("engine"), item.get("repo") or item.get("url"), item.get("path"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(item)
    return uniq[:max_items]


# ─────────────── 邮箱 / 联系人 ───────────────
async def harvest_emails(urls: list[str], domain_roots: list[str]) -> list[dict]:
    """从站点页面与搜索引擎里抽邮箱 / 电话"""
    out: dict[str, dict] = {}
    sem = asyncio.Semaphore(20)

    async def one(u: str) -> None:
        async with sem:
            r = await _get(u, timeout=10)
        if r is None or r.status_code != 200:
            return
        text = r.text[:300000]
        for m in EMAIL_RE.findall(text):
            m = m.lower()
            if not email_ok(m):
                continue          # 正则误捞的裸 @域名 / 占位域 / 转义残片
            out.setdefault(m, {"email": m, "page": u})
    await asyncio.gather(*[one(u) for u in urls[:120]], return_exceptions=True)

    for root in domain_roots[:5]:
        for q in (f'"@{root}" email', f'site:{root} "mailto"'):
            r = await _get("https://www.bing.com/search", {"q": q, "count": 30}, timeout=20)
            if r is None or r.status_code != 200:
                continue
            for m in EMAIL_RE.findall(r.text):
                m = m.lower()
                if m.endswith(root) and email_ok(m):
                    out.setdefault(m, {"email": m, "source": "bing"})
    return list(out.values())[:500]


# ─────────────── 邮件 DNS ───────────────
async def mail_dns(root: str, dns) -> dict:
    info: dict = {"root": root}
    try:
        info["mx"] = await dns.query_type(root, "MX")
        txt = await dns.query_type(root, "TXT")
        info["spf"] = [t for t in txt if "v=spf1" in t.lower()]
        for rec in (await dns.query_type(root, "NS")):
            info.setdefault("ns", []).append(rec)
        dmarc = await dns.query_type(f"_dmarc.{root}", "TXT")
        info["dmarc"] = [d for d in dmarc if "v=DMARC1" in d]
        dkim = []
        for sel in ("default", "google", "selector1", "selector2", "k1", "s1", "mail"):
            v = await dns.query_type(f"{sel}._domainkey.{root}", "TXT")
            if v:
                dkim.append({"selector": sel, "value": v[0][:120]})
        info["dkim"] = dkim
    except Exception:
        pass
    return info


# ─────────────── 云存储桶 / Git 泄露 ───────────────
async def bucket_enum(names: list[str]) -> list[dict]:
    """S3 / OSS / COS 常见命名枚举（只做 HEAD/GET 判公开）"""
    out: list[dict] = []
    cands: set[tuple[str, str]] = set()
    for n in names[:20]:
        for core in (n, n.replace(".", "-"), n.replace(".", "")):
            for suf in ("", "-assets", "-static", "-img", "-file", "-upload", "-data", "-backup",
                        "-prod", "-dev", "-test", "static", "assets", "files", "-oss", "-cdn"):
                cands.add((f"{core}{suf}".lower(), core))
    sem = asyncio.Semaphore(30)

    def probe_urls(bucket: str) -> list[tuple[str, str]]:
        return [
            ("oss", f"https://{bucket}.oss-cn-hangzhou.aliyuncs.com/"),
            ("cos", f"https://{bucket}-1250000000.cos.ap-guangzhou.myqcloud.com/"),
            ("s3", f"https://{bucket}.s3.amazonaws.com/"),
            ("obs", f"https://{bucket}.obs.cn-north-4.myhuaweicloud.com/"),
        ]

    async def one(bucket: str, core: str) -> None:
        for vendor, url in probe_urls(bucket):
            async with sem:
                r = await _get(url, timeout=8)
            if r is None:
                continue
            body = (r.text or "")[:4000]
            if r.status_code in (200, 403) and ("ListBucketResult" in body or "AccessDenied" in body
                                                or "<Error>" in body or "ListObjects" in body):
                pub = r.status_code == 200 and "ListBucketResult" in body
                # 只留「真存在且能列」或「他人公开桶」：403 AccessDenied 多为该厂商通用错误页，
                # 不能证明桶由一个种子域名衍生出来（否则每次跑都刷出同一批无关资产）
                if not pub:
                    return
                out.append({"bucket": bucket, "vendor": vendor, "url": url,
                            "status": r.status_code, "public": pub, "root": core})
                break

    await asyncio.gather(*[one(b, c) for b, c in list(cands)[:300]], return_exceptions=True)
    return out


_KV_LINE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_.\-]*\s*=", re.M)


def _kv_lines(text: str) -> int:
    return len(_KV_LINE.findall(text or ""))


def _is_html(r) -> bool:
    ct = (r.headers.get("content-type") or "").lower()
    if "html" in ct:
        return True
    head = (r.content or b"")[:400].lstrip().lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html")


async def git_leak(url: str) -> dict:
    """单站源码/配置泄露探测。

    每条特征都要能对上文件本体：只回 200 和 HTML 兜底页、SPA 回退页一律不算泄露。
    """
    base = url.rstrip("/")
    for path in ("/.git/HEAD", "/.git/config", "/.svn/entries", "/.DS_Store", "/.env",
                 "/WEB-INF/web.xml", "/WEB-INF/classes/application.properties"):
        r = await _get(base + path, timeout=8)
        if r is None or r.status_code != 200:
            continue
        text = (r.text or "")[:2000]
        low = text.lower()
        hit = False
        if path == "/.DS_Store":
            hit = (r.content or b"")[:4] == b"\x00\x00\x00\x01"
        elif _is_html(r):
            hit = False
        elif path == "/.git/HEAD":
            hit = low.startswith("ref: refs/") or bool(re.match(r"^[0-9a-f]{40}\s", low))
        elif path == "/.git/config":
            hit = low.lstrip().startswith("[core]")
        elif path == "/.svn/entries":
            hit = bool(re.match(r"^\s*(\d{1,2}|dir)\s*$", low))
        elif path == "/.env":
            hit = _kv_lines(text) >= 2 and "<html" not in low
        elif path.endswith(".properties"):
            hit = _kv_lines(text) >= 2 and "<html" not in low
        elif path == "/WEB-INF/web.xml":
            hit = "<web-app" in low
        if hit:
            return {"url": base + path, "status": 200, "evidence": text[:300]}
    return {}


# ─────────────── 截图 / nuclei ───────────────
async def screenshot(url: str, out_dir) -> str:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return ""
    from pathlib import Path

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", url)[:120] + ".png"
    fp = str(Path(out_dir) / name)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1440, "height": 900},
                                          ignore_https_errors=True)
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")
            await page.screenshot(path=fp, full_page=False)
            await browser.close()
        return fp
    except Exception:
        return ""


async def run_nuclei(urls: list[str], severity: str = "critical,high") -> list[dict]:
    exe = config.get("deep", "nuclei_path") or "nuclei"
    try:
        proc = await asyncio.create_subprocess_exec(
            exe, "-silent", "-jsonl", "-severity", severity, "-no-color",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.PIPE)
        payload = "\n".join(urls).encode()
        out, _ = await asyncio.wait_for(proc.communicate(payload), timeout=1800)
    except Exception:
        return []
    results = []
    import json as _json

    for line in out.decode("utf-8", "ignore").splitlines():
        try:
            d = _json.loads(line)
        except Exception:
            continue
        results.append({"template": d.get("template-id"), "name": d.get("info", {}).get("name"),
                        "severity": (d.get("info") or {}).get("severity"),
                        "matched": d.get("matched-at"), "host": d.get("host")})
    return results


# ─────────────── 统一入口 ───────────────
def _roots(hosts: list[str]) -> list[str]:
    out = []
    for h in hosts:
        if not h or is_ip(h):
            continue
        r = root_domain(h) or h
        if r not in out:
            out.append(r)
    return out


async def deep_collect(site_urls: list[str], dns, opts: dict | None = None) -> dict:
    """深度阶段总控：代码泄露 / 邮箱 / 邮件DNS / 存储桶 / Git 泄露

    `opts` 传进来就按它开关各步骤（单阶段执行时改的就是这一项的行为），
    不传则回落配置文件的 `deep` 段。
    """
    roots = _roots([u.split("://")[-1].split("/")[0].split(":")[0] for u in site_urls])
    opts = dict(opts if opts else config.section("deep"))
    result: dict = {"code_leak": [], "emails": [], "mail_dns": [], "buckets": [], "git": []}
    tasks = []
    if opts.get("code_leak"):
        tasks.append(("code_leak", asyncio.gather(*[search_code_leak(r) for r in roots[:3]])))
    if opts.get("email_harvest", True):
        tasks.append(("emails", harvest_emails(site_urls, roots)))
    if opts.get("mail_dns", True):
        tasks.append(("mail_dns", asyncio.gather(*[mail_dns(r, dns) for r in roots[:5]])))
    if opts.get("bucket_enum"):
        tasks.append(("buckets", bucket_enum(roots)))
    if opts.get("git_leak", True):
        tasks.append(("git", asyncio.gather(*[git_leak(u) for u in site_urls[:60]])))
    for key, coro in tasks:
        try:
            val = await coro
        except Exception:
            continue
        if key == "code_leak":
            merged = []
            for chunk in val:
                merged.extend(chunk)
            result[key] = merged
        elif key == "mail_dns":
            result[key] = [m for m in val if m]
        elif key == "git":
            result[key] = [g for g in val if g]
        else:
            result[key] = val
    return result


def dork_queries(domain: str) -> list[str]:
    q = [
        f"site:{domain} ext:env", f"site:{domain} ext:sql", f"site:{domain} ext:log",
        f"site:{domain} ext:bak", f"site:{domain} ext:zip", f"site:{domain} ext:swp",
        f"site:{domain} inurl:api", f"site:{domain} inurl:swagger", f"site:{domain} inurl:actuator",
        f"site:{domain} \"index of /\"", f'"{domain}" "密码"', f'"{domain}" "账号"',
    ]
    return [quoted for quoted in (quote(x) for x in q)]
