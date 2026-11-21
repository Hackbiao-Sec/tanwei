"""搜索引擎统一入口（企业名 → 域名归属判定的证据来源）。

只做一件事：给定查询词，从多个公开引擎拿回「标题 + 链接 + 摘要」，供上层做归属打分。
不做判断，不依赖任何 key，也不依赖 AI。

为什么不用单一引擎：Bing 对中文企业名的召回偏向媒体转载，百度 / 搜狗 / 360 对「官网」
意图的结果差异很大；同一域名被多个引擎同时排在前面，是「这就是官网」最强的免费信号。
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

from ...utils import is_valid_domain, root_domain
from .passive import _get

_NAME = r"(?:q|query|word|wd)"
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/131.0.0.0 Mobile Safari/537.36")
PC_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
         "Chrome/131.0.0.0 Safari/537.36")


async def _fetch(url: str, params: dict, timeout: float = 18, mobile: bool = False,
                 referer: str = ""):
    """先直连，被 IP 级反爬挡了再走一次已配置代理。
    搜狗 / 360 封的是出口 IP（换个 UA 也一律进 antispider），换出口才通。

    referer：搜狗移动页对无 Referer 的请求一律 403（页面 564 字节的空壳），带上站内 Referer
    才给结果。这条不是可选优化，缺了整家引擎恒为 0 条。"""
    headers = {"User-Agent": MOBILE_UA if mobile else PC_UA,
               "Accept-Language": "zh-CN,zh;q=0.9",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    if referer:
        headers["Referer"] = referer
    for proxy in _proxies():
        # "" 表示强制直连（空串这一态：扫描机全局挂了代理时，国内引擎仍走本机出口）
        r = await _get(url, params, headers=headers, timeout=timeout, proxy=proxy)
        if r is not None and r.status_code == 200 and not _is_captcha(r):
            return r
    return None


@dataclass
class Hit:
    """一条搜索结果。title/snippet 是归属判定的证据，url 是要抽的域名。"""

    title: str = ""
    url: str = ""
    snippet: str = ""
    engine: str = ""
    rank: int = 0          # 引擎结果里的名次（0 起），归属判定按名次加权

    @property
    def domain(self) -> str:
        m = re.match(r"https?://([a-z0-9.\-]+)", self.url, re.I)
        return (m.group(1).lower().strip(".") if m else "")

    @property
    def text(self) -> str:
        return f"{self.title} {self.snippet}"


@dataclass
class SearchOutcome:
    query: str = ""
    hits: list[Hit] = field(default_factory=list)
    engines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _clean(html: str) -> str:
    # 搜狗把高亮包成 <em><!--red_beg-->词<!--red_end--></em>：注释不去掉，
    # 标签替换会在标题里留下「瑞幸咖啡-视频」这种带顿号的怪串。
    s = re.sub(r"<!--.*?-->", "", html or "", flags=re.S)
    s = re.sub(r"<[^>]+>", "", s)
    s = (s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&quot;", '"')
          .replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">"))
    s = re.sub(r"\\u[0-9a-fA-F]{4}", "", s)          # JSON 里的转义残片，留着会被当成标题内容
    return re.sub(r"\s+", " ", s).strip()


_BING_CITE = re.compile(r"<cite[^>]*>\s*(?:https?://)?([a-z0-9.\-]+\.[a-z]{2,12})", re.I)


def _bing_real(href: str) -> str:
    """Bing 外部结果一律包在 /ck/a?…&u=a1<base64url> 里，u 后面那段就是真实地址。
    解不出来（新版 hsh 混编、站内结果）就返回空串，由调用方按 <cite> 展示域名兜底：
    返回 ck/a 这条跳转壳会把自己的域名记成 www.bing.com，一路绕过平台站过滤打到打分区。"""
    m = re.search(r"[?&]u=a1([A-Za-z0-9_\-]+)", href)
    if not m:
        return ""
    raw = m.group(1)
    try:
        url = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
    except Exception:
        return ""
    return url if re.match(r"https?://[a-z0-9]", url, re.I) else ""


async def _bing(query: str, count: int = 30, first: int = 1) -> list[Hit]:
    """Bing：<li class="b_algo"> 里 <h2><a href=…>标题</a>，<cite> 是展示域名"""
    r = await _fetch("https://www.bing.com/search",
                     {"q": query, "count": count, "first": first, "setlang": "zh-hans"}, 18)
    if r is None or r.status_code != 200:
        return []
    out: list[Hit] = []
    for blk in re.split(r'<li class="b_algo"', r.text)[1:]:
        a = re.search(r'<h2[^>]*>\s*<a[^>]+href="(https?://[^"]+)"', blk)
        if not a:
            continue
        title = re.search(r"<h2[^>]*>(.*?)</h2>", blk, re.S)
        snip = re.search(r'<p[^>]*class="[^"]*b_lineclamp[^"]*"[^>]*>(.*?)</p>', blk, re.S) \
            or re.search(r"<p[^>]*>(.*?)</p>", blk, re.S)
        url = _bing_real(a.group(1))
        if not url:
            cite = _BING_CITE.search(blk)
            if not cite:
                continue
            url = f"https://{cite.group(1)}"
        out.append(Hit(title=_clean(title.group(1)) if title else "",
                       url=url, snippet=_clean(snip.group(1)) if snip else "",
                       engine="bing", rank=len(out)))
    return out


_RSS_ITEM = re.compile(r"<item>(.*?)</item>", re.S)


def _xml_text(raw: str) -> str:
    """RSS 里的标题/摘要带 CDATA 与实体，统一还原成纯文本"""
    s = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", raw or "", flags=re.S)
    s = s.replace("<![CDATA[", "").replace("]]>", "")
    s = (s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
          .replace("&apos;", "'").replace("&#39;", "'").replace("&amp;", "&"))
    return _clean(s)


async def _bing_rss(query: str) -> list[Hit]:
    """Bing 的 RSS 形态：PC 网页版把外链包进 /ck/a?…&u=a1<base64>，RSS 直接给明文 <link>，
    且不带任何 JS / 挑战页 —— 国内直连就 200，是当前唯一能稳定给出真实站点的中文检索口。

    <title> 常写作「lkcoffee.com - 瑞幸咖啡」：根域在前、站点名在后，正好是判品牌的强证据，
    所以标题原样保留，不做裁剪。

    出口很关键（2026-11-08 实测）：补上 mkt=zh-CN 后，直连出 10 条中文站；走 7897 代理
    同样参数只回 15KB 无 <item> 的空壳，或干脆回别的查询的陈旧结果。RSS 这一路必须直连，
    不能用 _fetch 的「直连被挡再走代理」：代理这次不是救火，是把好结果换掉。"""
    for url, params in (("https://cn.bing.com/search",
                         {"q": query, "format": "rss", "count": 30,
                          "mkt": "zh-CN", "setlang": "zh-hans"}),
                        ("https://www.bing.com/search",
                         {"q": query, "format": "rss", "count": 30})):
        r = await _get(url, params, headers={"User-Agent": PC_UA,
                                             "Accept-Language": "zh-CN,zh;q=0.9"},
                       timeout=18, proxy="")
        if r is None or r.status_code != 200 or "<item" not in r.text:
            continue
        out = _rss_hits(r.text, "bing_rss")
        if out:
            return out
    return []


def _rss_hits(text: str, engine: str) -> list[Hit]:
    out: list[Hit] = []
    for blk in _RSS_ITEM.findall(text):
        link = re.search(r"<link>(.*?)</link>", blk, re.S)
        if not link:
            continue
        url = _xml_text(link.group(1)).strip()
        if not url.startswith("http"):
            continue
        title = re.search(r"<title>(.*?)</title>", blk, re.S)
        desc = re.search(r"<description>(.*?)</description>", blk, re.S)
        out.append(Hit(title=_xml_text(title.group(1))[:120] if title else "", url=url,
                       snippet=_xml_text(desc.group(1))[:300] if desc else "",
                       engine=engine, rank=len(out)))
    return out


_TT_HOST = re.compile(r'&quot;host&quot;:&quot;([A-Za-z0-9.\-]{4,120})&quot;')
# h5_url 在 cr-params 里是 URL 编码过的，分隔符成了 %26 / %3D，所以编码值与明文两种写法都要收
_TT_URL = re.compile(r'h5_url(?:=|%3D)(https?(?:%3A|:)(?:%2F|/){2}[^&"\'\s%]{3,400})', re.I)
# 一条结果的边界：头条把每条结果的 title / url / h5_url 串在同一个 cr-params 属性里。
# 早先版本把 host、标题、h5_url 各抽成一个列表再按下标配对，长查询里两者个数不等，
# 标题整体错位（抽成 ":\\"瑞幸 咖啡\\" 这种转义残片），「哪个域名是哪个站」的证据全废。
_TT_BLOCK = re.compile(r'<div class="result-content"[^>]*?(?:real-index="\d+")?[^>]*?>', re.S)
_TT_GID = re.compile(r'&quot;(?:gid|title|url|host)&quot;:&quot;')   # 结果数据区起点（JSON 形态）
_TT_T_PLAIN = re.compile(r'title":"(.{2,200}?)","url":"')


def _tt_title(raw: str) -> str:
    t = _clean(raw.replace("\\/", "/").replace('\\"', '"').replace("&#x3D;", "="))
    return t.strip(' :,"\\')


async def _toutiao(query: str) -> list[Hit]:
    """头条搜索：每条结果是一个 <div class="result-content" …>，块首 cr-params 属性里
    同时写着 title、article.zlink 跳转链与 h5_url（URL 编码的真实地址）。
    标题、主机必须取自同一个块，块内取第一个外部站点。
    它给的是主机名而不是完整路径，所以拼成根域首页当线索用。"""
    r = await _fetch("https://so.toutiao.com/search", {"keyword": query, "pd": "synthesis"}, 20)
    if r is None or r.status_code != 200:
        return []
    text = r.text
    # 先把官网卡捞出来：它带「查询词就是这站」的判定与首帧静态资源，比 cr-params 里那条空标题
    # 有用得多；同一主机随后按 seen 去重，cr-params 那轮不会重复产出。
    out: list[Hit] = []
    seen: set[str] = set()
    for h in _tt_ala(text):
        root = root_domain(urlparse(h.url).hostname or "") or ""
        if root and root not in seen:
            seen.add(root)
            out.append(h)
    marks = [m.start() for m in _TT_BLOCK.finditer(text)]
    if not marks:
        for h in _toutiao_json(text):      # 新版无 result-content 外壳时走 JSON 分块
            root = root_domain(urlparse(h.url).hostname or "") or ""
            if root and root not in seen:
                seen.add(root)
                out.append(h)
        return out
    marks.append(len(text))
    out: list[Hit] = []
    seen: set[str] = set()
    for i in range(len(marks) - 1):
        blk = text[marks[i]:marks[i + 1]][:4000]   # 只要本块的 cr-params 与卡片头，避免吃进下一条
        t = ""
        plain = _TT_T_PLAIN.search(blk)
        if plain:
            t = _tt_title(plain.group(1))
        else:
            q = re.search(r'&quot;title&quot;:&quot;(.{2,200}?)&quot;', blk)
            if q:
                t = _tt_title(q.group(1))
        _tt_emit(blk, t, out, seen)
    return out


def _tt_emit(blk: str, title: str, out: list[Hit], seen: set[str],
             official: bool = False) -> None:
    """块内找第一个外部站点：h5_url 优先（带真实地址），再退回 host 字段。一条结果只认一个站。"""
    cands: list[str] = []
    for u in _TT_URL.findall(blk):
        try:
            host = urlparse(unquote(u)).hostname or ""
        except Exception:
            host = ""
        if host and not _is_tt_self(host):
            cands.append(host)
    for h in _TT_HOST.findall(blk):
        if not _is_tt_self(h):
            cands.append(h)
    for h in cands:
        h = h.lower().strip(".")
        if h in seen or not is_valid_domain(h):
            continue
        seen.add(h)
        root = root_domain(h) or h
        note = "头条官网卡（查询词即该站）" if official else "头条结果命中主机"
        out.append(Hit(title=title[:120], url=f"https://{root}/",
                       snippet=f"{note} {h}", engine="toutiao", rank=len(out)))
        return


# 头条新版把每条结果的数据放在 <script data-for="ala-data" data-id="67-homepage_official-0">
# 里：`cell_type:67` 是**官网卡**（查询词被头条判定为该站自身），卡里还有 preload 的全部静态
# 资源地址，等于官方给出的「这站就是这个查询词」的背书。cr-params 里的 title 在官网卡上恒为空串，
# 只按 cr-params 解析会把这层背书整段丢掉，最后只剩一条无标题的裸域名。
_TT_ALA = re.compile(
    r'<script data-for="ala-data"[^>]*data-id="(\d+)-([a-z_]+)-(\d+)"[^>]*>(.*?)</script>',
    re.S)
_TT_PRELOAD = re.compile(r'"(?:html|js|css)":\[(.*?)\]', re.S)


def _tt_ala(text: str) -> list[Hit]:
    """从 ala-data 卡片取 (站点主机, 官网卡标记, 首帧地址)。"""
    out: list[Hit] = []
    seen: set[str] = set()
    for cell, kind, _idx, body in _TT_ALA.findall(text or ""):
        hosts: list[str] = []
        for blob in _TT_PRELOAD.findall(body):
            for u in re.findall(r'"(https?://[^"]+)"', blob):
                try:
                    h = urlparse(u).hostname or ""
                except Exception:
                    h = ""
                if h and not _is_tt_self(h):
                    hosts.append(h)
        for u in _TT_URL.findall(body):
            try:
                h = urlparse(unquote(u)).hostname or ""
            except Exception:
                h = ""
            if h and not _is_tt_self(h):
                hosts.append(h)
        for h in _TT_HOST.findall(body):
            if not _is_tt_self(h):
                hosts.append(h)
        official = cell == "67" and "homepage_official" in kind
        for h in hosts:
            h = h.lower().strip(".")
            if h in seen or not is_valid_domain(h):
                continue
            seen.add(h)
            root = root_domain(h) or h
            note = "头条官网卡（查询词即该站）" if official else "头条结果命中主机"
            out.append(Hit(title="", url=f"https://{root}/",
                           snippet=f"{note} {h}", engine="toutiao", rank=len(out)))
            break
    return out


def _toutiao_json(text: str) -> list[Hit]:
    """兜底：结果数据以 &quot;title&quot;:&quot;…&quot;,"url":&quot;…&quot; 的 JSON 串出现时，
    按 title 切块，块内取 h5_url / host。"""
    out: list[Hit] = []
    seen: set[str] = set()
    marks = [m.start() for m in _TT_GID.finditer(text)] + [len(text)]
    for i in range(len(marks) - 1):
        blk = text[marks[i]:marks[i + 1]]
        t = ""
        q = re.search(r'&quot;title&quot;:&quot;(.{2,200}?)&quot;', blk)
        if q:
            t = _tt_title(q.group(1))
        _tt_emit(blk, t, out, seen)
    return out


def _is_tt_self(host: str) -> bool:
    return bool(re.search(r"(toutiao\.com|bytedance|pstatp|byteimg|bdurl|zlink\.|snssdk)", host, re.I))


async def _baidu(query: str, page: int = 0) -> list[Hit]:
    """百度：结果块 <h3 class="…t…"> 里 a[href]，摘要 class 含 c-abstract / c-span-last"""
    r = await _fetch("https://www.baidu.com/s", {"wd": query, "rn": 20, "pn": page * 20}, 15)
    if r is None or r.status_code != 200:
        return []
    text = r.text
    out: list[Hit] = []
    # 百度结果里外链被包成 href="http://www.baidu.com/link?url=…"，标题旁的 mu= 才是真实地址
    for blk in re.split(r'<div[^>]+class="result[^"]*"', text)[1:]:
        a = re.search(r"<h3[^>]*>.*?<a[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", blk, re.S)
        if not a:
            continue
        real = re.search(r'mu="([^"]+)"', blk)
        url = real.group(1) if real else a.group(1)
        snip = re.search(r'<span[^>]*class="[^"]*content-right[^"]*"[^>]*>(.*?)</span>', blk, re.S) \
            or re.search(r'<div[^>]*class="[^"]*c-abstract[^"]*"[^>]*>(.*?)</div>', blk, re.S)
        if not url.startswith("http"):
            continue
        out.append(Hit(title=_clean(a.group(2))[:120], url=url,
                       snippet=_clean(snip.group(1)) if snip else "", engine="baidu"))
    return out


async def _sogou(query: str) -> list[Hit]:
    """搜狗：结果块 class="vrwrap"，标题 a 的 href 常是 /link?url=，展示域名在 <cite>"""
    r = await _fetch("https://www.sogou.com/web", {"query": query}, 15)
    if r is None or r.status_code != 200:
        return []
    out: list[Hit] = []
    for blk in re.split(r'<div[^>]+class="(?:vrwrap|rb)"', r.text)[1:]:
        a = re.search(r"<h3[^>]*>.*?<a[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", blk, re.S)
        if not a:
            continue
        url = a.group(1)
        if url.startswith("/"):
            cite = re.search(r"<cite[^>]*>\s*(?:https?://)?([a-z0-9.\-]+\.[a-z]{2,10})", blk, re.I)
            url = f"https://{cite.group(1)}" if cite else ""
        if not url.startswith("http"):
            continue
        snip = re.search(r'<p[^>]*class="[^"]*str_info[^"]*"[^>]*>(.*?)</p>', blk, re.S)
        out.append(Hit(title=_clean(a.group(2))[:120], url=url,
                       snippet=_clean(snip.group(1)) if snip else "", engine="sogou"))
    return out


async def _so360(query: str) -> list[Hit]:
    """360 搜索：结果块 class="res-list"，a 的 data-mdurl / href 为真实地址"""
    r = await _fetch("https://www.so.com/s", {"q": query}, 15)
    if r is None or r.status_code != 200:
        return []
    out: list[Hit] = []
    for blk in re.split(r'<li[^>]+class="res-list', r.text)[1:]:
        a = re.search(r"<h3[^>]*>.*?<a[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", blk, re.S)
        if not a:
            continue
        md = re.search(r'data-mdurl="([^"]+)"', blk)
        url = md.group(1) if md else a.group(1)
        if not url.startswith("http"):
            continue
        snip = re.search(r'<p[^>]*class="[^"]*res-desc[^"]*"[^>]*>(.*?)</p>', blk, re.S)
        out.append(Hit(title=_clean(a.group(2))[:120], url=url,
                       snippet=_clean(snip.group(1)) if snip else "", engine="360"))
    return out


async def _ddg(query: str) -> list[Hit]:
    """DuckDuckGo html 端点：不需要 key，结果是 result__a 里的 uddg 跳转链接。"""
    r = await _fetch("https://html.duckduckgo.com/html/", {"q": query}, 18)
    if r is None or r.status_code != 200:
        return []
    out: list[Hit] = []
    for m in re.finditer(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', r.text, re.S):
        href = m.group(1)
        real = re.search(r"[?&]uddg=([^&]+)", href)
        url = unquote(real.group(1)) if real else href
        if not url.startswith("http"):
            continue
        tail = r.text[m.end():m.end() + 900]
        snip = re.search(r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', tail, re.S)
        out.append(Hit(title=_clean(m.group(2))[:120], url=url,
                       snippet=_clean(snip.group(1))[:400] if snip else "", engine="ddg"))
    return out


def _mobile_get(url: str, params: dict, timeout: float = 18, proxy: str | None = None):
    """移动端搜索页用手机 UA：PC UA 会被直接打验证码，移动页面反而稳定返回结果。"""
    headers = {"User-Agent": MOBILE_UA, "Accept-Language": "zh-CN,zh;q=0.9",
               "Accept": "text/html,application/xhtml+xml"}
    return _get(url, params, headers=headers, timeout=timeout, proxy=proxy)


_CAPTCHA_MARK = ("qcaptcha", "antispider", "antip=", "captcha", "百度安全验证", "访问异常出错", "请输入验证码")


def _is_captcha(resp) -> bool:
    """验证码 / 拦截页：状态码也是 200，只能看落地地址和很短的开头正文。"""
    if resp is None:
        return True
    head = (resp.text or "")[:3000]
    if any(m in str(resp.url) for m in _CAPTCHA_MARK):
        return True
    return any(m in head for m in _CAPTCHA_MARK)


# 结果块里真实地址常藏在属性或跳转参数里（m.so.com/jump?u=…、data-pcurl="…"、百度跳转壳），
# 只解析 <a href> 会全部拿到跳转壳，包名也一起丢掉。
# 注意 360 的结果块属性是裸值（class=alink / data-pcurl=https://…，没有引号），所以这里不靠引号切。
_SHELL = re.compile(r"https?://(?:[\w\-]+\.)*(?:baidu|so|sogou)\.com/(?:link|jump|from|s)\b", re.I)
_MARKET_ID = re.compile(r"(?:sj\.qq\.com/appdetail/[\w.]+|app\.mi\.com/details\?id=[\w.]+|"
                        r"[?&]pkgname=[\w.]+|apps\.apple\.com/[a-z]{2}/app/[^\s\"'<>]{2,120}|"
                        r"apkpure\.com/[^\s\"'<>]{2,120})", re.I)


def _real_urls(html: str) -> list[str]:
    """把页面里出现的真实地址还原出来：裸 URL、data-pcurl、URL 编码的跳转参数都覆盖。"""
    raw = re.findall(r"https?://[^\s\"'<>\\)]+", html)
    raw += [unquote(u) for u in re.findall(r"https?%3A%2F%2F[^&\"'<>\s]{5,300}", html)]
    out: list[str] = []
    for u in raw:
        u = u.replace("&amp;", "&").rstrip(",;")
        cand = u
        for _ in range(2):
            m = re.search(r"[?&](?:u|url|target|to)=([^&]+)", cand)
            if not m:
                cand = unquote(cand)
                m = re.search(r"[?&](?:u|url|target|to)=([^&]+)", cand)
                if not m:
                    break
            cand = unquote(m.group(1))
        cand = unquote(cand).replace("&amp;", "&").split("#")[0]
        if cand.startswith("http") and not _SHELL.match(cand):
            out.append(cand)
    return list(dict.fromkeys(out))


def _block_hits(html: str, engine: str, title_re: str = r"<h3[^>]*>(.*?)</h3>") -> list[Hit]:
    """按结果块切分：标题和摘要给归属证据，块内市场链接给包名 / AppID。
    块切不出来（不同引擎骨架不一样）时返回空，由调用方走整页兜底。"""
    out: list[Hit] = []
    blocks = re.split(r'<div\s+class=["\']?[^"\'>]*res-list', html)[1:]
    for blk in blocks:
        title = re.search(title_re, blk, re.S)
        t = _clean(title.group(1))[:120] if title else ""
        snip = re.search(r'class=["\']?[^"\'>]*summary[^>]*>(.*?)</div>', blk, re.S)
        sn = _clean(snip.group(1))[:300] if snip else ""
        main = re.search(r"<a[^>]+href=[\"']?([^\"'\s>]+)", blk)
        link = main.group(1) if main else ""
        if link:
            urls = _real_urls(link) or ([link] if link.startswith("http") else [])
            for u in urls:
                out.append(Hit(title=t, url=u, snippet=sn, engine=engine))
        for u in _real_urls(blk):
            if _MARKET_ID.search(u):
                out.append(Hit(title=t, url=u, snippet=sn, engine=engine))
    return out


async def _first_ok(attempts: list) -> list[Hit]:
    """按顺序尝试若干 (url, params, engine, proxy)，第一个没被验证码拦住的就用它。
    直连稳定被拦时换成走代理再试一次 —— 家宽出口被墙得更宽松，但工具不该依赖代理可用。
    四组 URL×出口加起来能拖到 40s 以上，给整组一个总预算，超了直接认这一次没结果。"""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _ATTEMPT_BUDGET
    for url, params, engine, proxy in attempts:
        left = deadline - loop.time()
        if left < 3:
            break
        r = await _mobile_get(url, params, proxy=proxy, timeout=left)
        if r is None or r.status_code != 200 or _is_captcha(r) or "antispider" in str(r.url):
            continue
        out = _block_hits(r.text, engine)
        out += _url_only_hits(r.text, engine)
        out += _wx_hits(r.text, engine)
        if out:
            return out[:40]
    return []


def _proxies() -> list:
    """搜索页在国内直连常被拦，给一次走已配置代理的机会（没过代理就只试直连）。
    "" 表示强制直连：扫描机全局开了代理时，国内引擎的正确出口是本机，
    不能因为配置里有代理就一律绕出国（sogou 走 7897 直接 antispider）。
    下游 _get 把 "" 当直连，None 当「用配置代理」。"""
    from .passive import _proxy
    p = _proxy()
    return [""] + ([p] if p else [])


async def _baidu_m(query: str) -> list[Hit]:
    """百度：PC 页基本稳定给验证码，移动页偶发放行。
    结果链接几乎全是 m.baidu.com/from=… 跳转壳，真实地址在块内属性/编码串里。"""
    attempts = [(u, {"word": query}, "baidu_m", p) for p in _proxies() for u in
                ("https://m.baidu.com/s", "https://www.baidu.com/s?wd=" + query)]
    return await _first_ok(attempts)


async def _so360_m(query: str) -> list[Hit]:
    """360：真实地址在 data-pcurl / m.so.com/jump?u= 里，sj.qq.com 的包名连在路径上。
    直连容易被 qcaptcha 拦，走代理时 PC 页和移动页都稳定出结果。"""
    attempts = [(u, {"q": query}, "360_m", p) for p in _proxies() for u in
                ("https://www.so.com/s", "https://m.so.com/s")]
    return await _first_ok(attempts)


# 落在这些站上的命中一律不进归属打分：它们本身是「被查的对象库」（百科/工商/字典/新闻），
# 不是企业的业务站。真正要把平台站挡在资产外的一次性过滤在 enterprise._is_platform，
# 这里不重复做，否则「拼多多」「美团」这种平台自身官网会被连带扔掉。
_REF_SITES = ("baike.baidu.com", "baike.sogou.com", "wikipedia.org", "wikiwand.com",
              "zhihu.com", "tianyancha.com", "qcc.com", "qixin.com", "aiqicha.baidu.com",
              "kanzhun.com", "maimai.cn", "liepin.com", "zhipin.com", "lagou.com",
              "eastmoney.com", "xueqiu.com", "sina.com.cn", "sohu.com", "163.com/docs",
              "csdn.net", "cnblogs.com", "jianshu.com", "douban.com", "maigoo.com",
              "cr173.com", "guguzhu.com", "jxdown.com", "onlinedown.net", "duote.com",
              "52pojie.cn", "jingyan.baidu.com", "ipa.store")
# 字典 / 汉字解释页：引擎把中文企业名当成单字在查时的典型产物
_DICT_SITES = ("zdic.net", "zidian", "hanyuguoxue.com", "hgcha.com", "chagushici.com",
               "cidian", "guoxuedashi.net", "dict.", "youdao.com", "iciba.com",
               "xxjcy.com", "ciku5.com", "hydcd.com", "jitenon", "mojidic", "kanjipedia",
               "namedic", "kotobank", "kanji-jiten", "kanjitisiki", "minkan.co.jp")
_DICT_WORD = re.compile(r"(怎么读|拼音|部首|笔顺|的意思|解释|字典|词典|汉语|汉字|漢字|読み方)")


def _core_of(query: str) -> str:
    words = query.strip().replace('"', " ").split()
    return re.sub(r"[^\u4e00-\u9fa5A-Za-z0-9]", "", words[0]) if words else ""


def _is_ref(hit: Hit) -> bool:
    """百科 / 工商 / 新闻站：能给品牌别名，但永远不是企业自己的域名。"""
    d = hit.domain
    return any(d == s or d.endswith("." + s) for s in _REF_SITES)


def _is_degraded(hits: list[Hit], query: str) -> bool:
    """引擎没认出查询词、退回按首字查字典时出的结果。这类命中没有归属价值，
    留着会被当成企业证据污染打分。

    判定口径只看**字典/单字解释页**在整批里的占比：查「瑞幸咖啡」回来一堆日文汉字站
    （「漢字「瑞」の部首…」）就是这一批被降级了。中国引擎的回答页常常只有标题
    （「瑞幸咖啡 下载 - 搜狗应用」「瑞幸咖啡 lkcoffee.com」），标题里天然不会再出现企业名，
    所以「标题和查询词对不上」不算降级——那只说明这家引擎不吐摘要。"""
    if not query.strip() or not hits:
        return False
    head = _core_of(query)
    if len(head) < 3:
        return False
    bad = 0
    for h in hits:
        t = re.sub(r"[^\u4e00-\u9fa5A-Za-z0-9]", "", h.title)
        single = t == head[0] or (t.startswith(head[0]) and len(t) <= 12)
        if single or any(s in h.domain for s in _DICT_SITES) or _DICT_WORD.search(h.title):
            bad += 1
    return bad * 2 >= len(hits)


def _usable(hits: list[Hit], query: str) -> list[Hit]:
    """剔除降级批、以及百科/工商/字典页，剩下的才进归属打分。"""
    if _is_degraded(hits, query):
        return []
    return [h for h in hits if not _is_ref(h)]


async def _sogou_m(query: str) -> list[Hit]:
    """搜狗移动结果页：PC 页对裸请求直接 403（antispider），移动页照常给结果。
    结果块写作 <div class=vrResult id="sogou_vr_30010246_2">（属性不带引号），
    真实地址在该块 url= 参数里，data-packagename 直接给出 Android 包名。

    整页 URI 不能当线索：百科卡片（sogou_vr_30010462 那块）自带几十张图片 CDN，
    一路扫下去 70 条命中里 60 多条是 qqpublic.qpic.cn / inews.gtimg.com。
    所以只解析真的 vrResult 块，且每个块只认标题链接与摘要里的 url=。"""
    # Referer 必须是 /web/ 这一层：m.sogou.com/ 与裸请求一律 403（564 字节空壳），
    # 只有 https://m.sogou.com/web/ 给结果。缺这一个斜杠整家引擎恒为 0 条。
    r = await _fetch("https://m.sogou.com/web/searchList.jsp", {"keyword": query}, 18, mobile=True,
                     referer="https://m.sogou.com/web/")
    if r is None or r.status_code != 200:
        return []
    out: list[Hit] = []
    # 属性全不带引号的写法（<div class=vrResult id="sogou_vr_11023901_2">）也要切到，
    # 否则只剩带引号的那几个专题卡，正常结果一条都进不来
    blocks = [b for b in re.split(r'<div\s+class=["\']?vrResult\b', r.text)[1:] if "<h3" in b]
    for blk in blocks:
        # `<h3 class=vr-tit data-click-sugg-title><a …>` 是属性**不带引号**的写法，
        # 用 `<h3[^>]*>` 匹配会在属性值里提前断掉；而块开头到 <h3> 之间还有 <style>，
        # 直接用 `.*?</h3>` 会把整段 CSS 当成标题 —— 这正是标题恒为空、
        # 「厦门市特种设备检验检测院」这类地方机构拿不到搜索证据的直接原因。
        # 只取 <h3> 与 </h3> 之间那段，再从里面挑第一个 <a> 的可见文本。
        h3 = re.search(r"<h3\b(.*?)</h3>", blk, re.S)
        title = ""
        if h3:
            body = h3.group(1)
            inner = re.search(r"<a\b[^>]*>(.*?)</a>", body, re.S)
            title = _clean(inner.group(1) if inner else body)[:120]
        snip = re.search(r'<div class=["\']?clamp\d[^>]*>(.*?)</div>', blk, re.S) \
            or re.search(r'class=["\']?citeurl[^>]*>\s*<span>(.*?)</span>', blk, re.S)
        sn = _clean(snip.group(1))[:300] if snip else ""
        if not sn:
            # 移动页摘要常在 <a class="txt-summary …"> 的正文里，clamp 只包住第一段
            sm = re.search(r'class=["\']?txt-summary[^>]*>(.*?)</a>', blk, re.S)
            sn = _clean(sm.group(1))[:300] if sm else ""
        pkg = re.search(r'data-[Pp]ackagename=["\']?([A-Za-z0-9_.]{4,80})', blk)
        # 块内 url= 就是这条结果指向的站；同一块里标题与摘要重复给同一个 url，去重后取第一个
        urls = [u for u in _block_targets(blk) if not _SOGOU_SELF.search(u)]
        if not urls:
            continue        # 专题卡 / 应用聚合卡不带外站 url，别把同块图片 CDN 当结果
        for u in urls[:1]:
            out.append(Hit(title=title, url=u, snippet=sn, engine="sogou_m", rank=len(out)))
        if pkg:
            out.append(Hit(title=title, url=f"https://sj.qq.com/appdetail/{pkg.group(1)}",
                           snippet=sn, engine="sogou_m", rank=len(out)))
    return out


def _block_targets(blk: str) -> list[str]:
    """从结果块属性里取目标站：url= / pcurl= 后面跟 URL 编码地址，按出现顺序去重。"""
    out: list[str] = []
    for m in re.finditer(r"[?&`\s]((?:url|pcurl))=(https?%3A%2F%2F[^&\"'\s>]{6,300})", blk):
        u = unquote(m.group(2)).replace("&amp;", "&")
        if u.startswith("http") and u not in out:
            out.append(u)
    return out


# 搜狗自家与腾讯广告/埋点域：出现在检索页里但绝不是企业的站
_SOGOU_SELF = re.compile(r"(^|\.)(sogou\.com|sogoucdn\.com|sogou\.com\.web|gdt\.qq\.com|gdtimg\.cn|"
                         r"gtimg\.cn|cdn\.qq\.com|trace\.qq\.com|inlong\.qq\.com|qpic\.cn|"
                         r"html5\.qq\.com|docs\.qq\.com|qq\.com\.cn|myqcloud\.com|w3\.org|"
                         r"ssad\.qq\.com|p4psearch\.1688\.com)", re.I)


_YYB_ITEM = re.compile(r'"pkg_name"\s*:\s*"([A-Za-z][A-Za-z0-9_.]{4,80})".{0,400}?'
                       r'"name"\s*:\s*"([^"]{1,80})"', re.S)


async def _yyb(query: str) -> list[Hit]:
    """腾讯应用宝搜索页自带 SSR 数据：pkg_name + app_name 成对出现，一条就是一款应用。
    国内直连可用，不需要 key；只在按名称找包名时用（企业归属检索不走它）。"""
    r = await _fetch("https://sj.qq.com/search", {"q": query}, 20)
    if r is None or r.status_code != 200:
        return []
    out: list[Hit] = []
    for pkg, name in _YYB_ITEM.findall(r.text):
        if pkg.startswith(("com.tencent.android.qqdownloader",)):
            continue        # 页面自身的应用宝壳数据
        out.append(Hit(title=_clean(name)[:120], url=f"https://sj.qq.com/appdetail/{pkg}",
                       snippet=f"应用宝收录：{name} / {pkg}", engine="yyb", rank=len(out)))
    if not out:
        out += _url_only_hits(r.text, "yyb")
    return out[:30]


# 小程序在网页侧唯一稳定的登记形态是微信链接：公众号文章里的 #小程序://X/xxx、
# 分享卡片的 /s?…&scene=1（带 biz/appid）、以及小程序落地页 /mp/wxopen 之类。
_WX_LINK = re.compile(r"mp\.weixin\.qq\.com/(?:s|mp/appmsg|mp/wxopen|sph|sph/)", re.I)
_WX_BIZ = re.compile(r"[?&](?:__biz|appid)=(wx[0-9a-f]{16}|[\w=+/]{10,})", re.I)


def _wx_hits(html: str, engine: str) -> list[Hit]:
    """整页兜底里**只**捞微信链接。

    `_real_urls` 只认「市场详情 / 包名」形态，微信文章链接不是市场页，所以在原来的兜底里
    一条都留不下 —— 小程序这条面因此长期是空的。这里单独补一类。
    """
    out: list[Hit] = []
    for u in _real_urls(html):
        if _WX_LINK.search(u):
            out.append(Hit(title="页面明文微信链接", url=u, engine=engine))
    return out


def _url_only_hits(html: str, engine: str) -> list[Hit]:
    """整页兜底：市场详情页 / 包名 / AppID 只要出现在页面任何位置都算线索。"""
    out: list[Hit] = []
    for u in _real_urls(html):
        if _MARKET_ID.search(u):
            out.append(Hit(title="页面明文链接", url=u, engine=engine))
    for pkg in re.findall(r'"pkg_name"\s*:\s*"([A-Za-z][A-Za-z0-9_.]{4,80})"', html):
        if pkg.startswith("com.tencent.android.qqdownloader"):
            continue
        u = f"https://sj.qq.com/appdetail/{pkg}"
        if not any(h.url == u for h in out):
            out.append(Hit(title="页面内嵌包名", url=u, engine=engine))
    return out


async def search_packages(name: str) -> list[Hit]:
    """按应用名找 Android 包名：先问应用市场直查，再拿移动搜索兜底，只回市场详情形态的线索。
    只认与应用名对得上的那几条：引擎降级成「只查前两个字」时会回一堆同音应用。"""
    core = _core_of(name)
    out: list[Hit] = []
    # 移动版 360 被 qcaptcha 全面拦截（每查空跑 15s+）；搜狗移动页稳定给 data-packagename，
    # 应用宝直查最准但覆盖面窄，两条都走，命中即止。
    for fn in (_yyb, _sogou_m, _ddg):
        try:
            res = await fn(name)
        except Exception:
            continue
        got = [h for h in res if any(pkg in h.url for pkg in (
            "sj.qq.com/appdetail", "app.mi.com/details", "pkgname=", "apps.apple.com",
            "play.google.com/store/apps", "apps.apple.com/cn/app"))]
        got = [h for h in got if _matches_name(h, core)]
        out.extend(got)
        if out:
            break
    return out[:20]


def _matches_name(hit: Hit, core: str) -> bool:
    """标题里要有应用名的前两个字，才算这条也在说这个应用。"""
    if len(core) < 2:
        return True
    return core[:2] in hit.title or core[:2] in hit.snippet


def store_packages(text: str) -> list[str]:
    """从搜索结果文本里抽 Android 包名：只认可信市场链接形态，避免把普通域名当包名。"""
    pkgs: list[str] = []
    for pat in (r"appdetail/([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,})",
                r"details\?id=([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,})",
                r"[?&]pkgname=([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,})",
                r"apkpure\.com/(?:[a-z]{2}/)?[a-z0-9\-]+/([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,})"):
        pkgs += re.findall(pat, text)
    out: list[str] = []
    for p in pkgs:
        p = p.rstrip(".")
        if p.count(".") >= 2 and p not in out and not p.endswith((".com", ".cn", ".net", ".org")):
            out.append(p)
    return out


def store_appids(text: str) -> list[str]:
    """微信小程序 AppID：wx + 16 位十六进制，出现在分享链 / 收录页正文里。"""
    return list(dict.fromkeys(re.findall(r"\bwx[0-9a-f]{16}\b", text or "")))


ENGINES = {"bing": _bing, "bing_rss": _bing_rss, "toutiao": _toutiao,
           "baidu": _baidu, "sogou": _sogou, "360": _so360,
           "ddg": _ddg, "baidu_m": _baidu_m, "so360_m": _so360_m, "sogou_m": _sogou_m,
           "yyb": _yyb}
# 实测（家宽直连 + 7897 代理各试一遍，2026-11-08，逐个引擎单查询计时）：
#   toutiao   0.4～1s 出数，真实站埋在 h5_url / &quot;host&quot; 字段里，官网类词也稳排第一
#   sogou PC  0.9～1.1s，裸品牌能出 4～7 条；带「官网」的词会被降级成词典页（质量闸会剔）
#   bing_rss  0.3s 出数，但对「品牌 + 官网」整句会按首字降级，只对裸品牌词稳
#   bing      PC 版结果走 /ck/a 包装
#   baidu / baidu_m  间歇能出数（官网类词 19 条），裸品牌词空；其余时间撞 wappass 验证码
#   360 / so360_m    5～7s 才返回，经常空手，慢到会拖住整轮检索
#   ddg       走代理 14～18s 且结果块为空；yandex / yahoo → 验证码 / 超时
# 保留全部引擎是为了换网络环境后还能选出来，但默认集合只放秒级、常出数的四家。
DEFAULT_ENGINES = ("toutiao", "sogou", "sogou_m", "bing_rss", "baidu")
# 跟 DEFAULT_ENGINES 并行跑，凑不满再补：慢引擎不放进默认集合，否则一次检索就要等十几秒。
SLOW_ENGINES = ("bing", "360", "baidu_m", "so360_m", "ddg")
# 这些引擎在**下一轮**兜底时用：默认集合全空/全降级时补跑，仍拿不到才算这词没结果。
# sogou_m 曾经只挂在这里而从没被调用过（常量定义了但全项目无人引用），
# 结果就是「厦门市特种设备检验检测院」这类地方机构永远查不出资产 ——
# 默认四家里 bing_rss 对长中文名恒回别的查询的缓存结果、sogou PC 会降级成词典页、
# toutiao 只认消费类品牌，唯一能按全名命中官网的移动页被跳过。现在它进默认集合。


# 搜狗 / 360 按出口 IP 封：同一个 IP 连打十几次就整段 antispider，再换 UA 也没用。
# 所以同一引擎的请求串行（相邻两次之间留 INTERVAL），不同引擎之间并行。
# 结果缓存 10 分钟：一词多引擎、多阶段（归属打分 / 小程序 / App）会反复问同一批词，
# 缓存命中既省时间也直接免掉重复请求，是防封最有效的一层。
_CACHE_TTL = 600.0
_INTERVAL = 1.2
# 一次检索里四组 URL×出口能拖到 40s，整组给个总预算；连续空手就冷却，别拿它拖住整条检索。
_ATTEMPT_BUDGET = 8.0
_COOLDOWN = 180.0
_COOLDOWN_AFTER = 2
# 单个词空手只短冷却：换词后还该被问到，不然第一个词没命中就把引擎整轮踢掉。
_SLOW_COOLDOWN = 6.0
# 引擎近期响应耗时（秒，指数平滑）。慢引擎进不了预探，避免预热就吃掉整轮预算。
_engine_lat: dict[str, float] = {}
_PROBE_MAX_LAT = 5.0
_cache: dict[tuple[str, str], tuple[float, list[Hit]]] = {}
_engine_locks: dict[str, asyncio.Lock] = {}
_engine_last: dict[str, float] = {}
_engine_fail: dict[str, tuple[int, float]] = {}


def _note_engine(name: str, got: int) -> None:
    """记录一次引擎产出。连续空手就冷却，避免每轮都去撞同一堵反爬墙。"""
    if got:
        _engine_fail[name] = (0, 0.0)
        return
    fails, _ = _engine_fail.get(name, (0, 0.0))
    fails += 1
    if fails >= _COOLDOWN_AFTER:
        _engine_fail[name] = (fails, asyncio.get_running_loop().time() + _COOLDOWN)


async def _engine_call(name: str, query: str, timeout: float) -> list[Hit]:
    ck = (name, query)
    now = asyncio.get_running_loop().time()
    hit = _cache.get(ck)
    if hit and now - hit[0] < _CACHE_TTL:
        return list(hit[1])
    fails, until = _engine_fail.get(name, (0, 0.0))
    if now < until and ck not in _cache:
        return []
    lock = _engine_locks.setdefault(name, asyncio.Lock())
    failed = False
    res: list[Hit] = []
    async with lock:
        now = asyncio.get_running_loop().time()
        hit = _cache.get(ck)
        if hit and now - hit[0] < _CACHE_TTL:
            return list(hit[1])
        if now < _engine_fail.get(name, (0, 0.0))[1] and ck not in _cache:
            return []
        wait = _INTERVAL - (now - _engine_last.get(name, 0.0))
        if wait > 0:
            await asyncio.sleep(wait)
        lat = asyncio.get_running_loop().time() - now
        try:
            res = await asyncio.wait_for(ENGINES[name](query), timeout=timeout)
            if res:
                _engine_lat[name] = 0.7 * _engine_lat.get(name, lat) + 0.3 * min(lat, 20.0)
        except Exception:
            # 超时/网络错误也要计入冷却：一个引擎死掉还每轮等满 timeout 就是空转
            res, failed = [], True
        finally:
            _engine_last[name] = asyncio.get_running_loop().time()
    if failed:
        _note_engine(name, 0)
        return []
    if not res:
        # 空手多半是「这个词刚好没命中」（360 对长尾词经常 0 条），不代表引擎不可用：
        # 只做短冷却，换词再试；连续空手才进长冷却，否则一个词就能把整轮检索拖到预算外。
        fails, _ = _engine_fail.get(name, (0, 0.0))
        _engine_fail[name] = (fails + 1, asyncio.get_running_loop().time() + _SLOW_COOLDOWN)
    if len(_cache) > 2000:
        for k in sorted(_cache, key=lambda k: _cache[k][0])[:1000]:
            _cache.pop(k, None)
    if res:
        _cache[ck] = (asyncio.get_running_loop().time(), list(res))
    _note_engine(name, len(res))
    return list(res or [])


async def _drain(tasks: dict[str, asyncio.Task], out: SearchOutcome, query: str) -> None:
    """把已经结束的引擎结果并进 out；仍在跑的留着继续跑。"""
    for name, t in list(tasks.items()):
        if not t.done() or t.cancelled():
            continue
        tasks.pop(name, None)
        try:
            res = t.result()
        except Exception:
            out.errors.append(f"{name}: 请求失败")
            continue
        if res and _is_degraded(res, query):
            out.errors.append(f"{name}: 降级结果（只按首字查字典）")
            continue
        if res:
            keep = _usable(res, query)
            if not keep:
                out.errors.append(f"{name}: 只回了百科/字典类页面")
                continue
            out.engines.append(name)
            out.hits.extend(keep)


def enabled_engines(engines: tuple[str, ...] = DEFAULT_ENGINES) -> tuple[str, ...]:
    """按渠道开关过滤引擎：停用的那几路不参与检索，也不占预算。"""
    from .. import channels as channels_mod

    return tuple(e for e in engines if channels_mod.engine_on(e))


async def search(query: str, engines: tuple[str, ...] = DEFAULT_ENGINES,
                 timeout: float = 22, budget: float = 7.0) -> SearchOutcome:
    """多引擎检索。任何引擎失败都只记 errors，不影响其余结果。

    `budget` 是**首轮**等待窗口，不是总时限：到点先把已经出数的结果交出去，但仍在飞的请求
    会再等一个窗口。之前到点就把未完成的丢掉、只在一条都没拿到时才报错，等于把 3.8s 才返回
    的引擎结果静默扔了 —— 而中文机构全名恰恰只有那一家按查询词处理。慢引擎的结果值这个钱：
    整轮最多等到 `budget * 2`，仍不出数才算这个词没结果。
    """
    picked = [e for e in enabled_engines(engines) if e in ENGINES]
    out = SearchOutcome(query=query)
    if not picked:
        return out
    tasks = {e: asyncio.create_task(_engine_call(e, query, timeout)) for e in picked}
    if tasks:
        await asyncio.wait(list(tasks.values()), timeout=budget)
    await _drain(tasks, out, query)
    if tasks:
        # 第二轮只等服务那些真的还在跑的引擎；到点仍不返回才放弃。
        await asyncio.wait(list(tasks.values()), timeout=max(budget, 6.0))
    late = []
    await _drain(tasks, out, query)
    late = list(tasks)
    if late and not out.hits:
        out.errors.append(f"{'/'.join(late)} 超预算未返回")
    if not out.hits:
        # 默认集合一条可用结果都没有：补跑慢引擎再试一次。
        # 这几家慢，但中文机构全名只在这几家才被当查询词处理（默认集合会降级成城市词或字典词），
        # 一条不补就等于「这个词查不到」——那正是地方事业单位始终出不来资产的原因。
        spare = [e for e in SLOW_ENGINES if e in ENGINES and e not in picked
                 and e in enabled_engines((e,))]
        if spare:
            retry = {e: asyncio.create_task(_engine_call(e, query, timeout)) for e in spare}
            if retry:
                await asyncio.wait(list(retry.values()), timeout=budget)
            for name, t in retry.items():
                if not t.done() or t.cancelled():
                    continue
                try:
                    res = t.result()
                except Exception:
                    out.errors.append(f"{name}: 请求失败")
                    continue
                if res and _is_degraded(res, query):
                    out.errors.append(f"{name}: 降级结果（只按首字查字典）")
                    continue
                keep = _usable(res, query) if res else []
                if keep:
                    out.engines.append(name)
                    out.hits.extend(keep)
    return out


async def pick_engines(query: str, engines: tuple[str, ...] = DEFAULT_ENGINES,
                       probe: bool = True, timeout: float = 14.0) -> tuple[str, ...]:
    """此刻真能出结果的引擎，按 ENGINES 里的优先顺序返回。

    不能把任何一家写死当唯一来源：bing 对家宽出口长期返回降级结果（只按首字查字典），
    国内几家会按 IP 限速。probe=True 时拿真实查询词并发试一次，只有拿到非降级结果才算可用；
    全都不行就退回候选全集，让调用方按原来的多引擎并行跑（结果会进缓存，不浪费）。
    """
    now = asyncio.get_running_loop().time()
    engines = enabled_engines(engines)
    cand = [e for e in engines if e in ENGINES and now >= _engine_fail.get(e, (0, 0.0))[1]]
    if not cand:
        cand = [e for e in engines if e in ENGINES]
    # 近期量到过慢响应的引擎不进预探：预探跟正式检索抢的是同一条引擎锁，
    # 把一个 5s 的引擎拉进预探，等于让整轮检索先白等它一次。
    cand = [e for e in cand if _engine_lat.get(e, 0.0) < _PROBE_MAX_LAT] or cand
    if not probe or not cand:
        return tuple(cand)
    tasks = {e: asyncio.create_task(_engine_call(e, query, timeout)) for e in cand}
    if tasks:
        await asyncio.wait(list(tasks.values()), timeout=timeout + 1)
    good: list[str] = []
    degraded: list[str] = []
    for e in cand:
        t = tasks.get(e)
        if t is None or not t.done() or t.cancelled():
            if t is not None:
                t.cancel()
            continue
        try:
            res = t.result()
        except Exception:
            # 超时/连不上是引擎本身的问题，这次结果不留缓存
            _cache.pop((e, query), None)
            continue
        if res and not _is_degraded(res, query):
            good.append(e)
        elif res:
            degraded.append(e)
        if not res:
            # 空手不进缓存，否则真实检索会命中一条「空结果」
            _cache.pop((e, query), None)
    if not good:
        # 全部降级/空手时不能只退回默认集合就结束：默认集合对长中文机构名整批降级，
        # 退回它等于必然空手。把慢引擎也带上，让下游 search() 有机会补到真结果。
        extra = [e for e in SLOW_ENGINES if e in ENGINES and e not in cand
                 and e in enabled_engines((e,))]
        return tuple(cand + extra)
    # 只剔「降级」的引擎，不剔「这个词没命中」的：360 对「品牌 + 官方网站」这类长尾词
    # 经常 0 条，对裸品牌却能出十几条。把空手当失效，会把唯一稳的引擎踢出整轮检索。
    return tuple(e for e in cand if e not in degraded)


async def search_many(queries: list[str], engines: tuple[str, ...] = DEFAULT_ENGINES,
                      timeout: float = 22, budget: float = 20.0,
                      stat: dict | None = None) -> list[Hit]:
    """多条查询词并发，结果拍平去重（同一个 url 只留一条）。
    整批给一个总预算：一个引擎被反爬拖住时不能把整条采集链拖到几分钟。
    某个引擎空手就先给它单独记冷却，别让它拖累整批；空手引擎拿第一次的空结果，
    其余引擎照常出数。

    探活必须用**最长**那条词（2026-11-08 修正）：早先用 uniq[0]，也就是最短的裸品牌词。
    裸品牌词任何引擎都能出两三条「瑞幸咖啡是什么」的媒体页，探活一路通过；
    真正要跑的长词（「品牌 + 官网 / 小程序 appid」）才被切成单字查字典。
    结果就是整批引擎全「活着」，实际一条有用结果都没有 —— 这是信息搜集打偏的主因之一。"""
    uniq = [q for q in dict.fromkeys(q for q in queries if q)]
    if not uniq:
        return []
    engines = enabled_engines(engines)
    # 每条引擎这一轮到底活着还是死了：调用方（渠道面板）要能说清「哪一路失效」，
    # 光看最后拍平的结果分不出「没这个词」和「引擎被墙」。
    stat = stat if stat is not None else {}
    probe_q = max(uniq, key=len)
    # 先按每条引擎各探一条：拿不到结果的引擎直接摘掉，别让它在剩余查询词上继续拖预算
    probes = {b: asyncio.create_task(_engine_call(b, probe_q, timeout)) for b in engines}
    _, pending = await asyncio.wait(probes.values(), timeout=min(budget, timeout + 1))
    alive: list[str] = []
    for b, t in probes.items():
        if t in pending:
            t.cancel()
            stat[b] = "timeout"
        elif t.cancelled() or t.exception():
            stat[b] = "error"
        elif t.result():
            alive.append(b)
            stat[b] = "ok"
        else:
            stat[b] = "empty"
    if not alive:
        return []
    tasks = [asyncio.create_task(search(q, engines=tuple(alive), timeout=timeout))
             for q in uniq if q != probe_q]
    try:
        tail = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True),
                                     timeout=budget)
    except asyncio.TimeoutError:
        tail = []
    outs = []
    for b, t in probes.items():
        if b in alive and t.done() and not t.exception() and t.result():
            outs.append(SearchOutcome(query=probe_q, hits=t.result(), engines=[b]))
    outs += list(tail)
    seen: set[str] = set()
    flat: list[Hit] = []
    for oc in outs:
        if isinstance(oc, BaseException) or oc is None:
            continue
        for h in oc.hits:
            key = h.url.split("#")[0].rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            flat.append(h)
    return flat


def domains_of(hits: list[Hit], noise=None) -> dict[str, list[Hit]]:
    """把命中按根域聚合：同一根域多个子域出现，说明这是业务簇而不是单页镜像"""
    groups: dict[str, list[Hit]] = {}
    for h in hits:
        dom = h.domain
        if not dom or not is_valid_domain(dom):
            continue
        if noise and noise(dom):
            continue
        root = root_domain(dom) or dom
        groups.setdefault(root, []).append(h)
    return groups
