"""微信公众号采集。

只走公开、无需登录的通道，能拿到什么就记什么，拿不到就写进 notes，不编字段。

实测可用（2026-11-09）：
  · **发现**：移动端搜索 `site:mp.weixin.qq.com "<词>"`，命中全是
    `mp.weixin.qq.com/s?__biz=…&mid=…&idx=…&sn=…` 文章直链，URL 里就带 `__biz`，
    不用进正文就能按号聚合。
  · **身份**：`mp.weixin.qq.com/mp/homepage?__biz=…&hid=N`（约 44 KB）返回
    `nickname:"…"` 与 `gh_…`。hid 要按 1→2→3 依次试，试错回「错误」页。
  · **正文**：文章页（约 3.7 MB）里有 `var biz`、`var user_name`（gh_）、
    `id="js_name"`（昵称）、`var msg_title`、`var ct`（发布时间戳）、
    `var ori_head_img_url`；部分文章有 `var msg_source_url`（阅读原文）——那是
    公众号真正在用的业务域名，比正文里的引用更值钱。

实测不可用（别再试）：
  · `mp/getverifyinfo`、`mp/waverifyinfo`、`mp/appmsgalbum`、`mp/profile_ext`
    一律回 2034 B「验证」页，带微信号 UA / 文章 Referer / 完整 mid+idx+sn+chksm
    也过不去 —— 所以**认证主体拿不到**，本条只按昵称与实体名做匹配，字段留空并注明来源。
  · 搜狗微信结果页当前是反爬验证页（antispider），无文章链接、无 `__biz`。

相关性必须自己判：`site:` 检索对品牌词是宽松的（搜「瑞幸咖啡」会带出只是提到它的
第三方账号），所以每条都要用昵称 / 文章标题回比目标词，对不上的标 `relevance=low`，
由调用方决定要不要。宁可少给，不给一堆同名噪声。
"""

from __future__ import annotations

import asyncio
import html
import re
from dataclasses import dataclass, field

from ...config import config
from ...utils import is_valid_domain, root_domain
from ..sources import search as web
from ..sources.passive import _get

# 文章直链里的 __biz，base64 形态可能带 + / =
_BIZ_IN_URL = re.compile(r"__biz=([A-Za-z0-9+/=]{8,})")
_BIZ_ARG = re.compile(r"^[A-Za-z0-9+/=]{8,}$")
_GH_RE = re.compile(r"\bgh_[0-9a-z]{10,}\b", re.I)
_NICK_JS = re.compile(r"""nickname\s*:\s*["']([^"']{1,80})["']""")
_NICK_ID = re.compile(r"""id=["']js_name["'][^>]*>\s*([^<]{1,80})""")
_BIZ_VAR = re.compile(r"""var\s+biz\s*=\s*["']([^"']+)["']""")
_GH_VAR = re.compile(r"""var\s+user_name\s*=\s*["']([^"']+)["']""")
_TITLE_VAR = re.compile(r"""var\s+msg_title\s*=\s*['"]([^'"]{1,200})['"]""")
_CT_VAR = re.compile(r"""var\s+ct\s*=\s*["'](\d{9,13})["']""")
_SRC_VAR = re.compile(r"""var\s+msg_source_url\s*=\s*["']([^"']{0,400})["']""")
_HEAD_VAR = re.compile(r"""var\s+ori_head_img_url\s*=\s*["']([^"']{0,300})["']""")
_PAGE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,10})\b", re.I)
SUBJECT_RE = re.compile(r"([\u4e00-\u9fa5（）()]{4,40}?(?:有限责任公司|股份有限公司|有限公司|集团|"
                        r"设计院|检测院|检验院|研究院|科学院|研究所|事务所|基金会|委员会|"
                        r"工作室|中心|大学|学院|医院|银行|协会|院|所|局|厅|委|站))")

# 微信自家与常见 CDN：出现在文章页里是模板资源，不是目标业务域
_KNOWN_THIRD = ("weixin.qq.com", "qq.com", "qlogo.cn", "gtimg.com", "qpic.cn", "wx.qq.com",
                "tencent.com", "wechat.com", "w3.org", "bootstrapcdn.com", "jsdelivr.net",
                "googleapis.com", "gstatic.com", "aliyuncs.com", "myqcloud.com", "qiniu.com",
                "bcebos.com", "umeng.com", "sentry.io", "byteimg.com", "music.126.net")
_NOISE_TAIL = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".json",
               ".woff", ".woff2", ".ico", ".xml", ".html", ".htm", ".mp4", ".m3u8")
# 收录站 / 导航站：能当线索来源，不能当自有域
_DIRECTORY = ("baidu.com", "sogou.com", "so.com", "bing.com", "zhihu.com", "jianshu.com",
              "csdn.net", "juejin.cn", "github.com", "gitee.com", "douban.com", "weibo.com",
              "toutiao.com", "163.com", "sina.com.cn", "sohu.com", "ifeng.com", "36kr.com",
              "mp.weixin.qq.com")


def _hop(aw, timeout: float):
    """单跳硬上限：调用方现场造协程再包，囤着再造会在超时后留下悬空任务。"""
    return asyncio.wait_for(aw, timeout=timeout)


def _clean(raw: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw or ""))).strip()


def _third_party(domain: str) -> bool:
    d = domain.lower()
    return any(d == x or d.endswith("." + x) for x in _KNOWN_THIRD)


def _directory(domain: str) -> bool:
    d = domain.lower()
    return any(d == x or d.endswith("." + x) for x in _DIRECTORY)


def _domains_of(text: str) -> set[str]:
    out: set[str] = set()
    for m in DOMAIN_RE.findall(text or ""):
        d = m.lower()
        if d.endswith(_NOISE_TAIL) or not is_valid_domain(d):
            continue
        if _third_party(d) or _directory(d):
            continue
        out.add(root_domain(d) or d)
    return out


def _page_title(text: str) -> str:
    m = _PAGE_TITLE.search(text or "")
    return _clean(m.group(1)) if m else ""


def target_tokens(target: str) -> list[str]:
    """把目标词拆成回比用的几种写法：全名、去法人后缀、再去行政区前缀。

    「厦门市特种设备检验检测院」→ 全名 / 厦门市特种设备检验检测 / 特种设备检验检测，
    昵称里出现任意一种才算同一个号，避免把只是提到品牌的第三方号收进来。
    """
    t = (target or "").strip()
    if not t:
        return []
    toks = [t]
    core = re.sub(r"(?:股份)?有限(?:责任)?公司$|集团$|公司$|工作室$|研究院$|中心$|大学$|"
                  r"学院$|医院$|银行$|检测院$|检验院$|院$", "", t)
    if len(core) >= 2:
        toks.append(core)
    short = re.sub(r"^[\u4e00-\u9fa5]{2,8}?(?:省|市|自治区|特别行政区)", "", core)
    if len(short) >= 3:
        toks.append(short)
    # 品牌简称通常 2～6 字：只在前两步都没命中时兜底用，避免过宽
    return list(dict.fromkeys(x for x in toks if x))


@dataclass
class Mp:
    name: str = ""             # 公众号昵称
    wxid: str = ""             # gh_ 开头的原始 ID
    biz: str = ""              # __biz，抓文章 / 主页的唯一键
    subject: str = ""          # 认证主体（公开通道拿不到时留空）
    subject_source: str = ""   # nickname / none
    intro: str = ""
    relevance: str = "unknown"  # high / low / unknown
    domains: set = field(default_factory=set)
    articles: list = field(default_factory=list)   # [{title, url, ts}]
    evidence: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    avatar: str = ""
    notes: list = field(default_factory=list)
    key: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "wxid": self.wxid, "biz": self.biz,
                "subject": self.subject, "subject_source": self.subject_source,
                "intro": self.intro, "relevance": self.relevance,
                "domains": sorted(self.domains), "articles": self.articles[:5],
                "evidence": self.evidence[:6], "sources": self.sources,
                "avatar": self.avatar, "notes": self.notes}


def _wx_cookie() -> str:
    """公众号页面的登录态。没配就是空串，公开号照样能抓。"""
    for path in (("sources", "weixin", "cookie"), ("weixin", "cookie")):
        try:
            v = str(config.get(*path, default="") or "").strip()
        except Exception:
            v = ""
        if v:
            return v
    return ""


def _wx_headers() -> dict:
    ck = _wx_cookie()
    if not ck:
        return {}
    return {"Cookie": ck, "Referer": "https://mp.weixin.qq.com/"}


async def mp_by_biz(biz: str) -> Mp:
    """按 __biz 认号：主页接口比文章页小 80 倍，先拿昵称与 gh_。"""
    mp = Mp(biz=biz)
    mp.key = biz
    for hid in (1, 2, 3):
        url = f"https://mp.weixin.qq.com/mp/homepage?__biz={biz}&hid={hid}"
        try:
            r = await _hop(_get(url, timeout=10, headers=_wx_headers()), 11)
        except Exception:
            continue
        if r is None or r.status_code != 200:
            continue
        text = r.text or ""
        if _page_title(text) in ("错误", "验证", ""):
            continue
        nick = _NICK_JS.search(text) or _NICK_ID.search(text)
        if nick:
            mp.name = _clean(nick.group(1))[:60]
        gh = _GH_RE.search(text)
        if gh:
            mp.wxid = gh.group(0).lower()
        if mp.name or mp.wxid:
            mp.sources.append("homepage")
            mp.evidence.append(f"公众号主页：{url}")
            break
    if not mp.name:
        mp.notes.append("主页接口没回昵称，改用文章页取身份")
    return mp


async def mp_by_article(url: str, *, with_domains: bool = True) -> Mp | None:
    """抓一篇该号的文章：身份、样本标题、阅读原文域、正文里的自有域都在这里。"""
    if not url.startswith("http"):
        return None
    try:
        r = await _hop(_get(url, timeout=18, headers=_wx_headers()), 20)
    except Exception:
        return None
    if r is None or r.status_code != 200:
        return None
    text = r.text or ""
    if len(text) < 20000 or "环境异常" in text[:4000]:
        return None
    biz = _BIZ_VAR.search(text)
    mp = Mp(biz=(biz.group(1) if biz else ""))
    idm = _BIZ_IN_URL.search(url)
    if not mp.biz and idm:
        mp.biz = idm.group(1)
    mp.key = mp.biz or url
    nick = _NICK_ID.search(text)
    if nick:
        mp.name = _clean(nick.group(1))[:60]
    gh = _GH_VAR.search(text)
    if gh and _GH_RE.fullmatch(gh.group(1)):
        mp.wxid = gh.group(1).lower()
    head = _HEAD_VAR.search(text)
    if head:
        mp.avatar = head.group(1).strip()
    tm = _TITLE_VAR.search(text)
    ct = _CT_VAR.search(text)
    mp.articles.append({"title": _clean(tm.group(1)) if tm else "",
                        "url": url, "ts": int(ct.group(1)) if ct else 0})
    mp.sources.append("article")
    mp.evidence.append(f"公众号文章：{url[:160]}")
    if with_domains:
        src = _SRC_VAR.search(text)
        if src and src.group(1):
            mp.domains |= _domains_of(src.group(1))
            if mp.domains:
                mp.evidence.append("文章「阅读原文」指向：" + ", ".join(sorted(mp.domains)[:3]))
        # 正文里的链接才是可用的业务面；整页扫一遍再过滤 CDN，比只切 js_content 更稳
        mp.domains |= _domains_of(text)
    if not mp.name:
        mp.notes.append("文章页没解析出昵称")
    return mp


async def mp_search(target: str, *, limit: int = 8, deadline: float = 26.0) -> dict:
    """按公众号名 / 主体名 / 品牌 / gh_ / __biz / 文章链接查号。

    返回 {"items": [...], "domains": [...], "notes": [...]}。
    domains 只放过了第三方过滤的根域，交给主流水线继续被动收集。
    """
    target = (target or "").strip()
    notes: list[str] = []
    items: dict[str, Mp] = {}

    if not target:
        return {"items": [], "domains": [], "notes": ["目标为空"]}

    # 1) 直接输入 __biz 或 gh_
    if _BIZ_ARG.fullmatch(target):
        mp = await mp_by_biz(target)
        mp.key = target
        items[target] = mp
        return _finish(items, target, limit, notes, direct=True)
    if _GH_RE.fullmatch(target):
        notes.append("gh_ 原始 ID 无法直接反查 __biz（公开通道没有这个入口），"
                     "请改用公众号名或主体名再查一次")
        return {"items": [], "domains": [], "notes": notes}
    if "mp.weixin.qq.com" in target and "__biz=" in target:
        mp = await mp_by_article(target.split()[0])
        if mp is None:
            notes.append("给定文章链接打不开（可能需要微信内环境）")
            return {"items": [], "domains": [], "notes": notes}
        if not mp.name and mp.biz:
            home = await mp_by_biz(mp.biz)
            mp.name, mp.wxid = home.name or mp.name, home.wxid or mp.wxid
        items[mp.key] = mp
        return _finish(items, target, limit, notes, direct=True)

    # 2) 站内检索拿文章直链。一条查询词会被引擎降级成字典词，多条不同形态更稳；
    #    这里逐条调 search()，不用 search_many（它会用最长词探活，长主体名探空就整批作废）
    queries = [f'site:mp.weixin.qq.com "{target}"', f"site:mp.weixin.qq.com {target}"]
    if len(target) > 8:
        core = target_tokens(target)[-1]
        if core and core != target:
            queries.append(f'site:mp.weixin.qq.com "{core}"')
    engines = ("baidu_m", "sogou", "bing")
    hits: list = []
    for q in queries:
        try:
            oc = await _hop(web.search(q, engines=engines, budget=9), 24)
        except Exception:
            oc = None
        got = list(getattr(oc, "hits", []) or [])
        if not got:
            continue
        hits.extend(got)
        if len(hits) >= 40:
            break
    if not hits:
        notes.append("站内检索没回文章直链（引擎对这个词无收录或已限流）；"
                     "可改用品牌简称或公众号昵称重试")
        return {"items": [], "domains": [], "notes": notes}

    # 3) 按 __biz 聚合文章，先拿身份（小请求），再挑代表文章抓正文
    by_biz: dict[str, list] = {}
    title_of: dict[str, str] = {}
    for h in hits:
        if "mp.weixin.qq.com" not in (h.url or ""):
            continue
        m = _BIZ_IN_URL.search(h.url)
        if not m:
            continue
        biz = m.group(1)
        by_biz.setdefault(biz, [])
        if h.url not in [x.url for x in by_biz[biz]]:
            by_biz[biz].append(h)
        title_of.setdefault(biz, _clean(h.title))
    if not by_biz:
        notes.append("命中的微信页里没有 __biz（可能是首页或注册页），无法定位公众号")
        return {"items": [], "domains": [], "notes": notes}

    toks = target_tokens(target)

    async def _one(biz: str, sample) -> Mp:
        mp = await mp_by_biz(biz)
        mp.key = biz
        mp.articles.append({"title": title_of.get(biz, ""), "url": sample.url, "ts": 0})
        mp.evidence.append(f"站内检索命中：{sample.url[:160]}")
        # 昵称对得上才值得花 3.7 MB 去抓正文；对不上的只留身份，由调用方按 relevance 决定
        if _match(mp.name, title_of.get(biz, ""), toks):
            art = await mp_by_article(sample.url)
            if art is not None:
                mp.domains |= art.domains
                mp.wxid = mp.wxid or art.wxid
                mp.avatar = art.avatar or mp.avatar
                mp.articles = art.articles or mp.articles
                if art.notes:
                    mp.notes.extend(x for x in art.notes if x not in mp.notes)
        return mp

    picked = list(by_biz.items())[: max(limit, 4)]
    got = await asyncio.gather(*(_one(b, xs[0]) for b, xs in picked),
                               return_exceptions=True)
    for (biz, _xs), mp in zip(picked, got):
        if isinstance(mp, BaseException) or mp is None:
            notes.append(f"公众号 {biz} 采集失败")
            continue
        items[biz] = mp

    return _finish(items, target, limit, notes)


def _match(name: str, title: str, toks: list[str]) -> bool:
    blob = f"{name} {title}"
    return any(t and t in blob for t in toks)


def _finish(items: dict[str, Mp], target: str, limit: int, notes: list[str],
            *, direct: bool = False) -> dict:
    toks = target_tokens(target)
    domains: set[str] = set()
    out: list[Mp] = []
    for mp in items.values():
        if not mp.name and not mp.biz:
            continue
        if direct:
            mp.relevance = "high"
        else:
            mp.relevance = "high" if any(t and t in (mp.name or "") for t in toks) else "low"
        # 昵称本身就是法人写法时，它就是账号主体，比留空更有用
        if not mp.subject and SUBJECT_RE.fullmatch(mp.name or ""):
            mp.subject, mp.subject_source = mp.name, "nickname"
        elif not mp.subject:
            mp.subject_source = "none"
            if "认证主体" not in " ".join(mp.notes):
                mp.notes.append("认证主体需微信客户端才能看，公开通道拿不到；"
                                "这里按昵称与目标词匹配判断归属")
        domains |= {d for d in mp.domains if not _third_party(d)}
        out.append(mp)
    out.sort(key=lambda x: (x.relevance != "high", not x.domains, x.name))
    if out and all(x.relevance == "low" for x in out):
        notes.append("命中的号昵称都对不上目标词，只列出来供人确认，别当官方号用")
    return {"items": [mp.as_dict() for mp in out[:limit]],
            "domains": sorted(d for d in domains if is_valid_domain(d)),
            "notes": list(dict.fromkeys(notes))[:8]}


# 同一目标并发只跑一趟：流水线里品牌名与公司全名可能同时打进来
_INFLIGHT: dict[str, asyncio.Task] = {}


async def collect_mps(target: str, *, limit: int = 8, deadline: float = 26.0) -> dict:
    """统一入口，外面套总时限：到点交已完成部分，不把上游阶段顶死。"""
    _key = re.sub(r"\s+", "", target or "").lower()
    running = _INFLIGHT.get(_key)
    if running is not None:
        return await asyncio.shield(running)
    task = asyncio.create_task(mp_search(target, limit=limit, deadline=deadline))
    _INFLIGHT[_key] = task
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=deadline)
    except asyncio.TimeoutError:
        if task.done() and not task.cancelled() and task.exception() is None:
            return task.result()
        return {"items": [], "domains": [],
                "notes": [f"采集超时 {deadline:.0f}s：站内检索与身份确认未在时限内回来"]}
    finally:
        if _INFLIGHT.get(_key) is task:
            _INFLIGHT.pop(_key, None)
