"""微信小程序采集（新增能力，ARL 与 ARL-Next2 都没有）。

真实可达的入口只有三条，都不需要登录、不需要 key、不需要 AI：

  1. **AppID**（wx 开头 18 位）→ 微信官方公开档案页 `mp.weixin.qq.com/wxawap/wap/wxadetail?appid=…`。
     该页 2026 年已下线（稳定 404），抓不到就说抓不到，不编字段。
  2. **小程序名 / 主体名** → 多引擎搜「名称 + 小程序」，命中里能抽到：
     · `appid=wx…` / `#wechat_webview_type=1` 形态的微信内分享链（只在微信内转发时出现）
     · `wx…` 明文 AppID（代码引用页、开源仓库、收录页、开发者社区）
     · 收录页 / 导航站里登记的「小程序名 - 主体名」
  3. **小程序落地页**（分享链 / 码值命中的站）→ 抓页面，收介绍里出现的域名与公众号名。

拿到主体名后扩线分两跳：本机微信缓存按标题 / 主体 / 域名比对，拿带接口的真包；
再走备案库按单位名精确匹配，拿主体名下登记的小程序 / APP 备案号。两跳都只用登记
信息，平台按名字糊出来的同款进不来。
AI 只能补最后一层（推可能的业务域名），没过打分闸的不下发；没有 AI 也照常跑完。

产出：
  * kind=applet  一条小程序一个资产（appid / 主体 / 分享链 / 目录来源 / 证据）
  * kind=domain  从主体、介绍、落地页扩出的域（交给主流水线继续被动收集）
"""

from __future__ import annotations

import asyncio
import html
import os
import re
import time
from dataclasses import dataclass, field

from ...utils import is_valid_domain, root_domain
from .. import naming
from ..sources import passive
from ..sources import search as web
from ..sources.passive import _get

APPID_RE = re.compile(r"\bwx[0-9a-f]{16}\b", re.I)
# 常见误报：微信自家前端里的 `wx` 前缀常量（wxpay / wxconfig / wxnavigateTo…）
# 后面只跟 16 位十六进制的字符串才是 AppID，这里用词边界 + 全小写比对二次过滤
_HEX_AFTER_RE = re.compile(r"^wx[0-9a-f]{16}$", re.I)
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,10})\b", re.I)
SUBJECT_RE = re.compile(r"([\u4e00-\u9fa5（）()]{4,40}?(?:有限责任公司|有限公司|集团|工作室|"
                        r"研究院|中心|大学|银行|医院))")

# 微信小程序分享链里带 `appid=wx…` / `wechat_webview_type=1`。
# 搜狗 /link 壳要靠页面 JS 拼真实地址（不含 token），但拼出来的文章页里 AppID 实测 0 命中，
# 只有 __biz 和公众号名，所以这里只把搜索结果当主体线索，不跟跳转。
_SOGOU_WX = "https://weixin.sogou.com/weixin"
# 搜狗微信结果条：`<h3><a>文章标题</a></h3>` … `<p class="txt-info">摘要</p>` … `class="all-time-y2">公众号名`
_SOGOU_ITEM = re.compile(r"<h3[^>]*>\s*<a[^>]*>(.*?)</a></h3>(.*?)(?:all-time-y2\"[^>]*>(.*?)</span>|</div>)",
                         re.S)

# 收录站 / 导航站 / 微信自家域：只能当线索来源，不能当目标
_DIRECTORY = ("aldzs.com", "minapp.com", "xcx.com", "wxxcx.com", "wxapp.com", "jiuzhilan.com",
              "app100.cn", "zhihu.com", "jianshu.com", "csdn.net", "juejin.cn", "gitee.com",
              "github.com", "gitcode.com", "developers.weixin.qq.com", "mp.weixin.qq.com",
              "weixin.qq.com", "qq.com", "baidu.com", "sogou.com", "so.com", "bing.com",
              "juzibot.com", "wxapp-union.com", "xcxwo.com", "dianping.com")

# 2026-11-08 实测的「名称 → AppID」公开入口，按能拿到什么分两类：
#
# 能用（都不是 AppID，是主体/文章线索）：
#   weixin.sogou.com/weixin?type=2&query=…     200 0.3s，10 条「文章标题 + 公众号名」，
#      公众号名是真实开发主体的写法，直接当企业主体名扩线用（applet_by_weixin_search）
#   weixin.sogou.com/link?url=…（带搜索页 cookie）200 822B JS 壳，`url += '…'` 多段拼出
#      mp.weixin.qq.com/s?src=11&timestamp=…&signature=… 落地页；文章页 200 后能抽 `__biz`
#      与 `id="js_name"` 公众号名，但正文里的 data-miniprogram-appid 实测 0 命中
#   mp.weixin.qq.com/s?__biz=…                 200，抽 __biz / js_name；profile_ext、homepage、
#      getappmsgext 都要微信内签名，直连只回「请在微信客户端打开链接」
#
# 不能用（2026-11-08 复测，别再试）：
#   mp.weixin.qq.com/wxawap/wap/wxadetail?appid=  404（官方档案页下线）
#   mp.weixin.qq.com/wxawap/wxawap/wxa/search     404
#   weixin.sogou.com/weixin?type=1&query=…        200 但「暂无相关官方认证订阅号」，拿不到公众号主体
#   m.sogou.com/web/searchList.jsp?type=2         200，回的是 QQ 浏览器搜索首页，无 __biz / AppID
#   mp.weixin.qq.com/mp/search?action=…           404（微信内搜索接口不对外）
#   sj.qq.com/search?q=…                          200 但 0 个 AppID（搜索不覆盖小程序）；
#     页面里的 wx… 出自 iframe jssdk/share-page/core.html?wx_appid=…，是应用宝自己的
#     公众号 AppID，与搜索结果无关，别再当命中
#   developers.weixin.qq.com/community/search     302 → error/emergency?forceLogin=true
#   weixin.qq.com/wxopen/…                        404
#   baidu.com/s?wd=…                              「百度安全验证」
#   aldzs.com（阿拉丁指数）/ minapp.com / xcxrank.cn / xcx.com / wxapp.com
#                                                 超时 / 需 token / DNS 失败 / 522
# 结论：仍然没有免费的「名称 → AppID」入口。名称输入只能拿主体（公众号名、文章标题），
# AppID 只从多引擎明文与分享链里来；拿不到就留空条目 + notes，不编字段。

_KNOWN_THIRD = ("aliyuncs.com", "myqcloud.com", "qiniu.com", "qiniucdn.com", "bcebos.com",
                "aliyun.com", "tencent.com", "weixin.qq.com", "gtimg.com", "qlogo.cn",
                "umeng.com", "jpush.cn", "getui.com", "bugly.qq.com", "sentry.io",
                "amap.com", "map.baidu.com", "bootstrapcdn.com", "jsdelivr.net", "w3.org",
                "googleapis.com", "gstatic.com")

_NOISE_DOMAIN_TAIL = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".json",
                      ".woff", ".woff2", ".ico", ".xml", ".html", ".htm")

# 「名称 → AppID」这一路是多入口拼的（多引擎检索 / 搜狗微信 / 本机缓存 / CDN 包资源），
# 每个入口的失效原因不一样：引擎被墙、检索页反爬、本机没缓存。单项跑最想知道的就是
# 「到底哪几个入口是死的」，所以每条入口各自回一个状态，别糊成一个「小程序检索」。
LAST_CHANNELS: dict[str, dict] = {}


def _hop(aw, timeout: float):
    """给单跳加硬上限。调用方要 `await _hop(_get(...))` 现场造协程，囤着再造会在超时后泄漏。"""
    return asyncio.wait_for(aw, timeout=timeout)


def _sogou_text(raw: str) -> str:
    """搜狗结果里的标题/摘要带 `<em><!--red_beg-->` 高亮包裹，去掉标签再反转义实体。"""
    return html.unescape(re.sub(r"<[^>]+>", "", raw or "")).strip()


def _is_directory(domain: str) -> bool:
    d = domain.lower()
    return any(d == x or d.endswith("." + x) for x in _DIRECTORY)


def _is_third_party(domain: str) -> bool:
    d = domain.lower()
    return any(d == x or d.endswith("." + x) for x in _KNOWN_THIRD)


# 反向域名形态的包名 / 类名：com.xxx.yyy、cn.xxx.yyy，TLD 段不是真实顶级域
_PKG_TLD = {"com", "cn", "net", "org", "io", "co", "me", "cc", "tv", "in", "app", "xyz",
            "top", "vip", "club", "site", "online", "shop", "store", "biz", "info", "live"}


def _is_package(value: str) -> bool:
    """`com.tencent.mm` 这类包名，末段是类名不是 TLD。"""
    parts = value.lower().split(".")
    if len(parts) < 3:
        return False
    return parts[0] in _PKG_TLD and len(parts[-1]) <= 16 and parts[-1] not in ("com", "cn", "net", "org")


def _clean_domains(text: str) -> set[str]:
    out: set[str] = set()
    for m in DOMAIN_RE.findall(text or ""):
        d = m.lower()
        if d.endswith(_NOISE_DOMAIN_TAIL) or not is_valid_domain(d):
            continue
        if _is_directory(d) or _is_third_party(d):
            continue
        out.add(root_domain(d) or d)
    return out


@dataclass
class Applet:
    name: str = ""
    appid: str = ""
    subject: str = ""          # 开发主体 / 账号主体
    intro: str = ""
    domains: set = field(default_factory=set)
    apis: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    official_url: str = ""
    notes: list[str] = field(default_factory=list)
    # 备案号：备案库给的登记信息，落资产时用来区分「备案记录」和「真包 / 线索」
    license: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "appid": self.appid, "subject": self.subject,
                "intro": self.intro, "domains": sorted(self.domains),
                "apis": self.apis[:60],
                "evidence": self.evidence[:8], "sources": self.sources,
                "official_url": self.official_url, "notes": self.notes,
                "license": self.license}


async def applet_by_appid(appid: str) -> Applet:
    """AppID → 小程序档案。

    官方 wap 档案页已下线（404），这里仍先试一次（哪天恢复就能直接吃到昵称/主体），
    拿不到就把 AppID 记下并写明原因，不伪造字段。
    """
    ap = Applet(appid=appid.strip().lower())
    ap.official_url = f"https://mp.weixin.qq.com/wxawap/wap/wxadetail?appid={ap.appid}"
    # 应用宝也收录微信小程序，地址形态是 appdetail/wx…，标题里有小程序名和主体。
    # 两个站点互不依赖，且官方页 404 是常态：并发拿，别让一次确认分两跳等
    detail = f"https://sj.qq.com/appdetail/{ap.appid}"
    r, r2 = await asyncio.gather(
        # 官方页稳定 404（下线），短超时足够；15s 只会让每个 AppID 白等
        _hop(_get(ap.official_url, timeout=8), 9),
        # 应用宝对代理出口回 567 质询页（同 mobile._yyb_detail），必须显式直连
        _hop(_get(detail, timeout=8, proxy=""), 9), return_exceptions=True)
    if isinstance(r, BaseException):
        r = None
    if isinstance(r2, BaseException):
        r2 = None
    if r is not None and r.status_code == 200:
        text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", r.text or "", flags=re.S | re.I)
        for key, attr in (("nickname", "name"), ("username", "name"), ("signature", "intro"),
                          ("principal", "subject"), ("principalname", "subject")):
            m = re.search(rf"""{key}\s*[:=]\s*["']([^"']{{2,80}})["']""", text)
            if m and not getattr(ap, attr):
                setattr(ap, attr, m.group(1).strip())
        ap.domains |= _clean_domains(text)
        if ap.name or ap.subject:
            ap.sources.append("wechat_official")
            ap.evidence.append(f"微信官方小程序档案页：{ap.official_url}")
    if not ap.name:
        if r2 is not None and r2.status_code == 200 and ap.appid in (r2.text or ""):
            t = re.search(r"<title[^>]*>(.*?)</title>", r2.text, re.S)
            if t:
                ap.name = re.sub(r"\s*[-_|].*$", "", re.sub(r"<[^>]+>", "", t.group(1))).strip()[:60]
            blob = re.sub(r"<script.*?</script>|<style.*?</style>", " ", r2.text, flags=re.S | re.I)
            m = SUBJECT_RE.search(re.sub(r"<[^>]+>", " ", blob))
            if m:
                ap.subject = m.group(1)
            ap.domains |= _clean_domains(re.sub(r"<[^>]+>", " ", blob))
            ap.official_url = detail
            ap.sources.append("yingyongbao")
            ap.evidence.append(f"应用宝小程序详情页：{detail}")
    if not ap.name:
        ap.notes.append("微信官方档案页已下线（404），仅记录 AppID；主体请用小程序名或公司名再查")
    return ap


_HIT_STOP_WORDS = {"中国", "集团", "公司", "股份", "有限", "控股", "科技", "网络"}


def _target_words(target: str) -> list[str]:
    """目标 → 检索结果比对词：整串、去法人后缀的主名、长片段。

    搜索引擎对这一类词经常回一堆无关页（实测拿「瑞幸咖啡」去搜，必应回的全是
    「瑞」字的字典页），不过滤就被算成「引擎可用 · 10 条命中」，还把这些页里的
    公众号名、AppID 挂到目标头上。只留真的在标题 / 摘要 / 链接里写着目标的命中。
    """
    t = (target or "").strip()
    if not t:
        return []
    words = {t}
    try:
        short = naming.short_name(t)
    except Exception:
        short = ""
    if short and len(short) >= 2:
        words.add(short)
    for part in re.split(r"[^\w\u4e00-\u9fa5]+", t):
        if len(part) >= 3 and part not in _HIT_STOP_WORDS:
            words.add(part)
    return [w for w in words if w]


async def applet_by_name(name: str) -> list[Applet]:
    """小程序名 / 主体名 → 候选 AppID 档案。

    只认三类硬证据：微信内分享链参数、明文 AppID、收录页「小程序名 - 主体」写法。
    搜不到就返回一条空档案并说明原因，不拿同名站点凑数。
    """
    out: dict[str, Applet] = {}
    # 「小程序」+「appid」两个词就够定题；四查询词会把引擎锁和一个 search_many 预算
    # 摊得更薄，实测多的两词没带回任何新 AppID
    queries = [f"{name} 小程序 appid", f"{name} 微信小程序"]
    # 只留实测秒级出数的引擎：360/ddg 对这一类词经常 0 条却把 budget 耗满
    eng_stat: dict[str, str] = {}
    try:
        hits = await _hop(web.search_many(queries, engines=("toutiao", "bing_rss", "sogou"),
                                          budget=8, stat=eng_stat), 11)
    except Exception:
        hits = []
    # 引擎对这一类词经常回一堆无关页（拿品牌名去搜，回来的可能是同名单字的字典页），
    # 不过滤就被算成「可用 · 10 条命中」，还把这些页里的公众号名、AppID 挂到目标头上。
    # 只留标题 / 摘要 / 链接里真写着目标的命中。
    words = _target_words(name)
    raw = list(hits)
    if words:
        hits = [h for h in raw
                if any(w in f"{h.title} {h.snippet} {h.url}" for w in words)]
    raw_per_engine: dict[str, int] = {}
    for hit in raw:
        eng = str(getattr(hit, "engine", "") or "")
        if eng:
            raw_per_engine[eng] = raw_per_engine.get(eng, 0) + 1
    # 引擎状态只说明「探针词有没有回结果」。以前不管这轮检索命中几条都写 items: 0，
    # 于是面板上「必应RSS 可用 · 0 条」—— 看起来是入口通、本站没有，实际可能这个引擎
    # 一条都没给过。这里按引擎数真实命中条数，0 条 + 探针通 = 无数据，不是可用。
    per_engine: dict[str, int] = {}
    for hit in hits:
        eng = str(getattr(hit, "engine", "") or "")
        if eng:
            per_engine[eng] = per_engine.get(eng, 0) + 1
    for b, st in eng_stat.items():
        got_n = per_engine.get(b, 0)
        waste = raw_per_engine.get(b, 0) - got_n
        if got_n:
            st = "ok"
        elif st == "ok":
            st = "empty"
        note = (f"{got_n} 条命中 · 检索词 {' / '.join(queries)}" if got_n
                else f"探针通但检索词无命中 · {' / '.join(queries)}")
        if waste > 0:
            note += f" · 另 {waste} 条与目标无关已过滤"
        LAST_CHANNELS[f"applet:{b}"] = {
            "status": st, "items": got_n,
            "note": note[:150],
        }

    ids: set[str] = set()
    share_hits: list = []
    subjects: set[str] = set()
    for hit in hits:
        text = f"{hit.title} {hit.snippet} {hit.url}"
        for appid in APPID_RE.findall(text):
            ids.add(appid.lower())
        for m in SUBJECT_RE.finditer(f"{hit.title} {hit.snippet}"):
            subjects.add(m.group(1))
        if "wechat_webview_type" in hit.url or re.search(r"[?&#]appid=wx", hit.url, re.I):
            share_hits.append(hit)

    # 分享链：先抓落地页，收介绍里的域与公众号名，再挂到 AppID 档案
    share_domains: set[str] = set()
    share_evidence: list[str] = []
    picked = share_hits[:5]
    pages = await asyncio.gather(*(_hop(_get(h.url, timeout=8), 9) for h in picked),
                                 return_exceptions=True)
    for hit, r in zip(picked, pages):
        share_domains.add(root_domain(hit.domain) or hit.domain)
        share_evidence.append(f"微信内分享链：{hit.url[:100]}")
        if isinstance(r, BaseException) or r is None or r.status_code != 200:
            continue
        share_domains |= _clean_domains(r.text)
        ids |= {a.lower() for a in APPID_RE.findall(r.text or "")}

    picked_ids = list(ids)[:6]
    got = await asyncio.gather(*(_hop(applet_by_appid(a), 12) for a in picked_ids),
                               return_exceptions=True)
    for appid, ap in zip(picked_ids, got):
        if isinstance(ap, BaseException) or ap is None:
            continue
        ap.domains |= share_domains
        ap.evidence += [e for e in share_evidence if e not in ap.evidence]
        if share_evidence:
            ap.sources.append("wechat_share")
        out[appid] = ap

    if not out and share_domains:
        ap = Applet(name=name, domains=set(share_domains))
        if len(subjects) == 1:
            ap.subject = next(iter(subjects))
        ap.sources.append("wechat_share")
        ap.evidence += share_evidence
        out["__share__"] = ap

    if not out:
        # 一条硬证据都没有就不造条目：空壳进 items 会让调用方以为查到了小程序
        ap = Applet(name=name)
        ap.notes.append("未搜到明文 AppID 或微信分享链；可改用小程序名 + 公司主体名各查一次")
        return [ap]

    for ap in out.values():
        ap.name = ap.name or name
        if not ap.subject and len(subjects) == 1:
            ap.subject = next(iter(subjects))
            ap.evidence.append(f"搜索结果里的主体写法：{ap.subject}")
    return list(out.values())


async def applet_by_weixin_search(name: str) -> list[Applet]:
    """小程序名 / 品牌名 → 搜狗微信搜索结果里的明文 AppID。

    微信官方的小程序档案页（`xcxprofile` 系列）在 2026 年已全部 404，
    微信开放社区搜索页里的 AppID 是站点自己的 telemetry/OAuth 标识，跟目标无关。
    「名称 → AppID」目前没有免费且稳定的公开入口，收录站要登录。
    这条线只做一件事：把搜索页里**直接写着**的 `wx` 开头的 AppID 收下来；
    拿不到就返回空列表，由调用方给 note，不编条目。
    """
    name = (name or "").strip()
    if not name or len(name) < 2:
        return []

    async def _fetch(kind: int, query: str):
        try:
            # query 必须传原始中文：`_get` 自己会 urlencode，再套一层 quote 会变成
            # %25E7…，搜狗退化成通用搜索页（实测 0 条结果）
            return await _get(_SOGOU_WX, {"type": kind, "query": query},
                              headers={"Referer": "https://weixin.sogou.com/"},
                              timeout=8)
        except Exception:
            return None

    pages = await asyncio.gather(_fetch(2, f"{name} 小程序"), _fetch(2, name),
                                 return_exceptions=True)

    out: dict[str, Applet] = {}
    subjects: list[str] = []
    ok_pages = 0
    for page in pages:
        if page is None or isinstance(page, BaseException) or getattr(page, "status_code", 0) != 200:
            continue
        ok_pages += 1
        body = getattr(page, "text", "") or ""
        for appid in APPID_RE.findall(body):
            ap = Applet(name=name, appid=appid.lower())
            ap.sources.append("sogou_wx")
            ap.evidence.append("搜狗微信搜索结果里出现明文 AppID")
            out.setdefault(appid.lower(), ap)
        for title, mid, account in _SOGOU_ITEM.findall(body):
            account = _sogou_text(account)
            if account and len(account) <= 40 and account not in subjects:
                subjects.append(account)
            m = SUBJECT_RE.search(_sogou_text(f"{title} {mid}"))
            if m and m.group(1) not in subjects:
                subjects.append(m.group(1))

    # 检索页通了但一条主体都没读出来，多半是撞上反爬壳；和「词没命中」分开记，
    # 否则每次看到这条都是「无数据」，没人知道该换思路还是去修代理。
    if ok_pages and not (out or subjects):
        LAST_CHANNELS["applet:weixin"] = {
            "status": "blocked", "items": 0,
            "note": f"检索页 HTTP 200 但读不出结果条（{ok_pages} 页），疑似反爬壳"}
    else:
        LAST_CHANNELS["applet:weixin"] = {
            "status": "ok" if out else ("empty" if ok_pages else "blocked"),
            "items": len(out),
            "note": (f"读到 {len(subjects)} 个公众号名" if subjects else "检索页无结果条"),
        }

    # 搜狗微信的文章页里实测抽不到 AppID（data-miniprogram-appid 0 命中），
    # 但公众号名就是开发主体的对外写法，比裸品牌名更适合拿去搜工商/备案
    if subjects:
        ap = Applet(name=name)
        ap.subject = ", ".join(subjects[:3])
        ap.sources.append("sogou_wx")
        ap.evidence.append("搜狗微信文章列表里的公众号：" + "、".join(subjects[:5]))
        out.setdefault("__sogou__", ap)

    for ap in out.values():
        ap.name = ap.name or name
    return list(out.values())


# 主体自己的站点常常直接写着小程序：H5 用 <wx-open-launch-weapp appid="wx…"> 唤起，
# 文章卡片用 <mp-miniprogram data-miniprogram-appid="wx…" data-miniprogram-nickname="…">，
# uni-app / Taro 构建的页面里还有 miniProgram: { appId: "wx…" }。这些是明文、可核对的
# AppID，比拿企业名去平台按名字糊出来的同款硬得多。
# 公开渠道里实测没有可用的「企业名 → AppID」目录：微信小程序档案页 404 空响应、收录站
# 不是登录墙就是 SPA 空壳（首屏 HTML 里连品牌名都没有），所以主体自有站点是唯一能自己
# 验证的入口 —— 有域名就能挖，挖不到就如实记没挖到。
_MP_TAG_RE = re.compile(r"<mp-miniprogram\b[^>]*>", re.I)
_MP_ATTR_RE = re.compile(r"data-miniprogram-appid\s*=\s*[\"']?\s*([^\"'\s>]+)", re.I)
_MP_NICK_RE = re.compile(r"data-miniprogram-nickname\s*=\s*[\"']?\s*([^\"'>]+)", re.I)
_LAUNCH_TAG_RE = re.compile(r"<wx-open-launch-weapp\b[^>]*>", re.I)
# 实测站点的属性写法很松：`appid=" wxd75b5bb730db4fbb"` 引号里先来一个空格，
# 写成 `appid=["']?(wx…)` 就一个都抓不到。
_LAUNCH_APPID_RE = re.compile(r"\bapp-?id\s*=\s*[\"']?\s*(wx[0-9a-fA-F]{16})", re.I)
_MP_OBJ_RE = re.compile(
    r"mini-?program\s*:\s*\{[^}]{0,240}?app[\s_-]?id\s*:\s*[\"']?\s*(wx[0-9a-fA-F]{16})", re.I)
_GH_ATTR_RE = re.compile(
    r"\b(?:username|data-miniprogram-username)\s*=\s*[\"']?\s*(gh_[A-Za-z0-9]+)", re.I)
_MP_LINK_RE = re.compile(r"(?:weixin://dl/business/?\?t=[^\s\"'<>]*"
                         r"|https?://wxaurl\.cn/[A-Za-z0-9]{4,})", re.I)
_JS_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
# 逐行注释：`<wx-open-launch-weapp-->` / `id="…"-->` / `appid="wx…"-->`，标签被切成几段。
_COMMENT_SPLIT_RE = re.compile(r"-->[ \t]*\r?\n?[ \t]*<!--")

# 站点挖掘的耗时上限。并发抓首页 / 站点地图页 / 前端 JS，超预算就停并把「截断」写进
# 渠道说明，不静默少看几个域 —— 少看会让「这家没小程序」变成假结论。
SITE_BUDGET = 30.0
SITE_MAX_PAGES = 18        # 全轮最多读几页（各域共享这份额度）
SITE_MAX_JS = 14           # 全轮最多读几份 JS
SITE_CONCURRENT = 6        # 串行读十几页必然把预算耗光
# 唤起标签最常挂在移动端 H5 / 活动页上，门户首页反而是图片墙
_MOBILE_HOSTS = ("m", "wap", "h5", "mini")
_HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"'#]+)", re.I)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_ROBOTS_SITEMAP_RE = re.compile(r"^\s*sitemap\s*:\s*(\S+)\s*$", re.I | re.M)
# 静态资源 / 下载 / 图片不算页面，读了也只会白耗预算
_NOT_PAGE_RE = re.compile(
    r"\.(?:jpe?g|png|gif|webp|svg|ico|bmp|css|js|json|pdf|docx?|xlsx?|pptx?|zip|rar|7z|gz|"
    r"mp4|mp3|wav|avi|woff2?|ttf|eot|exe|apk)(?:$|[?#])", re.I)


def _same_site_of(url: str, dom: str) -> bool:
    """这个 URL 是否挂在 dom 或它的子域上。"""
    try:
        host = url.split("/")[2].lower().split(":")[0]
    except IndexError:
        return False
    return host == dom or host.endswith("." + dom)


def _js_allowed(url: str, dom: str) -> bool:
    """这份前端 JS 值不值得读：本站和自家 CDN 读，公共库 / 对象存储不读。

    品牌常把前端包放在独立 CDN 域（站点首页 10 个 script 全挂在自家 CDN 上），
    只认「同域」会让 JS 额度恒为 0，再把「没读到脚本」写成「页面里没有小程序卡片」。
    """
    try:
        host = url.split("/")[2].lower().split(":")[0]
    except IndexError:
        return False
    if not host:
        return False
    if _same_site_of(url, dom):
        return True
    return not any(host == t or host.endswith("." + t) for t in _KNOWN_THIRD)


def _join_split_comments(body: str) -> str:
    """把被逐行注释切碎的标签拼回去。

    实测站点上编辑器把整块按钮逐行注释，于是 HTML 里是
    `<wx-open-launch-weapp-->`、`id="launch-btn"-->`、`appid="wx…"-->` 三段。
    不拼回去，明文 AppID 就躺在这站页面上也读不出来。
    """
    out = body
    for _ in range(3):
        nxt = _COMMENT_SPLIT_RE.sub(" ", out)
        if nxt == out:
            break
        out = nxt
    return out


def _commented_out(raw: str, aid: str) -> bool:
    """这个 AppID 在原始页面里是否写在 HTML 注释中（照着上面的切碎写法判）。"""
    m = re.search(re.escape(aid) + r"[\"']?\s*-->", raw, re.I)
    return bool(m)


def _pick_site_applets(body: str) -> list[tuple[str, str, str, bool]]:
    """页面 / JS 里的小程序 AppID → [(appid, 小程序名, gh_ 用户名, 是否在注释里)]。

    只认明确标着「小程序」的三种写法。整页乱抓 `wx` + 16 位十六进制会把公司 H5 里
    `wx.config({appId})` 的公众号 AppID 当成小程序收进来 —— 那又是一次打偏。
    """
    got: list[tuple[str, str, str, bool]] = []
    seen: set[str] = set()
    raw = body
    body = _join_split_comments(body)

    def add(aid: str, nick: str = "", gh: str = "") -> None:
        aid = (aid or "").strip().lower()
        if not APPID_RE.fullmatch(aid) or aid in seen:
            return
        seen.add(aid)
        got.append((aid, (nick or "").strip()[:60], (gh or "").strip(),
                    _commented_out(raw, aid)))

    for tag in _MP_TAG_RE.findall(body):
        a = _MP_ATTR_RE.search(tag)
        if not a:
            continue
        n = _MP_NICK_RE.search(tag)
        g = _GH_ATTR_RE.search(tag)
        add(a.group(1), html.unescape(n.group(1)) if n else "", g.group(1) if g else "")
    for tag in _LAUNCH_TAG_RE.findall(body):
        a = _LAUNCH_APPID_RE.search(tag)
        if not a:
            continue
        g = _GH_ATTR_RE.search(tag)
        add(a.group(1), "", g.group(1) if g else "")
    for m in _MP_OBJ_RE.finditer(body):
        add(m.group(1))
    return got


async def applets_from_sites(domains: set[str] | list[str], *,
                            max_domains: int = 8, max_js: int = SITE_MAX_JS,
                            max_pages: int = SITE_MAX_PAGES) -> list[Applet]:
    """主体备案域名的首页 + 站点地图页 + 前端资源 → 明文小程序 AppID。

    只读公开页，不登录。拿不到就返回空列表，渠道状态由 LAST_CHANNELS 如实交代：
    域名一个都没有 / 首页打不开 / 读了但页面里没有小程序卡片，三种情况分开写。

    以前每个域只读一页 + 4 份 JS：门户首页常常是图片墙或 SPA 骨架，一个 AppID 都没有，
    结论就成了「这家没小程序」。现在把站点地图里的功能页、移动端 H5 一起读，JS 额度
    放大并并发抓；读不完的部分写进渠道说明，少读不能变成假结论。
    """
    doms = [d for d in dict.fromkeys(x for x in (domains or []) if x)][:max_domains]
    if not doms:
        return []
    t0 = time.monotonic()
    out: dict[str, Applet] = {}
    pages = 0
    scripts = 0
    links = 0
    dead: list[str] = []
    cut: list[str] = []
    too_big: list[str] = []
    page_budget = max(1, int(max_pages))
    js_budget = max(0, int(max_js))
    sem = asyncio.Semaphore(SITE_CONCURRENT)
    js_done: set[str] = set()

    def over() -> bool:
        return time.monotonic() - t0 > SITE_BUDGET

    def absorb(body: str, url: str, dom: str) -> None:
        nonlocal links
        links += len(_MP_LINK_RE.findall(body))
        for aid, nick, gh, commented in _pick_site_applets(body):
            ap = out.get(aid)
            if ap is None:
                ap = Applet(name=nick, appid=aid)
                ap.domains.add(root_domain(dom) or dom)
                ap.sources.append("site")
                ap.evidence.append(f"主体域名 {dom} 的前端里写着小程序 AppID：{url[:120]}")
                if commented:
                    # 注释里写死说明按钮已停用，但这个 AppID 是站点自己写的明文，
                    # 依然是这家名下的小程序，只是别让人以为页面上还能点。
                    ap.notes.append("页面上这段唤起标签已被注释停用，AppID 仍是明文")
                out[aid] = ap
            elif nick and not ap.name:
                ap.name = nick
            if gh:
                mark = f"小程序原始 ID：{gh}"
                if mark not in ap.evidence:
                    ap.evidence.append(mark)

    async def fetch(u: str):
        try:
            async with sem:
                return await _get(u, timeout=8)
        except Exception:
            return None

    def page_ok(r) -> bool:
        return r is not None and getattr(r, "status_code", 0) < 400

    def js_of(body: str, base: str, dom: str) -> list[str]:
        """页面里挂的前端包：自家 CDN 也读，公共库 / 对象存储跳过。"""
        got: list[str] = []
        for src in _JS_SRC_RE.findall(body):
            src = html.unescape(src).strip()
            if not src or src.startswith("data:"):
                continue
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base.rstrip("/") + src
            elif not src.startswith("http"):
                src = base.rstrip("/") + "/" + src
            if not src.startswith("http") or ".js" not in src.split("?")[0]:
                continue
            if _js_allowed(src, dom):
                got.append(src)
        return got

    async def read_js(urls: list[str], dom: str) -> None:
        nonlocal scripts
        todo = [u for u in dict.fromkeys(urls) if u not in js_done]
        if not todo or scripts >= js_budget:
            return
        todo = todo[:js_budget - scripts]
        js_done.update(todo)
        for ju, jr in zip(todo, await asyncio.gather(*(fetch(u) for u in todo))):
            if not page_ok(jr):
                continue
            tb = getattr(jr, "text", "") or ""
            # 前端包常是几 MB 的构建产物，超大的读全文只会把预算耗在一个文件上
            if len(tb) > 8_000_000:
                too_big.append(ju)
                continue
            scripts += 1
            absorb(tb, ju, dom)

    for idx, dom in enumerate(doms):
        if over():
            cut.append(f"{len(doms) - idx} 个域")
            break
        # 找这个域能打开的入口：根域常直接 403，真正的页面挂在 www / m / wap 上
        home = ""
        body = ""
        for host in (dom, f"www.{dom}", *(f"{p}.{dom}" for p in _MOBILE_HOSTS)):
            r = await fetch(f"https://{host}/")
            if page_ok(r) and "<" in (getattr(r, "text", "") or ""):
                home, body = f"https://{host}/", getattr(r, "text", "") or ""
                break
        if not home:
            dead.append(dom)
            continue
        pages += 1
        absorb(body, home, dom)
        base = home.rstrip("/")

        # 候选页：首页导航链接（功能页都挂在这一层）优先，站点地图里的落地页补齐
        todo: list[str] = []
        for href in _HREF_RE.findall(body)[:80]:
            href = html.unescape(href).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            if href.startswith("//"):
                href = "https:" + href
            elif href.startswith("/"):
                href = base + href
            elif not href.startswith("http"):
                continue
            if _NOT_PAGE_RE.search(href) or not _same_site_of(href, dom):
                continue
            if href.rstrip("/") == base or href in todo:
                continue
            todo.append(href)

        sites: list[str] = [f"{base}/robots.txt", f"{base}/sitemap.xml"]
        read_sm: set[str] = set()
        found: list[str] = []
        while sites and len(read_sm) < 4 and not over():
            sm = sites.pop(0)
            if sm in read_sm:
                continue
            read_sm.add(sm)
            r = await fetch(sm)
            if not page_ok(r):
                continue
            text = getattr(r, "text", "") or ""
            for loc in (_ROBOTS_SITEMAP_RE.findall(text) or _SITEMAP_LOC_RE.findall(text)):
                loc = html.unescape(loc).strip()
                if not loc.startswith("http") or not _same_site_of(loc, dom):
                    continue
                if loc.split("?")[0].lower().endswith(".xml"):
                    if loc not in read_sm:
                        sites.append(loc)
                    continue
                if _NOT_PAGE_RE.search(loc) or loc in found:
                    continue
                found.append(loc)
        for loc in found:
            if loc not in todo:
                todo.append(loc)

        for pos, url in enumerate(todo):
            if pages >= page_budget or over():
                cut.append(f"{len(todo) - pos} 个页面")
                break
            r = await fetch(url)
            if not page_ok(r):
                continue
            tb = getattr(r, "text", "") or ""
            if not tb:
                continue
            pages += 1
            absorb(tb, url, dom)
            await read_js(js_of(tb, url, dom), dom)
        if scripts >= js_budget and todo:
            cut.append("JS 额度用完")

    if out:
        note = f"{len(doms)} 个主体域名 · 读了 {pages} 页 / {scripts} 份 JS · 抽到 {len(out)} 个 AppID"
        status = "ok"
    elif pages:
        # 一份脚本都没读到的时候不能说「页面和脚本里都没有」——那只是页面里没有，
        # 脚本这一面根本没看过，写成「都没有」就是把没看当成没有。
        seen = "页面和脚本里都没有小程序卡片" if scripts else \
            f"页面里没有小程序卡片；前端脚本这轮没读到（{pages} 页里挂的包都在未收录的 CDN 或全是内联）"
        note = f"{len(doms)} 个主体域名 · 读了 {pages} 页 / {scripts} 份 JS，{seen}"
        status = "empty"
    else:
        note = f"{len(doms)} 个主体域名首页都打不开（403 / 超时），读不到前端"
        status = "blocked"
    if links:
        note += f" · 另有 {links} 条小程序跳转短链（短链本身不带 AppID）"
    if dead:
        note += f" · 打不开的域：{'、'.join(dead[:4])}"
    if too_big:
        note += f" · {len(too_big)} 份脚本超过 8MB 未读"
    if cut:
        note += f" · 被预算 / 额度截断：{'、'.join(dict.fromkeys(cut))}"
    LAST_CHANNELS["applet:site"] = {"status": status, "items": len(out), "note": note[:220]}
    return list(out.values())


def _binds(ap: "Applet", words: list[str]) -> bool:
    """条目是不是真挂在目标名下：名字 / 主体 / 简介任意一处出现目标全称或主名。"""
    text = f"{ap.name} {ap.subject} {ap.intro}"
    return any(w and w in text for w in words)


# 本机清单冷跑要读完所有包（五十来个包近一分钟），热跑只读新增 / 变过的包（0.1s）。
# 单项执行等不起一分钟，于是给清单一个预算：到点就停，把「读了几个 / 共几个 / 有没有
# 截断」原样带回去；已读的进磁盘缓存，下一枪接着读。控耗时靠预算，不靠少扫几个包——
# 少扫会让目标那个包根本没被看过，然后报「没有对上的包」，看着像这家没小程序。
INV_BUDGET = 18.0


async def _local_bind(target: str, *, budget: float = INV_BUDGET,
                      deep: int = 4) -> dict:
    """本机微信缓存全量清单 → 按目标打相关度 → 对上的包再解包取接口与域名。

    机构主体在公开检索里几乎拿不到明文 AppID（搜「厦门市特种设备检验检测院 小程序」
    回来的都是无关同款），而缓存里的包自带标题、主体、接口清单和域名，比按名字搜回来
    的硬得多。纯离线读本机文件，不联网也不需要登录态。
    返回 {"items", "records", "note", "stat", "errors"}，扫到哪一步都如实写进 note。
    """
    stat = {"scanned": 0, "total": 0, "cached": 0, "truncated": False,
            "elapsed": 0.0, "matched": 0, "roots": 0, "dirs": 0, "deep": 0}
    out: dict = {"items": [], "records": [], "note": "", "stat": stat, "errors": []}
    try:
        from . import wxscan
    except Exception:
        out["errors"].append("本机缓存模块不可用")
        return out
    try:
        got = await asyncio.wait_for(
            asyncio.to_thread(wxscan.mini_inventory, target=target, budget=budget),
            timeout=budget + 8)
    except asyncio.TimeoutError:
        out["note"] = f"本机缓存比对超时 {budget + 8:.0f}s；可单独跑「本机小程序解包」看完整结果"
        return out
    except Exception as e:
        out["errors"].append(f"本机缓存比对失败 {type(e).__name__}: {str(e)[:80]}")
        return out

    for k in ("scanned", "total", "cached", "truncated", "elapsed", "matched"):
        stat[k] = got.get(k, stat[k])
    stat["roots"] = len(got.get("roots") or [])
    stat["dirs"] = len(got.get("dirs") or [])
    for err in (got.get("errors") or [])[:3]:
        out["errors"].append(str(err))

    rows = [r for r in (got.get("apps") or [])
            if r.get("appid") and r.get("match") == "high"]
    # 覆盖度先写清楚：0 个对上可能是「本机真没这个包」，也可能是「这轮没扫完」，两者
    # 对用户的意义完全相反，不能都糊成一句「没有对上的包」。
    cov = (f"本机缓存 {stat['total']} 个包，这轮读了 {stat['scanned']} 个"
           f"（复用缓存 {stat['cached']} 个），对上目标 {len(rows)} 个")
    if stat["truncated"]:
        cov += "；到点截断，剩下的下轮接着读（已读的已进缓存）"
    out["note"] = cov
    if not rows:
        return out

    # 清单阶段为了快只读最新两代主包，接口未必全；对上的这几个再解一遍（含分包、
    # 落盘、压缩脚本美化），拿完整接口清单和后端域名。
    try:
        pkgs = wxscan.mini_appids()
    except Exception:
        pkgs = {}
    out_root = ""
    try:
        from ...config import DATA_DIR
        out_root = os.path.join(str(DATA_DIR), "applet", "unpack")
    except Exception:
        out_root = ""

    async def one(rec: dict) -> dict:
        aid = str(rec.get("appid") or "")
        files = pkgs.get(aid) or []
        if not files:
            return rec
        try:
            more = await asyncio.wait_for(
                asyncio.to_thread(wxscan.mini_app_record, aid, files, max_pkgs=6,
                                  target=target, out_root=out_root, workers=4,
                                  unpack=True),
                timeout=max(20.0, budget))
        except Exception:
            return rec
        if not (more.get("apis") or more.get("files")):
            return rec
        more["match"] = rec.get("match")
        more["match_words"] = rec.get("match_words") or []
        return more

    picked = rows[:max(0, deep)]
    deep_rows: list[dict] = []
    if picked:
        done = await asyncio.gather(*(one(r) for r in picked), return_exceptions=True)
        for rec, res in zip(picked, done):
            deep_rows.append(res if isinstance(res, dict) else rec)
        deep_rows += rows[len(picked):]
    else:
        deep_rows = rows
    stat["deep"] = sum(1 for r in deep_rows if r.get("unpack_dir"))

    for rec in deep_rows:
        aid = str(rec.get("appid") or "")
        # 包里只有页面标题，没有平台上的「小程序注册名」。拿标题顶名字能让人看懂这是个
        # 什么小程序，但必须注明是页标题 —— 否则「活动详情」「进群」这种标题会被当成
        # 这个小程序的名字看。
        name = str(rec.get("name") or "")
        ap = Applet(name=name or f"AppID {aid}", appid=aid)
        ap.subject = str(rec.get("subject") or "")
        ap.domains = {d for d in (rec.get("domains") or []) if is_valid_domain(d)}
        ap.apis = list(dict.fromkeys(rec.get("apis") or []))[:60]
        ap.sources.append("local_wechat")
        words = "/".join(rec.get("match_words") or []) or "标题"
        ap.evidence.append(
            f"本机微信缓存命中（{words}）：{rec.get('files')} 个文件 / "
            f"{len(ap.apis)} 个接口 / {len(ap.domains)} 个域")
        if rec.get("titles"):
            ap.notes.append("包内页标题（非小程序注册名）：" + "、".join(rec["titles"][:3]))
        if rec.get("unpack_dir"):
            ap.notes.append(f"已解包到 {rec['unpack_dir']}")
        out["items"].append(ap)
        # 原始记录一并带走：资产行要拿它落接口 / 域名 / 密钥命中
        out["records"].append(rec)
    return out


# 正在跑的小程序采集，按名字归一化后共一趟（见 collect_applets）
_INFLIGHT: dict[str, asyncio.Task] = {}


async def collect_applets(target: str, *, limit: int = 8, deadline: float = 25.0) -> dict:
    """统一入口：target 是 AppID 就查档案；否则按名称/主体搜，再沿主体扩域名。

    返回 {"items": [...], "domains": [...], "notes": [...]}，
    domains 只放过了证据闸的确认域，收录站 / 第三方 / 待核验都不下发。

    外面套总时限：下文每段都有各自的超时，但「名称检索 → 读主体 → 沿主体跑完整企业
    证据链」串起来在上游变慢时会到几分钟。P1b 一次并发多个名字，等不起，到点交已有结果。
    默认 25s：检索 13s、主体扩线 11s 已各自封顶，正常路径实测 1～8s。
    """
    # 同一名字重复采集（品牌名 → 公司全名 → 品牌名，以及 L2 同名并发）直接共享这一趟：
    # 每条检索都要排引擎锁，排两遍就是把同一批结果再等一次
    _key = re.sub(r"\s+", "", target or "").lower()
    running = _INFLIGHT.get(_key)
    if running is not None:
        return await asyncio.shield(running)
    box: dict = {}
    inner = asyncio.create_task(_collect_applets(target, limit=limit, box=box))
    _INFLIGHT[_key] = inner
    try:
        return await asyncio.wait_for(asyncio.shield(inner), timeout=deadline)
    except asyncio.TimeoutError:
        if inner.done() and not inner.cancelled() and inner.exception() is None:
            return inner.result()
        got = box.get("out")
        if got:
            got.setdefault("notes", []).append(f"采集超时 {deadline:.0f}s，以下为已完成部分")
            return got
        return {"items": [], "domains": [],
                "notes": [f"采集超时 {deadline:.0f}s：小程序检索与主体扩线均未在时限内回来"]}
    finally:
        # 只摘自己这一趟：同一名字后一轮已在跑时，别把它的任务从表里删掉
        if _INFLIGHT.get(_key) is inner:
            _INFLIGHT.pop(_key, None)


def _label_of(dom: str) -> str:
    """域名主体（去点去连字符、转小写），用来和站点标题里的品牌写法比。"""
    return re.sub(r"[^a-z0-9]", "", (dom or "").split(".")[0].lower())


async def _confirm_own_domain(dom: str, subj: str) -> str:
    """这个根域是不是这个主体自己的站：是就回一句可核对的依据，空 = 没确认。

    两道依据，任一条成立才算：首页自报主体对得上（含同族主体）；或者站点标题里
    写着和域名主体同一个品牌英文名。都没有就不采信 —— 小程序卡片只可能挂在自己
    站上，采信一个别人的站等于又打偏一次。
    """
    from . import enterprise  # 懒导入：enterprise 里也懒导入本模块，模块级互导会成环

    try:
        score, _why = enterprise._domain_brand_score(dom, subj)
    except Exception:
        return ""
    if score <= 0:
        return ""
    title, subs = "", set()
    try:
        title, subs, _ok = await asyncio.wait_for(
            enterprise._site_check(dom, subj), 8.0)
    except Exception:
        title, subs = "", set()
    if subs:
        try:
            hit = enterprise._subject_matches(subj, subs)
        except Exception:
            hit = ""
        return f"首页自报主体「{hit}」" if hit else ""
    label = _label_of(dom)
    if label and label in re.sub(r"[^a-z0-9]", "", (title or "").lower()):
        return f"站点标题「{(title or '')[:30]}」与域名同写这个品牌"
    return ""


async def _subject_site_domains(subj: str) -> tuple[set[str], str]:
    """主体名 → 它自己的域名（备案里查不到网站备案时的第二路）。

    小程序卡片只可能出现在主体自己的站上，而备案库按单位名精确匹配时经常一条
    `site` 记录都没有（官网挂在同族另一家主体名下时就是这样），站点挖掘于是整段
    跳过、看上去像「这家没小程序」。这里拿公开检索的候选根域补：先用品牌域打分
    筛掉同行与聚合站，再逐个用首页自称主体 / 站点标题同名确认。

    返回 (确认的根域, 一句说明)。确认不了就如实写没确认，不把候选当结果。
    """
    from . import enterprise

    try:
        roots, _hits, told = await asyncio.wait_for(
            enterprise._search_roots(subj, limit=4), 15.0)
    except asyncio.TimeoutError:
        return set(), "公开检索 15s 没回来"
    except Exception as e:
        return set(), f"公开检索失败：{str(e)[:60]}"
    scored: list[tuple[int, str]] = []
    for d in roots or ():
        try:
            score, _why = enterprise._domain_brand_score(d, subj)
        except Exception:
            score = 0
        if score > 0:
            scored.append((score, d))
    if not scored:
        tail = f"（{'；'.join(told[:2])}）" if told else ""
        return set(), f"公开检索没找到写着这个品牌的域名{tail}"
    scored.sort(key=lambda x: (-x[0], x[1]))
    picks = [d for _s, d in scored[:3]]
    outs = await asyncio.gather(*(_confirm_own_domain(d, subj) for d in picks),
                               return_exceptions=True)
    got: dict[str, str] = {}
    for d, why in zip(picks, outs):
        if isinstance(why, BaseException) or not why:
            continue
        got[d] = str(why)
    if not got:
        return set(), (f"公开检索给了 {len(scored)} 个疑似品牌域（{'、'.join(picks)}），"
                       "首页都没确认成这个主体，未采信")
    detail = "、".join(f"{d}（{why}）" for d, why in list(got.items())[:3])
    return set(got), f"公开检索确认 {len(got)} 个主体域名：{detail}"


async def _collect_applets(target: str, *, limit: int = 8, box: dict | None = None) -> dict:
    target = (target or "").strip()
    LAST_CHANNELS.clear()
    notes: list[str] = []
    local: dict | None = None
    if APPID_RE.fullmatch(target):
        items = [await applet_by_appid(target)]
    else:
        # 两条检索并行：多引擎（拿收录页 / 开发者社区里的明文 AppID）与搜狗微信
        # （拿微信内分享链）。两条入口互不依赖，串行等于白等一轮。本机缓存清单一起
        # 排在这里：热跑 0.1s（只读索引），冷跑按预算到点截断，不额外占检索的等待。
        general, wx, local = await asyncio.gather(_hop(applet_by_name(target), 13),
                                                 _hop(applet_by_weixin_search(target), 11),
                                                 _local_bind(target),
                                                 return_exceptions=True)
        items = general if isinstance(general, list) else []
        wx_items = wx if isinstance(wx, list) else []
        if not items and wx_items:
            items = wx_items
        elif wx_items:
            have = {ap.appid for ap in items if ap.appid}
            named = {ap.name for ap in items if ap.name}
            merged = list(items)
            for ap in wx_items:
                if ap.appid and ap.appid in have:
                    for cur in merged:
                        if cur.appid == ap.appid:
                            cur.domains |= ap.domains
                            cur.sources = list(dict.fromkeys(cur.sources + ap.sources))
                            cur.evidence += [e for e in ap.evidence if e not in cur.evidence]
                    continue
                if not ap.appid and ap.name in named:
                    continue
                merged.append(ap)
            items = merged

    # 企业名 / 域名不进小程序名称检索：拿公司全名去搜「XX 小程序」只会搜回公司官网，
    # 那不是小程序面，搜索出来的 AppID 也和这个主体没有绑定关系。
    dom_like = is_valid_domain(target.replace(" ", ""))
    pkg_like = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){2,}", target))
    # 机构全称的判定统一走 naming：以前这里的后缀表只列了公司/集团/研究院/中心，
    # 「厦门市特种设备检验检测院」这种以「院」结尾的事业单位漏在表外，整串被当成
    # 小程序名去检索，平台按名字糊出来的同款小程序全部放行 —— 单项跑小程序的
    # 结果「全打偏」就是这么来的。
    entity_like = dom_like or pkg_like or naming.is_org_name(target)
    # 本机缓存里对上的原始记录：条目里只有名字和 AppID，接口 / 域名 / 密钥命中
    # 落在 record 上，单独带出去给资产行用
    local_apps: list[dict] = []
    local_ids: set[str] = set()
    local_ok = isinstance(local, dict)
    local_stat: dict = (local.get("stat") if local_ok else None) or {}
    if not APPID_RE.fullmatch(target):
        # 本机缓存这趟一律跑，不再等「检索一条 AppID 都没绑住」才查。以前品牌名输入只要
        # 平台糊回一个同名小程序，就再也不看本机，真正装着的包全被跳过 —— 本机明明有它，
        # 结果一条都对不上。清单带磁盘缓存，热跑近 0 秒，一律跑不亏；没有缓存根也如实报。
        if local_ok:
            loc_items = [ap for ap in (local.get("items") or []) if ap.appid]
            if local.get("note"):
                notes.append(str(local["note"]))
            notes += [str(e) for e in (local.get("errors") or [])]
            local_ids = {ap.appid for ap in loc_items}
            if loc_items:
                # 本机包里出来的条目自成一路：它已经按目标打过相关度（标题 / 主体 /
                # 域名任一处命中），比平台按名字糊的概念条目硬，排前面。没有 AppID 的
                # 条目也留着，交给下面的相关度过滤去判，别在这一步静默丢掉。
                items = loc_items + [ap for ap in items
                                     if not ap.appid or ap.appid not in local_ids]
                local_apps = list(local.get("records") or [])
        if entity_like:
            # 只留名字 / 主体 / 简介里真的写着目标的条目。平台按名字糊出来的同款小程序
            # 也带明文 AppID，但跟目标一个字都不沾，收下就是「单项小程序全打偏」。
            # 用户自己输入的那串原样保留（那是他要找的主体）；从它派生出来的简称
            # 至少 3 个字才算绑定依据 —— 2 字简称在平台上是同名词，长度放开就把
            # 「咖啡」「科技」这类公共词命中的小程序全收进来，等于没过滤。
            short = naming.short_name(target)
            alias = [w for w in (target, short) if w and (w == target or len(w) >= 3)]
            # 本机缓存条目已经在清单里按目标打过相关度（命中点可能是包内页标题或后端
            # 域名，而 _binds 只看名字/主体/简介），不能再拿 _binds 过一遍把真包筛掉。
            bound = [ap for ap in items if ap.appid in local_ids or _binds(ap, alias)]
            kept = [ap for ap in bound if ap.appid]
            # 名字/主体对得上、但检索结果里没给明文 AppID 的：打不开包，也进不了
            # 「小程序」实体面。以前这类被静默丢掉，一条说明都没有，看上去就是
            # 「没搜到」；现在留成线索单列，并把条数、名字写进说明。
            loose = [ap for ap in bound if not ap.appid]
            # 只回了一条「名字=输入本身、没有主体也没有域名」的占位不算线索：
            # 那是检索没命中时留的空壳，收进资产页只是自己搜自己。
            loose = [ap for ap in loose
                     if ap.domains or ap.subject or (ap.name and ap.name != target)]
            for ap in loose:
                ap.notes.append("检索结果没给明文 AppID：打不开包，先当线索留着")
            dropped = len(items) - len(bound)
            if dropped > 0:
                notes.append(f"{dropped} 条检索结果的名字/主体与目标无关，已丢弃")
            if loose:
                names = "、".join(ap.name for ap in loose[:3] if ap.name)
                notes.append(f"{len(loose)} 条线索只有名字、没有 AppID"
                             f"（{names}）：打不开包，不算查到的实体；"
                             "要拿实体请给 AppID，或先在微信里打开该小程序再跑本机解包")
            items = kept + loose
        if not any(ap.appid for ap in items) and not local_apps and entity_like:
            notes.append("按主体名检索未拿到明文 AppID；本机缓存也没对上，"
                         "可去微信里打开目标小程序后再跑「本机小程序解包」")

    domains: set[str] = set()
    # 主体自有域名：备案里的网站备案与域名输入都给得出。这些站的前端常直接写着小程序
    # 卡片（见 applets_from_sites），是一条能自己核对、不靠平台按名字猜的入口。
    site_domains: set[str] = set()
    if dom_like:
        site_domains.add(root_domain(target) or target)
    # AppID 直查：没有主体名就没什么可扩的，拿 wx… 去搜企业只会搜回无关站。
    # 企业主体输入：检索词本身就是开发主体，直接拿它扩线才有意义（App 侧查出来的
    # 「XX信息技术（厦门）有限公司」正是这一步要用的钥匙，见 pipeline_stages.p1b_mobile）。
    if APPID_RE.fullmatch(target):
        subjects: set[str] = set()
    elif entity_like and not dom_like and not pkg_like:
        subjects = {target} | {ap.subject for ap in items if ap.subject}
    else:
        subjects = {ap.subject for ap in items if ap.subject}
    if dom_like:
        # 域名进、主体出：小程序备案是按单位名精确查的，域名检索结果里根本没有主体名。
        # 不先拿域名反查备案主体，这条最常用的入口永远查不到小程序 / APP 备案号，
        # 单项小程序看着就像「这家没小程序」。
        rev = await _hop(passive.miit_reverse_domain(root_domain(target) or target), 12)
        unit = str((rev or {}).get("unit") or "").strip() if isinstance(rev, dict) else ""
        if unit:
            subjects.add(unit)
            notes.append(f"按域名反查到备案主体：{unit}")
        else:
            notes.append("域名反查不到备案主体，跳过小程序 / APP 备案查询")
    # 只沿读出来的主体扩线。小程序名本身就是品牌简称，拿它当企业名跑一遍完整
    # 证据链（工商 / 备案 / 候选域探活）实测 18s 起，且对瑞幸这类裸品牌本来就扩不出确认域。
    queue: list[str] = []
    for subj in sorted(subjects):
        # 只有「输入自己就是主体」时才能拿 target 去扩；名称输入沿同名扩会绕回本站
        if subj == target and not (entity_like and not dom_like and not pkg_like):
            continue
        queue.append(subj)
    # 搜狗微信给的公众号名是逗号拼起来的多个候选，拆开逐个扩
    flat: list[str] = []
    for subj in queue:
        flat.extend(s.strip() for s in subj.split(",") if s.strip())
    expand_list = list(dict.fromkeys(flat))[:2]

    async def _expand(subj: str):
        try:
            # 这里以前跑的是 enterprise.collect_entity 整条证据链（工商 → 备案 → 证据
            # 评分 → 移动端），实测 18s 起步、当场被 11s 的封顶掐死，每次都只留一条
            # 「主体扩线超时」，一个域名都没扩出来。小程序真正缺的是「这个主体名下
            # 登记了哪些小程序 / APP」，备案库按单位名一跳就能给出备案号。
            # alias 必须开：备案库按登记证上的单位名精确匹配，输入是简称、或是
            # 「…检验检测院」这种把第二名称写在括号里的事业单位名，不开别名解析就
            # 一律回假空。解析多一跳工商，给到 16s。
            rows = await _hop(passive.miit_company(subj, kinds=("site", "mapp", "app", "kapp"),
                                                   pages=1, size=40, alias=True), 16)
            return subj, rows or [], ""
        except asyncio.TimeoutError:
            return subj, None, f"主体小程序备案查询超时 {subj}（16s）"
        except Exception as e:
            return subj, None, f"主体小程序备案查询失败 {subj}: {str(e)[:60]}"

    expanded = len(expand_list)
    miit_hits = 0
    site_told: list[str] = []
    if expand_list:
        # 备案查询与「主体域名确认」互不依赖：串行就是白等一轮，一起投出去。
        _n = len(expand_list)
        _jobs = [asyncio.ensure_future(_expand(s)) for s in expand_list]
        _jobs += [asyncio.ensure_future(_subject_site_domains(s)) for s in expand_list]
        _done = await asyncio.gather(*_jobs)
        for subj, rows, err in _done[:_n]:
            if err or not rows:
                notes.append(err or f"备案库里这个主体名下没有小程序/APP 备案：{subj}")
                continue
            for row in rows:
                kind = str(row.get("kind") or "")
                if kind == "site":
                    # 网站备案顺手给出主体自己的域名；这些站要单独留下来读前端，
                    # 不当成「备案里的一个小程序」记条目。
                    for d in (row.get("domain") or "").replace(",", "\n").split("\n"):
                        d = d.strip().lower()
                        if (d and is_valid_domain(d) and not _is_third_party(d)
                                and not _is_package(d)):
                            site_domains.add(root_domain(d) or d)
                    continue
                if kind not in ("mapp", "app", "kapp"):
                    continue
                lic = str(row.get("serviceLicence") or "").strip()
                svc = str(row.get("serviceName") or "").strip()
                unit = str(row.get("unitName") or "").strip()
                label = passive.MIIT_KIND_LABEL.get(kind, kind)
                # 备案库的 mapp / app 记录实测只回单位名与备案号，serviceName 恒为空。
                # 以前把它拼成「主体名·小程序 2X」，看上去像查到了三个小程序，其实只是
                # 三份备案号 —— 单项小程序「全打偏」有一半是这么来的。备案就是备案：
                # 条目名直接标备案号，单位放 subject，一眼分清「登记信息」和「真包」。
                name = svc or (f"{label}备案 {lic}" if lic else f"{label}备案（无备案号）")
                ap = Applet(name=name, subject=unit, license=lic)
                # 备案号是登记信息，不是平台按名字猜的同款：条目哪怕没有 AppID 也站得住。
                ap.evidence.append(f"工信部备案{label}：{lic}" if lic else f"工信部备案{label}")
                ap.sources.append("miit")
                for d in (row.get("domain") or "").replace(",", "\n").split("\n"):
                    d = d.strip().lower()
                    if (d and is_valid_domain(d) and not _is_third_party(d)
                            and not _is_package(d)):
                        ap.domains.add(root_domain(d) or d)
                items.append(ap)
                miit_hits += 1
        LAST_CHANNELS["applet:miit"] = {
            "status": "ok" if miit_hits else "empty",
            "items": miit_hits,
            "note": "工信部备案按单位名精确匹配，直接给主体的小程序 / APP 备案号" if miit_hits
                    else "备案库里这个主体名下没有小程序 / APP 备案记录",
        }
        if miit_hits:
            notes.append("备案库只登记单位名与备案号，不公开小程序名称：这几条是备案记录"
                         "（没有 AppID，也没有包），不是小程序实体")
        for res in _done[_n:]:
            if not (isinstance(res, tuple) and len(res) == 2):
                continue
            doms, why = res
            if isinstance(doms, set):
                site_domains |= doms
            if why:
                site_told.append(str(why))
        _parts = list(site_told[:2])
        if site_domains:
            _parts.append(f"站点挖掘共 {len(site_domains)} 个域名")
        LAST_CHANNELS["applet:domain"] = {
            "status": "ok" if site_domains else "empty",
            "items": len(site_domains),
            "note": "；".join(_parts) or "主体名没给出可用域名",
        }
    else:
        LAST_CHANNELS.setdefault("applet:domain", {
            "status": "skip", "items": 0, "note": "没有可扩的主体名，跳过主体域名确认"})
    if not subjects:
        notes.append("未从搜索结果读到开发主体，跳过主体扩线；已知主体名请直接输入")
    elif not expanded:
        notes.append("搜索结果里的主体与小程序名相同，拿它查备案只会绕回本站，已跳过")
    # 主体自有站点里的小程序卡片：H5 唤起标签 / 文章卡片 / uni-app 配置都写着明文 AppID。
    # 这条路能自己核对来源，不靠平台按名字糊同款；一个域名都没拿到时如实记跳过，
    # 不写成「这家没小程序」。
    if site_domains:
        try:
            mined = await _hop(applets_from_sites(site_domains), SITE_BUDGET + 6)
        except asyncio.TimeoutError:
            mined = None
            LAST_CHANNELS["applet:site"] = {
                "status": "partial", "items": 0,
                "note": f"{len(site_domains)} 个主体域名没在 {SITE_BUDGET + 6:.0f}s 内读完，"
                        f"站点挖掘被截断"}
        try:
            have = {ap.appid for ap in items if ap.appid}
            added = [ap for ap in (mined or []) if ap.appid and ap.appid not in have]
            if added:
                items.extend(added)
                notes.append(
                    f"主体站点前端里挖到 {len(added)} 个明文小程序 AppID"
                    f"（{'、'.join(ap.appid for ap in added[:3])}）")
        except Exception:
            pass
    else:
        LAST_CHANNELS.setdefault("applet:site", {
            "status": "skip", "items": 0,
            "note": "没拿到主体域名（备案里没有网站备案，公开检索也没确认出主体站点、"
                    "输入也不是域名），跳过站点挖掘"})
    # 微信 CDN 直取这条路实测已死（302 空 Location / page-frame 404 / 经代理 403），
    # 以前每条 AppID 白等一轮还只回「已下架」。不再走：接口与后端域名一律从本机缓存
    # 解包出来，没解到就是没解到，在渠道状态里如实标失效。
    for ap in items:
        domains |= {d for d in ap.domains if not _is_third_party(d)}
    # 包名不是域名：`com.tencent.mm` 会被 is_valid_domain 误认成合法域，进流水线就当根域去扫
    domains = {d for d in domains if not _is_package(d)}

    # 这一枪到底调了哪几路：单项执行没有任务可翻渠道面板，得自带一份自报。
    with_api = sum(1 for ap in items if ap.apis)
    # 条目出自哪几路要自报：备案库给的是登记号、本机缓存给的是真包、其余是公开检索。
    # 混成一句「公开检索 ok」就看不出这批条目到底有没有一条是搜出来的。
    _src_label = {"miit": "备案库", "local_wechat": "本机缓存", "weixin": "搜狗微信",
                  "site": "主体站点"}
    _got: dict[str, int] = {}
    for ap in items:
        for s in (ap.sources or ["applet"]):
            k = _src_label.get(s, "公开检索")
            _got[k] = _got.get(k, 0) + 1
    if APPID_RE.fullmatch(target):
        _note = "按 AppID 直查"
    elif _got:
        _note = "、".join(f"{k} {v} 条" for k, v in _got.items())
    else:
        _note = "公开检索未命中"
    status: dict[str, dict] = {
        "applet": {"status": "ok" if items else "empty", "items": len(items), "note": _note},
    }
    _ls = local_stat or {}
    _cov = (f"本机 {_ls.get('total') or 0} 个包 · 读了 {_ls.get('scanned') or 0} · "
            f"复用缓存 {_ls.get('cached') or 0} · 对上 {_ls.get('matched') or 0}")
    if not local_ok:
        status["local_wechat"] = {"status": "skip", "note": "AppID 直查，不需要读本机清单"}
    else:
        # 0 个对上和「没扫完所以没对上」是两件事：截断时必须标 partial，不能报成 无数据。
        status["local_wechat"] = {
            "status": "ok" if local_apps else ("partial" if _ls.get("truncated") else "empty"),
            "items": len(local_apps),
            "note": _cov + ("；已解包取接口与域名" if local_apps else "；没有对上的包")
                    + ("（到点截断，剩下的下轮接着读）" if _ls.get("truncated") else ""),
        }
    # 接口与后端域名只可能来自本机解包；CDN 直取已确认失效，标出来别再当可用路。
    status["applet:cdn"] = {"status": "blocked", "items": with_api,
                            "note": "微信 CDN 直取需客户端签名（实测 302 空 Location / 403），"
                                    "取不到包；接口与后端域名改由本机解包提供"}

    # 每条检索入口各自的自报状态并进来：面板上「小程序检索·必应RSS 失效」比一句
    # 笼统的「小程序检索 无数据」有用得多 —— 打偏到底是没入口还是没命中，一看就分清。
    for k, v in LAST_CHANNELS.items():
        status.setdefault(k, v)

    out = {"items": [ap.as_dict() for ap in items][:limit],
           "apps": local_apps,
           "domains": sorted(d for d in domains if is_valid_domain(d)),
           "notes": list(dict.fromkeys(notes))[:8],
           "source_status": status}
    if box is not None:
        box["out"] = out
    return out
