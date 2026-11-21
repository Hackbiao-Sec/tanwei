"""企业主体信息收集（对齐天鉴·索舆 P1 阶段）。

国内企业对外资产一般有三条线索，任何一条都能把"一个公司名"扩成"一堆资产"：
  1. 工商股权：主体名 / 统一社会信用代码 → 全资子公司 → 一层层往下（默认 100% 控股才跟进）
  2. ICP 备案：备案主体 ↔ 域名 双向反查（主体名 → 域名清单；域名 → 主体名）
  3. 新媒体 / 应用：公众号、小程序、APP 名称（用于信息收集阶段的名称枚举）

**归属精度（2026-11 修订）**：企业名 → 域名没有权威免费源，靠单一搜索会把同名站全带进来
（"打偏"的根因）。现在每个候选域都要过一遍**证据打分**，得分与理由逐域落库：

    +40  站内自我声明：企业名与 ICP备案号 / 版权行 / 关于我们 出现在同一段
    +25  搜索结果标题命中企业名
    +15  搜索结果摘要命中企业名
    +10  多个引擎同时命中（同一根域被 2 个以上引擎排进结果）
    +10  ICP 反查命中（备案主体 == 企业名）
    +10  TLS 证书 SAN 命中企业名拼音或品牌
    -50  命中 gov.cn / edu.cn 等公共主体后缀

≥45 直接下发；10~44 记为待核验（下发但标注）；<10 丢弃。没有 AI key 这条链路照样跑完，
AI 只做两件加值：① 对 10~44 这一段做人工级复核 ② 一个域都没有时猜域名（猜出来仍要过打分闸）。

数据来源分层，按可用性降级，缺哪个都不阻塞：
  * 内置备案引擎：直连工信部备案库按主体名查网站备案（令版 + 滑块全在本项目内实现）
  * 内置工商链路：公开工商接口取股东 / 对外投资 / 分支机构，累计持股 100% 才算全资子公司
  * 免费公开：ICP 反查页、RDAP、证书 SAN、多引擎搜索
  * 需要 key：天眼查 / 爱企查（用户自备，走通用 HTTP 适配器）
  * AI 辅助：DeepSeek / OpenAI 复核归属、生成同主体别名 / 产品名 / 英文名 / 历史名
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import ssl
import time
from dataclasses import dataclass, field

from ...config import config
from ...utils import IP_RE, idn_ascii, is_valid_domain, root_domain, run_blocking
from ..sources import passive
from ..sources import search as web
from ..sources.passive import _get
from .names import core_same

# 本机可用的外部工具（存在即启用，缺失自动跳过；核心链路不依赖其中任何一个）
TOOL_PATHS = {
    "oneforall": ["oneforall", "oneforall.exe"],
    "ehole": ["ehole", "ehole.exe", "EHole"],
    "nuclei": ["nuclei", "nuclei.exe"],
    "httpx": ["httpx", "httpx.exe"],
    "ffuf": ["ffuf", "ffuf.exe"],
    "nmap": ["nmap", "nmap.exe"],
    "jadx": ["jadx", "jadx.bat", "jadx.exe"],
    "apktool": ["apktool", "apktool.bat"],
}

# 证据权重（改这里就能调松紧，不用动判定逻辑）
W_OWN_ROOT = 60        # 品牌自家产品主域：集团品牌官网常与品牌字面无关（腾讯↔qq.com），靠已知产品根域直接认定
W_DECLARED = 40        # 站内自我声明
W_SUBJECT = 40         # 站点页脚/标题自报的工商主体与目标一致
W_SITE_TITLE = 35      # 站点 <title>/og:site_name 自称企业/品牌（需与域名/声明交叉）
W_TITLE = 25           # 搜索结果标题命中
W_SNIPPET = 15         # 搜索结果摘要命中
W_MULTI_ENGINE = 10    # 多引擎同时命中
W_ICP = 10             # ICP 反查命中
W_CERT = 10            # 证书 SAN 命中
W_PUBLIC_TLD = -50     # 公共主体后缀
W_PLATFORM = -60       # 地图 / 黄页 / 论坛 / 招聘 / 媒体转载等平台站：标题里出现企业名是常态，不是归属证据
W_FOREIGN_SUBJECT = -60  # 站点自报主体与目标无关：仿冒官网 / 加盟招商站，品牌名写得再多也不算自家资产
W_LATE = -10           # 标题命中但排在搜索结果后段
W_MENTION_ONLY = -5    # 只在摘要里顺带提及
TOP_RANK = 3           # 前 4 个名次算「引擎认为这就是官方」
CONFIRM_SCORE = 45     # 直接下发
PENDING_SCORE = 10     # 下发但标"待核验"

# 平台站根域：这些站的标题写哪个企业名都是由用户搜出来的，永远不能当"自有资产"
_PLATFORM_ROOTS = (
    "360.cn", "360.com", "baidu.com", "map.baidu.com", "amap.com", "gaode.com", "sogou.com",
    "so.com", "bing.com", "google.com", "qq.com", "weixin.qq.com", "sohu.com", "sina.com.cn",
    "163.com", "toutiao.com", "douyin.com", "xiaohongshu.com", "weibo.com", "zhihu.com",
    "douban.com", "tieba.baidu.com", "bilibili.com", "58.com", "ganji.com", "zhaopin.com",
    "51job.com", "lagou.com", "liepin.com", "nowcoder.com", "bosszhipin.com", "csdn.net",
    "jianshu.com", "juejin.cn", "cnblogs.com", "oschina.net", "gitee.com", "github.com",
    "qcc.com", "tianyancha.com", "qichacha.com", "aiqicha.baidu.com", "qixin.com",
    "dianping.com", "meituan.com", "pinduoduo.com", "taobao.com", "tmall.com", "jd.com",
    "1688.com", "alibaba.com", "made-in-china.com", "hc360.com", "china.cn", "b2b168.com",
    # B2B 黄页 / 供求信息 / 招标 / 行业门户：这些站收录了哪家企业，标题里就写哪家的名字，
    # 首页标题永远只写平台自己的口号。漏掉一个的代价不是少一条资产，而是整条流水线拿
    # 平台根域去跑被动子域 —— 顺企网一个根域就能灌回七百多条黄页子域。
    "11467.com", "huangye88.com", "51sole.com", "likuso.com", "zk71.com", "qianlima.com",
    "gongchang.com", "ebdoor.com", "makepolo.com", "qjy168.com", "herostart.com",
    "sooshong.com", "zhaoshang.net", "chinabgao.com", "b2b.cn", "cnlinxi.com",
    "gov.cn", "edu.cn", "org.cn", "ac.cn", "mil.cn", "wikipedia.org", "baike.com",
    "boss.com", "chinaz.com", "wjx.cn", "docin.com", "doc88.com", "book118.com",
    # 内容平台 / 聚合站：标题写企业名是「谁报道了它」，不是「这是它的站」
    "coze.cn", "jianshu.com", "zhuanlan.zhihu.com", "ixigua.com",
    "huxiu.com", "36kr.com", "chinadaily.com.cn", "people.com.cn", "xinhuanet.com",
    "cctv.com", "thepaper.cn", "jiemian.com", "yicai.com", "caixin.com", "eastmoney.com",
    "sina.com", "ifeng.com", "netease.com", "cnbeta.com", "ithome.com", "techweb.com.cn",
    "donews.com", "leiphone.com", "geekpark.net", "sspai.com", "woshipm.com",
    "app.mi.com", "sj.qq.com", "wandoujia.com", "coolapk.com", "apkpure.com",
)


@dataclass
class DomainEvidence:
    """一个候选域的归属证据：得分 + 理由列表（原样落库，UI 直接显示）。"""

    domain: str = ""
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    engines: list[str] = field(default_factory=list)
    status: str = "pending"          # confirmed / pending / rejected
    hits: list[str] = field(default_factory=list)   # 命中该域的结果标题（最多 3 条）
    site_title: str = ""             # 站点自己写的标题（最强证据之一）

    def add(self, weight: int, reason: str) -> None:
        self.score += weight
        self.reasons.append(reason)

    def as_dict(self) -> dict:
        return {"domain": self.domain, "score": self.score, "status": self.status,
                "engines": self.engines, "reasons": self.reasons, "hits": self.hits,
                "site_title": self.site_title}


@dataclass
class EntityInfo:
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    domains: set = field(default_factory=set)
    evidence: dict = field(default_factory=dict)   # domain → DomainEvidence
    sub_companies: list[str] = field(default_factory=list)
    equity: list[str] = field(default_factory=list)   # 达到控股门槛的子公司（按主体的持股线）
    equity_relation: dict = field(default_factory=dict)  # 子公司名 → 几级投资/累计持股/母体
    # 这次穿透的链路全量（`eq.as_dict()` + `ratio`）：主体阶段要拿它落控股 / 投资 /
    # 股东 / 分支机构资产，并给任务页画股权穿透图。只留名字的话这些行一条都建不出来。
    equity_detail: dict = field(default_factory=dict)
    apps: list[str] = field(default_factory=list)
    applets: list[str] = field(default_factory=list)
    icp: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    brand: str = ""


def tool_available(name: str) -> str:
    for cand in TOOL_PATHS.get(name, []):
        p = shutil.which(cand)
        if p:
            return p
    # 走界面一键安装的会落在本程序自带的 tools 目录，不在 PATH 上
    try:
        from .. import installer

        native = (cand or "").replace("/", os.sep)
        for c in (installer.TOOLS_DIR / native, installer.TOOLS_DIR / name / native):
            if c.exists():
                return str(c)
    except Exception:
        pass
    try:
        from .. import installer

        return installer._resolve_bin(name)
    except Exception:
        return ""


# ─────────────── 工商 / ICP ───────────────
def _icp_key(item: dict) -> tuple:
    """一条备案的去重键：同一域名可能挂多条号，同一号也可能对应多个域名。

    两个都空的行算无效，直接丢弃，免得空记录在资产页凑行数。
    """
    dom = str(item.get("domain") or "").strip().lower()
    num = str(item.get("icp") or "").strip().lower()
    if not dom and not num:
        return ()
    return (dom, num)


def _icp_empty_reason(company: str) -> str:
    """备案反查没拿到行时，说清是「真没有」还是「这一轮没查到」。

    频控 / 边缘风控 / 滑块未过都会让接口回空，这跟「这家企业没备案」是两件事。
    以前一律写成「未命中」，等于把网络侧的一次失败永久记成企业属性，
    这轮查不到、下轮查到了，数据就自相矛盾。
    """
    from ..sources import passive

    why = passive.miit_last_error()
    if why:
        return f"备案反查这一轮被挡（{why}），改走品牌检索与域名猜测"
    circ = passive._miit_circuit()
    if circ:
        return f"备案反查冷却中（{circ}），改走品牌检索与域名猜测"
    return f"「{company}」在备案库没有登记主体，改走品牌检索与域名猜测"


_icp_company_hint = ""


def icp_company_hint() -> str:
    """最近一次按主体名反查备案时的「口径提示」（主体名与登记名不一致等）。空串表示没有。"""
    return _icp_company_hint


async def icp_by_company(company: str, declared: list[str] | None = None, *,
                         kinds=("site",), pages: int = 2, size: int = 40,
                         retry: int | None = None, gap: float | None = None,
                         alias: bool = True, force: bool = False,
                         miit_api: str = "") -> list[dict]:
    """按企业名反查备案域名：内置备案引擎 → 公开反查页兜底。

    主路是本项目自带的备案查询引擎（见 passive.miit_company）：登录取令 + 滑块通过 +
    按单位名检索，走备案库本身，不依赖本机装任何东西。
    `declared` 是调用方已知的根域；有的话先用它反查备案主体全称，再用全称去翻页——
    备案库按单位名是精确匹配，简称查不到不代表没备案。
    `kinds` / `pages` / `size` / `retry` / `gap` 都是单项执行时可调的参数，
    非网站类备案（APP / 小程序 / 快应用）没有域名，落在 items 的 `kind` 字段上。
    自建库没收录该主体时，用公开反查页补一次；再不行交给上层「搜索 + 拼音猜测 + AI 复核」。
    `miit_api` 留空用内置备案接口地址，配置或表单里可以换成备用地址。
    """
    global _icp_company_hint
    _icp_company_hint = ""
    out: list[dict] = []
    seen: set[str] = set()

    def push(dom, unit, source, icp="", kind="site", app="", owner=None):
        d = (dom or "").strip().lower().split()[0] if dom else ""
        d = d.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        # 备案库里中文域名是原样登记的（「小米科技有限责任公司.中国」），转成 punycode
        # 才能进 DNS / 首页探活；留在 UTF-8 形态上等于把这条备案当脏值扔掉。
        d = idn_ascii(d)
        if kind == "site" and (not d or "." not in d):
            return
        key = (d or app) + "|" + kind
        if not (d or app) or key in seen:
            return
        seen.add(key)
        # 备案主体与目标的关系分三档，不能压成一个布尔：
        #   self    = 就是本主体，属行政登记结论
        #   family  = 同一品牌的兄弟主体（集团里另一家登记公司），进候选池但按线索计分
        #   foreign = 上级机关 / 同行 / 托管方，只列档不扩展
        # 以前只有 True/False 两档，集团的主干站（登记在区域公司名下）被并进 False，
        # 整片自家域名就这样被挡在候选池外。
        u = unit or company
        if owner is None:
            if _subject_self(u, company):
                rel = "self"
            elif _subject_family(u, company):
                rel = "family"
            else:
                rel = "foreign"
        else:
            rel = "self" if owner else "foreign"
        item = {"domain": d, "unit": u, "source": source, "kind": kind,
                "owner_match": rel != "foreign", "relation": rel}
        if icp:
            item["icp"] = icp
        if app:
            item["app"] = app
        out.append(item)

    # 1) 内置备案引擎（按单位名查备案，只认主体名对得上的行）
    #    备案库对 `unitName` 是精确匹配：全称有上千条，简称是 0 条。所以先用已知根域
    #    反查一次主体全称，拿全称再翻页；拿不到才用传进来的名字直接试（带后缀时才会命中）。
    names = [company]
    for dom in (declared or [])[:3]:
        try:
            rev = await passive.miit_reverse_domain(dom, retry=retry, api=miit_api)
        except Exception:
            continue
        unit = (rev or {}).get("unit") or ""
        if unit and unit not in names:
            names.insert(0, unit)
            break
    blocked = ""
    # 这个值记的是「最近一次失败」，上一家企业留下的原因会串到这一家头上，先清。
    passive._miit_company_error = ""
    try:
        rows: list[dict] = []
        for name in names:
            rows = await passive.miit_company(name, kinds=kinds, pages=pages, size=size,
                                              retry=retry, gap=gap, alias=alias,
                                              force=force, api=miit_api)
            if rows:
                break
        if not rows:
            # 空结果有两种：这家主体确实没有备案，或者这一轮被频控 / 被挡。
            # 记下原因，上层才不会把「被挡」写成「未命中」。
            blocked = passive.miit_last_error()
        if rows:
            _mark("miit", "ok", items=len(rows))
        elif blocked:
            _mark("miit", _status_of(blocked), blocked)
        else:
            _mark("miit", "empty", "备案库没有该主体名下的记录（这一轮没报错）")
        family_units: list[str] = []
        for row in rows:
            unit = row.get("unitName") or ""
            # 主体名要能对上：要么全等，要么互为包含（分支机构常带括号后缀），
            # 要么字号相同只差区划 / 组织形式（任务里填简称时就是这种，
            # 「漳州九龙江集团」对「漳州市九龙江集团有限公司」），要么是同一品牌的兄弟主体。
            # 最后两档以前被当成「对不上」整行丢掉，集团官网登记在区域公司名下时
            # （`luckincoffee.com` 挂在北京公司），自家的网站备案就这样一条都进不来。
            same = _subject_same(unit, company)
            if not same:
                if not _subject_family(unit, company):
                    continue
                if unit not in family_units:
                    family_units.append(unit)
            kind = str(row.get("kind") or "site")
            lic = row.get("serviceLicence") or ""
            if kind != "site":
                push("", unit, "miit", lic, kind=kind,
                     app=row.get("serviceName") or lic)
                continue
            for d in (row.get("domain") or "").replace(",", "\n").split("\n"):
                push(d, unit, "miit", lic)
        # 集团主体在备案库里常只登记了 APP / 小程序，网站备案记在区域公司名下。
        # 主名一条网站备案都没有时，按上面发现的兄弟主体补查一次；最多两家，
        # 备案接口按出口 IP 频控，翻多了整轮会被挡。
        if out and not any(x.get("kind") == "site" for x in out):
            for fu in family_units[:2]:
                try:
                    extra = await passive.miit_company(fu, kinds=("site",), pages=pages,
                                                       size=size, retry=retry, gap=gap,
                                                       alias=False, api=miit_api)
                except Exception:
                    continue
                for row in extra or []:
                    lic = row.get("serviceLicence") or ""
                    for d in (row.get("domain") or "").replace(",", "\n").split("\n"):
                        push(d, row.get("unitName") or fu, "miit", lic)
                if any(x.get("kind") == "site" for x in out):
                    break
    except Exception as e:
        blocked = f"{type(e).__name__}: {e}"[:120]
        passive.LAST_GET_ERROR = f"miit: {blocked}"[:160]
    # 只登记了 APP / 小程序备案的主体不在这里收工：那些行没有域名，直接返回等于
    # 「查到了备案却一个网站都没拿到」，集团主体（网站备案挂在区域公司名下）整片域
    # 就是这样漏掉的。再给工商备案一次机会，补不到再按原样返回。
    if out and any(str(x.get("kind") or "site") == "site" for x in out):
        return out

    # 2) 公开工商接口的备案信息。
    #    内置备案引擎被挡 / 频控 / 滑块没过时，只要工商登录态还有效，这里仍能出域名。
    try:
        from . import equity as _equity

        for row in await _equity.aqc_icp(company, pages=1, size=100):
            push(row.get("domain") or "", row.get("unit") or company, "aqc",
                 row.get("icp") or "")
        _mark("aiqicha_icp", "ok" if out else "empty",
              "" if out else "工商接口里该主体名下没有备案域名", items=len(out))
    except Exception as e:
        _mark("aiqicha_icp", "error", f"{type(e).__name__}: {e}"[:120])
    if out:
        return out

    # 3) 公开反查页兜底。
    #    这个站的正文由脚本异步填，常态是 200 + 空正文，所以给 6s 短超时：等不到就当没有，
    #    别把整轮采集拖十几秒 —— 备案缺了还有搜索引擎那条主路，两秒内就能出结果。
    #    被频控 / 被风控时连这一跳也省掉：那一跳打的是同一台出口 IP，等来的还是空。
    r = None if "频控" in blocked or "风控" in blocked else await _get(
        f"https://icp.aizhan.com/{company}/", timeout=6)
    if r is not None and r.status_code == 200:
        for m in re.finditer(r'href="https?://(?:www\.)?([a-z0-9\-]+\.[a-z]{2,6})/?"[^>]*>\s*([^<]{2,40})\s*<',
                             r.text, re.I):
            dom = m.group(1).lower()
            if is_valid_domain(dom):
                push(dom, company, "aizhan")
        _mark("aizhan", "ok" if out else "empty",
              "" if out else "反查页 200 但正文里没有可用的备案链接", items=len(out))
    elif r is None:
        _mark("aizhan", "skip", f"备案引擎报「{blocked}」，同一出口先跳过反查页")
    else:
        _mark("aizhan", "blocked" if r.status_code in (401, 403, 429) else "error",
              f"反查页 HTTP {r.status_code}")
    if out:
        return out

    # 4) 搜索引擎找官网 → 域名反查备案。
    #    事业单位 / 机关的主体名常登记成带括号的第二名称
    #    （「厦门市特种设备检验检测院(厦门市特种设备应急处置中心)」），
    #    备案库对 unitName 是精确匹配，拿裸名去查永远是 0 条。
    #    反过来按官网域名反查，一次就能带出带括号的主体全称与备案号；
    #    再用这个全称把该主体名下其它已备案域名一并翻出来。
    #    主体名必须与输入互含才算同一个主体，否则同行机构（省院 / 市院）会被认领过来。
    #    机关的官网常登记在上级单位名下（区局站点挂在政府办公厅），互含校验会把它挡掉，
    #    所以对不上的候选先存起来：真的一条都没有时，按官网实际备案主体列出来并标注，
    #    比只回一个 0 条有用。
    try:
        roots, _hits, _told = await _search_roots(company)
        _mark("searchengine", "ok" if roots else "empty",
              f"召回 {len(roots)} 个候选官网域名" if roots else "没召回可用的官网域名",
              items=len(roots))
    except Exception as e:
        roots, _hits = set(), []
        _mark("searchengine", "error", f"{type(e).__name__}: {e}"[:120])
    # 引擎召回常混进外省政务站与同行机关（拿区局全称搜，前几条可能全是总局和别的城市）。
    # 按命中正文给候选打分：标题/摘要里写着目标全称的优先，至少写着本地行政区划的次之，
    # 一条都不沾的丢掉。既省反查次数，也不会把无关站的备案当成结果。
    loc0 = _locality(company)
    full0 = re.sub(r"\s+", "", company or "")
    score: dict[str, int] = {}
    for h in _hits or []:
        d = (getattr(h, "domain", "") or "").lower()
        r = (root_domain(d) or d) if d else ""
        if not r or r not in roots:
            continue
        txt = re.sub(r"\s+", "", f"{getattr(h, 'title', '')}"
                                  f"{getattr(h, 'snippet', '')}{getattr(h, 'url', '')}")
        s = 2 if full0 and full0 in txt else (1 if loc0 and loc0 in txt else 0)
        if s > score.get(r, -1):
            score[r] = s
    cands = [r for r, s in sorted(score.items(), key=lambda kv: (-kv[1], kv[0])) if s >= 1]
    ckey = re.sub(r"[\s\u3000()（）·,，.。]", "", company or "")
    loc = _locality(company)
    near: list[tuple[str, str, str]] = []
    for dom in cands[:8]:
        try:
            rev = await passive.miit_reverse_domain(dom, retry=retry, api=miit_api)
        except Exception:
            continue
        unit = ((rev or {}).get("unit") or "").strip()
        ukey = re.sub(r"[\s\u3000()（）·,，.。]", "", unit)
        if not ckey or not unit or not (ckey in ukey or ukey in ckey):
            # 机关站点登记在上级单位名下时名不对名，用行政区划前缀兜底：
            # 「厦门市市场监督管理局」的官网登记在「厦门市人民政府办公厅」，同城才认。
            # 企业名基本不带行政区划前缀，这条兜底对它们不适用：搜索召回里混着公告托管站、
            # 同行门户，只凭两个字的公共片段就会把别人的备案认领过来（「福建龙溪轴承…」
            # 曾因此输出深圳证券信息有限公司的 cninfo.com.cn）。
            if loc and unit and loc in unit:
                near.append((dom, unit, (rev or {}).get("icp") or ""))
                if len(near) >= 2:
                    break
            continue
        push(dom, unit, "miit", (rev or {}).get("icp") or "")
        try:
            extra = await passive.miit_company(unit, kinds=kinds, pages=pages, size=size,
                                               retry=retry, gap=gap, alias=False,
                                               api=miit_api)
        except Exception:
            extra = []
        for row in extra or []:
            kind = str(row.get("kind") or "site")
            lic = row.get("serviceLicence") or ""
            if kind != "site":
                push("", unit, "miit", lic, kind=kind,
                     app=row.get("serviceName") or lic)
                continue
            for d in (row.get("domain") or "").replace(",", "\n").split("\n"):
                push(d, unit, "miit", lic)
        break
    if out:
        _mark("miit_reverse", "ok", f"按域名反查到同名备案主体，出 {len(out)} 条",
              items=len(out))
    elif cands:
        _mark("miit_reverse", "not_found" if not near else "empty",
              "候选域名的备案主体都与输入主体对不上" if near else "候选域名没有备案记录",
              items=len(near))
    else:
        _mark("miit_reverse", "skip", "搜索引擎没给出可反查的候选域名")
    # 裸名直查备案库是精确匹配，机构名带括号、带曾用名就查不到；域名反查却能对上。
    # 不把这条改写清楚，面板上「工信部备案 可用·无数据」和「域名反查 出 3 条」会并排出现，
    # 看着像备案库没干活，实际是这一跳的名字写法不对。
    if out and (LAST_STATUS.get("miit") or {}).get("status") in ("empty", "not_found"):
        _mark("miit", "not_found",
              "备案库按单位名是精确匹配，这个名字没命中；已改按官网域名反查，"
              "结果见「工信部备案·域名反查主体」")
    if out or not near:
        return out
    for dom, unit, icp in near[:3]:
        push(dom, unit, "miit", icp, owner=False)
    if out:
        _icp_company_hint = (
            f"官网 {near[0][0]} 的备案登记在「{near[0][1]}」名下，"
            f"与输入主体不同；已按官网实际备案列出，供人工确认（不计入候选域）")
        _mark("miit_reverse", "not_found",
              f"官网备案登记在「{near[0][1]}」名下，与输入主体不同，只列档不当候选域",
              items=len(out))
    return out


_icp_domain_error = ""


def icp_domain_error() -> str:
    """最近一次域名反查备案失败的原因（被挡 / 频控 / 未过滑块）。空串表示确实没有备案。"""
    return _icp_domain_error


#: 最近一次主体采集里每一路外部渠道的结果（``{source: {status, note, items}}``）。
#: 任务页的「数据渠道」面板靠它说清「这趟用了哪些渠道、哪条失效了」，
#: 不然失败原因只能从几十行日志里翻。
LAST_STATUS: dict[str, dict] = {}


def _mark(source: str, status: str, note: str = "", items: int = 0) -> None:
    """记一路渠道本轮的结果。

    同一路渠道一轮里会被调多次（全称反查 → 原名直查 → 子公司兜底），后一次的
    「没有记录」不能把前一次「取到 N 条」盖掉：渠道面板会因此把明明出了备案的
    那一路写成「可用·无数据」，让人以为备案库这趟没起作用。取到数据优先，条数累加。
    """
    key = str(source)
    prev = LAST_STATUS.get(key) or {}
    got = int(items or 0)
    if prev.get("status") == "ok" and status != "ok":
        prev["items"] = int(prev.get("items") or 0) + got
        return
    total = got
    if status == "ok" and prev.get("status") == "ok":
        total = int(prev.get("items") or 0) + got
    LAST_STATUS[key] = {"status": str(status), "note": str(note or "")[:160], "items": total}


def _status_of(text: str) -> str:
    """把备案引擎给的失败原因归成渠道状态：被挡 / 超时 / 冷却 / 报错。"""
    t = str(text or "")
    if not t:
        return "empty"
    if any(w in t for w in ("频控", "风控", "拦截", "429", "滑块", "校验", "禁止")):
        return "blocked"
    if "冷却" in t:
        return "quota"
    if "超时" in t or "imeout" in t:
        return "timeout"
    return "error"


async def icp_by_domain(domain: str, *, pages: int = 1, size: int = 40,
                        retry: int | None = None, gap: float | None = None,
                        force: bool = False, miit_api: str = "") -> list[dict]:
    """域名 → 备案号与备案主体：内置备案引擎为主，公开反查页兜底。

    备案库对域名是模糊匹配，一次检索能同时带出主体全称和该主体下登记的其它域名，
    比只认一条正则稳。引擎被挡（滑块 / 频控）时记下原因，别把一次网络失败写成「没有备案」。
    `pages` / `size` / `retry` / `gap` / `force` 是单项执行时可调的参数。
    """
    global _icp_domain_error
    _icp_domain_error = ""
    dom = (domain or "").strip().lower()
    dom = dom.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not dom or "." not in dom:
        return []
    out: list[dict] = []
    seen: set[str] = set()

    def push(d: str, icp: str, unit: str, source: str) -> None:
        d = (d or dom).strip().lower()
        if not d or d in seen:
            return
        seen.add(d)
        out.append({"domain": d, "icp": icp or "", "unit": unit or "",
                    "source": source, "kind": "site"})

    # 1) 内置备案引擎（可翻页）
    from ..sources import passive

    # 备案库对 domain 是精确匹配：`xmaj.com` 有记录，`www.xmaj.com` 是 0 条。
    # 所以按「完整域 → 根域」逐个试；第一枪被频控 / 被挡就停，
    # 同一台出口再撞一次只会把冷却拖长。
    cands: list[str] = []
    for c in (dom, root_domain(dom) or dom):
        if c and c not in cands:
            cands.append(c)
    rows: list[dict] = []
    got_error = ""
    hit_dom = dom
    try:
        for cand in cands:
            total = 0
            part_rows: list[dict] = []
            for page in range(1, max(1, int(pages or 1)) + 1):
                part = await passive.miit_query(cand, "site", page=page, size=size,
                                                retry=retry, gap=gap,
                                                force=force and page == 1,
                                                api=miit_api)
                part_rows.extend(part.get("rows") or [])
                total = int(part.get("total") or 0)
                if part.get("error"):
                    got_error = str(part["error"])[:120]
                    break
                if len(part_rows) >= total:
                    break
            if part_rows:
                rows = part_rows
                hit_dom = cand
                break
            if got_error:
                break
    except Exception as e:
        got_error = f"{type(e).__name__}: {e}"[:120]
    unit_hit = ""
    icp_hit = ""
    for row in rows:
        unit = row.get("unitName") or ""
        icp = row.get("serviceLicence") or ""
        for d in (row.get("domain") or "").replace(",", "\n").split("\n"):
            d = d.strip().lower()
            if d and (d == hit_dom or d.endswith("." + hit_dom)):
                push(d, icp, unit, "miit")
                if not unit_hit:
                    unit_hit, icp_hit = unit, icp
        if not unit_hit and unit:
            unit_hit, icp_hit = unit, icp
    if unit_hit and not out:
        # 检索有命中主体但域名栏没写全（部分主体只登记证书号），仍按主体回一条，
        # 上层要的是「这个域名备案在谁名下」。
        push(dom, icp_hit, unit_hit, "miit")
    if out:
        _mark("miit_domain", "ok", f"{hit_dom} 备案在「{unit_hit}」名下", items=len(out))
        return out
    if got_error:
        _icp_domain_error = got_error[:160]
        _mark("miit_domain", _status_of(got_error), got_error)
        return out
    circ = passive._miit_circuit()
    if circ:
        _icp_domain_error = f"备案引擎冷却中（{circ}）"
        _mark("miit_domain", "quota", _icp_domain_error)
    else:
        _icp_domain_error = passive.miit_last_error()
        _mark("miit_domain",
              _status_of(_icp_domain_error) if _icp_domain_error else "not_found",
              _icp_domain_error or "该域名在备案库没有记录")

    # 2) 公开反查页兜底
    r = await _get(f"https://icp.aizhan.com/{dom}/", timeout=15)
    if r is None or r.status_code != 200:
        _mark("aizhan_domain",
              "timeout" if r is None else
              ("blocked" if r.status_code in (401, 403, 429) else "error"),
              "反查页没响应" if r is None else f"反查页 HTTP {r.status_code}")
        return out
    m = re.search(r"(京ICP备|沪ICP备|粤ICP备|浙ICP备|苏ICP备|川ICP备|闽ICP备|鲁ICP备|鄂ICP备|湘ICP备|"
                  r"豫ICP备|冀ICP备|皖ICP备|赣ICP备|辽ICP备|吉ICP备|黑ICP备|桂ICP备|琼ICP备|渝ICP备|"
                  r"津ICP备|新ICP备|藏ICP备|蒙ICP备|宁ICP备|青ICP备|甘ICP备|云ICP备|贵ICP备|晋ICP备|"
                  r"陕ICP备|B2-|京公网安备)[0-9\-A-Za-z]+", r.text)
    unit = re.search(r"(?:主办单位名称|单位名称)[^<]{0,10}</[^>]+>\s*<[^>]+>([^<]{2,60})", r.text)
    if m:
        push(dom, m.group(0), unit.group(1).strip() if unit else "", "aizhan")
        if out:
            _icp_domain_error = ""
            _mark("aizhan_domain", "ok", f"反查页给出 {m.group(0)}", items=len(out))
    if not out:
        _mark("aizhan_domain", "not_found", "反查页 200 但没匹配到备案号")
    return out


async def icp_lookup(target: str, *, kinds=("site",), pages: int = 2, size: int = 40,
                     retry: int | None = None, gap: float | None = None,
                     alias: bool = True, force: bool = False,
                     site_limit: int = 0, miit_api: str = "") -> dict:
    """备案查询统一入口：输入可以是域名，也可以是单位名。

    返回 ``{"items","sites","apps","stats","total","mode","notes"}``：
    - ``items`` 每行带 ``kind``（site / app / mapp / kapp）；
    - 网站类落在 ``domain``，非网站类落在 ``app``（应用名）与 ``icp``（备案号）；
    - ``site_limit`` > 0 时只保留前 N 条网站域名（控制出表量）。

    参数全部来自单项执行的表单：``kinds`` 选备案类型，``pages`` 每类翻几页，
    ``size`` 每页条数（服务端上限 40），``retry`` 单条查询重试次数，``gap`` 查询间隔，
    ``force`` 绕过 7 天缓存重查；``miit_api`` 换备案接口地址（留空用内置）。
    """
    from ..sources import passive

    raw = (target or "").strip()
    looks_domain = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-.]*\.[A-Za-z]{2,}", raw))
    mode = "domain" if looks_domain else "company"
    ks = tuple(k for k in (kinds or ("site",)) if k in ("site", "app", "mapp", "kapp"))
    if not ks:
        ks = ("site",)
    if force:
        passive._miit_circuit("", force=True)
        passive._miit["token"] = ""

    notes: list[str] = []
    rows: list[dict] = []
    if mode == "domain":
        rows = await icp_by_domain(raw, pages=max(1, int(pages or 1)), size=size,
                                   retry=retry, gap=gap, force=force,
                                   miit_api=miit_api)
    else:
        rows = await icp_by_company(raw, kinds=ks, pages=pages, size=size,
                                    retry=retry, gap=gap, alias=alias,
                                    force=force, miit_api=miit_api)

    stats = {"site": 0, "app": 0, "mapp": 0, "kapp": 0}
    for r in rows:
        k = str(r.get("kind") or "site")
        if k not in stats:
            k = "site"
            r["kind"] = k
        stats[k] += 1
    sites = [r for r in rows if str(r.get("kind") or "site") == "site" and r.get("domain")]
    apps = [r for r in rows if str(r.get("kind") or "site") != "site"]
    if site_limit and int(site_limit) > 0 and len(sites) > int(site_limit):
        notes.append(f"网站备案 {len(sites)} 条，按出表上限只列前 {int(site_limit)} 条")
        sites = sites[:int(site_limit)]

    if not rows:
        why = icp_domain_error() if mode == "domain" else _icp_empty_reason(raw)
        st = passive._miit_state()
        if st.get("cool_left"):
            notes.append(f"备案引擎冷却 {int(st['cool_left'])} 秒"
                         f"（{st.get('reason') or '连续未通过校验'}）")
        if why:
            notes.append(f"本轮没有备案记录：{why}")
    elif mode == "company":
        notes.append(f"备案类型：网站 {stats['site']} · APP {stats['app']} · "
                     f"小程序 {stats['mapp']} · 快应用 {stats['kapp']}")
    if mode == "company":
        hint = icp_company_hint()
        if hint:
            notes.append(hint)
    return {"target": raw, "mode": mode, "items": sites + apps, "sites": sites,
            "apps": apps, "stats": stats, "total": len(sites) + len(apps),
            "notes": notes}


async def _equity_detail(name: str, ratio: float | None = None, depth: int = 2,
                         ubo_threshold: float | None = None,
                         ubo_levels: int | None = None,
                         branches: bool = True,
                         sources: list[str] | None = None,
                         gap: float | None = None,
                         retry: int | None = None,
                         on_progress=None, on_partial=None) -> tuple[list[str], dict, dict]:
    """工商股权链路：返回 ``(达标子公司名, 每个名字的层级标注, 链路全量)``。

    标注形如「⌈2⌋级投资⌈51.00%⌋-母体名」，用来回答「这家是怎么算进来的」：
    一级直投还是穿了两层、累计持股多少、从谁身上穿下来的。只要名字的调用方
    用 ``_equity_names`` 就够了，这里给需要展示链路的场合。
    第三项是 ``eq.as_dict()``（另带本次用的控股门槛）：主体阶段要把这条链路
    摊成控股 / 投资 / 股东 / 分支 / 备案资产并画穿透图，以前只取走名字，
    查到的几十条对外投资到不了任务资产里。
    ``sources`` 只跑点名的那几路工商来源，留空全开。
    """
    from . import equity as _equity
    if ratio is None:
        try:
            ratio = float(config.get("scan", "equity_ratio", default=100) or 100)
        except Exception:
            ratio = 100.0
    eq = await _equity.collect(name, depth=depth, ratio=ratio,
                               ubo_threshold=ubo_threshold, ubo_levels=ubo_levels,
                               branches=branches, sources=sources,
                               gap=gap, retry=retry, on_progress=on_progress,
                               on_partial=on_partial)
    names = _equity.full_owned_children(name, eq.chain, ratio=ratio)
    rel = eq.relation
    # 工商那几路的成败一起带出来。以前这里只把子公司名捞走、状态全丢掉，
    # 企业主体单项跑时面板只剩备案和搜索两栏，看不出子公司名单是哪家给的、
    # 哪家已经额度用尽、哪家登录态失效——「找得不全」就没法定位到具体一路。
    per_src: dict[str, int] = {}
    for c in eq.chain:
        s = str(c.get("src") or "")
        if s:
            per_src[s] = per_src.get(s, 0) + 1
    for src, st in (eq.source_status or {}).items():
        st = str(st or "")
        if not st or st == "skip":
            continue
        _mark(f"equity:{src}", st, "", per_src.get(str(src), 0))
    detail = eq.as_dict()
    # 本次用的门槛跟着链路一起交出去：控股 / 投资的分界、穿透图的标注都按它算，
    # 下游（主体阶段落资产、前端画图）拿到多少家、哪些算达标才对得上这一次执行。
    detail["ratio"] = float(ratio)
    return names, {n: rel[n] for n in names if n in rel}, detail


async def _equity_names(name: str, ratio: float | None = None, depth: int = 2,
                        ubo_threshold: float | None = None,
                        ubo_levels: int | None = None,
                        branches: bool = True,
                        sources: list[str] | None = None,
                        gap: float | None = None,
                        retry: int | None = None) -> list[str]:
    """工商股权链路：取累计持股达标（默认读配置门槛）的子公司名，供上层继续按主体名反查。"""
    names, _rel, _detail = await _equity_detail(
        name, ratio, depth,
        ubo_threshold=ubo_threshold,
        ubo_levels=ubo_levels,
        branches=branches, sources=sources,
        gap=gap, retry=retry)
    return names


def _equity_note(children: list[str]) -> list[str]:
    if not children:
        return []
    head = "、".join(children[:5])
    tail = f" 等 {len(children)} 家" if len(children) > 5 else ""
    return [f"工商股权链路带出达标子公司：{head}{tail}"]


# ─────────────── 新媒体 / 别名 ───────────────
_LOCALITY_RE = re.compile(r"^([\u4e00-\u9fa5]{2,6}?(?:省|市|自治区|自治州|地区|盟|区|县))")


def _locality(name: str) -> str:
    """主体名开头的行政区划前缀（厦门市 / 福建省 / 内蒙古自治区…），没有就空。"""
    m = _LOCALITY_RE.match(re.sub(r"[\s\u3000()（）]", "", name or ""))
    return m.group(1) if m else ""





async def _search_roots(name: str, *, limit: int | None = None) -> tuple[set[str], list, list[str]]:
    """把一组企业检索词并发打出去，返回候选根域、命中、需要告诉用户的说明。

    官网域名经常只在「品牌 + 官网」这一条里出现（瑞幸的 lkcoffee.com 就不在裸品牌的
    结果里），所以前几个词一起投。不单独预探引擎：探测本身就是一次真实检索，
    `search` 内部已经把死引擎记进冷却、活引擎结果进缓存。

    `limit` 只给「顺带用一下这批候选域」的调用方（小程序的站点挖掘）收窄检索面：
    那边等不起整轮七词，三轮中文 + 一轮拉丁就够把品牌主域捞出来。
    """
    queries = entity_queries(name) or [f"{name} 官网"]
    # 检索词分两类：中文词命中品牌页，拉丁词命中英文主域（`tencent` → tencent.com）。
    # 两类各留给对方，不能只取前 5 条——拉丁词永远排在末尾，截断就等于没投。
    latin_q = [q for q in queries if q.isascii()]
    cn_q = [q for q in queries if not q.isascii()]
    if limit is not None and limit > 0:
        queries = (cn_q[:max(1, limit - 1)] + latin_q[:1]) or queries[:limit]
    else:
        queries = (cn_q[:5] + latin_q[:2]) or queries[:5]
    outs = await asyncio.gather(*(web.search(q, engines=web.DEFAULT_ENGINES) for q in queries),
                                return_exceptions=True)
    roots: set[str] = set()
    hits: list = []
    told: list[str] = []
    dead: list[str] = []
    inst = _institution_only(name)
    full = re.sub(r"\s+", "", name or "")
    for q, res in zip(queries, outs):
        if isinstance(res, BaseException) or res is None:
            told.append(f"检索「{q}」异常")
            continue
        if not res.hits:
            dead.append(q)
            continue
        hits.extend(res.hits)
        for h in res.hits:
            d = h.domain
            if d and not _is_noise(d, name) and is_valid_domain(d):
                roots.add(root_domain(d) or d)
            # 机构类只按全称检索、`_hit_roots` 又要求标题写着全称，而**标题就是机构名那条**
            # 常被引擎写成「命中主机」（头条的空标题条），候选会整批丢掉、官网永远进不了池。
            # 这里的判据换成「检索词里写明的域名」：命中的域名必须真的出现在全称检索词里，
            # 同行站（湖州 / 山东检验院）与聚合站都不满足。
            if inst and q.isascii() is False and d and is_valid_domain(d) \
                    and re.search(rf"(?<![a-z0-9]){re.escape(root_domain(d) or d)}(?![a-z0-9])",
                                  q.lower()):
                roots.add(root_domain(d) or d)
    if not roots:
        told.append("搜索引擎无结果" + (f"（{'；'.join(dead[:3])}）" if dead else ""))
    return roots, hits, told


def _hit_roots(hits, name: str = "") -> set[str]:
    """搜索结果里的根域候选。只挡公共后缀与明显噪声，平台判定留给打分阶段。

    机构类目标（`厦门市特种设备检验检测院`）只能按全称检索，召回的噪声主要是**同行机构**
    与聚合站（湖州检验院、山东检验院、高校、字典站）：它们的标题里写的是自家名字。
    所以这一类要求命中条目的标题或摘要里出现目标全称/主体写法，才把该根域收进池；
    真官网那条（引擎按全称召回、标题就是机构名）照收。
    """
    strict = _institution_only(name)
    full = re.sub(r"\s+", "", name or "")
    core = _core_brand(full)
    out: set[str] = set()
    for h in hits or []:
        d = (getattr(h, "domain", "") or "").strip().lower()
        if not d or not is_valid_domain(d):
            continue
        r = root_domain(d) or d
        if r in _PUBLIC_SUFFIXISH or _is_noise(r, name) or _is_public_body(r):
            continue
        if len(r.split(".")[0]) < 3:
            continue
        if strict and not (full and full in f"{h.title}{h.snippet}{h.url}"):
            continue
        out.add(r)
    return out


async def new_media_search(name: str) -> list[str]:
    """公众号 / 小程序 / APP 名称线索（仅用于名称枚举，真实采集见 applet.py / mobile.py）

    查询词带上「微信小程序」而不是「小程序 OR App OR 公众号」：后者会被引擎当成独立词，
    回一堆字典/下载页。这里只要标题里同时出现品牌与载体词的条目。
    """
    out: set[str] = set()
    query = f"{name} 微信小程序"
    # 给 5s 而不是默认 15s：这一路只出「小程序名」线索，真实采集在 applet.py 里另走，
    # 让一条线索卡住首屏十几秒不值。超时就用已经拿到的部分，宁缺不拖。
    res = await web.search(query, engines=await web.pick_engines(query, probe=False), timeout=5)
    for h in res.hits:
        t = h.title
        # 标题里得同时有品牌和「小程序」才会是候选名；只带品牌的多半是新闻/百科
        if t and 2 <= len(t) < 60 and name[:2] in t and ("小程序" in t or "app" in t.lower()):
            out.add(t)
    return sorted(out)[:30]


async def ai_expand(name: str) -> dict:
    """AI 扩展：同主体别名 / 英文名 / 历史名 / 产品线（走 系统设置 → AI 的模型与中转站）"""
    from ..ai import expand_entity

    return await expand_entity(name)


# ─────────────── 归属证据 ───────────────
# 搜索里必然出现的第三方站点：百科、工商查询、代码托管、媒体，不是企业自有资产
_SEARCH_NOISE = (
    "baidu.com", "baike.com", "wikipedia.org", "wiki", "zhihu.com", "csdn.net", "jianshu.com",
    "qcc.com", "tianyancha.com", "aiqicha.com", "qixin.com", "bosszhipin.com", "zhipin.com",
    "liepin.com", "51job.com", "lagou.com", "nowcoder.com", "gitee.com", "github.com",
    "weixin.qq.com", "sohu.com", "sina.com.cn", "sina.com", "163.com", "toutiao.com",
    "thepaper.cn", "ifeng.com", "36kr.com", "huxiu.com", "cnbeta.com", "douban.com",
    "mbalib.com", "docin.com", "doc88.com", "renrendoc.com", "book118.com", "51cto.com",
    "cnblogs.com", "oschina.net", "segmentfault.com", "bilibili.com", "alexa.com", "china.com",
    "similarweb.com", "chinaz.com", "aizhan.com", "beian.miit.gov.cn", "miit.gov.cn",
    "dytt8.net", "iqiyi.com", "youku.com", "tudou.com", "douyin.com", "kuaishou.com",
    "xiaohongshu.com", "weibo.com", "weibo.cn", "dingtalk.com", "feishu.cn", "wps.cn",
    "aliyun.com", "tencent.com", "huaweicloud.com", "aliyuncs.com", "myqcloud.com",
    "jianshu.io", "zhihuishu.com", "cnki.net", "wanfangdata.com.cn", "baike.baidu.com",
    "sogou.com", "so.com", "bing.com", "sm.cn", "yandex.com", "google.com",
    # 软件/应用下载站与手机市场：搜索结果里高频出现的是「瑞幸咖啡 官方下载」这类页面，
    # 站点主体是下载平台，不是企业。曾经漏掉这一整类，pp.cn / wandoujia.com / downza.cn
    # 都一路进到打分表，把品牌自己的域挤到后面。
    "pp.cn", "wandoujia.com", "downza.cn", "cr173.com", "onlinedown.net", "duote.com",
    "guguzhu.com", "jxdown.com", "mydown.com", "pc6.com", "xiazaizhijia.com",
    "diannaowan.com", "qqtn.com", "5577.com", "zol.com.cn", "mydrivers.com", "xiazai.zol.com",
    "sj.qq.com", "app.mi.com", "apps.apple.com", "itunes.apple.com", "play.google.com",
    "apkpure.com", "apkmirror.com", "apkcombo.com", "huawei.com/appgallery", "appgallery.huawei.com",
    "coolapk.com", "azoyun.com", "7po.com", "yingyongbao.com",
    # 汉字/词典解释站：引擎把中文企业名切单字时就吐这一类
    "zdic.net", "hanyuguoxue.com", "hgcha.com", "chagushici.com", "gushici.net", "zi.tools",
    "cuhk.edu.hk", "guoxuedashi.net", "youdao.com", "iciba.com", "xxjcy.com", "ciku5.com",
    "hydcd.com", "51diyi.com", "dict.cn", "hidict.com", "bejson.com", "gjtdict.com",
    # 加盟/创业信息站：商标仿冒与「XXX加盟官网」是同一批词造成的高发误召回
    "brandstar.com.cn", "jiameng.com", "canyin168.com", "cy8.com", "xicanjm.com",
    "jm.chinabgao.com", "kaidianbang.com", "91jm.net", "hao315.com", "chinafranchisee.com",
    "vipzs.com", "jm.jmw.com.cn", "sp.jiameng.com", "tuangoujm.com",
    # 2026-11-08 实测「瑞幸咖啡」召回池里整类无关站：政府/zj 省级新闻（zjol / zj.gov）、
    # 与咖啡完全无关的机器人公司（roboind）、域名交易与展会站。
    # 共同点：标题里带品牌名，但站点主体与目标企业毫无关系，留着会把真官网挤到 pending。
    "zj.gov.cn", "zjol.com.cn", "zjnews.com.cn", "ces.cn", "roboind.com",
    "domain.cn", "ename.net", "4.cn", "west.cn", "22.cn", "yumi.com", "sedo.com",
    "zhanhui.com", "expo.com", "cantonfair.org.cn", "hktdc.com", "ccpit.org",
    # B2B 黄页 / 供求 / 招标 / 行业门户：候选池阶段就丢掉，连打分表都不进
    "11467.com", "huangye88.com", "51sole.com", "likuso.com", "zk71.com", "qianlima.com",
    "gongchang.com", "ebdoor.com", "makepolo.com", "qjy168.com", "herostart.com",
    "sooshong.com", "zhaoshang.net", "chinabgao.com", "b2b.cn", "cnlinxi.com",
)

# 一次打分最多探多少个根域（按命中条数取前 N）。不是候选上限：
# 候选池照样全收，只是首页探测 + 证书查询这类每域一跳的动作不可能对几百个域全跑。
_SCORE_TOP = 160

# 公共主体后缀：搜出来的 gov.cn / edu.cn 一定是政府 / 学校站，不是企业资产
_PUBLIC_SUFFIXES = ("gov.cn", "edu.cn", "org.cn", "ac.cn", "mil.cn", "gov.hk", "edu.hk")

# 二级公共后缀：搜索结果里常出现裸后缀（co.ltd / com.cn），它不是任何一家企业的资产
_PUBLIC_SUFFIXISH = frozenset({"co.ltd", "co.uk", "com.cn", "net.cn", "org.cn", "gov.cn",
                               "edu.cn", "com.hk", "com.tw", "co.jp", "com.au", "co.kr"})

# 子域前缀 → 该子域代表"业务面"，可以留在目标里；其余（www / 博客 / 文档）归约到根域
_BUSINESS_PREFIX = ("api", "admin", "gateway", "gw", "open", "portal", "passport", "sso",
                    "oa", "mail", "app", "m", "i", "console", "manage", "cloud", "job")

# 官方站的自我声明：备案号（主体名写在备案号旁边）/ 版权行 / 关于我们
_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/124.0 Safari/537.36")
_OFFICIAL_HINT = re.compile(
    r"(?:ICP证|icp证|ICP备|icp备|公网安备)[:：\s]*[0-9\-A-Za-z]{4,}|[©]|&copy;|版权|关于我们|about us",
    re.I)


def _is_noise(domain: str, name: str = "") -> bool:
    d = domain.lower()
    # 噪声表按「别家域名」编的：`tencent.com` 在里面是为了挡查别家时被腾讯云转载页干扰，
    # 但查腾讯自己时它就是官网。先放行自家根域，其余照旧。
    if name and (root_domain(d) or d) in _own_roots_of(name):
        return False
    if d in _PUBLIC_SUFFIXISH:
        return True
    # 只按"等于或子域"匹配，不用子串：子串会把 xiaomi.gov.cn 这类也杀掉，也会把
    # 品牌自己含有第三方名（如 bilibili.com.cn）误伤
    return any(d == n or d.endswith("." + n) for n in _SEARCH_NOISE)


def _is_public_body(domain: str) -> bool:
    d = domain.lower()
    return any(d == s or d.endswith("." + s) for s in _PUBLIC_SUFFIXES)


def _is_platform(domain: str, name: str = "") -> bool:
    d = domain.lower()
    # 品牌自家产品根域先放行：`qq.com` 在平台名单里是为了挡别家的转载，
    # 查腾讯自己时它是主业站，扣 -60 会把唯一能确认的根域直接判死。
    if name and (root_domain(d) or d) in _own_roots_of(name):
        return False
    if d in _PLATFORM_ROOTS:
        return True
    # 品牌自有主域（品牌名就是根域主体）不可能是平台站：`huawei.com` 被误列进平台名单就会把官网扣死。
    return any(d.endswith("." + s) for s in _PLATFORM_ROOTS) and not _is_own_brand_root(d, name)


# 首页拿得到标题、但标题与目标毫无关系时用的权重。这条守的是长尾：平台名单只能挡点名的站，
# 行业门户（锅炉之家这类）每天都在换，靠名单补永远漏下一个。
W_SITE_UNRELATED = -50
# 目录 / 黄页 / 供求 / 行业门户的标题特征：`锅炉之家 - 锅炉厂家大全_锅炉在线报价`
_DIRECTORY_TITLE_HINT = ("黄页", "名录", "大全", "供求", "供应", "求购", "招标", "采购",
                         "分类信息", "发布平台", "信息平台", "企业库", "行业门户", "导航",
                         "报价", "厂家", "市场", "展会", "论坛", "贴吧", "百科", "网店")
# 通用首页标题：不携带任何「我们是谁」的信息，不能拿来判「首页自述与目标无关」
_GENERIC_TITLE_RE = re.compile(
    r"^(首页|主页|网站首页|默认首页|欢迎光临|欢迎访问|加载中|无标题|未命名|"
    r"home|homepage|index|welcome|loading|untitled|default)$", re.I)


def _is_generic_title(title: str) -> bool:
    """标题里没有「我们是谁」的任何内容：`首页`、`Home`、`欢迎光临` 这类不能当反面证据。"""
    t = re.sub(r"[\s\-_|/·]+", "", title or "")
    if len(t) <= 2:
        return True
    return bool(_GENERIC_TITLE_RE.match(t))


def _directory_wording(text: str) -> bool:
    """这段文字读起来像目录/黄页/供求/行业门户（收录了这家企业），不是站点自报家门。"""
    return any(w in (text or "") for w in _DIRECTORY_TITLE_HINT)


# 品牌自家运营的产品根域：搜索里它就是这家公司的业务面，不是通用平台转载。
# 只用于「这个域对当前品牌来说算不算自家站」的判断，不改变它对别人的平台属性 ——
# 查腾讯时 qq.com 是自有资产，查别家时它仍然是平台，照样按平台扣分。
_OWN_ROOTS = {
    "腾讯": {"qq.com", "tencent.com", "tencentyun.com", "gtimg.com", "tenpay.com"},
    # 两字品牌的官网根域常与中文名、拼音都不完全相同：靠已知产品根域认定，
    # 免得好站只因为「域名两三个字母」被当成弱证据。
    "小米": {"mi.com", "mi.cn", "xiaomi.com", "xiaomi.cn", "xiaomiev.com", "mioffice.com"},
    "茅台": {"moutai.com.cn", "moutaichina.com", "moutaimall.com"},
    "华为": {"huawei.com", "huawei.cn", "huaweicloud.com", "hicloud.com"},
    # 电网的对外主域是 `sgcc.com.cn`，和「国网 / 国家电网」的中文、拼音都拼不上：
    # 省电力公司（`国网福建省电力有限公司`）的站全挂在这个根下，靠别名表永远认不回来，
    # 候选池最后只剩备案里那条中文域，整轮扩不出任何资产。
    "国网": {"sgcc.com.cn"},
    "国家电网": {"sgcc.com.cn"},
    # 国内主域常是「品牌名 + 国别」而官网主域是 `alibaba-inc.com`：两条路分开列，别名命中即算。
    "阿里": {"alibaba.com", "alibaba.cn", "alibaba-inc.com", "alicdn.com", "aliyun.com",
             "alipay.com", "taobao.com", "tmall.com", "1688.com", "alibabagroup.com"},
}


def _own_roots_of(name: str) -> set[str]:
    """按品牌名取这家公司自己的产品根域。"""
    brand = _brand(name) or name
    out: set[str] = set()
    for key, domains in _OWN_ROOTS.items():
        if key in name or key in brand or brand in key:
            out |= domains
    return out


def _is_own_brand_root(d: str, name: str = "") -> bool:
    """根域主体是否属于当前品牌自己（`huawei.com` 的英文名、`qq.com` 的产品根域）。"""
    root = root_domain(d) or d
    if name and root in _own_roots_of(name):
        return True
    label = re.sub(r"[^a-z0-9]", "", d.split(".")[0])
    if len(label) < 4:
        return False
    for vals in _LATIN_BRAND.values():
        for v in vals:
            if re.sub(r"[^a-z0-9]", "", v) == label:
                return True
    return False


def _name_keys(name: str) -> set[str]:
    """企业名 → 站内可能出现的写法（全称、简称、去掉组织形式）。

    只保留「像名字」的写法：去组织形式、去地名括号、去行政区前缀。**不**做
    「科技→」「技术→」这类词根裁剪 —— `字节跳动科技` 这种半截词会让引擎按单字切词，
    也不可能是站内自称呼，只会稀释标题命中的判断。
    """
    base = name.replace("（", "(").replace("）", ")").replace(" ", "")
    keys = {base}
    for suf in ("股份有限公司", "有限责任公司", "有限公司", "公司", "集团"):
        if base.endswith(suf):
            keys.add(base[: -len(suf)])
    # 去掉地域：(深圳)、(中国)、深圳、北京…
    plain = re.sub(r"[（(][^）)]{1,10}[）)]", "", base)
    plain = re.sub(r"^(?:中国|北京|上海|深圳|广州|杭州|成都|武汉|南京|西安|苏州)(?:市)?", "", plain)
    keys.add(plain)
    return {k for k in keys if len(k) >= 2}


# 行业/组织形式词：企业名里高频出现，但**不是**品牌标识。
# 只在品牌缩写与拼音桥接时剥掉，站内命中判断（`_name_keys`）保留，避免误伤「科技类媒体」这类写法。
_INDUSTRY_WORDS = ("科技", "技术", "网络", "信息", "控股", "电子商务", "电子", "实业", "传媒",
                   "文化", "商贸", "贸易", "发展", "投资", "管理", "服务", "数字", "智能", "软件",
                   "集团", "国际", "企业", "咨询", "工程", "医药", "生物", "食品", "餐饮", "教育",
                   "检验", "检测", "检定", "测试", "认证", "计量", "研究院", "研究所", "设计院",
                   "勘察", "测绘", "监理", "建设", "装修", "物流", "运输", "供应链", "物业",
                   "地产", "置业", "医疗", "医院", "诊所", "药业", "制药", "机械", "制造",
                   "材料", "新材", "能源", "环保", "水务", "电力", "燃气", "热力",
                   "旅游", "酒店", "广告", "影视", "文化传播", "餐饮管理")


# 行政区前缀：省级/直辖市 + 地级市。事业单位与地方国企的名字常以「厦门市」「山东省」打头，
# 剥掉地名才能看出名字里还剩什么品牌段。
_PROVINCE_RE = (r"(?:中国|北京|上海|天津|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|"
                r"江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|台湾|"
                r"内蒙古|广西|西藏|宁夏|新疆|香港|澳门)")
_CITY_RE = (r"(?:厦门|苏州|无锡|宁波|温州|东莞|佛山|珠海|中山|泉州|漳州|莆田|龙岩|三明|南平|"
            r"宁德|青岛|大连|烟台|潍坊|徐州|常州|南通|绍兴|嘉兴|金华|台州|芜湖|洛阳|唐山|"
            r"保定|临沂|淄博|济宁|泰安|威海|包头|柳州|桂林|宜昌|襄阳|岳阳|株洲|湘潭|赣州|"
            r"九江|盐城|扬州|镇江|湖州|衢州|丽水|舟山|汕头|惠州|江门|湛江|茂名|肇庆|揭阳|"
            r"石家庄|太原|郑州|长沙|合肥|南昌|福州|南宁|昆明|贵阳|兰州|银川|西宁|乌鲁木齐|"
            r"呼和浩特|哈尔滨|长春|沈阳|济南|西安|成都|武汉|南京|杭州|广州|深圳|大连|青岛)")
_ADMIN_RE = rf"(?:{_PROVINCE_RE}|{_CITY_RE})(?:省|市|自治区|特别行政区)?"

# 行业链：`特种设备`、`产品质量监督`、`石油天然气` 这类写法单独拿出来看像是名字，
# 连上后面的「检验检测院」才是完整业务范围。它们本身区分不了两家同名目机构
# （厦门的特种设备检验院与山东省的特种设备检验研究院一字不差），
# 只在地名层已经相同时才允许当身份键使用。
_TRADE_WORDS = ("特种设备", "压力容器", "压力管道", "电梯", "锅炉", "产品质量监督", "产品质量",
                "质量技术监督", "食品药品", "食品安全", "药品", "医疗器械", "环境保护",
                "环境监测", "水文", "气象", "地震", "测绘地理信息", "国土", "规划",
                "交通运输", "公路", "水利", "电力", "供水", "排水", "燃气", "供热",
                "石油天然气", "石油", "天然气", "矿山", "冶金", "化工", "轻工", "纺织",
                "农业", "林业", "畜牧", "渔业", "海洋", "气象服务", "公共资源", "政务服务")
_TRADE_RE = re.compile("(?:" + "|".join(sorted(_TRADE_WORDS, key=len, reverse=True)) + ")")


def _core_brand(text: str) -> str:
    """名字（主体全称 / 目标名）→ 去掉行政区与隶属前缀后的核心段，**不剥行业词**。

    `_brand` 会把行业词剥掉，`厦门市特种设备检验检测院` 于是只剩「特种设备」——
    这个写法对全国同行业的单位都成立，拿它当身份键等于认定「山东省特种设备检验研究院」
    也是同一家。这里保留行业词，只解决「去掉地名之后还剩不剩东西」这件事。
    """
    n = re.sub(r"[（(][^）)]*[）)]", "", text or "").strip()
    n = re.sub(r"(?:股份有限公司|有限责任公司|有限公司|集团|公司)$", "", n)
    if not n:
        return ""
    m = re.match(rf"^{_ADMIN_RE}(?=[\u4e00-\u9fa5]{{2,}})", n)
    if m:
        n = n[m.end():]
    else:
        m = re.match(rf"^([A-Za-z0-9]+){_ADMIN_RE}(?=[\u4e00-\u9fa5]{{2,}})", n)
        if m:
            n = m.group(1) + n[m.end():]
    return n.strip()


_SUBJECT_CUT = re.compile(r"[（(].*?[）)]")


def _subject_same(unit: str, name: str) -> bool:
    """备案主体 vs 目标名是否同一家：完整名称互相包含，或去掉地名后核心段相同。

    行业词只在**地名之后**才允许留下差异：`厦门市特种设备检验检测院` 与
    `厦门市特种设备应急处置中心` 的括号与后缀不同但同属一家（核心段都在厦门市下面），
    而 `山东省…研究院` 地名不同，核心段不相等，判为不同主体。

    任务里填的是简称时（`漳州九龙江集团` 对 `漳州市九龙江集团有限公司`），互相都不是
    对方的子串，差的是区划后缀和 `有限公司` —— 这一跳交给 `core_same`，只认字号与区划。
    """
    a = re.sub(r"[\s\u3000()（）·,，.。]", "", name or "")
    b = re.sub(r"[\s\u3000()（）·,，.。]", "", unit or "")
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    if core_same(unit, name):
        return True
    ca, cb = _core_brand(_SUBJECT_CUT.sub("", name or "")), _core_brand(_SUBJECT_CUT.sub("", unit or ""))
    if len(ca) >= 3 and ca == cb:
        return True
    # 全称剥掉行业词后如果还有可区分的写法（`字节跳动`），按它比；只剩行业词就到此为止
    ba, bb = _identity_brand(name), _identity_brand(unit)
    if ba and bb and ba == bb and len(ba) >= 3:
        return True
    return False


def _is_industry_only(text: str) -> bool:
    """整串拆完只剩行业词 / 行业链 / 资质后缀 —— 这种写法是「一类机构」，不是「一家机构」。"""
    s = (text or "").strip()
    if not s:
        return True
    for _ in range(12):
        prev = s
        for w in sorted(_INDUSTRY_WORDS, key=len, reverse=True):
            if s == w or (s.endswith(w) and len(s) > len(w)):
                s = s[: -len(w)]
                break
        for w in sorted(_TRADE_WORDS, key=len, reverse=True):
            if s == w:
                s = ""
                break
            if s.startswith(w) and len(s) > len(w):
                s = s[len(w):]
                break
        if len(s) > 1 and s[-1] in "院所厂台站部队校社中心":
            s = s[:-1]
        if s == prev or not s:
            break
    return len(s) < 2


def _trade_only(text: str) -> bool:
    """只含行业链 / 资质后缀、不含任何专有品牌段（`特种设备检验检测院`）。

    与 `_is_industry_only` 的区别：这里不剥 `检验` 这类零散行业词，只看有没有
    真正能区分主体的字。`特种设备检验检测院` 判 True，`瑞幸咖啡` / `字节跳动` 判 False。
    """
    s = (text or "").strip()
    if not s:
        return True
    for _ in range(12):
        prev = s
        for w in sorted(_TRADE_WORDS, key=len, reverse=True):
            if s == w:
                s = ""
                break
            if s.startswith(w) and len(s) > len(w):
                s = s[len(w):]
                break
        for w in ("检验检测", "检验", "检测", "检定", "测试", "认证", "计量", "监督"):
            if s == w:
                s = ""
                break
            if s.startswith(w) and len(s) > len(w):
                s = s[len(w):]
                break
        if len(s) > 1 and s[-1] in "院所厂台站部队校社中心":
            s = s[:-1]
        if s == prev or not s:
            break
    return len(s) < 2


def _identity_brand(name: str) -> str:
    """可以当「这家机构」身份键的写法；拿不出就回空串。

    `厦门市特种设备检验检测院` 剥完只剩「特种设备」，全称本身又查不到备案 —— 这种主体
    没有任何短写法能区分于同行，只能靠**完整名称 + 备案主体**认，返回空串让调用方
    走全称匹配，禁止退化成行业词匹配。
    """
    b = _brand(name)
    if b and not _is_industry_only(b) and not _trade_only(b):
        return b
    core = _core_brand(name)
    if core and 3 <= len(core) <= 8 and not _is_industry_only(core) and not _trade_only(core):
        return core
    # 行业院所 / 事业单位：名字里唯一起区分作用的是**地名**（`厦门`），行业链与资质后缀
    # 在全省全国都一样。这类主体的身份键是地名，配合全称匹配使用。
    m = re.match(rf"^({_PROVINCE_RE}|{_CITY_RE})(?:省|市|自治区|特别行政区)?", name or "")
    if m and m.group(1):
        return m.group(1)
    return ""


def _subject_self(unit: str, name: str) -> bool:
    """备案主体是否**就是**目标本身，而不是同一主办单位下的邻家机构。

    `厦门市特种设备检验检测院(厦门市特种设备应急处置中心)` 对「厦门市特种设备检验检测院」
    是本主体（括号里是并行挂牌名）；对「厦门市特种设备应急处置中心」也包含全称，
    但它是同一个事业单位的另一块牌子 —— 那条只能当同群体线索，不能独立确认。
    判据：目标全称（去括号）是备案主体名的主段或并行挂牌名之一。

    任务里填的是简称时（`漳州九龙江集团` 对 `漳州市九龙江集团有限公司`），两个名字
    差的是区划后缀和 `有限公司`，字号与区划都对得上，仍然是本主体 —— 这一档只认
    `core_same`（字号全等），不放开到行业词，避免把同行的另一家算成自己。
    """
    compact = re.sub(r"\s+", "", name or "")
    unit_c = re.sub(r"\s+", "", unit or "")
    if not compact or not unit_c:
        return False
    main = re.sub(r"[（(][^）)]*[）)]", "", unit_c)
    if compact == main or compact == unit_c:
        return True
    alts = re.findall(r"[（(]([^）)]*)[）)]", unit_c)
    if any(compact == re.sub(r"\s+", "", a) for a in alts):
        return True
    return core_same(unit, name)


_LEGAL_SUFFIX = ("股份有限公司", "有限责任公司", "有限公司", "集团有限公司", "集团")


def _family_core(name: str) -> str:
    """把主体名剥成「品牌芯」：去括号、去空格、去公司后缀与集团字样。

    「瑞幸咖啡（中国）有限公司」「瑞幸咖啡（北京）有限公司」都剥成「瑞幸咖啡」，
    这样才看得出它们是同一个品牌的兄弟公司，而不是两家不相干的企业。
    """
    s = re.sub(r"[（(][^）)]*[）)]", "", re.sub(r"\s+", "", name or ""))
    for suf in _LEGAL_SUFFIX:
        if s.endswith(suf) and len(s) - len(suf) >= 3:
            s = s[: -len(suf)]
            break
    if s.endswith("集团") and len(s) - 2 >= 3:
        s = s[:-2]
    return s


def _subject_family(unit: str, name: str) -> bool:
    """备案主体是不是目标品牌的兄弟公司（集团里另一家登记主体）。

    集团站常登记在区域公司名下：`luckincoffee.com` 的备案主体是「瑞幸咖啡（北京）
    有限公司」，而任务查的是「瑞幸咖啡（中国）有限公司」。以前这一行被判成「邻家机构」
    只给弱分，官网反而排到别的候选后面 —— 这就是「企业主体打偏」的主因。
    兄弟公司既不是本主体（名下还挂着加盟商与同名小公司），也不能与第三方等同，
    所以单独给一档：进候选池、按线索计分，但不给确认级的行政登记结论。
    """
    a = _family_core(unit)
    b = _family_core(name)
    if not a or not b:
        return False
    if a == b:
        return len(a) >= 3
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return len(short) >= 4 and long_.startswith(short)


def _institution_only(name: str) -> bool:
    """名字里没有任何能区分于同行、又能拿去检索的身份键：只剩地名 / 行业词 / 资质后缀。

    `厦门市特种设备检验检测院` 剥完是「特种设备」；地名「厦门」能区分于同行，
    但拿它去搜召回的是厦门一整片的政府与企业站，不能当检索词。这类主体只认全称 +
    反查备案主体（见 `_score_domain` 的反查档）。
    """
    b = _brand(name)
    if b and not _is_industry_only(b) and not _trade_only(b):
        return False
    core = _core_brand(name)
    if core and 3 <= len(core) <= 8 and not _is_industry_only(core) and not _trade_only(core):
        return False
    # 收尾在院所 / 中心 / 站 / 校这类资质后缀上：教育、检验检测、医院、研究所都属这一类
    compact = re.sub(r"[（(][^）)]*[）)]", "", name or "").strip()
    return bool(re.search(r"(院|所|中心|站|校|局|台|馆|队|部)$", compact))


def _brand(name: str) -> str:
    """企业名 → 对外品牌简称（`北京字节跳动科技有限公司` → `字节跳动`）。

    先剥组织形式与行政区，再剥末尾的行业词 —— 只剥**末尾**，`科技媒体` 这种把行业词放
    开头的名字不受影响。
    """
    n = re.sub(r"[（(][^）)]*[）)]", "", name)
    n = re.sub(r"(?:股份有限公司|有限责任公司|有限公司|集团|公司)$", "", n)
    # 输入本身就是域名（`xiaomi.com`）时，下面的行政区剥法会把拉丁前缀当成「地名前缀」切掉，
    # 只剩 `om` 这种残渣，后面被拿去查股权和应用商店。域名没有品牌简称可言，直接回空。
    if not n or re.fullmatch(r"[\x00-\x7f]+", n) or is_valid_domain(n.strip().lower()):
        return ""
    # 行政区只剥「地名 + 省/市」这一种形态，且只剥地名那一段：`OPPO广东移动通信` 里
    # `广东` 是地名，但它前面的 `OPPO` 是品牌，整段前缀剥掉会把品牌一起带走；
    # `北京字节跳动` 则是地名打头，剥完才剩下品牌。
    # 地级市要单独列：事业单位、地方国企、分支检测机构的名字常以「厦门市 / 苏州市」打头，
    # 不剥掉的话品牌简称会变成「厦门市特种设备检验检测院」整串，既搜不准也算不出域名缩写。
    _ADMIN = _ADMIN_RE
    m = re.match(rf"^{_ADMIN}(?=[\u4e00-\u9fa5]{{2,}})", n)
    if m:
        n = n[m.end():]
    else:
        m = re.match(rf"^([A-Za-z0-9]+){_ADMIN}(?=[\u4e00-\u9fa5]{{2,}})", n)
        if m:
            n = m.group(1) + n[m.end():]
    # 地名后面再跟一个区/县名（`厦门市思明区…`）也剥掉，只剥一层
    m = re.match(r"^[\u4e00-\u9fa5]{2,3}(?:区|县)(?=[\u4e00-\u9fa5]{2,})", n)
    if m and len(n) - m.end() >= 2:
        n = n[m.end():]
    # 剥到剥不动为止：事业单位名常是「品牌 + 行业 + 资质后缀」叠三层
    # （`特种设备检验检测院` = 特种设备 + 检验检测 + 院），剥一轮还剩「检验检测院」，
    # 拿它去搜会把同类院校全召回，算域名缩写也全错。
    for _ in range(6):
        prev = n
        for w in _INDUSTRY_WORDS:
            if n.endswith(w) and len(n) - len(w) >= 2:
                n = n[: -len(w)]
                break
        # 资质类单字后缀单独剥：`…院`、`…所`、`…厂`、`…台`、`…中心`
        if n.endswith(("院", "所", "厂", "台", "站", "部", "队", "校", "社")) and len(n) >= 4:
            n = n[:-1]
        if n == prev:
            break
    # 剥完只剩行业词（`特种设备`）就不是品牌，是「哪一类机构」。拿它当简称会去搜全省同类院：
    # 实测「厦门市特种设备检验检测院」的简称被剥成「特种设备」，检索词全变成行业词，
    # 召回来的 hztjzx.cn（湖州）/ sei.sd.cn（山东）挤掉了真官网 xmaj.com。
    if _is_industry_only(n) or _trade_only(n):
        return ""
    return n if len(n) >= 2 else ""


def entity_queries(name: str) -> list[str]:
    """企业全称 → 一组检索词，按召回质量排序。

    带括号的全称（`瑞幸咖啡（中国）有限公司`）在 Bing 上会被切成单字，返回字典站；
    品牌简称（`瑞幸咖啡`）才召回到官网。所以简称永远排在前面，全称只用于工商/ICP 类站点。
    """
    brand = _brand(name)
    full = re.sub(r"\s+", "", name)
    out: list[str] = []
    # 行业院所这类主体没有能区分同行的简称（`特种设备` 全省都有），拿简称、地名或拼音去搜
    # 只会召回同行站。这类词只打**全称**：引擎对中文机构全名按原意处理，
    # `厦门市特种设备检验检测院` 第一条就是官网 xmaj.com。
    if _institution_only(name):
        for q in (full, f"{full} 官网", f"{full} 网站", f'"{full}"'):
            if q and q not in out:
                out.append(q)
        return out
    # 裸品牌放最前：`_brand` 会砍成「浙江东方金融」，这类词单独搜会被引擎降级成地域页，
    # 品牌名原样可搜（`贵州茅台` → moutaichina.com），别让长查询把官网挤掉。
    for q in (brand if brand else "", f"{brand} 官网" if brand else "",
              f'"{brand}"' if brand else "", f"{brand} 官方网站" if brand else "",
              f"{full} 官网", f'"{full}"'):
        if q and q not in out:
            out.append(q)
    # 拉丁别名放最后，但一定要有：Bing / 头条 / 360 对「中文品牌 + 中文关键词」整句
    # 一律按首字切词（「瑞幸咖啡 官网」→ 查「瑞」字），只有「luckincoffee 官网」这种
    # 拉丁写法能按原意检索。主判定仍靠中文词，这一路是兜底召回。
    latin = sorted(_latin_brand_of(brand or name) | _pinyin_of(brand or name))
    for lat in latin[:2]:
        for q in (f"{lat} 官网", lat):
            if q not in out:
                out.append(q)
    return out


# 域名里的品牌词：bytedance.com ↔ 字节跳动 / ByteDance。中文品牌无法直接对上英文域名，
# 所以同时用「企业缩写 + 拼音首字母」两路做弱匹配，命中只加少量分，不单独构成归属。
# 常用汉字读音表（只覆盖企业名里高频出现的那批字）。
# 为什么不装拼音库：整条流水线要求零外部依赖，任何一次可选的第三方导入失败都会让
# 「拉丁别名兜底检索」整段失效，而搜索引擎对中文品牌整句是逐字切词的，只有拉丁写法能按原意召回。
_PINYIN = {
    "阿": "a", "埃": "ai", "艾": "ai", "安": "an", "鞍": "an", "奥": "ao",
    "八": "ba", "巴": "ba", "白": "bai", "百": "bai", "佰": "bai", "邦": "bang",
    "包": "bao", "保": "bao", "宝": "bao", "北": "bei", "贝": "bei", "本": "ben",
    "比": "bi", "碧": "bi", "宾": "bin", "波": "bo", "博": "bo", "步": "bu",
    "财": "cai", "彩": "cai", "参": "can", "草": "cao", "长": "chang", "常": "chang",
    "超": "chao", "朝": "chao", "车": "che", "晨": "chen", "成": "cheng", "诚": "cheng",
    "城": "cheng", "乘": "cheng", "程": "cheng", "驰": "chi", "赤": "chi", "川": "chuan",
    "传": "chuan", "创": "chuang", "春": "chun", "慈": "ci", "从": "cong", "达": "da",
    "大": "da", "代": "dai", "丹": "dan", "当": "dang", "岛": "dao", "道": "dao",
    "德": "de", "登": "deng", "迪": "di", "地": "di", "帝": "di", "第": "di",
    "典": "dian", "电": "dian", "东": "dong", "动": "dong", "都": "du", "读": "du",
    "度": "du", "端": "duan", "多": "duo", "俄": "e", "恩": "en", "二": "er",
    "发": "fa", "法": "fa", "帆": "fan", "方": "fang", "房": "fang", "飞": "fei",
    "菲": "fei", "分": "fen", "丰": "feng", "风": "feng", "峰": "feng", "凤": "feng",
    "佛": "fo", "福": "fu", "复": "fu", "富": "fu", "甘": "gan", "刚": "gang",
    "钢": "gang", "高": "gao", "歌": "ge", "格": "ge", "个": "ge", "工": "gong",
    "公": "gong", "谷": "gu", "股": "gu", "固": "gu", "光": "guang", "广": "guang",
    "贵": "gui", "国": "guo", "果": "guo", "海": "hai", "汉": "han", "杭": "hang",
    "航": "hang", "好": "hao", "浩": "hao", "禾": "he", "合": "he", "和": "he",
    "河": "he", "黑": "hei", "恒": "heng", "红": "hong", "宏": "hong", "虹": "hong",
    "侯": "hou", "湖": "hu", "虎": "hu", "互": "hu", "华": "hua", "化": "hua",
    "怀": "huai", "汇": "hui", "惠": "hui", "活": "huo", "火": "huo", "基": "ji",
    "吉": "ji", "极": "ji", "集": "ji", "济": "ji", "技": "ji", "计": "ji",
    "记": "ji", "加": "jia", "佳": "jia", "家": "jia", "嘉": "jia", "江": "jiang",
    "交": "jiao", "焦": "jiao", "角": "jiao", "教": "jiao", "洁": "jie", "捷": "jie",
    "金": "jin", "津": "jin", "进": "jin", "京": "jing", "经": "jing", "晶": "jing",
    "精": "jing", "景": "jing", "九": "jiu", "久": "jiu", "酒": "jiu", "巨": "ju",
    "聚": "ju", "君": "jun", "卡": "ka", "开": "kai", "凯": "kai", "康": "kang",
    "科": "ke", "可": "ke", "客": "ke", "空": "kong", "控": "kong", "口": "kou",
    "快": "kuai", "矿": "kuang", "坤": "kun", "昆": "kun", "扩": "kuo", "拉": "la",
    "来": "lai", "兰": "lan", "蓝": "lan", "朗": "lang", "老": "lao", "乐": "le",
    "雷": "lei", "连": "lian", "联": "lian", "良": "liang", "两": "liang", "林": "lin",
    "灵": "ling", "领": "ling", "令": "ling", "流": "liu", "六": "liu", "龙": "long",
    "隆": "long", "楼": "lou", "路": "lu", "绿": "lv", "轮": "lun", "罗": "luo",
    "马": "ma", "迈": "mai", "麦": "mai", "满": "man", "曼": "man", "贸": "mao",
    "茂": "mao", "梅": "mei", "美": "mei", "门": "men", "蒙": "meng", "梦": "meng",
    "米": "mi", "蜜": "mi", "面": "mian", "民": "min", "敏": "min", "名": "ming",
    "明": "ming", "摩": "mo", "魔": "mo", "目": "mu", "木": "mu", "耐": "nai",
    "南": "nan", "能": "neng", "尼": "ni", "年": "nian", "鸟": "niao", "宁": "ning",
    "牛": "niu", "农": "nong", "女": "nv", "欧": "ou", "派": "pai", "盘": "pan",
    "鹏": "peng", "片": "pian", "品": "pin", "平": "ping", "评": "ping", "普": "pu",
    "七": "qi", "奇": "qi", "其": "qi", "骑": "qi", "启": "qi", "千": "qian",
    "乾": "qian", "黔": "qian", "强": "qiang", "桥": "qiao", "青": "qing", "清": "qing",
    "庆": "qing", "秋": "qiu", "求": "qiu", "趣": "qu", "全": "quan", "泉": "quan",
    "群": "qun", "燃": "ran", "人": "ren", "仁": "ren", "日": "ri", "荣": "rong",
    "融": "rong", "如": "ru", "锐": "rui", "瑞": "rui", "润": "run", "赛": "sai",
    "三": "san", "森": "sen", "山": "shan", "闪": "shan", "商": "shang", "上": "shang",
    "尚": "shang", "少": "shao", "蛇": "she", "社": "she", "申": "shen", "深": "shen",
    "神": "shen", "沈": "shen", "生": "sheng", "圣": "sheng", "盛": "sheng", "胜": "sheng",
    "狮": "shi", "十": "shi", "石": "shi", "时": "shi", "实": "shi", "世": "shi",
    "市": "shi", "视": "shi", "适": "shi", "首": "shou", "寿": "shou", "书": "shu",
    "数": "shu", "水": "shui", "顺": "shun", "硕": "shuo", "思": "si", "四": "si",
    "松": "song", "宋": "song", "速": "su", "苏": "su", "素": "su", "算": "suan",
    "随": "sui", "遂": "sui", "索": "suo", "塔": "ta", "台": "tai", "太": "tai",
    "泰": "tai", "汤": "tang", "堂": "tang", "腾": "teng", "体": "ti", "天": "tian",
    "田": "tian", "甜": "tian", "铁": "tie", "通": "tong", "同": "tong", "铜": "tong",
    "统": "tong", "图": "tu", "土": "tu", "团": "tuan", "拓": "tuo", "外": "wai",
    "万": "wan", "王": "wang", "网": "wang", "旺": "wang", "为": "wei", "威": "wei",
    "微": "wei", "唯": "wei", "维": "wei", "伟": "wei", "卫": "wei", "位": "wei",
    "温": "wen", "文": "wen", "问": "wen", "无": "wu", "五": "wu", "武": "wu",
    "物": "wu", "西": "xi", "希": "xi", "禧": "xi", "喜": "xi", "先": "xian",
    "仙": "xian", "现": "xian", "线": "xian", "相": "xiang", "祥": "xiang", "翔": "xiang",
    "向": "xiang", "橡": "xiang", "消": "xiao", "小": "xiao", "晓": "xiao", "协": "xie",
    "携": "xie", "谢": "xie", "芯": "xin", "新": "xin", "信": "xin", "星": "xing",
    "兴": "xing", "行": "xing", "杏": "xing", "熊": "xiong", "修": "xiu", "秀": "xiu",
    "需": "xu", "徐": "xu", "许": "xu", "轩": "xuan", "学": "xue", "雪": "xue",
    "寻": "xun", "迅": "xun", "雅": "ya", "亚": "ya", "烟": "yan", "延": "yan",
    "严": "yan", "研": "yan", "眼": "yan", "燕": "yan", "央": "yang", "扬": "yang",
    "阳": "yang", "洋": "yang", "养": "yang", "药": "yao", "耀": "yao", "一": "yi",
    "医": "yi", "依": "yi", "易": "yi", "义": "yi", "亿": "yi", "艺": "yi",
    "银": "yin", "引": "yin", "印": "yin", "英": "ying", "营": "ying", "影": "ying",
    "应": "ying", "优": "you", "友": "you", "有": "you", "又": "you", "于": "yu",
    "余": "yu", "鱼": "yu", "宇": "yu", "羽": "yu", "语": "yu", "育": "yu",
    "元": "yuan", "员": "yuan", "源": "yuan", "远": "yuan", "院": "yuan", "约": "yue",
    "月": "yue", "跃": "yue", "越": "yue", "云": "yun", "运": "yun", "韵": "yun",
    "再": "zai", "在": "zai", "早": "zao", "造": "zao", "泽": "ze", "增": "zeng",
    "展": "zhan", "战": "zhan", "张": "zhang", "掌": "zhang", "招": "zhao",
    "浙": "zhe", "真": "zhen", "振": "zhen", "镇": "zhen", "正": "zheng", "证": "zheng",
    "志": "zhi", "制": "zhi", "致": "zhi", "智": "zhi", "中": "zhong", "众": "zhong",
    "重": "zhong", "州": "zhou", "周": "zhou", "珠": "zhu", "主": "zhu", "卓": "zhuo",
    "资": "zi", "紫": "zi", "自": "zi", "棕": "zong", "走": "zou", "足": "zu",
    "族": "zu", "最": "zui", "尊": "zun", "左": "zuo", "作": "zuo",
}


def _pinyin_of(brand: str) -> set[str]:
    """品牌名 → 拼音全拼与首字母。表里没有的字直接跳过，不影响主判定。"""
    try:
        from pypinyin import lazy_pinyin  # type: ignore

        syl = lazy_pinyin(brand)
        return {"".join(syl), "".join(s[0] for s in syl)}
    except Exception:
        pass
    syl = [_PINYIN[c] for c in brand if c in _PINYIN]
    if not syl:
        return set()
    return {"".join(syl), "".join(s[0] for s in syl)}


def _brand_aliases(name: str) -> set[str]:
    """品牌名 + 它的拉丁写法（拼音全拼 / 首字母 + 音近写法）。用于域名主体匹配。"""
    brand = _brand(name) or name
    out = {brand.lower()}
    out |= {p for p in _pinyin_of(brand) if len(p) >= 4}
    out |= {p for p in _pinyin_alt_of(brand) if len(p) >= 4}
    # 域名里只会出现拉丁字母：企业名本身带英文时要能用（`北京字节跳动科技有限公司` 没有，
    # 但 `TCL科技集团` / `OPPO广东移动通信` 这类有）
    out |= {t.lower() for t in re.findall(r"[A-Za-z]{3,}", name)}
    return {k for k in out if len(k) >= 3}


# 中文品牌的英文名常见写法：`字节跳动`→`ByteDance`、`瑞幸咖啡`→`Luckin Coffee`。
# 这类写法**拼不出来**，只能查表；表里没有就走拼音，不影响主判定。
_LATIN_BRAND = {
    "华为": {"huawei"}, "华为技术": {"huawei"},
    "字节跳动": {"bytedance", "toutiao", "douyin"},
    "抖音": {"douyin"}, "今日头条": {"toutiao"}, "飞书": {"feishu", "larksuite"},
    "瑞幸咖啡": {"luckin", "luckincoffee", "lkcoffee"},
    "腾讯": {"tencent"}, "阿里巴巴": {"alibaba", "alibabagroup"}, "蚂蚁": {"antgroup"},
    "京东": {"jd"}, "美团": {"meituan"}, "拼多多": {"pinduoduo"}, "小米科技": {"mi"},
    "小米": {"mi", "xiaomi"}, "蔚来": {"nio"}, "理想汽车": {"lixiang"}, "小鹏汽车": {"xiaopeng"},
    "比亚迪": {"byd"}, "宁德时代": {"catl"}, "顺丰": {"sf-express", "sfexpress"},
    "中国平安": {"pingan"}, "招商银行": {"cmbchina"}, "工商银行": {"icbc"},
    "建设银行": {"ccb"}, "农业银行": {"abchina"}, "中国银行": {"boc"},
    "哔哩哔哩": {"bilibili"}, "网易": {"netease"}, "百度": {"baidu"}, "知乎": {"zhihu"},
    "携程": {"ctrip"}, "去哪儿": {"qunar"}, "滴滴出行": {"didiglobal"}, "贝壳": {"ke"},
    "海康威视": {"hikvision"}, "大疆": {"dji"}, "科大讯飞": {"iflytek", "xfyun"},
    "三一重工": {"sany"}, "格力电器": {"gree"}, "美的集团": {"midea"},
    "茅台": {"moutai", "moutaichina"}, "五粮液": {"wuliangye"},
    "泸州老窖": {"lzlj"}, "洋河": {"yanghe"},
    "东方财富": {"eastmoney"}, "中信证券": {"citics"}, "国泰君安": {"gtja"},
    "交通银行": {"bankcomm"}, "浦发银行": {"spdb"},
    "民生银行": {"cmbc"}, "兴业银行": {"cib"}, "光大银行": {"cebbank"},
    "万科": {"vanke"}, "恒大": {"evergrande"}, "碧桂园": {"bgy", "countrygarden"},
    "融创": {"sunac"}, "龙湖": {"longfor"},
    "长城汽车": {"gwm"}, "吉利汽车": {"geely"}, "上汽集团": {"saicmotor"},
    "中国石化": {"sinopec"}, "中国石油": {"petrochina"}, "国家电网": {"sgcc"},
    "国网": {"sgcc"}, "国家电网": {"sgcc"},
    "中国移动": {"chinamobile"}, "中国电信": {"chinatelecom"}, "中国联通": {"chinaunicom"},
    "海尔": {"haier"}, "海信": {"hisense"}, "TCL": {"tcl"},
    "联想": {"lenovo"}, "浪潮": {"inspur"}, "用友": {"yonyou"}, "金蝶": {"kingdee"},
    "顺丰": {"sf-express", "sfexpress"}, "中通快递": {"zto"}, "圆通": {"yto"},
    "元气森林": {"yuanqisenlin"}, "农夫山泉": {"nongfuspring"},
    "安踏": {"anta"}, "李宁": {"lining"}, "波司登": {"bosideng"},
    "三只松鼠": {"3songshu"}, "良品铺子": {"lppz"},
    "同程": {"ly"},
    "小红书": {"xiaohongshu"}, "喜马拉雅": {"ximalaya"},
    "商汤": {"sensetime"}, "旷视": {"megvii"},
    "云从": {"cloudwalk"}, "依图": {"yitu"},
}


def _latin_brand_of(brand: str) -> set[str]:
    """品牌的中文名 → 已知英文名（查表合并全部命中项，查不到返回空）。

    不能命中一条就返回：`小米` 同时落在 `小米科技` 和 `小米` 两个键上，只取先命中的
    那个会漏掉另一个写法（`mi` / `xiaomi`），官网 xiaomi.com 就会因为「域名和品牌对不上」被丢。
    """
    b = (brand or "").strip()
    out: set[str] = set()
    for key, vals in _LATIN_BRAND.items():
        if key in b or b in key:
            out |= set(vals)
    return out


# 中文主体名里的行业缩写，常被压进域名的字母段（`zjdfjr` = 浙江东方 + 金融）
_IND_ABBR = {"jr": "金融", "kg": "控股", "touzi": "投资", "keji": "科技", "it": "信息",
             "wl": "网络", "ny": "能源", "yy": "医药", "zq": "证券", "cc": "财产",
             "bxy": "保险", "wlkj": "网络科技", "xxjs": "信息技术"}


def _abbr_match(plain: str, name: str) -> tuple[int, str]:
    """域名主体由「主体前缀 + 行业缩写」的拼音首字母拼成时才算匹配。

    `zjdfjr.cn` 是浙江东方金融控股集团的备案域，按品牌拼音（dongfang / df）都对不上；
    只按首字母全库匹配又会把 `zdj…`、`zjdy…` 一堆无关域打中，所以要求首字母严格对齐
    主体前缀，结尾再落在已知行业缩写上。
    """
    try:
        from pypinyin import lazy_pinyin  # type: ignore

        body = re.sub(r"(?:股份有限公司|有限责任公司|有限公司|集团|控股|股份|公司)$", "", name or "")
        ini = "".join(s[0] for s in lazy_pinyin(body) if s)
        if not (4 <= len(ini) <= 8):
            return 0, ""
        for ab, _zh in _IND_ABBR.items():
            for cut in range(3, len(ini) + 1):
                if plain == ini[:cut] + ab:
                    return 20, f"域名主体是主体名拼音首字母 + 行业缩写（{plain}）"
    except Exception:
        return 0, ""
    return 0, ""


def _pinyin_alt_of(brand: str) -> set[str]:
    """拼音的连写变体：`ruixingkafei` / `ruixing-kafei` / `ruixingkf` 都算同一品牌。"""
    try:
        from pypinyin import Style, lazy_pinyin  # type: ignore

        parts = [p for p in lazy_pinyin(brand, style=Style.NORMAL) if p]
    except Exception:
        parts = [_PINYIN[c] for c in brand if c in _PINYIN]
    if len(parts) < 2:
        return set()
    joined = "".join(parts)
    return {joined, parts[0] + "".join(p[0] for p in parts[1:]),
            "".join(p[0] for p in parts[:-1]) + parts[-1]}


def _domain_brand_score(domain: str, name: str, site_title: str = "") -> tuple[int, str]:
    """域名主体与品牌名的**字面**匹配（`huawei` / `lkcoffee` / `bytedance`）。

    中文品牌的拼音桥接（`瑞幸咖啡` → `rxkf`/`ruixingkafei`）只算弱证据：拼音能把
    `ruixingkafei.com` 生成出来，也能把一堆抢注域撞出来。真正算强证据的是品牌本身是
    拉丁字母、或企业名里写出来的英文词。站点标题里写了同一个拉丁词时，拼音桥接升级为成立。
    """
    if not name:
        return 0, ""
    label = (root_domain(domain) or domain).split(".")[0].lower()
    plain = re.sub(r"[^a-z0-9]", "", label)
    literals = _literal_aliases(name)
    latin = _latin_brand_of(_brand(name) or name) - literals
    if plain:
        # 已知英文名（`字节跳动`→`bytedance`、`瑞幸咖啡`→`lkcoffee`）：写进域名的就是这个品牌本身
        for k in latin:
            kp = re.sub(r"[^a-z0-9]", "", k)
            if plain == kp:
                return 30, f"域名主体就是该品牌的英文名（{plain}）"
        # 中文全称对应的英文缩写（`浙江东方金融控股集团` ⊃ 东方 → zjdf…）：域名在缩写后接
        # `jr`（金融）这类行业缩写，再按字面首字母切开对得上，才算「域名就是品牌缩写」。
        abbr = _abbr_match(plain, name)
        if abbr:
            return abbr
        for k in latin:
            kp = re.sub(r"[^a-z0-9]", "", k)
            if len(kp) >= 4 and (plain.startswith(kp) or plain.endswith(kp)):
                return 18, f"域名主体含品牌英文名（{plain} ⊃ {kp}）"
        for k in literals:
            if plain == k:
                return 25, f"域名主体就是品牌名（{plain}）"
        for k in literals:
            if len(k) >= 4 and (plain.startswith(k) or plain.endswith(k)):
                return 18, f"域名主体含品牌名（{plain} ⊃ {k}）"
    pinyin = {p for p in _pinyin_of(_brand(name) or name) if len(p) >= 4} - literals
    if plain:
        titled = re.sub(r"[^a-z0-9]", "", (site_title or "").lower())
        confirmed_by_title = any(k in titled for k in pinyin) if pinyin else False
        # 拼音全拼 / 首字母本身就是「品牌落进域名」的常见写法（huawei、lkcoffee、zjtd），
        # 只要站点标题与品牌对得上，就和字面品牌名同一档。
        # 站点标题是英文（`ByteDance` / `Huawei`）时，标题里的词本身就是域名的罗马化写法，
        # 而 `_pinyin_of` 只认中文的拼音，所以再按「域名主体是不是标题里的词」反查一次。
        if not confirmed_by_title and titled:
            confirmed_by_title = len(plain) >= 4 and plain in titled
        for k in pinyin:
            if plain == k:
                if confirmed_by_title:
                    return 18, f"域名主体是品牌拼音（{plain}），且站点标题写的是该品牌"
                return 9, f"域名主体是品牌拼音（{plain}），仅有拼写巧合"
            if len(k) >= 5 and (plain.startswith(k) or plain.endswith(k)):
                if confirmed_by_title:
                    return 14, f"域名主体含品牌拼音（{plain} ⊃ {k}），且站点标题写的是该品牌"
                return 6, f"域名主体含品牌拼音（{plain} ⊃ {k}），仅有拼写巧合"
    return 0, ""


def _literal_aliases(name: str) -> set[str]:
    """企业名里能直接落进域名的拉丁写法：品牌本身是英文，或企业名里带英文（`TCL科技`、`OPPO广东`）。

    只取企业名里写出来的英文，**不**包含品牌拼音 —— 拼音是「拼出来的」，抢注域同样能拼出来。
    """
    brand = _brand(name) or name
    out = {brand.lower()} if re.fullmatch(r"[A-Za-z0-9]{3,}", brand) else set()
    out |= {t.lower() for t in re.findall(r"[A-Za-z]{3,}", name)}
    return {k for k in out if len(k) >= 3}


def _domain_guesses(name: str) -> list[str]:
    """品牌名的拉丁写法 → 候选域名（huawei.com、rxkf.cn）。
    只产出候选，能否成立由打分闸决定；不出结果就当没有。
    机构类主体没有可用品牌缩写，硬猜只会拼出同行不相关的域，直接不给候选。"""
    if _institution_only(name):
        return []
    out: list[str] = []
    for c in sorted(_brand_aliases(name), key=len):
        for tld in ("com", "cn"):
            out.append(f"{c}.{tld}")
    return out[:8]


async def _official_hit(domain: str, name: str) -> bool:
    """兼容旧调用：只看自我声明。新流程用 `_site_check` 一次拿标题 + 主体 + 声明。"""
    chk = await _site_check(domain, name)
    return chk[2]


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_OG_SITE_RE = re.compile(
    r'<meta[^>]+(?:property|name)\s*=\s*["\'](?:og:site_name|application-name|apple-mobile-web-app-title)["\']'
    r'[^>]+content\s*=\s*["\']([^"\']{1,60})["\']', re.I)


def _title_brand_match(title: str, name: str, domain: str = "") -> bool:
    """站点标题是否在自称这家企业 / 这个品牌。

    只认**中文品牌写法**（`瑞幸咖啡`、`字节跳动`）或企业名里**写出来的**拉丁名（`BYD`）：
    标题里写「北京某某科技有限公司」常是聚合站条目，写「瑞幸咖啡」才是品牌自己。
    三条排除，都是实测踩过的坑：
      - 标题里只是出现了域名主体本身（`zjtd.cn` 这种统计后台页）→ 域名不是凭据；
      - 标题等于域名主体、没有别的词 → 同上；
      - 标题短于 4 个字 → `首页`、`Error` 这类通用页。
    """
    if not title or len(title.strip()) < 4:
        return False
    t = title.strip().lower()
    label = (root_domain(domain) or domain).split("://")[-1].split("/")[0].split(".")[0].lower() if domain else ""
    if label and label in t:
        return False
    brand = _brand(name) or name
    # 中文品牌直接比；站点标题里常写自己的拉丁品牌（`Luckin Coffee`、`LKCOFFEE.COM - 瑞幸咖啡`），
    # 所以把已知英文名与品牌本身也按字母比对一遍，避免只有拉丁写法的自查页被当成无关站。
    latin = {re.sub(r"[^a-z0-9]", "", v.lower()) for v in (_latin_brand_of(brand) | {brand})}
    latin = {k for k in latin if len(k) >= 4}
    if latin and any(re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", t) for k in latin):
        # 整词匹配：`xiaomi` 与 `Mi` 这类短词用包含会把 `United` / `Service` / `Submit` 全撞上，
        # 标题里写的是哪个品牌就只认那一整段词。
        return True
    cands = {brand.lower()} if brand and not brand.isascii() else set()
    cands |= {k.lower() for k in _literal_aliases(name)}
    if any(c and len(c) >= 2 and c in t for c in cands):
        return True
    # 站点标题以「有限公司 / Co., Ltd」这类主体后缀收尾 → 它在写自己的工商主体，
    # 这是域名自称身份最硬的写法（`ByteDance - Inspire Creativity` 的变体、`Luckin Coffee Co., Ltd`）。
    suffix = re.compile(r"(股份有限公司|有限责任公司|有限公司|集团|co\.,?\s*ltd|inc\.?|corp\.?|limited)", re.I)
    return bool(suffix.search(title)) and (not label or label in t or len(t) >= 8)


_SUBJECT_SUFFIX = re.compile(
    r"([\u4e00-\u9fa5A-Za-z（）()·\-]{2,24}?(?:股份有限公司|有限责任公司|有限公司))")
_LEGAL_WORDS = ("copyright", "版权", "©", "备案", "icp", "all rights reserved")


def _self_claimed_subjects(title: str, flat: str) -> set[str]:
    """站点自报的工商主体全称：标题里的 + 页脚「版权所有 / 备案」行里的。

    这是**域名 → 主体**方向的证据：站点自己写了它属于哪家公司。企业名的识别留到
    打分时做（品牌简称 / 品牌拼音 / 拼音首字母），这里只负责把主体全称捞全。
    """
    out: set[str] = set()
    for txt in (title,):
        for m in _SUBJECT_SUFFIX.finditer(txt or ""):
            out.add(m.group(1))
    low = (flat or "").lower()
    for m in _SUBJECT_SUFFIX.finditer(flat or ""):
        seg = low[max(0, m.start() - 60): m.end() + 60]
        if any(w in seg for w in _LEGAL_WORDS):
            out.add(m.group(1))
    return {s.strip() for s in out if 4 <= len(s.strip()) <= 30}


def _subject_matches(name: str, subjects: set[str]) -> str:
    """站点自报主体 vs 目标企业：品牌简称 / 品牌拼音 / 拼音首字母任一重合即算同一集团。

    品牌简称必须能区分「这家机构」：`厦门市特种设备检验检测院` 剥完只剩行业词，
    这时只认完整名称互相包含，禁止拿「特种设备」去认同行的「山东省特种设备检验研究院」。
    """
    if not subjects:
        return ""
    brand = _identity_brand(name)
    if not brand:
        full = re.sub(r"\s+", "", name or "")
        core = _core_brand(full)
        for s in subjects:
            low = re.sub(r"\s+", "", s)
            if len(full) >= 4 and (full in low or low in full):
                return s
            if core and len(core) >= 4 and core in low:
                return s
        return ""
    # 品牌段本身还带行业词时（`特种设备`），只认「完整名称 / 地名+核心段」两种硬对法：
    # 拿品牌段去比，山东省同类机构照样命中。
    if _is_industry_only(brand):
        full = re.sub(r"\s+", "", name or "")
        core = _core_brand(full)
        for s in subjects:
            low = re.sub(r"\s+", "", s)
            if len(full) >= 4 and (full in low or low in full):
                return s
            if core and len(core) >= 4 and core in low:
                return s
        return ""
    marks = {brand} | {k for k in _pinyin_of(brand) if len(k) >= 3} | _literal_aliases(name)
    latin = _latin_brand_of(brand)
    marks |= {k.replace("-", "").replace(" ", "") for k in latin}
    marks |= {k.replace("-", " ") for k in latin if " " in k or "-" in k}
    for key in _latin_brand_of(brand):
        for cand in (key.replace("-", ""), key.replace("-", " ")):
            if len(cand) >= 4:
                marks.add(cand)
    for s in subjects:
        low = s.lower()
        if any(m and m.lower() in low for m in marks):
            return s
    return ""


def _title_fullname_hit(name: str, title: str, brand: str = "") -> bool:
    """标题里出现机构全称（或能区分主体的核心段）+ 官方类词 → 认作官方站。

    SPA 官网常把品牌写进 `<title>`（`厦门市特种设备检验检测院`），但首页没有自我声明的
    备案主体；这条是「标题本身就是全称」这一路唯一能认回来的证据。
    """
    t = (title or "").strip()
    if len(t) < 4:
        return False
    official = ("官网", "官方网站", "集团", "官方", "简介", "首页", "门户")
    compact = re.sub(r"\s+", "", t)
    full = re.sub(r"\s+", "", name or "")
    if len(full) >= 4 and full in compact and any(x in t for x in official):
        return True
    core = _core_brand(full)
    if len(core) >= 4 and core in compact and any(x in t for x in official):
        return True
    key = _identity_brand(name) or brand
    if not key:
        return False
    core = re.sub(r"(科技|集团|股份|有限|公司|控股|技术)+$", "", key) or key
    for word in (key, core):
        if len(word) >= 2 and word in t:
            return any(x in t for x in official)
    return False


async def _site_check(domain: str, name: str) -> tuple[str, set[str], bool]:
    """抓候选域首页：返回 (站点自称标题, 站点自报主体全称集合, 是否有自我声明)。

    站点标题（`<title>` / og:site_name）是**域名 → 品牌**最直接的证据：搜索结果里
    排第一的不一定是官网（招聘站、开源站也常排第一），但站点自己写的标题会说实话。
    """
    keys = _name_keys(name)
    host = domain.split("://")[-1].strip("/")
    # 只在根域有 A 记录时才去试 www / http / /cn：没有任何解析的域四种写法都等满超时，
    # 白白吃掉整域预算（死域名常年是候选池里最多的那一类）。
    alts = [f"https://www.{host}/", f"http://www.{host}/", f"http://{host}", f"https://{host}/cn/",
            f"https://{host}/zh/", f"https://{host}/index.html"]
    if await _domain_alive(host):
        urls = [f"https://{host}"] + alts
    elif await _domain_alive(f"www.{host}"):
        # 只有 www 挂了 A 记录、裸域没有，是备案里最常见的一种写法（根域只做转发的
        # CNAME 记录在 HttpClient 里查不到）。以前这里直接只试裸域，等于把「官网
        # 只在 www 上」的站点判成没有站点证据，标题与自报主体两路证据全丢。
        urls = alts[:2] + [f"https://{host}"]
    else:
        urls = [f"https://{host}"]
    # 一组 URL 串行试、每次等满超时会把这个域拖到 30s 以上（首域常连不上 80/443 之外的写法），
    # 而 11 个候选是并发的，整轮就被最慢的那个域钉住。给每个 URL 5s、整域 12s 总预算：
    # 超了就用已经拿到的结果（拿不到就当无站点证据），归属判定还有证书 / ICP / 域名写法几路。
    # 预算给到这个量级是因为实测 `moutai.com.cn` 的 https 裸域每次都要等满超时才落到 www，
    # 8s 预算刚好在第二个写法上耗尽，官网标题就永远拿不到。
    deadline = asyncio.get_running_loop().time() + 12.0
    for url in urls:
        left = deadline - asyncio.get_running_loop().time()
        if left <= 0.5:
            break
        try:
            r = await _get(url, timeout=min(5.0, left), headers={
                "User-Agent": _BROWSER_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                # 部分官网按语言给不同首页：不带这句会落到海外站（`xiaomi.com` 直接跳日本站），
                # 站点标题与自报主体都变成另一家公司。
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
            })
        except Exception:
            continue
        if r is None:
            # 连接被拒 / DNS 失败这类硬错再换写法也连不上，直接收手；
            # 只有超时才值得换一个写法（有些站只挂 http 或只响应 www）。
            if "timeout" in passive.LAST_GET_ERROR.lower():
                continue
            # 别的写法仍可能连得上：大厂官网常把裸域的 443 直接断掉（反爬/CDN 策略只留 www），
            # 而 `www` 与 `http` 是通的。错误不按 host 区分时一律继续试，代价只是多一次 5s。
            continue
        raw = r.text or ""
        if r.status_code >= 400:
            # 4xx/5xx 有两类：一类是「站在这但没这个页面」，换写法还有机会；
            # 另一类是 WAF 拦截页 / 反代错误页（盾、网关 502、`405 Not Allowed`），
            # 正文里往往写着托管商名字而不是本站名字，拿去当证据就是误判。
            # 先只从这份正文里捞结构化自我描述（JSON-LD / og），捞不到再换写法。
            soft = _page_identity(raw, keys)
            if soft[0] or soft[1]:
                return soft[0], soft[1], soft[2]
            if left < 6.0:
                break
            continue
        return _page_identity(raw, keys)
    return "", set(), False


def _page_identity(raw: str, keys: set[str] | None = None) -> tuple[str, set[str], bool]:
    """从一份页面正文里提取 (站点自称标题, 站点自报主体, 是否有自我声明)。

    官网的自我描述散在三个地方，按可靠度从高到低都看一遍：
    `<title>` / og:site_name、页面可见正文里的备案号旁署名、内联 JSON 里的站点名。
    只看 `<title>` 会把 JS 渲染站和 WAF 盾后的站全部判成「无证据」。
    """
    keys = keys or set()
    raw = raw or ""
    m = _TITLE_RE.search(raw) or _OG_SITE_RE.search(raw)
    title = ""
    if m:
        title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1))).strip()
    if _is_intercept_title(title):
        # 「502 Bad Gateway」「405 Not Allowed」「安全防护」是中间件/盾的标题，
        # 不是站点自述，留着会把它当品牌证据。
        title = ""
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", raw, flags=re.S | re.I)
    flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))
    declared = False
    if keys and any(k in flat for k in keys):
        # 企业名出现在备案号旁边（或版权行里）才认，出现在新闻转载里不算
        for mm in _OFFICIAL_HINT.finditer(flat):
            seg = flat[max(0, mm.start() - 60): mm.end() + 60]
            if any(k in seg for k in keys):
                declared = True
                break
    # 只有一行 JS / 统计脚本、没有正文的页面不是官网（免费统计后台会内嵌自己的域）
    if declared and len(flat) < 200:
        declared = False
    # 满屏「加盟 / 招商 / 代理 / 开店咨询」的页面不是品牌方自己的站：这类站盗用品牌名做
    # 招商引流，页面一定会写品牌，但绝不会写自己的工商主体（写法本身就是仿冒）。
    if declared and _is_franchise_page(flat):
        declared = False
    subjects = _self_claimed_subjects(title, flat)
    if not title and not declared:
        # 既没有标题也没有声明：多半是等 JS 才出内容的壳页（`moutai.com.cn`
        # 这类官网就是整页脚本渲染）。再从结构化数据和内联 JSON 里捞站点名。
        for name in (_jsonld_name(raw), _inline_site_name(raw)):
            if name and not _is_intercept_title(name):
                title = name
                break
        if title:
            subjects = _self_claimed_subjects(title, flat)
    return title, subjects, declared


# 中间件 / WAF / 反代错误页的标题：这些页面确实是「有响应」，但内容与站点归属无关。
# 拿去打分等于拿盾的名字当品牌证据，比没有证据更糟。
_INTERCEPT_TITLE_RE = re.compile(
    r"bad gateway|service unavailable|gateway time|not allowed|access denied|forbidden|"
    r"安全防护|访问拦截|网站防火墙|云防护|请稍候|正在验证|人机验证|"
    r"^\s*(\d{3}|error|nginx|apache|iis|openresty|tencent|aliyun|yakit)\b",
    re.I)


def _is_intercept_title(title: str) -> bool:
    t = (title or "").strip()
    if not t:
        return False
    return bool(_INTERCEPT_TITLE_RE.search(t))


_JSONLD_RE = re.compile(r'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                        re.S | re.I)


def _jsonld_name(raw: str) -> str:
    """JSON-LD 里的 Organization / WebSite 名称：官网模板普遍标配，且在 <head> 里。"""
    if not raw or len(raw) > 400_000:
        return ""
    for block in _JSONLD_RE.findall(raw)[:6]:
        try:
            data = json.loads(block.strip())
        except Exception:
            continue
        stack = [data]
        while stack:
            cur = stack.pop()
            if isinstance(cur, list):
                stack.extend(cur[:20])
                continue
            if not isinstance(cur, dict):
                continue
            typ = str(cur.get("@type") or "")
            if typ in ("Organization", "Corporation", "LocalBusiness", "WebSite", "GovernmentOrganization"):
                for k in ("legalName", "name", "alternateName"):
                    v = str(cur.get(k) or "").strip()
                    if 2 <= len(v) <= 60 and len(re.findall(r"[\u4e00-\u9fff]", v)) >= 2:
                        return v
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
    return ""


_INLINE_NAME_RE = re.compile(
    r'"(?:siteName|site_name|shortName|appName|title|name)"\s*:\s*"([^"\\]{2,40})"', re.I)


def _inline_site_name(raw: str) -> str:
    """从壳页的内联 JSON / 脚本变量里捞站点名（JS 渲染站的标题常写在这里）。"""
    if not raw or len(raw) > 400_000:
        return ""
    for m in _INLINE_NAME_RE.finditer(raw):
        val = re.sub(r"\s+", " ", m.group(1)).strip()
        zh = len(re.findall(r"[\u4e00-\u9fff]", val))
        # 只收中文站点名：英文键名（`name":"app"`）噪声太多，中文名才对得上企业品牌
        if zh >= 2:
            return val
    return ""


# 站点标题里的「我们是谁」：`联系我们`、`集团简介` 这类导航词与品牌名同样有效 ——
# 两字品牌的官网常常只写「小米官网」「茅台集团」，标题里不含企业全称，靠这两条才能收住。
def _title_institutional(title: str, name: str) -> bool:
    """标题自称「XX 官网 / XX 集团 / 关于我们」，且 XX 就是品牌本身或品牌核心词。"""
    t = (title or "").strip()
    if len(t) < 4:
        return False
    brand = _identity_brand(name)
    if not brand:
        # 没有可区分的短写法（`厦门市特种设备检验检测院`）：只认全称出现在标题里
        full = re.sub(r"\s+", "", name or "")
        return len(full) >= 4 and full in t.replace(" ", "") and any(
            x in t for x in ("官网", "官方网站", "集团", "官方", "简介", "首页"))
    core = re.sub(r"(科技|集团|股份|有限|公司|控股|技术)+$", "", brand) or brand
    for word in (brand, core):
        if len(word) >= 2 and word in t:
            return any(x in t for x in ("官网", "官方网站", "集团", "官方", "简介", "首页"))
    return False


_FRANCHISE_WORDS = ("加盟", "招商", "代理", "加盟费", "开店", "投资回报", "门店", "加盟商", "培训费")


def _is_franchise_page(flat: str) -> bool:
    """页面主体是招商加盟内容而不是品牌自己的业务介绍。"""
    if len(flat) < 100:
        return False
    hits = sum(1 for w in _FRANCHISE_WORDS if w in flat)
    return hits >= 4


def _cert_der(domain: str) -> bytes:
    """取证书 DER。部分站的 TLS 只认新版套件，先默认上下文，再退回更宽的设置。"""
    host = domain.split("://")[-1].strip("/")
    attempts = []
    ctx1 = ssl.create_default_context()
    ctx1.check_hostname = False
    ctx1.verify_mode = ssl.CERT_NONE
    attempts.append(ctx1)
    try:
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.set_ciphers("DEFAULT:@SECLEVEL=0")
        attempts.append(ctx2)
    except Exception:
        pass
    last = ""
    for ctx in attempts:
        try:
            with socket.create_connection((host, 443), timeout=4) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(binary_form=True) or b""
        except Exception as e:
            last = str(e)
    raise OSError(last or "cert fetch failed")


async def _cert_brand_hit(domain: str, keys: set[str]) -> bool:
    """TLS 证书里出现企业名 / 品牌——比抓首页便宜，也不受反爬和 JS 渲染影响。

    中文主体名在证书里以 UTF8String 存放，直接按 UTF-8 视野扫 DER 就能命中；
    英文品牌名常出现在 CN / SAN 里，同样能扫到。
    """
    loop = asyncio.get_running_loop()
    # 阻塞套接字取消不掉：wait_for 只是不再等它，线程还占着。所以 DNS / 证书都走
    # utils 的专用阻塞池（线程数封顶），别去挤事件循环的默认池——默认池被占满后
    # 其它模块的阻塞调用全排在后面，表现就是整个服务像死掉。
    # 这里先给 DNS 解析设 3s 上限，解析不出来的域直接判无证书，别让十几个死域各占一条线程。
    try:
        await asyncio.wait_for(run_blocking(socket.gethostbyname, domain), timeout=3)
    except Exception:
        return False
    try:
        der = await asyncio.wait_for(run_blocking(_cert_der, domain), timeout=6)
    except Exception:
        return False
    if not der:
        return False
    text = der.decode("utf-8", "ignore")
    return any(k and k in text for k in keys)


async def _domain_alive(domain: str) -> bool:
    """活域闸：解析出 A 记录就放行。不探 HTTP，避免把只挂 API 的域误杀。
    站点全挂在 `www` 上、根域没有 A 记录也常见（moutaichina.com），根域不通再看 www。"""
    loop = asyncio.get_running_loop()

    async def _dns(host: str) -> bool:
        try:
            info = await asyncio.wait_for(
                run_blocking(socket.getaddrinfo, host, None), timeout=5)
            return bool(info)
        except Exception:
            return False

    return await _dns(domain) or await _dns(f"www.{domain}")


def _acronyms_of(name: str) -> set[str]:
    """主体名可能被缩成哪几个拉丁串（域名主体常就是其中之一）。

    `厦门市特种设备检验检测院` 的官网域名是 `xmaj.com`（厦门 + 安监），这个缩写既不是
    全拼、也不是逐字首字母，**任何按拼音推导都到不了**，只能靠站点/证书/检索位自己说话。
    这里只产出能被推导出来的两种：分节首字母连写（`xm` + `tzsbjy` → `xmtzsbjy`）与
    分节拼音缩写（`tezhongshebei` → `tzsb`）。调用方拿它做「域名是否与检索词有出处」
    的**前置过滤**，命中与否都不能单独当归属证据。
    """
    out: set[str] = set()
    parts = [p for p in re.split(r"[\s\u3000]+", _core_brand(name) or (name or "").strip()) if p]
    if not parts:
        return out
    heads: list[str] = []
    for part in parts:
        py = sorted(p for p in (_pinyin_of(part) or set()) if 2 <= len(p) <= 20)
        if not py:
            continue
        # `_pinyin_of` 同时给整串全拼与它的首字母；全拼取前两字母当这一段的首字母写法
        heads.append(min(py, key=len))
    if heads:
        for cut in (2, 3, 4, 5, 6, 8):
            if len(heads) >= cut:
                out.add("".join(heads[:cut]))
            joined = "".join(heads)
            if len(joined) >= cut:
                out.add(joined[:cut])
    for part in parts:
        for p in _pinyin_of(part) or set():
            if 2 <= len(p) <= 6 and p not in heads:
                out.add(p)
    return {a for a in out if len(a) >= 2}


def _query_mentions_domain(query: str, domain: str) -> bool:
    """域名主体能不能在检索词里找到出处：拉丁品牌直写，或拼音/首字母缩写。

    `xmaj.com` 对 `厦门市特种设备检验检测院`：`xm`（厦门）+ `aj`（安监）不是标准缩写，
    要能过这一关必须靠站点/证书自己说话，不靠字母巧合。
    """
    label = re.sub(r"[^a-z0-9]", "", (root_domain(domain) or domain).split(".")[0].lower())
    if not label:
        return True
    # 机构全称里点名写出的域名（`厦门市特种设备检验检测院 xmaj.com`）：引擎把这条当
    # 「这个全称对应这个站」返回，域名本身就是出处，不存在字母缩写碰巧撞上的问题。
    if re.search(rf"(?<![a-z0-9]){re.escape(root_domain(domain) or domain)}(?![a-z0-9])",
                 (query or "").lower()):
        return True
    q = re.sub(r"[^a-z0-9]", "", (query or "").lower())
    if len(label) >= 4 and label in q:
        return True
    for a in _acronyms_of(query):
        if len(a) < 3:
            continue
        # 双子缩写（`tzsb`⊂`tzsbjy`）在同行机构里满地都是，不算出处；4 字母以上要求整段相等
        if len(a) <= 4 and label == a:
            return True
        if len(a) >= 5 and a in label:
            return True
    return False


def _other_institution(title: str, full: str) -> bool:
    """标题写的是**另一家**同行业机构的全称（`湖州市特种设备检验检测院`），不是目标。

    形态：标题里有「XX市/省 + 行业词 + 院所后缀」的完整机构名，而且不含目标全称。
    真官网那条标题本身就等于目标全称，不会被判成别家。
    """
    t = re.sub(r"\s+", "", title or "")
    if not t or not full or full in t:
        return False
    m = re.search(rf"([\u4e00-\u9fa5]{{2,8}}(?:市|省|自治区|县|区))([\u4e00-\u9fa5]{{2,14}}"
                  r"(?:院|所|中心|站|校|局|台|馆|队))", t)
    if not m:
        return False
    return bool(_trade_only(m.group(2)) or _is_industry_only(m.group(2)))


def _score_domain(domain: str, hits: list[web.Hit], name: str, *, declared: bool = False,
                  icp_hit: bool = False, cert_hit: bool = False,
                  site_title: str = "", subjects: set[str] | None = None,
                  rev_icp: str = "", rev_subject: str = "",
                  icp_family: bool = False) -> DomainEvidence:
    """单域打分。所有证据都在这里汇总，返回值原样下发到前端与库里。

    判定分两档：**强证据**（站内自我声明 / 站点自报同一主体 / 域名写法即品牌 / ICP 主体一致）
    能独立成立；**弱证据**（搜索标题、摘要、多引擎同时出现、证书、拼音巧合）只能互相叠加，
    凑不齐就从 pending 降到 rejected。
    为什么：搜索标题里出现企业名经常是新闻转载、招聘页、开源页，单靠它下发会打偏整条流水线；
    而候选域里还有一批靠拼音拼出来的猜测域，它们必须有自己的真实站点才能过关。
    """
    ev = DomainEvidence(domain=domain)
    # 机构类目标（地名 + 行业词 + 院所后缀）的候选全是「同行站」：域名缩写对不上、标题写的
    # 是别家、站点也不会自报。这一类只认两条硬证据 —— 反查备案主体对得上，或站点标题写着
    # 目标全称。其余候选直接丢弃，避免同行站被多条弱证据叠成确认，把整条流水线带偏。
    # 机构类目标的候选池里本来就混着同行院与同主体的邻家机构，这条豁免只给「就是本主体」
    # 且主域确实有站的那一个；同群体域名只拿弱分。
    # `icp_hit` 是备案那一路给出的「这个域就登记在目标主体名下」：它本身就是行政登记结论，
    # 与反查得来的一档等价。以前只认 rev_icp，于是备案来源的域反而过不了这道机构闸
    # （`xmaj.com` 明明反查到了同一主体，仍被当成同行站丢掉）。
    self_icp = bool(icp_hit) or (bool(rev_icp) and _subject_self(rev_subject or rev_icp, name))
    if _institution_only(name) and not (self_icp or _title_fullname_hit(name, site_title, "")):
        ev.score = 0
        ev.reasons.append("机构类目标：未反查到同一备案主体、站点也未写目标全称，判为同行/无关站")
        ev.status = "rejected"
        return ev
    keys = _name_keys(name)
    brand = _brand(name) or name
    # 集团级品牌的官网根域常和品牌字面无关（`qq.com`、`tencent.com` 对上「腾讯」），
    # 域名写法、拼音桥接、证书主体都指不到它。这一类靠「已知产品根域」直接认定，
    # 但它只对当前品牌成立：查别家这个域仍按平台/无关站扣分。
    own_root = (root_domain(domain) or domain) in _own_roots_of(name)
    if own_root:
        ev.add(W_OWN_ROOT, f"该根域是「{brand}」自家的产品主域（{root_domain(domain) or domain}）")
    # 两个字的品牌（`寻梦`、`快手`）在中文里是同名小公司的高发词：搜索引擎返回的是另一个
    # 同名主体的词条，域名写法也对不上。这类只认它自己站点上写出来的主体/ICP。
    short_brand = len(brand) <= 2 and not brand.isascii() and not _is_own_brand_root(root_domain(domain) or domain, name)
    ev.engines = sorted({h.engine for h in hits})
    ev.site_title = site_title
    # 已知产品主域本身就是归属结论：它不依赖页面文案，也不与其它证据抢分。
    strong = 1 if own_root else 0
    # 反查备案（域名 → 主办单位）：备案库里登记的**主办单位全称**对得上目标，是行政登记
    # 结论，与页面文案、检索排名无关。这条对 SPA 官网最关键 —— `xmaj.com` 首页无 title、
    # 无自我声明，全称查备案又是 0 条，只有反查这一跳能把它认回来。反过来，同行站的备案
    # 主体写的是别家（`niast.com`），这一档也天然把它挡在外面。
    if rev_icp or icp_hit:
        # 这一档本身就是「主办单位全称对得上」，说明文案不重要，只描述证据来源。
        # 「就是本主体 + 主域有站」给到确认线；同一主办单位下的邻家机构名只算同群体弱分。
        unit_txt = rev_subject or rev_icp
        hit_mark = f"域名备案主办单位「{unit_txt}」" if unit_txt else "域名备案主办单位"
        if self_icp:
            ev.add(CONFIRM_SCORE, hit_mark + "与目标任务本身一致（反查域名得）")
            strong += 1
        elif icp_family:
            # 集团主干站常登记在区域公司名下：`luckincoffee.com` 的主办单位是北京公司，
            # 任务查的却是中国公司。这既不是本主体（给不了确认级结论），也绝不是邻家机构。
            # 以前两档只有「本主体 / 别人」二选一，这一整片自己被压进「仅作线索」，
            # 官网排到一排同名词条后面 —— 这就是企业主体「不全 + 打偏」的主因。
            ev.add(W_ICP + 15, hit_mark + "属同一品牌的兄弟主体（集团内另一家登记公司），按线索计分")
        else:
            ev.add(W_ICP, hit_mark + "属同一主办单位，但登记主体是邻家机构（仅作线索）")
    if declared:
        ev.add(W_DECLARED, "站内自我声明（企业名与备案号/版权/关于我们同段）")
        strong += 1
    site_subject = _subject_matches(name, subjects or set())
    if site_subject:
        ev.add(W_SUBJECT, f"站点自报主体「{site_subject}」与目标同属一家")
        strong += 1
    title_says_brand = bool(site_title) and _title_brand_match(site_title, name, domain)
    # SP 官网标题直接写机构全称（`厦门市特种设备检验检测院`）：机构类主体的官网页头
    # 就是这么写的，含全称的标题是站点自己在报家门，与「标题提到品牌」不是一回事。
    title_fullname = bool(site_title) and _title_fullname_hit(name, site_title, brand)
    # 两字品牌的官网常只写「小米科技」「茅台集团」，不含企业全称：标题自称官网/集团也算，
    # 但只作为解锁条件，不给单独加分（标题是站自己写的，单靠标题不进确认）。
    title_institutional = bool(site_title) and _title_institutional(site_title, name)
    self_described = title_says_brand or title_institutional
    # 用企业全称/品牌去搜，引擎把候选域排在最前几位，是「这条检索为该域背书」的信号。
    # 但签名式证据本身不等于归属：SPA 官网（`xmaj.com`）首页没有 title、没有自我声明，
    # 只有检索位；同一条规则放到「特种设备」这种行业词上，会把 hztjzx.cn / sei.sd.cn
    # 这些同行站一起排进前几位。所以它只在站点/域名已经给出主体写法时才算强证据，
    # 空标题站一律不给分，避免用「检索词里有这几个字母」把无关域拉进来。
    ent_q = entity_queries(name)[:3]
    dest_hit = None
    for h in hits:
        if h.rank > TOP_RANK or not ent_q:
            continue
        if (h.title or h.snippet):
            continue
        if not any(_query_mentions_domain(q, domain) for q in ent_q):
            continue
        dest_hit = h
        break
    if dest_hit is not None:
        ev.reasons.append(f"检索「{ent_q[0]}」第 {dest_hit.rank + 1} 位指向该域（空标题，单凭检索位不成立）")
    score, why = _domain_brand_score(domain, name, site_title)
    # 首页自述与目标无关（结构闸）：首页拿得到标题，但标题既没自称品牌/全称，也没有自报
    # 主体、备案、站内声明、已知主域任一项支撑，域名写法也对不上品牌 —— 说明这条候选的
    # 分数全部来自「引擎把黄页/行业门户的收录条目排在了前面」。黄页站收录了这家企业，
    # 标题里当然写着这个名字，以前这种标题会被当成强证据直接越过确认线（顺企网、锅炉之家
    # 都是这么进来的），确认后再按根域跑被动子域，几百条平台子域就灌进了资产池。
    # 空标题的 SPA 官网不触发：那种站只能靠检索位与备案认。
    site_unrelated = bool(site_title) and not _is_generic_title(site_title) and score < 14 and not (
        own_root or declared or self_icp or icp_hit or rev_icp or site_subject
        or title_says_brand or title_fullname or title_institutional)
    # 域名写法证据：字面品牌名（25/18），或拼音写法 + 站点标题交叉（18/14）。
    # 单纯拼音巧合（9/6）只当弱证据，防止抢注域靠拼写硬闯。
    domain_identity = score >= 14
    # 域名的**精确**写法（`xiaomi` / `mi`⊂`xiaomi` 这类只认全文相等，不含前后缀包含）
    # 是品牌自己的拉丁写法，同名小公司很难撞上；两字品牌的降级只针对拼音包含这类巧合。
    exact_latin = score >= 25
    if short_brand and domain_identity and not exact_latin and not (site_subject or icp_hit or declared or self_described):
        # 短品牌靠拼音包含（`xunmengvip` ⊃ `xunmeng`）会把同名小公司顶成确认：降为弱证据
        ev.add(min(score, 12), why + "（两个字的品牌仅作参考）")
    else:
        if score:
            ev.add(score, why)
            if domain_identity:
                strong += 1
    # 站点标题自称品牌：单独不算强证据（导航里写一句「相关企业」就能白拿分），
    # 与域名 / ICP / 声明任一条交叉才升级。
    if title_says_brand:
        if score or declared or icp_hit or site_subject or own_root:
            ev.add(W_SITE_TITLE, f"站点标题自称该企业/品牌：{site_title[:40]}（与域名/声明交叉佐证）")
            strong += 1
        else:
            ev.reasons.append(f"站点标题提到品牌「{site_title[:30]}」，但域名与声明都不支持")
    title_hit = [] if short_brand else [h for h in hits if any(k in h.title for k in keys)]
    brand_hit = [] if short_brand else [h for h in hits if any(k in h.title for k in (brand,))]
    snip_hit = [h for h in hits if any(k in h.title + " " + h.snippet for k in keys)]
    if title_fullname:
        ev.add(W_SUBJECT, f"站点标题写着机构全称：{site_title[:40]}")
        strong += 1
    if title_hit:
        best = min(title_hit, key=lambda h: h.rank)
        if best.rank <= TOP_RANK:
            ev.add(W_TITLE, f"搜索第 {best.rank + 1} 位标题就是企业名：{best.title[:40]}")
            if site_unrelated:
                # 黄页 / 行业门户收录了这家企业，标题当然写企业名：这条只说明「库里收录过」，
                # 不能升级成强证据，否则下面的弱证据封顶会被它一个人绕开。
                ev.reasons.append("首页自述与目标无关，这条只是收录条目，不算归属证据")
            elif not site_title and _directory_wording(best.title + " " + best.snippet):
                # 首页标题取不到，而引擎给回来的这条标题/摘要本身就是目录写法
                # （「…招标公告 - 电力招标网」）：那是门户收录本企业的条目，不是它自己的站。
                # 以前这种条目按「搜索第 1 位标题就是企业名」算强证据，标题 25 + 摘要 15
                # + 多引擎 10 = 50，正好越过 45 的确认线 —— 招标门户就是这么进主域清单、
                # 再被按根域跑一代子域的。空标题的 SPA 官网不在此列：它们的检索条目不会写成目录。
                ev.reasons.append("首页无标题，检索条目是目录/门户写法，不算归属强证据")
            else:
                strong += 1      # 引擎把这条排在最前，且标题写着品牌名：与官网声明同级
        else:
            ev.add(W_LATE, f"排在搜索第 {best.rank + 1} 位（偏远），仅作参考")
    elif brand_hit and min(brand_hit, key=lambda h: h.rank).rank <= TOP_RANK:
        best = min(brand_hit, key=lambda h: h.rank)
        ev.add(W_TITLE, f"搜索第 {best.rank + 1} 位标题是品牌名：{best.title[:40]}")
        if not site_unrelated and (site_title or not _directory_wording(best.title + " " + best.snippet)):
            strong += 1
    if snip_hit and not short_brand:
        ev.add(W_SNIPPET, "搜索摘要命中企业名")
    elif any(k in h.text for h in hits for k in keys) and not title_hit and not brand_hit:
        # 只在摘要里顺带提一句企业名：转载/对比/榜单页的典型形态，给负分把总分拉下来
        ev.add(W_MENTION_ONLY, "仅摘要顺带提及，无标题与声明支撑")
    if len(ev.engines) >= 2:
        ev.add(W_MULTI_ENGINE, f"{len(ev.engines)} 个引擎同时排到（{'/'.join(ev.engines)}）")
    if cert_hit:
        ev.add(W_CERT, f"TLS 证书里出现主体名 / 品牌「{brand}」" + ("" if strong else "（仅辅证）"))
    if _is_public_body(domain):
        ev.add(W_PUBLIC_TLD, "公共主体后缀（政府/教育/组织），不属于企业自有资产")
    if _is_platform(domain, name):
        ev.add(W_PLATFORM, "地图/黄页/论坛/招聘/媒体平台站：标题出现企业名是检索结果，不是自有资产")
    if site_unrelated:
        ev.add(W_SITE_UNRELATED,
               f"首页自述「{site_title[:30]}」与目标无关，得分只来自检索排名，不是这家企业的站")
        if _directory_wording(site_title):
            ev.add(W_PLATFORM, "首页标题是目录/黄页/供求/行业门户写法：它收录了这家企业，不是它的站")
    if subjects and not site_subject:
        # 站点写了自己的主体，但和目标对不上：加盟招商、山寨官网的典型形态——页面满屏品牌名，
        # 页脚版权却属于另一家公司（`瑞幸咖啡加盟官网` 的版权方是别的茶饮公司）。
        # 这类必须扣到确认线以下，否则「自称官网」就能把仿冒站送进采集链。
        other = sorted(subjects)[0]
        ev.add(W_FOREIGN_SUBJECT, f"站点自报主体「{other}」与目标无关（仿冒/加盟站形态）")
    ev.hits = [h.title[:60] for h in (title_hit or hits)[:3] if h.title]
    # 弱证据封顶：没有任何强证据时，标题+摘要+多引擎最多算 45 分，禁止靠叠加硬闯确认线；
    # 有强证据时总分照常累计，让「域名即品牌 + 官网声明」这类清晰案子分差拉开。
    if not strong:
        ev.score = min(ev.score, CONFIRM_SCORE - 1)
        ev.reasons.append("仅搜索类弱证据，未达到归属确认标准")
    foreign = bool(subjects) and not site_subject and not own_root
    if short_brand and not (site_subject or icp_hit or declared or own_root):
        # 两个字的品牌在同名主体之间无法靠名称区分，只能由站点自己申报主体、备案或已知产品主域来定
        ev.status = "pending" if ev.score >= PENDING_SCORE else "rejected"
        ev.reasons.append("两个字的品牌：站点未自报主体，仅作候选")
    elif foreign:
        # 站点明说了自己是谁，而且不是目标：其余证据（标题自称、域名含品牌）全部来源于页面文案，
        # 文案本身可被仿冒站随意书写，所以不给确认
        ev.status = "pending" if ev.score >= PENDING_SCORE else "rejected"
        ev.reasons.append("站点自报主体与目标无关，需人工核验")
    elif site_unrelated:
        # 首页自己都说了它是谁（黄页 / 行业门户），剩下的分数全是检索排名叠出来的：
        # 这类最多当候选，绝不允许进采集链再按根域跑被动子域。
        ev.status = "pending" if ev.score >= PENDING_SCORE else "rejected"
        ev.reasons.append("首页自述与目标无关，需人工核验")
    elif ev.score >= CONFIRM_SCORE:
        ev.status = "confirmed"
    elif ev.score >= PENDING_SCORE:
        ev.status = "pending"
    else:
        ev.status = "rejected"
    return ev


async def domain_evidence(name: str, candidates: list[str], *,
                          extra_icp: set[str] | None = None,
                          icp_units: dict[str, str] | None = None,
                          icp_rels: dict[str, str] | None = None,
                          hits: list["web.Hit"] | None = None,
                          pin: set[str] | None = None) -> list[DomainEvidence]:
    """给一批候选域打归属分。候选来自 ICP / 搜索 / AI 猜测，统一走这里。

    `hits` 由调用方传入已经搜到的结果，省掉一次重复检索；不传就自己搜。
    `candidates` 只收搜索命中里出现的域：搜索结果本身就是候选池，真实品牌域
    （瑞幸的 lkcoffee.com）只会在命中里出现一次，不会同时出现在调用方给的 ICP 名单里。
    `icp_units` 是「候选根域 → 备案主办单位全称」，只有备案这一路确认过的主体会带。
    有它就不必对同一个域再反查一次备案，也让判定理由能写出登记的那家公司全称。
    `icp_rels` 是同一个根域对应的关系档（self / family），兄弟主体不能给确认级结论。
    `pin` 是按品牌表钉进来的产品根域：检索常常一条都不命中，不能让它被条数排序截掉。"""
    icp_set = extra_icp or set()
    icp_units = icp_units or {}
    icp_rels = icp_rels or {}
    if hits is None:
        # 查询词按质量排序：品牌简称优先（全称带括号会被引擎切字），全称只保留一条作为补充。
        # 探活用最长那条：裸品牌词任何引擎都回得出媒体页，拿它探活会把「只出噪声」的引擎
        # 判成可用，整批词打出去却一条有用结果都没有。
        queries = entity_queries(name)
        engines = await web.pick_engines(max(queries, key=len) if queries else name)
        outcomes = await asyncio.gather(*(web.search(q, engines=engines) for q in queries),
                                        return_exceptions=True)
        hits = []
        for oc in outcomes:
            if isinstance(oc, BaseException) or oc is None:
                continue
            hits.extend(oc.hits)
    by_root: dict[str, list[web.Hit]] = {}
    for h in hits:
        dom = h.domain
        if not dom or _is_noise(dom, name) or _is_platform(dom, name) or not is_valid_domain(dom):
            continue
        by_root.setdefault(root_domain(dom) or dom, []).append(h)

    # 2) 每个候选域并发取证：站点标题 + 自我声明 + 证书
    # 槽位要盖得住一整批候选（池子常在 20 个上下）：给 16 时最后 4 个排到第二批，
    # 每个 8s 的空壳域等于让整轮白等一轮超时。这里探测都是短连接，32 不会压垮出口。
    brand = _brand(name)
    sem = asyncio.Semaphore(32)

    async def _rev_icp(dom: str) -> tuple[str, str]:
        """候选域反查备案主体（域名 → 主体方向），对得上目标就回 (主办单位全称, 关系档)。

        机构类目标（`厦门市特种设备检验检测院`）全称在备案库查不到，官网 xmaj.com 的
        备案却是这家自己 —— 这一跳是唯一能把它认回来的证据。同时也能挡住反向误判：
        `niast.com` 的备案主体是另一家检验院，它就认不进来。
        关系档三档：`self` 就是本主体（行政登记结论）、`family` 同一品牌的兄弟主体
        （集团里另一家登记公司，可按线索计分）、`local` 同群体但不是目标这一家。
        """
        try:
            rev = await passive.miit_reverse_domain(dom)
        except Exception:
            return "", ""
        unit = (rev or {}).get("unit") or ""
        if not unit or not _subject_same(unit, name):
            return "", ""
        if _subject_self(unit, name):
            return unit, "self"
        return unit, "family" if _subject_family(unit, name) else "local"

    async def _probe(dom: str) -> tuple[str, str, set, bool, bool, str, str]:
        root = root_domain(dom) or dom
        async with sem:
            site, cert = await asyncio.gather(
                _site_check(dom, name),
                _cert_brand_hit(dom, _name_keys(name) | _brand_aliases(name)) if brand
                else asyncio.sleep(0),
                return_exceptions=True)
            # 备案那一路已经把「这个域登记在谁名下、与本主体什么关系」查出来了，
            # 不必再打一次反查；这一档带着主办单位全称进打分，机构类目标才认得回自己的官网。
            if root in icp_set:
                rev, rel = icp_units.get(root) or "", icp_rels.get(root) or "self"
            else:
                rev, rel = await _rev_icp(root)
        if isinstance(site, tuple) and len(site) == 3:
            title, subjects, declared = site
        else:
            title, subjects, declared = "", set(), False
        return (root, title, subjects if isinstance(subjects, set) else set(),
                declared is True, cert is True, rev, rel)

    roots = sorted({root_domain(d) or d for d in candidates})
    # 候选池里的平台/下载站/字典/加盟站不浪费一次首页探测：它们进来只会陪跑到末尾
    roots = [r for r in roots if not _is_noise(r, name) and not _is_platform(r, name)]
    # 机构类目标（`厦门市特种设备检验检测院`）的候选池就是一批同行院：标题写的是别家，
    # 官网还常被 WAF 挡成 405 / SPA 空壳。整批丢在这类候选上的噪声，会盖掉它自己那几个
    # 根域。所以这一步只清「标题明确是另一家同行」的；「标题里没出现任何同行全称」的候选
    # 留着，由下面的反查备案定生死。
    if _institution_only(name):
        full = re.sub(r"\s+", "", name)
        roots = [r for r in roots
                 if not any(h.title and _other_institution(h.title, full) for h in by_root.get(r, []))]
    # 逐个打分之前先按结果条数排序并截断：一次企业名检索能召回几百个无关根域，
    # 全跑首页探测 + 证书查询要几分钟，而高分根域基本都落在命中次数最多的前一批里。
    roots.sort(key=lambda r: (-len(by_root.get(r, [])), len(r)))
    # 品牌已知产品根域（`sgcc.com.cn`、`qq.com`）与中文品牌名、拼音都对不上，检索里
    # 往往一条命中都没有，按条数排序必然落到最末，被下面这把刀整片切掉 —— 现场表现是
    # 「候选池里明明预置了官网根域，最后确认域名 0 个」。钉住的这几个保底进池，
    # 截断只作用在其余候选上。
    pin_set = {root_domain(p) or p for p in (pin or ()) if p}
    pinned = [r for r in roots if r in pin_set]
    if pinned:
        kept = [r for r in roots if r not in pin_set]
        roots = pinned + kept[: max(0, _SCORE_TOP - len(pinned))]
    else:
        roots = roots[:_SCORE_TOP]
    probed = await asyncio.gather(*(_probe(r) for r in roots), return_exceptions=True)
    flags: dict[str, tuple[str, set, bool, bool, str, str]] = {}
    for r in probed:
        if isinstance(r, BaseException):
            continue
        flags[r[0]] = (r[1], r[2], r[3], r[4], r[5] if isinstance(r[5], str) else "",
                       r[6] if isinstance(r[6], str) else "")

    out: list[DomainEvidence] = []
    for root in roots:
        hits = by_root.get(root, [])
        title, subjects, declared, cert, rev, rel = flags.get(
            root, ("", set(), False, False, "", ""))
        ev = _score_domain(root, hits, name, declared=declared, icp_hit=rel == "self",
                           cert_hit=cert, site_title=title, subjects=subjects,
                           rev_icp=rev, rev_subject=rev, icp_family=rel == "family")
        out.append(ev)

    # 3) 同根域交叉：`huawei.com` 在标题里自报「华为」，它下面的 `consumer.huawei.com`
    # 就不需要自己再写一遍。只在「上级根域已确认 + 域名确实是它的子域」时补强证据，
    # 弱证据不向下传递（一个误判不该扩散成一整片）。
    confirmed = [e for e in out if e.status == "confirmed"]
    for ev in out:
        root = root_domain(ev.domain) or ev.domain
        parent = next((c for c in confirmed if c.domain != ev.domain and c.domain.endswith("." + root)
                       and ev.domain.endswith("." + c.domain)), None)
        if parent is None:
            continue
        ev.add(W_SUBJECT // 2, f"上级官方域「{parent.domain}」已确认属于该企业（{parent.score} 分）")
        if ev.status == "pending" and ev.score >= CONFIRM_SCORE:
            ev.status = "confirmed"

    out.sort(key=lambda e: e.score, reverse=True)
    return out


# ─────────────── 主流程 ───────────────
def _is_short_pkg(value: str) -> bool:
    """`com.tencent.mm` 这种包名：三段以上、首段是通用前缀，末段不是真 TLD。

    包名会被 `is_valid_domain` 当成合法域，直接当候选下发就等于给流水线塞一个
    永远解析不了的根域，现场表现为「目标里多了一条 com.tencent」。
    """
    parts = (value or "").lower().split(".")
    if len(parts) < 3:
        return False
    return parts[0] in {"com", "cn", "net", "org", "io", "co", "me", "cc", "tv", "app", "xyz"}


async def mobile_leads(names: list[str]) -> dict:
    """品牌词 / 应用名 → App 自有域 + 小程序域 + 开发主体名（全公开、不要 key、不要 AI）。

    单独拎出来给 collect_entity 调：应用商店与小程序里登记的「开发者主体」是域名之外
    最硬的一条主体线索，很多公司只在 Apple 开发者名下写全称，官网上反而没有。
    这里拿到的域与主体名只当**候选**，同样要过证据打分，没过闸的不下发。
    """
    from . import applet as applet_mod
    from . import mobile

    names = [n for n in dict.fromkeys(x.strip() for x in names if x and x.strip())]
    names = [n for n in names if not is_valid_domain(n) and not _is_short_pkg(n)][:3]
    if not names:
        return {"domains": [], "subjects": [], "apps": [], "applets": [], "notes": []}

    async def _apps(n: str):
        try:
            return await mobile.collect_apps(n, limit=6)
        except Exception as e:
            return {"domains": [], "items": [], "notes": [f"App 采集失败 {n}: {str(e)[:60]}"]}

    async def _applets(n: str):
        try:
            # 时限跟着企业主体这一路放宽：默认 25s 只够「名称检索」跑完，主体扩线
            # （拿开发者全称再去查备案）实测要 32～45s，到点交白卷等于小程序这一半
            # 永远空着。这里给 45s，外层 collect_entity 的总预算足够覆盖。
            return await applet_mod.collect_applets(n, limit=6, deadline=45.0)
        except Exception as e:
            return {"domains": [], "items": [], "notes": [f"小程序采集失败 {n}: {str(e)[:60]}"]}

    doms: set[str] = set()
    subjects: list[str] = []
    apps: list[dict] = []
    applets: list[dict] = []
    notes: list[str] = []
    # 每个词内部已经串了商店 + 搜索好几跳，外面再串行就是分钟级；并发跑，结果顺序无关
    results = await asyncio.gather(*[_apps(n) for n in names], *[_applets(n) for n in names],
                                   return_exceptions=True)
    half = len(names)
    for i, res in enumerate(results):
        if isinstance(res, BaseException) or not isinstance(res, dict):
            continue
        for d in res.get("domains") or []:
            d = (d or "").strip().lower()
            if is_valid_domain(d) and not _is_short_pkg(d):
                doms.add(root_domain(d) or d)
        notes.extend(res.get("notes") or [])
        if i < half:
            for ap in res.get("items") or []:
                apps.append(ap)
                dev = (ap.get("developer") or "").strip()
                if dev and re.search(r"(?:公司|集团|有限|股份|工作室|研究院|中心)$", dev):
                    subjects.append(dev)
        else:
            for ap in res.get("items") or []:
                applets.append(ap)
                subj = (ap.get("subject") or "").strip()
                if subj:
                    subjects.append(subj)
    return {"domains": sorted(doms), "subjects": list(dict.fromkeys(subjects))[:6],
            "apps": apps[:12], "applets": applets[:12],
            "notes": list(dict.fromkeys(n for n in notes if n))[:6]}


async def collect_entity(target: str, *, mobile: bool = True,
                         equity_ratio: float | None = None,
                         equity_sources: list[str] | None = None,
                         icp_kinds=("site",), icp_pages: int = 2, icp_size: int = 40,
                         icp_retry: int | None = None, icp_gap: float | None = None,
                         icp_alias: bool = True, icp_force: bool = False,
                         icp_api: str = "", equity: bool = True,
                         on_log=None, on_partial=None,
                         budget_s: float | None = None) -> dict:
    """把用户输入的"公司名/域名"扩成实体信息（含逐域归属证据）

    `mobile=False` 关掉移动端线索那一路：批量跑根域时每个根域都去查一趟应用商店，
    既慢又多半没有结果（商店按名字登记，不按域名）。
    `equity_ratio` 覆盖配置里的控股门槛，给单个任务按需放宽或收紧。
    `equity_sources` 只跑点名的工商来源（aiqicha / tianyancha / icp / backup），留空全开。
    `equity=False` 不跑股权那一路：股权穿透一次就是几十次串行请求，调用方如果后面还会
    单独跑一遍（p1c 阶段、子公司并线），这里再穿一次就是同一份链路跑两三遍。
    `icp_*` 一路透传给备案查询：查哪几类、翻几页、每页多少条、重试、间隔、是否补全称。
    `budget_s` 是本段自己的时间预算：调用方给了硬时限就把它传进来，收尾那几步（兄弟主体
    反查、逐域取证、AI 复核）按剩余时间决定做不做，省得外层到点把协程掐掉、拿到的东西全丢。
    """
    t0 = time.monotonic()

    def _remain() -> float:
        """离预算用光还剩多少秒。没给预算就当作无限（单站直连、接口调用不受影响）。"""
        if not budget_s:
            return 1e9
        return (t0 + float(budget_s)) - time.monotonic()
    info = EntityInfo(name=target, brand=_brand(target))
    # 品牌已知产品主域（`sgcc.com.cn`、`qq.com`）：检索常常一条都不命中，按命中条数排序
    # 会被截掉。这里先取出来，既进候选池，也让中途快照能直接把它当自家域交出去。
    own_known = _own_roots_of(target)
    notes: list[str] = []

    def _say(msg: str, level: str = "info") -> None:
        # 这一段单跑就是几分钟：原来只每 30 秒报一次「还在跑」，人看不出在查哪一路。
        # 每路一回来就报一行，实时过程里能直接看到命中条数。
        if on_log is None:
            return
        try:
            on_log(str(msg), level)
        except Exception:
            pass

    # 中途快照里「已经过完证据闸」的两列：走到第 7 步才有，之前为空。
    snap: dict = {}

    def _publish() -> None:
        """把此刻已经查到的部分交出去。

        整段流程里光是股权穿透一段就能跑掉几分钟，外层硬时限一到就把协程掐了，
        已经查到的备案、控股子公司、移动端主体全在局部变量里跟着消失（现场表现是
        「股权穿透 33 家」「备案 43 条」都打了日志，任务最后 0 资产）。这里按里程碑
        交快照，外层超时后照样能入库。
        确认域只认备案登记在目标自己名下的那批，其余进待核验，不越证据闸。
        """
        if on_partial is None:
            return
        try:
            own = {d for d in domains if icp_rels.get(d) == "self"}
            own |= set(snap.get("domains") or ())
            # 品牌表钉住的主域不必等取证闸：它们不是检索召回的结果，含金量本来就由表决定。
            own |= own_known
            rest = sorted(d for d in info.domains if is_valid_domain(d))
            pend = [d for d in rest if d not in own]
            pend += [d for d in (snap.get("domains_pending") or ()) if d not in own
                     and d not in pend]
            on_partial({
                "name": info.name, "brand": info.brand,
                "aliases": list(info.aliases),
                "domains": sorted(own),
                "domains_pending": pend,
                "evidence": dict(info.evidence),
                "apps": list(info.apps), "applets": list(info.applets),
                "mobile_apps": list(mob.get("apps") or []),
                "mobile_applets": list(mob.get("applets") or []),
                "icp": list(info.icp),
                "equity": list(info.equity),
                "equity_relation": dict(info.equity_relation),
                "equity_detail": dict(info.equity_detail),
                "sources": list(info.sources),
                "notes": list(notes),
                "source_status": dict(LAST_STATUS),
                "partial": True,
            })
        except Exception:
            pass

    domains: set[str] = set()
    # 候选根域池先摆好：备案那一路一回来就要往里加，不能等 `await side` 之后才建。
    cands: set[str] = set()
    icp_set: set[str] = set()
    # 候选根域 → 备案主办单位全称：备案那一路查到的主体名要跟着域一起进打分，
    # 不然机构类目标看不出「这个域就是登记在它自己名下」。
    icp_units: dict[str, str] = {}
    # 候选根域 → 备案主体与本主体的关系（self / family）。兄弟主体不能给确认级结论，
    # 但要能进候选池，否则集团的主干站永远排在打分类候选后面。
    icp_rels: dict[str, str] = {}
    # 每轮清空渠道留痕：LAST_STATUS 是模块级的，不清理会把上一个主体的
    # 「可用/失效」带进这一次任务的渠道面板。
    LAST_STATUS.clear()
    # 移动端线索的默认形状先摆好：中途快照要在这一路还没回来时就读它。
    mob: dict = {"domains": [], "subjects": [], "apps": [], "applets": [], "notes": []}
    # 全资子公司名：备案兜底与「一路都没命中」时继续扩面用，所以要留到合并之后。
    owned_subs: list[str] = []
    is_domain = is_valid_domain(target.replace(" ", ""))

    if is_domain:
        info.domains.add(target.lower())
        root = root_domain(target) or target
        info.domains.add(root)
        icp = await icp_by_domain(root, pages=icp_pages, size=icp_size,
                                  retry=icp_retry, gap=icp_gap,
                                  force=icp_force, miit_api=icp_api)
        info.icp.extend(icp)
        for item in icp:
            if item.get("unit"):
                info.name = item["unit"]
                info.sources.append("icp")
        info.evidence[root] = DomainEvidence(domain=root, score=100, status="confirmed",
                                             reasons=["用户直接指定的域名"]).as_dict()
        return {
            "name": info.name, "brand": info.brand, "aliases": [], "apps": [], "applets": [],
            "domains": sorted(d for d in info.domains if is_valid_domain(d)),
            "domains_pending": [],
            "evidence": info.evidence, "icp": info.icp, "sources": info.sources, "notes": notes,
            "source_status": dict(LAST_STATUS),
        }

    info.name = target
    # 1) ICP 备案 + 工商股权；同时开搜索。三者互不依赖，串行会把 60s 拉到两分多钟。
    async def _rows(fn, tag: str, *args):
        try:
            return tag, await fn(target, *args)
        except Exception as e:
            return tag, e

    # 备案这一路额外带一份域名猜测当 `declared`：主体全称对不上备案库时，
    # 先用猜测根域反查出备案登记的全称，再用全称翻页，比单靠全称硬查命中率高得多。
    async def _icp_rows():
        try:
            return "icp_company", await icp_by_company(
                target, declared=_domain_guesses(target), kinds=icp_kinds,
                pages=icp_pages, size=icp_size, retry=icp_retry, gap=icp_gap,
                alias=icp_alias, force=icp_force, miit_api=icp_api)
        except Exception as e:
            return "icp_company", e

    icp_merged = [False]

    def _apply_icp(rows: list) -> None:
        """把备案结果并进主体：候选根域、自家根域标记、兄弟/外部主体留档。

        这段原来只写在 `await side` 之后。股权一路按 30 秒间隔穿子公司要跑几十分钟，
        备案十几秒就回来了也得在原地等着，快照里就始终没有域名；外层时限一落在股权段
        上，任务页看到的就只有主体行。现在备案一回来就并、就交快照。
        """
        icp_merged[0] = True
        if not rows:
            why = _icp_empty_reason(target)
            if why:
                notes.append(why)
            return
        # 企业名这条线查到的每一条备案都要留在 `info.icp` 里。以前这里只把合法域名
        # 拆成候选域，公益域、APP/小程序类备案（它们的 domain 不是合法域名）直接被丢掉，
        # 结果就是用了备案号的主体反而「一条 ICP 都没有」。
        seen = {(_icp_key(x)) for x in info.icp}
        for item in rows:
            k = _icp_key(item)
            if not k or k in seen:
                continue
            seen.add(k)
            info.icp.append(dict(item))
        foreign_icp: list[dict] = []
        family_icp: list[dict] = []
        for item in rows:
            if item.get("owner_match") is False:
                # 主办单位不是目标主体：留档展示，但不进候选域 / 扩展链
                foreign_icp.append(dict(item))
                continue
            if str(item.get("relation") or "self") == "family":
                family_icp.append(dict(item))
            dom = item.get("domain", "")
            if is_valid_domain(dom):
                r = root_domain(dom) or dom
                domains.add(r)
                icp_set.add(r)
                icp_units.setdefault(r, item.get("unit") or "")
                icp_rels.setdefault(r, str(item.get("relation") or "self"))
                cands.add(r)
                info.domains.add(dom)
                info.domains.add(r)
        if family_icp:
            # 兄弟主体名下的备案不是本主体的行政登记结论，但也绝不是第三方：
            # 集团官网就登记在区域公司名下。列档 + 进候选池，打分按线索档给。
            host = "、".join(sorted({(x.get("domain") or x.get("app") or "") for x in family_icp})[:4])
            unit = next((x.get("unit") for x in family_icp if x.get("unit")), "")
            notes.append(f"同品牌兄弟主体「{unit}」名下有 {len(family_icp)} 条备案（{host} 等），"
                         f"按集团内线索进候选池")
        if foreign_icp:
            host = "、".join(sorted({(x.get("domain") or x.get("app") or "") for x in foreign_icp})[:4])
            unit = next((x.get("unit") for x in foreign_icp if x.get("unit")), "")
            notes.append(f"备案主办单位非本主体的 {len(foreign_icp)} 条（{host} 登记在「{unit}」）"
                         f"只列档，未当候选域扩展")
        if "icp_company" not in info.sources:
            info.sources.append("icp_company")

    async def _watch_icp():
        tag, rows = await _icp_rows()
        if isinstance(rows, BaseException):
            _say(f"备案查询失败：{str(rows)[:60]}", "warn")
            return tag, rows
        rows = rows or []
        own = sum(1 for x in rows if isinstance(x, dict) and x.get("owner_match") is not False)
        _say(f"备案：{len(rows)} 条（主办单位对得上 {own} 条）")
        try:
            _apply_icp(rows)
        except Exception as e:
            notes.append(f"备案合并异常：{str(e)[:60]}")
        else:
            # 备案一批就交一批：域名、自家根域标记都在快照里了，后面的被动收集能开工。
            _publish()
        return tag, rows

    async def _watch_equity():
        # 逐层穿子公司是几十次串行请求，整段能跑十几分钟。链路一边长一边交回来：
        # 每收到一批就更新主体上的股权明细并对外发布快照，外层边收边入库，任务页的
        # 穿透图在中途就能看到已经穿到的那些主体，不用等整段跑完（也不会因为超时全丢）。
        seen_n = [0]

        def _on_part(detail: dict) -> None:
            if not isinstance(detail, dict) or not detail.get("chain"):
                return
            from . import equity as _equity_mod
            try:
                part_ratio = float(detail.get("ratio") or equity_ratio or 100)
            except (TypeError, ValueError):
                part_ratio = 100.0
            info.equity_detail = detail
            subs = _equity_mod.full_owned_children(
                target, detail.get("chain") or [], ratio=part_ratio)
            info.equity = subs[:12]
            try:
                rel = _equity_mod.Equities(
                    name=str(detail.get("name") or target),
                    chain=detail.get("chain") or [], ratio=part_ratio).relation
                info.equity_relation = {k: v for k, v in rel.items() if k in info.equity}
            except Exception:
                pass
            snap["equity_detail"] = dict(detail)
            _publish()
            n = len(detail.get("chain") or [])
            if n - seen_n[0] >= 20:
                seen_n[0] = n
                _say(f"股权穿透进行中：链路已到 {n} 个节点（边穿边入库）")

        tag, res = await _rows(lambda n, r: _equity_detail(n, r, sources=equity_sources,
                                                          on_progress=_say,
                                                          on_partial=_on_part),
                               "equity", equity_ratio)
        if isinstance(res, BaseException):
            _say(f"股权穿透失败：{str(res)[:60]}", "warn")
            return tag, res
        # 每一路工商来源各自报一行：额度用尽 / 被风控 / 只是超时，实时过程里当场分得清，
        # 不用等整段跑完再去翻渠道面板，也不会把额度问题当成「这家没子公司」。
        try:
            from .. import source_health as _health
            from . import equity as _equity_mod

            for key, st in (_equity_mod.LAST_STATUS or {}).items():
                if not st or st == "ok":
                    continue
                _say(f"股权来源 {_health.label_source(key)}：{_health.text_of(st) or st}", "warn")
        except Exception:
            pass
        subs = res[0] if isinstance(res, tuple) and res else res
        n = len([s for s in (subs or []) if isinstance(s, str)])
        chain_n = 0
        if isinstance(res, tuple) and len(res) > 2 and isinstance(res[2], dict):
            chain_n = len(res[2].get("chain") or [])
        _say(f"股权穿透：{n} 家达到控股门槛 / 链路 {chain_n} 条（一起入资产）")
        return tag, res

    # 先把已知的自家主域交出去。股权那一路一次穿透就是几十分钟，而域名要等第 7 步
    # 取证闸走完才写进快照；外层时限一到，快照里就只剩主体行，任务页看到的是
    # 「主体收集做完了，域名 0 个」。品牌表钉住的主域不依赖检索命中，这里先落一份，
    # 后面的被动收集 / 爆破 / 端口至少有一批根可以开工。
    if own_known:
        # 品牌表钉住的主域不依赖检索命中：既进候选池，也立刻交一份快照，
        # 后面的被动收集 / 爆破 / 端口至少有一批根可以开工。
        cands |= own_known
        _say(f"按品牌已知主域预置候选：{'、'.join(sorted(own_known))}")
        _publish()

    side_tasks = [_watch_icp()]
    if equity:
        side_tasks.append(_watch_equity())
    side = asyncio.gather(*side_tasks, return_exceptions=True)
    # 移动端线索也跟着一起开：应用商店 / 小程序的开发者主体名只有这条线拿得到
    mob_task = asyncio.create_task(mobile_leads([info.brand or target, target])) if mobile else None

    # 2) 搜索候选（无论 ICP 有没有结果都跑：ICP 只给备案域，搜索引擎能带出品牌域）
    #    查询词用品牌简称打头：带括号的全称会让引擎按单字切词，召回一堆字典站。
    #    已知品牌主域已在上面并进 `cands`：这类官网根域与中文品牌名、拼音都对不上
    #    （`qq.com`、`sgcc.com.cn`），只靠搜索引擎召不回来就整轮没有可扩的根。
    hits: list = []
    # 搜索与 ICP/工商同时开：三路互不依赖，串行会让首屏多等十几秒。
    searches = asyncio.create_task(_search_roots(target))
    try:
        roots, hits, s_notes = await searches
        cands |= roots
        notes.extend(s_notes)
        if roots:
            info.sources.append("search")
        _say(f"搜索引擎：命中 {len(roots)} 个候选根域")
        # `_search_roots` 只回「命中品牌词」的那几个根域，而真官网友时只在条目域名上
        # 出现、标题不写品牌。命中的根域全部入池，归属交给后面的取证打分定，
        # 不在候选阶段凭域名先杀掉。
        cands |= _hit_roots(hits, target)
    except Exception as e:
        notes.append(f"search 异常：{str(e)[:60]}")

    # 品牌名本身当域名试一把：瑞幸 → lkcoffee 猜不到，但「华为 → huawei.com」这类直译经常对
    for g in _domain_guesses(target):
        cands.add(g)

    for tag, rows in await side:
        if isinstance(rows, BaseException):
            notes.append(f"{tag} 异常：{str(rows)[:60]}")
            continue
        if tag == "icp_company":
            # 备案在 `_watch_icp` 里已经并进主体并交过快照（含空结果原因），这里只做兜底：
            # 那一路若在合并前异常退出，用已拿到的行补一次。
            if rows and not icp_merged[0]:
                _apply_icp(rows)
                _publish()
            continue
        if not rows:
            continue
        if tag == "equity":
            # 股权链路给的是主体名（达到控股门槛的子公司），一个也不是域名，不能进上面按 domain 取值的分支
            vals = rows if isinstance(rows, tuple) else (rows,)
            owned_subs = [str(n) for n in (vals[0] if vals else []) if isinstance(n, str)]
            owned_rel = vals[1] if len(vals) > 1 and isinstance(vals[1], dict) else {}
            # 链路本体同时留下：控股 / 投资 / 股东 / 分支 / 软著这些行要按它摊，
            # 任务页的股权穿透图也读它。只留名字等于查完就扔，任务资产只剩几条。
            if len(vals) > 2 and isinstance(vals[2], dict):
                info.equity_detail = vals[2]
                snap["equity_detail"] = dict(vals[2])
            info.equity = owned_subs[:12]
            if isinstance(owned_rel, dict):
                info.equity_relation = {k: v for k, v in owned_rel.items() if k in owned_subs[:12]}
            continue

    notes.extend(_equity_note(owned_subs))
    # 备案 + 工商股权这两路都回来了：这是整段流程最贵的一段，先交一份快照。
    _publish()
    _say(f"主体合计：备案 {len(info.icp)} 条 / 控股 {len(owned_subs)} 家 / "
         f"候选域 {len(cands)} 个")

    # 3) 一个候选都没有：让 AI 猜（猜出来的同样要过打分闸，不直接下发）
    guessed: list[str] = []
    if not cands:
        from ..ai import guess_domains

        try:
            guessed = await guess_domains(target)
        except Exception as e:
            notes.append(f"ai 异常：{str(e)[:60]}")
        if guessed:
            cands |= {root_domain(d) or d for d in guessed if is_valid_domain(d)}
            info.sources.append("ai_guess")

    # 3b) 移动端线索：应用商店里的开发者站、小程序落地页域、开发者主体全称
    if mob_task is not None:
        try:
            mob = await mob_task
        except Exception as e:
            notes.append(f"移动端线索异常：{str(e)[:60]}")
        for d in mob.get("domains") or []:
            cands.add(d)
        if mob.get("domains"):
            info.sources.append("mobile")
        _say(f"移动端：{len(mob.get('domains') or [])} 个域 / "
             f"{len(mob.get('subjects') or [])} 个开发主体")
        # 开发者主体名再补一次搜索：Apple / 应用宝上登记的是公司全称，
        # 官网上往往只写品牌，这条 getName 到浏览器标题对不上的候选全靠它捞回来
        extra = [s for s in mob.get("subjects") or [] if s != target][:2]
        if extra:
            try:
                more, more_hits, more_notes = await _search_roots(extra[0])
                cands |= more
                hits.extend(more_hits)
                notes.extend(n for n in more_notes if n not in notes)
                if more:
                    info.sources.append("mobile_subject")
            except Exception as e:
                notes.append(f"移动端主体搜索异常：{str(e)[:60]}")
        notes.extend(f"移动端：{n}" for n in (mob.get("notes") or [])[:3])
    _publish()

    # 3c) 备案与搜索都没给出候选：按全资子公司名再反查一次公开备案。
    #     母公司域名常挂在子公司名下（品牌主体只做管理、实际备案在运营公司），
    #     这条兜底能在「主体名查不到备案」时不至于空手。
    if not cands and owned_subs:
        rows = []
        # 这一步是兜底：反查接口慢起来能挂好几分钟，主目标结果已经拿到，不能让它拖死整段。
        cap = min(45.0, _remain() - 10)
        if cap < 5:
            notes.append("时间预算不够，子公司备案反查已跳过")
        else:
            try:
                rows = await asyncio.wait_for(
                    icp_by_company(owned_subs[0], declared=list(cands)[:3]), cap)
            except asyncio.TimeoutError:
                notes.append(f"子公司备案反查超过 {int(cap)}s 未返回，已跳过")
            except Exception as e:
                notes.append(f"子公司备案反查异常：{str(e)[:60]}")
        for row in rows:
            if row.get("owner_match") is False:
                continue
            d = row.get("domain") or ""
            r = root_domain(d) or d
            if is_valid_domain(r):
                cands.add(r)
        if rows:
            info.sources.append("icp_equity")
            notes.append(f"按全资子公司「{owned_subs[0]}」的备案反查补到 {len({root_domain(x.get('domain') or '') or x.get('domain') for x in rows})} 个候选域")

    # 3d) 本主体名下的网站备案很薄（0 条，或只有一两条撑不起整片资产）时，
    #     顺着候选域反查到的登记主体再扩一圈。
    #     集团的品牌站常整片登记在区域公司名下（`luckincoffee.com` 的主办单位是北京公司，
    #     任务查的却是中国公司），本主体在备案库里只剩 APP / 小程序备案。反查候选域能拿到
    #     真实登记主体全称，再按这个全称列出它名下全部网站备案，整片自家域才进得来 ——
    #     这就是「企业主体搜集不全」在企业名下网站备案薄时的正解。
    #     以前只在「一条网站备案都没有」时才做、且第一家补到就 break，判据一薄就锁死
    #     在第一批兄弟主体上，剩下的整片域再也进不来。现在按「薄」判、串行扩到 4 家、
    #     把补到的兄弟主体继续排队（最多 4 家），补满 12 个域就收，备案接口按出口 IP 频控。
    site_icp_n = sum(1 for x in info.icp if str(x.get("kind") or "site") == "site")
    if site_icp_n < 2 and cands and _remain() > 90:
        # 这一段是串行反查（一家一家查备案）＋ 反查页，最慢的一段。
        # 整段用剩余预算的七成：到点就停在已经补到的域上，别把整个主体扩线一起拖超时。
        t3d = time.monotonic()
        cap_rev = min(60.0, _remain() - 45)
        cap_exp = min(120.0, _remain() - 15)
        hit_cnt: dict[str, int] = {}
        for h in hits:
            cnt_root = root_domain(getattr(h, "domain", "") or "")
            if cnt_root:
                hit_cnt[cnt_root] = hit_cnt.get(cnt_root, 0) + 1
        # 先探命中次数最多的几个：噪声域排在后面，反查也轮不到它们
        order = sorted(cands, key=lambda d: (-hit_cnt.get(d, 0), len(d)))[:8]
        queue: list[str] = []
        for cand in order:
            if time.monotonic() - t3d > cap_rev:
                notes.append(f"候选域反查登记主体超过 {int(cap_rev)}s，剩余候选已跳过")
                break
            try:
                rev = await asyncio.wait_for(passive.miit_reverse_domain(cand), 20)
            except Exception:
                continue
            unit = (rev or {}).get("unit") or ""
            if unit and unit not in queue and _subject_family(unit, target):
                queue.append(unit)
            if len(queue) >= 3:
                break
        tried: set[str] = set()
        grown = 0
        # 跨主体去重：多家登记主体名下会挂着同一条网站备案，逐家重建集合就会重复堆进来。
        seen_icp = {_icp_key(x) for x in info.icp}
        while queue and len(tried) < 4 and grown < 12:
            if time.monotonic() - t3d > cap_exp:
                notes.append(f"兄弟主体备案扩查超过 {int(cap_exp)}s，剩下 {'、'.join(queue[:3])} 没查")
                break
            unit = queue.pop(0)
            if unit in tried:
                continue
            tried.add(unit)
            try:
                # declared 传空：这里要查的就是刚反查出来的这家登记主体本身，
                # 带上候选域会让内部先把候选域反查到的另一家插到队首，查成别人名下。
                rows = await asyncio.wait_for(
                    icp_by_company(unit, declared=[], kinds=("site",), pages=2,
                                   retry=icp_retry, gap=icp_gap), 40)
            except asyncio.TimeoutError:
                notes.append(f"兄弟主体「{unit}」备案扩查超过 40s，已跳过")
                continue
            except Exception as e:
                notes.append(f"兄弟主体「{unit}」备案扩查异常：{str(e)[:60]}")
                continue
            added = 0
            for row in rows:
                if row.get("owner_match") is False:
                    continue
                # 兄弟主体名下还会挂着别的同品牌登记单位，继续排队（总部 → 区域 → 城市）
                ru = (row.get("unit") or "").strip()
                if ru and ru not in queue and ru not in tried and _subject_family(ru, target):
                    queue.append(ru)
                d = row.get("domain") or ""
                r = root_domain(d) or d
                if not is_valid_domain(r):
                    continue
                # 兄弟主体名下这些网站备案是这批域的来源，都要进备案清单：
                # 以前只把域并进候选池，ICP 列表里仍是本主体那三条 APP 备案，
                # 人看到的备案数和域名数对不上，像是漏查。
                k = _icp_key(row)
                if k and k not in seen_icp:
                    seen_icp.add(k)
                    info.icp.append(dict(row))
                rel = "self" if _subject_self(row.get("unit") or unit, target) else "family"
                if icp_rels.get(r) != "self":
                    icp_rels[r] = rel
                icp_units.setdefault(r, row.get("unit") or unit)
                icp_set.add(r)
                info.domains.add(d)
                info.domains.add(r)
                if r not in cands:
                    cands.add(r)
                    domains.add(r)
                    added += 1
            if added:
                grown += added
                notes.append(f"本主体名下网站备案薄（{site_icp_n} 条）；按候选域反查到同品牌登记主体"
                             f"「{unit}」，它名下补到 {added} 个自家域（按集团内线索计分）")
                if "icp_family" not in info.sources:
                    info.sources.append("icp_family")
        if grown:
            notes.append(f"同品牌兄弟主体一共补到 {grown} 个自家域（查了 {len(tried)} 家登记主体）")

    # 4) 去活闸（死域不浪费打分时间）
    # 备案的 `domain` 字段什么都可能装：IP、带中文标签的主域名、公司名拼后缀。
    # 这些进候选池只会占掉取证时间，还会被当成「自家根域」在后续阶段扩线。
    cand_list = sorted(d for d in cands if is_valid_domain(d) and not IP_RE.match(d))
    junk = sorted(set(cands) - set(cand_list))
    if junk:
        notes.append(f"{len(junk)} 个备案值不是可用域名已剔除：{'、'.join(junk[:4])}")
    if cand_list:
        _say(f"去活：{len(cand_list)} 个候选域逐个探活")
        alive = await asyncio.gather(*(_domain_alive(d) for d in cand_list))
        live = [d for d, ok in zip(cand_list, alive) if ok]
        dead = [d for d, ok in zip(cand_list, alive) if not ok]
        # 备案登记在目标自己名下的域，当前没有 A 记录也要留：备案主体是强归属证据
        # （域历史上就属于它），停解析只是眼下没站点，不等于「不是它的域」。
        # 以前一律按无解析剔除，现场表现是「备案都查到域了，候选池却只剩下一个」。
        keep_icp = [d for d in dead if d in icp_set]
        # 品牌已知主域（`_OWN_ROOTS`）同理，而且更要留：省公司的站全挂在
        # `www.fj.sgcc.com.cn`、`www.hk.sgcc.com.cn` 这类子域上，根域和 `www` 都没有 A
        # 记录（内网解析），去活闸一剔，真实主域就永远进不了被动 / 测绘，只剩备案里
        # 那条中文域名。这里只放行人工维护的品牌主域，不会把搜索召回的门户站捞回来。
        keep_brand = [d for d in dead
                      if d not in icp_set and (root_domain(d) or d) in own_known]
        keep = keep_icp + keep_brand
        dead = [d for d in dead if d not in keep]
        cand_list = live + keep
        if dead:
            notes.append(f"{len(dead)} 个候选域无解析已剔除：{'、'.join(dead[:4])}")
        if keep_icp:
            notes.append(f"{len(keep_icp)} 个候选域当前无解析但备案在目标名下，已保留取证："
                         f"{'、'.join(keep_icp[:4])}")
        if keep_brand:
            notes.append(f"{len(keep_brand)} 个候选域当前无解析但属品牌已知主域，已保留取证"
                         f"（站点可能只挂在子域上）：{'、'.join(keep_brand[:4])}")
        if guessed:
            survived = [d for d in cand_list if d in {root_domain(g) or g for g in guessed}]
            if not survived:
                notes.append("AI 猜测的域名都不解析，已放弃")

    # 5) 逐域取证打分
    #    备案主办单位就是目标主体的那些候选，归属是行政登记结论，不需要再抓首页/证书：
    #    直接按确认下发，把时间全部让给「只有搜索线索」的候选。
    #    以前一律走证据闸，候选一多就整段撞超时，现场表现是「确认 0 个域、待核验几十个」。
    evs: list[DomainEvidence] = []
    if cand_list:
        pre_set = {d for d in cand_list
                   if str(icp_rels.get(d) or "") == "self"
                   and not _is_noise(d, target) and not _is_platform(d, target)}
        rest = [d for d in cand_list if d not in pre_set]
        for d in sorted(pre_set):
            evs.append(DomainEvidence(
                domain=d, score=CONFIRM_SCORE, status="confirmed",
                reasons=[f"备案主办单位即目标主体（{icp_units.get(d) or target}）"]))
        if pre_set:
            _say(f"备案直认：{len(pre_set)} 个候选域的主办单位就是目标主体")
        if pre_set or rest:
            # 取证还没跑完就先交一版快照。外层硬时限一到协程被掐，这一刻的确认域和
            # 还没取证的候选域都在局部变量里，快照只剩更早那个里程碑的两列空值 ——
            # 现场表现是「备案直认了 2 个域，界面仍只有确认 1 个、待核验 0 个」。
            snap["domains"] = sorted(pre_set)
            snap["domains_pending"] = sorted(rest)
            _publish()
        if rest:
            # 每个候选域都要抓一遍首页 + 证书，32 并发，一批约 10s；下限 60s，
            # 别让它塌成「勉强一批」，那等于把整批候选白白降级成待核验。
            cap_ev = min(240.0, max(60.0, 15.0 + (len(rest) / 32.0 + 1) * 12.0))
            if budget_s:
                cap_ev = min(cap_ev, max(45.0, _remain() - 12))
            _say(f"逐域取证：{len(rest)} 个候选逐个抓首页 + 证书（上限 {int(cap_ev)}s）")
            try:
                evs.extend(await asyncio.wait_for(
                    domain_evidence(target, rest, extra_icp=icp_set,
                                    icp_units=icp_units, icp_rels=icp_rels, hits=hits,
                                    pin=own_known), cap_ev))
            except asyncio.TimeoutError:
                notes.append(f"逐域取证超过 {int(cap_ev)}s 未跑完，{len(rest)} 个弱线索候选按待核验下发")
                evs.extend(DomainEvidence(domain=d, score=PENDING_SCORE, status="pending",
                                          reasons=["取证超时，按待核验下发"]) for d in rest)
            except Exception as e:
                notes.append(f"打分异常：{str(e)[:80]}")
                evs.extend(DomainEvidence(domain=d, score=PENDING_SCORE, status="pending",
                                          reasons=["打分失败，按待核验下发"]) for d in rest)

    # 6) 低分段交 AI 复核（没有 key 时直接跳过，不影响任何结果）
    low = [e for e in evs if e.status == "pending"]
    if low and _remain() > 25:
        try:
            from ..ai import judge_domains

            _say(f"低分段交 AI 复核：{min(len(low), 8)} 个待核验域")
            verdict = await asyncio.wait_for(
                judge_domains(target, [e.domain for e in low[:8]], notes_hint=info.brand),
                max(12.0, min(45.0, _remain() - 3)))
            for e in low:
                v = verdict.get(e.domain)
                if not v:
                    continue
                if v.get("belong") is True:
                    e.status = "confirmed"
                    e.add(5, f"AI 复核判定属于该主体：{str(v.get('why') or '')[:40]}")
                elif v.get("belong") is False:
                    e.status = "rejected"
                    e.add(-100, f"AI 复核判定不属于该主体：{str(v.get('why') or '')[:40]}")
        except Exception:
            pass  # AI 不可用 = 维持规则判定

    # 7) 汇总：只有确认域进入收集链；待核验域只记账给人看，不给流水线当种子
    #    （待核验放进 domains 会被后面所有阶段当目标继续扩，一条弱证据能带出一整片别人的资产）
    for e in evs:
        info.evidence[e.domain] = e.as_dict()
    confirmed = [e.domain for e in evs if e.status == "confirmed"]
    pending = [e.domain for e in evs if e.status == "pending"]
    rejected = [e.domain for e in evs if e.status == "rejected"]
    for d in confirmed:
        info.domains.add(d)
        info.domains.add(root_domain(d) or d)
    if confirmed:
        info.sources.append("evidence")
    if pending:
        notes.append(f"{'、'.join(pending[:6])} 证据不足（已标待核验）："
                     f"{'；'.join(pending_reason(evs, pending)[:3])}")
    if rejected:
        notes.append(f"{len(rejected)} 个候选因证据不足丢弃：{'、'.join(rejected[:6])}")
    _say(f"取证：确认 {len(confirmed)} 个域 / 待核验 {len(pending)} 个 / 丢弃 {len(rejected)} 个")
    # 只会认回中文域名时，下游被动收集基本拿不到子域（证书里几乎不出现 punycode 根），
    # 任务会以「done 100%」收场却几乎没有资产。这里当场点明，免得看着像整轮没干活。
    if confirmed and all(any(label.startswith("xn--") for label in d.split(".")) for d in confirmed):
        _say("确认域只有中文域名（punycode），这类根通常没有子域、被动收集会空跑；"
             "建议核对真实主域后手工补入", "warn")
    _publish()

    # 7b) 主域清单只放确认域。待核验域以前和确认域混在同一个 `domains` 里，下游把它当
    #     自家根去扩线，弱证据（站点标题「页面不存在」、只挂一条备案的壳域）就整片打偏。
    #     现在拆两列：`domains` 进收集链，`domains_pending` 只列档给人看，复核后可单跑补。
    pend_set = set(pending)
    conf_roots = {root_domain(d) or d for d in confirmed}
    pend_roots = {root_domain(d) or d for d in pend_set} - conf_roots
    domains_all = sorted(d for d in info.domains
                         if is_valid_domain(d) and not IP_RE.match(d))
    domains_ok = [d for d in domains_all
                  if d not in pend_set and (root_domain(d) or d) not in pend_roots]
    # 待核验这一列要包含证据闸判 pending 的根域本身。它们从来没进过 `info.domains`，
    # 只从 `info.domains` 里反筛的话这一列恒为空 —— 界面就只剩「确认 1 个」，
    # 看起来像整轮只搜到一个域，其实另外几个是被证据闸挡下来的（有分数和原因）。
    domains_maybe = sorted(pend_roots | {d for d in domains_all if d not in domains_ok})
    # 最后一道网：平台 / 黄页根域从别的分支（先验收到的子域、AI 猜测、股权域名）混进来时，
    # 也不许进采集链。按本主体名判，目标是平台自己时 `_is_platform` 会放行。
    platform_drop = [d for d in domains_ok
                     if _is_platform(d, info.name) or _is_noise(d, info.name)]
    if platform_drop:
        domains_ok = [d for d in domains_ok if d not in platform_drop]
        domains_maybe = sorted(set(domains_maybe) | set(platform_drop))
        notes.append(f"{len(platform_drop)} 个平台/黄页根域已拦下（不当自家根扩线）："
                     f"{'、'.join(platform_drop[:6])}")
    if domains_maybe:
        notes.append(f"{len(domains_maybe)} 个待核验域没有并入主域清单（不当自家根扩线）："
                     f"{'、'.join(domains_maybe[:8])}")
    # 证据闸已经过完：主域清单从这里起就是最终那两列，后面的增强段掐掉也不影响它们。
    snap["domains"] = list(domains_ok)
    snap["domains_pending"] = list(domains_maybe)
    _publish()

    # 8) 新媒体 / AI 别名扩展（纯增强，失败不影响主结果）
    #    两路都是「加线索」，互不依赖：串行跑等于在首屏末尾白排两轮等待。
    async def _media() -> list[str]:
        return await new_media_search(target)

    async def _ai() -> dict:
        return await ai_expand(target)

    _say("补新媒体 / AI 别名扩展")
    try:
        # 这一段是纯增强：AI 中转站慢起来能挂住整段，主结果早已拿到，不能让它拖死首屏。
        media, ai = await asyncio.wait_for(
            asyncio.gather(_media(), _ai(), return_exceptions=True), 60)
    except asyncio.TimeoutError:
        media, ai = None, None
        notes.append("新媒体 / AI 别名扩展超过 60s 未返回，已跳过（主结果不受影响）")
    if isinstance(media, list) and media:
        info.applets = media
        info.sources.append("newmedia")
    if isinstance(ai, dict) and ai:
        info.aliases = [a for a in (ai.get("aliases") or []) if isinstance(a, str)][:10]
        info.apps += [a for a in (ai.get("apps") or []) if isinstance(a, str)][:10]
        info.sources.append("ai")
        # AI 给的关键词只当线索，不当域名直接下发：不走证据闸的外来域正是打偏的来源
        info.aliases += [k for k in (ai.get("keywords") or [])
                         if isinstance(k, str) and not is_valid_domain(k)][:5]

    return {
        "name": info.name,
        "brand": info.brand,
        "aliases": info.aliases,
        "domains": domains_ok,
        "domains_pending": domains_maybe,
        "evidence": info.evidence,
        "mobile_apps": mob.get("apps") or [],
        "mobile_applets": mob.get("applets") or [],
        "apps": info.apps,
        "applets": info.applets,
        "icp": info.icp,
        "equity": info.equity,
        "equity_relation": info.equity_relation,
        "equity_detail": info.equity_detail,
        "sources": info.sources,
        "notes": notes,
        "source_status": dict(LAST_STATUS),
    }


def pending_reason(evs: list[DomainEvidence], pending: list[str]) -> list[str]:
    out = []
    for e in evs:
        if e.domain in pending:
            out.append(f"{e.domain} 得 {e.score} 分（{e.reasons[0] if e.reasons else '仅搜索出现'}）")
    return out


async def expand_sub_company(name: str, *, ratio: float | None = None, depth: int = 2,
                             ubo_threshold: float | None = None,
                             ubo_levels: int | None = None,
                             branches: bool = True,
                             sources: list[str] | None = None,
                             gap: float | None = None,
                             retry: int | None = None) -> list[str]:
    """达标子公司名：走工商股权链路，累计持股达到配置门槛（默认 100% 全资）才算、才入池。

    `depth` 往下追几层、`ratio` 持股门槛、`ubo_threshold`/`ubo_levels` 实控人穿透，
    都由单项执行表单给；不填就走配置默认值。`branches` 控制是否查分支机构，
    `sources` 控制只跑哪几路工商来源，留空全开。
    """
    try:
        return sorted(set(await _equity_names(name, ratio, depth,
                                              ubo_threshold=ubo_threshold,
                                              ubo_levels=ubo_levels,
                                              branches=branches, sources=sources,
                                              gap=gap, retry=retry)))
    except Exception:
        return []
