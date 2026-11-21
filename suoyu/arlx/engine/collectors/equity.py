"""股权穿透与主体画像：投资链路（深度 + 持股比例）、股东、分支机构、软著。

目的：把「全资控股闸」从人工判断变成可计算的数据。

* ``hold >= 100`` 的链路才算本集团资产，参股 / 联营默认不进挖掘池。
* 每条链路带 ``depth``（几级）和 ``ratio``（累计持股比例，逐级相乘）。
* 采集来源按可用性降级，缺哪个都不阻塞：
  内置备案引擎（按母子公司名继续反查）→ 公开工商接口（需登录态）→ 空结果并说明原因。

数据只用于「要不要把这个主体算进资产」，不产生报告内容。
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from ...config import config
from .. import channels as channels_mod
from .. import creds
from ..throttle import risk_hit, throttle
from .names import core_same

INVEST_API = "https://aiqicha.baidu.com"
#: 登录态失效时检索接口回空列表，拿不到 pid 就读不到 ``userType``；用这家公开主体的
#: pid 兜底探一次，专门判断 Cookie 还有没有效、股权查询还剩几次。
AQC_PROBE_PID = "77272571515291"
TIANYANCHA_API = "https://capi.tianyancha.com"
TIANYANCHA_WEB = "https://www.tianyancha.com"
# 对外投资分页（每页 companyId 列表），正文里的 gid 就是下一层要用的主体 id
TYC_INVEST = "/biz-service/cloud-company-background/company/investListV2"
# 控股企业：和对外投资不是同一份清单。对外投资只列「直接投出去的那些」，
# 控股企业按持股层级把隔着几层的控股子公司也列出来，专门查这一面才不漏。
TYC_HOLD = "/biz-service/cloud-equity-provider/v4/hold/companyholding"
# 股东列表：name 在 shareHolderName，机构股东的上游 gid 在 shareHolderGid
TYC_HOLDER = ("/biz-service/cloud-company-background/companyV2/"
              "dim/holder/latest/announcement")
# 主体检索：POST JSON ``{"word": 名称}``，结果在 ``data.companyList[].id``
TYC_SEARCH = "/cloud-tempest/web/searchCompanyV4"
# 分支机构：GET + query，行数组在 ``data.result``，真实家数在 ``data.total``
TYC_BRANCH = "/biz-service/cloud-company-background/company/branchList"
# 备案：GET + query 且主体参数叫 ``id``（不是 gid/pid），行数组键是 ``item``
TYC_ICP = "/biz-service/cloud-intellectual-property/intellectualProperty/icpRecordList"

# 最后一次被风控的说明，供 collect 写进 notes；节流器按来源串行，不会串到别的任务
_RISK_LAST: dict[str, str] = {}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")


# 最终受益人的控制线：累计持股达到这条线算控制（工商口径常用 25%）
DEFAULT_UBO_THRESHOLD = 25.0


@dataclass
class Equities:
    name: str
    depth: int = 2
    ratio: float = 100.0
    ubo_threshold: float = DEFAULT_UBO_THRESHOLD
    ubo_depth: int = 1
    pid: str = ""
    holders: list[dict] = field(default_factory=list)
    invests: list[dict] = field(default_factory=list)
    chain: list[dict] = field(default_factory=list)
    branches: list[dict] = field(default_factory=list)
    copyrights: list[dict] = field(default_factory=list)
    icps: list[dict] = field(default_factory=list)
    apps: list[dict] = field(default_factory=list)
    wechats: list[dict] = field(default_factory=list)
    weibos: list[dict] = field(default_factory=list)
    jobs: list[dict] = field(default_factory=list)
    suppliers: list[dict] = field(default_factory=list)
    source: str = ""
    resolved: str = ""          # 工商库里真正命中的主体全名，可能和输入不同
    source_status: dict[str, str] = field(default_factory=dict)  # 来源 → 状态码
    notes: list[str] = field(default_factory=list)
    # 被自设上限 / 额度砍掉的部位：键是原因（budget / pages / cap），值是给人看的一句话。
    # 单独放一份，是因为它既不是「渠道坏了」也不是「这轮没启用」，混进 source_status
    # 会让面板把某一路工商源整个标成失效，反而看不出真正该调的是额度。
    cap_notes: dict[str, str] = field(default_factory=dict)

    @property
    def full_owned(self) -> list[str]:
        """累计持股达到 ``ratio`` 门槛的主体名（含自己），可直接进资产池"""
        out = [self.name]
        for c in self.chain:
            if _acc(c) >= self.ratio and c.get("name"):
                out.append(c["name"])
        return list(dict.fromkeys(out))

    @property
    def partial(self) -> list[dict]:
        """低于门槛的参股 / 联营：默认不进池，只作线索"""
        return [c for c in self.chain if _acc(c) < self.ratio]

    @property
    def relation(self) -> dict:
        """每个主体「从谁身上穿下来」的标注：几级投资、累计持股、母体名。

        同一家公司在链路里可能出现多次（母公司直投 + 孙公司间接持股），
        取层级最浅、累计持股最高的那条，标注才稳定，不会同一次查询两个结果。
        """
        best: dict[str, tuple] = {}
        for c in self.chain:
            nm = str(c.get("name") or "").strip()
            if not nm:
                continue
            acc = _acc(c)
            lvl = int(c.get("depth") or 1)
            old = best.get(nm)
            rank = (lvl, -acc)
            if old and old[0] <= rank:
                continue
            best[nm] = (rank, lvl, acc, str(c.get("parent") or self.name).strip())
        out: dict[str, str] = {}
        for nm, (_rank, lvl, acc, parent) in best.items():
            out[nm] = f"⌈{lvl}⌋级投资⌈{acc:.2f}%⌋-{parent}"
        return out

    @property
    def ubo(self) -> dict:
        """最终受益人：股东树按累计持股折算，同一人多条链路相加"""
        return compute_ubo(self.name, self.holders,
                           threshold=self.ubo_threshold,
                           max_depth=self.ubo_depth + 1)

    def as_dict(self) -> dict:
        return {
            "name": self.name, "depth": self.depth, "source": self.source,
            "pid": self.pid, "resolved": self.resolved,
            "holders": self.holders, "invests": self.invests[:200],
            "chain": self.chain[:500], "branches": self.branches[:200],
            "copyrights": self.copyrights[:200], "icps": self.icps[:200],
            "apps": self.apps[:200], "wechats": self.wechats[:200],
            "weibos": self.weibos[:200], "jobs": self.jobs[:200],
            "suppliers": self.suppliers[:200],
            "full_owned": self.full_owned, "partial": self.partial[:200],
            "relation": self.relation,
            "full_owned_count": len(self.full_owned), "partial_count": len(self.partial),
            "ubo": self.ubo,
            "notes": self.notes, "source_status": self.source_status,
            "cap_notes": self.cap_notes,
        }


def _acc(c: dict) -> float:
    """链路节点的累计持股（逐级相乘）。累计值优先，没有就退回单级比例。"""
    v = c.get("acc_ratio")
    if v is None or v == "":
        v = c.get("ratio")
    return _pct(v)


def _pct(v) -> float:
    """把 '100%' / '51.00%' / 45 / 0.51 统一成百分数 float。

    公开工商接口常直接给 0~1 的小数比例，这里统一折算成百分数，
    免得 51% 被当成 0.51% 挡在控股闸外。
    """
    if v is None or v == "":
        return 0.0
    if isinstance(v, (int, float)):
        num = float(v)
    else:
        m = re.search(r"-?\d+(?:\.\d+)?", str(v).replace("％", "%"))
        if not m:
            return 0.0
        num = float(m.group(0))
    if "%" not in str(v) and 0 < num <= 1:
        num *= 100.0
    return round(num, 4)


def _typed(v) -> float:
    """已知是比例字段（0~1 小数）时用，不猜单位"""
    if v is None or v == "":
        return 0.0
    try:
        return round(float(v), 4)
    except Exception:
        return _pct(v)


def _num(v) -> int:
    try:
        return int(re.sub(r"[^\d]", "", str(v)) or 0)
    except Exception:
        return 0


def _first(row: dict, *keys: str) -> str:
    """按候选键取第一个非空值。工商同一含义的字段在不同接口里叫法不一样。"""
    for k in keys:
        v = row.get(k)
        if v not in (None, "", [], {}, "0"):
            return str(v).strip()
    return ""


# 机构名常见词：用来把「个人股东」从「上游还有一层要穿」的机构里分出来
_ORG_WORDS = ("公司", "集团", "厂", "店", "中心", "学院", "大学", "医院", "研究院",
              "事务所", "银行", "基金", "合伙", "企业", "委员会", "协会", "工作室",
              "控股", "投资", "资管", "证券", "保险", "科技", "实业", "商贸")


def _looks_org(name: str) -> bool:
    """名称像机构才值得往上穿一层；个人股东没有股东关系可拉。"""
    s = (name or "").strip()
    if not s:
        return False
    return any(w in s for w in _ORG_WORDS)


def compute_ubo(name: str, holders: list[dict], threshold: float = DEFAULT_UBO_THRESHOLD,
                max_depth: int = 2) -> dict:
    """把股东树折成最终受益人。

    逐级相乘算有效持股，同一人在多条链路上的有效持股相加；累计到 ``threshold``
    视为控制。``holders`` 里带嵌套 ``holders`` 时才会往上一层走，
    没有嵌套就是直接股东，比空着更接近实控人。
    """
    thr = float(threshold or DEFAULT_UBO_THRESHOLD)
    agg: dict[str, dict] = {}

    def walk(rows, chain: list[str], acc: float, depth: int) -> None:
        for h in rows or []:
            if not isinstance(h, dict):
                continue
            nm = str(h.get("name") or "").strip()
            if not nm or nm == name:
                continue
            r = _pct(h.get("ratio"))
            eff = acc * (r / 100.0) if r else 0.0
            slot = agg.setdefault(nm, {"ratio": 0.0, "paths": [], "depth": depth})
            slot["ratio"] += eff * 100.0
            slot["depth"] = min(slot["depth"], depth)
            path = [nm] + chain
            p = " → ".join(path)
            if p not in slot["paths"]:
                slot["paths"].append(p)
            sub = h.get("holders")
            if isinstance(sub, list) and sub and depth < max_depth:
                walk(sub, path, eff, depth + 1)

    walk(holders, [name], 1.0, 1)
    rows = []
    for nm, v in agg.items():
        ratio = min(100.0, round(v["ratio"], 2))
        rows.append({"name": nm, "ratio": ratio, "control": ratio >= thr,
                     "depth": v["depth"], "paths": v["paths"][:6]})
    rows.sort(key=lambda x: (-x["ratio"], x["depth"], x["name"]))
    return {"threshold": thr, "holders": rows[:40],
            "controls": sum(1 for x in rows if x["control"])}


def _client(timeout: float = 20.0, *, referer: str = "") -> httpx.AsyncClient:
    """来源站点客户端。内部来源直连，不经过本地代理。"""
    proxy = (config.get("proxy", "url") or "").strip()
    use = bool(config.get("proxy", "sources_via_proxy", default=False))
    headers = {"User-Agent": UA, "Accept": "application/json, text/plain, */*"}
    if referer:
        headers["Referer"] = referer
    kw: dict = {"timeout": timeout, "verify": False, "headers": headers}
    if use and proxy:
        kw["proxy"] = proxy
    else:
        kw["proxy"] = None
        kw["trust_env"] = False
    return httpx.AsyncClient(**kw)


def _sec(name: str) -> dict:
    return config.section("sources").get(name, {}) or {}


# ─────────────── 内置备案引擎补链路 ───────────────
async def _icp_children(name: str) -> list[dict]:
    """按主体名查备案，顺便把「备案主体 → 域名」变成可追的子公司线索。

    备案库只登记主体本身，不登记股权；这里只用来给空链路兜底，
    让「没有工商登录态」时至少还能从备案主体名往外扩一层。
    """
    try:
        from ..sources import passive
        rows = await passive.miit_company(name, kinds=("site",), pages=1)
    except Exception:
        return []
    out: list[dict] = []
    for r in rows or []:
        dom = str(r.get("domain") or "").strip()
        if dom and dom not in [x.get("domain") for x in out]:
            out.append({"domain": dom, "unit": r.get("unitName") or name,
                        "licence": r.get("serviceLicence") or ""})
    return out


# ─────────────── 公开工商接口 ───────────────
def _aqc_ready() -> str:
    """这一轮该用哪份登录态：池子里取当前那份，全空才算没配。"""
    return creds.value("aiqicha")


def _aqc_sync(cli: httpx.AsyncClient) -> dict:
    """把池子当前那份 Cookie 刷进请求头，返回 ``pick``（凭据 + 序号）。"""
    pick = creds.pick("aiqicha")
    if pick["cred"]:
        cli.headers["Cookie"] = pick["cred"]
    return pick


def _mark_risk(name: str, why: str, label: str = "") -> dict:
    """记一次风控并返回占位回包，让调用方拿到空数据但能看懂原因。"""
    left = throttle.penalize(name, why)
    msg = f"{label or name}风控拦截（{why}）"
    msg += f"，冷却 {left:.0f} 秒" if left else "，已拉长间隔"
    _RISK_LAST[name] = msg
    return {"__risk": msg}


def _note_risk(eq: Equities, name: str) -> bool:
    """把这次采集里出现过的风控说明写进 notes；返回是否命中过。"""
    msg = _RISK_LAST.get(name)
    if msg:
        eq.notes.append(msg)
        return True
    return False


async def _aqc_get(cli: httpx.AsyncClient, path: str, params: dict,
                  *, soft: bool = False) -> dict:
    """工商接口 GET。

    ``soft=True`` 只把异常记进说明、不触发来源级冷却：单个接口改版回「系统异常」时，
    若照常惩罚整家来源，同一轮后面的分支机构 / 备案查询会被一起挡掉。
    """
    base = (_sec("aiqicha").get("api") or "").strip().rstrip("/") or INVEST_API
    # 路径统一补前导斜杠：漏一个斜杠，拼出来的就是 ``aiqicha.baidu.comdetail/...``，
    # 直接抛 URL 异常、回包变成 ``{}``——表现和「这个面板没有数据」一模一样。
    path = "/" + str(path or "").lstrip("/")
    body: dict = {}
    attempts = _retry_times()
    # 被风控就换下一份登录态。换号不算一次重试（不计入 attempts），但最多把池子里
    # 剩下的那几份各试一遍，免得一份被封的 Cookie 把整轮采集拖成死循环。
    switch_left = max(0, creds.count("aiqicha") - 1)
    tries = 0
    while tries < attempts:
        tries += 1
        pick = _aqc_sync(cli)
        if not await throttle.acquire("aiqicha"):
            _RISK_LAST["aiqicha"] = "工商接口冷却中，这一轮跳过该请求"
            return {"__risk": _RISK_LAST["aiqicha"]}
        await _pace("aiqicha")
        again = False
        try:
            r = await cli.get(base + path, params=params)
        except Exception:
            again = True
        else:
            hit = ""
            if r.status_code == 429:
                hit = "HTTP 429"
            elif r.status_code in (401, 403):
                hit = f"HTTP {r.status_code}"
            if hit:
                creds.report("aiqicha", pick["cred"],
                             "blocked" if r.status_code == 429 else "invalid")
                if switch_left > 0:
                    switch_left -= 1
                    tries -= 1
                    _RISK_LAST["aiqicha"] = f"公开工商接口 {hit}，已换下一份登录态重试"
                    continue
                if r.status_code == 429:
                    return _mark_risk("aiqicha", "HTTP 429", "公开工商接口")
                return {}
            if r.status_code >= 500:
                again = True
            elif r.status_code != 200:
                return {}
            else:
                try:
                    parsed = r.json()
                except Exception:
                    again = True
                else:
                    if isinstance(parsed, dict) and str(parsed.get("status")) == "1" \
                            and "系统异常" in str(parsed.get("msg") or ""):
                        # ``status=1 / msg=系统异常`` 不是「接口改版」：pid 没按 ddw 还原时，
                        # 任何面板接口都回这一句。记一笔别静默吞掉。
                        _RISK_LAST["aiqicha"] = (
                            f"公开工商接口 {path} 回系统异常（pid 或参数不对）")
                        return {}
                    hit = risk_hit(parsed)
                    if hit:
                        # 风控词命中就当这份登录态被盯上了，换一份再来；都换过才认输
                        creds.report("aiqicha", pick["cred"], "blocked")
                        if switch_left > 0:
                            switch_left -= 1
                            tries -= 1
                            _RISK_LAST["aiqicha"] = (
                                f"公开工商接口 {path} 被风控（{hit}），已换下一份登录态重试")
                            continue
                        if soft:
                            msg = (f"公开工商接口 {path} 返回：{hit}"
                                   "（该接口本轮跳过，其它接口照常）")
                            _RISK_LAST["aiqicha"] = msg
                            return {"__risk": msg}
                        return _mark_risk("aiqicha", hit, "公开工商接口")
                    body = parsed
                    throttle.reward("aiqicha")
                    creds.report("aiqicha", pick["cred"], "ok")
        if not again:
            break
        if tries < attempts:
            # 越往后等越久：连错说明对面在限速，短间隔重试只会加重
            await asyncio.sleep(max(1.0, _expand_sleep()) * tries)
    return body


async def _aqc_post(cli: httpx.AsyncClient, path: str, form: dict) -> dict:
    base = (_sec("aiqicha").get("api") or "").strip().rstrip("/") or INVEST_API
    # 路径统一补前导斜杠：漏一个斜杠，拼出来的就是 ``aiqicha.baidu.comdetail/...``，
    # 直接抛 URL 异常、回包变成 ``{}``——表现和「这个面板没有数据」一模一样。
    path = "/" + str(path or "").lstrip("/")
    body: dict = {}
    attempts = _retry_times()
    switch_left = max(0, creds.count("aiqicha") - 1)
    tries = 0
    while tries < attempts:
        tries += 1
        pick = _aqc_sync(cli)
        if not await throttle.acquire("aiqicha"):
            _RISK_LAST["aiqicha"] = "工商接口冷却中，这一轮跳过该请求"
            return {"__risk": _RISK_LAST["aiqicha"]}
        await _pace("aiqicha")
        again = False
        try:
            r = await cli.post(base + path, data=form)
        except Exception:
            again = True
        else:
            hit = ""
            if r.status_code == 429:
                hit = "HTTP 429"
            elif r.status_code in (401, 403):
                hit = f"HTTP {r.status_code}"
            if hit:
                creds.report("aiqicha", pick["cred"],
                             "blocked" if r.status_code == 429 else "invalid")
                if switch_left > 0:
                    switch_left -= 1
                    tries -= 1
                    _RISK_LAST["aiqicha"] = f"公开工商接口 {hit}，已换下一份登录态重试"
                    continue
                if r.status_code == 429:
                    return _mark_risk("aiqicha", "HTTP 429", "公开工商接口")
                return {}
            if r.status_code >= 500:
                again = True
            elif r.status_code != 200:
                return {}
            else:
                try:
                    parsed = r.json()
                except Exception:
                    again = True
                else:
                    hit = risk_hit(parsed)
                    if hit:
                        creds.report("aiqicha", pick["cred"], "blocked")
                        if switch_left > 0:
                            switch_left -= 1
                            tries -= 1
                            _RISK_LAST["aiqicha"] = (
                                f"公开工商接口 {path} 被风控（{hit}），已换下一份登录态重试")
                            continue
                        return _mark_risk("aiqicha", hit, "公开工商接口")
                    body = parsed
                    throttle.reward("aiqicha")
                    creds.report("aiqicha", pick["cred"], "ok")
        if not again:
            break
        if tries < attempts:
            await asyncio.sleep(max(1.0, _expand_sleep()) * tries)
    return body


def _norm_ent(s) -> str:
    """主体名归一：去高亮标签、去空白、全角括号折半角，用于比对。"""
    t = re.sub(r"<[^>]+>", "", str(s or ""))
    t = t.replace("（", "(").replace("）", ")").replace("　", "")
    return re.sub(r"\s+", "", t)


def _aqc_pick(found: dict, name: str, *, first: bool = False) -> tuple[str, str]:
    """在检索结果里挑真正对上的主体，返回 (pid, 命中主体名)。

    搜索接口对「北京字节跳动科技」这类输入会先回一堆近似名——「跳动字节科技（北京）
    有限公司」是另一家公司，直接取第一条的 pid 会把整条穿透链挂到别人身上。这里必须
    先按主体名核对：完全一致优先，其次才接受互相包含；一个都对不上默认空手回去，
    宁可这轮没有链路，也不要把别人的母子公司算进资产池。

    ``first=True`` 是给「先要链路、名字回头人工核对」的入口用的：工商站的排序本身
    带主体对齐，一个名字都对不上时按排序首条对接，比整趟空手而归更接近实测数据；
    上层必须在说明里交代这是首条对接，别让人以为是精确命中。
    """
    want = _norm_ent(name)
    data = found.get("data") if isinstance(found, dict) else None
    rows: list[dict] = []
    if isinstance(data, dict):
        for key in ("resultList", "list", "result"):
            batch = data.get(key)
            if isinstance(batch, list):
                rows.extend([r for r in batch if isinstance(r, dict)])
    if not rows:
        pid = (data or {}).get("pid") if isinstance(data, dict) else ""
        return (str(pid) if pid else "", str((data or {}).get("entName") or ""))

    scored: list[tuple[int, str, str]] = []
    for row in rows:
        cand = _norm_ent(row.get("entName") or row.get("titleName") or row.get("name") or "")
        pid = str(row.get("pid") or row.get("id") or "")
        if not cand or not pid:
            continue
        if want and cand == want:
            score = 3
        elif want and len(want) >= 3 and (want in cand or cand in want):
            score = 2
        elif core_same(name, cand):
            # 简称对全称（差一个「市」/「有限公司」这种）：只认字号加区划都对得上
            score = 2
        else:
            score = 0
        scored.append((score, cand, pid))
    scored.sort(key=lambda x: -x[0])
    if not scored:
        return ("", "")
    if scored[0][0] == 0:
        # 稳定排序：同分的保持接口原顺序，所以首条仍是工商站排第一的那个。
        return (scored[0][2], scored[0][1]) if first else ("", "")
    return (scored[0][2], scored[0][1])


# 检索结果里的 pid 是逐位替换过的，`ddw` 指明用哪张替换表。
_AQC_PID_TABLES = {
    1: {"4": "5", "5": "4", "6": "7", "7": "6", "8": "9", "9": "8"},
    2: {"4": "6", "5": "8", "6": "9", "7": "4", "8": "5", "9": "7"},
}


def _aqc_pid_decode(raw, ddw) -> str:
    """把检索接口回出来的混淆 pid 还原成真实 pid。

    ``advanceFilterAjax`` 的 ``resultList[].pid`` 每一位都被换过，拿它直接去查详情面板
    只会得到 ``{"status":1,"msg":"系统异常，请联系管理员"}`` 和 ``data=null``——看起来
    像接口改版、额度用尽或登录态失效，其实只是 pid 没还原。``ddw`` 不是 1/2 时说明
    这份回包没有混淆，原样返回。
    """
    raw = str(raw or "")
    try:
        table = _AQC_PID_TABLES.get(int(ddw))
    except (TypeError, ValueError):
        table = None
    if not raw or not table:
        return raw
    return "".join(table.get(ch, ch) for ch in raw)


async def _aqc_panel_all(cli: httpx.AsyncClient, path: str, pid: str, *,
                         page_size: int = 100, cap: int = 600,
                         pages: int = 30) -> dict:
    """把 ``detail/`` 下的面板接口翻页拉满，回包形状与单页接口一致。

    面板接口的分页参数各家不同：多数是 ``size``，控股/对外投资那两个口是 ``s``。
    只取第一页时分支机构 143 家只剩 10 家、软著 227 条只剩 10 条，看起来就像
    「这个企业没有这些数据」。这里先按 ``size`` 打，若 ``total>0`` 但列表为空，
    再换 ``s`` 重打同一页，两种写法都能出数，调用方不用逐个接口记参数名。

    控股 / 对外投资还有一个不靠参数的坑：账号免费次数扣完后 ``total`` 照旧给，
    ``list`` 却是空的、``limitForward.remainCount=0``。这时换参数名重试没有意义，
    直接把额度提示带在 ``__quota`` 里，让上层写进说明，别让人以为是主体没数据。

    返回 ``{"data": {"total": N, "list": [...]}}``，沿用单页时的解析写法。
    """
    out: list[dict] = []
    total = 0
    param = "size"
    quota = ""
    risk = ""
    page = 1
    eff = page_size
    while page <= pages and len(out) < cap:
        body = await _aqc_get(cli, path,
                              {"pid": pid, "p": page, param: page_size}, soft=True)
        if not isinstance(body, dict):
            break
        if body.get("__risk"):
            # 被节流闸挡下时回包是空的：留一句原因，别让它看着像「这个面板没数据」
            risk = str(body.get("__risk") or "")
            break
        total, rows = _aqc_rows(body, "list")
        # 服务端不一定认我们给的 ``size``：软著面板固定一页 10 条，回包里自带真实页大小。
        # 拿它做翻页判断，否则「10 < 100」会被当成最后一页，227 条只拿到 10 条。
        box = body.get("data") if isinstance(body.get("data"), dict) else body
        for k in ("size", "pageSize", "limit"):
            try:
                v = int(box.get(k))
            except (TypeError, ValueError):
                continue
            if v > 0:
                eff = v
                break
        # 额度提示是整账号级的，出数的面板也照样带着 ``remainCount=0``。
        # 先看有没有数据：有数据就不算被截断，别把这份标记当成「这个面板取不到」。
        quota = "" if rows else _aqc_quota(body)
        if not rows and total and param == "size" and not quota:
            # 同一页换参数名再来一次：只在「说有 N 条却一条不给、且不是额度问题」时走
            alt = await _aqc_get(cli, path,
                                 {"pid": pid, "p": page, "s": page_size}, soft=True)
            if isinstance(alt, dict) and not alt.get("__risk"):
                t2, r2 = _aqc_rows(alt, "list")
                if r2:
                    param, total, rows = "s", (t2 or total), r2
                else:
                    quota = _aqc_quota(alt)
        if not rows:
            break
        out.extend(rows)
        if total and len(out) >= total:
            break
        if len(rows) < eff:
            break
        page += 1
    res = {"data": {"total": total or len(out), "list": out}}
    if quota:
        res["__quota"] = f"{path}：{quota}"
    if risk:
        res["__risk"] = f"{path}：{risk}"
    return res


def _aqc_icp_rows(rows: list[dict]) -> list[dict]:
    """备案面板展开成「一条域名一行」。

    这个接口一行里 ``domain`` 和 ``homeSite`` 都是数组：一个备案号常挂多个域名，
    直接 ``str(domain)`` 会得到 ``"['a.cn']"`` 这种带壳字符串，域名列全废。备案号在
    ``icpNo``（不是 ``licence``），站名取 ``homeSite`` 第一个。
    """
    out: list[dict] = []
    for it in rows if isinstance(rows, list) else []:
        if not isinstance(it, dict):
            continue
        doms = it.get("domain")
        if isinstance(doms, list):
            doms = [str(d).strip() for d in doms if str(d or "").strip()]
        else:
            d = str(doms or "").strip()
            doms = [d] if d else []
        site = it.get("homeSite")
        if isinstance(site, list):
            site = str(site[0] if site else "").strip()
        else:
            site = str(site or "").strip()
        for dom in doms:
            dom = dom.replace("http://", "").replace("https://", "").split("/")[0].strip().lower()
            if not dom:
                continue
            out.append({
                "domain": dom,
                "site_name": site or _first(it, "siteName", "webName"),
                "licence": _first(it, "icpNo", "icp", "licence", "liscence", "licenceNum", "code"),
                "unit": _first(it, "unitName", "companyName", "unit", "unitNameCn", "name"),
                "source": "aqc",
            })
    return out


def _aqc_logged_out(payload) -> bool:
    """回包自称游客（``userType=nologin``）说明 Cookie 已经失效。

    工商站登录态过期时不给 401：请求照常 200，但检索回空列表、面板按游客处理。
    只盯「没有结果」会把登录态过期误判成「这主体查不到」。
    """
    if not isinstance(payload, dict):
        return False
    for box in (payload.get("data"), payload):
        if not isinstance(box, dict):
            continue
        lf = box.get("limitForward") or box.get("limit") or {}
        if isinstance(lf, dict) and str(lf.get("userType") or "") == "nologin":
            return True
    return False


def _aqc_quota(payload: dict) -> str:
    """读「本次查询额度」提示；返空串表示额度没问题。

    工商站的免费查询次数是按账号扣的，扣完仍回 200，只是 ``list`` 永远为空、
    ``limitForward.remainCount`` 变成 0。不把这句认出来，界面就只会显示「无股权数据」，
    看起来像主体本身没有股东。
    """
    if not isinstance(payload, dict):
        return ""
    # 额度提示有时包在 data 里，有时和 total/list 一起平铺在顶层，两种都要认
    for box in (payload.get("data"), payload):
        if not isinstance(box, dict):
            continue
        lf = box.get("limitForward") or box.get("limit") or {}
        if not isinstance(lf, dict):
            continue
        if str(lf.get("userType") or "") == "nologin":
            return ("公开工商接口（爱企查）登录态已失效（Cookie 过期或被登出），"
                    "这一页没有再返回数据")
        try:
            remain = int(lf.get("remainCount"))
        except (TypeError, ValueError):
            continue
        if remain <= 0 and str(lf.get("limitStatus") or "") in ("1", "2"):
            return ("公开工商接口（爱企查）账号免费次数已用完，"
                    "这一页没有再返回数据")
    return ""


def _parse_holders(rows) -> list[dict]:
    """工商股东列表 → 统一结构。空名字丢掉，否则 UBO 聚合和前端列表都会出现空节点。"""
    out: list[dict] = []
    for it in rows if isinstance(rows, list) else []:
        if not isinstance(it, dict):
            continue
        nm = str(it.get("name") or it.get("shareholder") or "").strip()
        if not nm:
            continue
        out.append({"name": nm,
                    "ratio": _typed(it.get("subRate")),
                    "pid": str(it.get("pid") or ""),
                    "type": "机构" if _looks_org(nm) else ""})
    return out


async def _fill_upstream(cli, rows: list[dict], levels: int, branches: int,
                         depth: int = 1) -> None:
    """机构股东再往上拉股东，结果挂回 ``rows[i]['holders']``，供 UBO 逐级折算。

    每层最多展开 ``branches`` 家、总共 ``levels`` 层：工商站按次扣次数，
    默认只穿一层。遇到风控 / 冷却就立刻返回，不硬撞。
    """
    if depth > levels or branches <= 0:
        return
    targets = [h for h in rows
               if isinstance(h, dict) and h.get("pid") and _looks_org(h.get("name"))]
    for h in targets[:branches]:
        body = await _aqc_get(cli, "/compdata/headinfoAjax", {"pid": h["pid"]}, soft=True)
        if not isinstance(body, dict) or body.get("__risk"):
            return
        raw = body.get("data") or {}
        sub = ((raw.get("shareholdersData") or {}).get("list")) if isinstance(
            raw.get("shareholdersData"), dict) else []
        kids = _parse_holders(sub)
        if not kids:
            continue
        h["holders"] = kids
        await _fill_upstream(cli, kids, levels, max(1, branches - 1), depth + 1)


#: 「不限额」内部用的哨兵：翻页仍然受每层 30 页 / 400 家封顶，不会真的无限发。
_BUDGET_UNLIMITED = 100000


def _expand_budget() -> int:
    """本次穿透允许消耗的工商请求次数（一次约等于翻一页，100 条）。

    这个额度是「翻对外投资页 + 往上穿股东 + 逐层穿子公司」三件事共用的，
    所以不能只按「够翻两页」给：12 次在一家人数十家的集团上会被第一层吃光，
    深层子公司就整片漏掉，看着像没找到。

    默认不限额（0）：40 次看着多，碰上国网 / 集团这类主体第 2 层就没了，
    链路断在半截，现场表现是「股权穿透被截断」。真要收着花再显式填数字。

    填 0 表示不限额：翻页一直翻到没有下一页为止，只受「每层 30 页 / 400 家」和
    执行时限约束。慢节奏（每次等几十秒）要拉得全，靠的就是这一档。
    """
    override = _BUDGET_OVERRIDE.get()
    if override is not None:
        return _BUDGET_UNLIMITED if int(override) <= 0 else max(1, int(override))
    try:
        val = int(config.get("scan", "equity_budget", default=0) or 0)
    except Exception:
        return _BUDGET_UNLIMITED
    return _BUDGET_UNLIMITED if val <= 0 else max(1, val)


#: 单次执行传入的间隔 / 重试覆盖值。穿透是一条调用链（翻页、上游股东、子公司），
#: 逐层传参会漏，用上下文变量让整条链上的请求都吃同一个值。
_GAP_OVERRIDE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "equity_gap_override", default=None)
_RETRY_OVERRIDE: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "equity_retry_override", default=None)
#: 单次执行的穿透额度覆盖：一次任务里几个主体可能大小差很多，
#: 小主体按几十次够用，集团主体要翻十几页，额度得跟着任务走。
_BUDGET_OVERRIDE: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "equity_budget_override", default=None)

#: 最近一次 ``collect()`` 的中间状态：哪一路回来就先写进来。
#: 上层套了硬时限、任务被掐断时，只有这份快照能说明是额度尽、被风控，还是卡在某一路。
LAST_STATUS: dict[str, str] = {}

#: 进度回调：穿透是几十次串行请求、默认每次至少隔 1.5 秒，几分钟里界面只有一句
#: 「进行中」，看不出正在翻哪一家。``collect(on_progress=...)`` 设进来的函数会在
#: 每次开翻一个主体前收到一行「正在查谁、第几层」，实时日志就能跟着走。
_PROGRESS: contextvars.ContextVar = contextvars.ContextVar("equity_progress", default=None)


def _prog(msg: str) -> None:
    """往上抛一行进度；没有回调（脚本直调、单测）就什么也不做。"""
    cb = _PROGRESS.get()
    if cb is None:
        return
    try:
        cb(str(msg))
    except Exception:
        pass


#: 中途快照回调：逐层穿子公司是几十次串行请求、单主体就能跑上十几分钟，链路是一条条
#: 长出来的。``collect(on_partial=...)`` 设进来后，每穿完一家就交一份「此刻的链路」，
#: 外层边收边入库；硬时限一到协程被掐，已经穿出来的节点不会跟着局部变量一起消失。
_PARTIAL: contextvars.ContextVar = contextvars.ContextVar("equity_partial", default=None)


def _beat(src) -> None:
    """把此刻穿到的链路交给外层（没接回调就什么也不做）。

    ``src`` 可以是一份 ``Equities``，也可以是只带 ``name`` / ``chain`` / ``invests``
    的字典——逐层穿那个循环只拿得到链路本体，没有整份对象的上下文。
    """
    cb = _PARTIAL.get()
    if cb is None:
        return
    try:
        cb(src)
    except Exception:
        pass


def effective_gap(gap: float | None = None) -> float:
    """这次执行真正会用的「每一次请求之间」间隔（秒）。

    面板没填（``gap`` 为 0 / None）就走配置里的 ``scan.equity_sleep``。上层要按这个
    值放大执行时限：30 秒 × 40 次是 20 分钟，时限还按默认 900 秒掐，配了延时反而
    拉得更少——这才是「拉取不全」最容易踩的坑。
    """
    if gap:
        return max(0.0, min(_GAP_MAX, float(gap)))
    try:
        return max(0.0, min(_GAP_MAX, float(config.get("scan", "equity_sleep", default=1.5) or 0)))
    except Exception:
        return 1.5


def _expand_sleep() -> float:
    """每一次工商请求之前要额外等待的秒数（不是每页、不是每层）。

    节流闸本身已经按来源给了 2.5～6 秒间隔，这里再叠一层是给「穿透」用的：
    一次跑几十页属正常量，连着打最容易触发风控，留多长由用户按账号情况调。
    单次执行传了 ``gap`` 就用那一枪的值，没传才回落到配置。
    """
    return effective_gap(_GAP_OVERRIDE.get())


#: 单次间隔上限。工商站慢节奏拉取（一分钟两次以内）能稳稳跑完几千条，
#: 用户按账号被封的次数调这一项，别在代码里替他把节奏压回去。
_GAP_MAX = 300.0

#: 节拍器的「上一次出请求的时刻」：按来源记，穿透是一次一次串着打的，
#: 只有真正做到「每次请求都等够」才能把风控压下去。
_PACE_AT: dict[str, float] = {}
_PACE_LOCK: dict[str, asyncio.Lock] = {}


async def _pace(source: str) -> None:
    """同一来源相邻两次真实请求之间至少隔 ``_expand_sleep()`` 秒。

    以前间隔只插在翻页和逐层展开处，一页里夹着的头部信息 / 股东 / 分支几次子查询
    完全不受约束，配了间隔照样连打——这就是「配了延时还是被截断、还拉不全」的由来。
    节拍放在请求出口，翻页、补穿、重试都吃同一份节拍。
    """
    gap = _expand_sleep()
    if gap <= 0:
        return
    lock = _PACE_LOCK.get(source)
    if lock is None:
        lock = _PACE_LOCK[source] = asyncio.Lock()
    async with lock:
        wait = gap - (time.monotonic() - _PACE_AT.get(source, 0.0))
        if wait > 0:
            await asyncio.sleep(wait)
        _PACE_AT[source] = time.monotonic()


def _retry_times() -> int:
    """单个请求的尝试次数：1 表示不重试。"""
    v = _RETRY_OVERRIDE.get()
    if v is not None:
        try:
            return max(1, min(10, int(v)))
        except Exception:
            return 1
    try:
        return max(1, min(10, int(config.get("scan", "equity_retry", default=1) or 1)))
    except Exception:
        return 1


def _aqc_rows(payload: dict, key: str = "list") -> tuple[int, list[dict]]:
    """工商回包取 ``(total, 列表)``：有的包一层 ``data``，有的和 total 一起平铺。"""
    if not isinstance(payload, dict):
        return (0, [])
    outer_total = payload.get("total")
    for box in (payload.get("data"), payload):
        if not isinstance(box, dict):
            continue
        rows = box.get(key)
        if isinstance(rows, list):
            total = box.get("total")
            if total is None:
                total = outer_total
            return (_num(total), [r for r in rows if isinstance(r, dict)])
    return (0, [])


async def _aqc_invest_all(cli: httpx.AsyncClient, pid: str, *,
                          page_size: int = 100, cap: int = 400,
                          budget: dict | None = None,
                          path: str = "/detail/investAjax",
                          label: str = "对外投资") -> tuple[list[dict], str]:
    """投资面全量分页，返回 ``(清单, 额度提示)``。

    这个接口一页固定回 ``s`` 条，``total`` 才是真实家数：只取第一页时，
    对外投资几十家的集团会被截成十几家，看起来就像「查不到子公司」。
    每翻一页扣一次账号次数，所以用 ``cap`` 封顶、用 ``budget['left']`` 记账，
    额度见底立刻收手，不拿空回包硬撞。

    ``path`` / ``label`` 给「控股企业」那份清单复用：两个面板的分页写法一模一样，
    只是接口名和说明里的称呼不同。
    """
    out: list[dict] = []
    if not pid:
        return (out, "")
    seen: set[str] = set()
    page = 1
    quota = ""
    total_seen = 0
    cut = False
    while len(out) < cap and page <= 30:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 0:
            cut = True
            break
        body = await _aqc_get(cli, path,
                              {"pid": pid, "p": page, "s": page_size}, soft=True)
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        if not isinstance(body, dict) or body.get("__risk"):
            quota = quota or str(_RISK_LAST.get("aiqicha") or "")
            break
        quota = _aqc_quota(body) or quota
        total, rows = _aqc_rows(body, "list")
        total_seen = int(total or 0) or total_seen
        # 额度提示是整账号级的：出数的这一页照样带 ``remainCount=0``。
        # 有数据就继续翻，把这份标记当成「这一路停了」会把已经拿到的一半丢掉。
        if rows:
            quota = ""
        if quota:
            # 额度尽的那一页照样会带回 total：这是上游报的「这家一共有多少家对外投资」。
            # 把这两个数字写进说明，用户才算得清是「本来就没几家」还是「被额度截断」，
            # 而不是只能凭感觉说一句「找的不全」。
            if total:
                # 这里的「取到 M 家」只算这一路。主源停了、另一路还在出数，
                # 少了来源名就会被读成整趟只拿到 0 家。
                quota = (f"{quota}；爱企查这一路称该主体{label}共 {int(total)} 家，"
                         f"这一路取到 {len(out)} 家")
            break
        if not rows:
            break
        fresh = 0
        for it in rows:
            nm = str(it.get("entName") or it.get("name") or "").strip()
            key = nm or str(it.get("pid") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(it)
            fresh += 1
        if not fresh:
            break
        if total and len(out) >= total:
            break
        page += 1
    if cut:
        _mark_budget_cut(budget, len(out), total_seen, label)
    return (out, quota)


async def _aqc_hold_all(cli: httpx.AsyncClient, pid: str, **kw) -> tuple[list[dict], str]:
    """控股企业清单：与对外投资同一套翻页，接口名不同。"""
    kw.setdefault("cap", 600)
    return await _aqc_invest_all(cli, pid, path="/detail/holdsAjax",
                                 label="控股企业", **kw)


async def _aqc_expand(cli: httpx.AsyncClient, root_name: str, chain: list[dict], *,
                      depth: int, ratio: float, budget: dict) -> str:
    """按层展开对外投资：子公司 → 孙公司，累计比例逐级相乘。

    ``chain`` 里已经有根主体的直接投资（depth=1）。``ratio`` 是**结果**门槛（哪些算
    达标进资产池），不是下钻门槛：只占三成的控股子公司照样有它自己的全资孙公司，
    按 100% 卡住会把整棵子树砍掉，用户设了 2 层却只能看到 1 级。翻不翻由额度管——
    已按累计持股从高到低排，额度见底就收手。返回额度提示，空串表示没触到额度。

    累计比例算法与工商一致：上一级 ``acc_ratio`` × 本层持股比例。
    """
    if depth <= 1 or not chain:
        return ""
    quota = ""
    seen: set[tuple[str, str]] = {(str(c.get("parent") or ""), str(c.get("name") or ""))
                                  for c in chain}
    level = [c for c in chain if int(c.get("depth") or 1) == 1]
    for _ in range(1, int(depth)):
        nxt: list[dict] = []
        # 先穿持股比例高的，额度有限的账号能把钱花在真正控股的枝上
        for node in sorted(level, key=lambda c: -float(c.get("acc_ratio") or 0)):
            if quota:
                break
            if int(budget.get("left", 0)) <= 0:
                # 这一层还没穿完额度就没了：不记一句，界面只会显示「只穿到某一层」。
                _mark_budget_cut(budget, len(nxt), 0, "逐层子公司穿透")
                break
            pid = str(node.get("pid") or "")
            base = float(node.get("acc_ratio") or 0)
            # 只要还持有一点就值得翻：用 ratio 卡下钻会把整棵子公司子树砍掉
            if not pid or base <= 0:
                continue
            _prog(f"股权穿透：翻「{node.get('name') or root_name}」的对外投资"
                  f"（第 {int(node.get('depth') or 1) + 1} 层，累计 {base:.2f}%）")
            rows, quota = await _aqc_invest_all(cli, pid, budget=budget)
            if quota:
                break
            for it in rows:
                child = str(it.get("entName") or it.get("name") or "").strip()
                if not child or child == root_name:
                    continue
                key = (str(node.get("name") or ""), child)
                if key in seen:
                    continue
                seen.add(key)
                pct = _typed(it.get("regRate"))
                acc = round(base * pct / 100.0, 2)
                rec = {"name": child, "parent": str(node.get("name") or root_name),
                       "ratio": pct, "acc_ratio": acc,
                       "depth": int(node.get("depth") or 1) + 1,
                       "pid": str(it.get("pid") or ""), "src": "aiqicha",
                       "capital": it.get("regCapital") or "",
                       "status": it.get("cancelStatus") or ""}
                chain.append(rec)
                # 逐层穿是几十次串行请求，一个主体就能跑十几分钟。每长出一家报一声，
                # 外层把它并进「此刻已穿到的链路」；硬时限一到协程被掐，已经穿出来的
                # 节点不会跟着局部变量一起消失。
                _beat({"name": root_name, "chain": chain})
                # 下钻只看「有没有持股」，不看结果门槛：一家 51% 的控股子公司
                # 自己还有全资孙公司，用 100% 卡住会把整棵子树砍掉。
                # 翻不翻由额度管，已按累计持股从高到低排。
                if acc > 0:
                    nxt.append(rec)
        if quota or not nxt:
            break
        level = nxt
    return quota


async def _skip_dict() -> dict:
    """占位协程：某项面关掉时顶替并发位，保持 gather 不降速。"""
    return {}


async def from_aiqicha(name: str, depth: int = 2, ratio: float | None = None,
                       branches: bool = True) -> Equities:
    """爱企查：股东 / 对外投资 / 分支机构 / 软著 / 备案。

    登录态放在 ``sources.aiqicha.cookie``；未配置时只返回说明，不阻塞其它来源。
    ``depth`` 是向下穿透层数，``ratio`` 是继续往下展开要过的累计持股门槛，
    ``branches`` 关掉就不打分支机构接口（少一次请求、少一次额度消耗）。
    """
    if ratio is None:
        try:
            ratio = float(config.get("scan", "equity_ratio", default=100) or 100)
        except Exception:
            ratio = 100.0
    eq = Equities(name=name, depth=depth, source="aiqicha")
    _RISK_LAST.pop("aiqicha", None)
    cookie = _aqc_ready()
    if not cookie:
        eq.source_status["aiqicha"] = "no_credential"
        eq.notes.append("公开工商接口未配置登录态，股东 / 投资链路跳过")
        return eq

    headers = {"Cookie": cookie}
    ref = f"{INVEST_API}/s?q={quote(name)}"
    async with _client(referer=ref) as cli:
        cli.headers.update(headers)
        # 1) 先拿 pid：搜索页的 suggest 只回显关键字，真正带 pid 的是筛选列表
        found = await _aqc_get(cli, "/s/advanceFilterAjax",
                               {"q": name, "p": 1, "s": 10, "o": 0, "f": "{}", "t": 0})
        eq.pid, hit = _aqc_pick(found, name, first=True)
        if eq.pid and isinstance(found, dict):
            # 检索回的 pid 逐位被替换过，不还原的话后面每个详情面板都回「系统异常」
            eq.pid = _aqc_pid_decode(eq.pid, found.get("ddw"))
        if not eq.pid:
            sug: dict = {}
            sug = await _aqc_post(cli, "/index/suggest", {"q": name, "t": 0})
            eq.pid, hit = _aqc_pick(sug, name, first=True)
            if eq.pid and isinstance(sug, dict):
                eq.pid = _aqc_pid_decode(eq.pid, sug.get("ddw"))
        if not eq.pid:
            if _note_risk(eq, "aiqicha"):
                eq.source_status["aiqicha"] = "blocked"
            elif _aqc_logged_out(found) or _aqc_logged_out(sug):
                eq.source_status["aiqicha"] = "no_credential"
                eq.notes.append("爱企查登录态已失效（Cookie 过期或被登出），"
                                "检索按游客处理，股东 / 投资链路跳过；重新取 Cookie 后再跑")
            else:
                eq.source_status["aiqicha"] = "not_found"
                eq.notes.append("公开工商接口未检索到同名主体（名称不精确）")
            return eq
        eq.resolved = hit
        if hit and _norm_ent(hit) != _norm_ent(name):
            if core_same(name, hit):
                eq.notes.append(f"工商主体按输入对齐到：{hit}")
            else:
                eq.notes.append(
                    f"检索没有同名主体，按排序首条对接：{hit}；链路可能挂到近似名的另一家"
                    "公司，核不上的把目标改成工商全称再跑")

        # 2) 主体画像：股东与对外投资在同一份 figure 数据里
        head = await _aqc_get(cli, "/compdata/headinfoAjax", {"pid": eq.pid}, soft=True)
        raw = ((head.get("data") or {}) if isinstance(head, dict) else {})
        sh = ((raw.get("shareholdersData") or {}).get("list") or []) if isinstance(
            raw.get("shareholdersData"), dict) else []
        iv = ((raw.get("investRecordData") or {}).get("list") or []) if isinstance(
            raw.get("investRecordData"), dict) else []
        if not (sh or iv):
            # 老版本接口：stockchart 一次给股东 + 投资两段
            chart = await _aqc_get(cli, "/stockchart/stockchartAjax", {"pid": eq.pid}, soft=True)
            cdata = (chart.get("data") or {}) if isinstance(chart, dict) else {}
            sh = sh or (((cdata.get("shareholdersData") or {}).get("list")) or [])
            iv = iv or (((cdata.get("investRecordData") or {}).get("list")) or [])
        # 对外投资分页拉满：这个口才是真正的子公司清单，``headinfo`` 里的那份常常只是首屏
        budget = {"left": _expand_budget()}
        quota = ""
        if eq.source_status.get("aiqicha") != "quota":
            more, quota = await _aqc_invest_all(cli, eq.pid, budget=budget)
            if more:
                iv = more
            if budget.get("cut"):
                eq.cap_notes.setdefault("budget", str(budget["cut"]))
            if quota:
                # 分页被次数挡住时，详情页首屏那份投资清单照样是全的：
                # 这时写「这一路取到 0 家」只会让人以为整趟没查到子公司。
                note = (f"爱企查对外投资分页被账号次数挡住；已用详情页首屏的 "
                        f"{len(iv)} 家") if iv else quota
                if not iv:
                    eq.source_status["aiqicha"] = "quota"
                if note not in eq.notes:
                    eq.notes.append(note)
        # 控股企业是另一份清单：对外投资只列直接投出去的那些，隔着几层的控股子公司
        # 只在「控股企业」面板里。少这一面，纯控股型的子公司整片找不到。
        iv = iv if isinstance(iv, list) else []
        if eq.source_status.get("aiqicha") != "quota":
            held, hq = await _aqc_hold_all(cli, eq.pid, budget=budget)
            if held:
                have = {_norm_ent(it.get("entName") or it.get("name"))
                        for it in iv if isinstance(it, dict)}
                for it in held:
                    nm_ = str(it.get("entName") or it.get("name") or "").strip()
                    if not nm_ or _norm_ent(nm_) in have:
                        continue
                    have.add(_norm_ent(nm_))
                    iv.append({"entName": nm_,
                               "regRate": (it.get("proportion") or it.get("subRate")
                                           or it.get("percent") or it.get("regRate")),
                               "pid": it.get("pid") or it.get("entPid") or "",
                               "cancelStatus": (it.get("openStatus")
                                                or it.get("cancelStatus") or "")})
            elif hq:
                eq.notes.append(hq)

        # 分支 / 软著 / 备案三个面板：接口名在 ``detail/`` 下、分页参数是 ``size``。
        # 原来写成 ``cs/xxxAjax`` + ``s=``，回包一律 ``data=null``，看着像「该企业
        # 没有这些数据」；再叠上没还原的 pid，就整片是空的。
        # 五个附加面板（移动应用 / 公众号 / 微博 / 招聘 / 供应商）和分支机构同批发，
        # 一次并发换五类「主体画像」，比逐个补请求省一半等待。
        (branch, cpr, icp, apps, wechats, weibos,
         jobs, sups) = await asyncio.gather(
            _aqc_panel_all(cli, "detail/branchajax", eq.pid) if branches else _skip_dict(),
            _aqc_panel_all(cli, "detail/copyrightAjax", eq.pid),
            _aqc_panel_all(cli, "detail/icpinfoAjax", eq.pid),
            _aqc_panel_all(cli, "c/appinfoAjax", eq.pid),
            _aqc_panel_all(cli, "c/wechatoaAjax", eq.pid),
            _aqc_panel_all(cli, "c/microblogAjax", eq.pid),
            _aqc_panel_all(cli, "c/enterprisejobAjax", eq.pid),
            _aqc_panel_all(cli, "c/supplierAjax", eq.pid),
            return_exceptions=True)
        # 面板报额度、或本该有数据却一条没给时，把原因写进说明：
        # 界面上显示「分支机构 0 家」和「额度用尽，未取到」是两件事。
        for name_, panel in (("分支机构", branch), ("软件著作权", cpr), ("备案", icp),
                             ("移动应用", apps), ("微信公众号", wechats), ("微博", weibos),
                             ("招聘", jobs), ("供应商", sups)):
            if not isinstance(panel, dict):
                continue
            q = str(panel.get("__quota") or "")
            pdata = panel.get("data")
            pdata = pdata if isinstance(pdata, dict) else {}
            if q and pdata.get("list"):
                # 出数的面板只是被次数提示了一句，数据是齐的：记一句说明就行，
                # 不能因此把整路标成额度用尽。
                if q not in eq.notes:
                    eq.notes.append(q)
                q = ""
            if q and q not in eq.notes:
                eq.notes.append(q)
                eq.source_status["aiqicha"] = "quota"
                continue
            rk = str(panel.get("__risk") or "")
            if rk:
                if rk not in eq.notes:
                    eq.notes.append(rk)
                continue
            ptotal = int(pdata.get("total") or 0)
            if not pdata.get("list") and ptotal > 0:
                note = f"{name_}面板称有 {ptotal} 条但未返回列表"
                if note not in eq.notes:
                    eq.notes.append(note)

        # 3) 最终受益人：股东里的机构再往上穿，人才能穿到底。
        #    额度已用尽 / 冷却时直接不做，别把次数耗在必然空回的分支上。
        eq.holders = _parse_holders(sh)
        levels = int(config.get("scan", "equity_ubo_levels", default=1) or 0)
        # 这里只给「往上穿几个机构股东」用；别用 branches 命名，会把入参的
        # 「要不要打分支机构接口」布尔值盖掉，后面 stat 出来全是数字
        ubo_branch = int(config.get("scan", "equity_ubo_branches", default=3) or 0)
        if eq.holders and levels > 0 and ubo_branch > 0 \
                and eq.source_status.get("aiqicha") != "quota":
            await _fill_upstream(cli, eq.holders, levels, ubo_branch)

    for it in iv if isinstance(iv, list) else []:
        if not isinstance(it, dict):
            continue
        child = str(it.get("entName") or it.get("name") or "").strip()
        if not child or child == name:
            continue
        pct = _typed(it.get("regRate"))
        rec = {"name": child, "parent": name, "ratio": pct,
               "acc_ratio": round(pct, 2), "depth": 1,
               "pid": str(it.get("pid") or ""), "src": "aiqicha",
               "capital": it.get("regCapital") or "",
               "status": it.get("cancelStatus") or ""}
        eq.invests.append({"name": child, "ratio": pct, "pid": rec["pid"]})
        eq.chain.append(rec)

    # 首层链路先交出去：往下穿之前就有东西可入库，慢的是后面那几层。
    if eq.chain:
        _beat(eq)

    # 向下穿透单独记额度：上一段对外投资分页可能已经把 budget 花光，共用一份时
    # depth>1 整段不跑，用户看到的就是「设了两层却全是 1 级」。
    expand_budget = {"left": _expand_budget()}
    if depth > 1 and eq.chain and eq.source_status.get("aiqicha") != "quota" \
            and int(expand_budget.get("left", 0)) > 0:
        async with _client(referer=ref) as cli:
            cli.headers.update(headers)
            deeper = await _aqc_expand(cli, name, eq.chain, depth=depth,
                                       ratio=ratio, budget=expand_budget)
        if deeper and deeper not in eq.notes:
            eq.notes.append(deeper)
            eq.source_status["aiqicha"] = "quota"
        if expand_budget.get("cut"):
            eq.cap_notes.setdefault("budget", str(expand_budget["cut"]))

    # 分支机构：要能出「企业名称 / 法人 / 状态 / PID」四列，只留名字等于没有数据。
    # 同一含义的键在各家接口里叫法不同，按候选顺序取第一个非空。
    if isinstance(branch, dict) and not isinstance(branch, Exception):
        data = branch.get("data") or {}
        rows = data.get("list") if isinstance(data, dict) else None
        for it in rows if isinstance(rows, list) else []:
            if not isinstance(it, dict):
                continue
            nm = _first(it, "entName", "branchName", "name", "titleName")
            if not nm:
                continue
            eq.branches.append({
                "name": nm,
                "legal": _first(it, "legalPersonName", "legalPerson", "legalMan",
                                "operName", "oper"),
                "status": _first(it, "openStatus", "cancelStatus", "regStatus", "status"),
                "pid": _first(it, "pid", "id"),
                "capital": _first(it, "regCapital", "capital", "amount"),
                "established": _first(it, "estiblishTime", "establishDate", "foundDate",
                                      "regDate"),
                "address": _first(it, "regAddr", "regAddress", "address", "addr"),
            })

    # 软著只留一个名字等于把「登记号 / 取得方式 / 分类」白丢了：导出分表这几列
    # 全是空的，用户看到的是一张只有名字的表。
    _CPR_KEYS = (("name", ("softwareName", "name")),
                 ("short_name", ("shortName", "short_name")),
                 ("category", ("softwareType", "catName", "category")),
                 ("reg_num", ("regNo", "regNum", "reg_num")),
                 ("pub_type", ("pubType", "softwareWork", "pub_type")),
                 ("pub_date", ("regDate", "pubDate")),
                 ("owner", ("softwareWork", "ownerName")))
    if isinstance(cpr, dict):
        data = cpr.get("data") or {}
        rows = data.get("list") if isinstance(data, dict) else None
        for it in rows if isinstance(rows, list) else []:
            if not isinstance(it, dict):
                continue
            item: dict = {}
            for dst, srcs in _CPR_KEYS:
                val = ""
                for k in srcs:
                    val = it.get(k) or val
                    if val:
                        break
                if val:
                    item[dst] = val
            if item.get("name"):
                eq.copyrights.append(item)

    # 备案：一条备案常挂多个域名，``domain`` 是数组，要拆成多行才落得进域名列
    if isinstance(icp, dict):
        data = icp.get("data") or {}
        rows = data.get("list") if isinstance(data, dict) else None
        for it in _aqc_icp_rows(rows if isinstance(rows, list) else []):
            if not it.get("unit"):
                it["unit"] = hit or name
            eq.icps.append(it)

    # 附加画像面板：字段名照各面板回包取，缺的留空，不硬编码成一行空记录
    def _rows_of(panel) -> list:
        box = panel.get("data") if isinstance(panel, dict) else None
        box = box if isinstance(box, dict) else {}
        rows = box.get("list")
        return rows if isinstance(rows, list) else []

    for it in _rows_of(apps):
        if isinstance(it, dict):
            nm = _first(it, "name", "appName", "title")
            if nm:
                eq.apps.append({
                    "name": nm,
                    "classify": _first(it, "classify", "category", "type"),
                    "version": _first(it, "currentVersion", "version"),
                    "updated": _first(it, "updateTime", "updated", "publishTime"),
                    "brief": _first(it, "logoBrief", "brief", "summary", "introduction"),
                    "logo": _first(it, "logo", "icon"),
                    "bundle": _first(it, "bundleId", "packageName", "package"),
                    "link": _first(it, "link", "url", "market"),
                })
    for it in _rows_of(wechats):
        if isinstance(it, dict):
            nm = _first(it, "wechatName", "name", "nickname")
            if nm:
                eq.wechats.append({
                    "name": nm,
                    "account": _first(it, "wechatId", "wxId", "gh"),
                    "brief": _first(it, "wechatIntruduction", "introduction",
                                    "brief", "desc"),
                    "qrcode": _first(it, "qrcode", "qrCode"),
                    "logo": _first(it, "wechatLogo", "logo"),
                })
    for it in _rows_of(weibos):
        if isinstance(it, dict):
            nm = _first(it, "nickname", "name", "weiboName")
            if nm:
                eq.weibos.append({
                    "name": nm,
                    "link": _first(it, "weiboLink", "link", "url"),
                    "brief": _first(it, "brief", "introduction", "desc"),
                    "logo": _first(it, "logo"),
                })
    for it in _rows_of(jobs):
        if isinstance(it, dict):
            nm = _first(it, "jobTitle", "title", "name")
            if nm:
                eq.jobs.append({
                    "name": nm,
                    "education": _first(it, "education", "edu"),
                    "location": _first(it, "location", "city", "address"),
                    "published": _first(it, "publishDate", "publishTime", "date"),
                    "desc": _first(it, "desc", "description", "requirement"),
                })
    for it in _rows_of(sups):
        if isinstance(it, dict):
            nm = _first(it, "supplier", "name", "supplierName")
            if nm:
                eq.suppliers.append({
                    "name": nm,
                    "cooperated": _first(it, "cooperationDate", "date", "reportDate"),
                    "source": _first(it, "source", "dataSource"),
                    "pid": _first(it, "supplierId", "pid"),
                })

    risk = _note_risk(eq, "aiqicha")
    # 额度为 0 时上面已经写明原因，别再补一句「登录态失效」把排查方向带偏
    if not (eq.holders or eq.invests) and not risk \
            and eq.source_status.get("aiqicha") != "quota":
        eq.notes.append("公开工商接口返回空（登录态失效，或该主体确实没有股东与对外投资）")
    if not eq.source_status.get("aiqicha"):
        has = bool(eq.holders or eq.invests or eq.branches or eq.icps
                   or eq.copyrights or eq.apps or eq.wechats or eq.weibos
                   or eq.jobs or eq.suppliers)
        eq.source_status["aiqicha"] = "ok" if has else ("blocked" if risk else "empty")
    elif risk and eq.source_status["aiqicha"] == "empty":
        eq.source_status["aiqicha"] = "blocked"
    return eq


_EM_TAG = re.compile(r"</?em>")
_NEXT_DATA = re.compile(
    r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', re.S)
_COMPANY_LINK = re.compile(
    r'href="https://www\.tianyancha\.com/company/(\d+)"[^>]*>(.*?)</a>', re.S)


def _tyc_from_pick(pick: dict) -> tuple[str, str, str]:
    """把一份登录态摊成 ``(x-auth-token, x-tycid, Cookie)``。

    池子条目写成字典时 token / tycid 自成一套，优先用那一套；只粘 Cookie 的条目
    从 Cookie 里抠；都抠不到才回落到 ``sources.tianyancha`` 单独填的两项——粘过
    Cookie 又另填一项的人，不该被 Cookie 里的旧值盖掉。
    """
    sec = _sec("tianyancha")
    cookie = str(pick.get("cred") or "").strip()
    extra = pick.get("extra") or {}
    token = str(extra.get("token") or "").strip()
    if not token:
        token = (sec.get("token") or "").strip()
    if not token:
        m = re.search(r"(?:^|;\s*)auth_token=([^;]+)", cookie)
        token = m.group(1).strip() if m else ""
    tycid = str(extra.get("tycid") or "").strip()
    if not tycid:
        tycid = (sec.get("tycid") or "").strip()
    if not tycid:
        m = re.search(r"(?:^|;\s*)TYCID=([^;]+)", cookie)
        tycid = m.group(1).strip() if m else ""
    return (token, tycid, cookie)


def _tyc_cred() -> tuple[str, str, str]:
    """天眼查当前该用的那份凭据：``(x-auth-token, x-tycid, Cookie)``。

    ``x-auth-token`` 就是登录态里的 ``auth_token`` JWT，``x-tycid`` 是 ``TYCID``；
    两个都能从整行 Cookie 里抠出来，所以只粘 Cookie 也能跑通。有配置池时从池子里
    取当前那一份，口径见 ``_tyc_from_pick``。
    """
    return _tyc_from_pick(creds.pick("tianyancha"))


def _tyc_sync(cli: httpx.AsyncClient) -> dict:
    """把池子当前那份刷进请求头，返回 ``pick``；换号后下一次请求就带新凭据。"""
    pick = creds.pick("tianyancha")
    token, tycid, cookie = _tyc_from_pick(pick)
    for key, val in (("x-auth-token", token), ("x-tycid", tycid), ("Cookie", cookie)):
        if val:
            cli.headers[key] = val
        else:
            cli.headers.pop(key, None)
    return pick


def _tyc_headers(token: str, tycid: str, cookie: str, name: str = "") -> dict:
    """天眼查接口只认这几个头，Cookie 只是兜底。

    这里不放 ``Content-Type``：这家有两条路，POST 的 JSON 正文要它，而分支机构 /
    备案只吃 GET 查询串，带着正文类型去 GET 会被回 ``state:error``。让 httpx 在
    发 POST 时自己按 ``json=`` 补上，两条路都不出错。
    """
    ref = f"{TIANYANCHA_WEB}/search?key={quote(name)}" if name else TIANYANCHA_WEB + "/"
    head = {"Accept": "application/json, text/plain, */*",
            "version": "TYC-Web",
            "Origin": TIANYANCHA_WEB,
            "Referer": ref}
    if token:
        head["x-auth-token"] = token
    if tycid:
        head["x-tycid"] = tycid
    if cookie:
        head["Cookie"] = cookie
    return head


def _tyc_pick(rows: list[tuple[str, str]], name: str, *,
              first: bool = False) -> tuple[str, str]:
    """从 ``[(登记全称, gid)]`` 里挑主体：完全一致优先，其次互相包含，再其次字号相等。

    核对口径和另一路工商一致：一个都对不上默认空手回去，不把别人的母子公司算进
    资产池。``first=True`` 时按检索首条对接，口径见 ``_aqc_pick``。
    """
    want = _norm_ent(name)
    best: tuple[int, str, str] = (0, "", "")
    for nm, gid in rows:
        cand = _norm_ent(nm)
        if not cand:
            continue
        if want and cand == want:
            score = 3
        elif want and len(want) >= 3 and (want in cand or cand in want):
            score = 2
        elif core_same(name, nm):
            # 简称对全称（差一个「市」/「有限公司」这种）：只认字号加区划都对得上
            score = 2
        else:
            score = 0
        if score > best[0]:
            best = (score, gid, nm)
    if best[0]:
        return (best[1], best[2])
    if first:
        for nm, gid in rows:
            if (nm or "").strip() and (gid or "").strip():
                return (gid, nm)
    return ("", "")


def _tyc_gid(html: str, name: str, *, first: bool = False) -> tuple[str, str]:
    """从搜索页 SSR 结果里挑出主体 gid，返回 ``(gid, 命中名)``。

    搜索页是服务端直出的，公司清单在 ``__NEXT_DATA__`` 里；名字带 ``<em>`` 高亮，
    比对前先剥掉。这条只当检索接口的兜底，能出 JSON 时优先走 ``_tyc_search``。
    ``first`` 口径同 ``_tyc_pick``。
    """
    rows: list[tuple[str, str]] = []
    m = _NEXT_DATA.search(html or "")
    if m:
        try:
            data = json.loads(m.group(1))
        except Exception:
            data = {}
        box = ((data.get("props") or {}).get("pageProps") or {}).get("listRes") or {}
        for it in ((box.get("data") or {}).get("companyList") or []):
            if not isinstance(it, dict):
                continue
            nm = _EM_TAG.sub("", str(it.get("name") or "")).strip()
            gid = str(it.get("id") or "").strip()
            if nm and gid:
                rows.append((nm, gid))
    if not rows:
        for mm in _COMPANY_LINK.finditer(html or ""):
            nm = _EM_TAG.sub("", re.sub(r"<[^>]+>", "", mm.group(2))).strip()
            if nm:
                rows.append((nm, mm.group(1)))
    return _tyc_pick(rows, name, first=first)


async def _tyc_search(cli: httpx.AsyncClient, name: str, *,
                      page_size: int = 20, page: int = 1) -> list[tuple[str, str]]:
    """名称 → ``[(登记全称, gid)]``，走检索接口的 JSON，不解析搜索页 HTML。

    回包形状是 ``data.companyList[]``，``id`` 就是主体 gid，``name`` 带 ``<em>``
    高亮。参数名必须是 ``word``：换成 ``keyword`` 会回「搜索词太宽泛」的空结果，
    换成 GET 直接 405——两种都看着像这家公司查不到。
    """
    body = await _tyc_post(cli, TYC_SEARCH,
                           {"word": name, "pageSize": page_size, "pageNum": page})
    if not isinstance(body, dict) or body.get("__risk"):
        return []
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    out: list[tuple[str, str]] = []
    for it in data.get("companyList") or []:
        if not isinstance(it, dict):
            continue
        nm = _EM_TAG.sub("", str(it.get("name") or "")).strip()
        gid = str(it.get("id") or "").strip()
        if nm and gid:
            out.append((nm, gid))
    return out


async def _tyc_locate(cli: httpx.AsyncClient, name: str, *,
                      strict: bool = False, first: bool = False) -> tuple[str, str]:
    """名称 → ``(gid, 登记全称)``：先打检索接口，抽不出主体再退回搜索页 SSR。

    ``strict`` 只认完全一致，回查链路里的登记全称时用：互相包含会把
    「某某人才」和「某某人才发展集团」串成一棵别人的子树。
    ``first`` 一个都对不上时按检索首条对接（口径见 ``_aqc_pick``），只给
    「先要链路、名字回头核对」的入口用。
    """
    gid, hit = "", ""
    try:
        gid, hit = _tyc_pick(await _tyc_search(cli, name), name, first=first)
    except Exception:
        gid, hit = "", ""
    if not gid:
        try:
            _tyc_sync(cli)
            await _pace("tianyancha")
            r = await cli.get(f"{TIANYANCHA_WEB}/search", params={"key": name})
        except Exception:
            r = None
        if r is not None and r.status_code == 200:
            gid, hit = _tyc_gid(r.text, name, first=first)
    if strict and gid and _norm_ent(hit) != _norm_ent(name):
        return ("", "")
    return (gid, hit)


async def resolve_name(name: str) -> str:
    """简称 → 工商登记全称。只做一次主体检索，不取股东、不穿透。

    备案库按单位名精确匹配，拿「小米」去查必然 0 条；先对齐到
    「小米科技有限责任公司」，再用全称去查才有数据。
    """
    want = (name or "").strip()
    if not want:
        return ""
    # 1) 天眼查：先打检索接口，抽不出主体再退搜索页 SSR
    token, tycid, cookie = _tyc_cred()
    if token or cookie:
        try:
            async with _client(referer=f"{TIANYANCHA_WEB}/search?key={quote(want)}") as cli:
                cli.headers.update(_tyc_headers(token, tycid, cookie, want))
                _gid, hit = await _tyc_locate(cli, want)
            if hit:
                return hit
        except Exception:
            pass
    # 2) 公开工商接口的筛选列表 / suggest
    cookie = _aqc_ready()
    if cookie:
        try:
            async with _client(referer=f"{INVEST_API}/s?q={quote(want)}") as cli:
                cli.headers.update({"Cookie": cookie})
                found = await _aqc_get(cli, "/s/advanceFilterAjax",
                                       {"q": want, "p": 1, "s": 10, "o": 0, "f": "{}", "t": 0})
                _pid, hit = _aqc_pick(found, want)
                if hit:
                    return hit
                sug = await _aqc_post(cli, "/index/suggest", {"q": want, "t": 0})
                _pid, hit = _aqc_pick(sug, want)
                if hit:
                    return hit
        except Exception:
            pass
    return ""


async def aqc_icp(name: str, *, pages: int = 1, size: int = 100) -> list[dict]:
    """公开工商接口的备案信息：主体 → 域名 + 备案号。

    这是备案反查的第二条数据源。内置备案引擎被挡 / 频控时，
    只要工商登录态还有效，这里通常仍能拿到该主体名下登记的域名。

    三个细节决定这个口出不出数：检索回的 ``pid`` 要按 ``ddw`` 逐位还原（否则一律
    ``系统异常 / data=null``）；面板接口在 ``detail/icpinfoAjax``（不是 ``cs/``）；
    分页参数是 ``size``（不是 ``s``）。一条备案常挂多个域名，``domain`` 是数组。
    """
    cookie = _aqc_ready()
    want = (name or "").strip()
    if not cookie or not want:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    try:
        async with _client(referer=f"{INVEST_API}/s?q={quote(want)}") as cli:
            cli.headers.update({"Cookie": cookie})
            found = await _aqc_get(cli, "/s/advanceFilterAjax",
                                   {"q": want, "p": 1, "s": 10, "o": 0, "f": "{}", "t": 0})
            pid, hit = _aqc_pick(found, want)
            if pid and isinstance(found, dict):
                pid = _aqc_pid_decode(pid, found.get("ddw"))
            if not pid:
                sug = await _aqc_post(cli, "/index/suggest", {"q": want, "t": 0})
                pid, hit = _aqc_pick(sug, want)
                if pid and isinstance(sug, dict):
                    pid = _aqc_pid_decode(pid, sug.get("ddw"))
            if not pid:
                return []
            body = await _aqc_panel_all(cli, "detail/icpinfoAjax", pid,
                                        page_size=max(10, int(size or 100)),
                                        pages=max(1, int(pages or 1)),
                                        cap=max(10, int(size or 100)) * max(1, int(pages or 1)))
            data = body.get("data") or {}
            rows = data.get("list") if isinstance(data, dict) else None
            for it in _aqc_icp_rows(rows if isinstance(rows, list) else []):
                if not it.get("unit"):
                    it["unit"] = hit or want
                # 老调用方读 ``icp``，新口径读 ``licence``；两个都填，别让下游取到空
                it["icp"] = it.get("licence") or ""
                if it["domain"] in seen:
                    continue
                seen.add(it["domain"])
                out.append(it)
    except Exception:
        return out
    return out


async def _tyc_probe() -> dict:
    """天眼查连通测试：检索接口能出主体才算登录态被认。

    以前只探搜索页：页面能打开时探测报「有效」，而真正取数的股东 / 投资接口可能全
    被拒。这里先打取数口（检索），拿不到再从 SSR 兜底。
    """
    token, tycid, cookie = _tyc_cred()
    url = f"{TIANYANCHA_WEB}/search?key=%E5%B0%8F%E7%B1%B3%E7%A7%91%E6%8A%80"
    if not (cookie or token):
        return {"ok": False, "msg": "未填写凭据，先在上面填入登录态再测"}
    note = _jwt_note(token)
    if note:
        return {"ok": False, "msg": note, "base": url}
    try:
        async with _client(timeout=15.0, referer=TIANYANCHA_WEB) as cli:
            cli.headers.update(_tyc_headers(token, tycid, cookie, "小米科技"))
            rows = await _tyc_search(cli, "小米科技", page_size=5)
            if rows:
                _gid, hit = _tyc_pick(rows, "小米科技")
                return {"ok": True,
                        "msg": f"检索接口正常，登录态有效（命中「{hit or rows[0][0]}」）",
                        "base": url}
            gate = _GATE_LAST.get("tianyancha", "")
            if gate:
                return {"ok": False,
                        "msg": f"{gate}，Cookie / 令牌需要重新取", "base": url}
            r = await cli.get(f"{TIANYANCHA_WEB}/search", params={"key": "小米科技"})
            html = r.text or ""
    except Exception as e:
        return {"ok": False, "msg": f"{url} 请求失败：{type(e).__name__}"[:200], "base": url}
    if r.status_code in (401, 403, 412, 423, 429):
        return {"ok": False, "msg": f"HTTP {r.status_code}，凭据被拒或被限流，Cookie 需要重新取",
                "base": url}
    if r.status_code != 200:
        return {"ok": False, "msg": f"HTTP {r.status_code}，对方拒绝了这次探测请求", "base": url}
    gid, hit = _tyc_gid(html, "小米科技")
    if gid:
        return {"ok": True, "msg": f"HTTP 200，登录态有效（搜索命中「{hit}」）", "base": url}
    if "请登录" in html[:4000] or "登录后" in html[:4000]:
        return {"ok": False, "msg": "HTTP 200 但搜索页要求登录，Cookie 需要重新取", "base": url}
    return {"ok": False, "msg": "HTTP 200 但搜索页没解析出主体（登录态失效或页面结构已变）",
            "base": url}


# 门槛和风控是两件事：风控是打得太密，门槛是这个账号没有这一面的权限。
# 混成一类会被当成封号把整个来源冷却掉，还把「没会员」说成「这家没有子公司」。
_TYC_GATES = (
    ("mustvip", "该账号没有这一面的会员权限"),
    ("mustlogin", "登录态已失效"),
    ("unauthorized api", "登录态已失效"),
    ("请登录以使用完整功能", "登录态已失效"),
)
_GATE_LAST: dict[str, str] = {}


def _tyc_gate(body) -> str:
    """回包若是「权限 / 登录门槛」，返回一句人话；正常业务回包返回空串。"""
    if not isinstance(body, dict):
        return ""
    msg = " ".join(str(body.get(k) or "") for k in ("message", "msg")).strip()
    low = msg.lower()
    for word, why in _TYC_GATES:
        if word in low:
            return why
    return ""


def _tyc_base() -> str:
    """天眼查接口域名。旧配置里存过已停用的静态桶域名，命中就退回当前接口域名。"""
    base = (_sec("tianyancha").get("api") or "").strip().rstrip("/")
    if not base or "tianyancha.com" in base and not base.startswith(TIANYANCHA_API):
        return TIANYANCHA_API
    return base


async def _tyc_call(cli: httpx.AsyncClient, path: str, *,
                    payload: dict | None = None,
                    params: dict | None = None) -> dict:
    """天眼查统一出口：先过节流闸，回包认风控。

    这家两条路的写法不统一：检索 / 投资 / 股东只吃 POST 的 JSON 正文，分支机构 /
    备案只吃 GET 的查询串，用错方法一律 ``state:error``、405 或「系统异常」，
    看着就像接口没了。``payload`` 给出走 POST，``params`` 给出走 GET。
    """
    base = _tyc_base()
    data: dict = {}
    attempts = _retry_times()
    # 与爱企查同一套逻辑：被风控就换池子里下一份登录态重来，换号不算重试次数
    switch_left = max(0, creds.count("tianyancha") - 1)
    tries = 0
    while tries < attempts:
        tries += 1
        pick = _tyc_sync(cli)
        if not await throttle.acquire("tianyancha"):
            _RISK_LAST["tianyancha"] = "第二工商来源冷却中，这一轮跳过该请求"
            return {"__risk": _RISK_LAST["tianyancha"]}
        await _pace("tianyancha")
        again = False
        try:
            if payload is not None:
                r = await cli.post(base + path, json=payload)
            else:
                r = await cli.get(base + path, params=params or {})
        except Exception:
            again = True
        else:
            hit = ""
            if r.status_code == 429:
                hit = "HTTP 429"
            elif r.status_code in (401, 403):
                hit = f"HTTP {r.status_code}"
            if hit:
                creds.report("tianyancha", pick["cred"],
                             "blocked" if r.status_code == 429 else "invalid")
                if switch_left > 0:
                    switch_left -= 1
                    tries -= 1
                    _RISK_LAST["tianyancha"] = (
                        f"第二工商来源 {hit}，已换下一份登录态重试")
                    continue
                if r.status_code == 429:
                    return _mark_risk("tianyancha", "HTTP 429", "第二工商来源")
                return {}
            if r.status_code >= 500:
                again = True
            elif r.status_code != 200:
                return {}
            else:
                try:
                    parsed = r.json()
                except Exception:
                    again = True
                else:
                    gate = _tyc_gate(parsed)
                    if gate:
                        # 门槛不算风控：照常给节流器记一次成功，冷却留给真被封的时候用，
                        # 否则一个会员面就能把这个来源整轮打成「不可用」。
                        _GATE_LAST["tianyancha"] = gate
                        throttle.reward("tianyancha")
                        return {"__gate": gate}
                    _GATE_LAST.pop("tianyancha", None)
                    hit = risk_hit(parsed)
                    if hit:
                        creds.report("tianyancha", pick["cred"], "blocked")
                        if switch_left > 0:
                            switch_left -= 1
                            tries -= 1
                            _RISK_LAST["tianyancha"] = (
                                f"第二工商来源被风控（{hit}），已换下一份登录态重试")
                            continue
                        return _mark_risk("tianyancha", hit, "第二工商来源")
                    data = parsed
                    throttle.reward("tianyancha")
                    creds.report("tianyancha", pick["cred"], "ok")
        if not again:
            break
        if tries < attempts:
            await asyncio.sleep(max(1.0, _expand_sleep()) * tries)
    return data


async def _tyc_post(cli: httpx.AsyncClient, path: str, payload: dict) -> dict:
    """POST 那一半：检索 / 投资 / 股东。"""
    return await _tyc_call(cli, path, payload=payload)


async def _tyc_get(cli: httpx.AsyncClient, path: str, params: dict) -> dict:
    """GET 那一半：分支机构 / 备案，参数全在查询串上。"""
    return await _tyc_call(cli, path, params=params)


def _mark_budget_cut(budget: dict | None, got: int, total: int, label: str) -> None:
    """额度见底、页还没翻完就收手：把这件事写进调用方传进来的 budget 记账本。

    不写这一句，用户只看到「工商来源可用」加一张短清单，永远猜不到是额度被吃光；
    额度是「翻投资页 + 往上追股东 + 逐层穿子公司」三件事共用的，很容易被第一层花完。
    """
    if not isinstance(budget, dict):
        return
    if total and got >= total:
        return
    if budget.get("cut"):
        return
    budget["cut"] = (f"{label}只取到 {got} 家"
                     + (f" / 共 {total} 家" if total else "")
                     + "，请求额度已用尽；调「请求额度」或单阶段重跑补上")


async def _tyc_invest_all(cli: httpx.AsyncClient, gid: str, *,
                          page_size: int = 100, cap: int = 400,
                          budget: dict | None = None) -> list[dict]:
    """对外投资全量分页。

    一页就是 ``pageSize`` 家，``data.total`` 才是真实家数：只取首屏时，
    投资几十家的集团会被截成十家。每次请求之前都走同一份节拍（``scan.equity_sleep``），
    避免连着几十页把账号打进风控。
    """
    out: list[dict] = []
    if not gid:
        return out
    seen: set[str] = set()
    total_seen = 0
    page = 1
    cut = False
    # 额度调成「不限」时把单层封顶一起放开：集团主体对外投资上千家，
    # 还按 400 家 / 30 页截断的话，加了额度也拿不到多出来的那些。
    if isinstance(budget, dict) and int(budget.get("left", 0)) >= _BUDGET_UNLIMITED:
        cap = max(cap, 2000)
    max_pages = max(30, (cap + page_size - 1) // page_size)
    while len(out) < cap and page <= max_pages:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 0:
            cut = True
            break
        body = await _tyc_post(cli, TYC_INVEST,
                               {"gid": gid, "pageSize": page_size,
                                "pageNum": page, "benefitSharesType": 1})
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        if not isinstance(body, dict) or body.get("__risk"):
            break
        total, rows = _aqc_rows(body, "result")
        total_seen = total or total_seen
        if not rows:
            break
        fresh = 0
        for it in rows:
            key = str(it.get("id") or "").strip() or str(it.get("name") or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(it)
            fresh += 1
        if not fresh:
            break
        if total and len(out) >= total:
            break
        page += 1
    if cut:
        _mark_budget_cut(budget, len(out), total_seen, "对外投资")
    elif (total_seen and len(out) < int(total_seen) and isinstance(budget, dict)
          and (len(out) >= cap or page > max_pages)):
        # 不是额度砍的：单层 400 家封顶 / 上游只肯给 30 页。这种截断同样要落一句，
        # 否则清单短了用户只会去调额度，调多少都还是这个数。
        budget.setdefault(
            "cut",
            f"对外投资翻页封顶：该主体共 {int(total_seen)} 家，本轮取到 {len(out)} 家")
    if isinstance(budget, dict):
        budget["__total"] = total_seen
    return out


async def _tyc_hold_all(cli: httpx.AsyncClient, gid: str, *,
                        page_size: int = 20, cap: int = 600,
                        budget: dict | None = None,
                        gate: dict | None = None) -> tuple[list[dict], int]:
    """控股企业全量分页，返回 ``(控股行, 上游报的总家数)``。

    和对外投资不是同一份清单：对外投资只给「直接投出去的那些」，隔着几层的控股
    子公司只在这一面。这个口是 GET + 查询串（``graphId`` / ``id`` / ``gid`` 都给
    同一个主体），行数组在 ``data.list``，``cid`` 才是子主体可用于继续往下穿的 id。
    ``gate`` 传一个字典进来时，遇到权限 / 登录门槛会把原因写进去：这一面普通账号
    是 ``mustvip``，混进「没数据」里会被读成「这家没有控股子公司」。
    """
    out: list[dict] = []
    if not gid:
        return (out, 0)
    seen: set[str] = set()
    total_seen = 0
    page = 1
    cut = False
    while len(out) < cap and page <= 30:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 0:
            cut = True
            break
        body = await _tyc_get(cli, TYC_HOLD,
                              {"graphId": gid, "id": gid, "gid": gid,
                               "pageSize": page_size, "pageNum": page})
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        if not isinstance(body, dict) or body.get("__risk"):
            break
        if body.get("__gate"):
            if isinstance(gate, dict):
                gate["why"] = str(body["__gate"])
            break
        total, rows = _aqc_rows(body, "list")
        if not total and isinstance(body.get("data"), dict):
            # 这一面的总数不叫 total：挨个试几处常见键，别只认一种写法。
            for k in ("itemTotal", "count", "finalInvestCount"):
                total = _num(body["data"].get(k)) or total
        total_seen = total or total_seen
        if not rows:
            break
        fresh = 0
        for it in rows:
            nm = str(it.get("name") or "").strip()
            key = nm or str(it.get("cid") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            rec = dict(it)
            # 这一面的主体 id 叫 ``cid``；``_tyc_edge`` 按 ``id`` 取，先对齐再交出去。
            if not str(rec.get("id") or "").strip():
                rec["id"] = str(it.get("cid") or "").strip()
            out.append(rec)
            fresh += 1
        if not fresh:
            break
        if total and len(out) >= total:
            break
        page += 1
    if cut:
        _mark_budget_cut(budget, len(out), total_seen, "控股企业")
    elif (total_seen and len(out) < int(total_seen) and isinstance(budget, dict)
          and (len(out) >= cap or page > 30)):
        budget.setdefault(
            "cut", f"控股企业翻页封顶：该主体共 {int(total_seen)} 家，本轮取到 {len(out)} 家")
    return (out, total_seen)


def _tyc_branch_rows(rows) -> list[dict]:
    """分支行 → 与另一路同形的分支记录。

    这家的分支行没有注册资本、没有注册地址，``id`` 是分支自己的 companyId 而不是
    可继续穿的主体 id：缺的留空，别让导出表里出现一堆 ``None``。
    """
    out: list[dict] = []
    for it in rows if isinstance(rows, list) else []:
        if not isinstance(it, dict):
            continue
        nm = str(it.get("name") or "").strip()
        if not nm:
            continue
        out.append({
            "name": nm,
            "legal": _first(it, "legalPersonName", "legalPersonAlias", "legalPerson"),
            "status": _first(it, "regStatus", "serviceType"),
            "pid": _first(it, "id", "companyId"),
            "capital": _first(it, "regCapital", "capital"),
            "established": _first(it, "estiblishTime", "estiblishDate", "regDate"),
            "address": _first(it, "area", "regAddr", "regAddress", "address"),
            "source": "tyc",
        })
    return out


async def _tyc_branch_all(cli: httpx.AsyncClient, gid: str, *,
                          page_size: int = 100, cap: int = 600,
                          budget: dict | None = None) -> tuple[list[dict], int]:
    """分支机构全量分页，返回 ``(分支行, 上游报的总家数)``。

    行数组在 ``data.result``（不是 ``list``），真实家数在 ``data.total``：大行挂几千
    家分支，只取首屏等于没有。每页一次请求，额度按 ``budget['left']`` 记账，
    被额度或页上限砍短要把原因写进 ``budget['cut']``，别让人以为这家没有分支。
    """
    out: list[dict] = []
    if not gid:
        return (out, 0)
    seen: set[str] = set()
    total_seen = 0
    page = 1
    # 大行挂几千家分支；额度不限时别用 600 家封顶，否则调了额度还是这张短表。
    if isinstance(budget, dict) and int(budget.get("left", 0)) >= _BUDGET_UNLIMITED:
        cap = max(cap, 2000)
    max_page = max(1, (cap + page_size - 1) // page_size)
    cut = False
    while len(out) < cap and page <= max_page:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 0:
            cut = True
            break
        body = await _tyc_get(cli, TYC_BRANCH,
                              {"gid": gid, "pageSize": page_size, "pageNum": page})
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        if not isinstance(body, dict) or body.get("__risk"):
            break
        total, rows = _aqc_rows(body, "result")
        total_seen = total or total_seen
        rows = _tyc_branch_rows(rows)
        if not rows:
            break
        fresh = 0
        for it in rows:
            if it["name"] in seen:
                continue
            seen.add(it["name"])
            out.append(it)
            fresh += 1
        if not fresh:
            break
        if total_seen and len(out) >= total_seen:
            break
        page += 1
    if cut:
        _mark_budget_cut(budget, len(out), total_seen, "分支机构")
    elif total_seen and len(out) < total_seen and isinstance(budget, dict):
        budget.setdefault(
            "cut", f"分支机构翻页封顶：该主体共 {total_seen} 家，本轮取到 {len(out)} 家")
    return (out, total_seen)


def _tyc_icp_rows(rows) -> list[dict]:
    """备案行 → 一条域名一行。

    域名在 ``ym``（主域名）另加 ``webSite[]``；备案号原样拼写在 ``liscense`` 里
    （上游就是这个拼法，别照 ``licence`` 猜）。一个备案号常挂多个域名，拆开才能
    和另一路的备案表并进同一张表。
    """
    out: list[dict] = []
    for it in rows if isinstance(rows, list) else []:
        if not isinstance(it, dict):
            continue
        doms: list[str] = []
        ym = str(it.get("ym") or "").strip()
        if ym:
            doms.append(ym)
        site = it.get("webSite")
        if isinstance(site, list):
            for d in site:
                if isinstance(d, dict):
                    d = d.get("ym") or d.get("domain") or d.get("url") or ""
                d = str(d or "").strip()
                if d:
                    doms.append(d)
        elif isinstance(site, str) and site.strip():
            doms.append(site.strip())
        site_name = _first(it, "webName", "siteName", "homeSite")
        licence = _first(it, "liscense", "licence", "icpNo")
        unit = _first(it, "companyName", "unitName", "unit")
        for d in dict.fromkeys(doms):
            d = str(d).replace("http://", "").replace("https://", "")
            d = d.split("/")[0].strip().lower()
            if not d:
                continue
            out.append({"domain": d, "site_name": site_name, "licence": licence,
                        "unit": unit, "source": "tyc"})
    return out


async def _tyc_icp_all(cli: httpx.AsyncClient, gid: str, *,
                       page_size: int = 100, cap: int = 300,
                       budget: dict | None = None) -> tuple[list[dict], int]:
    """备案面板全量分页，返回 ``(备案行, 上游报的总条数)``。

    主体参数叫 ``id``（不是 ``gid`` / ``pid``），行数组键是 ``item``，总数在
    ``data.itemTotal``：照 ``list`` / ``total`` 去读会一律拿到空，看起来像这家
    主体没有备案。
    """
    out: list[dict] = []
    if not gid:
        return (out, 0)
    seen: set[str] = set()
    total_seen = 0
    page = 1
    max_page = max(1, (cap + page_size - 1) // page_size)
    cut = False
    while len(out) < cap and page <= max_page:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 0:
            cut = True
            break
        body = await _tyc_get(cli, TYC_ICP,
                              {"id": gid, "pageSize": page_size, "pageNum": page})
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        if not isinstance(body, dict) or body.get("__risk"):
            break
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        total_seen = _num(data.get("itemTotal")) or total_seen
        rows = _tyc_icp_rows(data.get("item"))
        if not rows:
            break
        fresh = 0
        for it in rows:
            if it["domain"] in seen:
                continue
            seen.add(it["domain"])
            out.append(it)
            fresh += 1
        if not fresh:
            break
        if total_seen and len(out) >= total_seen:
            break
        page += 1
    if cut:
        _mark_budget_cut(budget, len(out), total_seen, "备案")
    elif total_seen and len(out) < total_seen and isinstance(budget, dict):
        budget.setdefault(
            "cut", f"备案翻页封顶：该主体共 {total_seen} 条，本轮取到 {len(out)} 条")
    return (out, total_seen)


def _tyc_edge(it: dict, parent: str, parent_acc: float | None, depth: int) -> dict | None:
    """投资行 → 链路节点。首层用工商给的合计持股，更深层按上一级累计相乘。"""
    child = str(it.get("name") or "").strip()
    if not child or child == parent:
        return None
    pct = _pct(it.get("percent"))
    if parent_acc is None:
        acc = _pct(it.get("totalPercent")) or pct
    else:
        acc = round(parent_acc * pct / 100.0, 2)
    return {"name": child, "parent": parent, "ratio": pct, "acc_ratio": round(acc, 2),
            "depth": depth, "pid": str(it.get("id") or ""), "src": "tianyancha",
            "capital": it.get("amount") or it.get("regCapital") or "",
            "status": it.get("regStatus") or ""}


async def _tyc_expand(cli: httpx.AsyncClient, root_name: str, chain: list[dict], *,
                      depth: int, ratio: float, budget: dict) -> None:
    """按层穿控股枝：子公司 → 孙公司。

    ``ratio`` 是结果门槛，不当下钻门槛：参股三成的子公司同样有自己的全资孙公司，
    按门槛卡住会把整棵子树砍掉。翻不翻由额度管（已按累计持股从高到低排）。
    """
    if depth <= 1 or not chain:
        return
    seen: set[tuple[str, str]] = {(str(c.get("parent") or ""), str(c.get("name") or ""))
                                  for c in chain}
    level = [c for c in chain if int(c.get("depth") or 1) == 1]
    for _ in range(1, int(depth)):
        nxt: list[dict] = []
        for node in sorted(level, key=lambda c: -float(c.get("acc_ratio") or 0)):
            if int(budget.get("left", 0)) <= 0:
                _mark_budget_cut(budget, len(nxt), 0, "逐层子公司穿透")
                break
            pid = str(node.get("pid") or "")
            base = float(node.get("acc_ratio") or 0)
            # 只要还持有一点就值得翻
            if not pid or base <= 0:
                continue
            _prog(f"股权穿透：翻「{node.get('name') or root_name}」的对外投资"
                  f"（第 {int(node.get('depth') or 1) + 1} 层，累计 {base:.2f}%）")
            rows = await _tyc_invest_all(cli, pid, budget=budget)
            for it in rows:
                rec = _tyc_edge(it, str(node.get("name") or root_name), base,
                                int(node.get("depth") or 1) + 1)
                if not rec:
                    continue
                key = (rec["parent"], rec["name"])
                if key in seen:
                    continue
                seen.add(key)
                chain.append(rec)
                # 同上：这一路的逐层穿也是串行的，边穿边往外报，别等整趟返回。
                _beat({"name": root_name, "chain": chain})
                # 同爱企查：持股大于 0 就往下穿一层，结果门槛只决定哪些算「控股」。
                if float(rec["acc_ratio"]) > 0:
                    nxt.append(rec)
        if not nxt:
            break
        level = nxt


async def _tyc_holders(cli: httpx.AsyncClient, gid: str, *, page_size: int = 100,
                       cap: int = 300,
                       budget: dict | None = None) -> list[dict]:
    """股东列表（分页）。机构股东的上游 gid 在 ``shareHolderGid``，自然人不穿。

    只取第一页时股东过百的主体上半截全丢，最终受益人折算跟着错；这里按
    ``data.total`` 往下翻，页数受 ``cap`` 和 ``budget`` 管，砍短留不了痕迹的
    问题交给调用方记账。
    """
    out: list[dict] = []
    if not gid:
        return out
    seen: set[tuple[str, str]] = set()
    total_seen = 0
    page = 1
    max_page = max(1, (cap + page_size - 1) // page_size)
    while len(out) < cap and page <= max_page:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 0:
            _mark_budget_cut(budget, len(out), total_seen, "股东")
            break
        body = await _tyc_post(cli, TYC_HOLDER,
                               {"gid": gid, "pageSize": page_size, "pageNum": page})
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        if not isinstance(body, dict) or body.get("__risk"):
            break
        total, rows = _aqc_rows(body, "result")
        total_seen = total or total_seen
        if not rows:
            break
        fresh = 0
        for it in rows:
            nm = str(it.get("shareHolderName") or it.get("name") or "").strip()
            if not nm:
                continue
            org = str(it.get("shareHolderType") or "") == "2" or bool(it.get("jigouName"))
            key = (nm, str(it.get("shareHolderGid") or "") if org else "")
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": nm, "ratio": _pct(it.get("percent")),
                        "pid": key[1],
                        "type": "机构" if org else "",
                        "final": _pct(it.get("finalBenefitShares")),
                        "tag": str(it.get("shareHolderTypeOnPage") or "")})
            fresh += 1
        if not fresh:
            break
        if total_seen and len(out) >= total_seen:
            break
        page += 1
    return out


async def _tyc_fill_upstream(cli: httpx.AsyncClient, rows: list[dict], levels: int,
                             branches: int, depth: int = 1,
                             budget: dict | None = None) -> None:
    """机构股东再往上拉股东，挂回 ``rows[i]['holders']`` 给 UBO 折算。

    每层最多 ``branches`` 家、总共 ``levels`` 层；每一次请求都走 ``scan.equity_sleep``
    节拍，次数快用完就收手。
    """
    if depth > levels or branches <= 0:
        return
    targets = [h for h in rows if isinstance(h, dict) and h.get("pid")]
    for h in targets[:branches]:
        if isinstance(budget, dict) and int(budget.get("left", 0)) <= 1:
            return
        if isinstance(budget, dict):
            budget["left"] = int(budget.get("left", 0)) - 1
        kids = await _tyc_holders(cli, str(h["pid"]))
        if not kids:
            continue
        h["holders"] = kids
        await _tyc_fill_upstream(cli, kids, levels, max(1, branches - 1), depth + 1, budget)


async def _tyc_gid_lookup(cli: httpx.AsyncClient, name: str, *, cookie: str = "") -> str:
    """名称 → 工商第二来源的主体 id，供补穿使用。

    搜索对「互相包含」的名字也会出结果（某某人才 vs 某某人才发展集团），补穿是从
    已有的链路上按全称回查，一次对歪就会把整棵别人的子树挂进来，所以这里只认全称
    完全一致（``strict``）。
    """
    try:
        gid, _hit = await _tyc_locate(cli, name, strict=True)
    except Exception:
        return ""
    return gid


async def _tyc_fill_gap(name: str, eq, *, depth: int, ratio: float) -> int:
    """一路工商额度用尽时，用还健康那一路把对方留下的空位补穿。

    背景：两路工商各自有免费额度，先耗尽的那一路会在某一层突然只剩一半子公司，
    而另一路还有额度。以前合并只看「这轮谁先回来」，这部分就永久缺着，现场表现是
    「明明查到了 20 家控股子公司，图上只有 5 家」。

    这里只补「另一路给出来的一级节点、但那一侧没有再往下穿」的那部分，节点数与
    请求次数都随 ``scan.equity_budget`` 放大，每次请求都照走 ``scan.equity_sleep``。
    """
    if depth <= 1:
        return 0
    have = {str(c.get("name") or "") for c in eq.chain}
    todo: list[dict] = []
    for c in eq.chain:
        if int(c.get("depth") or 1) != 1:
            continue
        if str(c.get("src") or "") == "tianyancha":
            continue
        nm = str(c.get("name") or "")
        if not nm or float(c.get("acc_ratio") or 0) <= 0:
            continue
        todo.append(c)
    if not todo:
        return 0
    # 累计持股高的先补：额度不够时，至少把集团主业那几家穿下去。
    # 这一步的「只补 4 家」和下面 12 次请求都是硬上限，砍短了必须写进截断说明，
    # 否则用户看到的还是「某层的子公司凭空少了一半」，查不出是谁砍的。
    # 两个上限都跟着「请求额度」走：以前写死 4 家，把额度调到 300 也还是只补 4 家，
    # 剩下的一级子公司永远停在图上不往下穿，看着就像「穿透不全」。
    todo.sort(key=lambda c: -float(c.get("acc_ratio") or 0))
    eq_budget = max(5, _expand_budget())
    unlimited = eq_budget >= _BUDGET_UNLIMITED
    # 不限额时不能再套 10 家 / 30 次这两个写字数：额度已经调成「不限」还被砍在半截，
    # 用户只会以为穿透本身不全，怎么调参数都没变化。
    cap_nodes = min(len(todo), 40) if unlimited else max(4, min(10, eq_budget // 6))
    dropped = max(0, len(todo) - cap_nodes)
    todo = todo[:cap_nodes]
    if dropped:
        eq.cap_notes.setdefault(
            "gap", f"跨来源补穿这轮只补 {cap_nodes} 个一级节点，另有 {dropped} 家没往下穿")
    token, tycid, cookie = _tyc_cred()
    if not (token or cookie):
        return 0
    budget = {"left": max(12, min(30, eq_budget // 3))} if not unlimited else \
        {"left": min(400, max(30, cap_nodes * 4))}
    added = 0
    try:
        async with _client(referer=TIANYANCHA_WEB) as cli:
            cli.headers.update(_tyc_headers(token, tycid, cookie, name))
            for i, node in enumerate(todo):
                if int(budget.get("left", 0)) <= 0:
                    eq.cap_notes.setdefault(
                        "gap", f"跨来源补穿请求次数用尽，只补了 {i} 个一级节点就停了")
                    break
                nm = str(node.get("name") or "")
                gid = await _tyc_gid_lookup(cli, nm, cookie=cookie)
                if not gid:
                    continue
                synth = [{"name": nm, "parent": str(node.get("parent") or name),
                          "ratio": node.get("ratio") or node.get("acc_ratio") or 0,
                          "acc_ratio": float(node.get("acc_ratio") or 0), "depth": 1,
                          "pid": gid, "src": "tianyancha",
                          "capital": node.get("capital") or "",
                          "status": node.get("status") or ""}]
                await _tyc_expand(cli, nm, synth, depth=depth, ratio=ratio,
                                  budget=budget)
                for c in synth[1:]:
                    cn = str(c.get("name") or "")
                    if cn and cn not in have:
                        eq.chain.append(c)
                        have.add(cn)
                        added += 1
                if added:
                    _beat(eq)
    except Exception:
        return added
    if added:
        eq.notes.append(f"有一路工商额度用尽，已用另一路补穿出 {added} 个下游主体")
    return added


async def _aqc_fill_gap(name: str, eq, *, depth: int, ratio: float) -> int:
    """天眼查那一路这轮没跑全时，反过来用爱企查把对方留下的空位补穿。

    `_tyc_fill_gap` 只覆盖「爱企查停摆、天眼查还在」一个方向；反过来（天眼查额度尽 /
    被风控 / 没检索到 / 只回半截）以前完全没人接，链路就停在对方给出的那一层。
    补法与前一个方向同一套：只挑一级节点里不是本路给的、还没往下穿的，逐家查 pid
    再展开；请求照走 ``scan.equity_sleep``，节点数与次数跟着 ``scan.equity_budget``。
    """
    if depth <= 1:
        return 0
    cookie = _aqc_ready()
    if not cookie:
        return 0
    have = {str(c.get("name") or "") for c in eq.chain}
    todo: list[dict] = []
    for c in eq.chain:
        if int(c.get("depth") or 1) != 1:
            continue
        if str(c.get("src") or "") == "aiqicha":
            continue
        nm = str(c.get("name") or "")
        if not nm or float(c.get("acc_ratio") or 0) <= 0:
            continue
        todo.append(c)
    if not todo:
        return 0
    todo.sort(key=lambda c: -float(c.get("acc_ratio") or 0))
    eq_budget = max(5, _expand_budget())
    unlimited = eq_budget >= _BUDGET_UNLIMITED
    cap_nodes = min(len(todo), 40) if unlimited else max(4, min(10, eq_budget // 6))
    dropped = max(0, len(todo) - cap_nodes)
    todo = todo[:cap_nodes]
    if dropped:
        eq.cap_notes.setdefault(
            "gap", f"跨来源补穿这轮只补 {cap_nodes} 个一级节点，另有 {dropped} 家没往下穿")
    budget = {"left": max(12, min(30, eq_budget // 3))} if not unlimited else \
        {"left": min(400, max(30, cap_nodes * 4))}
    added = 0
    try:
        async with _client(referer=INVEST_API) as cli:
            cli.headers.update({"Cookie": cookie})
            for i, node in enumerate(todo):
                if int(budget.get("left", 0)) <= 0:
                    eq.cap_notes.setdefault(
                        "gap", f"跨来源补穿请求次数用尽，只补了 {i} 个一级节点就停了")
                    break
                nm = str(node.get("name") or "")
                found = await _aqc_get(cli, "/s/advanceFilterAjax",
                                       {"q": nm, "p": 1, "s": 10, "o": 0,
                                        "f": "{}", "t": 0})
                pid, _hit = _aqc_pick(found, nm, first=True)
                if pid and isinstance(found, dict):
                    pid = _aqc_pid_decode(pid, found.get("ddw"))
                if not pid:
                    sug = await _aqc_post(cli, "/index/suggest", {"q": nm, "t": 0})
                    pid, _hit = _aqc_pick(sug, nm, first=True)
                    if pid and isinstance(sug, dict):
                        pid = _aqc_pid_decode(pid, sug.get("ddw"))
                if not pid:
                    continue
                synth = [{"name": nm, "parent": str(node.get("parent") or name),
                          "ratio": node.get("ratio") or node.get("acc_ratio") or 0,
                          "acc_ratio": float(node.get("acc_ratio") or 0), "depth": 1,
                          "pid": pid, "src": "aiqicha",
                          "capital": node.get("capital") or "",
                          "status": node.get("status") or ""}]
                await _aqc_expand(cli, nm, synth, depth=depth, ratio=ratio,
                                  budget=budget)
                for c in synth[1:]:
                    cn = str(c.get("name") or "")
                    if cn and cn not in have:
                        eq.chain.append(c)
                        have.add(cn)
                        added += 1
                if added:
                    _beat(eq)
    except Exception:
        return added
    if added:
        eq.notes.append(f"有一路工商这轮没跑全，已用另一路补穿出 {added} 个下游主体")
    return added


async def from_tianyancha(name: str, depth: int = 2, ratio: float | None = None,
                          branches: bool = True) -> Equities:
    """工商画像主来源之一（天眼查）：股东 + 对外投资 + 逐层穿透 + 分支/备案。

    令牌或 Cookie 放 ``sources.tianyancha.token`` / ``cookie``；只填 Cookie 也行，
    ``auth_token`` / ``TYCID`` 会从 Cookie 里解析出来当请求头用。
    ``branches`` 关掉就不打分支机构面板（省一次请求、省一份额度）。
    """
    if ratio is None:
        try:
            ratio = float(config.get("scan", "equity_ratio", default=100) or 100)
        except Exception:
            ratio = 100.0
    eq = Equities(name=name, depth=depth, ratio=ratio, source="tianyancha")
    token, tycid, cookie = _tyc_cred()
    if not (token or cookie):
        eq.source_status["tianyancha"] = "no_credential"
        eq.notes.append("工商画像第二来源未配置凭据，跳过")
        return eq

    _RISK_LAST.pop("tianyancha", None)
    budget = {"left": _expand_budget()}
    ref = f"{TIANYANCHA_WEB}/search?key={quote(name)}"
    try:
        async with _client(referer=ref) as cli:
            cli.headers.update(_tyc_headers(token, tycid, cookie, name))
            # 检索接口的 JSON 比搜索页 SSR 稳：页面结构一改就抽不出主体，看着
            # 就像这家公司压根不存在。接口抽不出再从 SSR 兜底。
            gid, hit = await _tyc_locate(cli, name, first=True)
            if gid:
                eq.pid = gid
                eq.resolved = hit
                if hit and _norm_ent(hit) != _norm_ent(name):
                    if core_same(name, hit):
                        eq.notes.append(f"工商主体按输入对齐到：{hit}")
                    else:
                        eq.notes.append(
                            f"检索没有同名主体，按排序首条对接：{hit}；链路可能挂到"
                            "近似名的另一家公司，核不上的把目标改成工商全称再跑")
            if not gid:
                if _note_risk(eq, "tianyancha"):
                    eq.source_status["tianyancha"] = "blocked"
                else:
                    eq.source_status["tianyancha"] = "not_found"
                    eq.notes.append(
                        "第二工商来源未检索到该主体（检索接口和搜索页都没给出能对齐"
                        "的主体；可能被要求登录或被风控）")
                return eq

            eq.holders = await _tyc_holders(cli, gid, budget=budget)
            # 先把「这个主体投了谁」翻满，再拿剩下的额度去追上游股东。
            # 反过来的话，一个股东树很深的集团会把额度全花在往上穿，
            # 主业的子公司清单只剩首屏，看着就像「没找到子公司」。
            root_rows = await _tyc_invest_all(cli, gid, budget=budget)
            root_total = int(budget.pop("__total", 0) or 0)
            if root_total > len(root_rows):
                eq.notes.append(
                    f"该主体对外投资共 {root_total} 家，本轮取到 {len(root_rows)} 家")
            for it in root_rows:
                rec = _tyc_edge(it, name, None, 1)
                if not rec:
                    continue
                eq.invests.append({"name": rec["name"], "ratio": rec["ratio"],
                                   "pid": rec["pid"], "id": rec["pid"],
                                   "total_ratio": rec["acc_ratio"],
                                   "status": rec.get("status") or ""})
                eq.chain.append(rec)
            # 控股企业再补一遍：对外投资漏掉的隔层控股子公司只在这一面，
            # 少这一面，纯控股型的集团子公司整片找不到。按名字去重后并进链路，
            # 后面的逐层穿透会把它们一起往下穿。
            hold_gate: dict = {}
            held, hold_total = await _tyc_hold_all(cli, gid, budget=budget, gate=hold_gate)
            if hold_gate.get("why"):
                eq.notes.append(
                    f"控股企业这一面没取到：{hold_gate['why']}，改用另一路工商来源补这一面")
            if hold_total > len(held):
                eq.notes.append(
                    f"该主体控股企业共 {hold_total} 家，本轮取到 {len(held)} 家")
            have = {_norm_ent(c.get("name")) for c in eq.chain}
            for it in held:
                rec = _tyc_edge(it, name, None, 1)
                if not rec or _norm_ent(rec["name"]) in have:
                    continue
                have.add(_norm_ent(rec["name"]))
                eq.invests.append({"name": rec["name"], "ratio": rec["ratio"],
                                   "pid": rec["pid"], "id": rec["pid"],
                                   "total_ratio": rec["acc_ratio"],
                                   "status": rec.get("status") or ""})
                eq.chain.append(rec)
            if eq.chain:
                _beat(eq)
            await _tyc_expand(cli, name, eq.chain, depth=depth, ratio=ratio, budget=budget)
            # 分支机构 / 备案是画像面板，和股权链路不是一回事：面板挂了只记一句，
            # 别把整路来源标成 blocked——那会让人以为连股权也查不了。
            panel_budget = budget if isinstance(budget, dict) else None
            if branches:
                try:
                    rows_br, total_br = await _tyc_branch_all(cli, gid, budget=panel_budget)
                    eq.branches.extend(rows_br)
                    if total_br > len(rows_br):
                        eq.notes.append(
                            f"该主体分支机构共 {total_br} 家，本轮取到 {len(rows_br)} 家")
                except Exception as e:
                    eq.notes.append(f"分支机构面板取数失败：{type(e).__name__}")
            try:
                rows_icp, total_icp = await _tyc_icp_all(cli, gid, budget=panel_budget)
                eq.icps.extend(rows_icp)
                if total_icp > len(rows_icp):
                    eq.notes.append(
                        f"该主体备案共 {total_icp} 条，本轮取到 {len(rows_icp)} 条")
            except Exception as e:
                eq.notes.append(f"备案面板取数失败：{type(e).__name__}")
            # 最终受益人：机构股东再往上穿，只穿人。单独记一份额度，
            # 别让上游追股东把子公司穿透的次数一起吃光。
            levels = int(config.get("scan", "equity_ubo_levels", default=1) or 0)
            branches = int(config.get("scan", "equity_ubo_branches", default=3) or 0)
            if eq.holders and levels > 0 and branches > 0:
                ubo_budget = {"left": _expand_budget()}
                await _tyc_fill_upstream(cli, eq.holders, levels, branches,
                                         budget=ubo_budget)
    except Exception as e:
        eq.notes.append(f"工商画像第二来源请求失败：{type(e).__name__}")
        return eq

    risk = _note_risk(eq, "tianyancha")
    if not (eq.holders or eq.invests or eq.chain or eq.branches or eq.icps) and not risk:
        eq.notes.append("工商画像第二来源返回空（凭据可能无效）")
    if not eq.source_status.get("tianyancha"):
        has = bool(eq.holders or eq.invests or eq.chain or eq.branches or eq.icps)
        eq.source_status["tianyancha"] = "ok" if has else ("blocked" if risk else "empty")
    # 额度在「翻投资页 / 逐层穿子公司 / 追上游股东」三处共用，任何一处被吃光都要
    # 单独交代一句：只写进 source_status 会把这一路工商源整个标成失效，
    # 用户就会去修一个根本没坏的渠道。
    for _bk in (budget, locals().get("ubo_budget")):
        if isinstance(_bk, dict) and _bk.get("cut"):
            eq.cap_notes.setdefault("budget", str(_bk["cut"]))
    return eq


#: 股权链路可选来源。留空 = 全开，选一个就只跑那一路，避免不用时白耗额度。
#: 主源是两家工商站（股东 / 对外投资 / 分支机构 / 备案都给全量分页），
#: 其余按「辅助」处理：主源缺字段（比如没配登录态、被次数挡住）时靠它们补，
#: 不再单独当数据主干的来源。
EQUITY_SOURCES = {
    "aiqicha": "爱企查（股东/对外投资/分支机构/备案）",
    "tianyancha": "天眼查（股东/对外投资/分支机构/备案全量分页）",
    "xiaolanben": "小蓝本（股东/对外投资）",
    "icp": "备案主体反查（不需要登录态）",
    "backup": "工商辅助源（企查查等，按已配凭据）",
}

#: 主源只有两家工商站；界面按它把来源分「主源 / 辅助」两栏画。
#: 备案反查不需要登录态，跟主源一起并发跑，用来兜住两家 cookie 都失效的情况。
EQUITY_PRIMARY = ("aiqicha", "tianyancha")
#: 默认勾上的那几路：主源两家 + 备案兜底；要凭据的辅助源留空，勾了才会发请求。
EQUITY_DEFAULT = ("aiqicha", "tianyancha", "icp")
EQUITY_AUX = tuple(k for k in EQUITY_SOURCES if k not in EQUITY_PRIMARY)


def _pick_sources(sources) -> set[str]:
    """把外部传进来的来源列表收敛成白名单；空值一律当「全开」。渠道面板停用的不参与。"""
    if not sources:
        keep = set(EQUITY_SOURCES)
    else:
        if isinstance(sources, str):
            sources = [sources]
        want = {str(s).strip().lower() for s in sources if str(s).strip()}
        keep = want & set(EQUITY_SOURCES) or set(EQUITY_SOURCES)
    return {s for s in keep if channels_mod.source_on(s)}


async def collect(name: str, *, depth: int = 2, ratio: float = 100.0,
                  ubo_threshold: float | None = None,
                  ubo_levels: int | None = None,
                  branches: bool = True,
                  sources: list[str] | None = None,
                  gap: float | None = None,
                  retry: int | None = None,
                  budget: int | None = None,
                  on_progress: "callable | None" = None,
                  on_partial: "callable | None" = None) -> Equities:
    """多来源一起上，按字段合并；任一来源缺凭据都不影响其它链路。

    ``ubo_threshold`` / ``ubo_levels`` 不给就取 ``scan.equity_ubo_*``：
    控制线决定「多少算控制」，层数决定股东树往上折算几层。
    ``branches`` 控制是否查分支机构。
    ``sources`` 只跑点名的那几路（``aiqicha`` / ``tianyancha`` / ``icp`` / ``backup``），
    留空全开；关掉的一路不发现场请求，额度全留给要用的那条。
    ``gap`` 是每次工商请求之间额外的等待秒数（0 = 只走节流闸，不额外等），
    ``retry`` 是单个请求的尝试次数。两者都不给就回落到配置 ``scan.equity_sleep`` /
    ``scan.equity_retry``；给了就只影响本次执行，不改全局。
    ``on_progress(msg)`` 是实时进度回调：每开翻一个主体前收到一行，界面上能直接看到
    正在查哪一家、第几层，而不是只有一句「进行中」。
    ``on_partial(snapshot)`` 是途中快照：逐层穿子公司是几十次串行请求，一跑十几分钟。
    接上这个回调后，每长出一批节点就交一份「此刻的链路」（节流约 8 秒一次），外层
    边收边入库。硬时限一到协程被掐，已经穿出来的主体仍在库里，不会跟着局部变量消失。
    """
    name = (name or "").strip()
    if not name:
        return Equities(name="", notes=["主体名为空"])
    try:
        ratio = float(ratio if ratio is not None else 100.0)
    except Exception:
        ratio = 100.0

    if ubo_threshold is None:
        ubo_threshold = config.get("scan", "equity_ubo_threshold",
                                   default=DEFAULT_UBO_THRESHOLD)
    if ubo_levels is None:
        ubo_levels = config.get("scan", "equity_ubo_levels", default=1)
    try:
        ubo_threshold = float(ubo_threshold or DEFAULT_UBO_THRESHOLD)
    except Exception:
        ubo_threshold = DEFAULT_UBO_THRESHOLD
    try:
        ubo_levels = max(0, int(ubo_levels if ubo_levels is not None else 1))
    except Exception:
        ubo_levels = 1

    use = _pick_sources(sources)

    # 间隔 / 重试只在本次执行内生效：穿透会翻页、追上游股东、追子公司，
    # 逐层传参容易漏，用上下文变量让整条链上的请求都吃同一个值。
    _gap_tok = None
    _retry_tok = None
    _budget_tok = None
    _prog_tok = None if on_progress is None else _PROGRESS.set(on_progress)
    if budget is not None:
        try:
            _budget_tok = _BUDGET_OVERRIDE.set(max(0, min(2000, int(budget))))
        except (TypeError, ValueError):
            _budget_tok = None
    if gap is not None:
        try:
            _gap_tok = _GAP_OVERRIDE.set(max(0.0, min(_GAP_MAX, float(gap))))
        except (TypeError, ValueError):
            _gap_tok = None
    if retry is not None:
        try:
            _retry_tok = _RETRY_OVERRIDE.set(max(1, min(10, int(retry))))
        except (TypeError, ValueError):
            _retry_tok = None

    async def _off(key: str):
        """没被点名的一路：不发请求，直接给空结果，后面合并逻辑按「空来源」跳过。"""
        return None

    # 途中快照：逐层穿子公司要几十次串行请求，整趟十几分钟。这里把每次长出来的
    # 节点并进一份累计链路，节流后交给外层入库——超时被掐时，已经穿出来的主体
    # 已经在库里，不会连同一个「已入库」的日志一起被丢掉。
    _part_tok = None
    if on_partial is not None:
        acc = Equities(name=name, depth=depth, ratio=ratio,
                       ubo_threshold=ubo_threshold, ubo_depth=ubo_levels)
        _acc_idx: dict[str, dict] = {}
        _acc_inv: set[str] = set()
        _last_emit = [0.0]

        def _emit(src) -> None:
            if isinstance(src, Equities):
                nodes, invests = src.chain, src.invests
            elif isinstance(src, dict):
                nodes, invests = src.get("chain") or [], src.get("invests") or []
            else:
                nodes, invests = list(src or []), []
            for c in nodes:
                if not isinstance(c, dict):
                    continue
                nm = str(c.get("name") or "")
                if not nm:
                    continue
                cur = _acc_idx.get(nm)
                if cur is None:
                    cur = dict(c)
                    _acc_idx[nm] = cur
                    acc.chain.append(cur)
                    continue
                # 同名字节点就地合并：取更大的累计持股、更浅的层级，缺的字段补上
                if float(c.get("acc_ratio") or 0) > float(cur.get("acc_ratio") or 0):
                    cur["acc_ratio"] = c.get("acc_ratio")
                    if c.get("ratio"):
                        cur["ratio"] = c.get("ratio")
                d_new = int(c.get("depth") or 0)
                if d_new and d_new < int(cur.get("depth") or 99):
                    cur["depth"] = d_new
                    if c.get("parent"):
                        cur["parent"] = c.get("parent")
                for f in ("pid", "capital", "status", "src"):
                    if not cur.get(f) and c.get(f):
                        cur[f] = c.get(f)
            for iv in invests:
                if not isinstance(iv, dict):
                    continue
                inm = str(iv.get("name") or "")
                if inm and inm not in _acc_inv:
                    _acc_inv.add(inm)
                    acc.invests.append(dict(iv))
            # 节流：一次穿透会追加几百次，每次都落库会把库写穿
            now = time.monotonic()
            if now - _last_emit[0] < 8.0:
                return
            _last_emit[0] = now
            snap = acc.as_dict()
            snap["ratio"] = ratio
            try:
                on_partial(snap)
            except Exception:
                pass

        _part_tok = _PARTIAL.set(_emit)

    LAST_STATUS.clear()

    async def _track(key: str, skey: str, coro):
        """哪一路先回来就先把状态写进 LAST_STATUS，被外层超时掐断时还能交代进度。"""
        _prog(f"股权穿透：{EQUITY_SOURCES.get(key, key).split('（')[0]} 开查「{name}」"
              f"（每请求间隔 {effective_gap():.0f} 秒）")
        try:
            res = await coro
        except Exception:
            LAST_STATUS[key] = "error"
            _prog(f"股权穿透：{EQUITY_SOURCES.get(key, key).split('（')[0]} 异常")
            raise
        st = ""
        if isinstance(res, Equities):
            st = str(res.source_status.get(skey) or "")
        LAST_STATUS[key] = st or ("ok" if res else "empty")
        # 逐路报回：一次穿透几分钟起步，只在开始时说一句，界面看着还是卡住。
        _prog(f"股权穿透：{EQUITY_SOURCES.get(key, key).split('（')[0]} 返回 "
              f"{LAST_STATUS[key]}（链路 {len(getattr(res, 'chain', []) or [])} 节点）")
        return res

    # 主源（两家工商站 + 备案兜底）先并发打满；辅助源只在主源一条数据都没取到时
    # 才补位，主源已经出数就不再白耗它的额度与等待时间。
    _prog(f"股权穿透：{name} 开跑（{'、'.join(EQUITY_SOURCES.get(k, k).split('（')[0] for k in sorted(use))}"
          f"；每次请求间隔 {effective_gap():.0f} 秒，深度 {depth} 层）")
    aqc, tyc, icp = await asyncio.gather(
        _track("aiqicha", "aiqicha",
               from_aiqicha(name, depth, ratio=ratio, branches=branches)
               if "aiqicha" in use else _off("aiqicha")),
        _track("tianyancha", "tianyancha",
               from_tianyancha(name, depth, ratio=ratio, branches=branches)
               if "tianyancha" in use else _off("tianyancha")),
        _track("icp", "icp", _icp_children(name) if "icp" in use else _off("icp")),
        return_exceptions=True)

    def _has_data(remote) -> bool:
        if not isinstance(remote, Equities):
            return False
        return bool(remote.chain or remote.holders or remote.icps or remote.branches
                    or remote.invests or remote.copyrights)

    # 备案反查已经跟主源一起并发跑过了，不再算进「主源没出数才补跑」的辅助名单
    aux_wanted = [k for k in EQUITY_AUX if k in use and k != "icp"]
    aux_skipped: list[str] = []
    xlb = bak = None
    aux_note = ""
    if aux_wanted:
        # 备案那一路只给备案行，链路主体仍要靠工商：只有备案出数、两家工商都空的时候
        # 辅助源照样要补位，不能因为「有一路非空」就把辅助源整段跳过。
        if _has_data(aqc) or _has_data(tyc):
            aux_skipped = list(aux_wanted)
            aux_note = ("主源已取到数据，辅助工商源（"
                        + "、".join(EQUITY_SOURCES.get(k, k).split("（")[0]
                                   for k in aux_wanted)
                        + "）本轮未调用")
        else:
            kicks = {
                "xiaolanben": ("xiaolanben", "xiaolanben", from_xiaolanben(name)),
                "backup": ("backup", "backup", from_backup_sources(name)),
            }
            jobs = [kicks[k] for k in aux_wanted if k in kicks]
            got = await asyncio.gather(
                *[_track(k, sk, coro) for k, sk, coro in jobs],
                return_exceptions=True)
            for (k, _sk, _coro), res in zip(jobs, got):
                if k == "xiaolanben":
                    xlb = res
                else:
                    bak = res
            aux_note = "主源一条数据都没取到，已补跑辅助工商源"

    eq = Equities(name=name, depth=depth, ratio=ratio,
                  ubo_threshold=ubo_threshold, ubo_depth=ubo_levels)
    for k in EQUITY_SOURCES:
        if k not in use:
            eq.source_status[k] = "skip"
    if aux_note:
        eq.notes.append(aux_note)
    for remote in (aqc, tyc, xlb, bak):
        if not isinstance(remote, Equities):
            continue
        eq.source_status.update(remote.source_status)
        # 同一家子公司在两路工商里都会出现。以前按名字去重、先到先得，等于把后一路
        # 的累计持股和它自己的节点 id 一起丢掉：链路图上显示的是先回来那一份（往往是
        # 被风控截断的那一路），层级也停在浅的那一层。这里改成同名字节点就地合并，
        # 取更大的累计持股、更浅的层级，缺 pid 时把另一路的 id 和它的来源一起补上。
        idx = {str(c.get("name") or ""): c for c in eq.chain}
        for c in remote.chain:
            nm = str(c.get("name") or "")
            if not nm:
                continue
            cur = idx.get(nm)
            if cur is None:
                eq.chain.append(c)
                idx[nm] = c
                continue
            if float(c.get("acc_ratio") or 0) > float(cur.get("acc_ratio") or 0):
                cur["acc_ratio"] = c.get("acc_ratio")
                if c.get("ratio") and not cur.get("ratio"):
                    cur["ratio"] = c.get("ratio")
            d_new = int(c.get("depth") or 0)
            if d_new and d_new < int(cur.get("depth") or 99):
                cur["depth"] = d_new
                if c.get("parent"):
                    cur["parent"] = c.get("parent")
            if not cur.get("pid") and c.get("pid"):
                cur["pid"] = c.get("pid")
                cur["src"] = c.get("src") or cur.get("src") or ""
            for f in ("capital", "status"):
                if not cur.get(f) and c.get(f):
                    cur[f] = c.get(f)
        eq.holders = eq.holders or remote.holders
        seen_inv = {str(i.get("name") or "") for i in eq.invests}
        for i in remote.invests:
            nm = str(i.get("name") or "")
            if nm and nm not in seen_inv:
                eq.invests.append(i)
                seen_inv.add(nm)
        # 分支机构 / 备案按名字（域名）并集：两路工商都会给同一份，谁先到久谁留下，
        # 另一路补进它没覆盖的那些。以前用 ``or`` 只留第一份非空，于是「主来源额度
        # 用尽、另一路还有」时，面板上就永久只剩半张表。
        seen_br = {str(b.get("name") or "") for b in eq.branches}
        for b in remote.branches:
            nm = str(b.get("name") or "")
            if nm and nm not in seen_br:
                eq.branches.append(b)
                seen_br.add(nm)
        eq.copyrights = eq.copyrights or remote.copyrights
        seen_icp = {str(i.get("domain") or "") for i in eq.icps}
        for i in remote.icps:
            dm = str(i.get("domain") or "")
            if dm and dm not in seen_icp:
                eq.icps.append(i)
                seen_icp.add(dm)
        # 附加画像同样要合并：只并前面这几项时，面板取到了也会在合并这一步丢掉，
        # 界面上看着像「这个主体没有移动应用 / 供应商」。
        eq.apps = eq.apps or remote.apps
        eq.wechats = eq.wechats or remote.wechats
        eq.weibos = eq.weibos or remote.weibos
        eq.jobs = eq.jobs or remote.jobs
        eq.suppliers = eq.suppliers or remote.suppliers
        eq.pid = eq.pid or remote.pid
        # 主体对齐结果也要合并。主来源把「输入名对齐到的登记全称」写在 resolved 上，
        # 另一路只补链路时这一项是空的；不并就会出现穿透跑成了、面板上主体对齐一栏
        # 却是空白，看不出这轮到底按哪家主体穿的。
        eq.resolved = eq.resolved or remote.resolved
        # 备用来源里「未配置」很常见（大部分人不配七八家），只在主来源也没拿到数据时提示，
        # 否则每条任务日志都被一堆跳过说明刷满。
        for n in remote.notes:
            if "未配置" in n or "未检索到" in n or "返回空" in n:
                if eq.chain or eq.holders:
                    continue
            if n not in eq.notes:
                eq.notes.append(n)
        if remote.chain or remote.holders:
            eq.source = f"{eq.source}+{remote.source}" if eq.source else remote.source
        # 截断说明按来源合并：某一路被额度砍短，另一路补上了，勾选那一路的说明
        # 仍然要留着，否则面板上看不出「这轮为什么比上次少」。
        for ck, cv in (getattr(remote, "cap_notes", None) or {}).items():
            if ck == "budget":
                if not eq.cap_notes.get("budget"):
                    eq.cap_notes["budget"] = cv
                continue
            eq.cap_notes.setdefault(ck, cv)

    # 两路工商互相补位：任一路这轮没跑全（额度用尽 / 被风控 / 没检索到 / 只回半截），
    # 就让还健康的那一路把对方停下的那一层接下去穿。两个方向都补 —— 以前只有
    # 「爱企查停摆、天眼查还在」一个方向，反过来天眼查停了没人接，现场表现就是
    # 「天眼查这次是不是没用上」：用了，但停在半截没人续。
    _GAP_STATES = ("quota", "blocked", "not_found", "empty", "partial", "error", "timeout")
    _st_aqc = str(eq.source_status.get("aiqicha") or "")
    _st_tyc = str(eq.source_status.get("tianyancha") or "")
    if "tianyancha" in use and eq.chain and _st_tyc == "ok" and _st_aqc in _GAP_STATES:
        try:
            await _tyc_fill_gap(name, eq, depth=depth, ratio=ratio)
        except Exception as e:
            eq.notes.append(f"跨来源补穿失败：{type(e).__name__}")
        # 主源停摆时面板上只剩「这一路取到 0 家」，看着像整趟没拉到。
        # 这里必须补一句「谁在接续、最后拿到多少」，否则用户只能猜是不是没权限。
        if eq.invests or eq.chain:
            eq.notes.append(
                f"另一路工商来源已接续主来源，本轮对外投资共取到 "
                f"{len(eq.invests)} 家、链路 {len(eq.chain)} 个节点")
    if "aiqicha" in use and eq.chain and _st_aqc == "ok" and _st_tyc in _GAP_STATES:
        try:
            await _aqc_fill_gap(name, eq, depth=depth, ratio=ratio)
        except Exception as e:
            eq.notes.append(f"跨来源补穿失败：{type(e).__name__}")
        if eq.invests or eq.chain:
            eq.notes.append(
                f"另一路工商来源已接续主来源，本轮对外投资共取到 "
                f"{len(eq.invests)} 家、链路 {len(eq.chain)} 个节点")

    if "icp" in use:
        # 备案这一路原来只往里塞数据、从不写状态，界面上永远看不到它跑没跑。
        if isinstance(icp, Exception):
            eq.source_status["icp"] = "error"
        elif isinstance(icp, list) and icp:
            seen_icp = {str(i.get("domain") or "") for i in eq.icps}
            for it in icp:
                dm = str(it.get("domain") or "")
                if dm and dm not in seen_icp:
                    eq.icps.append(it)
                    seen_icp.add(dm)
            eq.source_status["icp"] = "ok"
            if not eq.source:
                eq.source = "icp"
        else:
            eq.source_status["icp"] = "empty"
    if "backup" in use:
        if isinstance(bak, Exception):
            eq.source_status["backup"] = "error"
        elif isinstance(bak, Equities):
            # 汇总状态由 from_backup_sources 按各家结果算好，连同 backup:<源> 明细
            # 一起在合并那一步并进来了。以前这里拿备注字面量猜，六家里五家没配时
            # 先命中的是「未配置登录态」，把「有凭据、只是登录态过期（回 302）」那一家
            # 也写成了「未配置凭据」，面板上根本看不出该去补哪一家。
            if not eq.source_status.get("backup"):
                eq.source_status["backup"] = (
                    "ok" if (bak.chain or bak.holders or bak.invests) else "empty")
        else:
            eq.source_status["backup"] = "skip"
    # 辅助源被主源挡掉、这轮压根没发请求：状态要显示「未运行」。写成 empty 会被
    # 读成「跑过一趟、什么都没抓到」，进而让人去查凭据或换来源。
    for k in aux_skipped:
        eq.source_status[k] = "skip"
    if not eq.chain and not eq.holders and not eq.branches and not eq.icps:
        eq.notes.append("该主体暂无可用股权数据，仅按主体名继续采集")
    # 收尾再交一次完整链路：最后一段没过节流闸的节点、辅助源并进来的那部分，
    # 都在这里补齐。超时被掐时走不到这一步，靠的是上面那些途中快照。
    if _part_tok is not None:
        try:
            snap = eq.as_dict()
            snap["ratio"] = ratio
            on_partial(snap)
        except Exception:
            pass
        _PARTIAL.reset(_part_tok)
    if _gap_tok is not None:
        _GAP_OVERRIDE.reset(_gap_tok)
    if _retry_tok is not None:
        _RETRY_OVERRIDE.reset(_retry_tok)
    if _budget_tok is not None:
        _BUDGET_OVERRIDE.reset(_budget_tok)
    if _prog_tok is not None:
        _PROGRESS.reset(_prog_tok)
    LAST_STATUS.update(eq.source_status)
    return eq


def full_owned_children(name: str, chain: list[dict], limit: int = 400,
                        ratio: float = 100.0) -> list[str]:
    """从链路里挑出「累计持股 ≥ ratio」的主体，作为可入池的子公司清单。

    ``ratio`` 就是配置里的控股门槛：默认 100 只收全资，调成 51 或 20 就按那个线放开。
    """
    out: list[str] = []
    for c in chain:
        child = str(c.get("name") or "").strip()
        if not child or child == name:
            continue
        if _acc(c) >= ratio:
            out.append(child)
        if len(out) >= limit:
            break
    return list(dict.fromkeys(out))


# ─────────────── 小蓝本 ───────────────
# 网页版的接口分在 /api.xiaolanben.com 这个挂载点下，数据接口还要带 h_t / h_v / h_sign
# 三个签名参数，签名由页面里的脚本现算；直连只带 Cookie 会被回「验签错误」。
# 这里只做两件能确定的事：用不验签的登录态校验口判 Cookie 有没有效；有效就照网页的调用
# 形状真打一次检索和股东 / 投资，拿得到就解析，拿不到就把对方的原话写进备注。
XLB_BASE = "https://sou.xiaolanben.com"
_XLB_MOUNT = "/api.xiaolanben.com"
# 网页端固定的应用标识，登录态校验口用得到；缺了会被回「参数'big_app_id'是必须的」。
_XLB_APP = {"big_app_id": 35, "app_id": 2026, "channel": "xlb-pc-none", "plat": 4}
_XLB_VALID = "/usercenter-gateway/api/v2/web/token/valid"
_XLB_SEARCH = "/bluebook/api/v1/es/queryCompanys"
_XLB_SHARE = "/xlb-gateway/blue-book/company/companyData"
_XLB_INVEST = "/bluebook/api/v1/company/investment"


def _xlb_base() -> str:
    """配置里可换镜像地址；默认是网页版主站。"""
    sec = _sec("xiaolanben")
    base = str(sec.get("api") or "").strip().rstrip("/")
    return base or XLB_BASE


def _xlb_head() -> dict:
    """小蓝本的登录态就是浏览器 Cookie；Token 可留空，填了按网页的方式带 Authorization。"""
    sec = _sec("xiaolanben")
    pick = creds.pick("xiaolanben")
    cookie = (pick["cred"] or "").strip()
    if not cookie:
        return {}
    head = {"Cookie": cookie}
    token = str((pick.get("extra") or {}).get("token") or sec.get("token") or "").strip()
    if token:
        head["Authorization"] = token if token.lower().startswith("encrypt ") else f"encrypt {token}"
    return head


def _xlb_reason(r) -> str:
    """读对方的拒绝原话：验签被拒和登录态过期要能分清，否则只会看到「取不到数据」。"""
    msg = ""
    try:
        body = r.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            msg = str(errs[0].get("message") or "")
        if not msg:
            msg = str(body.get("message") or "")
    if "验签" in msg or "h_sign" in msg:
        return "对方要求页面内验签（h_sign），直连取不到数据"
    if msg:
        return f"对方返回：{msg[:60]}"
    return f"HTTP {r.status_code}"


async def _xlb_login(head: dict) -> tuple[str, str]:
    """登录态校验：这个口不需要验签，200 = Cookie 有效，401 = 没登录或已过期。"""
    url = _xlb_base() + _XLB_MOUNT + _XLB_VALID
    try:
        async with _client(timeout=15.0, referer=XLB_BASE + "/") as cli:
            cli.headers.update(head)
            r = await cli.post(url, params=dict(_XLB_APP))
    except Exception as e:
        return "error", f"小蓝本登录态校验没打通：{type(e).__name__}"
    if r.status_code == 200:
        return "ok", ""
    if r.status_code in (401, 403):
        return "blocked", "小蓝本 Cookie 已失效（登录态校验回 401），需要重新登录后复制"
    return "error", f"小蓝本登录态校验 HTTP {r.status_code}：{_xlb_reason(r)}"


async def from_xiaolanben(name: str) -> Equities:
    """小蓝本：Cookie 有效时按网页的调用形状取股东与对外投资，写一条 ``xiaolanben`` 状态。"""
    eq = Equities(name=name, source="")
    sec = _sec("xiaolanben")
    if not sec.get("enabled", True) or not channels_mod.source_on("xiaolanben"):
        eq.source_status["xiaolanben"] = "skip"
        return eq
    head = _xlb_head()
    if not head:
        eq.source_status["xiaolanben"] = "no_credential"
        eq.notes.append("小蓝本 未配置登录态，跳过")
        return eq
    st, why = await _xlb_login(head)
    if st != "ok":
        eq.source_status["xiaolanben"] = st
        if why:
            eq.notes.append(why)
        return eq

    base = _xlb_base() + _XLB_MOUNT
    rows: list[dict] = []
    note = ""
    try:
        async with _client(timeout=20.0, referer=XLB_BASE + "/") as cli:
            cli.headers.update(head)
            r = await cli.get(base + _XLB_SEARCH,
                              params={"keyword": name, "pageId": 1, "pageSize": 5})
            if r.status_code != 200:
                eq.source_status["xiaolanben"] = "blocked"
                eq.notes.append(f"小蓝本 检索被拒：{_xlb_reason(r)}")
                return eq
            try:
                found = r.json() or {}
            except Exception:
                eq.source_status["xiaolanben"] = "blocked"
                eq.notes.append("小蓝本 检索没回 JSON，接口可能需要页面内验签")
                return eq
            comps = found.get("companys") or found.get("companyList") or []
            eid = ""
            if isinstance(comps, list):
                for row in comps:
                    if not isinstance(row, dict):
                        continue
                    nm = str(row.get("name") or row.get("companyName") or "").strip()
                    if nm and (nm == name or name in nm):
                        eid = str(row.get("eid") or row.get("id") or "")
                        if eid:
                            break
            if not eid:
                eq.source_status["xiaolanben"] = "not_found"
                eq.notes.append("小蓝本 未检索到该主体")
                return eq
            # 股东与对外投资是两条独立的接口；任一路被拒都不影响另一路。
            for url, params in (
                (base + _XLB_SHARE, {"type": "shareholders", "eid": eid}),
                (base + _XLB_INVEST, {"eid": eid}),
            ):
                try:
                    r2 = await cli.get(url, params=params)
                except Exception as e:
                    note = note or f"小蓝本 接口没打通：{type(e).__name__}"
                    continue
                if r2.status_code != 200:
                    note = note or f"小蓝本 {_xlb_reason(r2)}"
                    continue
                try:
                    rows.extend(_rows_with_ratio(r2.json()))
                except Exception:
                    continue
    except Exception as e:
        eq.source_status["xiaolanben"] = "error"
        eq.notes.append(f"小蓝本 请求失败：{type(e).__name__}")
        return eq

    if not rows:
        eq.source_status["xiaolanben"] = "blocked" if note else "not_found"
        eq.notes.append(note or "小蓝本 没解析到股东 / 对外投资")
        return eq
    eq.source_status["xiaolanben"] = "ok"
    eq.source = "xiaolanben"
    for row in rows:
        child = str(row.get("name") or "").strip()
        if not child or child == name:
            continue
        pct = row.get("ratio") or 0.0
        eq.chain.append({"name": child, "parent": name, "ratio": pct,
                         "acc_ratio": round(pct, 2), "depth": 1, "via": "xiaolanben",
                         "src": "xiaolanben"})
    return eq


# ─────────────── 备用工商来源 + 连通测试 ───────────────
# 各家页面接口的返回结构会变，这里只认「明显是风控 / 未登录」的信噪，其余结构一律宽松解析：
# 拿到条数就记条数，拿不到就只报 HTTP 状态，绝不猜数据。
_LOGIN_HINTS = ("mustlogin", "请先登录", "请登录", "重新登录", "login required", "未登录",
                "账号存在风险", "安全验证", "验证码", "cookie有问题", "cookie失效",
                "cookie过期", "访问频率过快", "too many requests", "forbidden")

# 网页型站点：探一个稳定的公开路径，看登录态有没有被认
_PAGES = {
    "qichacha": ("https://www.qcc.com", "/web/search?key=测试", ("cookie",), ["tycid"]),
    "qcctid": ("https://api.qichacha.com", "/", ("cookie",), ["tycid"]),
    "riskbird": ("https://www.riskbird.com", "/api/ent/query", ("cookie",), []),
    "kuaicha": ("https://www.kuaicha365.com", "/", ("cookie",), []),
    "qidian": ("https://www.qidianxin.com", "/", ("cookie",), []),
    "chinaz": ("https://www.chinaz.com", "/", ("cookie",), []),
    "aldzs": ("https://www.aldzs.com", "/", ("cookie",), []),
    "appbk": ("https://www.appbk.com", "/", ("cookie",), []),
    "aiqicha": ("https://aiqicha.baidu.com", "/s/advanceFilterAjax?q=测试&p=1&s=10&o=0&f={}&t=0",
                ("cookie",), []),
    "tianyancha": ("https://www.tianyancha.com", "/search?key=测试",
                   ("cookie", "token"), []),
    "qimai": ("https://api.qimai.cn", "/", ("cookie",), []),
}

# 这些源没有稳定可探的公开路径，只在配置里存凭据，由各自采集流程去用
_NO_PROBE = {"appbk"}

# 备用来源的检索路径：各家搜索 / 列表接口的名字不一样，先探最像的那个；
# 拿不到就只在连通测试里报「需登录态」，不当成凭据失效。
_SEARCH = {
    "qichacha": "/web/search?key={q}",
    "riskbird": "/riskbird-api/newSearch",
    "kuaicha": "/search-result",
}


def _has_login_hint(text: str) -> bool:
    low = (text or "").lower()
    return any(h in low for h in _LOGIN_HINTS)


def _jwt_note(token: str) -> str:
    """本地读 JWT 的过期时间，给出「哪天过期」。

    凭据过期时对方常回 412 这类与登录无关的状态码，只看回包只能判「被拒」；
    直接把过期日说清楚，用户才知道要去重新登录，而不是反复换代理重试。
    """
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return ""
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        body = json.loads(base64.urlsafe_b64decode(pad.encode()).decode("utf-8", "ignore"))
    except Exception:
        return ""
    exp = body.get("exp")
    if not isinstance(exp, (int, float)) or exp <= 0:
        return ""
    if exp <= time.time():
        return f"登录 Token 已于 {time.strftime('%Y-%m-%d', time.localtime(exp))} 过期，需要重新登录后再取"
    return ""


def _cred_of(sec: dict, fields: tuple, pick: dict | None = None) -> dict:
    """按来源把配置里的登录态拾成请求头；缺关键字段返回空 dict。

    ``pick`` 给出时用池子里那一份（附带该条目自己的 token / tycid），否则用主值。
    """
    pick = pick or {}
    extra = pick.get("extra") or {}
    cookie = str(pick.get("cred") or sec.get("cookie") or "").strip()
    token = str(extra.get("token") or sec.get("token") or "").strip()
    tycid = str(extra.get("tycid") or sec.get("tycid") or "").strip()
    if not cookie:
        return {}
    head = {"Cookie": cookie}
    if "token" in fields and token:
        head["Authorization"] = token
    if tycid:
        head["X-Tycid"] = tycid
    return head


def _cred_blocked(r: httpx.Response) -> bool:
    """这份登录态是不是废了：跳登录页 / 401 / 403 / 429 / 正文提示登录。"""
    if r.status_code in (301, 302, 303, 307, 308, 401, 403, 429):
        return True
    return _has_login_hint(r.text)


async def _xlb_probe() -> dict:
    """小蓝本的连通测试只打登录态校验口：数据接口一律要验签，测不出 Cookie 好坏。"""
    head = _xlb_head()
    if not head:
        return {"ok": False, "base": _xlb_base(),
                "msg": "未填写 Cookie；小蓝本未登录时所有接口都回「验签错误」"}
    st, why = await _xlb_login(head)
    if st == "ok":
        return {"ok": True, "base": _xlb_base(),
                "msg": "HTTP 200，登录态有效（数据接口需页面内验签，采集时以实际返回为准）"}
    return {"ok": False, "base": _xlb_base(), "msg": why or "登录态校验未通过"}


async def probe_source(name: str) -> dict:
    """连通测试：用已保存的登录态打一次真实请求，回答「认了 / 没认 / 没填」。

    这是给设置页的按钮用的，不落任何数据。没凭据就明确说没填，别让人以为测通了。
    """
    name = (name or "").strip()
    if name == "xiaolanben":
        return await _xlb_probe()
    spec = _PAGES.get(name)
    if not spec:
        return {"ok": False, "msg": f"{name or '该来源'}没有可探接口，保存后由采集流程验证"}
    if name in _NO_PROBE:
        sec = _sec(name)
        ok = bool((sec.get("cookie") or "").strip())
        return {"ok": ok, "msg": "已保存凭据，实际效果由采集流程验证" if ok else "未填写凭据"}
    base, path, fields, _ = spec
    sec = _sec(name)
    head = _cred_of(sec, fields)
    if not head:
        return {"ok": False, "msg": "未填写凭据，先在上面填入登录态再测"}
    url = base.rstrip("/") + path
    if name == "tianyancha":
        # 搜索页是服务端直出，直接看能不能解析出主体，比读 JSON 更准
        return await _tyc_probe()
    kw: dict = {}
    try:
        async with _client(timeout=15.0, referer=base) as cli:
            cli.headers.update(head)
            r = await cli.get(url, **kw) if not kw else await cli.post(url, **kw)
            text = (r.text or "")[:4000]
    except Exception as e:
        return {"ok": False, "msg": f"{url} 请求失败：{type(e).__name__}"[:200], "base": url}
    if _has_login_hint(text):
        return {"ok": False, "msg": f"HTTP {r.status_code}，回包提示未登录 / 被风控，Cookie 需要重新取",
                "base": url}
    # 登录态失效最常见的表现不是 401，而是 HTTP 200 + 业务错误码 / unauth 标记（风鸟就回
    # {"state":"system_error","vipInfo":{"status":"unauth"}}）。只看状态码会把死 Cookie 判成可用。
    try:
        body = r.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        st = str(body.get("state") or body.get("code") or body.get("errcode") or "").lower()
        vip = body.get("vipInfo") if isinstance(body.get("vipInfo"), dict) else {}
        unauth = (str(vip.get("status") or "").lower() in ("unauth", "notlogin", "guest")
                  or body.get("isLogin") is False or body.get("login") is False)
        if st and st not in ("200", "0", "ok", "success", "true"):
            return {"ok": False, "msg": f"HTTP {r.status_code}，对方返回业务错误 state={st}"
                                        f"（登录态无效或接口结构已变）", "base": url}
        if unauth:
            return {"ok": False, "msg": f"HTTP {r.status_code}，对方标记未登录（{vip.get('status') or 'unauth'}），"
                                        f"Cookie 需要重新取", "base": url}
    if r.status_code in (401, 403, 412, 423, 429):
        hint = {401: "凭据被拒", 403: "凭据被拒或无权限", 412: "请求被拒（登录态 / 签名无效）",
                423: "被限流", 429: "被限流"}[r.status_code]
        return {"ok": False, "msg": f"HTTP {r.status_code}，{hint}，Cookie / Token 需要重新取", "base": url}
    if 400 <= r.status_code < 500:
        return {"ok": False, "msg": f"HTTP {r.status_code}，对方拒绝了这次探测请求", "base": url}
    if r.status_code >= 500:
        return {"ok": False, "msg": f"HTTP {r.status_code}，对方服务异常，凭据是否有效无法确认",
                "base": url}
    if body is not None:
        n = _count_rows(body)
        msg = f"HTTP {r.status_code}，回包可解析" + (f"，{n} 条" if n else "")
        if name == "aiqicha":
            msg += await _aqc_quota_report(head, body)
        return {"ok": True, "msg": msg, "base": url}
    return {"ok": False, "msg": f"HTTP {r.status_code}，未返回 JSON（可能需要登录态）", "base": url}


async def _aqc_quota_report(head: dict, found: dict) -> str:
    """顺手把登录态与「股权查询还剩几次」读出来，让设置页能看出是哪种断供。

    免费账号的股权接口扣量后仍回 200，只把 ``remainCount`` 归零；Cookie 过期也只把
    请求降级成游客。不单独读一次，界面上只会表现成「查不到股权」，用户没法判断
    是主体没有股东、额度没了，还是登录态该换了。
    """
    pid = ""
    rows = ((found.get("data") or {}).get("resultList") or []) if isinstance(found, dict) else []
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        pid = str(rows[0].get("pid") or "")
    if pid:
        pid = _aqc_pid_decode(pid, (found.get("ddw") if isinstance(found, dict) else ""))
    # 登录态失效时检索回空列表、拿不到 pid，用固定主体探一次，才读得到 userType
    pid = pid or AQC_PROBE_PID
    try:
        async with _client(timeout=12.0, referer=f"{INVEST_API}/company_detail_{pid}") as cli:
            cli.headers.update(head)
            r = await cli.get(f"{INVEST_API}/detail/investAjax",
                              params={"pid": pid, "p": 1, "s": 1})
            data = ((r.json() or {}).get("data") or {})
    except Exception:
        return ""
    lf = data.get("limitForward") or {}
    if not isinstance(lf, dict):
        return ""
    if str(lf.get("userType") or "") == "nologin":
        return "；登录态已失效（对方按游客处理），Cookie 需要重新取"
    try:
        remain = int(lf.get("remainCount"))
    except (TypeError, ValueError):
        return ""
    return (f"；股权查询剩余 {remain} 次" if remain > 0
            else "；股权查询额度已用尽（账号额度按日恢复，或换账号）")


def _count_rows(v, depth: int = 0) -> int:
    """从任意结构里找「列表条数」：优先 total / count 字段，其次第一个非空列表。"""
    if depth > 4:
        return 0
    if isinstance(v, dict):
        for k in ("total", "totalCount", "count", "totalNum"):
            n = v.get(k)
            if isinstance(n, int) or (isinstance(n, str) and n.isdigit()):
                return int(n)
        for x in v.values():
            n = _count_rows(x, depth + 1)
            if n:
                return n
    if isinstance(v, list):
        return len(v)
    return 0


async def from_backup_sources(name: str) -> Equities:
    """备用工商来源：有凭据就各打一枪，捞股东 / 对外投资。

    结构会变，所以只做宽松解析：字典里同时出现「名称类」和「比例类」字段就当一条链路。
    每一家单独记一条 ``backup:<源>`` 状态：以前六家合成一个「备用工商源 未配置凭据」，
    明明是有凭据、只是登录态过期（回 302 跳登录页）的那一家也被写成了「没配」，
    看面板根本不知道该去补哪一个。
    """
    eq = Equities(name=name, source="")
    for src, (base, path, fields, _) in _PAGES.items():
        key = f"backup:{src}"
        if src in ("aiqicha", "tianyancha", "qimai"):
            continue
        if src in _NO_PROBE:
            # 这几家只按 AppID / 包名检索，喂主体名拿不到东西：记「未启用」而不是
            # 干脆不出现，面板上才解释得清「为什么备用源只有六路」。
            eq.source_status[key] = "skip"
            continue
        sec = _sec(src)
        if not sec.get("enabled", True):
            eq.source_status[key] = "skip"
            eq.notes.append(f"{src} 已被配置关掉（enabled: false）")
            continue
        if not channels_mod.source_on(src):
            eq.source_status[key] = "skip"
            eq.notes.append(f"{src} 已在渠道面板停用，本次没发请求")
            continue
        head = _cred_of(sec, fields)
        if not head:
            eq.notes.append(f"{src} 未配置登录态，跳过")
            eq.source_status[key] = "no_credential"
            continue
        path_q = _SEARCH.get(src)
        url = base.rstrip("/") + (path_q.format(q=quote(name)) if path_q else "/")
        # 备用源也吃 Cookie 池：这一份被挡就换下一份再打一枪，池子里每份只试一次
        r = None
        rows: list[dict] = []
        tried: set[str] = set()
        while True:
            pick = creds.pick(src)
            if pick["cred"] in tried:
                break
            tried.add(pick["cred"])
            head = _cred_of(sec, fields, pick)
            if not head:
                eq.notes.append(f"{src} 未配置登录态，跳过")
                eq.source_status[key] = "no_credential"
                r = None
                break
            try:
                async with _client(timeout=15.0, referer=base) as cli:
                    cli.headers.update(head)
                    r = await cli.get(url, params=None if path_q else {"q": name})
            except Exception as e:
                eq.source_status[key] = "error"
                eq.notes.append(f"{src} 请求失败：{type(e).__name__}")
                r = None
                break
            if _cred_blocked(r) and len(tried) < creds.count(src):
                creds.report(src, pick["cred"],
                             "blocked" if r.status_code in (403, 429) else "invalid")
                eq.notes.append(f"{src} 当前登录态失效，已换下一份 Cookie 重试")
                continue
            break
        if r is None:
            continue
        loc = str(r.headers.get("location") or "")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            eq.source_status[key] = "blocked"
            eq.notes.append(f"{src} HTTP {r.status_code} → {loc.split('?')[0][:40]}，"
                            f"登录态已过期，需要重新复制 Cookie")
            continue
        if r.status_code != 200 or _has_login_hint(r.text):
            eq.source_status[key] = "blocked"
            eq.notes.append(f"{src} HTTP {r.status_code}，登录态可能失效")
            continue
        try:
            rows = _rows_with_ratio(r.json())
        except Exception:
            rows = []
        if not rows:
            eq.source_status[key] = "not_found"
            eq.notes.append(f"{src} 未解析到股东 / 投资链路")
            continue
        eq.source_status[key] = "ok"
        if not eq.source:
            eq.source = src
        for row in rows:
            child = str(row["name"]).strip()
            if not child or child == name:
                continue
            pct = row["ratio"]
            eq.chain.append({"name": child, "parent": name, "ratio": pct,
                             "acc_ratio": round(pct, 2), "depth": 1, "via": src,
                             "src": src})
    # 汇总一条 ``backup``：外层 _track 只认这个键，没有任何子渠道时它会把整路记成
    # 「ok」，面板上就是「备用工商源 可用」配一张空表。按严重度挑一个代表状态。
    per = [v for k, v in eq.source_status.items() if k.startswith("backup:")]
    if per:
        for want in ("ok", "blocked", "quota", "error", "no_credential", "empty", "not_found"):
            if want in per:
                eq.source_status["backup"] = want
                break
        else:
            eq.source_status["backup"] = "empty"
    return eq


def _rows_with_ratio(v, depth: int = 0) -> list[dict]:
    """宽松解析：字典里同时有名称类字段和比例类字段，就算一条股东 / 投资记录。"""
    out: list[dict] = []
    if depth > 5:
        return out
    if isinstance(v, dict):
        nm = next((v[k] for k in ("name", "entName", "companyName", "corpName",
                                  "shareholderName", "investName") if v.get(k)), "")
        rt = next((v[k] for k in ("ratio", "percent", "rate", "investRatio", "regRate",
                                  "shareholdingRatio", "fundedRatio") if v.get(k) not in (None, "")), None)
        if nm and rt is not None:
            out.append({"name": str(nm), "ratio": _pct(rt)})
        else:
            for x in v.values():
                out.extend(_rows_with_ratio(x, depth + 1))
    elif isinstance(v, list):
        for x in v:
            out.extend(_rows_with_ratio(x, depth + 1))
    return out[:300]
