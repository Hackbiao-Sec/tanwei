"""数据渠道目录 / 启用开关 / 一键自检。

面板要能回答两件事：这一路现在到底还能不能用、我想停掉哪几路。所以这里做三件事：

1. ``catalog()`` 把采集流程里所有来源登记成一张固定表（分组 + 需要哪些凭据）；
2. ``is_enabled()`` / ``off_list()`` / ``save_off()`` 管开关，落到 config.yaml 的
   ``channels.off``，与 ``sources.<名>.enabled`` 并存，任一为关就不发请求；
3. ``probe_many()`` 真打一次最小请求，把「额度用尽」「登录态过期」「没填凭据」
   和「能用」分开——只看有没有填过凭据说明不了现在还能不能用。

只读配置和发探测请求，不落任务数据。
"""
from __future__ import annotations

import asyncio
import re
import time

import httpx

from ..config import config
from . import source_health
from . import space as space_mod
from .sources import passive, search

# ─────────────── 分组 ───────────────
GROUP_ORDER = ("equity", "app", "icp", "space", "passive", "engine", "content")

GROUP_LABEL = {
    "equity": "工商主体",
    "app": "应用与小程序市场",
    "icp": "备案",
    "space": "空间测绘",
    "passive": "证书 · 被动 DNS",
    "engine": "搜索引擎",
    "content": "内容平台",
}

GROUP_HINT = {
    "equity": "股东、对外投资、分支机构。停掉只少一层子公司，主体本身仍会查。",
    "app": "按主体名反查 App / 小程序榜单。",
    "icp": "按主体名反查备案。没有工商登录态时靠这两路兜底。",
    "space": "按域名 / 主体做空间测绘检索，扩 host 和指纹。停掉这一路，"
             "被动收集里复用同一把 key 的那一路也会跟着停。",
    "passive": "证书透明日志、被动 DNS、情报库。被动收集的主干。",
    "engine": "关键词召回：把品牌名变成站点和接口线索。",
    "content": "微博、公众号文章。按品牌名召回内容里冒出来的域名和主体。",
}

# 凭据字段的人话名
CRED_LABEL = {
    "key": "Key",
    "keys": "Key",
    "id": "API ID",
    "secret": "API Secret",
    "user": "账号",
    "token": "Token",
    "cookie": "Cookie",
}

# 各分组固定键。顺序就是面板上的顺序：常用的在前。
_EQUITY = ("aiqicha", "tianyancha", "xiaolanben", "qichacha", "qcctid",
           "riskbird", "kuaicha", "qidian", "chinaz")
_APP = ("qimai", "aldzs", "appbk")
_ICP = ("miit", "icp")
_SPACE = tuple(space_mod.QUERY_FUNCS)
_ENGINE_ORDER = ("toutiao", "sogou", "sogou_m", "bing_rss", "baidu",
                 "bing", "360", "baidu_m", "so360_m", "ddg", "yyb")
_CONTENT = ("weibo", "weixin")

# 被动收集里有两路其实是搜索引擎：不单列，归到对应引擎开关上。
# 否则「停掉搜索·Bing」之后被动那一枪还会继续打，面板和实际行为对不上。
_ENGINE_OF = {"bing": "engine:bing", "duckduckgo": "engine:ddg"}

# 被动收集：去掉已经单独成组的那几路，避免同一个 key 出现两行。
_SKIP_PASSIVE = set(_SPACE) | set(_ICP) | {"equity"} | set(_ENGINE_OF)
_PASSIVE = tuple(n for n in passive.DOMAIN_SOURCES if n not in _SKIP_PASSIVE)

# 需要凭据的渠道与字段名。没列出的（免费公开源、备案）不需要。
_CREDS = {
    "aiqicha": ("cookie",),
    "tianyancha": ("cookie", "token", "tycid"),
    "qichacha": ("cookie",),
    "qcctid": ("cookie",),
    "xiaolanben": ("cookie",),
    "riskbird": ("cookie",),
    "kuaicha": ("cookie",),
    "qidian": ("cookie",),
    "chinaz": ("cookie",),
    "qimai": ("cookie",),
    "aldzs": ("cookie",),
    "appbk": ("cookie",),
    "weibo": ("cookie",),
    "weixin": ("cookie",),
    "fofa": ("key",),
    "hunter": ("key",),
    "quake": ("key",),
    "zoomeye": ("key",),
    "shodan": ("key",),
    "zero_zone": ("key",),
    "censys": ("id", "secret"),
    "virustotal": ("key",),
    "securitytrails": ("key",),
    "passivetotal": ("user", "key"),
    "chaos": ("key",),
    "threatbook": ("key",),
    "github": ("token",),
}

#: 凭据「任填一项即算配好」的来源。这几路的登录态整个挂在 Cookie 上，
#: 另填的 token / tycid 只是 Cookie 里抠不到时的覆盖项，不能当必填。
_ANY_ONE = {"tianyancha"}


def _sec(name: str) -> dict:
    return config.section("sources").get(name) or {}


def _new(key: str, group: str, kind: str, source: str = "", doc: str = "") -> dict:
    src = source or key
    creds = tuple(_CREDS.get(src, ()))
    return {
        "key": key,
        "group": group,
        "kind": kind,
        "source": src,
        "creds": creds,
        "label": source_health.label_source(key),
        "doc": doc,
        "need": " / ".join(CRED_LABEL.get(c, c) for c in creds),
    }


def _build() -> list[dict]:
    specs: list[dict] = []
    for key in _EQUITY:
        specs.append(_new(key, "equity", "equity"))
    for key in _APP:
        specs.append(_new(key, "app", "app"))
    for key in _ICP:
        specs.append(_new(key, "icp", "icp"))
    for key in _SPACE:
        specs.append(_new(key, "space", "space", doc="按域名做空间测绘检索"))
    for name in _PASSIVE:
        fn = passive.DOMAIN_SOURCES.get(name)
        doc = (fn.__doc__ or "").strip().splitlines()[0] if fn and fn.__doc__ else ""
        specs.append(_new(name, "passive", "passive", doc=doc))
    engines = list(_ENGINE_ORDER) + [e for e in search.ENGINES if e not in _ENGINE_ORDER]
    for name in engines:
        specs.append(_new(f"engine:{name}", "engine", "engine", source=name))
    for name in _CONTENT:
        # 内容平台两路各有自己的探测口，kind 直接用源名，不用一个共用的 content 分支
        specs.append(_new(name, "content", name))
    return specs


_SPECS: list[dict] = _build()
_BY_KEY: dict[str, dict] = {s["key"]: s for s in _SPECS}
_KEYS: set[str] = set(_BY_KEY)

# 源名 → 渠道 key。被动收集 / 采集流程拿源名来问「这一路还开不开」。
_SOURCE_KEY: dict[str, str] = {}
for _s in _SPECS:
    _SOURCE_KEY.setdefault(_s["source"], _s["key"])


# ─────────────── 开关 ───────────────
def off_list() -> list[str]:
    """当前停用的渠道 key。只留目录里认识的，旧配置里已下线的名字顺手忽略。"""
    raw = config.get("channels", "off", default=[]) or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for one in raw:
        k = str(one or "").strip()
        if k and k in _KEYS and k not in out:
            out.append(k)
    return out


def _off_reason(key: str) -> str:
    """这一路为什么不会发请求；空串表示开着。"""
    if key in off_list():
        return "你手动停用了这一路，采集流程不会为它发请求"
    spec = _BY_KEY.get(key) or {}
    src = spec.get("source") or key
    if src and _sec(src).get("enabled") is False:
        return f"配置里 sources.{src}.enabled 为 false，采集流程不会为它发请求（在上面重新启用会一并打开）"
    return ""


def is_enabled(key: str) -> bool:
    """渠道 key 是否启用。不认识的 key 当开——新加的源不该因为没登记就被静默关掉。"""
    k = str(key or "").strip()
    if not k:
        return True
    return not _off_reason(k)


def source_on(name: str) -> bool:
    """被动收集里这一路是否要跑。"""
    n = str(name or "").strip()
    if not n:
        return True
    return is_enabled(_SOURCE_KEY.get(n) or n)


def engine_on(name: str) -> bool:
    """搜索引擎那一路是否要跑。"""
    n = str(name or "").strip().lower()
    if not n:
        return True
    return is_enabled(_ENGINE_OF.get(n) or f"engine:{n}")


def save_off(keys: list[str]) -> dict:
    """整表覆盖停用列表。重新启用的会把残留的 sources.<名>.enabled: false 一并打开。"""
    want: list[str] = []
    for one in keys or []:
        k = str(one or "").strip()
        if k and k in _KEYS and k not in want:
            want.append(k)
    config.persist({"channels": {"off": want}})
    config.reload()
    reopened: list[str] = []
    for key in _SPECS:
        if key["key"] in want:
            continue
        src = key["source"]
        if src and _sec(src).get("enabled") is False:
            config.persist({"sources": {src: {"enabled": True}}})
            reopened.append(src)
    if reopened:
        config.reload()
    return {"off": off_list(), "reopened": reopened}


# ─────────────── 目录 ───────────────
EXTRA_STATE = {"untested": "未测"}

# 「失效」这一档底下原因差得远：额度用尽、登录态被风控、只是超时。面板只写「失效」，
# 人会去换一份其实还有效的 Cookie。原因是哪一种就写哪一种。
_NARROW_LABEL = {"quota", "blocked", "timeout", "no_credential"}


def _state_label(state: str, status: str) -> str:
    if status in _NARROW_LABEL:
        return source_health.text_of(status)
    return source_health.STATE_LABEL.get(state) or EXTRA_STATE.get(state) or state

# 最近一次自检结果，按渠道 key 存。只活在进程里：自检是「现在能不能用」，
# 重启后继续显示上一次的结论会骗人。
_LAST: dict[str, dict] = {}
_TESTED_AT: list[str] = [""]


def _cred_ok(source: str, creds) -> tuple[bool, list[str]]:
    """凭据够不够。``keys`` 列表里有任意一把也算填了 key。"""
    if not creds:
        return True, []
    sec = _sec(source)
    if source in _ANY_ONE:
        # 这几路的登录态整个都在 Cookie 里，单独填的那几项只是覆盖项，任意一项有就够。
        if any(str(sec.get(c) or "").strip() for c in creds):
            return True, []
        return False, list(creds)
    missing: list[str] = []
    for c in creds:
        val = str(sec.get(c) or "").strip()
        if not val and c == "key":
            if [k for k in (sec.get("keys") or []) if str(k or "").strip()]:
                continue
        if not val:
            missing.append(c)
    return (not missing), missing


def catalog() -> list[dict]:
    """全量渠道 + 开关 + 上次自检结论。"""
    offs = set(off_list())
    rows: list[dict] = []
    for spec in _SPECS:
        key, src = spec["key"], spec["source"]
        cred_ok, missing = _cred_ok(src, spec["creds"])
        enabled = key not in offs
        note = ""
        status = ""
        last = _LAST.get(key) or {}
        if enabled:
            reason = _off_reason(key)
            if reason:
                enabled = False
        if not enabled:
            state = "skip"
            status = "skip"
            note = _off_reason(key) or "已停用"
        elif not cred_ok:
            state = "config"
            status = "no_credential"
            note = "未填写 " + " / ".join(CRED_LABEL.get(c, c) for c in missing)
        elif last:
            state = last.get("state") or "untested"
            status = last.get("status") or ""
            note = last.get("note") or ""
        else:
            state = "untested"
            note = "还没测过。点「一键自检」会真打一次最小请求"
        rows.append({
            "key": key,
            "group": spec["group"],
            "kind": spec["kind"],
            "source": src,
            "label": spec["label"],
            "doc": spec["doc"],
            "need": spec["need"],
            "enabled": enabled,
            "cred_ok": cred_ok,
            "missing": missing,
            "state": state,
            "state_label": _state_label(state, status),
            "status": status,
            "status_text": source_health.text_of(status) if status else "",
            "note": note,
            "items": int(last.get("items") or 0) if enabled else 0,
            "ms": int(last.get("ms") or 0) if enabled else 0,
            "base": last.get("base") or "",
            "query": last.get("query") or "",
            "at": last.get("at") or "",
        })
    return rows


def _count(rows: list[dict], state: str) -> int:
    return sum(1 for r in rows if r["enabled"] and r["state"] == state)


def _late_count(rows: list[dict]) -> int:
    """超时单独计数：多半只是这一路慢，别和真失效混在一起吓人。"""
    return sum(1 for r in rows if r["enabled"] and r["state"] == "dead"
               and r["status"] == "timeout")


def _dead_count(rows: list[dict]) -> int:
    """真失效：超时的另算，否则人会把能用只是慢的渠道一起删掉。"""
    return sum(1 for r in rows if r["enabled"] and r["state"] == "dead"
               and r["status"] != "timeout")


def overview() -> dict:
    """按分组的整表 + 顶部统计。前端只渲染这一份。"""
    rows = catalog()
    groups = []
    for g in GROUP_ORDER:
        items = [r for r in rows if r["group"] == g]
        groups.append({
            "group": g,
            "label": GROUP_LABEL.get(g, g),
            "hint": GROUP_HINT.get(g, ""),
            "items": items,
            "total": len(items),
            "enabled": sum(1 for r in items if r["enabled"]),
            "usable": sum(1 for r in items
                          if r["enabled"] and r["state"] in ("ok", "empty", "partial")),
            "dead": _dead_count(items),
            "timeout": _late_count(items),
            "untested": _count(items, "untested"),
        })
    return {
        "groups": groups,
        "items": rows,
        "total": len(rows),
        "enabled": sum(1 for r in rows if r["enabled"]),
        "usable": sum(1 for r in rows
                      if r["enabled"] and r["state"] in ("ok", "empty", "partial")),
        "dead": _dead_count(rows),
        "timeout": _late_count(rows),
        "config": _count(rows, "config"),
        "skip": sum(1 for r in rows if r["state"] == "skip"),
        "untested": _count(rows, "untested"),
        "off": off_list(),
        "tested_at": _TESTED_AT[0],
    }


# ─────────────── 自检 ───────────────
_PROBE_KEYWORD = "腾讯"
_PROBE_COMPANY = "深圳市腾讯计算机系统有限公司"
_PROBE_DOMAIN = "example.com"
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*(\.[a-z0-9][a-z0-9\-]*)+$")

_TIMEOUT = {
    "equity": 25.0,
    "app": 25.0,
    "icp": 40.0,
    "passive": 25.0,
    "space": 25.0,
    "engine": 25.0,
    "weibo": 20.0,
    "weixin": 20.0,
}
# 归档 / 全量索引类天生慢，按组超时会把「能用但慢」判成失效，单独放宽
_SLOW_SOURCE = {"wayback": 45.0, "commoncrawl": 40.0, "subdomain_center": 40.0}
# 整轮自检的总时长上限：一路卡死不能把一次点按钮拖成好几分钟
_BUDGET = 200.0


_QUOTA_HINTS = ("额度", "余额", "配额", "quota", "套餐", "剩余次数")
_COLD_HINTS = ("未填写", "未配置", "没有配置", "还没有填", "缺少 key")


def _timeout_of(spec: dict) -> float:
    """这一路的判定超时。慢源单独放宽，免得把能用但排队久的判成失效。"""
    return float(_SLOW_SOURCE.get(spec["source"], _TIMEOUT.get(spec["kind"], 30.0)))


def _status_from_text(msg: str) -> str:
    """把一句回包里的提示归到状态。额度耗尽比「请求失败」更该单独说。"""
    m = (msg or "").strip()
    if not m:
        return "error"
    low = m.lower()
    if any(h in m or h in low for h in _QUOTA_HINTS):
        return "quota"
    if any(h in m or h in low for h in _COLD_HINTS):
        return "no_credential"
    return source_health.status_of_error(m)


def _merge_status(ok: bool, msg: str) -> str:
    """返回码说通了，但回包里可能写着「额度用尽」——那个才是现在能不能用。"""
    hint = _status_from_text(msg)
    if hint in ("quota", "no_credential"):
        return hint
    if ok:
        return "ok"
    return hint or "error"


def _probe_domain(query: str) -> str:
    """被动源要一个真域名。自检框里填的是品牌名时退回示例域名。"""
    q = (query or "").strip().lower()
    if q and _DOMAIN_RE.match(q):
        return q
    return _PROBE_DOMAIN


async def _probe_equity(spec: dict, query: str) -> dict:
    from .collectors import equity
    res = await equity.probe_source(spec["source"])
    msg = str(res.get("msg") or "")
    status = _merge_status(bool(res.get("ok")), msg)
    if status == "error" and ("302" in msg or "登录" in msg):
        # 备用工商源登录态过期最典型的表现是 302 跳登录页，回包里不会有一句「未登录」
        status = "blocked"
    return {
        "status": status,
        "note": msg,
        "items": 0,
        "base": str(res.get("base") or ""),
    }


async def _probe_miit(spec: dict, query: str) -> dict:
    # unitName 是精确匹配，简称查不到不等于渠道坏了：自检默认用登记全称打一枪
    kw = (query or "").strip() or _PROBE_COMPANY
    rows = await passive.miit_company(kw, kinds=("site",), pages=1,
                                      size=5, retry=1)
    err = passive.miit_last_error()
    if err:
        return {"status": _status_from_text(err), "note": err, "items": len(rows)}
    return {
        "status": "ok" if rows else "empty",
        "note": "" if rows else "连通但没检索到这个主体的备案（换个主体全称再试）",
        "items": len(rows),
    }


async def _probe_passive(spec: dict, query: str) -> dict:
    name = spec["source"]
    fn = passive.DOMAIN_SOURCES.get(name)
    if fn is None:
        return {"status": "error", "note": "代码里没有这一路", "items": 0}
    dom = _probe_domain(query)
    res = await fn(dom)
    items = len(res.subdomains) + len(res.records)
    return {
        "status": source_health.status_of_error(res.error),
        "note": res.error or "",
        "items": items,
        "query": dom,
    }


async def _probe_icp(spec: dict, query: str) -> dict:
    if spec["source"] == "miit":
        return await _probe_miit(spec, query)
    return await _probe_passive(spec, query)


async def _probe_space(spec: dict, query: str) -> dict:
    q = (query or "").strip()
    res = await space_mod.probe(spec["source"], q if _DOMAIN_RE.match(q.lower()) else "",
                                size=1)
    err = str(res.get("error") or "")
    return {
        "status": "ok" if res.get("ok") else _status_from_text(err),
        "note": "" if res.get("ok") else err,
        "items": int(res.get("rows") or 0),
        "base": str(res.get("base") or ""),
        "query": str(res.get("query") or ""),
    }


async def _probe_engine(spec: dict, query: str) -> dict:
    name = spec["source"]
    if name not in search.ENGINES:
        return {"status": "error", "note": "代码里没有这个引擎", "items": 0}
    q = (query or "").strip() or _PROBE_KEYWORD
    loop = asyncio.get_running_loop()
    fails, until = search._engine_fail.get(name, (0, 0.0))
    if fails and loop.time() < until:
        return {"status": "blocked",
                "note": f"上一次调用失败，冷却中（还剩 {int(until - loop.time())} 秒）",
                "items": 0}
    t0 = time.time()
    hits = await search._engine_call(name, q, 20.0)
    spent = time.time() - t0
    if hits:
        return {"status": "ok", "note": "", "items": len(hits)}
    if spent >= 17.0:
        # 卡满引擎超时和「真的被风控」是两件事：前者换个网络可能就好了
        return {"status": "timeout",
                "note": f"{int(spent)} 秒没取到结果，多半是这一路慢或被限速，未必不能用"}
    fails, _ = search._engine_fail.get(name, (0, 0.0))
    if fails:
        return {"status": "blocked",
                "note": "取不到结果：可能被风控或页面结构变了", "items": 0}
    return {"status": "empty", "note": "连通但这个词没命中，换个词再试", "items": 0}


async def _probe_weibo(spec: dict, query: str) -> dict:
    from .collectors import weibo
    ck = weibo._cookie()
    if not ck:
        return {"status": "no_credential", "note": "未填写 Cookie", "items": 0}
    q = (query or "").strip() or _PROBE_KEYWORD
    rows, notes = await weibo._api_search(q, ck, pages=1, timeout=12)
    bad = [n for n in (notes or [])
           if ("登录" in n or "432" in n or "非 JSON" in n or "失效" in n)]
    if bad:
        return {"status": "blocked", "note": "；".join(bad)[:200], "items": len(rows)}
    return {
        "status": "ok" if rows else "empty",
        "note": "" if rows else "连通但这个词没检索到内容",
        "items": len(rows),
    }


async def _probe_weixin(spec: dict, query: str) -> dict:
    """公众号文章那一路：带已保存的 Cookie 打一次首页，看是不是被拦。

    没有 Cookie 也照打——公开文章本来就能抓，只是量少；拦了才说不可用。
    """
    from .collectors import mp
    headers = mp._wx_headers() or {}
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers,
                                     follow_redirects=True) as cli:
            r = await cli.get("https://mp.weixin.qq.com/")
            text = (r.text or "")[:3000]
    except Exception as e:
        return {"status": "error", "note": f"请求失败：{type(e).__name__}", "items": 0}
    if "环境异常" in text or "验证" in text:
        return {"status": "blocked",
                "note": f"HTTP {r.status_code}，公众号页要求验证，Cookie 需要重新取",
                "items": 0}
    if r.status_code >= 500:
        return {"status": "error", "note": f"HTTP {r.status_code}，上游异常", "items": 0}
    note = "" if mp._wx_cookie() else "没填 Cookie，只能抓公开文章"
    return {"status": "ok", "note": note, "items": 0,
            "base": "https://mp.weixin.qq.com/"}


_PROBES = {
    "equity": _probe_equity,
    "app": _probe_equity,
    "icp": _probe_icp,
    "passive": _probe_passive,
    "space": _probe_space,
    "engine": _probe_engine,
    "weibo": _probe_weibo,
    "weixin": _probe_weixin,
}


def _store_probe(key: str, *, status: str, note: str, items: int = 0,
                 base: str = "", ms: int = 0, query: str = "") -> dict:
    status = status or "error"
    state = source_health.state_of(status)
    row = {
        "key": key,
        "status": status,
        "status_text": source_health.text_of(status),
        "state": state,
        "state_label": _state_label(state, status),
        "note": str(note or "")[:240],
        "items": int(items or 0),
        "base": base,
        "ms": int(ms or 0),
        "query": query,
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _LAST[key] = row
    return dict(row)


async def probe_one(key: str, query: str = "") -> dict:
    """测一路：真打一次最小请求，结论留在内存里给面板用。"""
    spec = _BY_KEY.get(str(key or "").strip())
    if spec is None:
        return {"key": key, "label": source_health.label_source(str(key or "")),
                "status": "error", "status_text": "未知渠道", "state": "dead",
                "state_label": "失效", "note": "目录里没有这一路", "items": 0,
                "base": "", "ms": 0, "query": "", "at": "", "enabled": True}
    fn = _PROBES.get(spec["kind"])
    q = (query or "").strip()
    t0 = time.time()
    if fn is None:
        got = {"status": "error", "note": "这一路没有探测器"}
    else:
        try:
            got = await asyncio.wait_for(fn(spec, q), _timeout_of(spec))
        except asyncio.TimeoutError:
            # 超时只说明这一枪慢，不说明渠道坏了：备注里点明，别让人直接删渠道
            got = {"status": "timeout",
                   "note": f"{int(_timeout_of(spec))} 秒内没返回，可能只是这一路慢或被限速，稍后可单测一次"}
        except Exception as e:
            got = {"status": "error", "note": f"{type(e).__name__}: {str(e)[:160]}"}
    got = dict(got or {})
    row = _store_probe(
        spec["key"],
        status=str(got.get("status") or "error"),
        note=str(got.get("note") or ""),
        items=int(got.get("items") or 0),
        base=str(got.get("base") or ""),
        ms=int((time.time() - t0) * 1000),
        query=str(got.get("query") or q),
    )
    row["label"] = spec["label"]
    return row


async def probe_many(keys: list[str] | None = None, query: str = "") -> list[dict]:
    """并发自检。不传 keys 就是全量；按目录顺序返回，前端不用再排。"""
    want = {str(k or "").strip() for k in (keys or []) if str(k or "").strip()}
    picked = [s for s in _SPECS if not want or s["key"] in want]
    sem = asyncio.Semaphore(12)
    deadline = time.time() + _BUDGET

    def late(spec: dict, note: str) -> dict:
        row = _store_probe(spec["key"], status="timeout", note=note, query=query)
        row["label"] = spec["label"]
        return row

    async def one(spec: dict) -> dict:
        # 一路卡住不能拖住整轮：每路超时之外再压一个总预算，到点就记「没测成」
        async with sem:
            left = deadline - time.time()
            if left < 2.0:
                return late(spec, f"整轮自检到 {int(_BUDGET)} 秒上限，这一路没轮到")
            try:
                return await asyncio.wait_for(probe_one(spec["key"], query), left)
            except asyncio.TimeoutError:
                return late(spec, f"整轮自检到 {int(_BUDGET)} 秒上限，这一路没测完")

    rows = await asyncio.gather(*(one(s) for s in picked))
    if rows:
        _TESTED_AT[0] = time.strftime("%Y-%m-%d %H:%M:%S")
    order = {s["key"]: i for i, s in enumerate(_SPECS)}
    return sorted(rows, key=lambda r: order.get(str(r.get("key") or ""), 999))
