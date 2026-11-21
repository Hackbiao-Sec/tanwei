"""网络空间测绘多引擎统一检索与查询语法库。

两件事：

1. **统一检索**：同一句语法分别送到 FOFA / Hunter / Quake / ZoomEye / Shodan / 零零信安，
   各平台字段归一化成同一套键，调用方不用记每家返回的字段名。
   各平台字段能力差别靠 ``FIELD_MATRIX`` 说明，界面上只展示该平台真有的字段。

2. **语法模板 + 补全**：内置国内常见 OA / 中间件 / 框架的测绘语法，
   以及 ``--`` 触发的位置感知补全（``app=`` ``title=`` ``port=`` ``domain=`` 等）。

字段命名以各平台官方 API 的返回为准，内部统一键见 ``NORMAL_FIELDS``。
"""

from __future__ import annotations

import asyncio
import base64
import re
import time
from dataclasses import dataclass, field

import httpx

from ..config import config

# ─────────────── 统一字段 ───────────────
NORMAL_FIELDS = (
    "host", "url", "ip", "port", "protocol", "domain", "title", "server",
    "app", "os", "isp", "cname", "icp", "cert_cn", "favicon_hash", "product",
    "country", "province", "city", "banner", "updated", "engine", "raw",
)

# 各平台实际能返回的字段（前端据此决定列；不虚构能力）
FIELD_MATRIX: dict[str, tuple[str, ...]] = {
    "fofa": ("host", "url", "ip", "port", "protocol", "domain", "title", "server",
             "os", "isp", "cname", "icp", "cert_cn", "favicon_hash", "product",
             "country", "province", "city", "banner", "updated"),
    "hunter": ("host", "url", "ip", "port", "protocol", "domain", "title", "server",
               "app", "os", "cname", "cert_cn", "country", "province", "city", "banner",
               "updated"),
    "quake": ("host", "url", "ip", "port", "protocol", "domain", "title", "server",
              "app", "os", "favicon_hash", "product", "country", "province", "city",
              "banner"),
    "zoomeye": ("host", "url", "ip", "port", "protocol", "domain", "title", "server",
                "app", "os", "favicon_hash", "country", "city", "banner"),
    "shodan": ("host", "url", "ip", "port", "protocol", "domain", "title", "server",
               "os", "product", "country", "city", "banner", "updated"),
    "zero_zone": ("host", "url", "ip", "port", "domain", "title", "app", "icp", "banner"),
}

ENGINE_LABEL = {
    "fofa": "FOFA",
    "hunter": "奇安信 Hunter",
    "quake": "360 Quake",
    "zoomeye": "知道创宇 ZoomEye",
    "shodan": "Shodan",
    "zero_zone": "零零信安 0.zone",
}

# 语法模板里用来标「这句在哪些平台生效」的写法 → 内部引擎名
PLATFORM_ALIAS = {
    "fofa": "fofa", "hunter": "hunter", "quake": "quake", "zoomeye": "zoomeye",
    "shodan": "shodan", "零零信安": "zero_zone", "zero_zone": "zero_zone", "0.zone": "zero_zone",
}


@dataclass
class SpaceResult:
    engine: str
    query: str
    rows: list[dict] = field(default_factory=list)
    total: int = 0
    error: str = ""
    fields: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.error

    def as_dict(self) -> dict:
        return {
            "engine": self.engine,
            "label": ENGINE_LABEL.get(self.engine, self.engine),
            "query": self.query,
            "count": len(self.rows),
            "total": self.total,
            "error": self.error,
            "fields": list(self.fields or FIELD_MATRIX.get(self.engine, ())),
            "rows": self.rows,
        }


# ─────────────── HTTP 客户端 ───────────────
def _sec(engine: str) -> dict:
    return config.section("sources").get(engine, {}) or {}


def _base(engine: str, default: str) -> str:
    """根地址：中转站优先，其次 api，最后官方兜底（与 config.src_base 一致）。

    key 由中转站签发时，直连官方一定报账号/Key 无效；必须和中转站成对使用。
    """
    sec = _sec(engine)
    return (sec.get("relay") or sec.get("api") or "").strip().rstrip("/") or default


def _client(engine: str, timeout: float = 30.0, force_proxy: bool = False) -> httpx.AsyncClient:
    """按引擎配置决定走不走代理。

    ``trust_env`` 默认关掉：否则 httpx 会拾取系统环境变量里的代理，
    配置说「直连」实际仍被本机抓包代理接管，回包是拦截页而不是平台 JSON。
    需要吃系统代理时把 ``proxy.sources_trust_env`` 打开。
    """
    proxy = config.get("proxy", "url") or ""
    use = bool(config.get("proxy", "sources_via_proxy", default=True)) or force_proxy
    trust_env = bool(config.get("proxy", "sources_trust_env", default=False))
    kw: dict = {"timeout": timeout, "verify": False, "trust_env": trust_env,
                "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}}
    if use and proxy:
        kw["proxy"] = proxy
    del engine
    return httpx.AsyncClient(**kw)


def _str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v if x is not None)
    return str(v)


def _num(v) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return 0


def _row(engine: str, **kw) -> dict:
    rec = {k: "" for k in NORMAL_FIELDS}
    for k, v in kw.items():
        if k in rec:
            rec[k] = v if isinstance(v, int) else _str(v)
    rec["engine"] = engine
    if not rec["host"] and rec["domain"]:
        rec["host"] = rec["domain"]
    if not rec["url"] and rec["host"]:
        rec["url"] = rec["host"]
    return rec


# ─────────────── FOFA ───────────────
# 字段按「账号实际权限」分三档：高权限账号能取 icon_hash/cert，普通账号一取就 820001。
# 逐档降级，保证换 key 后不用改代码也能出数据。
_FOFA_FIELD_LEVELS = (
    "host,ip,port,protocol,domain,title,server,cname,icp,cert,icon_hash,"
    "product,os,org,country_name,province,city,banner,lastupdatetime",
    "host,ip,port,protocol,domain,title,server,cname,icp,cert,"
    "product,os,org,country_name,province,city,banner,lastupdatetime",
    "host,ip,port,protocol,domain,title,server",
)
_FOFA_FIELDS = _FOFA_FIELD_LEVELS[0]
# 单行几 KB 的重字段：只在取少量样本时带，翻多页时丢掉
_FOFA_HEAVY = ("cert", "banner")
_FOFA_FIELD_DENIED = ("无权限", "没有权限", "820001", "820002", "820003")
# 已经探明这台账号能取的字段；命中后本轮进程内不再重复撞被拒的那一档
_FOFA_OK_FIELDS = ""
# 中转站限速回的是 45012；撞上了退避重试一次比直接判失败有用
_FOFA_RATE_HINT = ("45012", "请求速度过快", "too many request", "频率")
# 直连中转站慢到超时/被限速时，改走本机代理；成功一次后本轮优先走代理
_FOFA_LINK_BY_PROXY = False
_FOFA_LINK_HINT = ("FOFA 请求失败", "[-501]", "服务错误", "45012", "请求速度过快")


def _fofa_link_broken(msg: str) -> bool:
    """这次的失败像不像「链路不行」，而不是「key/语法不行」。"""
    return any(k in (msg or "") for k in _FOFA_LINK_HINT)


def _fofa_denied_field(msg: str) -> str:
    """从「没有权限搜索icon_hash字段」里抠出被拒的字段名，抠不到回空串。"""
    m = re.search(r"(?:搜索|查询|返回)\s*([A-Za-z_][A-Za-z0-9_]*)\s*字段", msg or "")
    return m.group(1) if m else ""


def _fofa_levels(size: int = 100) -> list:
    """本次可试的字段档位（原档, 实际字段）。

    探明能用的排最前，省掉每次先撞一遍 820001；翻多页时丢掉证书全文和
    banner 这类单行几 KB 的字段，回包体积和解析开销都能降一个量级。
    """
    order = ([_FOFA_OK_FIELDS] if _FOFA_OK_FIELDS else []) + \
        [lv for lv in _FOFA_FIELD_LEVELS if lv != _FOFA_OK_FIELDS]
    out, seen = [], set()
    for lv in order:
        eff = ",".join(f for f in lv.split(",") if f not in _FOFA_HEAVY) if size > 10 else lv
        if not eff or eff in seen:
            continue
        seen.add(eff)
        out.append((lv, eff))
    return out


async def _fofa_fetch(query: str, size: int, cli, retry_net: bool = True) -> SpaceResult:
    """用给定的通道打一次查询；字段权限被拒时自己降档。"""
    global _FOFA_OK_FIELDS
    res = SpaceResult("fofa", query, fields=FIELD_MATRIX["fofa"])
    key = _sec("fofa").get("key") or ""
    if not key:
        res.error = "未配置 sources.fofa.key"
        return res
    base = _base("fofa", "https://fofa.info")
    qb = base64.b64encode(query.encode()).decode()
    levels = _fofa_levels(size)
    while levels:
        want, fields = levels[0]
        names = fields.split(",")
        page, got, denied = 1, 0, ""
        res.rows = []
        while got < size and page <= 10:
            data, tries = {}, 0
            while True:
                try:
                    r = await cli.get(f"{base}/api/v1/search/all",
                                      params={"key": key, "qbase64": qb, "fields": fields,
                                              "size": min(1000, size - got), "page": page})
                    data = r.json()
                except Exception as e:
                    if retry_net and tries < 1:
                        tries += 1
                        await asyncio.sleep(1.5)
                        continue
                    res.error = f"FOFA 请求失败：{type(e).__name__}"
                    return res
                if data.get("error") and tries < 2:
                    msg0 = _str(data.get("errmsg") or data.get("message") or "")
                    if any(k in msg0 for k in _FOFA_RATE_HINT):
                        tries += 1
                        await asyncio.sleep(2.0 * tries)
                        continue
                break
            if data.get("error"):
                msg = _str(data.get("errmsg") or data.get("message") or "未知原因")
                if any(k in msg for k in _FOFA_FIELD_DENIED):
                    denied = _fofa_denied_field(msg) or ""
                    break
                res.error = f"平台拒绝：{msg}"
                return res
            rows = data.get("results") or []
            res.total = _num(data.get("size")) or res.total
            if not rows:
                break
            for raw in rows:
                d = dict(zip(names, raw))
                res.rows.append(_row(
                    "fofa", host=d.get("host"), ip=d.get("ip"), port=_num(d.get("port")),
                    protocol=d.get("protocol"), domain=d.get("domain"), title=d.get("title"),
                    server=d.get("server"), cname=d.get("cname"), icp=d.get("icp"),
                    cert_cn=d.get("cert"), favicon_hash=d.get("icon_hash"),
                    product=d.get("product"), os=d.get("os"), isp=d.get("org"),
                    country=d.get("country_name"),
                    province=d.get("province"), city=d.get("city"), banner=d.get("banner"),
                    updated=d.get("lastupdatetime"), raw=", ".join(_str(x) for x in raw),
                ))
            got += len(rows)
            if len(rows) < 1000:
                break
            page += 1
            await asyncio.sleep(0.6)
        if not denied:
            if want:
                _FOFA_OK_FIELDS = want
            res.error = ""
            return res
        # 这一档被字段权限挡住：去掉被拒字段再试，仍不行就整档降级
        keep = [f for f in names if f != denied]
        if not keep or denied not in names:
            levels = levels[1:]
        else:
            trimmed = ",".join(keep)
            levels = [(want if denied not in want else "", trimmed)] + \
                [lv for lv in levels[1:] if lv[1] != trimmed]
        if not levels:
            res.error = f"平台拒绝：没有权限搜索 {denied or '所需'} 字段"
            return res
    return res


def _fofa_spare_proxy() -> str:
    """直连不通时可换的备用通道：本机已配的代理地址。

    配置本来就要求走代理时不返回备用地址，避免拿同一条路重试。
    """
    proxy = (config.get("proxy", "url") or "").strip()
    if not proxy:
        return ""
    if bool(config.get("proxy", "sources_via_proxy", default=True)):
        return ""
    return proxy


async def query_fofa(query: str, size: int = 100) -> SpaceResult:
    global _FOFA_LINK_BY_PROXY
    spare = _fofa_spare_proxy()
    # 中转站上游自己排队，单次可能要十几秒；超时给足，别把「慢」判成「不可用」
    async with _client("fofa", timeout=60.0, force_proxy=_FOFA_LINK_BY_PROXY) as cli:
        res = await _fofa_fetch(query, size, cli, retry_net=not spare)
    if not res.error or not _fofa_link_broken(res.error):
        return res
    if not spare or _FOFA_LINK_BY_PROXY:
        return res
    # 直连这条链路连不上：改走本机代理再试一次，成功就记下来，后续优先走代理
    async with _client("fofa", timeout=60.0, force_proxy=True) as cli:
        again = await _fofa_fetch(query, size, cli)
    if not again.error:
        _FOFA_LINK_BY_PROXY = True
    else:
        return res
    return again




# ─────────────── 奇安信 Hunter ───────────────
_HUNTER_MAP = {
    "domain": "domain", "ip": "ip", "port": "port", "protocol": "protocol",
    "web_title": "title", "component": "app", "os": "os", "url": "url",
    "country": "country", "province": "province", "city": "city",
    "updated_at": "updated", "company": "product", "ip_attr": "isp",
}


async def query_hunter(query: str, size: int = 100) -> SpaceResult:
    res = SpaceResult("hunter", query, fields=FIELD_MATRIX["hunter"])
    key = _sec("hunter").get("key") or ""
    if not key:
        res.error = "未配置 sources.hunter.key"
        return res
    base = _base("hunter", "https://hunter.qianxin.com")
    b64 = base64.urlsafe_b64encode(query.encode()).decode()
    page, got = 1, 0
    page_size = min(100, size)
    async with _client("hunter") as cli:
        while got < size and page <= 20:
            try:
                r = await cli.get(f"{base}/openApi/search",
                                  params={"api-key": key, "search": b64,
                                          "page": page, "page_size": page_size})
                data = r.json()
            except Exception as e:
                res.error = f"Hunter 请求失败：{type(e).__name__}"
                break
            code = _str(data.get("code"))
            if code and code not in ("200", "0"):
                res.error = f"Hunter: {data.get('message') or code}"
                break
            body = data.get("data") or {}
            res.total = _num(body.get("total")) or res.total
            arr = body.get("arr") or []
            if not arr:
                break
            for item in arr:
                kw = {}
                for src, dst in _HUNTER_MAP.items():
                    if item.get(src) not in (None, ""):
                        kw[dst] = item.get(src)
                kw["port"] = _num(item.get("port"))
                kw["banner"] = item.get("banner") or item.get("web_title") or ""
                kw["server"] = item.get("protocol") or ""
                res.rows.append(_row("hunter", **kw))
            got += len(arr)
            if len(arr) < page_size:
                break
            page += 1
    return res


# ─────────────── 360 Quake ───────────────
async def query_quake(query: str, size: int = 100) -> SpaceResult:
    res = SpaceResult("quake", query, fields=FIELD_MATRIX["quake"])
    key = _sec("quake").get("key") or ""
    if not key:
        res.error = "未配置 sources.quake.key"
        return res
    base = _base("quake", "https://quake.360.net")
    start, got = 0, 0
    async with _client("quake") as cli:
        while got < size and start < 10000:
            try:
                r = await cli.post(f"{base}/api/v3/search/quake_service",
                                   json={"query": query, "start": start,
                                         "size": min(500, size - got), "ignore_cache": True},
                                   headers={"X-QuakeToken": key})
                data = r.json()
            except Exception as e:
                res.error = f"Quake 请求失败：{type(e).__name__}"
                break
            if _str(data.get("code")) not in ("0", ""):
                res.error = f"Quake: {data.get('message') or data.get('code')}"
                break
            res.total = _num((data.get("meta") or {}).get("pagination", {}).get("total")) or res.total
            arr = data.get("data") or []
            if not arr:
                break
            for item in arr:
                svc = item.get("service") if isinstance(item.get("service"), dict) else {}
                http = svc.get("http") if isinstance(svc.get("http"), dict) else {}
                loc = item.get("location") if isinstance(item.get("location"), dict) else {}
                res.rows.append(_row(
                    "quake",
                    host=http.get("host") or item.get("domain") or item.get("ip"),
                    url=http.get("url"),
                    ip=item.get("ip"),
                    port=_num(item.get("port")),
                    protocol=svc.get("name") or item.get("transport"),
                    domain=item.get("domain"),
                    title=http.get("title"),
                    server=http.get("server"),
                    app=svc.get("product") or svc.get("name"),
                    os=item.get("os_name"),
                    favicon_hash=http.get("favicon", {}).get("hash")
                    if isinstance(http.get("favicon"), dict) else "",
                    product=svc.get("product"),
                    country=loc.get("country_cn") or loc.get("country_en"),
                    province=loc.get("province_cn"),
                    city=loc.get("city_cn"),
                    banner=_str(svc.get("response"))[:600],
                ))
            got += len(arr)
            if len(arr) < 500:
                break
            start += len(arr)
    return res


# ─────────────── ZoomEye ───────────────
async def query_zoomeye(query: str, size: int = 100) -> SpaceResult:
    res = SpaceResult("zoomeye", query, fields=FIELD_MATRIX["zoomeye"])
    key = _sec("zoomeye").get("key") or ""
    if not key:
        res.error = "未配置 sources.zoomeye.key"
        return res
    base = _base("zoomeye", "https://api.zoomeye.org")
    page, got = 1, 0
    async with _client("zoomeye") as cli:
        while got < size and page <= 10:
            try:
                r = await cli.get(f"{base}/host/search",
                                  params={"query": query, "page": page, "pagesize": min(100, size)},
                                  headers={"API-KEY": key})
                data = r.json()
            except Exception as e:
                res.error = f"ZoomEye 请求失败：{type(e).__name__}"
                break
            if data.get("error"):
                res.error = f"ZoomEye: {data.get('error')}"
                break
            res.total = _num(data.get("total")) or res.total
            arr = data.get("matches") or []
            if not arr:
                break
            for item in arr:
                portinfo = item.get("portinfo") if isinstance(item.get("portinfo"), dict) else {}
                res.rows.append(_row(
                    "zoomeye",
                    host=item.get("domain") or item.get("ip"),
                    ip=item.get("ip"),
                    port=_num(portinfo.get("port")),
                    protocol=portinfo.get("app") or portinfo.get("service"),
                    domain=item.get("domain"),
                    title=(item.get("title") or (_str(item.get("title")) if item.get("title") else "")),
                    server=portinfo.get("product"),
                    app=portinfo.get("app") or portinfo.get("product"),
                    os=portinfo.get("os") or (item.get("geoinfo") or {}).get("os") if isinstance(item.get("geoinfo"), dict) else portinfo.get("os"),
                    favicon_hash=(item.get("iconhash_md5") or item.get("iconhash") or ""),
                    country=item.get("geoinfo", {}).get("country", {}).get("names", {}).get("zh-CN")
                    if isinstance(item.get("geoinfo"), dict) else "",
                    city=item.get("geoinfo", {}).get("city", {}).get("names", {}).get("zh-CN")
                    if isinstance(item.get("geoinfo"), dict) else "",
                    banner=_str(item.get("banner"))[:600],
                ))
            got += len(arr)
            if len(arr) < 100:
                break
            page += 1
    return res


# ─────────────── Shodan ───────────────
async def query_shodan(query: str, size: int = 100) -> SpaceResult:
    res = SpaceResult("shodan", query, fields=FIELD_MATRIX["shodan"])
    key = _sec("shodan").get("key") or ""
    if not key:
        res.error = "未配置 sources.shodan.key"
        return res
    base = _base("shodan", "https://api.shodan.io")
    page, got = 1, 0
    async with _client("shodan") as cli:
        while got < size and page <= 10:
            try:
                r = await cli.get(f"{base}/shodan/host/search",
                                  params={"key": key, "query": query, "page": page})
                data = r.json()
            except Exception as e:
                res.error = f"Shodan 请求失败：{type(e).__name__}"
                break
            if data.get("error"):
                res.error = f"Shodan: {data.get('error')}"
                break
            res.total = _num(data.get("total")) or res.total
            arr = data.get("matches") or []
            if not arr:
                break
            for item in arr:
                http = item.get("http") if isinstance(item.get("http"), dict) else {}
                loc = item.get("location") if isinstance(item.get("location"), dict) else {}
                hosts = item.get("hostnames") or []
                dom = next((h for h in hosts if h and "." in h), "")
                res.rows.append(_row(
                    "shodan",
                    host=dom or item.get("ip_str"),
                    url=(f"{http.get('scheme')}://{dom or item.get('ip_str')}:{item.get('port')}"
                         if http.get("scheme") else ""),
                    ip=item.get("ip_str"),
                    port=_num(item.get("port")),
                    protocol=item.get("transport"),
                    domain=dom,
                    title=http.get("title"),
                    server=http.get("server"),
                    os=item.get("os"),
                    isp=item.get("isp") or item.get("org"),
                    product=item.get("product"),
                    country=loc.get("country_name"),
                    city=loc.get("city"),
                    banner=_str(item.get("data"))[:600],
                    updated=item.get("timestamp"),
                ))
            got += len(arr)
            if len(arr) < 100:
                break
            page += 1
    return res


# ─────────────── 零零信安 0.zone ───────────────
async def query_zero_zone(query: str, size: int = 100) -> SpaceResult:
    """0.zone 的语法以 ``company=`` / ``domain=`` 这类键值为主，直接透传。"""
    res = SpaceResult("zero_zone", query, fields=FIELD_MATRIX["zero_zone"])
    key = _sec("zero_zone").get("key") or ""
    if not key:
        res.error = "未配置 sources.zero_zone.key"
        return res
    url = _base("zero_zone", "https://0.zone/api/data/")
    try:
        async with _client("zero_zone") as cli:
            r = await cli.post(url, json={"query": query, "query_type": "site",
                                          "page": 1, "pagesize": min(100, size)},
                               headers={"Content-Type": "application/json", "X-Key": key})
            data = r.json()
    except Exception as e:
        res.error = f"0.zone 请求失败：{type(e).__name__}"
        return res
    if _num(data.get("code")) not in (0, 200) and data.get("code") is not None:
        res.error = f"0.zone: {data.get('message') or data.get('code')}"
        return res
    body = data.get("data") or data.get("list") or []
    if isinstance(body, dict):
        body = body.get("list") or body.get("data") or []
    res.total = _num((data.get("page") or {}).get("total")) if isinstance(data.get("page"), dict) else 0
    for item in body:
        res.rows.append(_row(
            "zero_zone",
            host=item.get("domain") or item.get("url") or item.get("ip"),
            url=item.get("url"),
            ip=item.get("ip"),
            port=_num(item.get("port")),
            domain=item.get("domain"),
            title=item.get("title"),
            app=item.get("app") or item.get("company"),
            icp=item.get("icp") or item.get("icp_name"),
            banner=_str(item.get("banner"))[:600],
        ))
    return res


QUERY_FUNCS = {
    "fofa": query_fofa,
    "hunter": query_hunter,
    "quake": query_quake,
    "zoomeye": query_zoomeye,
    "shodan": query_shodan,
    "zero_zone": query_zero_zone,
}


# 连通测试用各家的最小合法语法（字段名各家不同，不能共用一句）
PROBE_QUERY = {
    "fofa": 'domain="example.com"',
    "hunter": 'domain="example.com"',
    "quake": 'domain:"example.com"',
    "zoomeye": 'site:"example.com"',
    "shodan": "hostname:example.com",
    "zero_zone": 'domain="example.com"',
}

# 命中这些片段说明是「这把 key 不能用」，换下一把还有机会
_KEY_REJECT = ("账号无效", "-700", "未登录", "invalid", "unauthorized",
               "额度", "quota", "次数", "key", "token")


def keys_of(engine: str) -> list[str]:
    """主 key + ``keys`` 列表，去重保序；配了多份 key 时按序轮换。"""
    sec = _sec(engine)
    out: list[str] = []
    for one in [sec.get("key")] + list(sec.get("keys") or []):
        k = str(one or "").strip()
        if k and k not in out:
            out.append(k)
    return out


def _use_key(engine: str, key: str) -> None:
    config.section("sources").setdefault(engine, {})["key"] = key


_KEY_LOCKS: dict[str, asyncio.Lock] = {}


def _key_lock(engine: str) -> asyncio.Lock:
    """换 key 会改引擎的当前 key，同一引擎的轮换必须串行。"""
    lock = _KEY_LOCKS.get(engine)
    if lock is None:
        lock = asyncio.Lock()
        _KEY_LOCKS[engine] = lock
    return lock


def _key_rejected(err: str) -> bool:
    low = (err or "").lower()
    return any(t.lower() in low for t in _KEY_REJECT)


async def search(engine: str, query: str, size: int = 100) -> SpaceResult:
    name = (engine or "").lower()
    fn = QUERY_FUNCS.get(name)
    if fn is None:
        return SpaceResult(engine, query, error=f"不支持的引擎：{engine}")
    query = (query or "").strip()
    if not query:
        return SpaceResult(engine, query, error="语法为空")
    size = max(1, min(int(size or 100), 1000))
    keys = keys_of(name)
    if len(keys) <= 1:
        return await fn(query, size)

    backup = _sec(name).get("key") or ""
    last: SpaceResult | None = None
    async with _key_lock(name):
        for key in keys:
            _use_key(name, key)
            res = await fn(query, size)
            if not res.error:
                return res
            last = res
            if not _key_rejected(res.error):
                return res      # 不是 key 的问题，换 key 也没用
        if backup:              # 全失败：别把无效 key 写死进配置
            _use_key(name, backup)
    return last or SpaceResult(name, query, error="无可用 key")


async def probe(engine: str, query: str = "", size: int = 1) -> dict:
    """连通测试：真打一次最小查询，回报耗时、命中数、错误原文。

    只看「有没有填 key」说明不了能不能用——额度和账号状态只有打一次才知道。
    """
    name = (engine or "").lower()
    if name not in QUERY_FUNCS:
        return {"engine": name, "label": ENGINE_LABEL.get(name, name),
                "ok": False, "error": f"不支持的引擎：{engine}"}
    q = (query or "").strip() or PROBE_QUERY.get(name, 'domain="example.com"')
    t0 = time.time()
    res = await search(name, q, size)
    return {
        "engine": name,
        "label": ENGINE_LABEL.get(name, name),
        "ok": not res.error,
        "error": res.error,
        "rows": len(res.rows),
        "total": res.total,
        "query": q,
        "keys": len(keys_of(name)),
        "base": _base(name, ""),
        "ms": int((time.time() - t0) * 1000),
    }


async def search_many(engines: list[str], query: str, size: int = 100) -> list[SpaceResult]:
    """多引擎并发检索。某一台挂了不影响其它台的结果。"""
    names = [e for e in dict.fromkeys(engines or []) if e in QUERY_FUNCS]
    if not names:
        return []
    got = await asyncio.gather(*(search(n, query, size) for n in names), return_exceptions=True)
    out: list[SpaceResult] = []
    for name, item in zip(names, got):
        if isinstance(item, SpaceResult):
            out.append(item)
        else:
            out.append(SpaceResult(name, query, error=f"{type(item).__name__}: {item}"))
    return out


def harvest_hosts(results: list[SpaceResult], limit: int = 5000) -> list[str]:
    """把检索结果归一成「可当任务目标的 host」：域名优先，其次 IP。"""
    seen: set[str] = set()
    out: list[str] = []
    for res in results:
        for rec in res.rows:
            host = rec.get("domain") or rec.get("host") or ""
            host = str(host).split("://")[-1].split("/")[0].split(":")[0].strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            out.append(host)
            if len(out) >= limit:
                return out
    return out


# ─────────────── 语法模板库 ───────────────
@dataclass(frozen=True)
class SyntaxTemplate:
    key: str
    label: str
    syntax: str
    platforms: tuple[str, ...]
    note: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "syntax": self.syntax,
                "platforms": list(self.platforms), "note": self.note}


def _all() -> tuple[str, ...]:
    return ("fofa", "hunter", "quake", "zoomeye", "shodan", "zero_zone")


SYNTAX_TEMPLATES: tuple[SyntaxTemplate, ...] = (
    # —— 备案 / 主体 ——
    SyntaxTemplate("icp-name-hunter", "按备案企业名查",
                    'icp.name="{企业名称}"', ("hunter",),
                    "Hunter 独有：直接按 ICP 主办单位过滤"),
    SyntaxTemplate("icp-number-hunter", "按备案号查",
                    'icp.number="{备案号}"', ("hunter",)),
    SyntaxTemplate("icp-number-fofa", "按备案号查",
                    'icp="{备案号}"', ("fofa", "quake")),
    SyntaxTemplate("domain-suffix", "按域名后缀查",
                    'domain="{根域名}"', ("fofa", "quake")),
    SyntaxTemplate("cert-domain", "按证书域名查",
                    'cert="{域名}"', ("fofa", "quake")),
    SyntaxTemplate("cname", "按 CNAME 查云厂商资产",
                    'cname="{cname}"', ("fofa",)),
    # —— 响应过滤 ——
    SyntaxTemplate("filter-5xx", "过滤 5xx 响应",
                    'status_code!=502 && status_code!=503',
                    ("fofa", "hunter", "quake", "zoomeye", "zero_zone"),
                    "配合其它条件用 && 拼接"),
    SyntaxTemplate("filter-error-page", "排除错误页标题",
                    'title!="502 Bad Gateway" && title!="503 Service Unavailable"',
                    ("hunter",)),
    # —— 国产 OA / 协同 ——
    SyntaxTemplate("weaver", "泛微 OA",
                    'app="泛微-云桥e-Bridge" || app="泛微-EMobile" || app="泛微-EOffice" || '
                    'app="泛微-OA（e-cology）" || app="泛微-E-Weaver" || app="泛微-协同办公OA"',
                    ("fofa",)),
    SyntaxTemplate("tongda", "通达 OA",
                    'app="TDXK-通达OA" || body="tongda.ico" || icon_hash="-759108386" || '
                    '(title="网络智能办公系统" && body="office")',
                    ("fofa",)),
    SyntaxTemplate("seeyon", "致远互联",
                    'app="致远互联-OA" || icon_hash="1238198741" || icon_hash="-47597126" || '
                    'icon_hash="-529860832" || icon_hash="-271445657"',
                    ("fofa",)),
    SyntaxTemplate("landray", "蓝凌 OA",
                    'app="Landray-OA系统" || icon_hash="831854882"', ("fofa",)),
    SyntaxTemplate("ezoffice", "万户 ezOFFICE",
                    'app="万户网络-ezOFFICE" || icon_hash="-1827521324"', ("fofa",)),
    SyntaxTemplate("hongfan", "红帆 ioffice",
                    'title="ioffice" || body="ioffice"', ("fofa",)),
    # —— ERP / 中间件 ——
    SyntaxTemplate("yonyou", "用友",
                    'app="用友-UFIDA-NC" || app="用友-YonBIP" || app="用友-PLM" || '
                    'app="用友-NC-Cloud" || app="用友-U8远程"', ("fofa",)),
    SyntaxTemplate("kingdee", "金蝶",
                    'app="Kingdee-EAS" || app="金蝶云星空-管理中心" || body="kdUtils.min.js" || '
                    'app="Apusic应用服务器"', ("fofa",)),
    SyntaxTemplate("esafenet", "亿赛通电子文档安全",
                    'body="/CDGServer3/index.jsp" || title="电子文档安全管理系统" || '
                    'cert="esafenet" || app="亿赛通-DLP"', ("fofa",)),
    SyntaxTemplate("ruoyi", "若依框架",
                    'icon_hash="-1231872293" || icon_hash="706913071" || '
                    'body="认证失败，无法访问系统资源"', ("fofa",)),
    SyntaxTemplate("tomcat", "Tomcat",
                    'title="Apache Tomcat" || app="tomcat" || icon_hash="-297069493"', ("fofa",)),
    SyntaxTemplate("weblogic", "WebLogic",
                    'header="WebLogic" || app="Weblogic_interface_7001" || app="BEA-WebLogic-Server"',
                    ("fofa",)),
    SyntaxTemplate("nacos", "Nacos",
                    'app="nacos" && (port="8848" || icon_hash="13942501")', ("fofa",)),
    SyntaxTemplate("spring-boot", "Spring Boot 未授权面",
                    'body="Whitelabel Error Page" || body="/actuator/env"', ("fofa",)),
    SyntaxTemplate("nextjs", "Next.js 静态资源特征",
                    'app="Next.js" && body="/_next/static/chunks/app/" || app="React.js"',
                    ("fofa",), "原文条件间缺 && ，此处按正确布尔补齐"),
    SyntaxTemplate("fnos", "飞牛 fnOS",
                    'title="飞牛 fnOS"', ("fofa",)),
)


def templates(platform: str = "", keyword: str = "") -> list[dict]:
    """列出语法模板。``platform`` 过滤生效平台，``keyword`` 模糊匹配名称/语法。"""
    eng = PLATFORM_ALIAS.get((platform or "").strip().lower(), platform or "")
    kw = (keyword or "").strip().lower()
    out = []
    for t in SYNTAX_TEMPLATES:
        if eng and eng not in t.platforms:
            continue
        if kw and kw not in t.label.lower() and kw not in t.syntax.lower() and kw not in t.key:
            continue
        out.append(t.as_dict())
    return out


# ─────────────── 语法自动补全 ───────────────
# 各平台支持的字段关键字（用于输入提示，不代替平台校验）
FIELD_KEYWORDS: dict[str, tuple[str, ...]] = {
    "fofa": ("app", "title", "body", "header", "domain", "host", "ip", "port", "protocol",
             "server", "cname", "cert", "icp", "icon_hash", "fid", "country", "province",
             "city", "os", "banner", "status_code", "type", "product"),
    "hunter": ("app", "title", "body", "header", "domain", "domain.suffix", "ip", "port",
               "protocol", "web.title", "web.body", "cert", "icp.name", "icp.number", "os",
               "country", "province", "city", "status_code", "component", "asset_tag"),
    "quake": ("app", "title", "body", "domain", "ip", "port", "service", "server", "cert",
              "icp", "favicon", "os", "country", "province", "city", "transport", "response"),
    "zoomeye": ("app", "title", "body", "domain", "hostname", "ip", "port", "service",
                "server", "iconhash", "os", "country", "city", "cidr", "device"),
    "shodan": ("http.title", "http.html", "http.component", "http.favicon.hash", "hostname",
               "domains", "ip", "port", "org", "os", "product", "country", "city",
               "ssl.cert.subject.cn", "net"),
    "zero_zone": ("company", "domain", "site", "app", "email", "icp", "ip", "title"),
}

OPERATORS = ("=", "!=", "*=", "==", "&&", "||", "!()", "()")


def _platform_keys(engine: str) -> tuple[str, ...]:
    return FIELD_KEYWORDS.get(PLATFORM_ALIAS.get(engine, engine), FIELD_KEYWORDS["fofa"])


def complete(text: str, cursor: int | None = None, engine: str = "fofa",
             limit: int = 30) -> dict:
    """位置感知补全。

    三种情况：
      * 光标在某个字段名上 → 补字段关键字
      * 刚打完 ``字段=`` → 补该字段常见取值（如 ``app=`` 出常见产品名）
      * 补算子与逻辑连接符
    """
    text = text or ""
    pos = len(text) if cursor is None else max(0, min(int(cursor), len(text)))
    head = text[:pos]
    tail = text[pos:]
    word = ""
    for i in range(len(head) - 1, -1, -1):
        ch = head[i]
        if ch.isalnum() or ch in "._-":
            word = head[i] + word
        else:
            break
    prefix = head[:len(head) - len(word)]
    keys = _platform_keys(engine)

    items: list[dict] = []
    kind = "field"
    stripped = prefix.rstrip()
    after_operator = bool(stripped) and stripped[-1] in "&|"
    field_capture = stripped.rstrip("=!*").strip().split()
    last_field = field_capture[-1] if field_capture else ""

    if stripped.endswith(("=", "!=", "*=")) or stripped.endswith("!="):
        kind = "value"
        for v in FIELD_VALUES.get(last_field, ()):
            if not word or v.lower().startswith(word.lower()):
                items.append({"label": v, "insert": v, "kind": "value", "field": last_field})
        if not items and word:
            items.append({"label": word, "insert": word, "kind": "value", "field": last_field})
        if not items:
            for k in keys:
                items.append({"label": k, "insert": k, "kind": "field"})
            kind = "field"
    elif after_operator:
        kind = "operator"

    if kind == "field":
        lw = word.lower()
        for k in keys:
            if not lw or k.lower().startswith(lw) or lw in k.lower():
                items.append({"label": k, "insert": k, "kind": "field"})
        if not lw:
            for op in OPERATORS:
                items.append({"label": op, "insert": f" {op} ", "kind": "operator"})
    elif kind == "operator":
        for op in OPERATORS:
            items.append({"label": op, "insert": f" {op} ", "kind": "operator"})

    seen: set[str] = set()
    uniq = []
    for it in items:
        if it["label"] in seen:
            continue
        seen.add(it["label"])
        uniq.append(it)
    return {"engine": PLATFORM_ALIAS.get(engine, engine), "kind": kind,
            "word": word, "start": len(head) - len(word), "end": pos,
            "tail": tail, "items": uniq[:limit]}


FIELD_VALUES: dict[str, tuple[str, ...]] = {
    "app": ("泛微-OA（e-cology）", "TDXK-通达OA", "致远互联-OA", "Landray-OA系统", "nacos",
            "tomcat", "用友-UFIDA-NC", "Kingdee-EAS", "若依", "Apusic应用服务器"),
    "protocol": ("http", "https", "ssh", "ftp", "rdp", "telnet", "smtp", "mysql", "redis",
                 "mongodb", "postgresql", "ldap"),
    "port": ("80", "443", "8080", "8443", "22", "3306", "6379", "27017", "9200", "8848",
             "7001", "8443", "11211"),
    "server": ("nginx", "Apache", "IIS", "Tomcat", "Jetty", "openresty", "Caddy"),
    "os": ("Windows", "Windows Server 2012", "Windows Server 2016", "Linux", "CentOS",
           "Ubuntu", "VMware ESXi"),
    "country": ("CN", "HK", "TW", "US", "JP", "SG"),
    "status_code": ("200", "301", "302", "401", "403", "404", "500"),
    "type": ("service", "subdomain"),
    "service": ("http", "https", "http_proxy", "ssh", "mysql", "redis"),
    "transport": ("tcp", "udp"),
    "http.component": ("jQuery", "Bootstrap", "Vue.js", "React", "WordPress"),
    "title": ("后台管理", "登录", "系统", "OA", "ERP", "统一身份认证"),
    "body": ('"/actuator/env"', '"/swagger-ui.html"', '"Whitelabel Error Page"'),
}

# 域名 / 主机类字段没有固定取值，补几个占位写法，免得光标处空着
FIELD_PLACEHOLDER: dict[str, tuple[str, ...]] = {
    "domain": ('"example.com"', '"*.example.com"'),
    "domain.suffix": ('"example.com"',),
    "host": ('"example.com"', '"1.1.1.1"'),
    "hostname": ('"example.com"',),
    "domains": ('"example.com"',),
    "ip": ('"1.1.1.1"', '"1.1.1.0/24"'),
    "cname": ('"example.cdn.com"',),
    "cert": ('"example.com"',),
    "cert_cn": ('"example.com"',),
    "icp": ('"京ICP备00000000号"',),
    "icp.name": ('"企业名称"',),
    "icp.number": ('"京ICP备00000000号"',),
    "iconhash": ('"-123456789"',),
    "icon_hash": ('"-123456789"',),
    "http.favicon.hash": ('"-123456789"',),
    "favicon": ('"-123456789"',),
    "fid": ('"rqhtFwF4sIF7wTOroKTQGw=="',),
    "org": ('"Example Corp"',),
    "company": ('"企业名称"',),
    "net": ('"1.1.1.0/24"',),
    "cidr": ('"1.1.1.0/24"',),
    "province": ("Beijing", "Zhejiang", "Guangdong"),
    "city": ("Beijing", "Hangzhou", "Shenzhen"),
}
FIELD_VALUES.update({k: v for k, v in FIELD_PLACEHOLDER.items() if k not in FIELD_VALUES})



