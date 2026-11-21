"""组件指纹识别：把「这是不是某组件」和「这个组件能不能免认证进」拆开。

与 `probe.py` 的分工：

- `probe.py`：命中就是要报的未授权面（Nacos 用户列表、Docker API…）。
- `identify.py`（本文件）：先认组件，命中不等于洞。用于把站点归到具体产品
  （FineReport / Shiro / Weaver / xxl-job…），供后续按组件选探针、也给资产表打标。

20 条识别规则：18 条移植自 ARL-NPoC `xing/plugins/identify`，另补 CDP 远程调试口与
k8s Konnectivity 隧道两条。原来每条是一个独立插件，
这里压成「候选路径 + 判定函数」的表格，失败不抛错、命中即止。
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Callable

import httpx

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def _client(timeout: float = 8.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True, trust_env=False,
                             headers={"User-Agent": UA, "Accept": "*/*"})


async def _req(c: httpx.AsyncClient, url: str, *, method: str = "GET", data: Any = None,
               json_body: Any = None, headers: dict | None = None) -> httpx.Response | None:
    try:
        if method == "POST":
            return await c.post(url, data=data, json=json_body, headers=headers)
        return await c.get(url, headers=headers)
    except Exception:
        return None


def _text(r: httpx.Response | None, limit: int = 400_000) -> str:
    if r is None or len(r.content) > limit:
        return ""
    return r.text


def _cookie(r: httpx.Response | None, name: str) -> str:
    return (r.headers.get("Set-Cookie") or "") if r is not None and name in (r.headers.get("Set-Cookie") or "") else ""


# ─────────────── 判定函数 ───────────────
# 入参 (response, text)，返回证据字符串；空串 = 未命中。

def _adminer(r, t) -> str:
    if r is not None and r.status_code == 200 and b">Login - Adminer<" in r.content:
        return "Adminer 数据库管理页"
    return ""


def _any800(r, t) -> str:
    if "new Date(nowtime_time+offset+offset_b);" in t:
        return "Any800 全渠道智能客服"
    if ">Any800v" in t:
        return "Any800 全渠道智能客服（登录页）"
    return ""


def _cas(r, t) -> str:
    if "Apereo" in t and "cas" in t.lower():
        return "Apereo CAS 单点登录"
    return ""


def _ofbiz(r, t) -> str:
    if r is None:
        return ""
    if "OFBiz.Visitor=" in (r.headers.get("Set-Cookie") or ""):
        return "Apache OFBiz（Set-Cookie 带 OFBiz.Visitor）"
    if ">OFBiz" in t:
        return "Apache OFBiz"
    return ""


def _clickhouse(r, t) -> str:
    r_ = r
    if r_ is None:
        return ""
    summary = r_.headers.get("X-ClickHouse-Summary") or ""
    if "read_rows" in summary and b"Ok." in r_.content:
        return "ClickHouse HTTP 接口"
    return ""


def _finereport_v10(r, t) -> str:
    if "frontSeed" in t and "name" in t:
        return "帆软 FineReport V10（system/info 可读）"
    return ""


def _finereport(r, t) -> str:
    if "jQuery=" in t and "<title>" not in t:
        return "帆软 FineReport（ReportServer 资源可读）"
    return ""


def _grafana(r, t) -> str:
    if "Grafana</title>" in t:
        return "Grafana"
    return ""


def _graphql(r, t) -> str:
    if r is not None and r.status_code == 400 and "query missing" in t and "<" not in t:
        return "GraphQL 端点（GET 返回 query missing）"
    return ""


def _harbor(r, t) -> str:
    if r is not None and r.status_code == 200 and '"harbor_version"' in t and "<" not in t:
        return "Harbor 镜像仓库 API（systeminfo 免认证）"
    return ""


def _hystrix(r, t) -> str:
    if ">Hystrix Dashboard<" in t:
        return "Hystrix Dashboard"
    return ""


def _nacos(r, t) -> str:
    if "<title>Nacos</title>" in t:
        return "Nacos 控制台"
    return ""


def _weblogic(r, t) -> str:
    if "WLS Administration Console" in t:
        return "Oracle WebLogic 控制台"
    return ""


def _shiro(r, t) -> str:
    if r is not None and "rememberMe=deleteMe" in (r.headers.get("Set-Cookie") or ""):
        return "Apache Shiro（rememberMe 探测回 deleteMe）"
    return ""


def _swagger(r, t) -> str:
    if r is None or r.status_code != 200:
        return ""
    body = t.strip()
    if not (body.startswith("{") and body.endswith("}")):
        return ""
    if '"paths"' in body and '"swagger"' in body:
        try:
            paths = list((r.json() or {}).get("paths", {}).keys())
        except Exception:
            paths = []
        extra = f"，接口 {len(paths)} 个（{', '.join(paths[:4])}）" if paths else ""
        return f"Swagger 文档可读{extra}"
    return ""


def _vcenter(r, t) -> str:
    if r is None or r.status_code != 200:
        return ""
    m = re.findall(r"<fullName>(.*?)</fullName>", t)
    if len(m) == 1:
        return f"VMware vCenter {m[0]}"
    return ""


def _ecology(r, t) -> str:
    if '$(this).attr("src","image/btn_help_click' in t:
        return "泛微 Ecology"
    if r is not None and "ecology_JSessionid" in (r.headers.get("Set-Cookie") or ""):
        return "泛微 Ecology（Set-Cookie 带 ecology_JSessionid）"
    return ""


def _xxl_job(r, t) -> str:
    if "<b>XXL</b>JOB" in t:
        return "xxl-job-admin 调度平台"
    return ""


def _cdp(r, t) -> str:
    """Chrome DevTools 远程调试口：/json/version 直接给浏览器版本和 WebSocket 地址。"""
    if r is None or r.status_code != 200:
        return ""
    body = t.strip()
    if not (body.startswith("{") and '"webSocketDebuggerUrl"' in body):
        return ""
    m = re.search(r'"Browser"\s*:\s*"([^"]{1,80})"', body)
    return f"Chrome 远程调试口（{m.group(1) if m else 'CDP'}）"


def _konnectivity(r, t) -> str:
    """kube-apiserver 的 Konnectivity 代理：拿到即可经它转发到集群内任意地址。"""
    if r is None:
        return ""
    if r.status_code == 404 and "konnectivity" in t.lower():
        return "Konnectivity 代理（k8s 节点隧道）"
    if r.status_code in (400, 405) and "CONNECT" in t.upper():
        return "Konnectivity 代理（k8s 节点隧道）"
    return ""


# ─────────────── 规则表 ───────────────
# (键, 组件名, 说明, [(路径, 判定, 方法, 请求体/头)])
# 请求体/头用来处理 vCenter 的 SOAP 与 Shiro 的 rememberMe。
ShiroHeaders = {"Cookie": "rememberMe=1"}
VCENTER_XML = (b'<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
               b'xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" '
               b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><env:Body>'
               b'<RetrieveServiceContent xmlns="urn:vim25">'
               b'<_this type="ServiceInstance">ServiceInstance</_this>'
               b'</RetrieveServiceContent></env:Body></env:Envelope>')

RULES: tuple[dict[str, Any], ...] = (
    {"key": "adminer", "app": "Adminer", "kind": "数据库管理", "check": _adminer,
     "paths": ("/admin/adminer.php", "/adminer.php", "/adminer/adminer.php")},
    {"key": "any800", "app": "Any800", "kind": "客服系统", "check": _any800,
     "paths": ("/any800/echatManager.do", "/ump/umpLogin/login")},
    {"key": "apereo_cas", "app": "Apereo CAS", "kind": "统一认证", "check": _cas,
     "paths": ("/cas/login",)},
    {"key": "ofbiz", "app": "Apache OFBiz", "kind": "ERP", "check": _ofbiz,
     "paths": ("/webtools/control/main",)},
    {"key": "clickhouse_http", "app": "ClickHouse", "kind": "数据库", "check": _clickhouse,
     "paths": ("/ping", "/?query=SELECT%201")},
    {"key": "finereport_v10", "app": "帆软 FineReport V10", "kind": "报表", "check": _finereport_v10,
     "paths": ("/webroot/decision/system/info", "/decision/system/info")},
    {"key": "finereport", "app": "帆软 FineReport", "kind": "报表", "check": _finereport,
     "paths": ("/webroot/ReportServer?op=resource&resource=/com/fr/web/jquery.js",
               "/WebReport/ReportServer?op=resource&resource=/com/fr/web/jquery.js",
               "/seeyonreport/ReportServer?op=resource&resource=/com/fr/web/jquery.js")},
    {"key": "grafana", "app": "Grafana", "kind": "监控", "check": _grafana,
     "paths": ("/login", "/grafana/login", "/monitor/login")},
    {"key": "graphql", "app": "GraphQL", "kind": "接口", "check": _graphql,
     "paths": ("/graphql", "/v2/graphql", "/v1/graphql")},
    {"key": "harbor", "app": "Harbor", "kind": "镜像仓库", "check": _harbor,
     "paths": ("/api/systeminfo", "/harbor/api/systeminfo")},
    {"key": "hystrix", "app": "Hystrix Dashboard", "kind": "监控", "check": _hystrix,
     "paths": ("/hystrix", "/api/hystrix", "/actuator/hystrix", "/")},
    {"key": "nacos", "app": "Nacos", "kind": "配置中心", "check": _nacos,
     "paths": ("/nacos/", "/")},
    {"key": "weblogic", "app": "WebLogic", "kind": "中间件", "check": _weblogic,
     "paths": ("/console/css/test.css", "/#/console/css/test.css",
               "/console/css/test.css;/../../../")},
    {"key": "shiro", "app": "Apache Shiro", "kind": "框架", "check": _shiro,
     "paths": ("/",), "headers": ShiroHeaders},
    {"key": "swagger", "app": "Swagger", "kind": "接口文档", "check": _swagger,
     "paths": ("/swagger.json", "/api/swagger.json", "/swagger/v1/swagger.json",
               "/v2/api-docs", "/api/v2/api-docs", "/api/v2/swagger.json")},
    {"key": "vcenter", "app": "VMware vCenter", "kind": "虚拟化", "check": _vcenter,
     "paths": ("/sdk",), "method": "POST", "data": VCENTER_XML},
    {"key": "ecology", "app": "泛微 Ecology", "kind": "OA", "check": _ecology,
     "paths": ("/help/sys/help.html", "/js")},
    {"key": "xxl_job", "app": "xxl-job-admin", "kind": "调度", "check": _xxl_job,
     "paths": ("/toLogin", "/xxl-job/toLogin", "/xxl-job-admin/toLogin", "/xxl/toLogin",
               "/xxljob/toLogin")},
    {"key": "cdp", "app": "Chrome DevTools", "kind": "调试口", "check": _cdp,
     "paths": ("/json/version", "/json/list", "/json")},
    {"key": "konnectivity", "app": "k8s Konnectivity", "kind": "隧道代理", "check": _konnectivity,
     "paths": ("/konnectivity-agent", "/proxy/konnectivity", "/")},
)

IDENTIFY_PORTS = {
    "3306": ("adminer",), "5432": ("adminer",), "8123": ("clickhouse_http",),
    "8848": ("nacos",), "3000": ("grafana",), "9000": ("harbor",), "443": ("vcenter",),
    "9222": ("cdp",), "9229": ("cdp",), "8132": ("konnectivity",),
}


async def identify(base_url: str, *, port: int | None = None, deep: bool = False,
                   concurrency: int = 12) -> list[dict]:
    """识别一个站点上的组件。deep=False 时只打与端口相关或通用的规则。

    各规则之间并发跑；每条规则内部仍按路径顺序、命中即停，避免对同一站点的
    一个产品连打十几条。单站 60+ 请求串行会把 deep 阶段拖成分钟级。
    """
    base = base_url.rstrip("/")
    scoped = IDENTIFY_PORTS.get(str(port or ""), ())
    todo = RULES if (deep or not port) else [r for r in RULES if r["key"] in scoped]
    if not todo:
        todo = RULES
    sem = asyncio.Semaphore(max(1, concurrency))
    hits: list[dict] = []

    async def one(c: httpx.AsyncClient, rule: dict[str, Any]) -> dict | None:
        method = rule.get("method", "GET")
        for path in rule["paths"]:
            async with sem:
                r = await _req(c, f"{base}{path}", method=method, data=rule.get("data"),
                               headers=rule.get("headers"))
            if r is None:
                continue
            ev = rule["check"](r, _text(r))
            if ev:
                return {"key": rule["key"], "app": rule["app"], "kind": rule["kind"],
                        "url": f"{base}{path}", "evidence": ev, "status": r.status_code}
        return None

    async with _client() as c:
        results = await asyncio.gather(*(one(c, rule) for rule in todo), return_exceptions=True)
    for item in results:
        if isinstance(item, dict):
            hits.append(item)
    return hits


# 识别结果 → 该组件下值得继续探的路径，供 pipeline 决定下一步（不在此处发请求）。
NEXT_PATHS: dict[str, tuple[str, ...]] = {
    "swagger": ("/v3/api-docs", "/swagger-resources"),
    "ecology": ("/weaver/bsh.servlet.BshServlet", "/mobile/plugin/1/ofsLogin.jsp"),
    "finereport": ("/webroot/decision/login",),
    "xxl_job": ("/xxl-job-admin/jobinfo",),
    "grafana": ("/api/admin/settings", "/api/health"),
    "harbor": ("/api/v2.0/projects", "/api/v2.0/users"),
    "vcenter": ("/sdk/vimService.wsdl",),
    "shiro": ("/favicon.ico",),
}
