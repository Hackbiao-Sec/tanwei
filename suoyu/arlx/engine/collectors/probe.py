"""组件未授权访问 + 非 HTTP 端口指纹。

两种探针：

- HTTP 未授权（`http_probes`）：把常见中间件/数据库的「免认证管理口」探一遍，
  命中即返回证据行（URL、指纹字段、建议严重度）。
- TCP 指纹（`tcp_probes`）：往非 HTTP 端口发一条协议握手，按回包特征认服务，
  并顺带判断该服务有没有开认证（Redis / Memcached / ZooKeeper / MongoDB 等）。

参考实现来自 ARL-NPoC 的 xing 插件（noauth / sniffer）。
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

import httpx

from ...utils import host_of, is_ip, run_blocking

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"


def _client(timeout: float = 8.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True, trust_env=False,
                             headers={"User-Agent": UA, "Accept": "*/*"})


async def _get(c, url: str, method: str = "GET", json_body: dict | None = None,
               headers: dict | None = None, files: dict | None = None) -> httpx.Response | None:
    try:
        if method == "POST":
            return await c.post(url, json=None if files else json_body, files=files, headers=headers)
        return await c.get(url, headers=headers)
    except Exception:
        return None


async def _exists(c, url: str) -> bool:
    r = await _get(c, url)
    return r is not None and r.status_code < 400


# ─────────────── 路径组合：常见的 context-path 前缀 ───────────────
# 组件常挂在 /api、/prod-api、/jeecg-boot 之类的上下文中，逐个拼会让请求数暴涨，
# 所以每个组件只取前 2 个最可能的 prefix，命中即止。
PREFIXES = ("", "/api", "/prod-api", "/manage", "/management", "/jeecg-boot")

# ─────────────── HTTP 未授权探针 ───────────────
# 每条：(组件, 严重度, 描述, 候选路径列表, 判定函数)
# 判定函数拿到 (response, text) 返回证据字符串，空串表示没命中。
def _no_html(text: str) -> bool:
    head = text[:400].lower()
    return "<html" not in head and "<!doctype" not in head


def _actuator_env(r, t) -> str:
    if r.status_code == 200 and _no_html(t):
        m = re.search(r'"(java\.runtime\.version|java\.version|systemProperties|propertySources)"', t)
        if m:
            keys = re.findall(r'"([a-zA-Z0-9_.\-]{3,40})":', t)[:6]
            return f"env 端点免认证返回配置：命中 {m.group(1)}，可见键 {', '.join(keys)}"
    return ""


def _actuator_index(r, t) -> str:
    if r.status_code != 200 and r.status_code != 404:
        pass
    if r.status_code == 200 and _no_html(t) and '"_links"' in t:
        links = re.findall(r'"([a-z\-]{3,24})"\s*:\s*\{\s*"href"', t)
        return f"actuator 索引免认证列出端点：{', '.join(sorted(set(links))[:12]) or '无 href'}"
    return ""


def _actuator_heapdump(r, t) -> str:
    ct = (r.headers.get("content-type") or "").lower()
    if r.status_code == 200 and "octet-stream" in ct and len(r.content) > 1000:
        return f"heapdump 可未授权下载（{len(r.content) // 1024} KB 起），含全量堆内存"
    return ""


def _actuator_httptrace(r, t) -> str:
    if r.status_code == 200 and '{"traces"' in t.replace(" ", ""):
        return "httptrace 免认证返回历史请求记录（含 Cookie / 令牌头）"
    return ""


def _druid(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and '"ResultCode"' in t and '"RequestCount"' in t:
        return "Druid 监控页免认证可读 SQL 统计与会话列表"
    return ""


def _nacos(r, t) -> str:
    if r.status_code != 200 or not _no_html(t):
        return ""
    if '"pageNumber"' in t and '"password"' in t:
        try:
            data = r.json()
        except Exception:
            return ""
        users = (data.get("pageItems") or []) if isinstance(data, dict) else []
        names = [u.get("username") for u in users if isinstance(u, dict) and u.get("username")]
        return f"Nacos 用户列表免认证：{len(users)} 个账号（{', '.join(names[:6])}）"
    return ""


def _swagger(r, t) -> str:
    if r.status_code != 200:
        return ""
    try:
        data = r.json()
    except Exception:
        return ""
    if isinstance(data, dict) and ("swagger" in data or "openapi" in data) and data.get("paths"):
        paths = list(data["paths"].keys())
        return f"OpenAPI 文档免认证可读：{len(paths)} 个接口（{', '.join(paths[:4])}）"
    return ""


def _etcd(r, t) -> str:
    if r.status_code != 200:
        return ""
    if "etcdserver" in t and "etcdcluster" in t:
        return "etcd /version 免认证"
    return ""


def _etcd_data(r, t) -> str:
    if r.status_code != 200 or not _no_html(t):
        return ""
    if '"node":{' in t or '"action":"get"' in t or '"kvs"' in t:
        return "etcd 键值数据免认证可读（/v2/keys 或 /v3/kv/range 返回真实数据）"
    return ""


def _docker(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and '"ApiVersion"' in t:
        return "Docker Remote API 免认证，可直接控制宿主机容器"
    return ""


def _es(r, t) -> str:
    if r.status_code == 200 and ("/_cat/master" in t or "cluster_name" in t and "version" in t):
        return "Elasticsearch 免认证可读集群信息与索引"
    return ""


def _es_indices(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and '"index"' in t and '"docs.count"' in t:
        rows = re.findall(r'"index"\s*:\s*"([^"]+)"', t)
        return f"Elasticsearch 索引免认证可读：{len(rows)} 个索引（{', '.join(rows[:6])}）"
    return ""


def _kibana(r, t) -> str:
    if r.status_code == 200 and ".kibanaWelcomeView" in t:
        return "Kibana 界面免认证可访问"
    return ""


def _solr(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and "responseHeader" in t:
        cores = re.findall(r'"name"\s*:\s*"([^"]+)"', t)
        return f"Solr 核心管理口免认证：{len(cores)} 个 core（{', '.join(cores[:6])}）"
    return ""


def _hadoop(r, t) -> str:
    if r.status_code == 200 and "Hadoop" in t:
        m = re.search(r'"clusterInfo"\s*:\s*\{\s*"id"\s*:\s*(\d+)', t)
        return f"Hadoop YARN ResourceManager 免认证{('，集群 id ' + m.group(1)) if m else ''}"
    return ""


def _apollo(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and '"ownerEmail"' in t and '"ownerName"' in t:
        apps = re.findall(r'"appId"\s*:\s*"([^"]+)"', t)
        return f"apollo-adminservice 免认证列出应用：{len(apps)} 个（{', '.join(apps[:6])}）"
    return ""


def _kubelet(r, t) -> str:
    if r.status_code == 200 and '"nodeName"' in t and '"kubeletEndpoint"' in t:
        return "Kubelet /pods 免认证，可列出节点全部 Pod 与容器配置"
    return ""


def _kubelet_healthz(r, t) -> str:
    if r.status_code == 200 and t.strip() in ("ok", "Ok", "OK"):
        return "Kubelet 10250 免认证健康接口可达（可继续探 /pods）"
    return ""


def _k8s_api(r, t) -> str:
    if r.status_code == 200 and '"kind":"APIVersions"' in t.replace(" ", ""):
        return "Kubernetes apiserver 匿名可读 API 版本"
    return ""


def _onlyoffice(r, t) -> str:
    if r.status_code == 200 and "<Error>-7</Error>" in t and "<?xml" in t:
        return "OnlyOffice ConvertService 免认证（可被用作 SSRF / 文档转码入口）"
    return ""


def _milvus_users(r, t) -> str:
    if r.status_code != 200:
        return ""
    try:
        data = r.json()
    except Exception:
        return ""
    if isinstance(data, dict) and "usernames" in data:
        return f"Milvus 用户枚举免认证：{data['usernames']}"
    return ""


def _milvus_collections(r, t) -> str:
    if r.status_code != 200:
        return ""
    try:
        data = r.json()
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    cols = data.get("collection_names")
    status = data.get("status") if isinstance(data.get("status"), dict) else {}
    if isinstance(cols, list) or "error_code" in status:
        return f"Milvus 集合元数据免认证：{cols if cols else '已获得读权限'}"
    return ""


def _consul(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and '"ServiceName"' in t:
        svcs = re.findall(r'"ServiceName"\s*:\s*"([^"]+)"', t)
        return f"Consul agent 免认证可读服务注册表（{', '.join(sorted(set(svcs))[:6])}）"
    return ""


def _rabbit(r, t) -> str:
    if r.status_code == 200 and '"rabbitmq_version"' in t and '"management_version"' in t:
        m = re.search(r'"rabbitmq_version"\s*:\s*"([^"]+)"', t)
        return f"RabbitMQ 管理口免认证（版本 {m.group(1) if m else '未知'}）"
    return ""


def _zabbix(r, t) -> str:
    if r.status_code == 200 and _no_html(t) and '"version"' in t and '"error"' in t:
        return "Zabbix API JSON-RPC 可达"
    return ""


# ─────────── 单点 POC（来自 ARL-Next2 xing/plugins/poc，逐条移植） ───────────
# 这几条不是「组件指纹」而是「具体漏洞可复现」，所以判定时要比基线：
# 只看到一个 200 或一段通用 HTML 不算，必须证明是这台机器特有的那条路径。
# 判定签名统一是 (r, 正文)；需要基线的在 `poc_baseline` 里先取一次对照页，
# 判定函数再从 `_BASELINE`（按 host 缓存）里取，避免同一站重复请求。
_BASELINE: dict[str, Any] = {}          # host → {"roots": list[str], "weak": str}

# 「弱 404」站：任何不存在的路径都回 200 + 首页，属 SPA 兜底。
# 这种站上除非证据是「结构化数据」，光看状态码和 HTML 全是假点。
_SPA_MARK = ('id="app"', "id='app'", 'id="root"', "<div id=\"app\"", "webpackJsonp",
             "/static/js/", "/assets/index-")

# Django 技术 404 页的独有标记（Django 3/4 都带），比单看 "Django" 三个字稳
_DJANGO_MARKS = ("<title>Page not found at", "Using the URLconf defined in", "DEBUG = True",
                 "You're seeing this error because you have <code>DEBUG = True</code>")

# 响应像 JSON 而不是 HTML——Ueditor 这类控制器回包
def _is_json(t: str) -> bool:
    s = t.strip()
    return bool(s) and s[0] in "{[" and "<" not in s[:200]


def _django_debug(r, t) -> str:
    # 关键在于「404 也回技术页」：开启 DEBUG 后任意不存在路径都会泄露 URLconf、中间件与配置项。
    # 只认 Django 独有标记，且要求是技术 404 页；SPA 兜底页里出现 "Django" 三个字不算。
    if r.status_code != 404:
        return ""
    marks = sum(1 for m in _DJANGO_MARKS if m in t)
    if marks < 2:
        return ""
    m = re.search(r"<title>Page not found at\s*(/[^<]*)</title>", t)
    return (f"Django DEBUG=True：任意不存在的路径都返回技术 404 页"
            f"（{m.group(1) if m else '自定义路径'}），泄露 URLconf 与配置项")


def _gitlab_user_leak(r, t) -> str:
    # /api/v4/users/1 是 GitLab 公开端点，只要站点开了公开可见就能匿名枚举。
    # 必须回一个带 username 的 JSON 对象；回 message（401/404）不算。
    if r.status_code != 200:
        return ""
    try:
        data = r.json()
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    u = data.get("username")
    if not u or not isinstance(u, str):
        return ""
    return (f"GitLab 用户信息匿名可读：id={data.get('id')} username={u} "
            f"name={data.get('name') or '-'}，可按 id 递增枚举全员用户名与公开邮箱")


def _ueditor_paths() -> tuple[str, ...]:
    # controller 所在的上下文目录：Ueditor 常被塞在静态目录下，带不带前缀都要试
    return ("/ueditor/php/controller.php", "/Public/ueditor/php/controller.php",
            "/js/ueditor/php/controller.php", "/statics/ueditor/php/controller.php",
            "/module/ueditor/php/controller.php", "/static/ueditor/php/controller.php")


def _ueditor_ssrf(r, t) -> str:
    # 只有「catchimage 收到连不上的地址」这一种回包才说明 controller 可达且真的走了抓取逻辑。
    # 命中返回里的 URL 是 127.0.0.1:1，外部探针拿不到这个字符串，除非服务端真去拉了。
    if "<" in t[:200]:
        return ""
    for k in ("\\u94fe\\u63a5\\u4e0d\\u53ef\\u7528", "链接不可用"):
        if k in t:
            return "Ueditor catchimage 会去拉取任意 URL（SSRF），服务端抓取逻辑已确认可达"
    return ""


def _ueditor_upload(r, t) -> str:
    # 上传接口对不存在的 action 会回「无效的Action」；拿到这个错误只说明 controller 在，
    # 真正要判的是传 xml/svg 后回包 SUCCESS 且 url 里出现落盘后的文件名。
    if "<" in t[:200]:
        return ""
    if '"state"' in t or "'state'" in t:
        if "SUCCESS" in t.upper() and re.search(r"\.(xml|svg|html|htm)\b", t, re.I):
            m = re.search(r'"url"\s*:\s*"([^"]+)"', t)
            return (f"Ueditor 未限制上传类型：xml/svg 上传成功"
                    f"（{m.group(1) if m else '返回 url 含 .xml/.svg'}），可落存储型 XSS")
        return ""
    for k in ("\\u65e0\\u6548\\u7684Action", "无效的Action", "upload method not exists",
              "请求地址出错", "\\u8bf7\\u6c42\\u5730\\u5740\\u51fa\\u9519"):
        if k in t:
            return "Ueditor 上传控制器可达（action 未生效），可尝试 xml/svg 上传落存储 XSS"
    return ""


def _webinf_leak(r, t) -> str:
    # 正常站点对这三条畸形路径都回 404；回 200 且是 XML 描述符才算绕过读到了 web.xml。
    # 还要求里面有 servlet/servlet-mapping 才认——否则就是 SPA 兜底页伪装成 200。
    if r.status_code != 200:
        return ""
    if "</web-app>" not in t and "</web-app " not in t:
        return ""
    names = t.count("<servlet-name") + t.count("<servlet-mapping")
    if not names:
        return ""
    return f"WEB-INF/web.xml 路径绕过可读（{names} 处 servlet 声明），泄露内部类名与路由映射"


async def poc_baseline(c: httpx.AsyncClient, base: str) -> dict:
    """取两次对照：根首页 + 一条必然不存在的路径。

    用途：
    - 根首页判断是不是 SPA（这类站 404 全回 200，只看状态码全是假点）；
    - 随机不存在路径判断「弱 404」，命中页如果和它一模一样就是兜底页。

    只打两条请求，代价可忽略；失败不抛错，判定函数自行降级。
    """
    import os
    host = host_of(base) or base
    memo = _BASELINE.get(host)
    if memo is not None:
        return memo
    memo = {"roots": [], "weak": ""}
    r = await _get(c, base + "/")
    if r is not None:
        memo["roots"].append((r.text or "")[:200_000])
    probe = f"/arlx-not-exist-{os.urandom(4).hex()}.txt"
    r2 = await _get(c, base + probe)
    if r2 is not None:
        memo["weak"] = (r2.text or "")[:200_000]
    _BASELINE[host] = memo
    return memo


def _is_spa(base: str) -> bool:
    memo = _BASELINE.get(host_of(base) or base) or {}
    for txt in memo.get("roots") or []:
        if any(k in txt for k in _SPA_MARK):
            return True
    return False


def _weak_404(base: str, t: str) -> bool:
    """命中页和「随机不存在路径」的回包一致 → 是兜底页，不是真文件。"""
    weak = ((_BASELINE.get(host_of(base) or base) or {}).get("weak") or "").strip()
    if not weak:
        return False
    return t.strip()[:4000] == weak[:4000]


# (键, 组件名, 严重度, 说明, paths, 判定)
HTTP_PROBES: tuple[dict[str, Any], ...] = (
    {"key": "actuator_env", "app": "Spring Boot Actuator", "sev": "high",
     "paths": ("/actuator/env", "/env", "/api/actuator/env", "/manage/env"),
     "hint": "配置项全部可读（数据库口令、密钥常在）", "check": _actuator_env},
    {"key": "actuator_index", "app": "Spring Boot Actuator", "sev": "medium",
     "paths": ("/actuator", "/api/actuator", "/actuator.json"), "hint": "端点清单可读",
     "check": _actuator_index},
    {"key": "actuator_heapdump", "app": "Spring Boot Actuator", "sev": "critical",
     "paths": ("/actuator/heapdump", "/heapdump", "/api/actuator/heapdump"), "hint": "堆转储可下载",
     "check": _actuator_heapdump},
    {"key": "actuator_httptrace", "app": "Spring Boot Actuator", "sev": "high",
     "paths": ("/actuator/httptrace", "/api/actuator/httptrace", "/actuator;/httptrace",
               "/actuator/httptrace;.css"),
     "hint": "历史请求含令牌", "check": _actuator_httptrace},
    {"key": "druid", "app": "Alibaba Druid", "sev": "high",
     "paths": ("/druid/webapp.json", "/druid/index.html", "/api/druid/webapp.json"), "hint": "SQL 监控",
     "check": _druid},
    {"key": "nacos", "app": "Nacos", "sev": "critical",
     "paths": ("/nacos/v1/auth/users?pageNo=1&pageSize=10", "/v1/auth/users?pageNo=1&pageSize=10"),
     "hint": "用户与配置可读", "check": _nacos},
    {"key": "swagger", "app": "OpenAPI / Swagger", "sev": "medium",
     "paths": ("/v3/api-docs", "/swagger-resources", "/api/v3/api-docs", "/v2/api-docs",
               "/api/v2/api-docs", "/doc.html"), "hint": "接口清单",
     "check": _swagger},
    {"key": "docker", "app": "Docker Remote API", "sev": "critical",
     "paths": ("/version", "/info", "/v1.41/version"), "hint": "宿主机控制",
     "check": _docker},
    {"key": "es", "app": "Elasticsearch", "sev": "high",
     "paths": ("/_cat/indices?format=json", "/", "/_cluster/health"), "hint": "数据可读",
     "check": _es},
    {"key": "es_indices", "app": "Elasticsearch", "sev": "high",
     "paths": ("/_cat/indices?v", "/_cat/indices?format=json"), "hint": "索引清单",
     "check": _es_indices},
    {"key": "etcd", "app": "etcd", "sev": "critical",
     "paths": ("/version", "/v3/kv/range", "/v2/keys"), "hint": "集群键值",
     "check": _etcd},
    {"key": "etcd_data", "app": "etcd", "sev": "critical",
     "paths": ("/v2/keys", "/v3/kv/range"), "hint": "键值数据", "check": _etcd_data},
    {"key": "kibana", "app": "Kibana", "sev": "medium",
     "paths": ("/app/kibana", "/app/monitoring", "/api/status"), "hint": "日志检索",
     "check": _kibana},
    {"key": "solr", "app": "Apache Solr", "sev": "high",
     "paths": ("/solr/admin/cores?wt=json&indexInfo=false", "/admin/cores?wt=json&indexInfo=false"),
     "hint": "核心管理与数据", "check": _solr},
    {"key": "hadoop", "app": "Hadoop YARN", "sev": "critical",
     "paths": ("/ws/v1/cluster/info", "/cluster/apps", "/ws/v1/cluster/apps"), "hint": "作业提交",
     "check": _hadoop},
    {"key": "apollo", "app": "apollo-adminservice", "sev": "high",
     "paths": ("/apps", "/apollo/apps", "/apps/all"), "hint": "配置中心", "check": _apollo},
    {"key": "kubelet", "app": "Kubelet", "sev": "critical",
     "paths": ("/pods", "/api/v1/nodes", "/runningpods/"), "hint": "Pod 与容器",
     "check": _kubelet},
    {"key": "k8s_api", "app": "Kubernetes apiserver", "sev": "critical",
     "paths": ("/version", "/api", "/apis"), "hint": "集群 API", "check": _k8s_api},
    {"key": "onlyoffice", "app": "OnlyOffice", "sev": "medium",
     "paths": ("/ConvertService.ashx", "/web-apps/apps/api/documents/api.js"), "hint": "文档转码 SSRF",
     "check": _onlyoffice},
    {"key": "milvus_users", "app": "Milvus", "sev": "high",
     "paths": ("/api/v1/credential/users", "/v2/vectordb/users/list"), "hint": "向量库账号",
     "check": _milvus_users},
    {"key": "milvus_collections", "app": "Milvus", "sev": "high",
     "paths": ("/api/v1/collections", "/v2/vectordb/collections/list"), "hint": "向量集合",
     "check": _milvus_collections},
    {"key": "consul", "app": "Consul", "sev": "high",
     "paths": ("/v1/catalog/services", "/v1/agent/services", "/ui/"), "hint": "服务注册表",
     "check": _consul},
    {"key": "rabbitmq", "app": "RabbitMQ Management", "sev": "high",
     "paths": ("/api/overview", "/api/queues"), "hint": "消息队列管理", "check": _rabbit},
    # ── 具体 POC（xing/plugins/poc 移植） ──
    {"key": "django_debug", "app": "Django", "sev": "medium",
     "paths": ("/lljfafd", "/api/lljfafd"), "hint": "调试错误页泄露配置与源码片段",
     "check": _django_debug, "baseline": True},
    {"key": "gitlab_user_leak", "app": "GitLab", "sev": "medium",
     "paths": ("/api/v4/users/1",), "hint": "用户名与公开邮箱可匿名枚举",
     "check": _gitlab_user_leak},
    {"key": "ueditor_ssrf", "app": "Ueditor", "sev": "high",
     "paths": tuple(f"{p}?action=catchimage&source%5b%5d=http://127.0.0.1:1/x.png"
                    for p in _ueditor_paths()),
     "hint": "内网可达", "check": _ueditor_ssrf},
    {"key": "ueditor_upload", "app": "Ueditor", "sev": "medium",
     "paths": tuple(f"{p}?action=uploadfile" for p in _ueditor_paths())
              + ("/ueditor/jsp/controller.jsp?action=uploadfile",),
     "hint": "可传 xml/svg 落存储 XSS", "check": _ueditor_upload,
     "multipart": {"upfile": ("1.xml", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
                              "application/vnd.ms-excel")}},
    {"key": "webinf_leak", "app": "Java Web", "sev": "medium",
     "paths": ("/%2e/WEB-INF/web.xml", "/WEB-INF/web.xml.", "/static?/%2557EB-INF/web.xml"),
     "hint": "泄露类名与路由映射", "check": _webinf_leak, "baseline": True},
)

# 80/443 这类普通站点端口上，只有这些组件在常规 Web 站里有意义；
# 其余（docker / es / etcd / hadoop…）跑在专门端口，挂在 443 上的概率极低。
WEB_FALLBACK = frozenset({
    "actuator_env", "actuator_index", "actuator_heapdump", "actuator_httptrace",
    "druid", "nacos", "swagger",
})

# 只在特定端口上打，避免每台机器对这些路径全喷一遍
PORT_SCOPED = {
    "2375": ("docker",), "2376": ("docker",), "2379": ("etcd", "etcd_data"),
    "9200": ("es", "es_indices"), "9300": ("es",), "5601": ("kibana",),
    "8983": ("solr",), "8848": ("nacos",), "8088": ("hadoop",), "8080": ("hadoop", "apollo"),
    "10250": ("kubelet",), "10255": ("kubelet",), "6443": ("k8s_api",), "8500": ("consul",),
    "15672": ("rabbitmq",), "19530": ("milvus_users", "milvus_collections"),
    "9091": ("milvus_users", "milvus_collections"),
}


# 组件路径天然在根下，只有极少数会挂在二级目录（jeecg 的 /manage、spring 的 /actuator 兜底等）。
# 每个前缀再乘一遍会把请求数放大 6 倍，探测从分钟级涨到小时级。
# 注意只按「已经在路径里写明目录」的才算根下；"/admin/cores" 这类本身就带 /admin，
# 不能再叠 /manage 之类的前缀。
_ROOT_ONLY = ("/ws/", "/cluster", "/ConvertService", "/web-apps", "/runningpods", "/v1.41",
              "/kv/range", "/wt=json")

_PREFIX_MEMO: dict[str, tuple[str, ...]] = {}

# 已经含目录层级、或探测本身就要拼前缀的路径，原样打一次就够
_NESTED_PREFIX = ("/api/", "/manage/", "/actuator/", "/druid/", "/nacos/", "/v1/", "/v2/", "/v3/",
                  "/_cat/", "/v2/api-docs", "/v3/api-docs", "/swagger-resources")


def _prefixes_for(path: str) -> tuple[str, ...]:
    """该路径要不要再叠 /api、/manage 这类前缀。

    默认叠（组件常被反代到二级目录）；路径里已经写明目录的，原样打一次即可，
    否则请求数按前缀数成倍膨胀，探测从分钟级涨到小时级。
    """
    memo = _PREFIX_MEMO.get(path)
    if memo is not None:
        return memo
    nested = path.startswith(_ROOT_ONLY) or path.count("/") >= 3 or path.startswith(_NESTED_PREFIX)
    out: tuple[str, ...] = ("",) if nested else PREFIXES
    _PREFIX_MEMO[path] = out
    return out


# 单点 POC 与端口无关：不管站点开在哪个端口都该跑（成本低、命中即高危）。
# 单独拎出来是为了让它们在默认探测里也执行，不受 WEB_FALLBACK / PORT_SCOPED 的裁剪影响。
POC_KEYS = frozenset({"django_debug", "gitlab_user_leak", "ueditor_ssrf", "ueditor_upload",
                      "webinf_leak"})


async def http_probes(base_url: str, *, port: int | None = None, deep: bool = False,
                      timeout: float = 4.0, concurrency: int = 12,
                      only: list[str] | None = None) -> list[dict]:
    """对一个站点根地址跑组件探针。

    deep=True 时全部组件都探；only 给定时只探这些键（用于已经识别出指纹的站点）；
    否则只探与端口相关的组件，端口没登记过组件时按「常见 Web 站」子集处理——
    80/443 上也只跑与 HTTP 站点有关的几组，避免每站几百个请求。
    """
    base = base_url.rstrip("/")
    scoped = PORT_SCOPED.get(str(port or ""), ()) + tuple(POC_KEYS)
    if only:
        wanted = set(only) | POC_KEYS     # 认出了组件，也照样补一遍 POC
        todo = [p for p in HTTP_PROBES if p["key"] in wanted]
    elif deep:
        todo = list(HTTP_PROBES)
    elif scoped:
        todo = [p for p in HTTP_PROBES if p["key"] in scoped]
    else:
        todo = [p for p in HTTP_PROBES
                if p["key"] in WEB_FALLBACK or p["key"] in POC_KEYS]
    if not todo:
        return []
    hits: list[dict] = []
    sem = asyncio.Semaphore(concurrency)

    async def one(c: httpx.AsyncClient, spec: dict, url: str, body: dict | None) -> bool:
        async with sem:
            r = await _get(c, url, "POST" if (body or spec.get("multipart")) else "GET",
                           json_body=body, files=spec.get("multipart"))
        if r is None:
            return False
        text = r.text if len(r.content) < 400_000 else ""
        ev = spec["check"](r, text)
        if not ev:
            return False
        hits.append({"key": spec["key"], "app": spec["app"], "severity": spec["sev"],
                     "url": url, "evidence": ev, "hint": spec["hint"]})
        return True

    async with _client(timeout=timeout) as c:
        # 先取基线：SPA 站和弱 404 站，光看 200/片段会整片误报
        try:
            await poc_baseline(c, base)
        except Exception:
            pass
        spa = _is_spa(base)
        for spec in todo:
            # SPA 兜底页会让所有路径都回 200：这类站只留「结构化数据」类 POC，
            # 否则 webinf / ueditor 这些 HTML 判定全是假点。
            if spa and spec["key"] in ("webinf_leak", "ueditor_upload"):
                continue
            jobs = []
            for path in spec["paths"]:
                for pre in _prefixes_for(path):
                    url = f"{base}{pre}{path}"
                    jobs.append(asyncio.create_task(
                        one(c, spec, url, {"key": "Lw=="} if "kv/range" in url else None)))
            try:
                for fut in asyncio.as_completed(jobs):
                    if await fut:
                        break
            finally:
                for j in jobs:
                    if not j.done():
                        j.cancel()
    return hits


# ─────────────── TCP 指纹 ───────────────
async def _tcp(host: str, port: int, payload: bytes, timeout: float = 4.0) -> bytes:
    def work() -> bytes:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            try:
                if payload:
                    s.sendall(payload)
                return s.recv(512)
            finally:
                s.close()
        except Exception:
            return b""

    return await run_blocking(work, timeout=timeout + 2)


async def _p_redis(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"help\r\n")
    if d.startswith(b"-NOAUTH") or d.startswith(b"-ERR unknown command"):
        auth = "已开认证" if d.startswith(b"-NOAUTH") else "未认证（免密码读写）"
        return {"app": "Redis", "detail": f"PING 握手成功，{auth}", "noauth": d.startswith(b"-ERR")}
    return None


async def _p_memcached(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"stats\r\n")
    if d.startswith(b"STAT ") or d.startswith(b"ERROR"):
        return {"app": "Memcached", "detail": "stats 命令直接可用（免认证，缓存可读可写）", "noauth": True}
    return None


async def _p_zookeeper(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"ruok")
    if d.strip() == b"imok":
        env = await _tcp(host, port, b"envi")
        extra = "，envi 亦可用（可读系统环境）" if env.startswith(b"Environment") else ""
        return {"app": "ZooKeeper", "detail": f"四字命令 ruok 返回 imok{extra}", "noauth": True}
    return None


async def _p_mongo(host: str, port: int) -> dict | None:
    ack = bytes.fromhex("3f0000001400000000000000d40700000400000061646d696e2e24636d640000000000ffffffff"
                        "18000000106c697374446174616261736573000100000000")
    d = await _tcp(host, port, ack)
    if len(d) >= 16:
        import struct
        _, _, rid, opcode = struct.unpack("<iiii", d[:16])
        if rid == 20 and opcode == 1:
            return {"app": "MongoDB", "detail": "listDatabases 免认证返回数据库列表", "noauth": True}
        return {"app": "MongoDB", "detail": "端口可握手（可能需认证）", "noauth": False}
    return None


async def _p_jdwp(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"JDWP-Handshake")
    if d.startswith(b"JDWP-Handshake"):
        return {"app": "JDWP", "detail": "调试端口免认证握手成功（可接管 JVM）", "noauth": True}
    return None


async def _p_dubbo(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"kjaz\r\n")
    if b"dubbo>" in d:
        return {"app": "Dubbo", "detail": "telnet 控制台免认证可执行命令", "noauth": True}
    return None


async def _p_ajp(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"\x12\x34\x00\x01\x0A")
    if d[:3] == b"AB\x00":
        return {"app": "AJP13", "detail": "AJP 连接器开放（Ghostcat 类风险面）", "noauth": True}
    return None


async def _p_ssh(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"")
    if d.startswith(b"SSH-"):
        banner = d.split(b"\r\n")[0].decode("utf-8", "ignore")
        return {"app": "SSH", "detail": banner[:80], "noauth": False}
    return None


async def _p_ftp(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"")
    if d.startswith(b"220"):
        return {"app": "FTP", "detail": d.split(b"\r\n")[0].decode("utf-8", "ignore")[:80], "noauth": False}
    return None


async def _p_redis_banner(host: str, port: int) -> dict | None:
    return await _p_redis(host, port)


async def _p_rdp(host: str, port: int) -> dict | None:
    """RDP 连接请求（X.224 + RDP Negotiation Request），看服务端是否回 TPKT。"""
    pkt = bytes.fromhex(
        "0300002b26e00000000000" "00" "0100080003000000" "02 00 08 00 00 00 00 00".replace(" ", "")
    )
    d = await _tcp(host, port, pkt)
    if d[:2] == b"\x03\x00":
        return {"app": "RDP", "detail": "远程桌面端口（暴露面，弱口令/BlueKeep 类风险）", "noauth": False}
    return None


async def _p_rsync(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"")
    if d.startswith(b"@RSYNCD:"):
        ver = d.split(b"\n")[0].decode("utf-8", "ignore").strip()
        return {"app": "Rsync", "detail": f"守护进程标识 {ver}（常可匿名列目录）", "noauth": True}
    return None


async def _p_rmi(host: str, port: int) -> dict | None:
    """Java RMI / JMX：发 4a524d49（JRMI）握手。"""
    d = await _tcp(host, port, b"JRMI\x00\x02\x4b")
    if d.startswith(b"JRMI"):
        return {"app": "Java RMI", "detail": "RMI 注册表开放（反序列化面）", "noauth": True}
    return None


async def _p_t3(host: str, port: int) -> dict | None:
    """WebLogic T3 协议头；回 ERROR 即说明 T3 已开（反序列化面）。"""
    d = await _tcp(host, port, b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")
    if b"HELO" in d[:16] or b"ERROR" in d[:16]:
        return {"app": "WebLogic T3", "detail": "T3 协议已开（IIOP/T3 反序列化面）", "noauth": False}
    return None


async def _p_smb(host: str, port: int) -> dict | None:
    """SMB2 NEGOTIATE 探测；只看是否回 NetBIOS 会话头。"""
    d = await _tcp(host, port, b"")
    if d.startswith(b"\x85\x00") or d.startswith(b"\x82\x00"):
        # SMB1 保持连接（0x85）；老设备常见
        return {"app": "SMB", "detail": "SMB 服务可用（共享枚举 / EternalBlue 类风险）", "noauth": False}
    if d.startswith(b"\x00"):
        return {"app": "SMB", "detail": "SMB 端口可连（共享枚举风险面）", "noauth": False}
    return None


async def _p_nfs(host: str, port: int) -> dict | None:
    """NFS 端口映射器（rpcbind）会主动回，用于确认 111 上的 NFS 导出。"""
    d = await _tcp(host, port, b"")
    if len(d) >= 4 and d[0] in (0x80, 0x00):
        return {"app": "rpcbind", "detail": "RPC 端口映射器可连（NFS 导出枚举面）", "noauth": True}
    return None


async def _p_postgres(host: str, port: int) -> dict | None:
    """PostgreSQL SSLRequest：'S'=接受 TLS，'N'=明文，均为服务在线。"""
    d = await _tcp(host, port, bytes.fromhex("0000000804d2162f"))
    if d[:1] in (b"S", b"N"):
        return {"app": "PostgreSQL", "detail": "SSLRequest 握手成功", "noauth": False}
    return None


async def _p_smtp(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"")
    if d.startswith(b"220"):
        line = d.split(b"\r\n")[0].decode("utf-8", "ignore")[:80]
        return {"app": "SMTP", "detail": line, "noauth": False}
    return None


async def _p_pop3(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"")
    if d.startswith(b"+OK"):
        return {"app": "POP3", "detail": d.split(b"\r\n")[0].decode("utf-8", "ignore")[:80], "noauth": False}
    return None


async def _p_imap(host: str, port: int) -> dict | None:
    d = await _tcp(host, port, b"")
    if d.startswith(b"* OK") or d.startswith(b"* PREAUTH"):
        return {"app": "IMAP", "detail": d.split(b"\r\n")[0].decode("utf-8", "ignore")[:80],
                "noauth": d.startswith(b"* PREAUTH")}
    return None


async def _p_cobaltstrike(host: str, port: int) -> dict | None:
    """CobaltStrike Team Server：发空包看是否回 0x0000beef 格式的 4 字节长度头。"""
    d = await _tcp(host, port, b"")
    if len(d) >= 4:
        import struct
        n = struct.unpack(">I", d[:4])[0]
        if 0 < n < 0x100000:
            return {"app": "CobaltStrike", "detail": "疑似 Team Server（长度前缀握手）", "noauth": False}
    return None


async def _p_oracle(host: str, port: int) -> dict | None:
    """Oracle TNS：CONNECT 包会回 ACCEPT / REFUSE / REDIRECT，三种都带类型字节。"""
    body = (b"(DESCRIPTION=(CONNECT_DATA=(COMMAND=CONNECT)(VERSION=314))))"
            b"(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=0))")
    # TNS 头 8 字节：length(2) packet_checksum(2) type(1) reserved(1) header_checksum(2)
    head = (8 + len(body)).to_bytes(2, "big") + b"\x00\x00" + b"\x01" + b"\x00" + b"\x00\x00"
    d = await _tcp(host, port, head + body)
    if len(d) >= 8 and d[4] in (2, 4, 11, 12, 14):
        # type 2=ACCEPT 4=REFUSE 11/12=REDIRECT 14=RESEND
        ver = ""
        m = re.search(rb"\(VERSION=([0-9. ]{1,12})\)", d)
        if m:
            ver = " / 版本 " + m.group(1).decode("ascii", "ignore").strip()
        kind = {2: "ACCEPT", 4: "REFUSE", 11: "REDIRECT", 12: "REDIRECT", 14: "RESEND"}[d[4]]
        return {"app": "Oracle TNS", "detail": f"TNS {kind}{ver}", "noauth": False}
    return None


async def _p_socks(host: str, port: int) -> dict | None:
    """Socks5 → Socks4 依次握手；免认证的 Socks 是内网跳板。"""
    d = await _tcp(host, port, b"\x05\x01\x00")
    if len(d) >= 2 and d[0] == 5 and d[1] in (0, 2, 0xFF):
        meth = {0: "免认证", 2: "需账号密码", 0xFF: "无可用方式"}[d[1]]
        return {"app": "SOCKS5", "detail": f"握手成功（{meth}）", "noauth": d[1] == 0}
    d = await _tcp(host, port, b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
    if len(d) >= 2 and d[0] == 0 and d[1] in (90, 91, 92, 93):
        return {"app": "SOCKS4", "detail": "握手成功（无需认证）", "noauth": True}
    return None


async def _p_zmtp(host: str, port: int) -> dict | None:
    """ZeroMQ 的 ZMTP：发 64 字节 greeting，回包第 10 字节是 0x7F 即 ZMTP/3.x。"""
    grease = b"\x00" * 64
    pkt = bytes([0xFF, 0, 0, 0]) + b"\x7f" + bytes([3, 1]) + b"NULL" + grease[10:]
    d = await _tcp(host, port, pkt)
    if len(d) >= 11 and d[9] == 0x7F:
        ver = f"{d[10]}.{d[11]}" if len(d) > 11 else "3"
        return {"app": "ZeroMQ (ZMTP)", "detail": f"ZMTP 握手成功 / 版本 {ver}", "noauth": True}
    return None


async def _p_ldap(host: str, port: int) -> dict | None:
    """LDAP（389/636）：发匿名 bindRequest，回 bindResponse 且 resultCode=0 即允许匿名绑定。"""
    # messageID=1 / version 3 / bindRequest / DN="" / simple 认证 ""
    pkt = bytes.fromhex("300c020101600702010304008000")
    d = await _tcp(host, port, pkt)
    if len(d) >= 2 and d[0] == 0x30:
        if b"\x61" in d[:12]:
            return {"app": "LDAP", "detail": f"匿名 bind 有响应（{len(d)} 字节）", "noauth": True}
        return {"app": "LDAP", "detail": "LDAP 服务在线（bind 需认证）", "noauth": False}
    return None


async def _p_proxy_https(host: str, port: int) -> dict | None:
    """HTTPS 代理（如 Squid 的 443/3128 加密口）：发 CONNECT，回 200 即通。"""
    req = b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"
    d = await _tcp(host, port, req, timeout=5.0)
    if d.startswith(b"HTTP/1.") and b" 200" in d[:16]:
        return {"app": "HTTPS 代理", "detail": "CONNECT 返回 200（可作跳板）", "noauth": True}
    if d.startswith(b"HTTP/1.") and (b" 407" in d[:16] or b" 401" in d[:16]):
        return {"app": "HTTPS 代理", "detail": "CONNECT 需认证", "noauth": False}
    return None


async def _p_hrpc(host: str, port: int) -> dict | None:
    """Hadoop RPC（HRPC）：发 ipc.version + 服务类 + 用户，回 "hrpc" 即在线。"""
    hrpc = b"hrpc" + bytes([9, 0]) + b"\x00" + b"org.apache.hadoop.ipc.ProtocolInfo"
    d = await _tcp(host, port, hrpc)
    if d.startswith(b"hrpc"):
        return {"app": "Hadoop IPC", "detail": "HRPC 握手成功", "noauth": True}
    return None


async def _p_iiop(host: str, port: int) -> dict | None:
    """CORBA IIOP：GIOP 1.2 LocateRequest，带 GIOP/GIOP 回显即在线。"""
    giop = b"GIOP\x01\x02" + b"\x00" + b"\x04" + b"\x00\x00\x00\x00"
    d = await _tcp(host, port, giop)
    if d.startswith(b"GIOP"):
        return {"app": "CORBA IIOP", "detail": f"GIOP 回显 {d[:12]!r}", "noauth": True}
    return None


# (端口集合, 探针函数)
TCP_PROBES: tuple[tuple[frozenset[int], Any], ...] = (
    (frozenset({6379, 6380}), _p_redis),
    (frozenset({11211}), _p_memcached),
    (frozenset({2181, 2182}), _p_zookeeper),
    (frozenset({27017, 27018}), _p_mongo),
    (frozenset({5005, 5000, 8000, 8787}), _p_jdwp),
    (frozenset({20880, 20881}), _p_dubbo),
    (frozenset({8009}), _p_ajp),
    (frozenset({22, 2222}), _p_ssh),
    (frozenset({21}), _p_ftp),
    (frozenset({3389}), _p_rdp),
    (frozenset({873}), _p_rsync),
    (frozenset({1099, 1100, 1098}), _p_rmi),
    (frozenset({7001, 7002}), _p_t3),
    (frozenset({445, 139}), _p_smb),
    (frozenset({111}), _p_nfs),
    (frozenset({5432}), _p_postgres),
    (frozenset({25, 465, 587}), _p_smtp),
    (frozenset({110}), _p_pop3),
    (frozenset({143, 993}), _p_imap),
    (frozenset({50050}), _p_cobaltstrike),
    (frozenset({1521, 1522, 1526}), _p_oracle),
    (frozenset({1080, 1081, 10808}), _p_socks),
    (frozenset({5672, 5555}), _p_zmtp),
    (frozenset({8020, 9000, 2809, 3700}), _p_iiop),
    (frozenset({8020, 9000, 8022, 8021}), _p_hrpc),
    (frozenset({389, 636, 3268}), _p_ldap),
    (frozenset({3128, 8081, 8888}), _p_proxy_https),
)


def _probes_for(port: int) -> list:
    return [fn for ports, fn in TCP_PROBES if port in ports]


async def _port_open(host: str, port: int, timeout: float = 4.0) -> bool:
    """裸 TCP 连接，只判断端口开不开。"""

    def work() -> bool:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    try:
        return await run_blocking(work, timeout=timeout + 2)
    except Exception:
        return False


async def tcp_probe(host: str, port: int) -> list[dict]:
    """对一个 TCP 端口按协议握手认服务；握手没命中但端口开着也报一条。

    以前只跑有握手探针的端口，5399/80/443/8080 这类没有专用探针的端口即使开着也返回空，
    看着像没开。现在握手全空时补一次裸连接，报「端口开放，未识别协议」。
    """
    out: list[dict] = []
    for fn in _probes_for(port):
        try:
            r = await asyncio.wait_for(fn(host, port), timeout=8)
        except Exception:
            r = None
        if r:
            out.append({**r, "port": port, "target": f"{host}:{port}", "open": True})
    if out:
        return out
    if await _port_open(host, port):
        out.append({"app": "", "detail": "端口开放，未识别协议", "noauth": False,
                    "port": port, "target": f"{host}:{port}", "open": True})
    return out


async def tcp_probes(host: str, ports: list[int], *, concurrency: int = 12) -> list[dict]:
    """批量：只对已知业务端口跑，纯 IP 也可。"""
    if not host or not ports:
        return []
    sem = asyncio.Semaphore(concurrency)
    out: list[dict] = []

    async def one(p: int):
        async with sem:
            out.extend(await tcp_probe(host, p))

    await asyncio.gather(*(one(p) for p in ports))
    return out


def is_probe_target(value: str) -> bool:
    return bool(value) and (is_ip(value) or "://" not in value)
