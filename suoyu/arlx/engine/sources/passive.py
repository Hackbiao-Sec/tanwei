"""被动子域 / 资产收集数据源（替代 ARL 的 13 源 QUERY_PLUGIN，并扩充市面源）。

统一签名：async def src_x(domain: str) -> SourceResult
  * 无 key 的公开源：crt.sh / certspotter / rapiddns / hackertarget / alienvault / urlscan / anubis
  * CT 备用：crt.sh 多镜像 + certspotter + myssl + ctlogs
  * 需 key：FOFA / Hunter / Quake / ZoomEye / Shodan / Censys / VirusTotal / SecurityTrails / Passivetotal / Chaos / ThreatBook / GitHub
  * 搜索引擎：Bing / DuckDuckGo
  * 登记信息：RDAP（whois 替代）/ ICP（实时查询 + 本地推断）
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote

import httpx

from ...config import config, src_base
from ...utils import is_ip, is_public_ip, root_domain
from ..whois_lookup import whois_domain

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


@dataclass
class SourceResult:
    source: str
    subdomains: set = field(default_factory=set)
    records: list = field(default_factory=list)
    error: str = ""

    def add(self, host: str, ip: str = "", **extra) -> None:
        host = (host or "").strip().lower()
        host = host.split("//")[-1].split("/")[0].split(":")[0].strip(".")
        if host.startswith("*."):
            host = host[2:]
        if not host or " " in host:
            return
        self.subdomains.add(host)
        if ip or extra:
            self.records.append({"domain": host, "ip": ip, **extra})


def _proxy() -> str | None:
    if config.get("proxy", "sources_via_proxy") and config.get("proxy", "url"):
        return config.get("proxy", "url")
    return None


# 失败原因只有调用方分得清「该换写法再试」和「再怎么试也一样」：这里只记不发。
LAST_GET_ERROR = ""


async def _get(url: str, params: dict | None = None, headers: dict | None = None,
               timeout: float = 15, auth=None, proxy: "str | None" = None) -> httpx.Response | None:
    """proxy 三态：None=用配置代理；"" （空串）= 强制直连；其它=用这个代理。
    空串这一态专给搜索引擎用：扫描机挂了全局代理时，国内引擎必须走本机出口。"""
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    # httpx 把 proxy="" 当非法 URL 抛异常：直连必须显式传 None，且不能落到配置代理上
    eff = None if proxy == "" else (proxy if proxy is not None else _proxy())
    global LAST_GET_ERROR
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True,
                                     trust_env=False, proxy=eff, headers=h) as c:
            return await c.get(url, params=params, auth=auth)
    except Exception as e:
        LAST_GET_ERROR = f"{type(e).__name__}: {e}"
        return None


async def _post(url: str, data=None, json_body=None, headers: dict | None = None,
                timeout: float = 20) -> httpx.Response | None:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True, trust_env=False,
                                     proxy=_proxy(), headers=h) as c:
            return await c.post(url, data=data, json=json_body)
    except Exception:
        return None


# ─────────────── 免费 CT / 被动 DNS ───────────────
async def src_crtsh(domain: str) -> SourceResult:
    """CT 日志：crt.sh 多镜像并发，先到先用"""
    res = SourceResult("crtsh")
    bases = ("https://crt.sh", "https://crt.sh.cn", "https://certssh.com")

    async def one(base: str) -> set[str]:
        out: set[str] = set()
        r = await _get(f"{base}/", params={"q": f"%.{domain}", "output": "json"}, timeout=40)
        if r is None or r.status_code != 200:
            return out
        try:
            data = r.json()
        except Exception:
            return out
        for item in data if isinstance(data, list) else []:
            for name in str(item.get("name_value") or "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    out.add(name)
            cn = str(item.get("common_name") or "").lower().lstrip("*.")
            if cn.endswith(domain):
                out.add(cn)
        return out

    results = await asyncio.gather(*[one(b) for b in bases], return_exceptions=True)
    for r in results:
        if isinstance(r, set):
            res.subdomains |= r
    return res


async def src_certspotter(domain: str) -> SourceResult:
    res = SourceResult("certspotter")
    key = config.get("sources", "certspotter", "key")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    r = await _get(src_base('certspotter', 'https://api.certspotter.com') + "/v1/issuances",
                   {"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                   headers=headers)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        for item in r.json():
            for n in item.get("dns_names") or []:
                n = str(n).lower().lstrip("*.")
                if n.endswith(domain):
                    res.add(n)
    except Exception as e:
        res.error = str(e)
    return res


async def src_rapiddns(domain: str) -> SourceResult:
    res = SourceResult("rapiddns")
    r = await _get(f"https://rapiddns.io/subdomain/{domain}", {"full": "1"}, timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    for m in re.finditer(r"<td>([a-z0-9_.\-]+\." + re.escape(domain) + r")</td>", r.text, re.I):
        res.add(m.group(1))
    for m in re.finditer(r">([a-z0-9_.\-]+\." + re.escape(domain) + r")</td>\s*<td>(\d+\.\d+\.\d+\.\d+)", r.text, re.I):
        res.add(m.group(1), m.group(2))
    return res


async def src_hackertarget(domain: str) -> SourceResult:
    res = SourceResult("hackertarget")
    r = await _get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
    if r is None or r.status_code != 200:
        return res
    for line in r.text.splitlines():
        if "," in line:
            host, ip = line.split(",", 1)
            if host.lower().endswith(domain):
                res.add(host, ip.strip())
    return res


async def src_alienvault(domain: str) -> SourceResult:
    res = SourceResult("alienvault")
    r = await _get("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns"
                   .format(domain), timeout=25)
    if r is None or r.status_code != 200:
        return res
    try:
        for item in (r.json() or {}).get("passive_dns") or []:
            host = item.get("hostname") or ""
            ip = item.get("address") or ""
            if host.lower().endswith(domain):
                res.add(host, ip)
    except Exception:
        pass
    return res


async def src_anubis(domain: str) -> SourceResult:
    res = SourceResult("anubis")
    r = await _get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=20)
    if r is None or r.status_code != 200:
        return res
    try:
        for host in r.json() or []:
            if str(host).lower().endswith(domain):
                res.add(host)
    except Exception:
        pass
    return res


async def src_urlscan(domain: str) -> SourceResult:
    res = SourceResult("urlscan")
    r = await _get("https://urlscan.io/api/v1/search/", {"q": f"domain:{domain}", "size": 1000},
                   timeout=25)
    if r is None or r.status_code != 200:
        return res
    try:
        for item in (r.json() or {}).get("results") or []:
            for key in ("page", "task"):
                host = ((item.get(key) or {}).get("domain") or "")
                if host.lower().endswith(domain):
                    res.add(host, (item.get("page") or {}).get("ip") or "")
    except Exception:
        pass
    return res


async def src_myssl(domain: str) -> SourceResult:
    """MySSL 证书透明度子域查询（CT 备用源）"""
    res = SourceResult("myssl")
    r = await _get("https://myssl.com/api/v1/discover_sub_domain", {"domain": domain}, timeout=20)
    if r is None or r.status_code != 200:
        return res
    try:
        for host in (r.json() or {}).get("data") or []:
            if isinstance(host, str) and host.lower().endswith(domain):
                res.add(host)
            elif isinstance(host, dict) and str(host.get("domain", "")).lower().endswith(domain):
                res.add(host.get("domain"))
    except Exception:
        pass
    return res


async def src_ctlogs(domain: str) -> SourceResult:
    """Cert Spotter 免费公开 / crt.sh 之外的备用：certstream 历史镜像（crt.sh 的 alt 查询）"""
    res = SourceResult("ctlogs")
    r = await _get("https://crt.sh/", {"q": f"%25.{domain}", "output": "json",
                                       "exclude": "expired"}, timeout=35)
    if r is None or r.status_code != 200:
        return res
    try:
        for item in r.json() or []:
            for name in str(item.get("name_value") or "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    res.add(name)
    except Exception:
        pass
    return res


async def src_riddler(domain: str) -> SourceResult:
    res = SourceResult("riddler")
    r = await _get(f"https://riddler.io/search/exportcsv",
                   {"q": f"pld:{domain}", "range": "i_month"}, timeout=20)
    if r is None or r.status_code != 200:
        return res
    for m in re.finditer(r"([a-z0-9_.\-]+\." + re.escape(domain) + r")", r.text, re.I):
        res.add(m.group(1))
    return res


async def _get_hist(url: str, params: dict | None = None,
                    timeout: float = 40, tries: int = 3) -> httpx.Response | None:
    """归档类接口：直连不通报错或上游 502 时重试，仍不行再用配置的代理补一次。

    这类站点（档案馆、抓取索引）本来就不稳：nginx 过载会直接回 502，国内直连又常被拦。
    单次失败就放弃会把一路来源整个丢掉，所以先重试，最后补一次代理尝试。
    """
    for i in range(max(1, tries)):
        r = await _get(url, params, timeout=timeout, proxy="")
        if r is not None and r.status_code not in (429, 502, 503, 504):
            return r
        await asyncio.sleep(1.5 * (i + 1))
    proxy = config.get("proxy", "url")
    if proxy:
        return await _get(url, params, timeout=timeout + 10, proxy=proxy)
    return None


async def src_wayback(domain: str) -> SourceResult:
    """互联网档案馆 CDX 索引：历史上被抓过的 URL → 主机名。

    抓的是 `url=*.domain` 的原始 URL 列表，不取正文，只提主机名。
    老站下线后子域常在归档里还留着名字，是 CT / 被动 DNS 之外的一路补充。
    """
    res = SourceResult("wayback")
    r = await _get_hist("https://web.archive.org/cdx/search/cdx",
                        {"url": f"*.{domain}", "output": "text", "fl": "original",
                         "collapse": "urlkey", "limit": "8000", "filter": "statuscode:200"},
                        timeout=40)
    if r is None or r.status_code != 200:
        return res
    for line in r.text.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        host = line.split("://", 1)[1].split("/")[0].split(":")[0].strip(".").lower()
        if host.endswith(domain):
            res.add(host)
    return res


_CC_INDEX: dict[str, Any] = {"name": "", "ts": 0.0}


async def _cc_latest_index() -> str:
    """CommonCrawl 最新一次抓取的索引名，一小时缓存一次。"""
    if _CC_INDEX["name"] and time.time() - _CC_INDEX["ts"] < 3600:
        return _CC_INDEX["name"]
    r = await _get_hist("https://index.commoncrawl.org/collinfo.json", timeout=25)
    if r is None or r.status_code != 200:
        return _CC_INDEX["name"]
    try:
        rows = r.json() or []
        # id 形如 CC-MAIN-2025-05，最新在前
        name = str((rows[0] or {}).get("id") or "").strip()
    except Exception:
        return _CC_INDEX["name"]
    if name:
        _CC_INDEX["name"] = name
        _CC_INDEX["ts"] = time.time()
    return name


async def src_commoncrawl(domain: str) -> SourceResult:
    """CommonCrawl 索引：按站点匹配整棵域，取 url 字段里的主机名。

    用 `matchType=domain` 走索引自带的后缀匹配；写成 `*.domain` 会让服务端做全表扫描，
    大域经常直接超时，拿不到结果。
    """
    res = SourceResult("commoncrawl")
    idx = await _cc_latest_index()
    if not idx:
        return res
    r = await _get_hist(f"https://index.commoncrawl.org/{idx}-index",
                        {"url": domain, "matchType": "domain",
                         "output": "json", "limit": "6000"}, timeout=60)
    if r is None or r.status_code != 200:
        return res
    for line in r.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            url = str((json.loads(line) or {}).get("url") or "")
        except Exception:
            continue
        if "://" not in url:
            continue
        host = url.split("://", 1)[1].split("/")[0].split(":")[0].strip(".").lower()
        if host.endswith(domain):
            res.add(host)
    return res


# ─────────────── 需 key 的空间测绘 ───────────────
def fofa_qbase64(query: str) -> str:
    return base64.b64encode(query.encode()).decode()


async def fofa_search(query: str, size: int = 1000, fields: str = "") -> list[dict]:
    """通用 FOFA 查询（任意语法），返回 records 列表"""
    key = config.get("sources", "fofa", "key")
    if not key:
        return []
    base = src_base("fofa", "https://fofa.info")
    fields = fields or "host,ip,port,protocol,title,domain,server,header,banner,favicon_hash,icp,cname"
    size = min(int(size or 1000), 10000)
    out: list[dict] = []
    page = 1
    while len(out) < size:
        r = await _get(f"{base}/api/v1/search/all",
                       {"key": key, "qbase64": fofa_qbase64(query), "fields": fields,
                        "size": min(1000, size - len(out)), "page": page}, timeout=30)
        if r is None or r.status_code != 200:
            break
        try:
            data = r.json()
        except Exception:
            break
        if data.get("error"):
            break
        rows = data.get("results") or []
        if not rows:
            break
        names = fields.split(",")
        for row in rows:
            out.append(dict(zip(names, row)))
        if len(rows) < 1000:
            break
        page += 1
    return out


# ─────────────── FOFA v5 热点榜 / 语法联想（免 key） ───────────────
FOFA_V5 = "https://api.fofa.info"
# v5 新版入口在部分网络下被 TLS 拦，按顺序降级，能通哪个用哪个
FOFA_V5_BASES = ("https://v5api.fofa.info", "https://api.fofa.info")


async def _hot_json() -> tuple[Any, str]:
    """热点榜取数：先走配置代理，代理链上证书校验失败时改直连再试一次。

    榜单接口在部分网络里由中间人证书托管，走代理会报自签证书；直连反而通。
    两条路都不通才报错，并把两个失败原因都带出来。
    """
    last = ""
    for via in (None, ""):
        for base in FOFA_V5_BASES:
            r = await _get(f"{base}/v1/hotsearch", timeout=15, proxy=via)
            if r is None:
                last = f"{base} {LAST_GET_ERROR or '无响应'}"
                continue
            if r.status_code != 200:
                last = f"{base} HTTP {r.status_code}"
                continue
            try:
                return r.json(), ""
            except Exception:
                last = f"{base} 非 JSON"
    return None, last or "热点榜不可达"


async def fofa_hot_search(keyword: str = "", limit: int = 30) -> dict:
    """热点检索榜：返回近期高增长的产品/组件及其现成查询语法。

    无需 key。keyword 非空时按应用名/语法模糊筛。用途是给种子与查询语法起手，
    不产生资产。接口自带的总量字段长期为 0，真正有用的是 30 天增量曲线，
    所以按曲线算 total / recent / peak / growth，排序看近 7 天放量速度。
    """
    got: dict[str, Any] = {"rows": [], "error": ""}
    data, last = await _hot_json()
    if data is None:
        got["error"] = last
        return got
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        got["error"] = str((data or {}).get("message") or "热点榜结构变化")
        return got
    kw = (keyword or "").strip().lower()
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        app = str(row.get("app") or "").strip()
        q = str(row.get("query_string") or "").strip()
        if kw and kw not in app.lower() and kw not in q.lower():
            continue
        trend = [t for t in (row.get("hot_trend") or []) if isinstance(t, dict)]
        vals = [int(t.get("value") or 0) for t in trend]
        total = sum(vals)
        recent = vals[-1] if vals else 0
        peak = max(vals) if vals else 0
        last7 = sum(vals[-7:])
        prev7 = sum(vals[-14:-7]) if len(vals) > 7 else 0
        growth = round(last7 / prev7, 2) if prev7 else 0.0
        out.append({"app": app, "query": q, "total": total, "recent": recent,
                    "peak": peak, "is_hot": bool(row.get("is_hot")),
                    "last7": last7, "growth": growth,
                    "today": str(trend[-1].get("date") or "") if trend else "",
                    "spark": vals[-14:],
                    "why": (f"30 天累计新增 {total}，昨日 {recent}，单日峰值 {peak}"
                            + (f"，近 7 天环比 {growth} 倍" if prev7 else ""))})
    # 正在放量的排前面：先看近 7 天，再看累计；只按历史总量会把冷下去的顶上来
    out.sort(key=lambda x: (x["last7"], x["total"], x["growth"]), reverse=True)
    got["rows"] = out[:max(1, min(int(limit or 30), 200))]
    return got


async def fofa_suggest(field: str, query: str = "", limit: int = 20) -> dict:
    """语法候选：用免 key 的热点榜反推某字段的可选值，替代需要登录的在线联想。

    field 目前只覆盖 app（应用名）/ query（现成语法）/ protocol（从语法里抽出的协议）；
    其它字段给出提示后返回空，不浪费 key 配额去瞎试。
    """
    got: dict[str, Any] = {"rows": [], "error": ""}
    field = (field or "").strip().lower()
    if field not in ("app", "query", "protocol", "product"):
        got["error"] = "该字段不支持免登录联想，直接写语法查询即可"
        return got
    hot = await fofa_hot_search(query, limit=200)
    if hot.get("error"):
        got["error"] = hot["error"]
        return got
    q_low = (query or "").strip().lower()
    bag: list[str] = []
    for row in hot["rows"]:
        if field in ("app", "product"):
            bag.append(row["app"])
        elif field == "query":
            bag.append(row["query"])
        else:
            bag.extend(re.findall(r"\b(rdp|ssh|mysql|redis|ftp|smtp|telnet|http|https|"
                                  r"ldap|mongodb|elastic|memcache|vnc|snmp)\b",
                                  row["query"].lower()))
    seen: list[str] = []
    for x in bag:
        v = str(x or "").strip()
        if not v or v in seen:
            continue
        if q_low and q_low not in v.lower():
            continue
        seen.append(v)
        if len(seen) >= max(1, min(int(limit or 20), 50)):
            break
    got["rows"] = seen
    if not seen:
        got["error"] = "热点榜里没有匹配项"
    return got


def _fofa_hosts(records: list[dict], domain: str, source: str) -> SourceResult:
    res = SourceResult(source)
    for rec in records:
        host_field = str(rec.get("host") or "")
        url = str(rec.get("url") or "")
        dom = str(rec.get("domain") or "")
        if url:
            host = url.split("://")[-1].split("/")[0].split(":")[0]
            if host.lower().endswith(domain):
                res.add(host, rec.get("ip") or "", port=rec.get("port"), title=rec.get("title"))
        if dom and dom.lower().endswith(domain):
            res.add(dom, rec.get("ip") or "", port=rec.get("port"), title=rec.get("title"))
        if host_field and is_ip(host_field.split(":")[0]) and not is_public_ip(host_field.split(":")[0]):
            # `0.0.0.0:0` 是引擎没查到数据时的占位记录
            continue
        if host_field and (is_ip(host_field) or re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", host_field)
                           or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host_field)):
            res.add(host_field, rec.get("ip") or host_field.split(":")[0],
                    port=rec.get("port"), title=rec.get("title"), raw=host_field)
    return res


async def src_fofa_domain(domain: str) -> SourceResult:
    size = config.get("sources", "fofa", "size") or 1000
    if not config.get("sources", "fofa", "key"):
        return SourceResult("fofa", error="未配置 FOFA key")
    recs = await fofa_search(f'domain="{domain}"', size=size)
    res = _fofa_hosts(recs, domain, "fofa")
    if not recs:
        res.error = "无结果"
    return res


async def src_hunter_domain(domain: str) -> SourceResult:
    key = config.get("sources", "hunter", "key")
    res = SourceResult("hunter")
    if not key:
        res.error = "未配置 Hunter key"
        return res
    base = src_base("hunter", "https://hunter.qianxin.com")
    page, size = 1, 100
    while page <= 20:
        q = f'domain.suffix="{domain}"'
        b64 = base64.urlsafe_b64encode(q.encode()).decode()
        r = await _get(f"{base}/openApi/search", {"api-key": key, "search": b64,
                                                  "page": page, "page_size": size}, timeout=25)
        if r is None or r.status_code != 200:
            if r is not None and page == 1:
                res.error = f"HTTP {r.status_code}"
            break
        try:
            data = r.json()
        except Exception:
            break
        arr = ((data.get("data") or {}).get("arr") or [])
        if not arr:
            break
        for item in arr:
            host = item.get("domain") or ""
            if host and str(host).lower().endswith(domain):
                res.add(host, item.get("ip") or "", port=item.get("port"), title=item.get("web_title"))
            elif item.get("ip"):
                res.add(str(item.get("ip")), item.get("ip"), port=item.get("port"),
                        title=item.get("web_title"), raw=f"{item.get('ip')}:{item.get('port')}")
        if len(arr) < size:
            break
        page += 1
    return res


async def src_quake_domain(domain: str) -> SourceResult:
    key = config.get("sources", "quake", "key")
    res = SourceResult("quake")
    if not key:
        res.error = "未配置 Quake key"
        return res
    query = f'domain: "{domain}"'
    r = await _post(src_base('quake', 'https://quake.360.net') + "/api/v3/search/quake_service",
                    json_body={"query": query, "start": 0, "size": 500,
                               "ignore_cache": True},
                    headers={"X-QuakeToken": key, "Content-Type": "application/json"})
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        data = r.json()
    except Exception:
        return res
    for item in ((data.get("data") or []) if isinstance(data, dict) else []):
        host = item.get("domain") or ""
        if host and host.lower().endswith(domain):
            res.add(host, item.get("ip") or "", port=item.get("port"),
                    title=(item.get("service") or {}).get("http", {}).get("title")
                    if isinstance(item.get("service"), dict) else "")
        elif item.get("ip"):
            res.add(item.get("ip"), item.get("ip"), port=item.get("port"),
                    raw=f"{item.get('ip')}:{item.get('port')}")
    return res


async def src_zoomeye_domain(domain: str) -> SourceResult:
    key = config.get("sources", "zoomeye", "key")
    res = SourceResult("zoomeye")
    if not key:
        res.error = "未配置 ZoomEye key"
        return res
    headers = {"API-KEY": key}
    r = await _get(src_base('zoomeye', 'https://api.zoomeye.org') + "/domain/search", {"q": domain, "type": 1, "s": 1000},
                   headers=headers, timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        for item in (r.json() or {}).get("list") or []:
            name = item.get("name") or ""
            if name.lower().endswith(domain):
                res.add(name)
    except Exception:
        pass
    return res


async def src_shodan_domain(domain: str) -> SourceResult:
    key = config.get("sources", "shodan", "key")
    res = SourceResult("shodan")
    if not key:
        res.error = "未配置 Shodan key"
        return res
    r = await _get(src_base('shodan', 'https://api.shodan.io') + "/dns/domain/" + domain, {"key": key}, timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        data = r.json() or {}
        for item in data.get("data") or []:
            sub = item.get("subdomain") or ""
            full = f"{sub}.{domain}" if sub else domain
            res.add(full)
    except Exception:
        pass
    return res


async def src_censys_domain(domain: str) -> SourceResult:
    cid = config.get("sources", "censys", "id")
    secret = config.get("sources", "censys", "secret")
    res = SourceResult("censys")
    if not (cid and secret):
        res.error = "未配置 Censys"
        return res
    r = await _get(f"{src_base('censys', 'https://search.censys.io')}/api/v1/view/websites/{domain}", auth=(cid, secret),
                   timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        for item in ((r.json() or {}).get("result") or {}).get("auto_added") or []:
            res.add(item)
    except Exception:
        pass
    return res


async def src_virustotal(domain: str) -> SourceResult:
    key = config.get("sources", "virustotal", "key")
    res = SourceResult("virustotal")
    if not key:
        res.error = "未配置 VirusTotal key"
        return res
    headers = {"x-apikey": key}
    cursor = ""
    for _ in range(10):
        params = {"limit": 40}
        if cursor:
            params["cursor"] = cursor
        r = await _get(f"{src_base('virustotal', 'https://www.virustotal.com')}/api/v3/domains/{domain}/subdomains",
                       params, headers=headers, timeout=25)
        if r is None or r.status_code != 200:
            if r is not None and r.status_code == 401:
                res.error = "key 无效"
            break
        try:
            data = r.json() or {}
        except Exception:
            break
        for item in data.get("data") or []:
            res.add(item.get("id"))
        cursor = (data.get("meta") or {}).get("cursor") or ""
        if not cursor:
            break
    return res


async def src_securitytrails(domain: str) -> SourceResult:
    key = config.get("sources", "securitytrails", "key")
    res = SourceResult("securitytrails")
    if not key:
        res.error = "未配置 SecurityTrails key"
        return res
    r = await _get(f"{src_base('securitytrails', 'https://api.securitytrails.com')}/v1/domain/{domain}/subdomains",
                   headers={"APIKEY": key}, timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        for sub in (r.json() or {}).get("subdomains") or []:
            res.add(f"{sub}.{domain}")
    except Exception:
        pass
    return res


async def src_passivetotal(domain: str) -> SourceResult:
    user = config.get("sources", "passivetotal", "user")
    key = config.get("sources", "passivetotal", "key")
    res = SourceResult("passivetotal")
    if not (user and key):
        res.error = "未配置 PassiveTotal"
        return res
    r = await _get(src_base('passivetotal', 'https://api.riskiq.net') + "/pt/v2/enrichment/subdomains",
                   {"query": domain}, auth=(user, key), timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        for sub in (r.json() or {}).get("subdomains") or []:
            res.add(f"{sub}.{domain}")
    except Exception:
        pass
    return res


async def src_chaos(domain: str) -> SourceResult:
    key = config.get("sources", "chaos", "key")
    res = SourceResult("chaos")
    if not key:
        res.error = "未配置 Chaos key"
        return res
    r = await _get(f"{src_base('chaos', 'https://api.projectdiscovery.io')}/v1/domain/{domain}/subdomains",
                   headers={"Authorization": key}, timeout=25)
    if r is None or r.status_code != 200:
        if r is not None:
            res.error = f"HTTP {r.status_code}"
        return res
    try:
        data = r.json()
        items = data.get("subdomains") if isinstance(data, dict) else data
        for sub in items or []:
            res.add(f"{sub}.{domain}" if not str(sub).endswith(domain) else sub)
    except Exception:
        pass
    return res


async def src_threatbook(domain: str) -> SourceResult:
    key = config.get("sources", "threatbook", "key")
    res = SourceResult("threatbook")
    if not key:
        return res
    r = await _get(src_base('threatbook', 'https://api.threatbook.cn') + "/v3/domain/sub_domains",
                   {"apikey": key, "resource": domain}, timeout=25)
    if r is None or r.status_code != 200:
        return res
    try:
        data = (r.json() or {}).get("data") or {}
        for sub in data.get(domain) or []:
            res.add(sub)
    except Exception:
        pass
    return res


# ─────────────── 搜索引擎 / 代码托管 ───────────────
async def src_bing(domain: str) -> SourceResult:
    res = SourceResult("bing")
    for q in (f"site:{domain}", f"site:*.{domain}"):
        for first in (0, 51):
            r = await _get("https://www.bing.com/search", {"q": q, "first": first, "count": 50})
            if r is None or r.status_code != 200:
                continue
            for m in re.finditer(r"([a-z0-9][a-z0-9\-_.]+\." + re.escape(domain) + r")\b", r.text, re.I):
                res.add(m.group(1))
            for m in re.finditer(r'<h2><a href="(https?://[^"]+)"', r.text):
                host = m.group(1).split("://")[-1].split("/")[0].split(":")[0]
                if host.endswith(domain):
                    res.add(host)
    return res


async def src_duckduckgo(domain: str) -> SourceResult:
    res = SourceResult("duckduckgo")
    r = await _get("https://html.duckduckgo.com/html/", {"q": f"site:{domain}"}, timeout=20)
    if r is None or r.status_code != 200:
        return res
    for m in re.finditer(r"uddc=([^&\"']+)", r.text):
        host = unquote(m.group(1)).split("://")[-1].split("/")[0].split(":")[0].lower()
        if host.endswith(domain):
            res.add(host)
    return res


async def src_github(domain: str) -> SourceResult:
    token = config.get("sources", "github", "token")
    res = SourceResult("github")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    api = src_base("github", "https://api.github.com")
    for q in (f'"{domain}"', f'"{domain}" password', f'"{domain}" api_key'):
        r = await _get(f"{api}/search/code", {"q": q, "per_page": 100}, headers=headers, timeout=25)
        if r is None or r.status_code != 200:
            continue
        try:
            for item in (r.json() or {}).get("items") or []:
                res.records.append({"repo": (item.get("repository") or {}).get("full_name"),
                                    "path": item.get("path"), "html_url": item.get("html_url")})
        except Exception:
            continue
    return res


# ─────────────── 注册信息 ───────────────
async def src_rdap(domain: str) -> SourceResult:
    """域名登记信息：先打注册局 WHOIS，拿不到再退回 RDAP。

    先前只打 `rdap.org`，国内网络对它直接 Reset（实测 WinError 10054），
    所以这条源一直静默回 0 条，导出表「Whois」列也就永远空着。
    """
    res = SourceResult("rdap")
    info = await whois_domain(domain)
    if info and (info.get("registrar") or info.get("created")):
        res.records.append({
            "domain": domain, "root": root_domain(domain), "whois_server": info.get("server"),
            "registrar": [info["registrar"]] if info.get("registrar") else [],
            "events": {k: info[v] for k, v in
                       (("registration", "created"), ("expiration", "expires"),
                        ("updated", "updated")) if info.get(v)},
            "raw": info.get("raw"),
        })
        return res
    r = await _get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"},
                   timeout=20)
    if r is None or r.status_code != 200:
        return res
    try:
        data = r.json()
    except Exception:
        return res
    info = {"domain": domain, "root": root_domain(domain), "rdap": data}
    names = []
    for ent in data.get("entities") or []:
        for v in (ent.get("vcardArray") or [[], []])[1] if ent.get("vcardArray") else []:
            if v and v[0] == "fn" and len(v) > 3:
                names.append(str(v[3]))
    info["registrar"] = names
    info["events"] = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
    res.records.append(info)
    return res


async def src_icp(domain: str) -> SourceResult:
    """ICP 备案查询（免费公开接口，失败不阻塞）"""
    res = SourceResult("icp")
    r = await _get("https://api.vvhan.com/api/icp", {"domain": domain}, timeout=15)
    if r is not None and r.status_code == 200:
        try:
            data = r.json() or {}
            if data.get("success") and data.get("info"):
                res.records.append({"domain": domain, "icp": data["info"]})
                return res
        except Exception:
            pass
    r = await _get("https://icp.aizhan.com/" + domain + "/", timeout=15)
    if r is not None and r.status_code == 200:
        m = re.search(r"(京ICP备|沪ICP备|粤ICP备|浙ICP备|苏ICP备|川ICP备|闽ICP备|鲁ICP备|鄂ICP备|湘ICP备|豫ICP备|冀ICP备|皖ICP备|赣ICP备|辽ICP备|吉ICP备|黑ICP备|桂ICP备|琼ICP备|渝ICP备|津ICP备|新ICP备|藏ICP备|蒙ICP备|宁ICP备|青ICP备|甘ICP备|云ICP备|贵ICP备|晋ICP备|陕ICP备)[0-9\-A-Za-z]+", r.text)
        if m:
            res.records.append({"domain": domain, "icp": m.group(0)})
    return res


# ─────────────── 工信部备案反查（网站 / App / 小程序 / 快应用） ───────────────
MIIT_HOME = "https://beian.miit.gov.cn/"
MIIT_AUTH = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
MIIT_API = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
MIIT_CHECK_IMAGE = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint"
MIIT_CHECK_SUBMIT = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage"
# 请求头只放「浏览器有、但不是客户端提示」的那几项。边缘防护拿 sec-ch-ua / sec-fetch-*
# 这类客户端提示头做指纹：带上就整条路径 403 并回一张 JS 挑战页，剔掉就直接进业务层。
# 实测同一 POST、同一 TLS、同一 IP，只差这组头的结果是 403 与 200，所以这里一个都不带。
MIIT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Origin": "https://hlwicpfwc.miit.gov.cn",
    "Referer": "https://hlwicpfwc.miit.gov.cn/icpproject_query/",
}
# 服务端只认整数：1=网站 6=APP 7=小程序 8=快应用。传字符串或别的数字一律 401「非法请求」。
# 这一组取值是从前端「搜索类型」单选项的 label 直接读出来的，改错会让整条查询静默失败。
MIIT_KINDS = {"site": 1, "app": 6, "mapp": 7, "kapp": 8}
# 前端「备案类型」多选用的中文名。这四类之外的服务端取值实测全部返回「非法请求」，
# 所以不假装支持更多类型，免得选了之后静默空结果。
MIIT_KIND_LABEL = {"site": "网站", "app": "APP", "mapp": "小程序", "kapp": "快应用"}

# token 有效期 5 分钟，期间复用；每条查询自己过一遍滑块拿一次性 sign，所以这里不缓存 sign。
_miit: dict[str, Any] = {"token": "", "exp": 0.0}


# ─────── 备案结果缓存 ───────
# 这张表是「谁查过什么、结果是什么」。命中缓存就不打网络，所以同一家企业第二次
# 反查一定是同一份数据，不会出现「这一轮有、下一轮变无」的抖动；
# 被频控 / 被拦的那一次**不写缓存**，否则一次失误会把这家企业永久记成「无备案」。
_MIIT_CACHE_TTL = 7 * 86400.0
_MIIT_MISS_TTL = 6 * 3600.0
_miit_mem: dict[tuple[str, int], tuple[float, list[dict], int]] = {}


def _miit_cache_get(keyword: str, kind: str) -> tuple[list[dict], int] | None:
    sp = MIIT_KINDS.get(kind, 1)
    mem = _miit_mem.get((keyword, sp))
    if mem and mem[0] > time.time():
        return mem[1], mem[2]
    try:
        from arlx import db  # 延迟导入：采集层允许在没有库的环境下单独跑
        row = db.store.conn().execute(
            "SELECT rows_json, total, ts FROM miit_cache WHERE keyword=? AND kind=?",
            (keyword, sp)).fetchone()
    except Exception:
        row = None
    if not row:
        return None
    # sqlite3.Row 只支持按列名的下标取值，没有 dict.get，缺列会直接抛 KeyError。
    def _col(name: str):
        try:
            return row[name]
        except (KeyError, IndexError):
            return None

    age = time.time() - float(_col("ts") or 0)
    rows = json.loads(_col("rows_json") or "[]")
    ttl = _MIIT_CACHE_TTL if rows else _MIIT_MISS_TTL
    if age > ttl:
        return None
    total = int(_col("total") or len(rows))
    _miit_mem[(keyword, sp)] = (time.time() + max(60.0, ttl - age), rows, total)
    return rows, total


def _miit_cache_put(keyword: str, kind: str, rows: list[dict], total: int) -> None:
    sp = MIIT_KINDS.get(kind, 1)
    ttl = _MIIT_CACHE_TTL if rows else _MIIT_MISS_TTL
    _miit_mem[(keyword, sp)] = (time.time() + ttl, rows, total)
    try:
        from arlx import db
        db.store.conn().execute(
            "INSERT INTO miit_cache(keyword, kind, rows_json, total, ts) VALUES(?,?,?,?,?) "
            "ON CONFLICT(keyword, kind) DO UPDATE SET rows_json=excluded.rows_json, "
            "total=excluded.total, ts=excluded.ts",
            (keyword, sp, json.dumps(rows, ensure_ascii=False), total, time.time()))
        db.store.conn().commit()
    except Exception:
        pass


async def aizhan_unit_lookup(name: str) -> list[str]:
    """公开备案反查页：单位名 → 备案库里的完整主体名。

    只取页面上出现的主体名，不取域名。反查页常年数据走异步接口，拿不到就回空，
    由调用方拼候选兜底，不能因为这一步失败就判定「没有备案」。
    """
    out: list[str] = []
    r = await _get(f"https://icp.aizhan.com/{quote(str(name or '').strip())}/", timeout=6)
    if r is None or r.status_code != 200:
        return out
    text = r.text or ""
    # 这个站常回 200 + 空正文（正文由异步脚本拼接），空就立刻返回，别在正则上白跑。
    if len(text) < 400:
        return out
    for m in re.finditer(r'<a[^>]+href="/[^"]*"[^>]*>\s*([^<]{4,60}?(?:公司|集团|中心|大学|学院|医院|研究院|事务所))\s*<',
                         text):
        unit = m.group(1).strip()
        if unit and unit not in out:
            out.append(unit)
    return out


def _miit_blocked(text: str) -> str:
    """识别拦截 / 限流 / 滑块未过的回包，返回原因，否则空串。

    三类要分开：边缘 WAF 的 JS 挑战（能算）、滑块人机校验（图能算）、频控（等一会恢复）。
    混成一句会把「被挡住导致查不到」误读成「这家企业没有备案」。
    """
    low = (text or "").lower()
    if "请完成安全验证" in text or "向右拖动滑块" in text or "拼图" in text:
        return "MIIT 滑块校验未过"
    if "创宇盾" in text or "error_403_type" in low or "captcha" in low:
        return "MIIT 边缘风控拦截"
    if ("验证码" in text and ("不匹配" in text or "错误" in text or "非法" in text)) or "非法请求" in text:
        return "MIIT 滑块校验未过"
    if ("访问频繁" in text or "访问过快" in text or "频次过高" in text
            or "too many" in low or "请稍后再试" in text):
        return "MIIT 频控，稍后重试"
    if "非法" in text and "请求" in text:
        return "MIIT 请求未通过校验"
    if "没有通过身份验证" in text or "token过期" in text:
        return "MIIT 令牌失效"
    return ""


# 滑块失败是单次事件，不是整轮状态：一次没过就锁死整轮，会让「换个主体再查」也拿不到，
# 看着像这家企业没备案。改成连续失败计数，攒够阈值才熔断，冷却结束自动恢复。
# 阈值 / 冷却 / 重试次数都能在配置 sources.miit 里改（见 _miit_cfg）。
_miit_bad: dict[str, Any] = {"fails": 0, "at": 0.0, "reason": "", "last": 0.0}


def _miit_cfg(name: str, default: float) -> float:
    try:
        val = config.get("sources", "miit", name, default=default)
        return float(val)
    except Exception:
        return float(default)


def _miit_api() -> str:
    """备案查询接口地址。

    内置地址换来换去是常态（换网关、加校验、走反代），把它做成可配置项，
    接口一变就填到 `sources.miit.api` 里，不用等发版。
    """
    try:
        val = str(config.get("sources", "miit", "api", default="") or "").strip()
    except Exception:
        val = ""
    return val or MIIT_API


def _miit_circuit(reason: str = "", seconds: float = 0.0, force: bool = False) -> str:
    """读 / 写熔断状态。

    - 不传 reason：只读，返回当前仍未解除的冷却原因。
    - 传 reason：记一次失败；连续失败攒到 fail_limit 次（或 force）才真正熔断。
    - force 配合 reason=""：清空计数与冷却，给前端「重试一次」用。
    """
    now = time.time()
    if reason:
        _miit_bad["fails"] = int(_miit_bad.get("fails") or 0) + 1
        _miit_bad["last"] = now
        limit = max(1, int(_miit_cfg("fail_limit", 3)))
        if force or _miit_bad["fails"] >= limit:
            cool = float(seconds or _miit_cfg("cool_seconds", 180))
            _miit_bad["at"] = now + max(10.0, cool)
            _miit_bad["reason"] = reason
    elif force:
        _miit_bad.update({"fails": 0, "at": 0.0, "reason": ""})
    if _miit_bad["at"] > now:
        return str(_miit_bad["reason"] or "")
    return ""


def _miit_reset() -> None:
    """查询成功：把连续失败清掉，避免偶发一次滑块失败攒到最后变成熔断。"""
    _miit_bad["fails"] = 0


def _miit_state() -> dict:
    """给前端 / 日志看的熔断实况。"""
    now = time.time()
    return {"fails": int(_miit_bad.get("fails") or 0),
            "cool_left": max(0, int(_miit_bad["at"] - now)),
            "reason": str(_miit_bad.get("reason") or "") if _miit_bad["at"] > now else "",
            "fail_limit": int(_miit_cfg("fail_limit", 3))}


def _miit_hard(reason: str) -> bool:
    """这个原因要不要立刻熔断。

    频控按 IP 计，继续打只会把冷却拉长，立即熔断（冷却短）；滑块 / 边缘校验先重试，
    连续多次都过不去才由 _miit_circuit 的计数阈值兜住。
    """
    return "频控" in (reason or "")


MIIT_POINT_RE = re.compile(r"(point-[0-9a-fA-F-]{8,})")
_MIIT_POINT: dict[str, Any] = {"value": "", "ts": 0.0}


def _miit_point(html_text: str) -> str:
    """滑块接口要 clientUid，形如 point-<uuid>；优先用页面上已有的，没有就自己造并记住。"""
    m = MIIT_POINT_RE.search(html_text or "")
    if m:
        _MIIT_POINT["value"] = m.group(1)
        _MIIT_POINT["ts"] = time.time()
        return m.group(1)
    if _MIIT_POINT["value"] and time.time() - _MIIT_POINT["ts"] < 3600:
        return _MIIT_POINT["value"]
    val = "point-" + str(uuid.uuid4())
    _MIIT_POINT.update(value=val, ts=time.time())
    return val


async def _miit_token(cli: httpx.AsyncClient, force: bool = False) -> tuple[str, str]:
    """返回 (token, 错误)。authKey=md5("test"+"test"+毫秒)，回包 params.bussiness 就是 token。

    token 有效期 5 分钟，期间可以复用；同一 token 下每次查询各过一遍滑块即可。
    """
    circ = _miit_circuit()
    if circ:
        return "", circ
    now = time.time()
    if not force and _miit["token"] and (_miit["exp"] - now) > 60:
        return _miit["token"], ""
    jar: dict[str, str] = {}
    headers = dict(MIIT_HEADERS)
    ts = int(time.time() * 1000)
    auth_key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
    try:
        r = await cli.post(MIIT_AUTH, data={"authKey": auth_key, "timeStamp": ts},
                           headers=headers, cookies=jar)
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"[:120]
    why = _miit_blocked(r.text)
    if why:
        # 边缘挑战会把 API 也一起挡住（回 521 + 一段 document.cookie 脚本）。
        # 官网首页的挑战解不掉不代表 API 这条路断了：把 jar 丢掉，下一轮换新 uid 重取。
        if "document.cookie" in (r.text or "") and not _miit_hard(why):
            _miit.update(cookie={})
        if _miit_hard(why):
            _miit_circuit(why)
        return "", why
    try:
        params = (r.json() or {})["params"]
        tok = str(params["bussiness"])
        _miit.update(token=tok, exp=time.time() + float(params.get("expire") or 0) / 1000)
        return tok, ""
    except Exception:
        snippet = (r.text or "").strip().replace("\n", " ")[:80]
        return "", f"auth 非 JSON HTTP {r.status_code} {snippet}"


async def miit_slider(cli: httpx.AsyncClient, token: str) -> tuple[str, str, str]:
    """过滑块校验，返回 (sign, uuid, 错误)。

    服务端下发底图 + 滑块小图，客户端算出缺口横坐标 x，连同下发的 uuid 一起提交，
    换回一次性 sign；查业务接口时 uuid 和 sign 必须同时放在请求头里。
    """
    from ..collectors.slider import SliderError, solve_x

    headers = dict(MIIT_HEADERS)
    headers["token"] = token
    uid = _miit_point("")
    try:
        r = await cli.post(MIIT_CHECK_IMAGE, json={"clientUid": uid}, headers=headers)
    except Exception as e:
        return "", "", f"滑块图请求失败 {type(e).__name__}"
    try:
        data = (r.json() or {}).get("params") or {}
    except Exception:
        return "", "", f"滑块图非 JSON HTTP {r.status_code}"
    big = data.get("bigImage") or data.get("bgImage") or ""
    small = data.get("smallImage") or ""
    uuid = str(data.get("uuid") or data.get("key") or "")
    if not (big and small and uuid):
        return "", "", "滑块图回包缺字段"

    try:
        x = solve_x(str(big), str(small))
    except SliderError as e:
        return "", "", f"滑块识别失败 {e}"
    except Exception as e:
        return "", "", f"滑块识别异常 {type(e).__name__}"

    try:
        r = await cli.post(MIIT_CHECK_SUBMIT, json={"key": uuid, "value": str(x)},
                           headers=headers)
        got = r.json() or {}
    except Exception as e:
        return "", "", f"滑块提交失败 {type(e).__name__}"
    if not got.get("success") and str(got.get("code")) not in ("200", "0"):
        return "", "", f"滑块未通过 code={got.get('code')} {str(got.get('msg') or '')[:40]}"
    # params 直接就是 sign 本体（JWT 串），不是对象；校验通过后 uuid 也会换成回包里新的那个。
    raw = got.get("params")
    sign = raw.get("sign") if isinstance(raw, dict) else raw
    if not sign:
        sign = got.get("sign") or (got.get("data") or {}).get("sign") or ""
    if not sign:
        return "", "", "滑块回包无 sign"
    if isinstance(raw, dict) and raw.get("uuid"):
        uuid = str(raw["uuid"])
    return str(sign), uuid, ""


# 相邻两条查询之间至少隔这么久。实测连发到第 5 条会被回 429「访问频次过高」，
# 间隔 3 秒也踩到过，留到 6 秒才不会把频控当成「这家企业没有备案」。
MIIT_GAP = 6.0
_miit["last"] = 0.0


async def _miit_gap(interval: float | None = None) -> None:
    """把上一条查询到现在的间隔补齐，避免连续翻页触发频控。

    间隔带随机抖动：固定节拍本身也是能被识别的特征。
    传了 interval 就用它（单项执行里可调），没传读配置。
    """
    if interval is not None and interval >= 0:
        lo = hi = float(interval)
    else:
        lo = float(config.get("throttle", "per_source", "miit", "min_interval",
                              default=MIIT_GAP) or MIIT_GAP)
        hi = float(config.get("throttle", "per_source", "miit", "max_interval",
                              default=MIIT_GAP * 1.5) or MIIT_GAP * 1.5)
    gap = random.uniform(min(lo, hi), max(lo, hi))
    wait = gap - (time.time() - float(_miit.get("last") or 0))
    if wait > 0:
        await asyncio.sleep(wait)
    _miit["last"] = time.time()


async def miit_query(keyword: str, kind: str = "site", page: int = 1, size: int = 40,
                     retry: int | None = None, gap: float | None = None,
                     force: bool = False, api: str = "") -> dict:
    """查一类备案。返回 {"rows": [...], "total": int, "error": str}。

    查询体是 {pageNum, pageSize, unitName, serviceType}，uuid/sign 走请求头；
    `unitName` 在服务端是**精确匹配**：传全称「深圳市腾讯计算机系统有限公司」有 1703 条，
    传简称「腾讯」是 0 条。所以这里每次都要用完整主体名，简称查不到不代表没备案。
    sign 是一次性的：复用上一次的 sign 会立刻 401「非法请求」，所以每条查询都重新过滑块。

    size 必须显式发：不传 pageSize 服务端只回 10 条，翻页判断会因此提前退出。
    retry 是本次查询的换令牌 / 重过滑块次数，滑块没过一次不再锁死整轮。
    """
    sp = MIIT_KINDS.get(kind, 1)
    size = max(1, min(int(size or 40), 40))
    body = {"pageNum": str(max(1, int(page or 1))), "pageSize": str(size),
            "unitName": keyword, "serviceType": sp}
    # 缓存放在熔断判断之前：熔断是为了不打网络，而缓存里的结果本来就不用打网络。
    # 顺序反了会让「频控期间再跑一次」变成全空，看着像这家企业突然没有备案了。
    if page == 1 and not force:
        cached = _miit_cache_get(keyword, kind)
        if cached is not None:
            return {"rows": cached[0], "total": cached[1], "error": "", "cached": True}
    circ = _miit_circuit()
    if circ and not force:
        return {"rows": [], "total": 0, "error": circ}
    if force:
        _miit_circuit("", force=True)
        _miit["token"] = ""
    tries = max(1, int(retry if retry is not None else _miit_cfg("retry_times", 4)))
    r = None
    text = ""
    try:
        async with httpx.AsyncClient(timeout=float(_miit_cfg("timeout", 20)),
                                     verify=False, trust_env=False,
                                     follow_redirects=True) as cli:
            for attempt in range(1, tries + 1):
                await _miit_gap(gap)
                tok, err = await _miit_token(cli, force=attempt > 1)
                if err:
                    if attempt >= tries or _miit_hard(err):
                        _miit_circuit(err)
                        return {"rows": [], "total": 0, "error": err}
                    await asyncio.sleep(1.5)
                    continue
                sign, uid, err = await miit_slider(cli, tok)
                if err:
                    why = _miit_blocked(err) or f"MIIT 滑块校验未过（{err}）"
                    # 滑块没过只作废令牌，下一轮换 clientUid 重来；不在这里锁整轮。
                    _miit["token"] = ""
                    if attempt >= tries or _miit_hard(why):
                        _miit_circuit(why)
                        return {"rows": [], "total": 0, "error": why}
                    await asyncio.sleep(2.0)
                    continue
                headers = dict(MIIT_HEADERS)
                headers["token"] = tok
                headers["uuid"] = uid
                headers["sign"] = sign
                r = await cli.post(api or _miit_api(), json=body, headers=headers)
                text = r.text or ""
                flat = text.replace(" ", "")
                # 业务层拒绝也要认：HTTP 200 + success:false 里既有频控，也有「非法请求」
                # （sign 用掉 / 令牌过期）。只看 HTTP 状态会把这两种都当成正常空结果，
                # 「没有备案」就是这么被写出来的。
                why = _miit_blocked(text)
                if not why and r.status_code == 429:
                    why = "MIIT 频控，稍后重试"
                if not why and r.status_code == 200 and '"success":false' in flat:
                    _miit["token"] = ""
                    if attempt >= tries:
                        return {"rows": [], "total": 0,
                                "error": "MIIT 校验未过（sign 或令牌失效）"}
                    await asyncio.sleep(1.5)
                    continue
                if not why and r.status_code == 200:
                    break
                _miit["token"] = ""
                if "频控" in why:
                    # 频控按 IP 计，同一轮里再打只会拉长冷却，直接把整轮停掉。
                    _miit_circuit(why, seconds=_miit_cfg("freq_cool_seconds", 120), force=True)
                    return {"rows": [], "total": 0, "error": why}
                if attempt >= tries:
                    _miit_circuit(why)
                    return {"rows": [], "total": 0, "error": why or f"HTTP {r.status_code}"}
                await asyncio.sleep(2.0)
                continue
    except Exception as e:
        return {"rows": [], "total": 0, "error": f"{type(e).__name__}: {e}"[:120]}
    if r is None:
        return {"rows": [], "total": 0, "error": "MIIT 无响应"}
    if r.status_code != 200:
        _miit["token"] = ""
        return {"rows": [], "total": 0, "error": f"HTTP {r.status_code} {text[:80]}"}
    try:
        data = r.json() or {}
    except Exception:
        _miit["token"] = ""
        return {"rows": [], "total": 0, "error": "非 JSON 响应"}
    if data.get("success") is False:
        # 走到这里说明重试循环已经放过它了（频控 / 边缘拦截 / 反复 401），
        # 统一按「被挡」记，绝不能落成空结果。
        msg = str(data.get("msg") or "")[:60]
        why = _miit_blocked(msg) or f"MIIT 业务层拒绝 {data.get('code')} {msg}"
        _miit_circuit(why)
        return {"rows": [], "total": 0, "error": why}
    _miit_reset()
    params = (data.get("params") or {})
    rows = params.get("list") or []
    total = int(params.get("total") or len(rows))
    norm = []
    for it in rows:
        if not isinstance(it, dict):
            continue
        norm.append({
            "unitName": it.get("unitName") or "",
            "serviceName": it.get("serviceName") or "",
            "serviceLicence": it.get("serviceLicence") or it.get("mainLicence") or "",
            "domain": it.get("domain") or "",
            "domains": it.get("domains") or it.get("domainList") or "",
            "mainUnit": it.get("mainUnit") or "",
            "natureName": it.get("natureName") or "",
            "version": it.get("version") or "",
            "updateRecordTime": it.get("updateRecordTime") or "",
            "kind": kind,
        })
    if page == 1:
        _miit_cache_put(keyword, kind, norm, total)
    return {"rows": norm, "total": total, "error": ""}


async def _miit_company_once(keyword: str, kinds, pages: int, size: int,
                             retry: int | None, gap: float | None,
                             force: bool, api: str = "") -> tuple[list[dict], str]:
    """按一个确定的单位名查备案，返回 (行, 失败原因)。别名变体由 miit_company 负责。"""
    out: list[dict] = []
    last_error = ""
    pages = max(1, int(pages or 1))
    for kind in kinds:
        kind = str(kind or "site")
        if kind not in MIIT_KINDS:
            continue
        got_total = 0
        for page in range(1, pages + 1):
            got = await miit_query(keyword, kind, page=page, size=size,
                                   retry=retry, gap=gap,
                                   force=force and page == 1, api=api)
            if got.get("error"):
                # 记下原因再跳出：上层要据此区分「被挡」和「真没备案」，
                # 只看空列表会把两者当同一件事。
                last_error = got["error"]
                break
            rows = got.get("rows") or []
            for row in rows:
                row["kind"] = kind
                out.append(row)
            got_total += len(rows)
            # 服务端会无视 pageSize：网站类固定每页 10 条，APP 类才按 40 条给。
            # 「回包不足一页」只能按实际回来的条数判，拿请求的 size 去比会让
            # 92 条备案在第 1 页就 break，看着像这家企业只有 10 条网站。
            if not rows or got_total >= int(got.get("total") or 0):
                break
    return out, last_error


async def miit_company(keyword: str, kinds=("site",), pages: int = 1,
                       size: int = 40, retry: int | None = None,
                       gap: float | None = None, alias: bool = True,
                       expand_domains: int = 0, force: bool = False,
                       api: str = "") -> list[dict]:
    """按单位名批量查备案，串行 + 可调间隔，避免触发频控。

    `unitName` 是精确匹配，简称会查到 0 条。所以按「原串 → 括号别名 → 工商/反查补出的全称」
    逐个试，第一个出结果的就返回 —— 否则「字节跳动」「厦门市特种设备检验检测院(应急处置中心)」
    这类输入会稳定得到「无备案」。

    kinds 决定查哪几类（site/app/mapp/kapp），pages 决定每类翻几页，
    `expand_domains` 大于 0 时把主体名下其它已备案域名一起捞回来（用于扩面）。
    `api` 留空用内置接口地址（配置 sources.miit.api 也可以覆盖）。
    """
    names: list[str] = []

    def push(n: str) -> None:
        n = (n or "").strip()
        if not n or n in names:
            return
        names.append(n)
        # 登记名里的括号是半角的，工商/官网给的全称常是全角：
        # 「…检验检测院（…应急处置中心）」精确查 0 条，「…检验检测院(…应急处置中心)」才出 3 条。
        # 别名补进来时一并排上全半角互换的写法，否则补进来的这一跳等于没补。
        for v in _miit_name_variants(n):
            if v and v not in names:
                names.append(v)

    push(keyword)
    if alias and not _miit_full_name(keyword):
        for name in await _miit_unit_aliases(keyword):
            push(name)
    last_error = ""
    rows: list[dict] = []
    for idx, name in enumerate(names[:5]):
        try:
            rows, last_error = await _miit_company_once(
                name, kinds, pages, size, retry, gap, force and idx == 0, api=api)
        except Exception as e:
            rows, last_error = [], f"{type(e).__name__}: {e}"[:120]
        if rows:
            return rows
        # 被挡 / 频控 / 校验未过：换名字再打只是多烧一次滑块，这轮到此为止。
        if last_error:
            break
    # 名字本身像是登记全称（以「院 / 局 / 站」这类后缀收尾）时，上面不会去猜全称。
    # 但事业单位的登记证常把第二名称写在括号里，备案库按登记证存：
    # 「厦门市特种设备检验检测院」精确查 0 条，「…检验检测院（厦门市特种设备应急处置中心）」
    # 才有数据。精确名打空、又没被挡，就再解析一次全称补打。
    if (alias and not last_error and not rows
            and _miit_full_name(keyword) and not _miit_name_variants(keyword)):
        tried = 1
        for name in await _miit_unit_aliases(keyword):
            # 同样排上全半角互换的写法：工商给全称、备案库存半角，正好差这一个字符。
            push(name)
            while tried < len(names):
                cand = names[tried]
                tried += 1
                try:
                    rows, last_error = await _miit_company_once(
                        cand, kinds, pages, size, retry, gap, False, api=api)
                except Exception as e:
                    rows, last_error = [], f"{type(e).__name__}: {e}"[:120]
                if rows:
                    return rows
                if last_error:
                    break
            if rows or last_error:
                break
    if last_error:
        global _miit_company_error
        _miit_company_error = last_error
        LAST_GET_ERROR = f"miit: {last_error}"[:160]
    return []


_miit_company_error = ""


def miit_last_error() -> str:
    """最近一次按主体名反查备案失败的原因（被频控 / 被挡 / 校验未过）。空串表示是「确实没有」。"""
    return _miit_company_error


_FORM_WORDS = ("有限公司", "股份公司", "分公司", "集团", "事务所", "工作室", "合作社", "中心",
               "大学", "学院", "医院", "研究院", "研究所", "协会", "基金会",
               # 事业单位 / 机关 / 群团：这些名字本来就是登记全称，不应再被当成简称去拼候选。
               "检验检测院", "设计院", "科学院", "研究院", "学院", "学校", "中学", "小学",
               "院", "局", "厅", "委", "办", "署", "部", "站", "所", "校", "馆", "社",
               "台", "队", "团", "室", "处", "科", "系", "厂", "场", "行", "店", "会",
               "委员会", "管理局", "监督局", "税务局", "公安局", "协会", "商会")


def _miit_full_name(name: str) -> bool:
    """判断是不是完整登记名。带组织形式 / 机关事业单位后缀才可能命中备案库的精确匹配。

    这里只判「要不要再去猜全称」：含「院 / 局 / 委 / 站」这类后缀的名字本身就是登记全称，
    以前漏了它们，事业单位目标会被拼成一堆「北京XX检测院有限公司」的假候选，
    结果一条都查不到，看着像没有备案。
    """
    n = (name or "").strip()
    if not n:
        return False
    if any(w in n for w in _FORM_WORDS):
        return True
    # 「福建省XX」这类带行政区划、名字又够长的，直接当全称试一次，失败会自然回落。
    return any(n.startswith(p) for p in ("中国", "国家", "中华", "全国")) and len(n) >= 8


_BRACKET_RE = re.compile(r"[（(]\s*([^（）()]{2,60})\s*[）)]")
_FULL2HALF = str.maketrans("（）", "()")
_HALF2FULL = str.maketrans("()", "（）")


def _miit_name_variants(name: str) -> list[str]:
    """括号别名变体：`A（B）` → `A`、`B`，外加括号全半角互换。

    事业单位 / 机关的登记名常把第二名称写在括号里，而备案库里未必按带括号的写法存。
    两种拆法各试一次，比只拿原串去撞多一次命中机会；名字本身没有括号就返回空表。
    工商导出习惯用半角括号（`福建龙溪轴承(集团)股份有限公司`），登记证写法是全角，
    备案库按登记证存，所以带括号的名字再补一条全半角互换的写法。
    """
    n = (name or "").strip()
    if not n:
        return []
    out: list[str] = []
    for m in _BRACKET_RE.finditer(n):
        for v in (_BRACKET_RE.sub("", n), m.group(1)):
            v = re.sub(r"\s+", " ", v or "").strip(" ·-—_，,")
            if len(v) >= 4 and v != n and v not in out:
                out.append(v)
    if out:
        for v in (n.translate(_FULL2HALF), n.translate(_HALF2FULL)):
            v = re.sub(r"\s+", " ", v or "").strip()
            if v != n and v not in out:
                out.append(v)
    return out


async def _miit_unit_aliases(name: str) -> list[str]:
    """简称 → 完整登记名候选。

    三条来源，按准确度排：
    1. 工商主体检索的命中名（天眼查 / 公开工商接口）—— 直接就是登记全称；
    2. 备案反查页上出现的主体名 —— 来自备案库本身；
    3. 本地按组织形式拼候选 —— 只在上面两条都空时兜底，且只留极少数。

    备案库对 `unitName` 是精确匹配，拼错一个字就是 0 条。以前一上来就拼
    「北京XX有限公司」这类 8 个假名字逐个去查，每次之间还要等 6 秒节流，
    查不到就把整轮拖到几十秒，还白白耗掉滑块与频控次数。
    """
    seen: list[str] = []
    base = (name or "").strip()
    if not base:
        return seen

    def add(v: str) -> None:
        u = (v or "").strip()
        if u and u != base and u not in seen:
            seen.append(u)

    # 1) 工商主体检索
    try:
        # 以前写的是 `from . import equity`，指到 arlx.engine.sources.equity —— 这个模块
        # 不存在，异常又被下面吞掉，于是「简称 → 登记全称」这一跳从来没真正跑过：
        # 事业单位的括号全称永远解析不出来，备案库按精确匹配就只回一条假空。
        from ..collectors import equity as _equity

        add(await _equity.resolve_name(base))
    except Exception:
        pass
    if seen:
        return seen[:3]

    # 2) 备案反查页（有熔断 / 已命中缓存时不必再等这一跳）
    if _miit_circuit() or _miit_cache_get(base, "site") is not None:
        got = []
    else:
        try:
            got = await aizhan_unit_lookup(base)
        except Exception:
            got = []
    for unit in got:
        u = (unit or "").strip()
        if u and base in u:
            add(u)
    if seen:
        return seen[:5]

    # 3) 本地兜底：只拼最常见的两个写法，失败就明确回报「简称没解析出全称」。
    # 名字本身已经带组织形式 / 机关后缀时不再拼 —— 拿
    # 「厦门市特种设备检验检测院」拼出「北京厦门市特种设备检验检测院有限公司」
    # 这种不存在的名字，只是白烧一次滑块再回一个假空。
    if _miit_full_name(base):
        return []
    for suffix in ("有限公司", "股份有限公司"):
        add(f"{base}{suffix}")
    return seen[:3]


async def miit_domains(keyword: str, kinds=("site",), pages: int = 2,
                       api: str = "") -> list[str]:
    """企业名 → 备案域名列表（只取命中主体名的行）。"""
    seen: dict[str, dict] = {}
    for row in await miit_company(keyword, kinds=kinds, pages=pages, api=api):
        for d in (row.get("domain") or "").split("\n"):
            d = d.strip().lower()
            if not d or "." not in d:
                continue
            seen.setdefault(d, row)
    return list(seen)


async def miit_reverse_domain(domain: str, retry: int | None = None,
                              size: int = 40, api: str = "") -> dict:
    """域名 → 备案主体（完整登记名）。

    这条方向比按企业名反查稳：备案库对域名是模糊匹配，`tencent.com` 一条就能带出
    「深圳市腾讯计算机系统有限公司」，拿到这个全称之后，按企业名翻页才有意义。
    """
    got = await miit_query(domain, "site", size=size, retry=retry, api=api)
    if got.get("error"):
        return {"unit": "", "icp": "", "error": got["error"]}
    hit = ""
    icp = ""
    for row in got["rows"]:
        name = row.get("unitName") or ""
        host = (row.get("domain") or "").strip().lower()
        if not name:
            continue
        # 主体名的拼音/字母缩写与域名后缀能对上时优先，避免同域下别的公司登记的行抢了主体。
        if host == domain or host.endswith("." + domain) or domain.split(".")[0] in name.lower():
            hit, icp = name, row.get("serviceLicence") or ""
            break
        if not hit:
            hit, icp = name, row.get("serviceLicence") or ""
    return {"unit": hit, "icp": icp, "error": "" if hit else "该域名无备案记录"}


async def src_equity(domain: str) -> SourceResult:
    """工商股权维度反查：按累计持股 100% 的全资子公司名逐个补公开备案域名。"""
    res = SourceResult("equity")
    try:
        from ..collectors.enterprise import expand_sub_company
        names = await expand_sub_company(domain)
    except Exception as e:
        res.error = f"{type(e).__name__}: {e}"[:120]
        return res
    if not names:
        # 没有全资子公司是这个维度的正常结论，不该记成失败，否则上层会把这句当报错展示。
        return res
    for sub in names[:30]:
        try:
            rows = await miit_company(sub, kinds=("site",), pages=1)
        except Exception:
            continue
        for row in rows or []:
            d = (row.get("domain") or "").strip().lower()
            if d and "." in d:
                res.add(d, source="equity", unit=row.get("unit") or sub)
    return res


# ─────────────── ip138 域名解析历史（当前解析 + 历史 A 记录） ───────────────
IP138_SITE = "https://site.ip138.com"
_IP138_HDR = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9",
}


def parse_ip138_page(html: str) -> dict:
    """解 ip138 域名页：_TOKEN 给 write.do 用，历史记录区直接出 IP 与生效区间。

    页面的「当前解析」是前端用 read.do 异步填的，静态 HTML 里只有历史记录；
    历史记录形如 `<span class="date">2022-02-23-----2026-10-26</span><a>152.136.248.40</a>`。
    """
    text = html or ""
    tok = re.search(r"_TOKEN\s*=\s*'([0-9a-fA-F]{16,64})'", text)
    out: dict[str, Any] = {
        "token": tok.group(1) if tok else "",
        "forbidden": bool(re.search(r"_IS_FORBIDDEN\s*=\s*true", text)),
        "history": [],
    }
    block = re.search(r'id="J_ip_history"(.*?)</div>', text, re.S)
    scope = block.group(1) if block else ""
    for m in re.finditer(r'<span class="date">\s*([0-9\-]+\s*-+\s*[0-9\-]*)\s*</span>(.*?)</p>',
                         scope, re.S):
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", m.group(2))
        # 区间前的 IP 是这条记录生效的地址，后面的 a 标签可能混入其它 IP 链接，只取首个
        if ips:
            out["history"].append({"range": m.group(1).strip(), "ip": ips[0]})
    if not out["history"]:
        # 结构变了之后的兜底：整段里只要成对的「日期区间 + IP」
        for m in re.finditer(r"([0-9]{4}-[0-9]{2}-[0-9]{2}\s*-+[^\s<]*)\s*"
                             r"(?:<[^>]*>\s*)*((?:\d{1,3}\.){3}\d{1,3})", scope or text):
            out["history"].append({"range": m.group(1).strip(), "ip": m.group(2)})
    return out


async def ip138_current(domain: str) -> dict:
    """read.do 拿当前解析。返回值里的 msg 同时是 write.do 的令牌，顺手续一次写回补齐缓存。"""
    got: dict[str, Any] = {"ips": [], "error": ""}
    hdr = dict(_IP138_HDR)
    hdr["X-Requested-With"] = "XMLHttpRequest"
    hdr["Referer"] = f"{IP138_SITE}/{domain}/"
    for _ in range(3):
        r = await _get(f"{IP138_SITE}/domain/read.do",
                       {"domain": domain, "time": int(time.time() * 1000)}, headers=hdr, timeout=10)
        if r is None or r.status_code != 200:
            got["error"] = f"read.do HTTP {getattr(r, 'status_code', 'ERR')}"
            continue
        try:
            data = r.json() or {}
        except Exception:
            got["error"] = "read.do 非 JSON"
            break
        ips = [str(row.get("ip") or "").strip() for row in (data.get("data") or [])
               if isinstance(row, dict)]
        ips = [ip for ip in ips if is_ip(ip)]
        tok = str(data.get("msg") or "")
        if data.get("status") is False and not ips:
            got["error"] = tok or "read.do 未返回解析"
            break
        got["ips"] = ips
        if tok and re.fullmatch(r"[0-9a-fA-F]{16,64}", tok):
            await _get(f"{IP138_SITE}/domain/write.do",
                       {"type": "domain", "input": domain, "token": tok}, headers=hdr, timeout=8)
        return got
    return got


IP138_IP_RE = re.compile(
    r'<span class="date">\s*(\d{4}-\d{2}-\d{2})?-*(\d{4}-\d{2}-\d{2})?\s*</span>\s*<a[^>]*>([^<]+)</a>')


def parse_ip138_ip_page(html: str) -> dict:
    """解 ip138 的 IP 页：这条 IP 上绑定过的域名 + 归属/机房。

    页面的域名列表在 `<ul id="list">` 里，每条是「生效区间 + 域名链接」；
    列表有截断（约 100 条），拿到多少算多少，不当作全量。
    """
    text = html or ""
    out: dict[str, Any] = {"token": "", "forbidden": False, "ip": "", "location": "",
                           "domains": []}
    tok = re.search(r"_TOKEN\s*=\s*'([0-9a-fA-F]{16,64})'", text)
    out["token"] = tok.group(1) if tok else ""
    out["forbidden"] = bool(re.search(r"_IS_FORBIDDEN\s*=\s*true", text))
    m = re.search(r"_INPUT\s*=\s*'([^']*)'", text)
    out["ip"] = m.group(1).strip() if m else ""
    loc = re.search(r'<div class="result result2">\s*<h3>(.*?)</h3>', text, re.S)
    if loc:
        out["location"] = re.sub(r"<[^>]+>", " ", loc.group(1)).strip()[:80]
    block = re.search(r'<ul id="list">(.*?)</ul>', text, re.S)
    scope = block.group(1) if block else ""
    for start, end, name in IP138_IP_RE.findall(scope):
        host = name.strip().lower()
        if not host:
            continue
        # 页面写 a-----b 表示该域名在这条 IP 上的生效区间；单端缺失只保留另一端
        span = [x for x in (start, end) if x]
        out["domains"].append({"domain": host,
                               "start": span[0] if span else "",
                               "end": span[1] if len(span) > 1 else (span[0] if span else "")})
    return out


async def ip138_reverse(ip: str, limit: int = 200) -> dict:
    """IP 反查：这条 IP 上曾解析过哪些域名。拿去补被动子域，能捞出未被 CT 覆盖的老域名。"""
    got: dict[str, Any] = {"ip": ip, "domains": [], "location": "", "error": ""}
    if not is_ip(ip):
        got["error"] = "不是合法 IP"
        return got
    r = await _get(f"{IP138_SITE}/{ip}/", headers=_IP138_HDR, timeout=15)
    if r is None or r.status_code != 200:
        got["error"] = f"ip138 HTTP {getattr(r, 'status_code', 'ERR')}"
        return got
    parsed = parse_ip138_ip_page(r.text)
    if parsed.get("forbidden"):
        got["error"] = "ip138 拒绝查询该 IP"
    got["location"] = parsed.get("location") or ""
    got["domains"] = (parsed.get("domains") or [])[:max(1, int(limit or 200))]
    if not got["domains"] and not got["error"]:
        got["error"] = "该 IP 无绑定域名记录"
    return got


async def src_ip138_reverse(domain: str) -> SourceResult:
    """ip138 IP 反查：先把域名解析成 IP，再反查这些 IP 上绑定过的其它域名。

    记录放进 records（带 via=ip_reverse 与共用 IP），交给阶段按相似度筛；
    不直接塞 subdomains，避免把共用 CDN / 云主机的无关站当成本目标的子域。
    """
    res = SourceResult("ip138_rev")
    ips: list[str] = []
    try:
        import dns.asyncresolver as _ar

        ans = await _ar.Resolver().resolve(domain, "A")
        ips = [str(a) for a in ans]
    except Exception as e:
        res.error = f"DNS 解析失败：{type(e).__name__}"
        return res
    if not ips:
        res.error = "无 A 记录"
        return res
    seen: set[str] = set()
    for ip in ips[:5]:
        got = await ip138_reverse(ip)
        if got["error"] and not got["domains"]:
            res.error = res.error or got["error"]
            continue
        for row in got["domains"]:
            host = row["domain"]
            if host in seen:
                continue
            seen.add(host)
            res.records.append({"domain": host, "ip": ip, "via": "ip_reverse",
                                "ip138_location": got.get("location") or "",
                                "range": f"{row['start']} ~ {row['end']}".strip(" ~")})
    if not res.records and not res.error:
        res.error = "无反查结果"
    return res


async def src_ip138(domain: str) -> SourceResult:
    """ip138 域名解析历史：当前解析 + 历史生效 IP，反查真实套壳与曾被解析的源站。"""
    res = SourceResult("ip138")
    r = await _get(f"{IP138_SITE}/{domain}/", headers=_IP138_HDR, timeout=12)
    parsed: dict = {}
    if r is not None and r.status_code == 200:
        parsed = parse_ip138_page(r.text)
        if parsed.get("forbidden"):
            res.error = "ip138 拒绝查询该域名"
    cur = await ip138_current(domain)
    if cur.get("error") and not cur.get("ips"):
        res.error = res.error or cur["error"]
    for ip in cur.get("ips") or []:
        res.records.append({"domain": domain, "ip": ip, "kind": "current"})
    for row in parsed.get("history") or []:
        res.records.append({"domain": domain, "ip": row["ip"],
                            "kind": "history", "range": row["range"]})
    if not res.records and not res.error:
        res.error = "ip138 无解析记录"
    # 有 IP 说明域名在用，把域名本身也当一条命中，避免上层把空 subdomains 当失败
    if res.records:
        res.subdomains.add(domain)
    return res


# ─────────────── 0.zone 零零信安（域名 / 站点 / App / 邮箱，需 key） ───────────────
ZERO_ZONE_API = "https://0.zone/api/data/"


async def zero_zone_query(query: str, query_type: str = "site", *, page: int = 1,
                          pagesize: int = 10, key: str = "") -> dict:
    """0.zone 统一检索入口。query_type: site | domain | app | email。

    返回 {"rows": [...], "total": n, "error": ""}；没有 key 时直接给原因，不抛。
    """
    key = key or config.get("sources", "zero_zone", "key") or ""
    if not key:
        return {"rows": [], "total": 0, "error": "0.zone 未配置 key（sources.zero_zone.key）"}
    body = {"query": query, "query_type": query_type, "page": int(page),
            "pagesize": min(int(pagesize), 40), "zone_key_id": key}
    r = await _post(ZERO_ZONE_API, json_body=body, timeout=20,
                    headers={"Accept": "application/json", "Content-Type": "application/json"})
    if r is None:
        return {"rows": [], "total": 0, "error": "0.zone 请求失败"}
    if r.status_code != 200:
        return {"rows": [], "total": 0, "error": f"0.zone HTTP {r.status_code}"}
    try:
        data = r.json() or {}
    except Exception:
        return {"rows": [], "total": 0, "error": "0.zone 非 JSON"}
    if str(data.get("code")) != "1":
        return {"rows": [], "total": 0,
                "error": f"0.zone: {data.get('message') or data.get('code')}"}
    payload = data.get("data") or {}
    rows = payload.get("list") or payload.get("data") or []
    return {"rows": [row for row in rows if isinstance(row, dict)],
            "total": int(payload.get("total") or len(rows)), "error": ""}


async def src_zero_zone(domain: str) -> SourceResult:
    """0.zone 站点检索：按 domain 出站点/子域与指纹 banner。需 sources.zero_zone.key。"""
    res = SourceResult("zero_zone")
    got = await zero_zone_query(domain, "site", pagesize=20)
    if got["error"]:
        res.error = got["error"]
        return res
    for row in got["rows"]:
        host = (row.get("site") or row.get("domain") or row.get("host") or "").strip().lower()
        if not host:
            continue
        res.add(host, ip=str(row.get("ip") or ""), title=str(row.get("title") or "")[:120],
                banner=str(row.get("html_banner") or "")[:200])
    return res


async def src_miit(domain: str) -> SourceResult:
    """按域名反查工信部备案：拿到备案号后把主体名、载体形态记进 records。
    DOMAIN_SOURCES 的 src_* 统一签名是 (domain) -> SourceResult，所以这里只查网站域名那一类；
    企业维度的四类批量反查走 miit_company()（enterprise.icp_by_company 用）。"""
    res = SourceResult("miit")
    got = await miit_query(domain, "site")
    if got.get("error"):
        res.error = got["error"]
        return res
    for row in got["rows"]:
        if row["unitName"]:
            res.records.append({"domain": domain, "icp": row["serviceLicence"],
                                "unit": row["unitName"], "nature": row["natureName"]})
            break
    return res


# ─────────────── 无 key 补充源 ───────────────
def _under(host: str, domain: str) -> bool:
    """host 是不是 domain 本身或它下面的子域（不做根域推断）。"""
    host = (host or "").strip(".").lower()
    domain = (domain or "").strip(".").lower()
    return bool(domain) and (host == domain or host.endswith("." + domain))


async def src_subdomain_center(domain: str) -> SourceResult:
    """社区被动 DNS 聚合：整域子域列表，无 key（排队满时回 503，重试可过）。"""
    res = SourceResult("subdomain_center")
    for i in range(3):
        r = await _get("https://api.subdomain.center/", {"domain": domain},
                       timeout=35, proxy="")
        if r is None:
            res.error = LAST_GET_ERROR or "请求失败"
            break
        if r.status_code == 200:
            try:
                rows = r.json()
            except Exception:
                res.error = "返回不是 JSON"
                break
            for host in rows if isinstance(rows, list) else []:
                res.add(str(host))
            res.error = "" if res.subdomains else "无结果"
            return res
        if r.status_code in (429, 503):
            res.error = f"上游繁忙 HTTP {r.status_code}"
            await asyncio.sleep(2.0 * (i + 1))
            continue
        res.error = f"HTTP {r.status_code}"
        break
    return res


async def src_mnemonic(domain: str) -> SourceResult:
    """社区被动 DNS（Mnemonic）：按域取 A 记录历史，带首末次观测时间。"""
    res = SourceResult("mnemonic")
    r = await _get(f"https://api.mnemonic.no/pdns/v3/{domain}",
                   {"limit": 800, "rrtype": "a"}, timeout=30, proxy="")
    if r is None or r.status_code != 200:
        res.error = f"HTTP {getattr(r, 'status_code', 'ERR')}"
        return res
    try:
        body = r.json()
    except Exception:
        res.error = "返回不是 JSON"
        return res
    for row in body.get("data") or []:
        host = str(row.get("query") or "").strip().lower()
        ip = str(row.get("answer") or "").strip()
        # 被动 DNS 会把反查名和「同 IP 的别家域」一起吐回来，只留本域这一棵
        if not host or host.endswith(".in-addr.arpa") or not _under(host, domain):
            continue
        res.add(host, ip if is_ip(ip) else "",
                first_seen=int(row.get("firstSeenTimestamp") or 0) // 1000,
                last_seen=int(row.get("lastSeenTimestamp") or 0) // 1000)
    if not res.subdomains:
        res.error = "无结果"
    return res


async def src_robtex(domain: str) -> SourceResult:
    """社区被动 DNS（Robtex，NDJSON）：按域取解析历史，补 CT 覆盖不到的老子域。"""
    res = SourceResult("robtex")
    r = await _get(f"https://freeapi.robtex.com/pdns/forward/{domain}",
                   timeout=30, proxy="")
    if r is None or r.status_code != 200:
        res.error = f"HTTP {getattr(r, 'status_code', 'ERR')}"
        return res
    for line in r.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if str(row.get("rrtype") or "").upper() not in ("A", "AAAA"):
            continue
        host = str(row.get("rrname") or "").strip().lower()
        ip = str(row.get("rrdata") or "").strip()
        if host:
            res.add(host, ip if is_ip(ip) else "")
    if not res.subdomains:
        res.error = "无结果"
    return res


async def robtex_reverse(ip: str, limit: int = 60) -> dict:
    """Robtex IP 反查：这条 IP 上解析过的域名，无 key，可顶替被限流的反查站点。"""
    got: dict[str, Any] = {"ip": ip, "domains": [], "error": ""}
    if not is_ip(ip):
        got["error"] = "不是合法 IP"
        return got
    r = await _get(f"https://freeapi.robtex.com/pdns/reverse/{ip}", timeout=25, proxy="")
    if r is None or r.status_code != 200:
        got["error"] = f"HTTP {getattr(r, 'status_code', 'ERR')}"
        return got
    seen: set[str] = set()
    for line in r.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        host = str(row.get("rrname") or "").strip().lower()
        if host and host not in seen:
            seen.add(host)
            got["domains"].append({"domain": host, "ip": ip})
        if len(got["domains"]) >= max(1, int(limit or 60)):
            break
    if not got["domains"] and not got["error"]:
        got["error"] = "该 IP 无反查记录"
    return got


async def src_robtex_rev(domain: str) -> SourceResult:
    """Robtex IP 反查：解析本域 A 记录，再反查同 IP 上的其它域名。

    与 ip138 反查同口径：记录带 via=ip_reverse，交给阶段按相似度筛，
    不直接当子域，避免把共用云主机的无关站算进来。
    """
    res = SourceResult("robtex_rev")
    try:
        import dns.asyncresolver as _ar

        ans = await _ar.Resolver().resolve(domain, "A")
        ips = [str(a) for a in ans]
    except Exception as e:
        res.error = f"DNS 解析失败：{type(e).__name__}"
        return res
    if not ips:
        res.error = "无 A 记录"
        return res
    for ip in ips[:4]:
        got = await robtex_reverse(ip)
        if got["error"] and not got["domains"]:
            res.error = res.error or got["error"]
            continue
        for row in got["domains"]:
            res.records.append({"domain": row["domain"], "ip": ip, "via": "ip_reverse"})
    if not res.records and not res.error:
        res.error = "无反查结果"
    return res


# ─────────────── 统一入口 ───────────────
DOMAIN_SOURCES = {
    "crtsh": src_crtsh,
    "certspotter": src_certspotter,
    "ctlogs": src_ctlogs,
    "myssl": src_myssl,
    "rapiddns": src_rapiddns,
    "hackertarget": src_hackertarget,
    "alienvault": src_alienvault,
    "anubis": src_anubis,
    "urlscan": src_urlscan,
    "riddler": src_riddler,
    "wayback": src_wayback,
    "commoncrawl": src_commoncrawl,
    "fofa": src_fofa_domain,
    "hunter": src_hunter_domain,
    "quake": src_quake_domain,
    "zoomeye": src_zoomeye_domain,
    "shodan": src_shodan_domain,
    "censys": src_censys_domain,
    "virustotal": src_virustotal,
    "securitytrails": src_securitytrails,
    "passivetotal": src_passivetotal,
    "chaos": src_chaos,
    "threatbook": src_threatbook,
    "bing": src_bing,
    "duckduckgo": src_duckduckgo,
    "github": src_github,
    "rdap": src_rdap,
    "icp": src_icp,
    "miit": src_miit,
    "ip138": src_ip138,
    "ip138_rev": src_ip138_reverse,
    "subdomain_center": src_subdomain_center,
    "mnemonic": src_mnemonic,
    "robtex": src_robtex,
    "robtex_rev": src_robtex_rev,
    "zero_zone": src_zero_zone,
    "equity": src_equity,
}

# ARL 原生 13 源（兼容旧配置）
ARL_13 = ["crtsh", "certspotter", "virustotal", "chaos", "securitytrails", "passivetotal",
          "fofa", "hunter", "quake", "zoomeye", "shodan", "censys", "github"]

FREE_SOURCES = ["crtsh", "certspotter", "ctlogs", "myssl", "rapiddns", "hackertarget",
                "alienvault", "anubis", "urlscan", "riddler", "wayback", "commoncrawl",
                "bing", "duckduckgo", "rdap", "icp",
                "miit", "ip138", "subdomain_center", "mnemonic", "robtex", "robtex_rev"]


def gate_sources(names: list[str] | None = None) -> tuple[list[str], list[str]]:
    """按渠道开关把被动源分成「要跑」和「你停用了」两组。

    入口取 `enabled or 全部`，返回的第一组可直接交给 run_domain_sources。
    """
    from .. import channels as channels_mod

    picked = [n for n in (names or list(DOMAIN_SOURCES)) if n in DOMAIN_SOURCES]
    on = [n for n in picked if channels_mod.source_on(n)]
    off = [n for n in picked if n not in on]
    return on, off


async def run_domain_sources(domain: str, enabled: list[str] | None = None,
                             timeout: float = 120,
                             respect_channels: bool = True) -> list[SourceResult]:
    names = [n for n in (enabled or list(DOMAIN_SOURCES)) if n in DOMAIN_SOURCES]
    if respect_channels:
        # 渠道面板里停用的源不发请求；单源直跑（respect_channels=False）不受影响
        from .. import channels as channels_mod

        names = [n for n in names if channels_mod.source_on(n)]
    tasks = {n: asyncio.create_task(DOMAIN_SOURCES[n](domain)) for n in names}
    done, pending = await asyncio.wait(tasks.values(), timeout=timeout)
    for t in pending:
        t.cancel()
    out: list[SourceResult] = []
    for n, t in tasks.items():
        if t in done and not t.cancelled():
            try:
                out.append(t.result())
            except Exception as e:
                out.append(SourceResult(n, error=str(e)[:120]))
        else:
            out.append(SourceResult(n, error="超时"))
    return out


def source_meta() -> list[dict]:
    meta = []
    for name, fn in DOMAIN_SOURCES.items():
        need_key = name in ("fofa", "hunter", "quake", "zoomeye", "shodan", "censys", "virustotal",
                            "securitytrails", "passivetotal", "chaos", "threatbook", "zero_zone")
        # role 给界面分「主源 / 辅助」两栏用：要 key 的商用接口按量打满算主源，
        # 免 key 的公开接口走辅助。哪些是主源由后端说，前端不自己猜。
        meta.append({"name": name, "need_key": need_key,
                     "role": "primary" if need_key else "aux",
                     "short": name,
                     "doc": (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""})
    return meta


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)
