"""ASN / 网段归集：把一个落点 IP 归到持有者的 ASN，再列出该 ASN 宣告的网段。

用途有两个：
  * 资产侧：目标的对外服务常不只挂在一个 /24 里，同 ASN 的其它网段是天然的扩面线索，
    落成 netblock 资产，报告与后续重扫都能用。
  * 旁站侧：ISP/小机房往往一个 ASN 只宣告一两个 /24，这种段扫描成本可控，
    交给上层决定要不要真去扫（本模块只归集，不扫描）。

数据走 RIPEstat 公开接口，不要 key；单机内存缓存 6 小时，同一任务里重复 IP 只查一次。
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import httpx

from ...utils import is_ip

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
_PREFIX_API = "https://stat.ripe.net/data/prefix-overview/data.json"
_ANNOUNCE_API = "https://stat.ripe.net/data/announced-prefixes/data.json"

_TTL = 6 * 3600.0
_cache_asn: dict[str, tuple[float, dict]] = {}
_cache_prefix: dict[str, tuple[float, list[str]]] = {}


async def _get_json(cli: httpx.AsyncClient, url: str, params: dict) -> dict:
    try:
        r = await cli.get(url, params=params)
        if r.status_code != 200:
            return {}
        return r.json() or {}
    except Exception:
        return {}


def _prefix_len(cidr: str) -> int:
    try:
        return int(cidr.rsplit("/", 1)[1])
    except Exception:
        return 32


async def asn_of(ip: str) -> dict:
    """IP → {asn, holder, resource}。查不到给空 dict。"""
    if not is_ip(ip):
        return {}
    hit = _cache_asn.get(ip)
    if hit and time.time() - hit[0] < _TTL:
        return hit[1]
    out: dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=12, verify=False, trust_env=False,
                                 headers={"User-Agent": _UA, "Accept": "application/json"}) as cli:
        data = await _get_json(cli, _PREFIX_API, {"resource": ip})
        rows = ((data.get("data") or {}).get("asns") or [])
        if rows:
            top = rows[0] or {}
            out = {"asn": f"AS{top.get('asn')}" if top.get("asn") else "",
                   "holder": str(top.get("holder") or "")[:120],
                   "resource": str((data.get("data") or {}).get("resource") or "")}
    if out:
        _cache_asn[ip] = (time.time(), out)
    return out


async def prefixes_of(asn: str) -> list[str]:
    """ASN → 宣告的网段列表（IPv4 优先）。"""
    if not asn:
        return []
    hit = _cache_prefix.get(asn)
    if hit and time.time() - hit[0] < _TTL:
        return hit[1]
    out: list[str] = []
    async with httpx.AsyncClient(timeout=15, verify=False, trust_env=False,
                                 headers={"User-Agent": _UA, "Accept": "application/json"}) as cli:
        data = await _get_json(cli, _ANNOUNCE_API, {"resource": asn})
        for item in ((data.get("data") or {}).get("prefixes") or []):
            p = str((item or {}).get("prefix") or "").strip()
            if p and ":" not in p:
                out.append(p)
    # 最具体的段排前面：调用方按条数截取时留下的是最贴身的网段，而不是一个 /8 大块
    out.sort(key=_prefix_len, reverse=True)
    _cache_prefix[asn] = (time.time(), out)
    return out


async def collect(ips: list[str], max_ips: int = 15,
                  max_prefixes: int = 40) -> list[dict]:
    """批量归集：每个 IP 一条 {ip, asn, holder, prefixes}。

    同一 ASN 只查一次网段列表；查不到 ASN 的 IP 也给一条（asn 空），上层据此判断。
    """
    picked = [ip for ip in ips if is_ip(ip)][:max_ips]
    if not picked:
        return []
    asns = await asyncio.gather(*(asn_of(ip) for ip in picked))
    by_asn: dict[str, list[str]] = {}
    for info in asns:
        if info.get("asn"):
            by_asn.setdefault(info["asn"], [])
    for asn in list(by_asn):
        by_asn[asn] = await prefixes_of(asn)
    out: list[dict] = []
    for ip, info in zip(picked, asns):
        asn = info.get("asn") or ""
        out.append({"ip": ip, "asn": asn, "holder": info.get("holder") or "",
                    "resource": info.get("resource") or "",
                    "prefixes": (by_asn.get(asn) or [])[:max_prefixes]})
    return out


def small_blocks(rows: list[dict], min_len: int = 24, limit: int = 6) -> list[str]:
    """从归集结果里挑「扫描成本可控」的网段：前缀长度 ≥ min_len（即 ≤ /24 的规模）。"""
    out: list[str] = []
    for row in rows:
        for cidr in row.get("prefixes") or []:
            if _prefix_len(cidr) >= min_len and cidr not in out:
                out.append(cidr)
    return out[:limit]


def block_base_ips(cidrs: list[str], limit: int = 6) -> list[str]:
    """要扫的网段 → 段内一个可用地址，并按 /24 折叠去重。

    段扫描以 /24 为单位，比 /24 更小的段扫下去会带上邻居地址，所以同一 /24 只算一次。
    """
    out: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        if net.version != 4:
            continue
        base = ".".join(str(net.network_address).split(".")[:3]) + ".1"
        if base in out:
            continue
        out.append(base)
        if len(out) >= limit:
            break
    return out


def reset_cache() -> None:
    _cache_asn.clear()
    _cache_prefix.clear()
