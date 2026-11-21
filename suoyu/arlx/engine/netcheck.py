"""连通性诊断：判断这台机器能不能真的把请求送出去。

采集链路上任何一环断了都表现为「一条资产没有」，而日志里只看到空结果。
这里把每一环单独探一遍，说清是代理的问题、DNS 的问题，还是目标站本身挡了。

三类检测：
  * 本机直连：不走代理直接打纯 204 端点
  * 经代理：按配置里的代理地址打同一个端点
  * DNS：解析几个已知域名，确认本机解析没被劫持 / 没坏
"""

from __future__ import annotations

import asyncio
import socket
import time

import httpx

from ..config import config

# 纯 204 端点：不返回正文，只要网络通就是 2xx，最干净的连通性判据
PROBE_URLS = (
    ("gstatic", "https://www.gstatic.com/generate_204"),
    ("cloudflare", "https://cp.cloudflare.com/generate_204"),
)

DNS_TARGETS = ("qq.com", "baidu.com", "github.com")


async def _one_url(client: httpx.AsyncClient, name: str, url: str, timeout: float) -> dict:
    t0 = time.monotonic()
    try:
        r = await client.get(url)
        cost = int((time.monotonic() - t0) * 1000)
        ok = r.status_code < 400
        return {"name": name, "url": url, "ok": ok, "status": r.status_code,
                "ms": cost, "msg": "" if ok else f"HTTP {r.status_code}"}
    except Exception as exc:
        cost = int((time.monotonic() - t0) * 1000)
        return {"name": name, "url": url, "ok": False, "status": 0,
                "ms": cost, "msg": f"{type(exc).__name__}: {str(exc)[:120]}"}


async def _check_direct(timeout: float) -> list[dict]:
    async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=True) as c:
        return list(await asyncio.gather(*[_one_url(c, n, u, timeout) for n, u in PROBE_URLS]))


async def _check_proxy(proxy: str, timeout: float) -> list[dict]:
    async with httpx.AsyncClient(proxy=proxy, timeout=timeout, trust_env=False,
                                 follow_redirects=True) as c:
        return list(await asyncio.gather(*[_one_url(c, n, u, timeout) for n, u in PROBE_URLS]))


def _check_dns() -> list[dict]:
    out = []
    for host in DNS_TARGETS:
        t0 = time.monotonic()
        try:
            info = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            ips = sorted({item[4][0] for item in info})
            out.append({"host": host, "ok": bool(ips), "ips": ips[:4],
                        "ms": int((time.monotonic() - t0) * 1000), "msg": ""})
        except Exception as exc:
            out.append({"host": host, "ok": False, "ips": [],
                        "ms": int((time.monotonic() - t0) * 1000),
                        "msg": f"{type(exc).__name__}: {str(exc)[:120]}"})
    return out


def _verdict(direct: list[dict], proxied: list[dict] | None, proxy: str) -> tuple[str, str]:
    """把三类结果收成一句话结论，让人一眼知道该去改哪里。"""
    direct_ok = any(d["ok"] for d in direct)
    proxy_ok = any(p["ok"] for p in (proxied or [])) if proxied is not None else None
    if direct_ok and (proxy_ok is None or proxy_ok):
        return "ok", "外网可达，采集链路正常"
    if direct_ok and proxy_ok is False:
        return "proxy_broken", f"直连正常，但代理 {proxy} 不通 —— 走代理的数据源会全部空结果"
    if not direct_ok and proxy_ok:
        return "need_proxy", "直连被挡，代理可用 —— 需要通过代理的源才能出数据"
    return "offline", "直连和代理都不通 —— 检查网络、防火墙或代理端口"


async def diagnose(*, timeout: float = 8.0, with_proxy: bool = True) -> dict:
    """跑一次完整诊断。任一环节异常都不抛，结果里带原因。"""
    proxy = str(config.get("proxy", "url") or "").strip()
    direct = await _check_direct(timeout)
    proxied = None
    if with_proxy and proxy:
        proxied = await _check_proxy(proxy, timeout)
    dns = await asyncio.to_thread(_check_dns)
    code, note = _verdict(direct, proxied, proxy)
    return {
        "ok": code == "ok",
        "verdict": code,
        "note": note,
        "proxy": proxy,
        "direct": direct,
        "via_proxy": proxied,
        "dns": dns,
        "dns_ok": all(d["ok"] for d in dns),
    }
