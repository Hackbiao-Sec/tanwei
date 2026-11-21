"""域名登记信息查询（WHOIS 43 端口 + RDAP 兜底）。

为什么不用现成的 RDAP 聚合站：实测 `rdap.org` 从国内网络直接 Reset，
`rdap.cnnic.cn` 解析失败，唯一稳定的是两个东西——
1. 注册局自己的 43 端口 WHOIS（verisign / cnnic 都能通，秒回）；
2. 权威 RDAP（如 `rdap.verisign.com/com/v1/domain/x`）。

所以这里按「TLD 路由 → 注册局 WHOIS → 需要时跟一跳注册商 → RDAP 兜底」的顺序查，
只解析注册商与三个日期，原始文本留在 raw 里给详情页看。
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

# 常用 TLD 的注册局 whois；不在表里的走 iana 引导（port 43 问 "com" 回 whois 服务器）
_REGISTRY = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "cn": "whois.cnnic.cn",
    "com.cn": "whois.cnnic.cn",
    "net.cn": "whois.cnnic.cn",
    "org.cn": "whois.cnnic.cn",
    "gov.cn": "whois.cnnic.cn",
    "cc": "ccwhois.verisign-grs.com",
    "io": "whois.nic.io",
    "me": "whois.nic.me",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "top": "whois.nic.top",
    "xyz": "whois.nic.xyz",
    "co": "whois.nic.co",
    "ai": "whois.nic.ai",
    "hk": "whois.hkirc.hk",
    "tw": "whois.twnic.net.tw",
    "jp": "whois.jprs.jp",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "im": "whois.nic.im",
}

IANA_WHOIS = "whois.iana.org"

# 各家回包字段名不统一，按「谁是注册商、什么时候注册、什么时候到期」认几个常见写法。
# 注册局的回包每行前面带若干空格（verisign 是三格），所以行首必须允许空白。
_RE_REGISTRAR = re.compile(
    r"^\s*(?:Registrar|Sponsoring Registrar|Registrar Name|注册商)\s*:\s*(.+)$",
    re.I | re.M)
_RE_CREATED = re.compile(
    r"^\s*(?:Creation Date|Created On|Registered on|Registration Time|Domain Registration Date|"
    r"Created|Registration Date|注册时间|Domain Create Date)\s*:\s*(.+)$", re.I | re.M)
_RE_EXPIRES = re.compile(
    r"^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Time|"
    r"Expiry Date|Expiration Date|paid-till|到期时间|Domain Expire Date)\s*:\s*(.+)$",
    re.I | re.M)
_RE_UPDATED = re.compile(
    r"^\s*(?:Updated Date|Last updated on|Last Updated|Last Modified|changed|更新日期|"
    r"Domain Update Date)\s*:\s*(.+)$", re.I | re.M)
_RE_REFERRAL = re.compile(r"^\s*(?:Registrar WHOIS Server|whois|ReferralServer)\s*:\s*(\S+)",
                          re.I | re.M)


def _sock_query(server: str, query: str, timeout: float) -> str:
    """阻塞式 WHOIS 查询：一次连接、写到对端关闭为止。"""
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("utf-8", "ignore"))
        chunks: list[bytes] = []
        total = 0
        while total < 400_000:
            part = sock.recv(8192)
            if not part:
                break
            chunks.append(part)
            total += len(part)
    return b"".join(chunks).decode("utf-8", "ignore")


async def _query(server: str, query: str, timeout: float) -> str:
    """异步包一层：socket 放线程里跑，主线程不堵事件循环。"""
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sock_query, server, query, timeout),
                                      timeout + 2)
    except (OSError, asyncio.TimeoutError):
        return ""


def _tld(domain: str) -> str:
    parts = [p for p in domain.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return ""
    return ".".join(parts[-2:])


def _parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, pat in (("registrar", _RE_REGISTRAR), ("created", _RE_CREATED),
                     ("expires", _RE_EXPIRES), ("updated", _RE_UPDATED)):
        m = pat.search(text or "")
        if m:
            out[key] = m.group(1).strip()[:160]
    return out


async def whois_domain(domain: str, timeout: float = 12.0) -> dict[str, Any]:
    """查一个域名的登记信息，拿不到就是空字典。"""
    domain = (domain or "").strip().lower().lstrip(".").rstrip(".")
    if not domain or "." not in domain:
        return {}
    tld = _tld(domain)
    server = _REGISTRY.get(tld)
    if not server:
        # 不认识的 TLD：问 iana 它的注册局是谁（回包里有一行 whois: xxx）
        head = await _query(IANA_WHOIS, tld.split(".")[-1], min(timeout, 8.0))
        m = re.search(r"^whois\s*:\s*(\S+)", head, re.I | re.M)
        server = m.group(1) if m else ""
    registry_raw = await _query(server, domain, timeout) if server else ""
    if not registry_raw and server:
        # 注册局偶发空回 / "Out of this registry."（同一 IP 连打太快），补一次
        await asyncio.sleep(0.8)
        registry_raw = await _query(server, domain, timeout)
    if server and "Out of this registry" in registry_raw:
        registry_raw = ""
    info = _parse(registry_raw)
    raw = registry_raw

    # 注册局那一跳常只给注册商名字或干脆只给地址；有 Referral 就跟一跳拿注册商侧日期
    hop = _RE_REFERRAL.search(registry_raw or "")
    if hop and (not info or not info.get("registrar") or not info.get("created")):
        target = hop.group(1).strip().lower().rstrip("/")
        target = re.sub(r"^https?://", "", target).split("/")[0]
        if target and target != server and "." in target:
            sub_raw = await _query(target, domain, min(timeout, 8.0))
            if sub_raw:
                sub = _parse(sub_raw)
                for k, v in sub.items():
                    info.setdefault(k, v)
                raw = registry_raw + "\n\n# ---- registrar whois ----\n" + sub_raw

    ip = server or ""
    return {"domain": domain, "server": ip, "raw": raw[:4000], **info}
