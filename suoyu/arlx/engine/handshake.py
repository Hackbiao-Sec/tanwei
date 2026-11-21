"""探测握手增强：在存活探测结果上再取一层「侦察标记」。

存活探测给的是状态码、标题、指纹；实战里还差四样东西才能判这扇门值不值得进：
  * JARM —— 只看 TLS 握手的特征回包，不落地页面也能认出同一批同源资产（自研网关、
    反代、WAF 默认配置都是成片复制的），且目标换了 IP / 域名照样认得出
  * CORS / CSP —— 响应头里的信任边界，决定后续前端攻击面怎么打
  * TLS 证书链 —— SAN 之外的 issuer，能顺着签发关系捞同批证书
  * ASN —— 目标地址归属，判断是否落云厂商 / 机房 / 运营商 NAT

这些都不改页面状态，是对已有存活结果做的补充读取，失败一律当没有，不拖慢主流程。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..config import config

# JARM 标准参数：10 个 TLS ClientHello 变体，每个取应答前 30 字节做哈希
JARM_CIPHERS = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
]

# 加密套件组：不同组合让不同栈回不同握手字节，组合越多区分度越高
JARM_TLS_VERSIONS = ["1.3", "1.2", "1.1", "1.0"]


@dataclass
class HandshakeMark:
    host: str = ""
    port: int = 0
    jarm: str = ""
    tls_versions: list[str] = field(default_factory=list)
    cipher: str = ""
    san: list[str] = field(default_factory=list)
    issuer: str = ""
    asn: str = ""
    asn_org: str = ""
    csp: str = ""
    cors_origin: str = ""
    cors_credentials: str = ""
    hsts: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port, "jarm": self.jarm,
            "tls_versions": self.tls_versions, "cipher": self.cipher,
            "san": self.san, "issuer": self.issuer,
            "asn": self.asn, "asn_org": self.asn_org,
            "csp": self.csp, "cors_origin": self.cors_origin,
            "cors_credentials": self.cors_credentials, "hsts": self.hsts,
            "error": self.error,
        }


def _enabled() -> bool:
    return bool(config.get("scan", "handshake_mark", default=True))


def _timeout() -> float:
    try:
        return float(config.get("scan", "handshake_timeout", default=4) or 4)
    except Exception:
        return 4.0


def _wheel(seq: list[str], i: int) -> list[str]:
    """按位轮转：每个 ClientHello 变体换一个套件顺序，握手回包才会分叉。"""
    if not seq:
        return seq
    k = i % len(seq)
    return seq[k:] + seq[:k]


def _jarm_one(host: str, port: int, index: int, sni: str, timeout: float) -> bytes:
    """用指定套件顺序握一次手，返回服务端 ServerHello 的前 30 字节。"""
    ciphers = _wheel(JARM_CIPHERS, index)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # 每轮只留 3 个套件、并且版本随 index 变化，制造出足够不同的 ClientHello
        picked = ciphers[:3]
        ctx.set_ciphers(":".join(picked))
        try:
            ver = JARM_TLS_VERSIONS[index % len(JARM_TLS_VERSIONS)]
            ctx.minimum_version = {"1.3": ssl.TLSVersion.TLSv1_3,
                                   "1.2": ssl.TLSVersion.TLSv1_2,
                                   "1.1": ssl.TLSVersion.TLSv1_1,
                                   "1.0": ssl.TLSVersion.TLSv1}[ver]
            ctx.maximum_version = ctx.minimum_version
        except Exception:
            pass
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=sni or host)
            blob = b""
            try:
                # Python 不暴露原始 ServerHello，用协商结果 + 证书摘要近似出稳定指纹
                ver = ssock.version() or ""
                cipher = (ssock.cipher() or ("",))[0]
                der = ssock.getpeercert(binary_form=True) or b""
                blob = f"{ver}|{cipher}|{hashlib.sha256(der).hexdigest()[:16]}".encode()
            finally:
                try:
                    ssock.close()
                except Exception:
                    pass
            return blob
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception as e:
        return f"err:{type(e).__name__}".encode()


async def jarm(host: str, port: int = 443, *, timeout: float | None = None) -> str:
    """十轮握手拼成 JARM 风格指纹。

    真 JARM 的算法是逐字节拼服务端回包再取模糊哈希；Python 标准库拿不到原始
    ServerHello，这里用「协商版本 + 套件 + 证书摘要」作为每轮标识，再取整体哈希。
    同一套网关 / 反代 / WAF 的产物会稳定一致，跨域名认同源足够用。
    """
    t = float(timeout or _timeout())
    loop = asyncio.get_running_loop()
    parts: list[bytes] = []
    for i in range(10):
        blob = await loop.run_in_executor(None, _jarm_one, host, port, i, host, t)
        parts.append(blob[:30])
    joined = b"".join(parts)
    return hashlib.sha256(joined).hexdigest()


def _tls_detail(host: str, port: int, timeout: float) -> dict:
    out: dict = {"versions": [], "cipher": "", "san": [], "issuer": "", "error": ""}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["versions"] = [ssock.version() or ""]
                out["cipher"] = (ssock.cipher() or ("",))[0]
                der = ssock.getpeercert(binary_form=True) or b""
        if der:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                out["san"] = san.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
            org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            out["issuer"] = org[0].value if org else cert.issuer.rfc4514_string()[:120]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:160]
    return out


def asn_of(ip: str) -> tuple[str, str]:
    """IP 归属（ASN + 组织）。

    优先读本地 ASN 表；没有就走公开 whois 端点。拿不到返回空，不阻塞主流程。
    """
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return "", ""
    try:
        import httpx

        proxy = config.get("proxy", "url") if config.get("proxy", "sources_via_proxy") else None
        with httpx.Client(timeout=6, proxy=proxy or None, trust_env=False) as c:
            r = c.get(f"https://api.ipshudi.com/query/{ip}")
            if r.status_code == 200:
                data = r.json()
                d = data.get("data") or data
                asn = str(d.get("asn") or d.get("asnumber") or "")
                org = str(d.get("isp") or d.get("owner") or d.get("asowner") or "")
                return asn, org[:120]
    except Exception:
        pass
    return "", ""


_CORS_RE = re.compile(r"^access-control-allow-origin$", re.I)


def header_marks(url: str, headers: dict, body: str = "") -> dict:
    """从已有响应里抽信任边界标记（不额外发请求）。"""
    out: dict = {"csp": "", "cors_origin": "", "cors_credentials": "", "hsts": ""}
    if not headers:
        return out
    low = {str(k).lower(): str(v) for k, v in headers.items()}
    out["csp"] = low.get("content-security-policy", "")[:500]
    cors = ""
    for k, v in headers.items():
        if _CORS_RE.match(str(k)):
            cors = str(v)
            break
    out["cors_origin"] = cors
    out["cors_credentials"] = low.get("access-control-allow-credentials", "")
    out["hsts"] = low.get("strict-transport-security", "")
    # 页面里的 meta CSP 也算一层策略，正文里没有就不额外算
    if not out["csp"] and body:
        m = re.search(r'<meta[^>]+http-equiv=["\']?content-security-policy["\']?[^>]+content=["\']([^"\']+)',
                      body, re.I)
        if m:
            out["csp"] = m.group(1)[:500]
    return out


async def mark(url: str, headers: dict | None = None, body: str = "",
               jarm: bool | None = None, asn: bool | None = None) -> HandshakeMark:
    """对一个已存活 URL 做握手增强。HTTP 站也跑（只取头标记，不握手）。

    `jarm` / `asn` 传 None 时回落扫描配置：单项执行可以按需开关这两步，
    不传就跟全局一致。
    """
    if jarm is None:
        jarm = bool(config.get("scan", "jarm_probe", default=True))
    if asn is None:
        asn = bool(config.get("scan", "asn_lookup", default=True))
    parts = urlparse(url)
    host = parts.hostname or ""
    try:
        # 坏端口（:blank 这类抓来的链接）到取 .port 才抛，别让整次握手炸掉
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = 443 if parts.scheme == "https" else 80
    mk = HandshakeMark(host=host, port=int(port))
    if not host:
        mk.error = "invalid url"
        return mk
    mk_dict = header_marks(url, headers or {}, body)
    mk.csp = mk_dict["csp"]
    mk.cors_origin = mk_dict["cors_origin"]
    mk.cors_credentials = mk_dict["cors_credentials"]
    mk.hsts = mk_dict["hsts"]
    t = _timeout()
    try:
        if int(port) in (443, 8443, 9443, 4443, 6443):
            loop = asyncio.get_running_loop()
            det = await loop.run_in_executor(None, _tls_detail, host, int(port), t)
            mk.tls_versions = det.get("versions") or []
            mk.cipher = det.get("cipher") or ""
            mk.san = det.get("san") or []
            mk.issuer = det.get("issuer") or ""
            if det.get("error"):
                mk.error = det["error"]
            if jarm:
                mk.jarm = await jarm(host, int(port), timeout=t)
        if asn:
            loop = asyncio.get_running_loop()
            ip = await loop.run_in_executor(None, _resolve, host)
            if ip:
                mk.asn, mk.asn_org = await loop.run_in_executor(None, asn_of, ip)
    except Exception as e:
        mk.error = f"{type(e).__name__}: {e}"[:160]
    return mk


def _resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def to_jsonl_row(asset: dict) -> dict:
    """存活结果按通行 JSONL 字段命名落一行，导出给外部工具接着用。"""
    extra = asset.get("extra") or {}
    mk = extra.get("handshake") or {}
    return {
        "input": asset.get("url") or "",
        "url": extra.get("final_url") or asset.get("url") or "",
        "host": asset.get("host") or "",
        "port": asset.get("port") or "",
        "scheme": asset.get("scheme") or "",
        "status_code": asset.get("status_code") or 0,
        "title": extra.get("title") or asset.get("title") or "",
        "content_length": asset.get("length") or 0,
        "webserver": asset.get("server") or "",
        "tech": (extra.get("fingerprint") or []) if isinstance(extra.get("fingerprint"), list) else [],
        "favicon": extra.get("favicon") or 0,
        "cdn_name": asset.get("cdn") or "",
        "jarm_hash": mk.get("jarm") or "",
        "csp": mk.get("csp") or "",
        "cors": mk.get("cors_origin") or "",
        "asn": mk.get("asn") or "",
        "cert_issuer": (extra.get("cert") or {}).get("issuer") or "",
        "cname": "",
    }


def bom() -> str:
    """导出文件统一带 UTF-8 头，Excel 直接双击也不乱码。"""
    return base64.b64encode(b"\xef\xbb\xbf").decode()
