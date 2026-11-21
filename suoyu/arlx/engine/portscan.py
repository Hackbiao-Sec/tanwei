"""端口扫描（asyncio + asyncio.open_connection，跨平台，不依赖外部二进制）。

能力：
  * 端口组五档：企业端口 / 精简 / 常用 / 全端口 / 自定义
  * 排除端口、排除 IP（单点 / 区间 / CIDR 三种写法）
  * QPS 令牌桶限速（0 = 不限，只靠并发控制速率）
  * TCP 连接判定开放 + banner 探针认服务（含 TLS 握手指纹）
  * 断点续扫：记录已扫 IP×端口，中断后跳过
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field

import httpx

from ..config import config
from ..utils import PORT_SERVICE

TOP_10 = [80, 443, 22, 21, 8080, 8443, 3306, 3389, 445, 6379]

TOP_100 = TOP_10 + [
    25, 53, 110, 143, 465, 587, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 2376,
    3000, 3128, 3260, 4443, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 6000, 6379, 6443,
    7001, 7002, 7003, 7004, 7005, 7006, 7070, 8000, 8001, 8008, 8009, 8010, 8069, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8161, 8180,
    8200, 8443, 8500, 8686, 8888, 8983, 9000, 9001, 9042, 9080, 9090, 9091, 9092, 9093,
    9095, 9100, 9200, 9300, 9418, 9443, 9600, 9999, 10000, 10250, 11211, 15672, 16379,
    27017, 27018, 28017, 50000, 50070,
]

TOP_1000 = sorted(set(TOP_100 + list(range(1, 1025)) + [
    1080, 1099, 1241, 1352, 1433, 1521, 1527, 1604, 1701, 1717, 1883, 1900, 2049, 2082, 2083,
    2086, 2087, 2222, 2375, 2376, 2379, 2380, 2480, 2525, 2601, 2604, 3000, 3128, 3260, 3268,
    3306, 3389, 3690, 4000, 4040, 4369, 4443, 4444, 4505, 4506, 4567, 4711, 4848, 5000, 5001,
    5003, 5038, 5044, 5060, 5061, 5222, 5269, 5280, 5357, 5432, 5433, 5500, 5555, 5601, 5632,
    5672, 5683, 5900, 5901, 5938, 5984, 5985, 5986, 6000, 6001, 6379, 6380, 6443, 6444, 6445,
    6446, 6447, 6448, 6449, 6510, 6566, 7001, 7002, 7070, 7071, 7080, 7100, 7200, 7443, 7474,
    7547, 7777, 8000, 8001, 8008, 8009, 8010, 8020, 8032, 8042, 8069, 8070, 8080, 8081, 8082,
    8083, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8095, 8099, 8100, 8118, 8123,
    8139, 8140, 8161, 8172, 8180, 8181, 8200, 8222, 8243, 8254, 8280, 8332, 8333, 8400, 8443,
    8444, 8500, 8520, 8530, 8531, 8600, 8686, 8800, 8834, 8880, 8888, 8889, 8983, 9000, 9001,
    9002, 9009, 9010, 9042, 9043, 9080, 9081, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9100,
    9101, 9200, 9300, 9306, 9418, 9443, 9500, 9600, 9800, 9876, 9943, 9944, 9981, 9998, 9999,
    10000, 10001, 10250, 10255, 10256, 10443, 10554, 11211, 11371, 12345, 13722, 15000, 15672,
    16000, 16379, 16384, 16992, 16993, 17000, 18080, 18081, 19101, 20000, 20222, 25565, 25672,
    27017, 27018, 27019, 28017, 30000, 32400, 33060, 33899, 40000, 42000, 43000, 44334, 45000,
    46000, 47001, 48000, 50000, 50030, 50060, 50070, 50075, 50090, 50095, 51111, 55555, 56000,
    60000,
]))

# 企业端口：内网/边界最常见的对外服务面（数据库、中间件、远程管理、办公协作、物联网协议）。
# 覆盖面比 TOP100 宽、不代表「常用排名」，用于企业资产面排查。
ENTERPRISE_PORTS = sorted({
    21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 123, 135, 137, 139, 161, 177, 389, 427,
    443, 445, 465, 500, 515, 520, 523, 548, 623, 626, 636, 873, 902, 1080, 1099, 1433, 1434,
    1521, 1604, 1645, 1701, 1883, 1900, 2049, 2181, 2375, 2379, 2425, 3128, 3306, 3389, 4730,
    5060, 5222, 5351, 5353, 5432, 5555, 5601, 5672, 5683, 5900, 5938, 5984, 6000, 6379, 7001,
    7077, 8080, 8081, 8443, 8545, 8686, 9000, 9001, 9042, 9092, 9100, 9200, 9418, 9999, 11211,
    27017, 33848, 37777, 50000, 50070, 61616,
})

# 精简端口：只留 Web / 数据库 / 远程管理里最值钱的一撮，快速过一遍。
SLIM_PORTS = sorted({
    21, 22, 23, 80, 81, 88, 443, 445, 873, 1080, 1433, 1521, 2375, 3306, 3389, 5432, 5900,
    6379, 7001, 8000, 8001, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 11211, 27017,
})

ALL_PORTS = list(range(1, 65536))

PORT_PRESETS = {
    "enterprise": ENTERPRISE_PORTS,
    "slim": SLIM_PORTS,
    "top100": TOP_100,
    "top1000": TOP_1000,
    "top10": TOP_10,
    "all": ALL_PORTS,
}

# 端口组在界面上的中文名（后端日志与前端下拉共用同一套口径）
PORT_PRESET_LABELS = {
    "enterprise": "企业端口",
    "slim": "精简端口",
    "top100": "常用端口",
    "top1000": "扩展端口",
    "top10": "最小端口",
    "all": "全端口",
    "custom": "自定义",
}

BANNER_PROBES = {
    6379: b"\r\n",                 # redis: +PONG / -NOAUTH
    11211: b"version\r\n",         # memcached
    3306: b"",                     # mysql 服务端主动发握手包
    22: b"",                       # ssh 服务端主动发 banner
    21: b"",                       # ftp banner
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"",                      # TLS：只判开放
    8443: b"",
}

WEB_PORTS = {80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 3000, 5000, 7001, 7002, 8000, 8001,
             8008, 8009, 8010, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
             8090, 8091, 8092, 8093, 8095, 8161, 8180, 8200, 8443, 8500, 8686, 8800, 8888, 8983,
             9000, 9001, 9043, 9080, 9090, 9091, 9200, 9443, 9800, 10000, 10250, 10443, 15672,
             18080, 19101, 50000, 50070}

TLS_PORTS = {443, 8443, 9443, 4443, 6443, 444, 465, 993, 995, 10443}

TITLE_HINTS = {
    "redis": "redis", "mysql": "mysql", "ssh": "ssh-", "ftp": "220", "smtp": "220",
    "http": "http/", "memcached": "version", "mongodb": "mongodb",
}


@dataclass
class PortResult:
    ip: str
    port: int
    open: bool = False
    service: str = ""
    banner: str = ""
    is_web: bool = False
    is_tls: bool = False
    gateway: bool = False


def parse_ports(text: str) -> list[int]:
    """支持 "80,443" / "1-1000" / 混合"""
    ports: set[int] = set()
    for part in re.split(r"[,\s;]+", str(text or "")):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
                if lo > hi:
                    lo, hi = hi, lo
                ports.update(range(max(1, lo), min(65535, hi) + 1))
            except Exception:
                continue
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def ports_for_type(ptype: str, custom: str = "") -> list[int]:
    ptype = (ptype or "top100").lower()
    if ptype == "custom":
        return parse_ports(custom) or list(TOP_100)
    return list(PORT_PRESETS.get(ptype) or TOP_100)


def effective_ports(ptype: str, custom: str = "", exclude: str = "") -> list[int]:
    """端口组 − 排除端口。排除写错（空）就当没排除。"""
    ports = ports_for_type(ptype, custom)
    drop = set(parse_ports(exclude))
    if not drop:
        return ports
    return [p for p in ports if p not in drop]


# ───────── IP 范围解析 ─────────

_IP_SPLIT = re.compile(r"[,\s;、]+")


def parse_ip_ranges(text: str, limit: int = 65536) -> list[str]:
    """把 CIDR / 区间 / 单点混写的目标表展开成 IP 列表。

    支持 `10.0.0.0/24`、`10.0.0.1-10.0.0.20`、`10.0.0.1-20`（尾段简写）、单点。
    超出 limit 的段整段丢弃并记在返回值的第二项里，避免误写 `0.0.0.0/0` 把内存打爆。
    """
    out: list[str] = []
    seen: set[str] = set()
    for token in _IP_SPLIT.split(str(text or "")):
        token = token.strip()
        if not token:
            continue
        addrs = _expand_token(token, limit)
        for ip in addrs:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def _expand_token(token: str, limit: int) -> list[str]:
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except Exception:
            return []
        if net.version != 4 or net.num_addresses > limit:
            return []
        # /31 /32 没有「主机」概念，ip.hosts() 会返回空，这里按全部地址算
        return [str(x) for x in (net if net.num_addresses <= 2 else net.hosts())]
    if "-" in token:
        return _expand_range(token, limit)
    try:
        ipaddress.ip_address(token)
        return [token]
    except Exception:
        return []


def _expand_range(token: str, limit: int) -> list[str]:
    left, _, right = token.partition("-")
    left, right = left.strip(), right.strip()
    try:
        a = int(ipaddress.ip_address(left))
    except Exception:
        return []
    if right.isdigit() and "." in left:
        # 10.0.0.1-20：只给了尾段
        head = left.rsplit(".", 1)[0]
        right = f"{head}.{right}"
    try:
        b = int(ipaddress.ip_address(right))
    except Exception:
        return []
    lo, hi = (a, b) if a <= b else (b, a)
    if hi - lo + 1 > limit:
        return []
    return [str(ipaddress.ip_address(x)) for x in range(lo, hi + 1)]


def filter_ips(ips, exclude: str = "", limit: int = 65536) -> list[str]:
    """去掉排除表里的 IP（同样支持 CIDR / 区间 / 单点）。"""
    drop = set(parse_ip_ranges(exclude, limit))
    if not drop:
        return list(dict.fromkeys(ips))
    return [ip for ip in dict.fromkeys(ips) if ip not in drop]


def enumerate_domains(domain: str, exclude: str = "") -> list[str]:
    """从「域名 + IP 段」混写里取出域名（端口扫描只吃 IP，域名留给解析阶段）。"""
    out: list[str] = []
    drop = set(parse_ip_ranges(exclude))
    for token in _IP_SPLIT.split(str(domain or "")):
        token = token.strip()
        if not token or "/" in token or "-" in token:
            continue
        try:
            ip = str(ipaddress.ip_address(token))
        except Exception:
            out.append(token)
            continue
        if ip not in drop:
            out.append(ip)
    return out


# ───────── 限速 ─────────


class RateLimiter:
    """令牌桶：每秒放行 qps 个连接。qps<=0 表示不限速。"""

    def __init__(self, qps: float = 0) -> None:
        self.qps = float(qps or 0)
        self._interval = 1.0 / self.qps if self.qps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self._interval


class ScanCheckpoint:
    """断点续扫：记住已完成的 (ip, port)，中断后重跑跳过。

    只记开放结果与已扫标记，规模按批次增长；全端口扫大网段时按需开启。
    """

    def __init__(self, existing: set[tuple[str, int]] | None = None) -> None:
        self.done: set[tuple[str, int]] = set(existing or ())
        self.open: list[PortResult] = []

    def seen(self, ip: str, port: int) -> bool:
        return (ip, port) in self.done

    def mark(self, ip: str, port: int) -> None:
        self.done.add((ip, port))


# ───────── 扫描 ─────────


async def _banner(ip: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return ""
    out = ""
    try:
        # BANNER_PROBES 里存的是 bytes（HTTP 探针），其它协议可为空串不发送
        probe = BANNER_PROBES.get(port) or b""
        if isinstance(probe, str):
            probe = probe.encode()
        if probe:
            # 对端发完 SYN-ACK 就 RST 时 drain 会抛 ConnectionResetError。
            # 这只说明拿不到 banner，不该冒到端口扫描上层把整个任务判成异常。
            try:
                writer.write(probe)
                await writer.drain()
            except Exception:
                return ""
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=min(2.0, timeout + 0.5))
            out = data.decode("utf-8", "ignore").strip()
        except Exception:
            out = ""
    finally:
        try:
            writer.close()
        except Exception:
            pass
    out = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", out)
    return out[:300]


# 对照端口：只问「这台机器是不是什么都答应」。放在 6 万号段，正常主机绝不会开。
# 部分运营商 / 企业网关对任何 TCP 握手都先回 SYN-ACK，不透传流量：
# 结果是 top100 全「开放」，资产表里灌满根本不存在的 7001/9200/6379。
CONTROL_PORT = 59993


# create_default_context() 在 Windows 上要读一遍系统证书库（实测 86ms），而这段是同步的，
# 一跑就在事件循环线程里堵住。端口阶段每个 Web/TLS 端口问一次，几千个端口就是几分钟的
# 硬阻塞：健康检查发不出去，看门狗判死重启，任务停在半路。握手探测不需要校验证书，
# 所以只建一次裸上下文复用。
_TLS_PROBE_CTX: ssl.SSLContext | None = None


def _tls_probe_ctx() -> ssl.SSLContext:
    global _TLS_PROBE_CTX
    if _TLS_PROBE_CTX is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _TLS_PROBE_CTX = ctx
    return _TLS_PROBE_CTX


async def _tls_ok(ip: str, port: int, timeout: float) -> bool:
    """TLS 端口：完成握手才算开放（SYN-ACK 假开放在握手阶段一定失败）。"""
    try:
        ctx = _tls_probe_ctx()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip), timeout=timeout)
        writer.close()
        return True
    except Exception:
        return False


async def _http_alive(ip: str, port: int, tls: bool, timeout: float) -> bool:
    """HTTP 端点：必须回出状态行 / 响应头。空连接或立刻断开不算。"""
    path = f"{'https' if tls else 'http'}://{ip}:{port}/"
    try:
        # verify=是共享的 CERT_NONE 上下文：verify=False 时 httpx 每个客户端都要
        # 自己建上下文，一个 IP 几十个 Web 端口累计起来同样是秒级的同步开销。
        async with httpx.AsyncClient(timeout=timeout, verify=_tls_probe_ctx(), trust_env=False,
                                     follow_redirects=False) as cli:
            r = await cli.get(path)
        return 100 <= r.status_code < 600 and (r.status_code != 502 or bool(r.headers.get("server")))
    except Exception:
        return False


async def _tcp_speaks(ip: str, port: int, timeout: float) -> bool:
    """非 Web 端口：连上后要么服务端先说话，要么对探针有回应。"""
    try:
        banner = await _banner(ip, port, timeout)
    except Exception:
        banner = ""
    if banner:
        return True
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return False
    try:
        # 有些服务要收到换行才回问候语
        writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout=min(1.5, timeout))
        return bool(data)
    except Exception:
        return False
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def scan_port(ip: str, port: int, host: str | None = None, timeout: float | None = None,
                    detect: bool = True) -> PortResult:
    t = float(timeout or config.get("scan", "port_timeout") or 2)
    res = PortResult(ip=ip, port=port)
    if port == CONTROL_PORT:
        return res
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=t)
    except Exception:
        return res
    try:
        writer.close()
    except Exception:
        pass

    tls = port in TLS_PORTS
    web = port in WEB_PORTS
    if not detect:
        # 不识别服务时只能报「连上了」，但连上不等于服务在，
        # 所以控件端口一并打探，好让上层把假开放剔掉。
        if await _control_open(ip, min(3.0, t * 1.5)):
            res.gateway = True
            return res
        res.open = True
        res.is_tls, res.is_web = tls, web
        res.service = PORT_SERVICE.get(port, "unknown")
        return res

    # 控件端口这一枪必须在这里问：single-port 调用（旁站/C 段/深扫）不经过
    # scan_ip，那时任何端口都会「开放」，资产里就灌满不存在的 7001/9200。
    link_gateway = await _control_open(ip, min(3.0, t * 1.5))

    # 三种协议各问一次：TLS 看握手，Web 看状态行，其它看问候语。
    # 多数厂商网关只回 SYN-ACK 就沉默，三路都拿不到证据。
    answers = await asyncio.gather(
        _tls_ok(ip, port, t) if (tls or web) else asyncio.sleep(0, result=False),
        _http_alive(ip, port, False, t) if web else asyncio.sleep(0, result=False),
        _http_alive(ip, port, True, t) if web and tls else asyncio.sleep(0, result=False),
        _tcp_speaks(ip, port, t) if not tls else asyncio.sleep(0, result=False),
        return_exceptions=True,
    )
    # 单路探测被 RST/超时打断只等于这一路没有证据；异常对象不能再被 bool() 当成「命中」。
    tls_hit, http_hit, https_hit, tcp_hit = (x is True for x in answers)
    if link_gateway:
        # 这台机器对任意端口都回握手，上面几条「证据」也是链路伪造的。
        # 整台判为占位主机，不报任何开放端口。
        res.gateway = True
        return res
    if not (tls_hit or http_hit or https_hit or tcp_hit):
        return res

    res.open = True
    res.is_tls = tls_hit
    res.is_web = web or http_hit or https_hit
    res.service = PORT_SERVICE.get(port, "unknown")
    if tcp_hit and not tls:
        banner = await _banner(ip, port, t)
        if banner:
            res.banner = banner
            low = banner.lower()
            for svc, hint in TITLE_HINTS.items():
                if hint in low:
                    res.service = svc
                    break
            if "http/" in low or low.startswith("<!doctype") or "<html" in low:
                res.is_web = True
    return res


# 控件端口同一个 IP 每个端口都要问一次，一次 IP×99 端口就是 99 次多余握手。
# 结论按 IP 缓存一小段时间（缓存的是「这台机器对任意端口都回握手」这个主机属性）。
_CONTROL_CACHE: dict[str, tuple[float, bool]] = {}
_CONTROL_TTL = 60.0


async def _control_open(ip: str, timeout: float) -> bool:
    now = time.monotonic()
    hit = _CONTROL_CACHE.get(ip)
    if hit is not None and now - hit[0] < _CONTROL_TTL:
        return hit[1]
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, CONTROL_PORT),
                                           timeout=timeout)
    except Exception:
        ok = False
    else:
        try:
            writer.close()
        except Exception:
            pass
        ok = True
    if len(_CONTROL_CACHE) > 4096:
        _CONTROL_CACHE.clear()
    _CONTROL_CACHE[ip] = (now, ok)
    return ok


async def scan_ip(ip: str, ports: list[int], *, host: str | None = None, timeout: float = 2.0,
                  concurrent: int = 200, detect: bool = True,
                  limiter: RateLimiter | None = None,
                  checkpoint: ScanCheckpoint | None = None) -> list[PortResult]:
    sem = asyncio.Semaphore(max(1, concurrent))
    out: list[PortResult] = []
    # 主机对随机高端口也回 SYN-ACK：这台机器的「开放」多半是网关占位，
    # 三路协议证据时不会认，标记出来让上层记一条提示。
    link_gateway = False

    async def one(p: int):
        nonlocal link_gateway
        if checkpoint is not None and checkpoint.seen(ip, p):
            return
        async with sem:
            if limiter is not None:
                await limiter.acquire()
            # 单端口探测里的底层网络异常不能终止整台主机的扫描。
            try:
                r = await scan_port(ip, p, host, timeout, detect)
            except Exception:
                return
        if checkpoint is not None:
            checkpoint.mark(ip, p)
        if r.open:
            out.append(r)
            if checkpoint is not None:
                checkpoint.open.append(r)

    if ports and CONTROL_PORT not in ports:
        link_gateway = await _control_open(ip, min(3.0, float(timeout) * 2))
    await asyncio.gather(*[one(p) for p in ports], return_exceptions=True)
    if link_gateway:
        for r in out:
            r.gateway = True  # 上层据此在日志里点名，不把假端口当资产
    return sorted(out, key=lambda r: r.port)


async def scan_ips(ips: list[str], ports: list[int], *, timeout: float = 2.0,
                   concurrent: int = 300, detect: bool = True, qps: float = 0,
                   progress=None) -> dict[str, list[PortResult]]:
    limiter = RateLimiter(qps)
    out: dict[str, list[PortResult]] = {ip: [] for ip in ips}
    done = 0
    total = max(len(ips), 1)

    async def one(ip: str):
        nonlocal done
        try:
            res = await scan_ip(ip, ports, timeout=timeout, concurrent=max(1, concurrent),
                                detect=detect, limiter=limiter)
        except Exception:
            res = []
        out[ip] = res
        done += 1
        if progress and done % 5 == 0:
            progress(done, total)

    await asyncio.gather(*[one(ip) for ip in ips], return_exceptions=True)
    return out


def ip_network_ips(cidr: str, limit: int = 65536) -> list[str]:
    return _expand_token(cidr, limit)


def hostname_of_ip(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
