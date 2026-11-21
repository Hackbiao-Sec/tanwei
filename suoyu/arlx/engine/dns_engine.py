"""异步 DNS 引擎（替代 ARL 的 massdns）。

能力：
  * 批量 A/AAAA 解析（asyncio + dnspython UDP 直查，跨平台、无系统解析器依赖）
  * CNAME 链追踪
  * PTR 反查
  * 泛解析（wildcard）检测与剔除
  * MX / TXT / NS / SOA 查询（用于企业归属、备案、SPF 线索）

性能要点：dnspython 的 asyncresolver 需线程池且 LRU 缓存非线程安全，大字典时极慢；
这里直接用 asyncio.DatagramProtocol 发 UDP 包，自建 wire 解析与并发闸，2 万子域 300 并发可在秒级完成。
"""

from __future__ import annotations

import asyncio
import random
import string
import time
from dataclasses import dataclass, field

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.reversename

DEFAULT_NAMESERVERS = ["223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8"]

# 超时过的服务器在这段时间内排到队尾，避免每次都先撞同一台坏服务器
BLACKLIST_COOLDOWN = 60.0


@dataclass
class DnsResult:
    domain: str
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    wildcard: bool = False


def _rand_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class _UdpQuery(asyncio.DatagramProtocol):
    """单次 UDP DNS 查询：发出去 → 收到第一个匹配的回包 → 置 future"""

    def __init__(self, wire: bytes, qid: int, fut: asyncio.Future) -> None:
        self.wire = wire
        self.qid = qid
        self.fut = fut
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        try:
            transport.sendto(self.wire)
        except Exception as e:  # 发送失败直接结束
            if not self.fut.done():
                self.fut.set_exception(e)

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if self.fut.done():
            return
        # 最小校验：响应 ID 一致（防串包）
        if len(data) >= 2 and int.from_bytes(data[:2], "big") != self.qid:
            return
        self.fut.set_result(data)

    def error_received(self, exc) -> None:  # type: ignore[override]
        if not self.fut.done():
            self.fut.set_exception(exc)


class _DnsChannel(asyncio.DatagramProtocol):
    """对单个权威 DNS 服务器保持一条长连接 UDP socket，按 query id 分发回包。

    Windows 下 DNS 服务器对陌生随机源端口会丢包，每查询新建 socket 会造成大量超时；
    复用同一 socket 既稳定又能压满并发。
    """

    def __init__(self, server: str) -> None:
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None
        self.pending: dict[int, asyncio.Future] = {}
        self._ready: asyncio.Future | None = None
        self.sent = 0
        self.recv = 0
        self.blacklisted_at = 0.0

    async def connect(self, timeout: float = 3.0) -> None:
        loop = asyncio.get_running_loop()
        self._ready = loop.create_future()
        try:
            await asyncio.wait_for(
                loop.create_datagram_endpoint(lambda: self, remote_addr=(self.server, 53)),
                timeout=timeout)
        except Exception:
            self._ready = None
            raise

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        if self._ready and not self._ready.done():
            self._ready.set_result(True)

    def connection_lost(self, exc) -> None:  # type: ignore[override]
        self.transport = None
        for fut in list(self.pending.values()):
            if not fut.done():
                fut.set_exception(ConnectionError("dns channel closed"))
        self.pending.clear()

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if len(data) < 2:
            return
        qid = int.from_bytes(data[:2], "big")
        fut = self.pending.pop(qid, None)
        if fut is not None and not fut.done():
            self.recv += 1
            fut.set_result(data)

    def error_received(self, exc) -> None:  # pragma: no cover
        pass

    def alive(self) -> bool:
        return self.transport is not None and not self.transport.is_closing()

    def close(self) -> None:
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
            self.transport = None


class DnsEngine:
    def __init__(self, nameservers: list[str] | None = None, concurrent: int = 500,
                 timeout: float = 2.0) -> None:
        self.nameservers = nameservers or DEFAULT_NAMESERVERS
        self.concurrent = max(10, int(concurrent))
        self.timeout = timeout
        self.sem: asyncio.Semaphore | None = None
        self._channels: list[_DnsChannel] = []
        self._rr = 0

    def _sem(self) -> asyncio.Semaphore:
        # 信号量需绑定当前事件循环，延迟创建
        if self.sem is None:
            self.sem = asyncio.Semaphore(self.concurrent)
        return self.sem

    async def start(self) -> None:
        """建立到各 DNS 服务器的长连接（可重复调用）"""
        if all(c.alive() for c in self._channels) and self._channels:
            return
        self._channels = []
        for ns in self.nameservers:
            ch = _DnsChannel(ns)
            try:
                await ch.connect(self.timeout)
                self._channels.append(ch)
            except Exception:
                continue
        if not self._channels:
            raise ConnectionError("所有 DNS 服务器均连接失败")

    def close(self) -> None:
        for ch in self._channels:
            ch.close()
        self._channels = []

    def _pick(self, skip: set[str] | None = None) -> _DnsChannel | None:
        """按轮转挑一条可用长连接；近期超时过的服务器先跳过，避免单次查询直接落空。"""
        now = time.monotonic()
        skip = skip or set()
        live = [c for c in self._channels
                if c.alive() and c.server not in skip and now - c.blacklisted_at > BLACKLIST_COOLDOWN]
        if not live:
            # 全都在冷却：只用来兜底，不要再排除
            live = [c for c in self._channels if c.alive() and c.server not in skip]
        if not live:
            return None
        self._rr = (self._rr + 1) % len(live)
        return live[self._rr]

    async def _ask_channel(self, ch: _DnsChannel, name: dns.name.Name,
                           rtype: str) -> dns.message.Message | None:
        """在一条长连接上问一次；每次重建 query 以拿到新的 id，避免跨服务器串包。"""
        try:
            q = dns.message.make_query(name, rtype, want_dnssec=False)
        except Exception:
            return None
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        ch.pending[q.id] = fut
        try:
            ch.transport.sendto(q.to_wire())  # type: ignore[union-attr]
            ch.sent += 1
            data = await asyncio.wait_for(asyncio.shield(fut), timeout=self.timeout)
        except Exception:
            return None
        finally:
            ch.pending.pop(q.id, None)
        try:
            return dns.message.from_wire(data)
        except Exception:
            return None

    async def _once(self, fqdn: str, rtype: str) -> dns.message.Message | None:
        try:
            name = dns.name.from_text(fqdn)
        except Exception:
            return None
        # 单台 DNS 被丢包或被墙时换下一台。以前只挑一台，超时就当解析不到，
        # 于是同一域名会时有时无——单阶段重跑最容易撞上。
        tried: set[str] = set()
        for _ in range(max(1, min(2, len(self._channels)))):
            ch = self._pick(tried)
            if ch is None:
                break
            tried.add(ch.server)
            msg = await self._ask_channel(ch, name, rtype)
            if msg is not None:
                return msg
            ch.blacklisted_at = time.monotonic()
        # 兜底：长连接全不可用时走一次性 socket；先试没打过的服务器，最多两台
        spare = [ns for ns in self.nameservers if ns not in tried] or list(self.nameservers)
        for ns in spare[:2]:
            try:
                q = dns.message.make_query(name, rtype, want_dnssec=False)
            except Exception:
                return None
            data = await self._udp_once(q, ns)
            if not data:
                continue
            try:
                return dns.message.from_wire(data)
            except Exception:
                continue
        return None

    async def _udp_once(self, q: dns.message.Message, ns: str) -> bytes | None:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        transport = None
        try:
            transport, _ = await asyncio.wait_for(
                loop.create_datagram_endpoint(lambda: _UdpQuery(q.to_wire(), q.id, fut),
                                              remote_addr=(ns, 53)),
                timeout=self.timeout)
            return await asyncio.wait_for(asyncio.shield(fut), timeout=self.timeout)
        except Exception:
            return None
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    async def _udp(self, fqdn: str, rtype: str = "A") -> dns.message.Message | None:
        return await self._once(fqdn, rtype)

    async def _resolve_once(self, fqdn: str, rtype: str = "A") -> list[str]:
        async with self._sem():
            msg = await self._udp(fqdn, rtype)
        if msg is None:
            return []
        out: list[str] = []
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                continue
            if rtype == "A" and rrset.rdtype == dns.rdatatype.A:
                out.extend(r.address for r in rrset)
            elif rtype == "AAAA" and rrset.rdtype == dns.rdatatype.AAAA:
                out.extend(r.address for r in rrset)
            elif rrset.rdtype == dns.rdatatype.from_text(rtype):
                out.extend(r.to_text() for r in rrset)
        return out

    def _cnames_of(self, msg: dns.message.Message | None) -> list[str]:
        if msg is None:
            return []
        out: list[str] = []
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                out.extend(str(r.target).rstrip(".").lower() for r in rrset)
        return out

    async def resolve_a(self, domain: str) -> DnsResult:
        domain = domain.strip().strip(".").lower()
        if not domain:
            return DnsResult(domain=domain)
        msg = None
        async with self._sem():
            msg = await self._udp(domain, "A")
        if msg is None:
            return DnsResult(domain=domain)
        ips = [r.address for rr in msg.answer if rr.rdtype == dns.rdatatype.A for r in rr]
        cnames = self._cnames_of(msg)
        if not ips and cnames:
            # CNAME 指向解析（ARL 同样做链追踪，这里跟一跳）
            for cn in cnames:
                async with self._sem():
                    m2 = await self._udp(cn, "A")
                if m2:
                    ips.extend(r.address for rr in m2.answer
                               if rr.rdtype == dns.rdatatype.A for r in rr)
                if ips:
                    break
        if not ips:
            async with self._sem():
                m3 = await self._udp(domain, "AAAA")
            if m3:
                ips.extend(r.address for rr in m3.answer if rr.rdtype == dns.rdatatype.AAAA for r in rr)
        return DnsResult(domain=domain, ips=ips, cnames=cnames)

    async def resolve_many(self, domains: list[str], batch: int = 4000) -> dict[str, DnsResult]:
        uniq = list(dict.fromkeys(d for d in domains if d))
        out: dict[str, DnsResult] = {}
        for i in range(0, len(uniq), batch):
            chunk = uniq[i:i + batch]
            tasks = [self.resolve_a(d) for d in chunk]
            for res in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(res, DnsResult):
                    out[res.domain] = res
        return out

    async def detect_wildcard(self, root: str, samples: int = 3) -> set[str]:
        """用随机子域探测泛解析，返回泛解析 IP 集合"""
        probes = [f"{_rand_label()}.{root}" for _ in range(samples)]
        ips: set[str] = set()
        # 泛解析探测只是一条启发式：某次查询炸了就当这一枪没结果，
        # 不能把异常抛到流水线里（这里以前会把整段被动收集带走）。
        for res in await asyncio.gather(*[self.resolve_a(p) for p in probes],
                                        return_exceptions=True):
            if isinstance(res, DnsResult):
                ips.update(res.ips)
        return ips

    async def resolve_ptr(self, ip: str) -> list[str]:
        try:
            rev = str(dns.reversename.from_address(ip))
        except Exception:
            return []
        return await self._resolve_once(rev, "PTR")

    async def query_type(self, domain: str, rtype: str) -> list[str]:
        async with self._sem():
            msg = await self._udp(domain, rtype)
        if msg is None:
            return []
        want = dns.rdatatype.from_text(rtype)
        out: list[str] = []
        for rrset in msg.answer:
            if rrset.rdtype == want:
                for r in rrset:
                    if hasattr(r, "exchange"):
                        out.append(f"{r.preference} {r.exchange}")
                    elif hasattr(r, "target"):
                        out.append(str(r.target).rstrip("."))
                    else:
                        out.append(r.to_text().strip('"'))
        return out

    async def mail_records(self, root: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for rtype in ("MX", "TXT", "NS", "SOA"):
            vals = await self.query_type(root, rtype)
            if vals:
                out[rtype] = vals
        return out


def run_async(coro):
    """在已有事件循环之外安全执行（同步调用点用）"""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # 已在事件循环（如 FastAPI 路由内）→ 新线程跑
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
