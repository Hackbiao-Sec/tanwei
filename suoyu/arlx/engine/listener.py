"""带外回显（OOB）：给每个任务发一次性 token，DNS/HTTP 命中即落库，用于确认 SSRF、
盲注、XXE、Log4j 这类「不回显但会外连」的漏洞真的打穿了。

移植自 ARL-NPoC `xing/plugins/listener`：
- `dns.py`：UDP 53 权威解析，把每个 question 记下来 → 这里用 dnspython 解析报文 + 标准库收发，
  不再引入 xing 依赖的 dnslib / Flask；
- `http_api.py`：HTTP 回调接口，记录 method / path / headers / body → 这里挂在既有的
  FastAPI 服务上，复用统一鉴权，不另起一个 Flask 进程。

和 xing 的区别：xing 内置了 `/weblogic/<payload>`、`/eureka/<payload>` 两个 RCE 模板，
本文件只负责记录回连，不承载任何 exploit。

用法：
    token = listener.alloc(task_id)          # 任务开始时发一个
    payload = listener.payload(token, "dns") # 把 payload 塞进待测参数
    listener.hits(task_id=...)               # 看有没有回连
"""
from __future__ import annotations

import asyncio
import secrets
import socket
import time
from typing import Any

from ..config import config
from ..db import store

try:  # dnspython 已经是项目依赖；万一缺失只关掉 DNS 那一段，HTTP 回调照常
    from dns import message as dns_message
    from dns import rcode as dns_rcode
    from dns import rrset as dns_rrset
except Exception:  # pragma: no cover
    dns_message = None
    dns_rcode = None
    dns_rrset = None


# ─────────────── 配置 ───────────────
def _cfg(*path: str, default: Any = None) -> Any:
    return config.get("listener", *path, default=default)


def enabled() -> bool:
    return bool(_cfg("enabled", default=True))


def bind_addr() -> str:
    return str(_cfg("bind", default="0.0.0.0") or "0.0.0.0")


def dns_port() -> int:
    return int(_cfg("dns_port", default=53) or 53)


def http_port() -> int:
    return int(_cfg("http_port", default=8913) or 8913)


def base_domain() -> str:
    """权威域名。留空 = 没接自己的域，DNS 段自动关闭（公网 DNS 不会把我们的记录指过来）。"""
    return str(_cfg("domain", default="") or "").strip().strip(".")


def exit_ip() -> str:
    """公网出口 IP，用于拼 HTTP 回调地址；留空则运行时自动探测一次并缓存。"""
    got = str(_cfg("exit_ip", default="") or "").strip()
    if got:
        return got
    return _autodetect_ip()


_ip_cache: dict[str, Any] = {"ip": "", "ts": 0.0}


def _autodetect_ip() -> str:
    """走一次 UDP connect 拿本机出网地址；不产生实际流量、也不依赖外网 API。"""
    now = time.time()
    if _ip_cache["ip"] and now - _ip_cache["ts"] < 600:
        return _ip_cache["ip"]
    for probe in ("223.5.5.5", "114.114.114.114", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect((probe, 53))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                _ip_cache.update(ip=ip, ts=now)
                return ip
        except Exception:
            continue
    return ""


# ─────────────── token 与 payload ───────────────
def alloc(task_id: str) -> str:
    """给任务发一个 token 并落库。同一任务可多次调用，命中都按 token 反查回任务。"""
    token = secrets.token_hex(6)          # 12 位十六进制：够短能塞进 URL，碰撞概率可忽略
    try:
        c = store.conn()
        c.execute(
            "INSERT INTO listener_hits (token, task_id, proto, source_ip, host, path, method,"
            " headers, body, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (token, task_id, "alloc", "", "", "", "", "", "", time.time()),
        )
        c.commit()
    except Exception:
        pass
    return token


def payload(token: str, proto: str = "dns", task_id: str = "") -> str:
    """把 token 变成可以直接塞进参数的地址。task_id 只在 token 还没落库时才需要。"""
    proto = (proto or "dns").lower()
    if proto == "dns":
        dom = base_domain()
        if not dom:
            return ""
        return f"{token}.{dom}"
    if proto in ("http", "api"):
        # 走 FastAPI 那条路：与主服务同端口，命中带完整 headers/body
        ip = exit_ip()
        return f"http://{ip}:8913/l/{token}" if ip else ""
    ip = exit_ip()
    if not ip:
        return ""
    return f"http://{ip}:{http_port()}/{token}"


def payloads(token: str, task_id: str = "") -> list[str]:
    """一次给出可用的全部形态：DNS、HTTP、以及带常见参数名的 HTTP 变体。"""
    out: list[str] = []
    dom = payload(token, "dns")
    if dom:
        out.extend([dom, f"//{dom}", f"http://{dom}/"])
    base = payload(token, "http")
    if base:
        out.extend([base, f"{base}/a", f"{base}?u={base}"])
    return out


# ─────────────── 命中记录 ───────────────
def hit(token: str, proto: str, *, source_ip: str = "", host: str = "", path: str = "",
        method: str = "", headers: str = "", body: str = "") -> str:
    """记一次回连，按 token 反查任务。返回 task_id（没查到返回空串）。"""
    task_id = ""
    try:
        # 写必须过写锁：回连来自多个监听协程，直连 store.conn() 会绕开 db 的统一写序列化。
        with store._write_lock:
            c = store.conn()
            row = c.execute(
                "SELECT task_id FROM listener_hits WHERE token=? AND proto='alloc' LIMIT 1",
                (token,),
            ).fetchone()
            if row and row["task_id"]:
                task_id = row["task_id"]
            c.execute(
                "INSERT INTO listener_hits (token, task_id, proto, source_ip, host, path, method,"
                " headers, body, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (token, task_id, proto, source_ip, host, path, method,
                 (headers or "")[:8000], (body or "")[:8000], time.time()),
            )
            c.commit()
    except Exception:
        pass
    return task_id


def hits(task_id: str = "", token: str = "", limit: int = 200) -> list[dict]:
    """查命中，不含 alloc 占位行。"""
    sql = ("SELECT * FROM listener_hits WHERE proto<>'alloc'")
    args: list[Any] = []
    if task_id:
        sql += " AND task_id=?"
        args.append(task_id)
    if token:
        sql += " AND token=?"
        args.append(token)
    if not task_id and not token:
        sql += " AND created_at>?"
        args.append(time.time() - 86400)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit or 200), 2000)))
    try:
        rows = store.conn().execute(sql, args).fetchall()
    except Exception:
        return []
    out = []
    for r in rows:
        d = dict(r)
        d["created"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.get("created_at") or 0))
        out.append(d)
    return out


def tokens_of(task_id: str) -> list[str]:
    try:
        rows = store.conn().execute(
            "SELECT token FROM listener_hits WHERE task_id=? AND proto='alloc'", (task_id,)
        ).fetchall()
        return [r["token"] for r in rows]
    except Exception:
        return []


def status() -> dict:
    """给前端和 /api/status 用：说清哪一段是开的、监听在哪个地址。"""
    dom, ip = base_domain(), exit_ip()
    return {
        "enabled": enabled(),
        "dns": {"on": bool(enabled() and dom and dns_message), "domain": dom,
                "bind": f"{bind_addr()}:{dns_port()}"},
        "http": {"on": bool(enabled() and ip), "url": f"http://{ip}:{http_port()}" if ip else "",
                 "bind": f"{bind_addr()}:{http_port()}"},
        "note": "" if (dom or ip) else "未配置 listener.domain / exit_ip，只能等系统自动探测出口 IP",
    }


# ─────────────── DNS 权威应答 ───────────────
def dns_answer(data: bytes) -> bytes:
    """收到一个 DNS 报文 → 记下 question → 回 A 记录。解析失败就回 FORMERR。"""
    if dns_message is None:
        return data
    try:
        req = dns_message.from_wire(data)
    except Exception:
        return data
    resp = dns_message.make_response(req)
    resp.flags |= dns_message.QR
    if req.edns >= 0:
        resp.use_edns(0, 0, 1232)
    dom_base = base_domain()
    for q in req.question:
        qname = str(q.name).rstrip(".").lower()
        labels = qname.split(".")
        token = labels[0] if len(labels) > 1 else ""
        if token and (not dom_base or qname.endswith("." + dom_base.lower()) or qname == dom_base.lower()):
            hit(token, "dns", host=qname)
        if q.rdtype in (1, 255) and dns_rrset is not None:
            try:
                resp.answer.append(
                    dns_rrset.from_text(q.name, 60, "IN", "A", "127.0.0.1")
                )
            except Exception:
                pass
    resp.set_rcode(dns_rcode.NOERROR if dns_rcode is not None else 0)
    return resp.to_wire()


# ─────────────── 后台监听 ───────────────
class DnsListener(asyncio.DatagramProtocol):
    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            self.transport.sendto(dns_answer(data), addr)
        except Exception:
            pass


async def start() -> dict:
    """启动 UDP/TCP 53 与 HTTP 回调端口。端口被占、无权限绑 53 都不抛，只记进返回值。"""
    started = {"dns": "", "http": "", "errors": []}
    if not enabled():
        started["errors"].append("listener.enabled=false")
        return started

    if base_domain() and dns_message is not None:
        port = dns_port()
        try:
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(DnsListener, local_addr=(bind_addr(), port))
            started["dns"] = f"udp/{port}"
        except Exception as e:
            started["errors"].append(f"dns udp/{port}: {e}")
        try:
            srv = await asyncio.start_server(_tcp_dns, bind_addr(), port)
            started["dns"] = (started["dns"] + f"+tcp/{port}").lstrip("+")
            _keep.append(srv)
        except Exception as e:
            started["errors"].append(f"dns tcp/{port}: {e}")
    elif not base_domain():
        started["errors"].append("listener.domain 为空，DNS 段关闭")

    if exit_ip():
        try:
            srv = await asyncio.start_server(_http_stub, bind_addr(), http_port())
            started["http"] = f":{http_port()}"
            _keep.append(srv)
        except Exception as e:
            started["errors"].append(f"http :{http_port()}: {e}")
    else:
        started["errors"].append("拿不到公网出口 IP，HTTP 段关闭")

    return started


_keep: list[Any] = []


async def _tcp_dns(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """TCP 53：报文带 2 字节长度前缀。"""
    try:
        head = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        size = int.from_bytes(head, "big")
        data = await asyncio.wait_for(reader.readexactly(size), timeout=5)
        out = dns_answer(data)
        writer.write(len(out).to_bytes(2, "big") + out)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _http_stub(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """HTTP 兜底端口：只记录来回的请求行与头部，回一句 200。健康检查/浏览器误访问噪音也在此落库，
    方便确认端口通不通；真正业务回连走 FastAPI 的 /l/{token}。"""
    try:
        raw = await asyncio.wait_for(reader.read(16384), timeout=5)
        text = raw.decode("utf-8", "replace")
        lines = text.split("\r\n")
        first = lines[0] if lines else ""
        parts = first.split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        token = ""
        seg = path.strip("/").split("/")[0].split("?")[0]
        if len(seg) >= 8 and all(ch in "0123456789abcdef" for ch in seg.lower()):
            token = seg
        peer = writer.get_extra_info("peername") or ("", 0)
        if token:
            hit(token, "http", source_ip=str(peer[0]), host=str(peer[0]), path=path,
                method=parts[0] if parts else "", headers=text[:8000])
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n"
                     b"Connection: close\r\n\r\nok")
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
