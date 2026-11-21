"""nmap service-probes 解析 + TCP 服务识别引擎。

要覆盖「端口 → 服务名 + 版本 + 厂商/系统/CPE」的全量识别，靠 nmap 探针库这份公开数据
最省事。本项目原来只有 27 条手写 TCP 探针（`probe.py` 的 `TCP_PROBES`），只能认出
Redis/SSH/SMB 这类常见服务，冷门端口上的 ActiveMQ、AJP 等中间件全漏。本模块把 nmap
那份探针接进来补这个缺口。

与 `probe.py` 的分工：
- `probe.py`：认出来就是「未授权面」的探针（Redis 免密、Dubbo telnet…），命中即报洞。
- `svcmap.py`（本文件）：只做服务识别与版本带回，命中不等于洞，用来补资产标签、
  给后续阶段挑 POC。

数据来源：`dicts/nmap-service-probes`（nmap 官方探针库，随包分发；缺文件时引擎降级
为空表，不影响主流程）。
"""
from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable

from ...utils import run_blocking

DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "dicts", "nmap-service-probes")

# nmap 的探针语法与 Python re 有几处不兼容，转换表见 _to_py_regex。
_FIELD_DELIMS = "|/={*[#<"


@dataclass(frozen=True)
class Probe:
    name: str
    proto: str          # tcp / udp
    payload: bytes
    rarity: int = 1
    ssl: bool = False
    ports: tuple[str, ...] = ()      # 形如 "80,443,8000-8100"
    sslports: tuple[str, ...] = ()
    no_payload: bool = False
    matches: tuple["Match", ...] = field(default=(), compare=False)


@dataclass(frozen=True)
class Match:
    service: str
    pattern: re.Pattern[str]
    soft: bool
    # 字段：p=产品名 v=版本 i=补充信息 o=操作系统 h=主机名 d=设备类型 cpe=CPE
    fields: tuple[tuple[str, str], ...] = ()


def _unescape_nmap(s: str) -> bytes:
    r"""nmap 字符串转义 → 原始字节。

    nmap 只认 \xHH、八进制 \0-\9、\r \n \t 与 \\；其余反斜杠按字面保留，
    交给正则转换处理，避免元字符被提前吃掉。
    """
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch != "\\" or i + 1 >= n:
            out.extend(ch.encode("utf-8", "surrogateescape"))
            i += 1
            continue
        nxt = s[i + 1]
        if nxt == "x" and i + 3 < n:
            try:
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        if nxt.isdigit():
            out.append(int(nxt, 8) & 0xFF)
            i += 2
            continue
        mapped = {"r": b"\r", "n": b"\n", "t": b"\t", "\\": b"\\"}
        if nxt in mapped:
            out.extend(mapped[nxt])
            i += 2
            continue
        # \p \q \g 之类是 nmap 自己处理正则时的转义，原样留给 _to_py_regex
        out.extend(("\\" + nxt).encode("utf-8", "surrogateescape"))
        i += 2
    return bytes(out)


# nmap 正则里的专有写法 → Python re
_NMAP_REGEX_FIX = (
    (re.compile(r"\\p"), r"."),          # 任意可打印字符
    (re.compile(r"\\q"), r"\""),          # 双引号
    (re.compile(r"\\I"), r"\\b"),         # 词首
    (re.compile(r"\\g"), r"\\w"),         # 字母数字（近似）
)


def _to_py_regex(pat: bytes) -> re.Pattern[str] | None:
    try:
        text = pat.decode("latin-1")
    except Exception:
        return None
    for rx, rep in _NMAP_REGEX_FIX:
        text = rx.sub(rep, text)
    try:
        # 二进制回包按 latin-1 解码，保证字节一一对应
        return re.compile(text, re.S)
    except re.error:
        return None


def _split_fields(rest: str) -> list[tuple[str, str]]:
    """拆 `p/…/ v/…/ cpe:/…`，分隔符可以是 / | = 等任意字符。"""
    out: list[tuple[str, str]] = []
    i, n = 0, len(rest)
    while i < n:
        while i < n and rest[i] in " \t":
            i += 1
        if i >= n:
            break
        # m 后面的 i/s 是正则标志位，不是字段
        if rest[i] in "is" and (i + 1 >= n or rest[i + 1] in " \t"):
            i += 1
            continue
        # 字段名
        j = i
        while j < n and (rest[j].isalnum() or rest[j] == "-"):
            j += 1
        name = rest[i:j]
        if not name:
            i += 1
            continue
        while j < n and rest[j] == ":":
            j += 1        # cpe:/… 里的冒号
        if j >= n or rest[j] not in _FIELD_DELIMS:
            # 认不出的字段，跳过一个词
            while j < n and rest[j] not in " \t":
                j += 1
            i = j
            continue
        delim = rest[j]
        j += 1
        buf = []
        while j < n:
            c = rest[j]
            if c == "\\" and j + 1 < n:
                buf.append(rest[j:j + 2])
                j += 2
                continue
            if c == delim:
                break
            buf.append(c)
            j += 1
        out.append((name, "".join(buf)))
        i = j + 1
    return out


_MATCH_RE = re.compile(r"^(soft)?match\s+(\S+)\s+m")
# Probe <协议> <名字> [q<分隔符>载荷<分隔符>] [ssl] [no-payload]
_PROBE_RE = re.compile(r"^Probe\s+(\w+)\s+(\S+)\s*(?:q([|/=*{#<])(.*?)\3)?\s*(ssl|no-payload)?\s*$")


def _parse_match(service: str, line: str, soft: bool) -> Match | None:
    m = _MATCH_RE.match(line)
    if not m:
        return None
    pos = m.end()
    delim = line[pos]
    pos += 1
    buf = []
    n = len(line)
    while pos < n:
        c = line[pos]
        if c == "\\" and pos + 1 < n:
            # 转义按原样保留；只在分隔符本身被转义时去掉反斜杠
            if line[pos + 1] == delim:
                buf.append(delim)
            else:
                buf.append(line[pos:pos + 2])
            pos += 2
            continue
        if c == delim:
            break
        buf.append(c)
        pos += 1
    pattern = _to_py_regex(_unescape_nmap("".join(buf)))
    if pattern is None:
        return None
    rest = line[pos + 1:]
    fields = tuple(_split_fields(rest))
    return Match(service=service, pattern=pattern, soft=soft, fields=fields)


def parse_probes(path: str = DATA_FILE) -> tuple[list[Probe], dict[str, list[Match]], dict[str, list[Match]]]:
    """解析 nmap-service-probes。

    返回 (探针列表, 按 probe 名索引的 match, 按端口索引的 match)。
    端口索引用于「只发一条最省事的探针」的快速路径。
    """
    if not os.path.isfile(path):
        return [], {}, {}
    probes: list[Probe] = []
    by_probe: dict[str, list[Match]] = {}
    cur: dict | None = None
    cur_matches: list[Match] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            if line.startswith("Probe "):
                if cur is not None:
                    probes.append(Probe(**cur, matches=tuple(cur_matches)))
                    by_probe.setdefault(cur["name"], []).extend(cur_matches)
                pm = _PROBE_RE.match(line)
                if not pm:
                    cur, cur_matches = None, []
                    continue
                proto, name = pm.group(1).lower(), pm.group(2)
                payload = _unescape_nmap(pm.group(4) or "")
                tail = (pm.group(5) or "").lower()
                cur = {"name": name, "proto": proto, "payload": payload,
                       "ssl": tail == "ssl", "no_payload": tail == "no-payload"}
                cur_matches = []
                continue
            if cur is None:
                continue
            if line.startswith("match ") or line.startswith("softmatch "):
                soft = line.startswith("softmatch ")
                body = line.split(None, 1)[1]
                svc = body.split(None, 1)[0]
                mm = _parse_match(svc, line, soft)
                if mm is not None:
                    cur_matches.append(mm)
                continue
            key, _, val = line.partition(" ")
            val = val.strip()
            if key == "rarity":
                try:
                    cur["rarity"] = int(val)
                except ValueError:
                    pass
            elif key == "ports":
                cur["ports"] = tuple(x for x in val.split(",") if x)
            elif key == "sslports":
                cur["sslports"] = tuple(x for x in val.split(",") if x)
            elif key == "nopayload":
                cur["no_payload"] = True
    if cur is not None:
        probes.append(Probe(**cur, matches=tuple(cur_matches)))
        by_probe.setdefault(cur["name"], []).extend(cur_matches)
    return probes, by_probe, {}


@lru_cache(maxsize=1)
def engine() -> "ServiceEngine":
    return ServiceEngine()


class ServiceEngine:
    """按端口挑探针 → 发包 → 用 match 规则认服务。

    挑探针的策略与 nmap 一致但更省：先找显式写了该端口的探针，找不到就发 NULL
    探针（等 banner），再退到 rarity 最低的通用探针。单个端口最多发 2 条，避免
    在扫描阶段把耗时翻几倍。
    """

    def __init__(self, path: str = DATA_FILE) -> None:
        self.probes, self.by_probe, _ = parse_probes(path)
        self.by_name = {p.name: p for p in self.probes}
        self._port_probes: dict[int, list[Probe]] = {}
        for p in self.probes:
            for spec in p.ports:
                for port in _expand_ports(spec):
                    self._port_probes.setdefault(port, []).append(p)
        self.null_probe = self.by_name.get("NULL")

    @property
    def ok(self) -> bool:
        return bool(self.probes)

    def probes_for_port(self, port: int) -> list[Probe]:
        picked = list(self._port_probes.get(port, ()))
        if self.null_probe is not None and self.null_probe not in picked:
            picked.append(self.null_probe)
        if not picked:
            picked = self.probes[:1]
        return picked[:2]

    def match(self, probe: Probe, data: bytes) -> dict | None:
        if not data:
            return None
        text = data.decode("latin-1", "ignore")
        best_hard: dict | None = None
        soft: dict | None = None
        for m in probe.matches:
            mo = m.pattern.search(text)
            if not mo:
                continue
            rec = _build_hit(m, mo)
            if m.soft:
                if soft is None or _richness(rec) > _richness(soft):
                    soft = rec
                continue
            # 同一条正则常被多条 match 共用（一条只写服务名，一条带版本/CPE），
            # 取字段最全的那条，避免只拿到半截识别结果。
            if best_hard is None or _richness(rec) > _richness(best_hard):
                best_hard = rec
        if best_hard and best_hard.get("version"):
            return best_hard
        return best_hard or soft


def _richness(rec: dict) -> int:
    """字段越具体越好：带版本/CPE 的优先，其次产品名长的（通用 HTTP 正则常被一堆规则共用）。

    版本号权重最高：同一份回包能同时命中 Apache 和几条「只认 200 OK 外形」的通用规则，
    带版本的那条才是真答案。
    """
    score = 0
    if rec.get("version"):
        score += 1000
    for k in ("cpe", "os", "host", "device", "info"):
        if rec.get(k):
            score += 10
    return score + min(len(rec.get("product") or ""), 60)


def _build_hit(m: Match, mo: re.Match[str]) -> dict:
    info: dict[str, str] = {}
    for name, val in m.fields:
        # $1 $2 … 用捕获组回填
        filled = re.sub(r"\$(\d)", lambda x: (mo.group(int(x.group(1))) or ""), val)
        if name == "cpe":
            info.setdefault("cpe", filled)
        elif name.startswith("cpe"):
            info.setdefault("cpe", filled)
        else:
            info[name] = filled.strip()
    return {
        "service": m.service,
        "soft": m.soft,
        "product": info.get("p", ""),
        "version": info.get("v", ""),
        "info": info.get("i", ""),
        "os": info.get("o", ""),
        "host": info.get("h", ""),
        "device": info.get("d", ""),
        "cpe": info.get("cpe", ""),
    }


def _expand_ports(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return out


async def _tcp_exchange(host: str, port: int, payload: bytes, timeout: float = 4.0) -> bytes:
    def work() -> bytes:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            try:
                if payload:
                    s.sendall(payload)
                chunks = []
                got = 0
                while got < 4096:
                    b = s.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
                    got += len(b)
                return b"".join(chunks)
            finally:
                s.close()
        except Exception:
            return b""

    return await run_blocking(work, timeout=timeout + 2)


async def identify(host: str, port: int, *, timeout: float = 4.0) -> list[dict]:
    """对一个端口认服务，返回命中列表（可能多条：探针多种解释）。"""
    eng = engine()
    if not eng.ok:
        return []
    hits: list[dict] = []
    for probe in eng.probes_for_port(port):
        data = await _tcp_exchange(host, port, probe.payload, timeout=timeout)
        rec = eng.match(probe, data)
        if rec:
            rec["port"] = port
            rec["probe"] = probe.name
            rec["target"] = f"{host}:{port}"
            hits.append(rec)
            if not rec.get("soft"):
                break
    return hits


async def identify_many(host: str, ports: Iterable[int], *, concurrency: int = 12,
                        timeout: float = 4.0) -> list[dict]:
    import asyncio

    ports = [int(p) for p in ports if p]
    if not host or not ports:
        return []
    sem = asyncio.Semaphore(concurrency)
    out: list[dict] = []

    async def one(p: int) -> None:
        async with sem:
            try:
                out.extend(await asyncio.wait_for(identify(host, p, timeout=timeout), timeout=timeout * 3))
            except Exception:
                pass

    await asyncio.gather(*(one(p) for p in ports))
    return out


def service_names(port: int) -> tuple[str, ...]:
    """该端口常见服务名，用来给资产打标时做提示。"""
    eng = engine()
    names: list[str] = []
    for probe in eng.probes_for_port(port):
        for m in probe.matches:
            if m.service not in names:
                names.append(m.service)
    return tuple(names[:8])
