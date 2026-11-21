"""来源登录态池：一个来源配多份 Cookie / Token，被风控就自动换下一份。

配置写法（``sources.<源>`` 下，三种都认）：

    cookie: "<主 Cookie>"          # 老写法，永远是池子里的第一份
    cookie_pool:                   # 备用，列表顺序就是切换顺序
      - "<备用 Cookie>"
      - cookie: "<备用 Cookie>"    # 天眼查这种还要成套 token / tycid 的写成字典
        token: "<auth_token>"
        tycid: "<TYCID>"

池子状态只放内存：哪一份被封、冷却到什么时候。进程重启就从第一份重新试，
所以手工换了新 Cookie 之后不用等旧冷却。
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

from ..config import config

#: 默认轮换字段；工商几家都是 Cookie，天眼查另有 token / tycid 作为同一条目的附加项
FIELD = "cookie"

_LOCK = threading.RLock()
_POOLS: dict[str, dict] = {}

#: 风控 / 登录态失效的冷却梯度（秒）：被封短一点，登录态过期要人工换，长一点
_COOL_BLOCKED = (60, 1800)
_COOL_INVALID = (300, 7200)


def _build_slots(sec: dict, field: str) -> list[dict]:
    """把「主值 + 池子」摊平成条目；同一份值只留一条，免得白白多打一轮。"""
    raw: list = []
    main = str(sec.get(field) or "").strip()
    if main:
        raw.append(main)
    pool = sec.get(f"{field}_pool") or sec.get("pool") or []
    if isinstance(pool, str):
        pool = [part for part in pool.splitlines()]
    if isinstance(pool, dict):
        pool = [pool]
    for item in pool if isinstance(pool, list) else []:
        if isinstance(item, dict):
            cred = str(item.get(field) or item.get("value") or "").strip()
            extra = {k: v for k, v in item.items() if k not in (field, "value") and v}
            if cred:
                raw.append((cred, extra))
        else:
            cred = str(item or "").strip()
            if cred:
                raw.append(cred)
    slots: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        cred, extra = (item, {}) if isinstance(item, str) else item
        if not cred or cred in seen:
            continue
        seen.add(cred)
        slots.append({"cred": cred, "extra": dict(extra or {}),
                      "fails": 0, "cool": 0.0, "last": ""})
    return slots


def _reflect_extra(slots: list[dict], sec: dict) -> None:
    """池子条目没写 token / tycid 时，用主行里的值补齐（天眼查两个头要成套送）。"""
    for field in ("token", "tycid"):
        val = str(sec.get(field) or "").strip()
        if not val:
            continue
        for slot in slots:
            slot["extra"].setdefault(field, val)


def _pool(source: str, field: str = FIELD) -> dict:
    """取（必要时重建）某个来源的池子；配置一改签名就变，不用重启。"""
    sec = config.get("sources", source) or {}
    slots = _build_slots(sec, field)
    _reflect_extra(slots, sec)
    sig = hashlib.sha1(json.dumps([[s["cred"], s["extra"]] for s in slots],
                                  sort_keys=True).encode("utf-8")).hexdigest()
    with _LOCK:
        cur = _POOLS.get(source)
        if cur and cur["sig"] == sig:
            return cur
        # 配置变了就整池重建：手工换 Cookie 后旧冷却不该继续拦着
        cur = {"sig": sig, "slots": slots, "idx": 0}
        _POOLS[source] = cur
        return cur


def count(source: str, field: str = FIELD) -> int:
    return len(_pool(source, field)["slots"])


def pick(source: str, field: str = FIELD) -> dict:
    """当前该用的一份：``{"cred": "...", "extra": {...}, "idx": n, "total": n}``。

    全部在冷却里就挑最早解封的那份继续打——宁可带着已知冷却的那份试一次，
    也不让整家来源在这一轮变成「没有登录态」。
    """
    pool = _pool(source, field)
    slots = pool["slots"]
    if not slots:
        return {"cred": "", "extra": {}, "idx": -1, "total": 0}
    now = time.monotonic()
    n = len(slots)
    for step in range(n):
        i = (pool["idx"] + step) % n
        if slots[i]["cool"] <= now:
            pool["idx"] = i
            return {"cred": slots[i]["cred"], "extra": dict(slots[i]["extra"]),
                    "idx": i, "total": n}
    i = min(range(n), key=lambda k: slots[k]["cool"])
    pool["idx"] = i
    return {"cred": slots[i]["cred"], "extra": dict(slots[i]["extra"]), "idx": i, "total": n}


def value(source: str, field: str = FIELD) -> str:
    return pick(source, field)["cred"]


def report(source: str, cred: str, verdict: str, field: str = FIELD) -> None:
    """记一次使用结果：``ok`` / ``blocked``（风控、429）/ ``invalid``（401、登录态过期）。

    被封的条目进冷却，并把指针挪到下一份，下一次 ``pick`` 就换人。
    """
    pool = _pool(source, field)
    slots = pool["slots"]
    now = time.monotonic()
    for i, slot in enumerate(slots):
        if slot["cred"] != cred:
            continue
        slot["last"] = verdict
        if verdict == "ok":
            slot["fails"] = 0
            slot["cool"] = 0.0
            return
        slot["fails"] += 1
        lo, hi = _COOL_BLOCKED if verdict == "blocked" else _COOL_INVALID
        slot["cool"] = now + min(lo * (2 ** (slot["fails"] - 1)), hi)
        if len(slots) > 1:
            pool["idx"] = (i + 1) % len(slots)
        return


def rotate(source: str, field: str = FIELD) -> dict:
    """不问原因直接换下一份（调用方已经看出被风控了）。"""
    pool = _pool(source, field)
    if len(pool["slots"]) > 1:
        pool["idx"] = (pool["idx"] + 1) % len(pool["slots"])
    return pick(source, field)


def state() -> list[dict]:
    """池子现状，给设置页 / 自检页看：每份登录态的尾号、冷却、失败次数。"""
    out: list[dict] = []
    now = time.monotonic()
    for source in sorted((config.get("sources") or {}).keys()):
        pool = _pool(source)
        slots = pool["slots"]
        if not slots:
            continue
        out.append({
            "source": source,
            "total": len(slots),
            "active": pool["idx"],
            "slots": [{
                "idx": i,
                "tail": (s["cred"][-6:] if len(s["cred"]) > 6 else s["cred"]),
                "fails": s["fails"],
                "cooling": max(0, int(round(s["cool"] - now))),
                "last": s["last"],
            } for i, s in enumerate(slots)],
        })
    return out
