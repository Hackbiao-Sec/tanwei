"""来源站点节流闸门。

工商画像、备案、测绘这类站点都有频率风控：连着打几十枪就会回「系统异常」
或者直接 429。这里把同一来源的请求排成一队 —— 相邻两枪之间随机歇一会，
同来源并发压到 1；连续命中风控就指数退避并熔断冷却，冷却期内直接拒发。
上层拿 ``acquire`` 的布尔值就能把「被限流」和「真没数据」分开记。
"""

from __future__ import annotations

import asyncio
import random
import threading
import time

from ..config import config

# 回包里出现这些词，基本就是被站点风控拦了，不是业务返回
_RISK_WORDS = (
    "系统异常", "访问过于频繁", "请求过于频繁", "操作过于频繁", "访问频率",
    "安全验证", "验证码", "人机验证", "异常访问", "稍后再试", "请求受限",
    "too many requests", "rate limit", "forbidden",
)

_MSG_KEYS = ("msg", "message", "error", "errmsg", "errMsg", "reason", "desc", "info")


def risk_hit(payload) -> str:
    """从回包里认风控信号：只看状态与消息字段，不去猜业务正文。"""
    if not isinstance(payload, dict):
        return ""
    text = " ".join(str(payload.get(k) or "") for k in _MSG_KEYS).strip()
    low = text.lower()
    for word in _RISK_WORDS:
        if word in text or word.lower() in low:
            return word
    status = payload.get("status", payload.get("code"))
    data = payload.get("data", payload.get("result"))
    if data in (None, {}, [], "") and status not in (None, 0, "0", 200, "200", True):
        return "异常状态且无数据"
    return ""


class Throttle:
    """按来源名排队的节流器；参数全部来自 ``config.yaml`` 的 ``throttle`` 段。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last: dict[str, float] = {}
        self._risk: dict[str, int] = {}
        self._cooldown_until: dict[str, float] = {}
        self._cool_level: dict[str, int] = {}
        self._stat: dict[str, dict] = {}
        self._sem: dict[tuple, asyncio.Semaphore] = {}

    # ───────── 参数 ─────────
    def _cfg(self, name: str) -> dict:
        sec = config.section("throttle") or {}
        per = (sec.get("per_source") or {}).get(name) or {}
        lo = float(per.get("min_interval", sec.get("min_interval", 1.5)) or 0)
        hi = float(per.get("max_interval", sec.get("max_interval", 4.0)) or 0)
        if hi < lo:
            hi = lo
        return {
            "enabled": bool(sec.get("enabled", True)),
            "lo": max(0.0, lo),
            "hi": max(0.0, hi),
            "concurrent": max(1, int(sec.get("concurrent", 1) or 1)),
            "threshold": max(1, int(sec.get("risk_threshold", 3) or 3)),
            "cooldown": max(1.0, float(sec.get("cooldown", 60) or 60)),
            "cooldown_max": max(1.0, float(sec.get("cooldown_max", 900) or 900)),
        }

    def _stat_of(self, name: str) -> dict:
        st = self._stat.get(name)
        if st is None:
            st = self._stat[name] = {"ok": 0, "risk": 0, "cooldowns": 0,
                                     "last_why": "", "last_cooldown": 0.0}
        return st

    # ───────── 冷却 ─────────
    def cooling(self, name: str) -> float:
        """该来源还要冷却多少秒；0 表示可以打。"""
        with self._lock:
            left = self._cooldown_until.get(name, 0.0) - time.monotonic()
        return round(left, 1) if left > 0 else 0.0

    # ───────── 取许可 ─────────
    async def acquire(self, name: str) -> bool:
        """领一枪的许可。返回 False 表示该来源正在冷却，这一枪别打。"""
        cfg = self._cfg(name)
        if not cfg["enabled"]:
            return True
        if self.cooling(name):
            return False
        loop = asyncio.get_running_loop()
        key = (id(loop), name)
        sem = self._sem.get(key)
        if sem is None:
            sem = self._sem[key] = asyncio.Semaphore(cfg["concurrent"])
        async with sem:
            if self.cooling(name):
                return False
            with self._lock:
                gap = random.uniform(cfg["lo"], cfg["hi"])
                # 已经吃过风控就自动拉长间隔，不必等到熔断
                gap *= 1 + min(4, self._risk.get(name, 0))
                now = time.monotonic()
                last = self._last.get(name) or 0.0
                wait = last + gap - now
                self._last[name] = now + max(0.0, wait)
            if wait > 0:
                await asyncio.sleep(wait)
            return not self.cooling(name)

    # ───────── 记账 ─────────
    def reward(self, name: str) -> None:
        with self._lock:
            self._risk[name] = 0
            self._cool_level.pop(name, None)
            self._stat_of(name)["ok"] += 1

    def penalize(self, name: str, why: str = "") -> float:
        """记一次风控。返回这次触发的冷却秒数（0 表示还没到熔断）。"""
        cfg = self._cfg(name)
        with self._lock:
            n = self._risk.get(name, 0) + 1
            self._risk[name] = n
            st = self._stat_of(name)
            st["risk"] += 1
            st["last_why"] = (why or "")[:80]
            if n < cfg["threshold"]:
                return 0.0
            level = self._cool_level.get(name, 0) + 1
            self._cool_level[name] = level
            cool = min(cfg["cooldown_max"], cfg["cooldown"] * (2 ** (level - 1)))
            self._cooldown_until[name] = time.monotonic() + cool
            self._risk[name] = 0
            st["cooldowns"] += 1
            st["last_cooldown"] = round(cool, 1)
        return round(cool, 1)

    # ───────── 观测 ─────────
    def snapshot(self) -> dict:
        with self._lock:
            out = {}
            for name, st in self._stat.items():
                out[name] = {**st, "cooling": self.cooling(name),
                             "risk_streak": self._risk.get(name, 0)}
            return out

    def reset(self) -> None:
        with self._lock:
            self._last.clear()
            self._risk.clear()
            self._cooldown_until.clear()
            self._cool_level.clear()
            self._stat.clear()
            self._sem.clear()


throttle = Throttle()
