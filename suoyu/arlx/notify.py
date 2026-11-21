"""通知模块：Webhook / 钉钉 / 飞书 / 企业微信。

任务完成或发现高价值资产时推送一条摘要；任一通道失败不影响主流程。
"""

from __future__ import annotations

import json
import time

import httpx

from .config import config


def _summary(task: dict, stats: dict) -> str:
    st = stats or {}
    kinds = "、".join(f"{k} {v}" for k, v in sorted(st.items()) if isinstance(v, int) and v)
    return (
        f"### ARL-X 任务完成\n"
        f"- 任务：{task.get('name') or task.get('id')}\n"
        f"- 目标：{task.get('target')}\n"
        f"- 资产：{kinds or '无'}\n"
        f"- 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"- 地址：{config.get('server', 'public_url') or 'http://127.0.0.1:5113'}/#task/{task.get('id')}"
    )


async def _post(url: str, payload: dict, timeout: float = 10) -> bool:
    try:
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as c:
            r = await c.post(url, json=payload)
            return r.status_code < 400
    except Exception:
        return False


async def notify_task_done(task_id: str, task: dict, stats: dict) -> None:
    if not config.get("notification", "on_task_done", default=True):
        return
    text = _summary(task, stats)
    n = config.section("notification")
    tasks = []
    if n.get("webhook"):
        tasks.append(_post(n["webhook"], {"text": text, "task_id": task_id, "stats": stats}))
    if n.get("dingtalk"):
        tasks.append(_post(n["dingtalk"], {"msgtype": "markdown",
                                           "markdown": {"title": "ARL-X 完成", "text": text}}))
    if n.get("feishu"):
        tasks.append(_post(n["feishu"], {"msg_type": "interactive",
                                         "card": {"elements": [{"tag": "markdown", "content": text}]}}))
    if n.get("wecom"):
        tasks.append(_post(n["wecom"], {"msgtype": "markdown", "markdown": {"content": text}}))
    if tasks:
        await __import__("asyncio").gather(*tasks, return_exceptions=True)


async def notify_alert(title: str, body: str) -> None:
    """高价值资产提醒（公开存储桶 / Git 泄露 / 密钥命中）"""
    text = f"### ARL-X 告警\n- {title}\n{body[:1500]}"
    n = config.section("notification")
    sends = []
    if n.get("webhook"):
        sends.append(_post(n["webhook"], {"text": text}))
    if n.get("dingtalk"):
        sends.append(_post(n["dingtalk"], {"msgtype": "markdown",
                                           "markdown": {"title": title, "text": text}}))
    if n.get("feishu"):
        sends.append(_post(n["feishu"], {"msg_type": "interactive",
                                         "card": {"elements": [{"tag": "markdown", "content": text}]}}))
    if n.get("wecom"):
        sends.append(_post(n["wecom"], {"msgtype": "markdown", "markdown": {"content": text}}))
    if sends:
        await __import__("asyncio").gather(*sends, return_exceptions=True)


def _send_sync(text: str) -> None:
    """从非事件循环上下文（流水线阶段内）同步推送一次"""
    import asyncio

    n = config.section("notification")
    jobs = []
    if n.get("webhook"):
        jobs.append(("webhook", n["webhook"], {"text": text}))
    if n.get("dingtalk"):
        jobs.append(("dingtalk", n["dingtalk"],
                     {"msgtype": "markdown", "markdown": {"title": "ARL-X 新资产", "text": text}}))
    if n.get("feishu"):
        jobs.append(("feishu", n["feishu"], {"msg_type": "interactive",
                                             "card": {"elements": [{"tag": "markdown", "content": text}]}}))
    if n.get("wecom"):
        jobs.append(("wecom", n["wecom"], {"msgtype": "markdown", "markdown": {"content": text}}))
    if not jobs:
        return

    async def run() -> None:
        await asyncio.gather(*[_post(url, payload) for _, url, payload in jobs], return_exceptions=True)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(run())
    else:
        loop.create_task(run())


def notify_new_assets(root: str, items: list[str], task_id: str = "") -> None:
    """本轮相对上一轮新增资产：按 notification.on_new_asset 开关推送"""
    if not items or not config.get("notification", "on_new_asset", default=True):
        return
    lines = "\n".join(f"- {u}" for u in items[:40])
    more = f"\n- …共 {len(items)} 条" if len(items) > 40 else ""
    _send_sync(f"### ARL-X 新资产\n- 根域：{root}\n- 任务：{task_id}\n{lines}{more}")


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)
