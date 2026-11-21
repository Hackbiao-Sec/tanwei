"""ARL-X Web 服务（FastAPI，替代 ARL 的 Flask + Celery + RabbitMQ）。

一个进程跑完：Web、任务调度、扫描引擎、SQLite 存储、SSE 实时日志。
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import DATA_DIR, ROOT, config, src_base
from .db import RISK_RULES, SURFACE_LABEL, audit, store
from .db import with_liveness, live_state
from .engine import ai as ai_engine
from .engine import beauty
from .engine import dedupe
from .engine import handshake
from .engine import listener
from .engine import modules as modules_mod
from .engine import ops as ops_mod
from .engine import pipeline
from .engine import space as space_mod
from .engine import source_health
from .engine.collectors import enterprise, equity, mobile
from .engine.collectors import applet as applet_mod
from .engine.http_engine import fetch_text
from .engine.portscan import PORT_PRESETS, parse_ports, ports_for_type
from .engine.sources.passive import DOMAIN_SOURCES, FREE_SOURCES, fofa_search, source_meta
from .engine.throttle import throttle
from .utils import FingerPrint, is_ip, is_valid_domain, root_domain

APP_TITLE = "ARL-X · 资产侦察灯塔（增强版）"
SALT = "arlx!@#"
TOKENS: dict[str, dict] = {}
WEB_DIR = ROOT / "arlx" / "web"
BUILD_DIR = ROOT / "arlx" / "static"      # Vite 产物：index.html + assets/

class Utf8JSONResponse(JSONResponse):
    """默认响应类：中文直接输出（fastapi 默认的 JSON 响应会把中文转义成 ASCII）"""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":"), default=str).encode("utf-8")


app = FastAPI(title=APP_TITLE, version="2.8.0", default_response_class=Utf8JSONResponse)
STATIC_DIR = BUILD_DIR
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")


# ─────────────── 鉴权 ───────────────
def hash_password(pwd: str) -> str:
    return hashlib.md5(f"{SALT}{pwd}".encode()).hexdigest()


def issue_token(username: str) -> str:
    token = hashlib.sha1(f"{username}{time.time()}{SALT}".encode()).hexdigest()
    TOKENS[token] = {"username": username, "ts": time.time()}
    persist_tokens()
    return token


TOKEN_FILE = DATA_DIR / "tokens.json"


def persist_tokens() -> None:
    """会话表落盘：进程重启后浏览器仍能用原 Cookie/token 继续用，不必重登。"""
    try:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        alive = {k: v for k, v in TOKENS.items() if now - v["ts"] < 7 * 86400}
        TOKEN_FILE.write_text(json.dumps(alive), encoding="utf-8")
    except Exception:
        pass


def load_tokens() -> None:
    try:
        if TOKEN_FILE.exists():
            data = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
            now = time.time()
            TOKENS.update({k: v for k, v in data.items() if now - v["ts"] < 7 * 86400})
    except Exception:
        pass


def current_user(request: Request) -> str:
    api_key = config.get("server", "api_key")
    auth = request.headers.get("Authorization") or ""
    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    token = (request.headers.get("X-Token") or request.cookies.get("arlx_token")
             or request.headers.get("Token") or bearer
             or request.query_params.get("token") or "")
    if api_key and token == api_key:
        return "api_key"
    if not config.get("server", "auth", default=True):
        return "anonymous"
    info = TOKENS.get(token)
    if info and time.time() - info["ts"] < 7 * 86400:
        return info["username"]
    raise HTTPException(status_code=401, detail="未登录或登录已过期")


@app.on_event("startup")
async def on_startup() -> None:
    store.ensure_admin("admin", hash_password("arlpass"))
    load_tokens()
    # 进程重启后内存里没有 RUNNING 实例：上次没跑完的任务不可能再继续，统一标成中断
    for t in store.list_tasks(limit=500):
        if t.get("status") in ("running", "stopping"):
            store.update_task(t["id"], status="stopped", message="服务重启，任务中断")
    asyncio.create_task(_scheduler_loop())
    try:
        st = await listener.start()
        print(f"[listener] dns={st['dns'] or '-'} http={st['http'] or '-'} "
              f"{'; '.join(st['errors'])}", flush=True)
    except Exception as e:
        print(f"[listener] 启动失败：{e}", flush=True)


# ─────────────── 登录 ───────────────
@app.post("/api/login")
async def login(body: dict = Body(...), response: Response = None) -> JSONResponse:
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    user = store.get_user(username)
    if not user or user["password"] != hash_password(password):
        audit("login_fail", username)
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = issue_token(username)
    audit("login", username)
    resp = Utf8JSONResponse({"ok": True, "token": token, "username": username})
    resp.set_cookie("arlx_token", token, httponly=True, max_age=7 * 86400, samesite="lax")
    return resp


@app.post("/api/logout")
async def logout(request: Request) -> dict:
    token = request.headers.get("X-Token") or request.cookies.get("arlx_token") or ""
    TOKENS.pop(token, None)
    return {"ok": True}


@app.get("/api/me")
async def me(request: Request) -> dict:
    return {"username": current_user(request), "version": "2.8.0"}


# ─────────────── 配置 ───────────────
@app.get("/api/config")
def get_config(request: Request) -> dict:
    current_user(request)
    return {"ok": True, "config": config.masked()}


@app.post("/api/config")
def set_config(request: Request, patch: dict = Body(...)) -> dict:
    user = current_user(request)
    masked = config.masked()
    config.persist(patch)
    config.reload()
    audit("config_update", json.dumps(list(patch.keys())), user=user)
    _ = masked
    return {"ok": True, "config": config.masked()}


@app.get("/api/creds")
def creds_state(request: Request) -> dict:
    """各来源的登录态池：配了几份、当前用第几份、哪份在冷却。

    池子只在内存里记冷却，所以这里看到的就是这一轮采集正在用的那份。
    """
    current_user(request)
    from .engine import creds as creds_mod
    return {"ok": True, "pool": creds_mod.state()}


@app.post("/api/config/test")
async def test_config(request: Request, body: dict = Body(...)) -> dict:
    """测试数据源连通性：{source: 'fofa'} 或 {proxy: true}"""
    current_user(request)
    name = (body or {}).get("source") or ""
    if name == "proxy":
        import httpx

        url = config.get("proxy", "url")
        if not url:
            return {"ok": False, "msg": "未配置代理"}
        try:
            async with httpx.AsyncClient(proxy=url, timeout=8, trust_env=False) as c:
                r = await c.get("https://www.gstatic.com/generate_204")
            return {"ok": r.status_code < 400, "msg": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"ok": False, "msg": str(e)[:200]}
    if name in ("fofa", "llm"):
        # 走中转站时也能测：FOFA 用最小查询，LLM 发一句最短对话
        if name == "llm":
            return await ai_engine.test()
        base = src_base("fofa", "https://fofa.info")
        try:
            recs = await fofa_search('domain="qq.com"', size=1)
        except Exception as e:
            # 失败也要回显实际打的根地址，用户才能确认是不是真走了中转站
            return {"ok": False, "msg": f"{base} 请求异常：{str(e)[:160]}", "base": base}
        return {"ok": bool(recs), "msg": f"{base} 返回 {len(recs)} 条" if recs
                else f"{base} 无返回（Key 或中转站地址可能有误）",
                "base": base, "sample": recs[:1]}
    if name in ("weibo", "weixin"):
        # 这两条线的凭据不进 DOMAIN_SOURCES：一个是站内 JSON，一个是页面风控，只能现场打一枪
        from .engine.collectors import mp as _mp
        from .engine.collectors import weibo as _wb

        if name == "weibo":
            ck = _wb._cookie()
            if not ck:
                return {"ok": False, "msg": "未填写 Cookie：站内搜索与档案都拿不到，只能走搜索引擎发现主页"}
            _, notes = await _wb._api_search("微博", ck, pages=1, timeout=12)
            bad = [n for n in notes if ("登录" in n or "432" in n or "非 JSON" in n)]
            if bad:
                return {"ok": False, "msg": bad[0]}
            return {"ok": True, "msg": "站内搜索已认这条 Cookie"}
        ck = _mp._wx_cookie()
        if not ck:
            return {"ok": False, "msg": "未填写 Cookie：公开文章可抓，风控页会拦"}
        import httpx

        try:
            async with httpx.AsyncClient(timeout=12, follow_redirects=True) as c:
                r = await c.get("https://mp.weixin.qq.com/", headers=_mp._wx_headers())
            text = (r.text or "")[:4000]
            if "环境异常" in text or "验证" in text:
                return {"ok": False, "msg": "被风控拦（环境异常 / 验证页），Cookie 可能失效或 IP 受限"}
            return {"ok": r.status_code < 400, "msg": f"已带这条 Cookie 请求，HTTP {r.status_code}"}
        except Exception as e:
            return {"ok": False, "msg": f"请求失败：{type(e).__name__}"[:200]}
    fn = DOMAIN_SOURCES.get(name)
    if not fn:
        from .engine.collectors.equity import probe_source

        return await probe_source(name)
    try:
        res = await fn("example.com")
        base = src_base(name, "")
        return {"ok": not res.error, "msg": res.error or f"{len(res.subdomains)} 子域",
                "count": len(res.subdomains), "base": base}
    except Exception as e:
        return {"ok": False, "msg": str(e)[:200]}


@app.get("/api/sources")
def list_sources(request: Request) -> dict:
    current_user(request)
    return {"ok": True, "items": source_meta(), "free": FREE_SOURCES}


# ─────────────── 渠道：目录 / 开关 / 自检 ───────────────
@app.get("/api/channels")
def list_channels(request: Request) -> dict:
    """渠道目录 + 启用开关 + 上次自检结果。"""
    current_user(request)
    from .engine import channels as channels_mod

    return {"ok": True, **channels_mod.overview()}


@app.post("/api/channels")
def save_channels(request: Request, body: dict = Body(...)) -> dict:
    """改开关：{off: [key…]} 整表覆盖，或 {key, enabled} 单路切换。"""
    user = current_user(request)
    from .engine import channels as channels_mod

    body = body or {}
    if "key" in body:
        key = str(body.get("key") or "").strip()
        off = channels_mod.off_list()
        if body.get("enabled", True):
            off = [k for k in off if k != key]
        elif key and key not in off:
            off.append(key)
        act = "渠道启用" if body.get("enabled", True) else "渠道停用"
        detail = key
    else:
        off = [str(k) for k in (body.get("off") or [])]
        act = "渠道开关"
        detail = json.dumps(off, ensure_ascii=False)
    saved = channels_mod.save_off(off)
    audit("channels_update", f"{act} {detail}", user=user)
    return {"ok": True, **saved, **channels_mod.overview()}


@app.post("/api/channels/test")
async def test_channels(request: Request, body: dict = Body(...)) -> dict:
    """一键自检：不传 keys 就全量测，每路真打一次最小请求。"""
    current_user(request)
    from .engine import channels as channels_mod

    body = body or {}
    rows = await channels_mod.probe_many(body.get("keys") or None, str(body.get("query") or ""))
    return {"ok": True, "count": len(rows), "items": rows,
            "usable": sum(1 for r in rows if r.get("state") in ("ok", "empty")),
            "dead": sum(1 for r in rows if r.get("state") in ("dead", "config"))}


@app.get("/api/options")
def list_options(request: Request) -> dict:
    current_user(request)
    from .engine import dicts as dicts_mod

    dicts = sorted({d["name"] for d in dicts_mod.list_dicts()})
    from .engine.portscan import PORT_PRESET_LABELS

    return {"ok": True, "ports": list(PORT_PRESETS), "dicts": dicts,
            "port_presets": [{"v": k, "label": v} for k, v in PORT_PRESET_LABELS.items()],
            "phases": [{"key": k, "label": lab} for _, k, lab in pipeline.PHASES],
            "tools": {n: enterprise.tool_available(n) for n in enterprise.TOOL_PATHS}}


# ─────────────── 字典管理 ───────────────
@app.get("/api/dicts")
def dicts_index(request: Request) -> dict:
    """字典清单：行数、来源（内置/用户覆盖）、被哪个采集步骤引用。"""
    current_user(request)
    from .engine import dicts as dicts_mod

    return {"ok": True,
            "user_dir": str(dicts_mod.USER_DIR),
            "builtin_dir": str(dicts_mod.BUILTIN_DIR),
            "items": dicts_mod.list_dicts(),
            "bindings": dicts_mod._binding_state()}


@app.get("/api/dicts/{name}")
def dicts_preview(request: Request, name: str, offset: int = Query(0),
                        limit: int = Query(2000), raw: int = Query(0)) -> dict:
    current_user(request)
    from .engine import dicts as dicts_mod

    try:
        return {"ok": True, **dicts_mod.read_dict(name, offset, limit, raw=bool(raw))}
    except FileNotFoundError:
        raise HTTPException(404, "字典不存在")


@app.post("/api/dicts")
def dicts_create(request: Request, body: dict = Body(...)) -> dict:
    """新建字典；同名内置字典会写一份用户覆盖文件，内置原文件不动。"""
    user = current_user(request)
    from .engine import dicts as dicts_mod

    name = str(body.get("name") or "").strip()
    content = body.get("content") or ""
    words = dicts_mod.clean_words(content if isinstance(content, str) else "\n".join(content))
    try:
        out = dicts_mod.write_dict(name, words, append=bool(body.get("append")))
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit("dicts.create", name, f"写入 {out['lines']} 行", user)
    return {"ok": True, **out}


@app.put("/api/dicts/{name}")
def dicts_update(request: Request, name: str, body: dict = Body(...)) -> dict:
    user = current_user(request)
    from .engine import dicts as dicts_mod

    mode = str(body.get("mode") or "replace")
    content = body.get("content") or ""
    words = dicts_mod.clean_words(content if isinstance(content, str) else "\n".join(content))
    if mode == "append" and not words:
        raise HTTPException(400, "追加内容为空")
    try:
        out = dicts_mod.write_dict(name, words, append=(mode == "append"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit("dicts.update", name, f"{mode} → {out['lines']} 行", user)
    return {"ok": True, **out}


@app.delete("/api/dicts/{name}")
def dicts_delete(request: Request, name: str) -> dict:
    user = current_user(request)
    from .engine import dicts as dicts_mod

    try:
        out = dicts_mod.delete_dict(name)
    except FileNotFoundError:
        raise HTTPException(404, "用户字典里没有这份文件（内置字典只能覆盖，不能删除）")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit("dicts.delete", name, "删除用户覆盖", user)
    return {"ok": True, **out}


@app.post("/api/dicts/{name}/bind")
def dicts_bind(request: Request, name: str, body: dict = Body(...)) -> dict:
    """把某个采集配置项指向这份字典。"""
    user = current_user(request)
    from .engine import dicts as dicts_mod

    try:
        out = dicts_mod.bind(name, str(body.get("key") or ""))
    except FileNotFoundError:
        raise HTTPException(404, "字典不存在")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit("dicts.bind", name, f"{out['key']} → {name}", user)
    return {"ok": True, **out}


# ─────────────── 任务 ───────────────
@app.post("/api/tasks")
async def create_task(request: Request, body: dict = Body(...)) -> dict:
    user = current_user(request)
    targets_raw = body.get("targets")
    if isinstance(targets_raw, str):
        targets = [t.strip() for t in targets_raw.replace("\n", ",").replace(" ", ",").split(",")
                   if t.strip()]
    else:
        targets = [str(t).strip() for t in (targets_raw or []) if str(t).strip()]
    if not targets:
        raise HTTPException(status_code=400, detail="目标为空")
    options = body.get("options") or {}
    name = body.get("name") or ""
    task_id = await pipeline.start_task(targets, options, name)
    audit("task_create", ",".join(targets), detail=json.dumps(options, ensure_ascii=False), user=user)
    return {"ok": True, "task_id": task_id}


def _decorate_tasks(items: list[dict]) -> list[dict]:
    """给任务补上真实的资产分类数与该跑的五段进度。

    `stats` 是写入次数，资产页上的条数按去重后的资产行算，两边对不上会被当成虚报；
    列表里的数一律走 ``task_assets`` 去重。
    """
    if not items:
        return items
    breakdown = store.task_breakdown([t.get("id") or "" for t in items],
                                     modules=modules_mod.module_scopes())
    for t in items:
        bk = breakdown.get(t.get("id") or "") or {}
        kinds = bk.get("kinds") or {}
        stages = bk.get("stages") or {}
        counts = {k: int(v or 0) for k, v in kinds.items() if v}
        t["counts"] = {
            "total": int(bk.get("total") or 0),
            "kinds": counts,
            "stages": {k: int(v or 0) for k, v in stages.items() if v},
            "labels": {k: modules_mod.kind_label(k) for k in counts},
            "modules": {k: int(v or 0) for k, v in (bk.get("modules") or {}).items() if v},
        }
        options = t.get("options") or {}
        # 显式 only_stages 优先，其次按一键收集勾的 steps 折算：没勾的段才算跳过，
        # 不能把「没跑」和执行完的空结果一起写成无产出。
        only = modules_mod.stages_of_options(options)
        # 只回真实阶段键：历史任务里存过认不出的键，直接回给前端会在卡片上
        # 显示一个并不存在的「已选阶段」，和实际跑过的阶段对不上。
        t["selected_stages"] = [str(s) for s in only if str(s) in modules_mod.STAGE_ORDER]
        t["partial"] = modules_mod.is_partial(only)
        phase = str(t.get("phase") or "")
        t["phase_label"] = modules_mod.stage_label(phase)
        t["phase_module"] = modules_mod.MODULE_LABEL.get(modules_mod.STAGE_MODULE.get(phase, ""), "")
        t["modules"] = modules_mod.task_modules(
            only, t.get("phase") or "", t.get("status") or "",
            t["counts"]["modules"] or modules_mod.module_asset_counts(kinds, stages))
    return items


@app.get("/api/tasks")
def list_tasks(request: Request, limit: int = 100) -> dict:
    # 同步 SQLite 聚合放线程池跑：写成 async def 会把事件循环占住，
    # 任务列表一刷新，同时在加载的任务详情就跟着卡住。
    current_user(request)
    return {"ok": True, "items": _decorate_tasks(store.list_tasks(limit))}


@app.get("/api/tasks/active")
def active_tasks(request: Request) -> dict:
    """顶栏 / 左栏角标专用：只回各状态任务数，不拉任务表和资产聚合。"""
    current_user(request)
    counts = store.task_status_counts()
    return {"ok": True, "counts": counts,
            "running": int(counts.get("running", 0)),
            "pending": int(counts.get("pending", 0))}


@app.get("/api/modules")
async def list_modules(request: Request) -> dict:
    """五段口径 + 资产类型中文名：前端三处共用，不再各自维护一份阶段表。"""
    current_user(request)
    return {"ok": True, "items": modules_mod.modules_payload(),
            "tail": modules_mod.TAIL_STAGES,
            "stage_labels": modules_mod.stage_labels_payload(),
            "kinds": [{"key": k, "label": modules_mod.kind_label(k)}
                      for k in modules_mod.KIND_ORDER]}


@app.get("/api/tasks/{task_id}")
def get_task(request: Request, task_id: str) -> dict:
    current_user(request)
    task = store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    task["running"] = task_id in pipeline.RUNNING
    _decorate_tasks([task])
    return task


@app.post("/api/tasks/{task_id}/stop")
def stop_task(request: Request, task_id: str) -> dict:
    user = current_user(request)
    ok = pipeline.stop_task(task_id)
    audit("task_stop", task_id, user=user)
    return {"ok": True, "running": ok}


@app.delete("/api/tasks/{task_id}")
async def delete_task(request: Request, task_id: str) -> dict:
    """删任务，资产留在池子里（任务列表的删除按钮走这条）。"""
    user = current_user(request)
    if not store.get_task(task_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    if task_id in pipeline.RUNNING:
        pipeline.stop_task(task_id)
        await asyncio.sleep(1.5)
    ok = store.delete_task(task_id)
    audit("task_delete", task_id, user=user)
    return {"ok": bool(ok)}


@app.post("/api/tasks/{task_id}/rerun")
async def rerun_task(request: Request, task_id: str, stage: str = "") -> dict:
    """整条重跑，或只重跑某一个阶段（stage=web 这种阶段键）。

    单阶段重跑会新建一个任务，资产池按原任务已入库的域名 / IP 回填，
    新结果并进新任务的资产表，两个任务各自可查。
    """
    user = current_user(request)
    task = store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        body = await request.json()
    except Exception:
        body = {}
    key = str(stage or (body or {}).get("stage") or "").strip()
    options = dict(task["options"] or {})
    suffix = "整条重跑"
    if key:
        if key not in pipeline.RERUN_STAGES:
            raise HTTPException(status_code=400,
                                detail="这个阶段不能单独重跑，可选："
                                       + "、".join(pipeline.RERUN_STAGES))
        options["only_stages"] = [key]
        # 新任务本身没有资产，回填要从被重跑的那个任务读
        options["seed_task"] = task_id
        suffix = "重跑" + str(pipeline.PHASE_LABEL.get(key) or key)
        # 阶段内细分项：写成「阶段:子项」，只重测勾中的那几项
        raw_mods = (body or {}).get("modules") or []
        if isinstance(raw_mods, str):
            raw_mods = raw_mods.replace(",", " ").replace("，", " ").split()
        mods = [str(m).strip() for m in raw_mods if str(m).strip()]
        allowed = {f"{key}:{x['key']}" for x in modules_mod.stage_submodules().get(key, [])}
        mods = [m for m in mods if m in allowed]
        if mods:
            options["only_modules"] = mods
            suffix += "(" + "、".join(m.split(":", 1)[1] for m in mods) + ")"
        else:
            options.pop("only_modules", None)
        # 只重测指定的 host / IP：留空 = 整段全跑
        raw_hosts = (body or {}).get("targets") or []
        if isinstance(raw_hosts, str):
            raw_hosts = raw_hosts.replace(",", " ").replace("，", " ").split()
        hosts = [str(h).strip() for h in raw_hosts if str(h).strip()]
        if hosts:
            options["scope_targets"] = hosts
            suffix += "·" + (hosts[0] if len(hosts) == 1 else f"{len(hosts)}个目标")
        else:
            options.pop("scope_targets", None)
    else:
        options.pop("only_stages", None)
        options.pop("seed_task", None)
        options.pop("only_modules", None)
        options.pop("scope_targets", None)
    # 重跑的重跑不要再叠一层同名后缀
    base_name = str(task.get("name") or "")
    tail = "-" + suffix
    while base_name.endswith(tail):
        base_name = base_name[: -len(tail)]
    new_id = await pipeline.start_task(task["targets"], options, base_name + tail)
    audit("task_rerun", task_id, f"{new_id} {suffix}", user=user)
    return {"ok": True, "task_id": new_id, "stage": key or "", "name": suffix}


@app.get("/api/stages/rerun")
def rerun_stages(request: Request) -> dict:
    """可单独重跑的阶段，给前端阶段弹窗做勾选：整段、阶段内的细分项、限定目标"""
    current_user(request)
    return {"ok": True, "stages": pipeline.RERUN_STAGES,
            "labels": {k: pipeline.PHASE_LABEL.get(k, k) for k in pipeline.RERUN_STAGES},
            "submodules": modules_mod.stage_submodules()}


# ─────────────── 功能单项执行 ───────────────
@app.get("/api/ops")
def ops_catalog(request: Request) -> dict:
    """全部可单独执行的功能：阶段类（建任务跑）与直连类（同步出结果）。

    给「功能自检」页做清单：每项吃哪种输入、依赖哪些上游、有哪些参数。
    """
    current_user(request)
    return ops_mod.catalog()


@app.post("/api/ops/run")
async def ops_run(request: Request, body: dict = Body(...)) -> dict:
    """单独跑一个功能。

    body: {key: "stage:dns" | "direct:equity", targets, params, options,
           with_deps, seed_task, expand_entity}
    阶段类会建一个只跑选中阶段的任务（with_deps 时连同上游一起跑），
    直连类当场跑完把结果回给前端，不建任务。
    """
    user = current_user(request)
    key = str(body.get("key") or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="缺少 key")
    kind, _, sub = key.partition(":")
    if not sub:
        kind, sub = "stage", kind
    if kind == "direct":
        try:
            res = await ops_mod.run_direct(sub, body.get("params") or {})
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")
        audit("ops_direct", sub, user=user)
        return {"ok": True, "kind": "direct", **res}

    raw = body.get("targets")
    if isinstance(raw, str):
        targets = [t.strip() for t in raw.replace("\n", ",").replace(" ", ",").split(",")
                   if t.strip()]
    else:
        targets = [str(t).strip() for t in (raw or []) if str(t).strip()]
    if not targets:
        raise HTTPException(status_code=400, detail="目标为空")
    selected = ops_mod.stage_keys_for(sub)
    # 模块卡片上勾了哪几个阶段就跑哪几个：先裁阶段，再补上游依赖，否则依赖会被裁掉
    pick = {str(x).strip() for x in (body.get("stages") or []) if str(x).strip()}
    if pick:
        keep = [s for s in selected if s in pick]
        selected = keep or selected
    stages = pipeline.expand_stages(selected, bool(body.get("with_deps")))
    if not stages:
        raise HTTPException(status_code=400,
                            detail=f"这个功能不能单独执行：{sub}；"
                                   f"可用：{'、'.join(pipeline.RERUN_STAGES)}")
    reserved = {"only_stages", "with_deps", "seed_task", "ops_expand_entity"}
    options = {str(k): v for k, v in (body.get("options") or {}).items() if str(k) not in reserved}
    # 整段流程按界面上的分段开关裁：关掉的那段不排阶段，也就不会去请求
    stages = ops_mod.limit_stages(sub, stages, options)
    options["only_stages"] = stages
    options["with_deps"] = False
    # 单项测试多半直接喂企业名：允许 P0 做一次主体扩线，否则域名池是空的
    options["ops_expand_entity"] = bool(body.get("expand_entity", True))
    seed = str(body.get("seed_task") or "").strip()
    if seed:
        options["seed_task"] = seed
    label = pipeline.PHASE_LABEL.get(sub) or ops_mod.COMPOSITE_LABEL.get(sub, sub)
    name = str(body.get("name") or "").strip() or f"单项·{label}｜{targets[0][:40]}"
    task_id = await pipeline.start_task(targets, options, name)
    audit("ops_stage", sub, f"{task_id} {','.join(targets)}", user=user)
    return {"ok": True, "kind": "stage", "task_id": task_id, "name": name,
            "stages": stages,
            "labels": [pipeline.PHASE_LABEL.get(s, s) for s in stages]}


@app.get("/api/tasks/{task_id}/logs")
def task_logs(request: Request, task_id: str, after_id: int = 0, limit: int = 500) -> dict:
    current_user(request)
    return {"ok": True, "items": store.get_logs(task_id, after_id, limit)}


@app.get("/api/tasks/{task_id}/stream")
async def task_stream(request: Request, task_id: str) -> StreamingResponse:
    current_user(request)

    async def gen():
        last = 0
        idle = 0
        while True:
            if await request.is_disconnected():
                break
            rows = store.get_logs(task_id, last, 200)
            for r in rows:
                last = r["id"]
                yield f"data: {json.dumps(r, ensure_ascii=False)}\n\n"
            task = store.get_task(task_id) or {}
            yield ("event: state\ndata: " + json.dumps(
                {"status": task.get("status"), "progress": task.get("progress"),
                 "message": task.get("message"), "phase": task.get("phase"),
                 "stats": task.get("stats")}, ensure_ascii=False) + "\n\n")
            if task.get("status") in ("done", "error", "stopped") and not rows:
                idle += 1
                if idle > 3:
                    break
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─────────────── 资产 ───────────────
@app.get("/api/assets")
def query_assets(request: Request, kind: str = "", kinds: str = "", keyword: str = "",
                       host: str = "", ip: str = "", root_domain: str = "", task_id: str = "",
                       cdn: str = "", port: int = 0, limit: int = 100, offset: int = 0,
                       order: str = "last_seen DESC", is_new: int = 0,
                       surface: str = "", risk: str = "", stage: str = "",
                       min_ratio: float = 0.0) -> dict:
    current_user(request)
    f = {"kind": kind or None, "keyword": keyword or None, "host": host or None, "ip": ip or None,
         "root_domain": root_domain or None, "task_id": task_id or None, "cdn": cdn or None,
         "surface": surface or None, "risk": risk or None, "stage": stage or None,
         "kinds": [k.strip() for k in (kinds or "").split(",") if k.strip()] or None,
         "min_ratio": float(min_ratio or 0) or None,
         "is_new": is_new or None,
         "port": port or None, "limit": min(int(limit), 5000), "offset": int(offset), "order": order}
    items = store.query_assets(**f)
    for it in items:
        try:
            it["extra"] = json.loads(it.pop("extra_json", "") or "{}")
        except Exception:
            it["extra"] = {}
        # 存活状态：站点看状态码，域名看解析，端口看是实测还是测绘收录
        with_liveness(it)
    total = store.count_assets(**{k: v for k, v in f.items()
                                  if k not in ("limit", "offset", "order")})
    return {"ok": True, "items": items, "total": total}


@app.post("/api/assets/liveness")
def repair_liveness(request: Request, task_id: str = "") -> dict:
    """补全存活状态：把已探到的站点状态码回填给同主机的域名 / 端口 / 接口行。

    历史任务（以及 web 探测之后才落库的接口、域名行）状态码一直是空的，资产表里
    看不出死活。这里按任务或全库补一遍，补完前端刷新即可看到「存活 / 响应 / 解析」。
    """
    current_user(request)
    hit = store.repair_liveness(task_id)
    return {"ok": True, "updated": hit, "task_id": task_id}


# 注意顺序：/api/assets/facets 必须注册在 /api/assets/{asset_id} 之前，
# 否则 "facets" 会被当成 asset_id 解析成整数直接 422。
@app.get("/api/assets/facets")
def facets(request: Request, task_id: str = "", stage: str = "") -> dict:
    current_user(request)
    return {"ok": True, "surfaces": store.surface_counts(task_id=task_id, stage=stage),
            "labels": SURFACE_LABEL, **store.facets(task_id=task_id, stage=stage)}


@app.get("/api/risk")
def risk_view(request: Request, task_id: str = "", limit: int = 12) -> dict:
    """脆弱资产：整体预览与按任务分隔共用这一个接口"""
    current_user(request)
    return {"ok": True, "task_id": task_id, "rules": [k for k, _l, _c in RISK_RULES],
            "labels": {k: label for k, label, _c in RISK_RULES},
            **store.risk_overview(task_id=task_id, limit=min(int(limit), 100))}


@app.get("/api/risk/by-task")
def risk_by_task(request: Request, limit: int = 200) -> dict:
    """按任务分隔的脆弱资产：每趟侦察各自有多少条、落在哪几个桶"""
    current_user(request)
    return {"ok": True, "labels": {k: label for k, label, _c in RISK_RULES},
            "items": store.risk_by_task(limit=min(int(limit), 500))}


@app.get("/api/tasks/{task_id}/summary")
def task_summary(request: Request, task_id: str) -> dict:
    """单个任务自己的资产收集画像：分类、来源、根域、阶段证据。

    任务详情的资产 tab 靠这个接口回答「这趟到底收到了什么、哪一路出的」，
    不用再回到全局资产页自己筛。
    """
    current_user(request)
    task = store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        stats = json.loads(task.get("stats_json") or "{}")
    except Exception:
        stats = {}
    c = store.conn()
    total = int(c.execute(
        "SELECT COUNT(*) FROM task_assets WHERE task_id=?", (task_id,)).fetchone()[0])

    def rows(sql: str, limit: int = 0) -> list[dict]:
        q = sql + (" LIMIT %d" % int(limit) if limit else "")
        return [dict(r) for r in c.execute(q, (task_id,)).fetchall()]

    by_kind = rows("SELECT kind value, COUNT(*) count FROM assets WHERE id IN"
                   " (SELECT asset_id FROM task_assets WHERE task_id=?)"
                   " GROUP BY kind ORDER BY count DESC")
    by_source: dict[str, int] = {}
    for r in rows("SELECT sources FROM assets WHERE id IN"
                  " (SELECT asset_id FROM task_assets WHERE task_id=?)"):
        for s in str(r.get("sources") or "").split(","):
            s = s.strip()
            if s:
                by_source[s] = by_source.get(s, 0) + 1
    by_root = rows("SELECT root_domain value, COUNT(*) count,"
                   " SUM(CASE WHEN status_code BETWEEN 200 AND 399 THEN 1 ELSE 0 END) alive"
                   " FROM assets WHERE root_domain IS NOT NULL AND root_domain!=''"
                   " AND id IN (SELECT asset_id FROM task_assets WHERE task_id=?)"
                   " GROUP BY root_domain ORDER BY count DESC", 30)
    by_phase = rows("SELECT module value, level, COUNT(*) count, MAX(ts) last_ts FROM logs"
                    " WHERE task_id=? GROUP BY module, level ORDER BY count DESC", 80)
    evidence = rows("SELECT title, url, extra_json FROM assets WHERE kind='equity'"
                    " AND id IN (SELECT asset_id FROM task_assets WHERE task_id=?) LIMIT 20")
    equity = []
    for e in evidence:
        try:
            d = json.loads(e.get("extra_json") or "{}")
        except Exception:
            d = {}
        equity.append({"name": (d.get("name") or e.get("title") or "").replace(" 股权链路", ""),
                       "source": d.get("source") or "", "depth": d.get("depth"),
                       "ratio": d.get("ratio"),
                       "full_owned": (d.get("full_owned") or [])[1:60],
                       "partial": [p.get("name") for p in (d.get("partial") or [])][:60],
                       "holders": [h.get("name") for h in (d.get("holders") or [])][:20],
                       "children": len(d.get("full_owned") or []),
                       "notes": d.get("notes") or []})
    return {
        "ok": True,
        "task_id": task_id,
        "total": total,
        "by_kind": by_kind,
        # 资产面单独给一份：任务详情要能把 Web / 小程序 / 公众号 / APP 拆开看，
        # 和资产组页共用同一套 surface_cond 口径，避免两边条数对不上
        "surfaces": store.surface_counts(task_id=task_id),
        "by_source": [{"value": k, "count": v}
                      for k, v in sorted(by_source.items(), key=lambda x: -x[1])],
        "by_root_domain": by_root,
        "by_phase": by_phase,
        "stats": stats,
        "equity": equity,
    }


@app.get("/api/tasks/{task_id}/stages")
def task_stages(request: Request, task_id: str) -> dict:
    """逐阶段明细：每个阶段跑了多久、打了多少日志、这一阶段收进了哪些资产。

    任务详情的阶段轨迹要能点开，靠这个接口回答「点进去到底能看什么」。
    资产按 first_seen 落在该阶段时间窗内归属，日志按 module 聚合。
    """
    current_user(request)
    if not store.get_task(task_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    c = store.conn()
    agg = [dict(r) for r in c.execute(
        "SELECT module, level, COUNT(*) count, MIN(ts) first_ts, MAX(ts) last_ts"
        " FROM logs WHERE task_id=? GROUP BY module, level", (task_id,)).fetchall()]

    buckets: dict[str, dict] = {}
    for r in agg:
        key = r.get("module") or "system"
        key = modules_mod.LOG_MODULE_ALIAS.get(key, key)
        b = buckets.get(key)
        if b is None:
            b = buckets[key] = {"key": key, "count": 0, "warn": 0, "error": 0,
                                "first_ts": r.get("first_ts"), "last_ts": r.get("last_ts")}
        b["count"] += int(r.get("count") or 0)
        lv = str(r.get("level") or "").lower()
        if lv in ("warn", "warning"):
            b["warn"] += int(r.get("count") or 0)
        elif lv in ("error", "err", "fatal"):
            b["error"] += int(r.get("count") or 0)
        if r.get("first_ts") is not None:
            b["first_ts"] = min(b["first_ts"] or r["first_ts"], r["first_ts"])
        if r.get("last_ts") is not None:
            b["last_ts"] = max(b["last_ts"] or r["last_ts"], r["last_ts"])

    out = []
    # 阶段表里有时间窗但一条日志都没打（例如空间测绘无引擎直接跳过）也要能点开
    wins = {r["phase"]: r for r in c.execute(
        "SELECT phase, start_ts, end_ts FROM task_phases WHERE task_id=?", (task_id,)).fetchall()}
    for key, w in wins.items():
        if key not in buckets:
            buckets[key] = {"key": key, "count": 0, "warn": 0, "error": 0,
                            "first_ts": w["start_ts"], "last_ts": w["end_ts"]}
    for key, b in buckets.items():
        w = wins.get(key)
        lo = (w["start_ts"] if w else None) or b.get("first_ts") or 0
        hi = (w["end_ts"] if w else None) or b.get("last_ts") or 0
        # 别名合并后要把原名一起捞，否则「目标归一」点开一条日志都没有
        mods = [key] + [a for a, t in modules_mod.LOG_MODULE_ALIAS.items() if t == key]
        ph = ",".join("?" for _ in mods)
        samples = [dict(r) for r in c.execute(
            "SELECT ts, level, msg FROM logs WHERE task_id=? AND module IN (" + ph + ")"
            " ORDER BY CASE lower(level) WHEN 'error' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, ts"
            " LIMIT 40", (task_id, *mods)).fetchall()]
        # 归属优先看关联表记的阶段；老任务没记阶段时回落到时间窗。
        # 资产行按 url 全局合并：first_seen 可能是别的任务留下的，所以
        # 「首次见到」或「这趟又见到」（last_seen 每次 upsert 都刷新）都算本阶段产出。
        # 明细一次取回，kinds / sources / ports / roots 在内存里聚合。
        # 原来每阶段 6 条 join 扫描，14 个阶段就是 84 条，点开任务要等一秒。
        cols = ("SELECT a.id, a.kind, a.url, a.title, a.status_code, a.fingerprint, a.sources,"
                " a.host, a.ip, a.ips, a.port, a.root_domain"
                " FROM assets a JOIN task_assets t ON t.asset_id=a.id WHERE ")
        where = "t.task_id=? AND t.stage=?"
        vals: tuple = (task_id, key)
        rows = c.execute(cols + where + " ORDER BY a.id DESC LIMIT 5000", vals).fetchall()
        if not rows:
            where = ("t.task_id=? AND (t.stage IS NULL OR t.stage='') AND ("
                     "a.first_seen BETWEEN ? AND ? OR a.last_seen BETWEEN ? AND ?)")
            vals = (task_id, lo, hi + 1, lo, hi + 1)
            rows = c.execute(cols + where + " ORDER BY a.id DESC LIMIT 5000", vals).fetchall()

        kc: dict[str, int] = {}
        sc: dict[str, int] = {}
        pc: dict[int, int] = {}
        rc: dict[str, int] = {}
        for r in rows:
            k = r["kind"] or "unknown"
            kc[k] = kc.get(k, 0) + 1
            s = (r["sources"] or "").strip() or "未知"
            sc[s] = sc.get(s, 0) + 1
            p = int(r["port"] or 0)
            if p > 0:
                pc[p] = pc.get(p, 0) + 1
            # 工商 / 备案这类资产本身没有域名，只统计带根域的，别把几百条顶进榜首
            rd = r["root_domain"] or ""
            if rd:
                rc[rd] = rc.get(rd, 0) + 1

        def top(counter: dict, limit: int = 12) -> list[tuple]:
            return sorted(counter.items(), key=lambda kv: -kv[1])[:limit]

        kinds = [{"value": k, "count": n} for k, n in top(kc)]
        assets = [with_liveness(dict(r)) for r in rows[:60]]
        sources = [{"name": k, "count": n} for k, n in top(sc)]
        ports = [{"port": k, "count": n} for k, n in top(pc)]
        roots = [{"name": k, "count": n} for k, n in top(rc)]
        # 阶段窗只在开头写过一次时 start=end，算出来是 0 秒；日志跨度更接近真实耗时。
        # 两者取大：真跑了一刻钟的阶段不该显示 0 秒，一跳就过的阶段也别被日志拉长。
        span = max(max(0.0, (hi or 0) - (lo or 0)),
                   max(0.0, (b.get("last_ts") or 0) - (b.get("first_ts") or 0)))
        out.append({**b,
                    "label": (pipeline.PHASE_LABEL.get(key)
                              or modules_mod.LOG_MODULE_LABEL.get(key) or key),
                    "duration": round(span, 1),
                    "samples": samples, "assets": assets, "kinds": kinds,
                    "sources": sources, "ports": ports, "roots": roots,
                    "total_assets": sum(int(x.get("count") or 0) for x in kinds)})
    order = {k: i for i, (_, k, _) in enumerate(pipeline.PHASES)}
    out.sort(key=lambda x: (order.get(x["key"], 99), x.get("first_ts") or 0))
    return {"ok": True, "task_id": task_id, "stages": out}


def _pct_num(v: Any) -> float | None:
    """把 "43.20%" / 43.2 / "" 统一成百分数；拿不到就返回 None。"""
    s = str(v if v is not None else "").replace("%", "").replace(",", "").strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _equity_ubo(root: dict, threshold: float = 25.0) -> dict:
    """从穿透树推导最终受益人：叶子节点按累计持股合并，同名多路径相加。

    数据源只给直接比例时按路径连乘，给了累计比例就直接取，避免把 100% 全资
    链路层层相乘算成 0。低于门槛的叶子也一并返回，前端可以分开标注。
    """
    agg: dict[str, dict] = {}

    def walk(node: dict, carried: float | None, depth: int, path: list[str]) -> None:
        name = str(node.get("name") or "").strip()
        acc = _pct_num(node.get("acc"))
        ratio = _pct_num(node.get("ratio"))
        if acc is not None:
            cur = acc
        elif ratio is not None:
            cur = ratio if carried is None else carried * ratio / 100.0
        else:
            cur = carried
        kids = node.get("children") or []
        if not kids:
            if depth == 0 or not name:
                return
            rec = agg.get(name)
            if rec is None:
                rec = agg[name] = {"name": name, "ratio": 0.0, "depth": depth, "paths": []}
            if cur is not None:
                rec["ratio"] += cur
            rec["depth"] = max(rec["depth"], depth)
            if len(rec["paths"]) < 3:
                rec["paths"].append(" > ".join(path + [name]))
            return
        for k in kids:
            walk(k, cur, depth + 1, path + [name])

    walk(root, 100.0 if root.get("acc") is not None else None, 0, [])
    holders = []
    for r in agg.values():
        r["ratio"] = round(min(100.0, r["ratio"]), 2)
        r["control"] = r["ratio"] >= threshold
        holders.append(r)
    holders.sort(key=lambda x: (-x["ratio"], x["depth"]))
    return {"threshold": threshold,
            "holders": holders[:20],
            "main": [h["name"] for h in holders if h["control"]][:10]}


def _ubo_of(d: dict, root: dict) -> dict:
    """最终受益人：资产里已经算好的优先，再退回从穿透树推导。

    采集侧按股东树逐级折算，个人股东也能穿到底；穿透树只有链路节点，
    老资产没有 ``ubo`` 时才用它兜底，保证老任务打开也有内容。
    """
    stored = d.get("ubo")
    if isinstance(stored, dict) and stored.get("holders"):
        out = dict(stored)
        out["main"] = [h.get("name") for h in out["holders"] if h.get("control")][:10]
        return out
    return _equity_ubo(root)


@app.get("/api/tasks/{task_id}/equity")
def task_equity_tree(request: Request, task_id: str) -> dict:
    """股权穿透树：把链路拍平成 parent → children，交给前端画树图。

    ``chain`` 里每一项都带 parent / ratio / acc_ratio / depth，
    这里按父名挂接，缺失父节点的直接挂到根上，避免接口数据不全时丢节点。
    """
    current_user(request)
    if not store.get_task(task_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    c = store.conn()
    rows = [dict(r) for r in c.execute(
        "SELECT url, title, extra_json FROM assets WHERE kind='equity'"
        " AND id IN (SELECT asset_id FROM task_assets WHERE task_id=?)", (task_id,)).fetchall()]
    trees = []
    for r in rows:
        try:
            d = json.loads(r.get("extra_json") or "{}")
        except Exception:
            d = {}
        name = (d.get("name") or r.get("title") or "").replace(" 股权链路", "").strip()
        if not name:
            continue
        chain = [x for x in (d.get("chain") or []) if isinstance(x, dict) and x.get("name")]
        nodes: dict[str, dict] = {}

        def node_of(n: str, ratio=None, acc=None, depth=None) -> dict:
            cur = nodes.get(n)
            if cur is None:
                cur = nodes[n] = {"name": n, "children": []}
            if ratio is not None:
                cur["ratio"] = ratio
            if acc is not None:
                cur["acc"] = acc
            if depth is not None:
                cur["depth"] = depth
            return cur

        root = node_of(name, 100, 100, 0)
        for it in chain:
            child = str(it.get("name") or "").strip()
            if not child or child == name:
                continue
            n = node_of(child, it.get("ratio"), it.get("acc_ratio"), it.get("depth"))
            pid = str(it.get("parent") or "").strip() or name
            parent = nodes.get(pid)
            if parent is None:
                parent = node_of(pid, 100, 100, 0)
            if n is not parent and n not in parent["children"]:
                parent["children"].append(n)
        trees.append({"name": name, "source": d.get("source") or "",
                      "ratio_line": d.get("ratio"), "depth": d.get("depth"),
                      "notes": d.get("notes") or [],
                      "holders": [{"name": h.get("name"), "ratio": h.get("ratio")}
                                  for h in (d.get("holders") or [])][:30],
                      "full_owned": (d.get("full_owned") or [])[1:60],
                      "partial": [p.get("name") for p in (d.get("partial") or [])][:60],
                      "ubo": _ubo_of(d, root),
                      "source_status": d.get("source_status") or {},
                      "tree": root})
    # 主体阶段和股权阶段各会落一张穿透图，同一主体常常两张都在。
    # 汇总时已经按主体合并过资产；这里再兜一层，老任务 / 结构不同也能并成一张。
    raw_count = len(trees)
    trees = dedupe.merge_trees(trees)
    return {"ok": True, "task_id": task_id, "trees": trees, "raw_trees": raw_count}


@app.get("/api/tasks/{task_id}/sources")
def task_sources(request: Request, task_id: str) -> dict:
    """渠道面板：这次任务用了哪些数据渠道，哪些失效 / 额度尽 / 没配凭据。

    数据在采集时按「阶段 + 渠道」累加写入 ``task_sources``，这里只做聚合和排序，
    不重新探活：面板要回答「刚才这一轮发生了什么」，而不是再打一遍外部接口。
    """
    current_user(request)
    if not store.get_task(task_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"ok": True, "task_id": task_id, **source_health.snapshot(store, task_id)}


@app.get("/api/assets/{asset_id}")
def asset_detail(request: Request, asset_id: int) -> dict:
    current_user(request)
    rows = store.query_assets(limit=1)
    conn = store.conn()
    row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="资产不存在")
    d = dict(row)
    try:
        d["extra"] = json.loads(d.pop("extra_json", "") or "{}")
    except Exception:
        d["extra"] = {}
    with_liveness(d)
    _ = rows
    return {"ok": True, "item": d}


@app.get("/api/stats")
def stats(request: Request) -> dict:
    current_user(request)
    data = store.stats()
    data["tasks"] = len(store.list_tasks(1000))
    data["running"] = len(pipeline.RUNNING)
    return {"ok": True, **data}


@app.get("/api/diff")
def asset_diff(request: Request, root: str = "", limit: int = 200) -> dict:
    """每轮快照对比：返回各根域最近一次的新增数量与新增条目"""
    current_user(request)
    roots = [root] if root else [r["root_domain"] for r in store.stats().get("top_roots", [])]
    snaps = store.list_snapshots(roots) if roots else []
    seen: set[str] = set()
    out = []
    for s in snaps:                      # 已按时间倒序，每个根域取第一条（最新）
        if s["root_domain"] in seen:
            continue
        seen.add(s["root_domain"])
        out.append({"root_domain": s["root_domain"], "created_at": s["created_at"],
                    "count": s["count"], "new_count": s["new_count"],
                    "items": json.loads(s.get("items_json") or "[]")[-limit:]})
    return {"ok": True, "items": out}


# 全资产导出的列：基础列全体共用，其余按类型补。列名用中文，
# 直接丢给 Excel / 交接文档不用再翻译一遍。
EXPORT_BASE_COLS = ["类型", "地址", "主机", "IP", "端口", "根域", "标题", "状态码", "存活", "指纹",
                    "服务", "中间件", "CDN", "来源", "首次发现", "最后发现",
                    "协议", "应用", "Whois", "ISP", "OS", "地区", "更新时间"]
EXPORT_EXTRA_COLS = ["应用名", "接口路径", "所属页面", "Banner", "服务标识", "证书主体",
                     "证书签发者", "证书到期", "Favicon", "泄露类型", "泄露内容", "命中的位置",
                     "邮箱", "邮箱来源", "企业名称", "ICP备案", "数据关联", "应用包名", "开发者",
                     "小程序AppID", "应用市场", "存储桶", "是否公开", "仓库", "证据", "备注"]
# 分表导出：一张表只放一类资产，列与交接时常用的表格口径对齐。
# 键就是导出参数 ``sheet=``；``all`` 保留原来那张全量宽表，已有调用不受影响。
EXPORT_SHEETS: dict[str, dict] = {
    "all": {"label": "全量资产", "kinds": [],
            "cols": EXPORT_BASE_COLS + EXPORT_EXTRA_COLS},
    # 测绘阶段落两类资产：裸 IP 记服务、域名记域名。hostname 那批跟被动子域混在
    # 同一个 kind 里，按 kind 分不开，所以这张表只放裸 IP 服务 —— 至少条数是真的。
    "space": {"label": "空间测绘", "kinds": ["service"],
              "cols": ["ID", "URL", "IP", "端口", "存活", "协议", "标题", "指纹", "应用",
                       "Whois", "ICP备案", "ISP", "OS", "地区", "更新时间", "来源"]},
    # 端口扫描真连上的开放端口单独一张表：跟测绘收录的「服务」不是一回事，
    # 前者是现网确认开着，后者只是索引里出现过。
    "port": {"label": "端口", "kinds": ["port"],
             "cols": ["ID", "IP", "端口", "服务", "Banner", "Web", "存活", "来源",
                      "首次发现", "最后发现"]},
    # ── 主资产类型各占一张表：站点 / 域名 / IP / 接口 / JS / 组件 / 泄露 / VHost / 仓库 / 邮箱 ──
    # 之前只有测绘和 C 段分表，domain / site / api 这些量最大的类型全挤在「全量资产」里，
    # 交接时要在几万行里手工筛。按 kind 拆开后每张表列也按该类型的口径给。
    "site": {"label": "站点", "kinds": ["site"],
             "cols": ["ID", "URL", "域名", "IP", "端口", "状态码", "存活", "标题", "指纹", "中间件",
                      "CDN", "应用", "协议", "证书主体", "证书到期", "来源", "首次发现",
                      "最后发现", "更新时间"]},
    "domain": {"label": "域名", "kinds": ["domain"],
               "cols": ["ID", "域名", "IP", "端口", "根域", "标题", "状态码", "存活", "来源",
                        "Whois", "ISP", "地区", "首次发现", "最后发现"]},
    "ip": {"label": "IP 地址", "kinds": ["ip"],
           "cols": ["ID", "IP", "端口", "存活", "根域", "ASN", "持有者", "ISP", "OS", "地区",
                    "标题", "来源", "最后发现"]},
    "api": {"label": "接口", "kinds": ["api"],
            "cols": ["ID", "URL", "域名", "接口路径", "所属页面", "状态码", "存活", "标题",
                     "指纹", "应用", "来源", "首次发现", "最后发现"]},
    "js": {"label": "JS 文件", "kinds": ["js"],
           "cols": ["ID", "URL", "域名", "接口路径", "所属页面", "状态码", "存活", "指纹",
                    "来源", "最后发现"]},
    "component": {"label": "组件", "kinds": ["component"],
                  "cols": ["ID", "URL", "域名", "名称", "当前版本", "指纹", "应用",
                           "来源", "证据", "最后发现"]},
    "leak": {"label": "敏感泄露", "kinds": ["leak", "leakfile"],
             "cols": ["ID", "URL", "域名", "泄露类型", "泄露内容", "命中的位置", "状态码",
                      "存活", "标题", "证据", "来源", "最后发现"]},
    "vhost": {"label": "VHost", "kinds": ["vhost"],
              "cols": ["ID", "URL", "域名", "IP", "端口", "状态码", "存活", "标题", "指纹",
                       "来源", "最后发现"]},
    "git": {"label": "Git 仓库", "kinds": ["git"],
            "cols": ["ID", "URL", "仓库", "域名", "状态码", "存活", "证据", "来源", "最后发现"]},
    "email": {"label": "邮箱", "kinds": ["email", "mailinfo"],
              "cols": ["ID", "邮箱", "域名", "邮箱来源", "数据关联", "来源", "最后发现"]},
    "equity": {"label": "股权关系", "kinds": ["equity"],
               "cols": ["ID", "公司名称", "企业名称", "股东名称", "持股比例", "数据关联",
                        "来源", "最后发现"]},
    # C 段单独一张表：旁站 / 同段业务页（sibling）和 ASN 归集出的网段（netblock）。
    # 这两类资产量小、跟主资产口径不同，混进全量表容易被当成目标主站，单独导才看得清。
    "csegment": {"label": "C段/网段", "kinds": ["sibling", "netblock"],
                 "cols": ["ID", "IP", "端口", "URL", "标题", "CIDR", "ASN", "持有者",
                          "种子IP", "根域", "来源", "最后发现"]},
    # 应用来源有两条：本机解包（mobile）和工商链路带出的应用市场（mobileapp）。
    # 分表按 kinds 逐个查再拼一张表，两条来源落进同一个 APP 表。
    "app": {"label": "APP", "kinds": ["mobile", "mobileapp"],
            "cols": ["名称", "分类", "当前版本", "更新时间", "简介", "Logo", "Bundle ID",
                     "ICP备案", "链接", "market", "数据关联", "补充信息"]},
    # 小程序有三个来源：本机解包（applet）、工信部小程序备案（applet_icp）、
    # 只有名字没 AppID 的线索（applet_hint）。三者都算「小程序」这一面，
    # 只放 applet 会让导出漏掉后两类 —— 它们在资产页里看得到，导出来反倒没了。
    "applet": {"label": "小程序", "kinds": ["applet", "applet_icp", "applet_hint"],
               "cols": ["名称", "小程序AppID", "分类", "当前版本", "更新时间", "简介",
                        "Logo", "ICP备案", "链接", "数据关联", "补充信息"]},
    "icp": {"label": "ICP 备案", "kinds": ["icp"],
            "cols": ["网站名称", "网址", "域名", "网站备案/许可证号", "公司名称",
                     "数据关联", "补充信息"]},
    "enterprise": {"label": "企业信息", "kinds": ["enterprise"],
                   "cols": ["企业名称", "法人代表", "经营状态", "电话", "邮箱", "注册资本",
                            "成立日期", "注册地址", "经营范围", "统一社会信用代码", "PID",
                            "数据关联", "补充信息"]},
    "weibo": {"label": "微博", "kinds": ["weibo"],
              "cols": ["微博昵称", "链接", "简介", "头像", "数据关联", "补充信息"]},
    "mp": {"label": "公众号", "kinds": ["wxmp", "wechatoa"],
           "cols": ["名称", "ID", "简介", "二维码", "头像", "数据关联", "补充信息"]},
    "branch": {"label": "分支机构", "kinds": ["branch"],
               "cols": ["企业名称", "法人", "状态", "PID", "数据关联", "补充信息"]},
    "holds": {"label": "控股企业", "kinds": ["holds"],
              "cols": ["企业名称", "法人", "状态", "投资比例", "持股层级", "PID",
                       "数据关联", "补充信息"]},
    "invest": {"label": "对外投资", "kinds": ["invest"],
               "cols": ["企业名称", "法人", "状态", "投资比例", "PID",
                        "数据关联", "补充信息"]},
    "partner": {"label": "股东信息", "kinds": ["partner"],
                "cols": ["股东名称", "持股比例", "认缴出资金额", "PID",
                         "数据关联", "补充信息"]},
    "copyright": {"label": "软件著作权", "kinds": ["copyright"],
                  "cols": ["软件全称", "软件简称", "分类", "登记号", "权利取得方式",
                           "数据关联", "补充信息"]},
    "job": {"label": "招聘", "kinds": ["job"],
            "cols": ["公司名称", "岗位名称", "城市", "学历", "发布时间", "岗位描述",
                     "数据关联", "补充信息"]},
    "supplier": {"label": "供应商", "kinds": ["supplier"],
                 "cols": ["公司名称", "供应商名称", "合作时间", "来源渠道", "PID",
                          "数据关联", "补充信息"]},
}
# 只有这几张表的行带持股比例，比例筛选只对它们生效；其余表传了比例会被筛成空表。
RATIO_SHEETS = frozenset({"holds", "invest", "partner", "branch"})
# 私钥/口令类字段一律导出成「已命中」占位：导出的表会被到处转，原始值不进表格
SECRET_MASK_KEYS = ("password", "passwd", "secret", "private_key", "token", "access_key",
                    "secret_key", "apikey", "api_key")


def _pct_text(value: Any) -> str:
    """持股比例 → ``55%`` / ``55.5%``；空值留空，避免把「没取到」写成 0%。"""
    if value in (None, ""):
        return ""
    try:
        return f"{round(float(value), 2):g}%"
    except (TypeError, ValueError):
        return str(value)


def _brief(value: Any, limit: int = 300) -> str:
    """表格单元格：列表拼起来、字典压成 k=v，长文本截断，避免 CSV 被撑爆。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        parts = []
        for v in value[:12]:
            s = _brief(v, 120)
            if s and s not in parts:
                parts.append(s)
        return "; ".join(parts)[:limit]
    if isinstance(value, dict):
        parts = []
        for k, v in list(value.items())[:12]:
            s = "已命中" if str(k).lower() in SECRET_MASK_KEYS and v else _brief(v, 100)
            if s:
                parts.append(f"{k}={s}")
        return "; ".join(parts)[:limit]
    return str(value).replace("\r", " ").replace("\n", " ").strip()[:limit]


def _first_of(value: Any) -> str:
    """指纹列表里的主产品名：一行只留一个，其余在「指纹」列看。"""
    if isinstance(value, (list, tuple)):
        parts = [_brief(v, 60) for v in value if v]
    else:
        parts = [s.strip() for s in str(value or "").replace("；", ",").replace(";", ",").split(",")
                 if s.strip()]
    return parts[0] if parts else ""


def _region_of(extra: dict) -> str:
    """归属地：国家/省/市去重后由大到小拼。"""
    out: list[str] = []
    for k in ("country", "province", "city"):
        v = str(extra.get(k) or "").strip()
        if v and v not in out:
            out.append(v)
    return " ".join(out)


def _ts_of(value: Any) -> str:
    """时间列：库里存秒级时间戳，导出去给人看要变日期。"""
    if value in (None, ""):
        return ""
    s = str(value).strip()
    try:
        n = float(s)
    except (TypeError, ValueError):
        return s[:19]
    if n <= 0:
        return ""
    if n > 1e11:          # 毫秒时间戳
        n /= 1000.0
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(n))
    except (OSError, ValueError):
        return s[:19]


def _app_of(extra: dict, fp: Any, kind: str) -> str:
    """应用：先认平台给的产品名，再认页面指纹里的主力产品。"""
    name = _first_of(extra.get("product"))
    if name:
        return name
    if kind in ("", "domain", "service", "port", "site"):
        name = str(extra.get("app") or "").strip()
        if name:
            return name
    return _first_of(fp)


def _whois_of(extra: dict) -> str:
    """Whois：注册商 + 注册/到期日期，拿到什么写什么。"""
    parts: list[str] = []
    who = extra.get("whois") or extra.get("whois_registrar") or extra.get("registrar")
    if isinstance(who, (list, tuple)):
        who = "、".join(str(x) for x in who if x)
    if who:
        parts.append(str(who)[:120])
    created = str(extra.get("whois_created") or "")[:10]
    expires = str(extra.get("whois_expires") or "")[:10]
    if created or expires:
        parts.append(f"{created or '-'} 至 {expires or '-'}")
    return " ".join(parts)


def _export_row(r: dict) -> dict:
    """一条资产 → 一行全字段。按 kind 补专属列，拿不到的留空。"""
    # 库里存的是 extra_json 字符串；调用方也可能已经解成 extra 字典，两种都接
    extra = r.pop("extra", None)
    if extra is None:
        extra = r.pop("extra_json", None)
    if isinstance(extra, str):
        try:
            extra = json.loads(extra or "{}")
        except Exception:
            extra = {}
    extra = extra or {}
    kind = str(r.get("kind") or "")
    cert = extra.get("cert") if isinstance(extra.get("cert"), dict) else {}
    fp = extra.get("fingerprint") or r.get("fingerprint") or ""
    url = r.get("url") or ""
    row = {
        "类型": r.get("kind"), "地址": url, "主机": r.get("host"),
        "IP": r.get("ip"), "端口": r.get("port"), "根域": r.get("root_domain"),
        "标题": r.get("title") or extra.get("title") or "",
        "状态码": r.get("status_code"),
        # 存活：站点看码、域名看解析、端口看实测/测绘，一眼分得清死活
        "存活": live_state(r)[1],
        # 指纹：页面指纹优先，测绘平台回的产品名兜底——平台那行本来就带一串产品
        "指纹": _brief(fp) or _brief(extra.get("product")),
        "服务": r.get("service") or extra.get("service") or "",
        "中间件": r.get("server") or "", "CDN": r.get("cdn") or "",
        "来源": _brief(r.get("sources")), "首次发现": _ts_of(r.get("first_seen")),
        "最后发现": _ts_of(r.get("last_seen")),
        "应用名": extra.get("app") or extra.get("name") or "",
        "接口路径": extra.get("api") or extra.get("path") or extra.get("bucket") or "",
        "所属页面": extra.get("page") or extra.get("final_url") or "",
        "Banner": _brief(extra.get("banner") or extra.get("probe")),
        "服务标识": extra.get("identified") or extra.get("service") or "",
        "证书主体": _brief(cert.get("subject") or extra.get("cert_org")),
        "证书签发者": _brief(cert.get("issuer")),
        "证书到期": cert.get("not_after") or cert.get("expires") or "",
        "Favicon": extra.get("favicon") or "",
        "泄露类型": extra.get("type") or "",
        "泄露内容": _brief(extra.get("value") or extra.get("content") or extra.get("query")),
        "命中的位置": extra.get("where") or extra.get("evidence") or "",
        # 只有邮箱类资产才填邮箱列，别拿地址兜底污染整表
        "邮箱": extra.get("email") or (url[6:] if url.startswith("email:") else ""),
        "邮箱来源": extra.get("from") or extra.get("source") or "",
        # 备案资产是一条备案一行：主体名写在 unit 里，导表时补进「企业名称」列
        "企业名称": (extra.get("name") if r.get("kind") in (
            "enterprise", "holds", "invest", "partner") else extra.get("unit")
            if r.get("kind") == "icp" else ""),
        # 股权四类：控股 / 对外投资 / 股东 / 软著各有一列自己的口径
        "投资比例": _pct_text(extra.get("ratio")),
        "持股层级": "" if extra.get("level") in (None, "") else extra.get("level"),
        "股东名称": extra.get("name") if r.get("kind") == "partner" else "",
        "持股比例": _pct_text(extra.get("ratio")) if r.get("kind") == "partner" else "",
        "认缴出资金额": extra.get("capital") or "",
        "软件全称": extra.get("name") if r.get("kind") == "copyright" else "",
        "软件简称": extra.get("short_name") or extra.get("shortName") or "",
        "登记号": extra.get("reg_num") or extra.get("regNum") or "",
        "权利取得方式": extra.get("pub_type") or extra.get("pubType") or "",
        "ICP备案": _brief(extra.get("icp")),
        # 小程序备案 / 线索这两类没有关联字段，主办单位（subject）就是它唯一的主体线索，
        # 落到「数据关联」列，别在导出的表里丢掉。
        "数据关联": (extra.get("relation")
                     or (extra.get("subject") if kind in ("applet_icp", "applet_hint")
                         else "") or ""),
        "应用包名": extra.get("package") or extra.get("bundle") or "",
        "开发者": extra.get("developer") or "",
        "小程序AppID": extra.get("app") if r.get("kind") == "applet" else "",
        "应用市场": extra.get("platform") or extra.get("store_url") or "",
        "存储桶": extra.get("bucket") or "",
        "是否公开": "" if extra.get("public") is None else ("是" if extra.get("public") else "否"),
        "仓库": extra.get("repo") or "",
        "证据": _brief(extra.get("evidence")),
        "备注": _brief(extra.get("notes")),
        # 测绘平台一次就回了这些，早先只在详情里看，导出表没有列
        "协议": extra.get("protocol") or (url.split("://")[0].lower() if "://" in url else ""),
        "应用": _app_of(extra, fp, str(r.get("kind") or "")),
        "Whois": _whois_of(extra),
        "ISP": extra.get("isp") or extra.get("org") or extra.get("asn_org") or "",
        "OS": extra.get("os") or "",
        "地区": _region_of(extra),
        "更新时间": _ts_of(extra.get("updated") or r.get("last_seen")),
        # ── 以下只给分表用：全量宽表取 BASE+EXTRA，不重复这几列 ──
        "URL": url,
        "域名": r.get("host") or "",
        # C 段表：旁站行没有 CIDR，网段行的 host 就是 CIDR，两列各自认
        "CIDR": extra.get("cidr") or (r.get("host") if r.get("kind") == "netblock" else ""),
        "ASN": extra.get("asn") or "",
        "持有者": extra.get("holder") or "",
        "种子IP": extra.get("seed_ip") or "",
        "名称": extra.get("name") or extra.get("app") or r.get("title") or "",
        "当前版本": extra.get("version") or "",
        # 应用/公众号/招聘/供应商来自工商链路，字段名跟本机解包那套不一样，
        # 这里两套都认，保证同一个表里两种来源都能填满
        "分类": extra.get("category") or extra.get("classify") or "",
        "简介": (_brief(extra.get("intro") or extra.get("description")
                        or extra.get("brief") or extra.get("summary"))),
        "Logo": extra.get("logo") or extra.get("icon") or "",
        "Bundle ID": extra.get("package") or extra.get("bundle") or "",
        "链接": extra.get("store_url") or extra.get("link") or url,
        "market": extra.get("platform") or extra.get("market") or "",
        "补充信息": _brief(extra.get("extra") or extra.get("notes")),
        "网站名称": extra.get("site_name") or extra.get("webname") or r.get("title") or "",
        "网址": url,
        # 应用/小程序上架备案来自商店登记值，跟网站备案同一个字段名
        "ICP备案": _brief(extra.get("icp") or extra.get("license")),
        "网站备案/许可证号": _brief(extra.get("icp") or extra.get("license")),
        "公司名称": extra.get("unit") or extra.get("company") or extra.get("parent") or "",
        "法人代表": extra.get("legal") or extra.get("legal_person") or "",
        "经营状态": extra.get("status") or extra.get("reg_status") or "",
        "电话": extra.get("phone") or extra.get("tel") or "",
        "注册资本": extra.get("capital") or "",
        "成立日期": extra.get("established") or extra.get("found_date") or "",
        "注册地址": extra.get("address") or "",
        "经营范围": _brief(extra.get("business") or extra.get("scope")),
        "统一社会信用代码": extra.get("credit_code") or extra.get("uscc") or "",
        "PID": extra.get("pid") or "",
        "微博昵称": extra.get("nickname") or extra.get("name") or "",
        "ID": (extra.get("wxid") or extra.get("gh") or extra.get("account")
               or extra.get("app") or ""),
        "二维码": extra.get("qrcode") or "",
        "头像": extra.get("avatar") or extra.get("logo") or "",
        "法人": extra.get("legal") or extra.get("legal_person") or "",
        "状态": extra.get("status") or extra.get("cancel_status") or "",
        # 招聘 / 供应商：工商链路里的两个附加画像
        "岗位名称": extra.get("name") if kind == "job" else "",
        "城市": extra.get("location") or "",
        "学历": extra.get("education") or "",
        "发布时间": extra.get("published") or "",
        "岗位描述": _brief(extra.get("desc") or extra.get("requirement")),
        "供应商名称": extra.get("name") if kind == "supplier" else "",
        "合作时间": extra.get("cooperated") or "",
        "来源渠道": extra.get("source") or "",
    }
    return row


def _ratio_of(row: dict) -> float:
    """取这条资产的持股比例；工商各源字段名不统一，按常见键依次认。"""
    extra = row.get("extra")
    if not isinstance(extra, dict):
        try:
            extra = json.loads(row.get("extra_json") or "{}")
        except Exception:
            extra = {}
    for key in ("ratio", "percent", "invest_ratio", "hold_ratio", "share_ratio"):
        val = extra.get(key)
        if val in (None, ""):
            continue
        try:
            return float(str(val).replace("%", "").strip())
        except (TypeError, ValueError):
            continue
    return 0.0


def _export_filters(**raw: Any) -> dict[str, Any]:
    """筛选项归一：空串不参与过滤，否则 ``WHERE root_domain=''`` 会查成空表。"""
    out: dict[str, Any] = {}
    for key, val in raw.items():
        if val in (None, "", 0):
            continue
        out[key] = val
    return out


def _export_rows(name: str, kind: str = "", ratio: float = 0.0, **filters: Any) -> list[dict]:
    """按分表口径取行；``ratio`` 大于 0 时只留控股比例到这档的（子公司表筛控股用）。"""
    conf = EXPORT_SHEETS.get(name) or EXPORT_SHEETS["all"]
    # 一张分表可能对应多个 kind（APP 有本机解包和工商两个来源），逐个查再拼一张表。
    # 调用方明确给了 kind 就只导那一个。
    wanted = [kind] if kind else (list(conf["kinds"]) or [""])
    clean = _export_filters(**filters)
    rows: list[dict] = []
    for one in wanted:
        rows.extend(store.query_assets(kind=one or None, limit=100000, **clean))
    if ratio and ratio > 0 and name in RATIO_SHEETS:
        rows = [r for r in rows if _ratio_of(r) >= float(ratio)]
    return rows


@app.get("/api/export/sheets")
def export_sheets(request: Request, task_id: str = "", root_domain: str = "",
                  keyword: str = "", host: str = "", ip: str = "",
                  ratio: float = 0.0) -> dict:
    """分表清单 + 各自条数：前端「分类导出」直接按这个渲染成多表清单。

    条数按去重资产算，和资产页、任务列表同一个口径；空表也返回，方便看着勾。
    ``ratio`` 给控股 / 对外投资 / 股东这几张表按控股比例筛，条数跟着变。
    """
    current_user(request)
    clean = _export_filters(task_id=task_id, root_domain=root_domain,
                            keyword=keyword, host=host, ip=ip)
    # 一条 GROUP BY 数完所有类型：以前每张表都拉 10 万行只为数长度，整页要 2.6s
    kind_counts = store.asset_kind_counts(**clean)
    total = sum(kind_counts.values())
    gate = max(float(ratio or 0), 0.0)
    items = []
    for key, conf in EXPORT_SHEETS.items():
        kinds = [str(k) for k in (conf["kinds"] or [])]
        if key in RATIO_SHEETS and gate:
            count = store.count_assets(kinds=kinds or None, min_ratio=gate, **clean)
        elif kinds:
            count = sum(int(kind_counts.get(k, 0)) for k in kinds)
        else:
            count = total
        items.append({"key": key, "label": conf["label"], "cols": conf["cols"],
                      "kinds": kinds, "count": count,
                      "ratio": key in RATIO_SHEETS})
    return {"ok": True, "items": items}


@app.get("/api/export")
def export(request: Request, fmt: str = "csv", sheet: str = "all", kind: str = "",
                 root_domain: str = "", task_id: str = "", keyword: str = "", host: str = "",
                 ip: str = "", port: int = 0, cdn: str = "", ratio: float = 0.0) -> Response:
    """资产导出：csv / json / jsonl，``sheet`` 决定导哪张表。

    ``all`` 是全量宽表，其余分表只放一类资产、列按该类资产的口径给（APP / 小程序 /
    备案 / 企业 / 微博 / 公众号 / 分支机构 / 测绘）。筛选参数对所有分表都生效，
    ``ratio`` 只对带持股比例的分表（控股企业 / 对外投资 / 股东）有意义。
    """
    user = current_user(request)
    name = (sheet or "all").lower()
    if name not in EXPORT_SHEETS:
        name = "all"
    conf = EXPORT_SHEETS[name]
    rows = _export_rows(name, kind=kind, ratio=ratio, root_domain=root_domain,
                        task_id=task_id, keyword=keyword, host=host, ip=ip,
                        port=port, cdn=cdn)
    audit("export", f"{name} {fmt} rows={len(rows)}", user=user)
    fmt = (fmt or "csv").lower()
    items = [_export_row(dict(r)) for r in rows]
    if fmt in ("json", "jsonl"):
        if fmt == "jsonl":
            buf = io.StringIO()
            for it in items:
                buf.write(json.dumps(it, ensure_ascii=False) + "\n")
            return Response(content=buf.getvalue(), media_type="application/x-ndjson; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename=arlx_{name}.jsonl"})
        return Utf8JSONResponse(items)
    cols = conf["cols"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(cols)
    for i, it in enumerate(items, 1):
        # ID 是行号：表里没有这条资产的编号时，序号比空列好读
        w.writerow([i if c == "ID" else (it.get(c) or "") for c in cols])
    # BOM 加上 Excel 才把中文当 UTF-8 读；不加打开就是一堆乱码
    data = "\ufeff" + buf.getvalue()
    return Response(content=data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=arlx_{name}.csv"})


_CELL_BAD = dict.fromkeys(list(range(0x00, 0x09)) + [0x0b, 0x0c] + list(range(0x0e, 0x20)))


def _cell_safe(value: Any, limit: int = 32000) -> str:
    """xlsx 单元格：去掉控制字符（openpyxl 会直接抛错），超长截断。"""
    text = "" if value is None else str(value)
    text = text.translate(_CELL_BAD)
    return text[:limit]


# 工作表名另有禁用字符（\ / * ? : [ ]），碰上 openpyxl 直接 ValueError
_SHEET_BAD = str.maketrans({c: "-" for c in "\\/*?:[]"})
# reserve 给 Excel 自动补重名时加的 "(2)" 后缀
_sheet_seen: dict = {}


def _sheet_title(value: Any, limit: int = 28) -> str:
    """工作表名：剔掉 Excel 禁用字符，压到 31 字以内并保证同名唯一。"""
    text = _cell_safe(value, 400).translate(_SHEET_BAD).replace("'", "·").strip()
    text = text or "Sheet"
    base = text[:limit]
    n = _sheet_seen.get(base, 0)
    _sheet_seen[base] = n + 1
    return base if not n else f"{base}({n + 1})"


@app.get("/api/export/xlsx")
def export_xlsx(request: Request, task_id: str = "", root_domain: str = "",
                      keyword: str = "", host: str = "", ip: str = "", cdn: str = "",
                      ratio: float = 0.0, sheets: str = "") -> Response:
    """一次导出多张表：子公司 / 对外投资 / ICP / 企业 / 站点 / APP / 小程序…各占一个工作表。

    默认把非空分表都写进同一个工作簿（空表跳过，不塞一堆只有表头的页）；
    ``sheets`` 用逗号点名时只导点到的那几张。``ratio`` 给控股类分表筛控股比例。
    """
    user = current_user(request)
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
    except Exception:
        raise HTTPException(status_code=500, detail="服务端缺少 openpyxl，无法导出 xlsx")

    picked = [s.strip().lower() for s in (sheets or "").split(",") if s.strip()]
    picked = [s for s in picked if s in EXPORT_SHEETS]
    if not picked:
        picked = [k for k in EXPORT_SHEETS if k != "all"]
    filters = dict(task_id=task_id, root_domain=root_domain, keyword=keyword,
                   host=host, ip=ip, cdn=cdn)

    wb = Workbook()
    wb.remove(wb.active)
    _sheet_seen.clear()
    head_font = Font(bold=True, color="FFFFFF")
    head_fill = PatternFill("solid", fgColor="2F5D8A")
    written: list[str] = []
    total = 0
    for key in picked:
        conf = EXPORT_SHEETS[key]
        if key == "all":
            continue
        rows = _export_rows(key, ratio=ratio if key in RATIO_SHEETS else 0.0,
                            **filters)
        if not rows:
            continue
        items = [_export_row(dict(r)) for r in rows]
        cols = conf["cols"]
        ws = wb.create_sheet(title=_sheet_title(conf["label"]) or key)
        ws.append([_cell_safe(c, 120) for c in cols])
        for cell in ws[1]:
            cell.font = head_font
            cell.fill = head_fill
            cell.alignment = Alignment(vertical="center")
        for i, it in enumerate(items, 1):
            ws.append([_cell_safe(i if c == "ID" else (it.get(c) or "")) for c in cols])
        for idx, col in enumerate(cols, 1):
            width = max(10, min(42, max([len(str(col))] + [len(_cell_safe(it.get(col) or "", 60))
                                                           for it in items[:200]])))
            ws.column_dimensions[ws.cell(row=1, column=idx).column_letter].width = width
        ws.freeze_panes = "A2"
        written.append(key)
        total += len(items)
    if not written:
        # 一张都没数据时也给个工作簿，写明为什么空，省得以为是导出坏了
        ws = wb.create_sheet(title="说明")
        ws.append(["本次筛选下没有可导出的资产"])
        ws.append(["换个任务、根域或控股比例再试"])
    buf = io.BytesIO()
    wb.save(buf)
    audit("export", f"xlsx sheets={','.join(written) or '-'} rows={total}", user=user)
    fname = f"arlx_assets_{int(time.time())}.xlsx"
    return Response(content=buf.getvalue(),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ─────────────── 通用查询（空间测绘任意语法）───────────────
@app.post("/api/search")
async def search(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    query = (body.get("query") or "").strip()
    engine = (body.get("engine") or "fofa").lower()
    size = int(body.get("size") or 100)
    if not query:
        raise HTTPException(status_code=400, detail="query 为空")
    if engine == "fofa":
        recs = await fofa_search(query, size=size)
        return {"ok": True, "engine": engine, "count": len(recs), "items": recs}
    return {"ok": False, "msg": f"引擎 {engine} 暂只支持 FOFA 通用查询"}


# ─────────────── 总览 / 资产组 / 分面 ───────────────
@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "app": "suoyu", "version": "2.8.0", "ts": time.time()}


@app.get("/api/version")
def version() -> dict:
    return {"ok": True, "app": "天鉴·索舆", "version": "2.8.0", "build": "2026.11"}


@app.get("/api/throttle")
def throttle_state(request: Request) -> dict:
    """各来源当前的节流 / 冷却状态，给「细节可控」页和任务日志对照用。"""
    current_user(request)
    sec = config.section("throttle") or {}
    return {"ok": True, "config": {k: v for k, v in sec.items() if k != "per_source"},
            "per_source": sec.get("per_source") or {},
            "state": throttle.snapshot()}


THROTTLE_NUM = {
    # 键: (最小, 最大, 是否取整)
    "min_interval": (0.0, 120.0, False),
    "max_interval": (0.0, 300.0, False),
    "concurrent": (1, 8, True),
    "risk_threshold": (1, 20, True),
    "cooldown": (5.0, 3600.0, False),
    "cooldown_max": (30.0, 7200.0, False),
}


@app.post("/api/throttle")
def throttle_save(request: Request, patch: dict = Body(...)) -> dict:
    """改节流口径：全局间隔 / 并发 / 熔断阈值 / 冷却，以及单来源的间隔。

    改完立刻生效（节流器每次取许可都读配置），不用重启服务。
    单个来源只开放间隔两项：并发和熔断按全局走，避免一个来源把队伍堵死。
    """
    user = current_user(request)
    body = dict(patch or {})
    clean: dict = {}
    for key, (lo, hi, is_int) in THROTTLE_NUM.items():
        if key not in body:
            continue
        try:
            val = float(body[key])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"{key} 得是数字")
        val = min(hi, max(lo, val))
        clean[key] = int(round(val)) if is_int else round(val, 2)
    if "enabled" in body:
        clean["enabled"] = bool(body["enabled"])
    per = body.get("per_source")
    if isinstance(per, dict):
        old = (config.section("throttle") or {}).get("per_source") or {}
        merged = dict(old)
        for name, item in per.items():
            # 传 null 表示这条来源跟随全局。存成 null 而不是删键：
            # 默认配置里本来就写了这条来源的间隔，删键后重载配置会被默认值补回来
            if item is None:
                merged[str(name)] = None
                continue
            if not isinstance(item, dict):
                continue
            row = dict(merged.get(name) or {})
            for key, (lo, hi, is_int) in (("min_interval", THROTTLE_NUM["min_interval"]),
                                          ("max_interval", THROTTLE_NUM["max_interval"])):
                if key not in item:
                    continue
                try:
                    val = float(item[key])
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail=f"{name}.{key} 得是数字")
                row[key] = min(hi, max(lo, round(val, 2)))
            if row.get("min_interval") is not None and row.get("max_interval") is not None \
                    and row["max_interval"] < row["min_interval"]:
                row["max_interval"] = row["min_interval"]
            merged[str(name)] = row
        clean["per_source"] = merged
    if clean.get("min_interval") is not None and clean.get("max_interval") is not None \
            and clean["max_interval"] < clean["min_interval"]:
        clean["max_interval"] = clean["min_interval"]
    if not clean:
        raise HTTPException(status_code=400, detail="没有可改的节流参数")
    # 整段替换而不是深合并：深合并只加键不删键，per_source 里删掉的来源会被旧配置复活
    full = config.section("throttle") or {}
    for key, val in clean.items():
        full[key] = val
    config.replace_section("throttle", full)
    config.reload()
    audit("throttle_update", json.dumps(list(clean.keys()), ensure_ascii=False), user=user)
    sec = config.section("throttle") or {}
    return {"ok": True, "config": {k: v for k, v in sec.items() if k != "per_source"},
            "per_source": sec.get("per_source") or {}, "state": throttle.snapshot()}


@app.post("/api/throttle/reset")
def throttle_reset(request: Request) -> dict:
    """清空节流状态：换了账号或熔断误判后手工解封，不用重启服务。"""
    current_user(request)
    throttle.reset()
    return {"ok": True, "state": throttle.snapshot()}


@app.get("/api/overview")
def overview(request: Request) -> dict:
    current_user(request)
    return {"ok": True, **store.overview()}


@app.get("/api/groups")
def groups(request: Request, keyword: str = "", limit: int = 300,
                 by: str = "root") -> dict:
    """资产分组：by=root 按根域（全局视角），by=task 按任务（一个任务一组）"""
    current_user(request)
    if by == "task":
        return {"ok": True, "by": "task", "items": store.list_task_groups(keyword, limit)}
    return {"ok": True, "by": "root", "items": store.list_roots(keyword, limit)}


# ─────────────── 指纹（内置库 + 模板库 + 自定义增量）───────────────
@app.get("/api/fingerprints")
async def fingerprints(request: Request, keyword: str = "", tag: str = "",
                       limit: int = 300, offset: int = 0) -> dict:
    """三路指纹一起给：名称库、模板库（含 matcher 种类与标签）、自定义。

    模板库首次加载要几秒，放到线程里跑，避免卡住事件循环。
    """
    current_user(request)
    builtin = []
    try:
        builtin = [{"name": n, "tag": "内置", "kind": "webapp"} for n in FingerPrint().apps]
    except Exception:
        builtin = []

    tpl_all, tpl_stats = [], {}
    try:
        from .engine.http_engine import webfp_engine

        eng = await asyncio.to_thread(webfp_engine)
        if eng is not None:
            tpl_stats = eng.stats()
            tpl_all = list(eng.templates)
    except Exception:
        tpl_all, tpl_stats = [], {}

    tags: dict[str, int] = {}
    for t in tpl_all:
        for g in t.tags:
            tags[g] = tags.get(g, 0) + 1

    kw, want = (keyword or "").lower(), (tag or "").lower()
    if kw:
        builtin = [b for b in builtin if kw in b["name"].lower()]
    tpl_hit = [t for t in tpl_all
               if (not kw or kw in t.name.lower() or kw in t.tid.lower())
               and (not want or want in [g.lower() for g in t.tags])]
    rows = [{"id": t.tid, "name": t.name, "tags": t.tags, "severity": t.severity,
             "paths": t.paths[:4], "condition": t.condition,
             "matchers": [m.kind for m in t.matchers],
             "matcher_total": len(t.matchers)}
            for t in tpl_hit[offset: offset + max(1, int(limit))]]
    custom = store.list_fingerprints()
    if kw:
        custom = [c for c in custom if kw in (c.get("name") or "").lower()]
    return {"ok": True, "builtin": builtin[: int(limit)], "builtin_total": len(builtin),
            "templates": rows, "template_total": len(tpl_hit),
            "template_all": len(tpl_all), "tpl_stats": tpl_stats,
            "tags": sorted(({"tag": k, "count": v} for k, v in tags.items()),
                           key=lambda x: -x["count"])[:40],
            "custom": custom, "count": len(builtin) + len(tpl_hit) + len(custom)}


@app.post("/api/fingerprints")
def add_fingerprint(request: Request, body: dict = Body(...)) -> dict:
    user = current_user(request)
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="指纹名为空")
    store.save_fingerprint(body)
    audit("fingerprint_save", name, user=user)
    return {"ok": True}


@app.delete("/api/fingerprints/{name}")
def del_fingerprint(request: Request, name: str) -> dict:
    current_user(request)
    store.delete_fingerprint(name)
    return {"ok": True}


@app.post("/api/fingerprints/verify")
async def verify_fingerprint(request: Request, body: dict = Body(...)) -> dict:
    """拿一条 URL 现场验证：名称库与模板库的命中都算"""
    current_user(request)
    from .engine.http_engine import probe

    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url 为空")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    info = await probe(url)
    detail = getattr(info, "web_fp_detail", None) or []
    return {"ok": True, "status_code": getattr(info, "status", 0),
            "title": getattr(info, "title", ""),
            "fingerprints": getattr(info, "fingerprint", []) or [],
            "template_hits": [{"name": d.get("name"), "tags": d.get("tags"),
                               "evidence": (d.get("evidence") or [])[:6]} for d in detail[:30]],
            "server": getattr(info, "server", ""), "error": getattr(info, "error", "")}


# ─────────────── AI 工坊 ───────────────
AI_FEATURES = [
    {"key": "query_gen", "label": "测绘语法生成", "desc": "自然语言 / 企业名 → FOFA / Hunter / Quake / ZoomEye 可直接执行的检索语法"},
    {"key": "triage", "label": "资产研判排序", "desc": "把当前资产库按侦察价值排序，给出「为什么先看它」"},
    {"key": "summary", "label": "任务侦察小结", "desc": "一个任务跑完，自动写业务面、入口和下一步"},
    {"key": "fingerprint", "label": "指纹规则建议", "desc": "给一个网站 URL，从标题 / 头 / 正文反推可匹配的正则"},
    {"key": "entity", "label": "企业别名扩展", "desc": "公司全称 → 简称 / 英文名 / 产品 / App；任务 P1 阶段勾选「AI 关键词扩展」即启用"},
]


@app.get("/api/ai/status")
async def ai_status(request: Request) -> dict:
    current_user(request)
    st = ai_engine.status()
    return {"ok": True, **st, "features": AI_FEATURES,
            "switches": {"ai_search": bool(config.get("deep", "ai_search")),
                         "ai_triage": bool(config.get("deep", "ai_triage"))}}


@app.post("/api/ai/test")
async def ai_test(request: Request) -> dict:
    current_user(request)
    return await ai_engine.test()


@app.post("/api/ai/query")
async def ai_query(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="请填写目标或描述")
    try:
        return {"ok": True, **(await ai_engine.generate_query(text, body.get("engine") or "fofa"))}
    except ai_engine.AIError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/ai/triage")
async def ai_triage(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    try:
        return {"ok": True, **(await ai_engine.triage(kind=body.get("kind") or "",
                                                     root_domain=body.get("root_domain") or "",
                                                     limit=int(body.get("limit") or 120)))}
    except ai_engine.AIError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/ai/summary")
async def ai_summary(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    task_id = (body.get("task_id") or "").strip()
    if not task_id:
        raise HTTPException(status_code=400, detail="缺少 task_id")
    try:
        return {"ok": True, **(await ai_engine.summarize_task(task_id))}
    except ai_engine.AIError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/ai/fingerprint")
async def ai_fingerprint(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="请输入 URL")
    try:
        return {"ok": True, **(await ai_engine.suggest_fingerprint(url))}
    except ai_engine.AIError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ─────────────── 空间测绘 ───────────────
SPACE_ENGINES = [
    {"name": "fofa", "label": "FOFA", "need": ["key"], "doc": "https://fofa.info", "official": "https://fofa.info"},
    {"name": "hunter", "label": "Hunter 奇安信", "need": ["key"], "doc": "https://hunter.qianxin.com", "official": "https://hunter.qianxin.com"},
    {"name": "quake", "label": "Quake 360", "need": ["key"], "doc": "https://quake.360.net", "official": "https://quake.360.net"},
    {"name": "zoomeye", "label": "ZoomEye 知道创宇", "need": ["key"], "doc": "https://www.zoomeye.org", "official": "https://api.zoomeye.org"},
    {"name": "shodan", "label": "Shodan", "need": ["key"], "doc": "https://shodan.io", "official": "https://api.shodan.io"},
    {"name": "censys", "label": "Censys", "need": ["id", "secret"], "doc": "https://search.censys.io", "official": "https://search.censys.io"},
]


def _norm_official(eng: dict, sec: dict) -> str:
    """该引擎官方地址：用户填了 api 就用它，否则用内置默认"""
    return (sec.get("api") or "").strip().rstrip("/") or eng["official"]


@app.get("/api/space/engines")
def space_engines(request: Request) -> dict:
    current_user(request)
    out = []
    for e in SPACE_ENGINES:
        sec = config.section("sources").get(e["name"], {}) or {}
        ready = all(sec.get(k) for k in e["need"]) and sec.get("enabled", True)
        out.append({**e, "ready": bool(ready),
                    "base": src_base(e["name"], e["official"]),
                    "official": _norm_official(e, sec),
                    "via_relay": bool((sec.get("relay") or "").strip()),
                    "keys": len(space_mod.keys_of(e["name"])),
                    "fields": list(space_mod.FIELD_MATRIX.get(e["name"], ())),
                    "queryable": e["name"] in space_mod.QUERY_FUNCS})
    return {"ok": True, "items": out}


@app.get("/api/space/probe")
async def space_probe(request: Request, engine: str = "", query: str = "") -> dict:
    """连通测试：真打一次最小查询，回报耗时与平台错误原文。

    只填了 key 不代表能用——账号状态和额度只有打一次才知道。
    """
    current_user(request)
    name = (engine or "").strip().lower()
    if not name:
        raise HTTPException(status_code=400, detail="缺少 engine")
    res = await space_mod.probe(name, query, 1)
    return {"ok": bool(res.get("ok")), **res,
            "msg": res.get("error") or f"可用，命中 {res.get('total')} 条"}


@app.get("/api/space/probe-all")
async def space_probe_all(request: Request) -> dict:
    """把已配置 key 的引擎挨个打一次，返回可用/不可用清单。"""
    current_user(request)
    sec_all = config.section("sources") or {}
    names = [e["name"] for e in SPACE_ENGINES
             if e["name"] in space_mod.QUERY_FUNCS
             and (sec_all.get(e["name"], {}) or {}).get("key")]
    got = await asyncio.gather(*(space_mod.probe(n, "", 1) for n in names),
                               return_exceptions=True)
    items = []
    for n, item in zip(names, got):
        if isinstance(item, dict):
            items.append(item)
        else:
            items.append({"engine": n, "ok": False,
                          "error": f"{type(item).__name__}: {item}"})
    return {"ok": True, "count": len(items),
            "usable": [i["engine"] for i in items if i.get("ok")],
            "items": items}


@app.get("/api/space/syntax")
def space_syntax(request: Request, platform: str = "", keyword: str = "") -> dict:
    """内置测绘语法模板（OA / 中间件 / 框架 / 备案过滤），可按平台筛选"""
    current_user(request)
    items = space_mod.templates(platform, keyword)
    return {"ok": True, "count": len(items), "items": items}


@app.get("/api/space/complete")
async def space_complete(request: Request, text: str = "", cursor: int = -1,
                         engine: str = "fofa") -> dict:
    """查询语法位置感知补全：字段名 / 取值 / 算子；取值会叠加引擎实时热点榜"""
    current_user(request)
    res = space_mod.complete(text, None if cursor < 0 else cursor, engine)
    if res.get("kind") == "value":
        field = res.get("field") or ""
        word = res.get("word") or ""
        if field in ("app", "product", "protocol"):
            from .engine.sources.passive import fofa_suggest

            live = await fofa_suggest(field, word, limit=20)
            have = {it["label"] for it in res.get("items") or []}
            extra = [{"label": v, "insert": v, "kind": "value", "field": field}
                     for v in live.get("rows") or [] if v not in have]
            if extra:
                res["items"] = (extra + list(res.get("items") or []))[:30]
    return {"ok": True, **res}


@app.post("/api/space/search")
async def space_search(request: Request, body: dict = Body(...)) -> dict:
    """多引擎统一检索：同一句语法送一家或多家平台，字段归一化后返回"""
    current_user(request)
    query = (body.get("query") or "").strip()
    engine = (body.get("engine") or "").lower()
    engines = [str(e).lower() for e in (body.get("engines") or []) if str(e).strip()]
    size = min(int(body.get("size") or 100), 1000)
    if not query:
        raise HTTPException(status_code=400, detail="query 为空")
    if engine and engine not in engines:
        engines.insert(0, engine)
    if not engines:
        engines = ["fofa"]
    unknown = [e for e in engines if e not in space_mod.QUERY_FUNCS]
    if unknown:
        raise HTTPException(status_code=400,
                            detail=f"不支持的引擎：{', '.join(unknown)}；"
                                   f"可用：{', '.join(space_mod.QUERY_FUNCS)}")
    if len(engines) == 1:
        res = await space_mod.search(engines[0], query, size)
        data = res.as_dict()
        return {"ok": res.ok, **data, "engine": res.engine, "items": res.rows,
                "msg": res.error}
    many = await space_mod.search_many(engines, query, size)
    groups = [r.as_dict() for r in many]
    merged: list[dict] = []
    seen: set[str] = set()
    for r in many:
        for rec in r.rows:
            key = f"{rec.get('host')}|{rec.get('port')}"
            if key in seen:
                continue
            seen.add(key)
            merged.append(rec)
    failed = [f"{g['engine']}: {g['error']}" for g in groups if g["error"]]
    return {"ok": bool(merged) or not failed, "query": query, "count": len(merged),
            "items": merged, "groups": groups,
            "msg": "; ".join(failed) if failed else ""}


@app.post("/api/space/add-targets")
async def space_add_targets(request: Request, body: dict = Body(...)) -> dict:
    """把测绘结果一键转成新任务目标（只取 host，去重后建任务）"""
    user = current_user(request)
    hosts = body.get("hosts") or []
    rows = body.get("rows") or []
    if rows:
        hosts = list(hosts) + space_mod.harvest_hosts(
            [space_mod.SpaceResult("", "", rows=[r for r in rows if isinstance(r, dict)])])
    targets = sorted({str(h).split("://")[-1].split("/")[0].split(":")[0]
                      for h in hosts if str(h).strip()})
    if not targets:
        raise HTTPException(status_code=400, detail="没有可用的目标")
    options = body.get("options") or {}
    task_id = await pipeline.start_task(targets, options, body.get("name") or "测绘转入")
    audit("space_to_task", ",".join(targets[:10]), task_id, user=user)
    return {"ok": True, "task_id": task_id, "count": len(targets)}


# ─────────────── 企业主体 ───────────────
@app.post("/api/enterprise/search")
async def enterprise_search(request: Request, body: dict = Body(...)) -> dict:
    """公司名 / 域名 → 主体信息（ICP、全资子公司、别名、应用、域名清单）"""
    current_user(request)
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="请输入公司名或域名")
    info = await enterprise.collect_entity(target)
    return {"ok": True, **info}


@app.post("/api/enterprise/children")
async def enterprise_children(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="请输入公司名")
    children = await enterprise.expand_sub_company(name)
    return {"ok": True, "items": children, "count": len(children)}


@app.post("/api/enterprise/equity")
async def enterprise_equity(request: Request, body: dict = Body(...)) -> dict:
    """股权穿透：投资链路（层级 + 累计持股）+ 股东 + 分支机构 + 软著。

    `full_owned` 是可直接进挖掘池的全资主体，`partial` 是参股/联营（默认不挖，
    写错主体的洞投不进本 SRC）。

    参数与「单项执行 → 股权穿透」那一份对齐：间隔 / 额度 / 重试 / 来源 / 上游层数
    都能在这里单独给。慢节奏拉取（30 秒一次）必须能单独调，否则一定被风控截断。
    """
    current_user(request)
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="请输入公司名")

    def _num(key: str, cast=float, lo=None, hi=None):
        """可选数值参数：没给就返 None，让 ``collect()`` 回落到配置。"""
        raw = body.get(key)
        if raw is None or raw == "":
            return None
        try:
            v = cast(raw)
        except (TypeError, ValueError):
            return None
        if lo is not None:
            v = max(lo, v)
        if hi is not None:
            v = min(hi, v)
        return v

    eq = await equity.collect(
        name,
        depth=int(_num("depth", int, 1, 4) or 2),
        ratio=float(_num("ratio", float, 1.0, 100.0) or 100.0),
        ubo_threshold=_num("ubo_threshold", float, 1.0, 100.0),
        ubo_levels=_num("ubo_levels", int, 0, 4),
        branches=bool(body.get("branch", True)),
        sources=[str(s) for s in (body.get("sources") or [])] or None,
        gap=_num("gap", float, 0.0, 300.0) or _num("sleep", float, 0.0, 300.0),
        retry=_num("retry", int, 1, 10),
        budget=_num("budget", int, 0, 2000),
    )
    return {"ok": True, **eq.as_dict()}


# ─────────────── 移动端：小程序 / App ───────────────
@app.post("/api/mobile/search")
async def mobile_search(request: Request, body: dict = Body(...)) -> dict:
    """应用名 / 包名 / 本地 apk-ipa → 应用清单 + 自有域 + 第三方 SDK 域（不需要 key，也不需要 AI）"""
    current_user(request)
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="请输入应用名或包名")
    res = await mobile.collect_apps(target, package_path=(body.get("package_path") or "").strip(),
                                    limit=int(body.get("limit") or 8))
    return {"ok": True, **res}


@app.post("/api/applet/search")
async def applet_search(request: Request, body: dict = Body(...)) -> dict:
    """小程序名 / 主体名 / wx 开头 AppID → 小程序档案 + 域名（不需要 key，也不需要 AI）"""
    current_user(request)
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="请输入小程序名、主体名或 AppID")
    res = await applet_mod.collect_applets(target, limit=int(body.get("limit") or 8))
    return {"ok": True, **res}


@app.post("/api/mp/search")
async def mp_search_api(request: Request, body: dict = Body(...)) -> dict:
    """公众号名 / 主体名 / 品牌 / gh_ / __biz / 文章链接 → 公众号档案 + 正文域。

    认证主体不走公开通道（需要微信客户端），返回里带 `subject_source` 说明来源，
    昵称对不上检索词的结果标成 low 相关但保留，交给调用方自己判断。
    """
    current_user(request)
    from .engine.collectors import mp as mp_mod

    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="请输入公众号名、主体名或文章链接")
    res = await mp_mod.collect_mps(target, limit=int(body.get("limit") or 8))
    return {"ok": True, **res}


@app.get("/api/applet/local")
async def applet_local(request: Request, appid: str = "", limit: int = 20,
                       target: str = "", unpack: bool = True,
                       max_pkgs: int = 6, workers: int = 6) -> dict:
    """扫本机微信小程序缓存：解密 → 解包 → 抽接口/域名/密钥命中。

    纯离线，不联网也不需要登录态；只读当前用户目录下的包文件。
    给了 `target` 就按包内标题/主体/域名打分（`match=high` 才算对得上），
    `unpack` 打开时把包解到 data/applet 下并把压缩脚本美化一份。
    """
    current_user(request)
    from .engine.collectors import wxscan

    root = DATA_DIR / "applet" / "local" if unpack else None
    res = await asyncio.to_thread(wxscan.scan_local_mini, appid=appid.strip(),
                                  limit=max(1, min(int(limit or 20), 100)),
                                  target=target.strip(),
                                  max_pkgs=max(1, min(int(max_pkgs or 6), 16)),
                                  workers=max(1, min(int(workers or 6), 16)),
                                  out_root=str(root) if root else "", unpack=bool(unpack))
    return {"ok": True, **res}


# ─────────────── 一键收集全 ───────────────
# 预设把这几项都写全：前端拿预设套开关时，缺键会落成 undefined，
# 提交时就变成 false（现场表现：标着「深度侦察」，日志却写「字典爆破未启用」，
# 26 个被动源只跑在母公司一个域上）。写全了，谁读都不会漏。
_ONECLICK_COMMON = {"domain_dict": "domain_2w.txt", "domain_brute": True,
                    "site_spider": True, "asn_expand": True}
ONECLICK_PRESETS = {
    "quick": {"label": "快速侦察", "desc": "15 分钟内出结果：免费被动源 + 字典爆破 1 万 + TOP100 端口",
              "options": {**_ONECLICK_COMMON, "port_type": "top100",
                          "file_leak": False, "sibling": False, "deep": False, "vhost_collision": False}},
    "standard": {"label": "标准侦察", "desc": "被动全源 + 全字典 + TOP100 端口 + 爬虫 + 敏感文件 + 旁站",
                 "options": {**_ONECLICK_COMMON, "port_type": "top100",
                             "file_leak": True, "sibling": True, "deep": True, "vhost_collision": False}},
    "deep": {"label": "深度侦察", "desc": "标准 + TOP1000 端口 + VHost 碰撞 + 代码泄露 + 邮箱 + 存储桶",
             "options": {**_ONECLICK_COMMON, "port_type": "top1000",
                         "file_leak": True, "sibling": True, "deep": True, "vhost_collision": True}},
    "hunt": {"label": "资产监控", "desc": "只挖新增：浅端口 + 爬虫 + 变更对比，适合周期跑",
             "options": {**_ONECLICK_COMMON, "port_type": "top10",
                         "file_leak": False, "sibling": False, "deep": False, "vhost_collision": False}},
}


@app.get("/api/oneclick/presets")
def oneclick_presets(request: Request) -> dict:
    current_user(request)
    return {"ok": True, "items": [{"key": k, **v} for k, v in ONECLICK_PRESETS.items()]}


def _empty_reason(seeds: list[str], entities: list[dict], mobile_hits: dict) -> str:
    """三条路全空时给用户看的一句话：把每一步的真实原因串起来，不含糊成「无结果」。"""
    parts: list[str] = []
    for ent in entities:
        if ent.get("error"):
            parts.append(f"主体扩线失败：{ent['error']}")
            continue
        why = [n for n in (ent.get("notes") or []) if any(
            k in n for k in ("挡", "冷却", "频控", "风控", "没有登记", "无解析", "异常"))]
        if why:
            parts.append(f"{ent.get('name')}：{why[0]}")
        elif not ent.get("domains"):
            parts.append(f"{ent.get('name')}：没有拿到候选域名")
    for n in (mobile_hits.get("notes") or [])[:2]:
        parts.append(f"移动端：{n}")
    if not parts:
        return f"「{'、'.join(seeds[:3])}」这一轮没有解析出可扫描的目标"
    return "；".join(parts[:4])


def _miss_reason(entities: list[dict], dropped: int) -> str:
    """任务下发了，但一条域名都没确认时给的一句话。

    这时候返回 200 会让界面显示「已下发」，用户以为在挖，其实只拿企业名原词
    跑了一轮，一个域名都没进去。说清卡在哪一步，比给个成功更诚实。
    """
    parts: list[str] = []
    for ent in entities:
        why = [n for n in (ent.get("notes") or []) if any(
            k in n for k in ("挡", "冷却", "频控", "风控", "没有登记", "无解析", "异常", "证据不足"))]
        if why:
            parts.append(f"{ent.get('name')}：{why[0]}")
    if dropped:
        parts.append(f"{dropped} 个候选域证据不足未确认，只按企业名原词下发")
    return "；".join(parts[:3])


@app.post("/api/oneclick")
async def oneclick(request: Request, body: dict = Body(...)) -> dict:
    """一键收集全：企业名 / 域名 / IP 混着丢进来，自动分派

    * 企业名 → 先企业主体扩（ICP + 全资子公司 + AI 别名）得到域名清单
    * 域名 / IP → 直接当目标
    * 最终合成一个任务下发，保证同一轮里的资产能互相对比
    """
    user = current_user(request)
    raw = body.get("targets") or ""
    if isinstance(raw, list):
        raw = "\n".join(str(t) for t in raw)
    seeds = [s.strip() for s in raw.replace(",", "\n").replace("，", "\n").split("\n") if s.strip()]
    if not seeds:
        raise HTTPException(status_code=400, detail="目标为空")

    preset = ONECLICK_PRESETS.get((body.get("preset") or "standard").lower())
    options = dict(preset["options"]) if preset else {}
    options.update(body.get("options") or {})
    # 前端可以按任务覆盖控股门槛；没给就用配置里的 scan.equity_ratio
    if body.get("equity_ratio") not in (None, ""):
        try:
            options["equity_ratio"] = float(body["equity_ratio"])
        except Exception:
            pass
    # 最终受益人的控制线同理：一次任务想按 30% 看实控人，不必改全局配置
    if body.get("equity_ubo_threshold") not in (None, ""):
        try:
            options["equity_ubo_threshold"] = float(body["equity_ubo_threshold"])
        except Exception:
            pass

    # 五步勾选：p1 主体 / p2 域名 / p3 测绘 / p4 探测 / p5 深挖。
    # 前端默认全选；全选时不写 steps，老任务与外部调用照旧走完整流程。
    raw_steps = body.get("steps")
    if isinstance(raw_steps, str):
        raw_steps = [s for s in raw_steps.replace("，", ",").split(",")]
    steps = [s for s in (raw_steps or []) if s in pipeline.ONECLICK_STEPS]
    steps = list(dict.fromkeys(steps))
    all_steps = len(steps) == len(pipeline.ONECLICK_STEPS)
    if steps and not all_steps:
        options["steps"] = steps

    # 企业名 / 域名 / IP 直接当目标下发，主体扩线、应用商店、小程序都进任务里跑。
    # 以前在这里同步等工商、商店、小程序回来，一个主体就要几十秒，前端早就断开了，
    # 用户看到的是「点了没反应、任务里什么都没有」。现在先把任务建出来，扩展结果边跑边入这个任务。
    targets = _normalize_targets(seeds)
    name = body.get("name") or f"一键收集-{seeds[0][:20]}"
    if preset:
        name = f"{name}（{preset['label']}）"
    task_id = await pipeline.start_task(
        targets, options, name,
        expand={"enterprise": bool(body.get("expand_enterprise", True)) and "p1" in (steps or pipeline.ONECLICK_STEPS),
                "mobile": (bool(body.get("expand_mobile", True)) and bool(options.get("mobile", True))
                           and "p1" in (steps or pipeline.ONECLICK_STEPS)),
                "seeds": seeds},
    )
    audit("oneclick", ",".join(seeds)[:200], task_id, user=user)
    return {"ok": True, "task_id": task_id, "targets": targets, "count": len(targets),
            "entities": [], "mobile": {"apps": [], "applets": [], "domains": [], "notes": []},
            "preset": body.get("preset") or "standard",
            "steps": steps or list(pipeline.ONECLICK_STEPS),
            "message": "任务已创建，主体扩线 / 应用 / 小程序正在后台展开，进度看任务详情"} 


def _normalize_targets(seeds: list[str]) -> list[str]:
    """域名 / IP 归一成 host，企业名原样保留：P0 靠企业名分派主体扩线。"""
    resolved: list[str] = []
    for d in seeds:
        d = d.strip()
        if not d:
            continue
        host = d.split("://")[-1].split("/")[0].split(":")[0]
        resolved.append(host if (is_ip(host) or is_valid_domain(host)) else d)
    return list(dict.fromkeys(resolved))


async def _oneclick_expand(task_id: str, runner, plan: dict) -> None:
    """一键收集的前置展开：企业主体 → 全资子公司域名；应用商店 / 小程序 → 包名与域名。

    结果写进本任务的资产表与日志，任务详情页的「本任务资产收集情况」就能看到这摊。
    """
    seeds = plan.get("seeds") or []

    def log(module: str, msg: str, level: str = "info"):
        try:
            runner.log(module, msg, level)
        except Exception:
            pass

    def save(item: dict):
        try:
            runner.save_asset(item)
        except Exception:
            pass

    extra: list[str] = []
    if plan.get("enterprise"):
        from .engine.pipeline_stages import _usable_subject_name
        for s in seeds[:6]:
            if is_ip(s) or is_valid_domain(s.replace(" ", "")):
                continue
            if not _usable_subject_name(s):
                continue
            # 超时被掐时只剩这份快照：已经过证据闸的域名 / 备案 / 控股子公司先收下。
            # 以前这里超时直接 continue，一整轮主体扩线查到的东西跟着协程一起消失，
            # 任务里就只剩「主体收集」几行日志，域名 / 端口 / 网页全空。
            snap: dict = {}

            def on_partial(part, _snap=snap):
                if isinstance(part, dict) and part:
                    _snap.update(part)

            truncated = False
            try:
                # 这一遍只做主体识别 + 域名取证，股权穿透交给后面的 P1c 专用阶段跑一次：
                # 两处都穿等于把同一份工商额度烧两遍，碰上需要 30 秒延时的大主体，
                # 第二遍必定被时限掐断，最后落地的东西比第一遍还少。
                info = await asyncio.wait_for(
                    enterprise.collect_entity(
                        s, equity_ratio=runner.opt_equity_ratio(), equity=False,
                        on_log=lambda mod, msg, lvl="info": log(mod, msg, lvl),
                        on_partial=on_partial,
                        budget_s=max(60.0, runner._entity_timeout() - 30)),
                    timeout=runner._entity_timeout())
            except Exception as e:
                info = dict(snap) if snap else None
                truncated = bool(info)
                if truncated:
                    log("enterprise", f"主体扩线到时限（{str(e)[:60]}），改用途中快照："
                                      f"{s} 域名 {len(info.get('domains') or [])} 个",
                        "warn")
                else:
                    log("enterprise", f"主体扩线失败 {s}: {str(e)[:120]}", "warn")
            if not isinstance(info, dict) or not info:
                continue
            if not truncated:
                # 留给 P0 复用：同一个任务里这个主体已经查过了，别再查第二遍。
                try:
                    runner.expand_entities[s] = info
                except Exception:
                    pass
            doms = info.get("domains") or []
            extra.extend(doms)
            src_note = "/".join(info.get("sources") or []) or ("途中快照" if truncated else "无")
            log("enterprise", f"{s} → 域名 {len(doms)} 个（来源 {src_note}）")
            for leaf in (info.get("equity") or [])[:60] if isinstance(info.get("equity"), list) else []:
                nm = leaf.get("name") if isinstance(leaf, dict) else None
                if nm:
                    save({"kind": "equity", "url": f"equity:{nm}", "host": "",
                          "title": str(nm)[:120],
                          "sources": ["equity"], "extra": {"parent": s}})
            for dom in doms[:80]:
                log("enterprise", f"主体带出域名 {dom}")

    if plan.get("mobile"):
        for s in seeds[:4]:
            if not _usable_mobile_seed(s):
                continue
            try:
                got = await mobile.collect_apps(s, limit=8)
            except Exception as e:
                log("mobile", f"App 采集失败 {s}: {str(e)[:80]}", "warn")
                continue
            items = got.get("items") or []
            for it in items[:20]:
                if not isinstance(it, dict):
                    continue
                label_txt = it.get("name") or it.get("title") or ""
                ident = it.get("pkg") or it.get("appid") or it.get("appId") or label_txt
                if not ident:
                    continue
                save({"kind": "mobile", "url": f"mobile:{ident}", "host": "",
                      "title": f"App {label_txt}".strip()[:120],
                      "sources": [it.get("source") or "store"],
                      "extra": {k: v for k, v in it.items() if k in
                                ("pkg", "appid", "appId", "developer", "version", "size", "url")}})
            doms = got.get("domains") or []
            extra.extend(doms)
            log("mobile", f"{s} → App {len(items)} 个 / 域名 {len(doms)} 个")
            for n in (got.get("notes") or [])[:3]:
                log("mobile", str(n)[:160], "warn")

    extra = [d for d in dict.fromkeys(extra) if d]
    if extra:
        try:
            runner.absorb_targets(extra)
        except Exception as e:
            log("target", f"扩展域名并入本轮失败: {str(e)[:100]}", "warn")


def _usable_mobile_seed(text: str) -> bool:
    """应用商店 / 小程序检索词：域名和 Latin 短词查不出东西，白耗网络。"""
    text = (text or "").strip()
    return bool(text) and "." not in text and not is_ip(text)


# 一键收集的展开要在任务内部跑，引擎那边留了挂点，这里注册进去
pipeline.oneclick_expand = _oneclick_expand


# ─────────────── 模板 / 计划 / 审计 ───────────────
@app.get("/api/templates")
def templates(request: Request) -> dict:
    current_user(request)
    return {"ok": True, "items": store.list_templates()}


@app.post("/api/templates")
def save_template(request: Request, body: dict = Body(...)) -> dict:
    current_user(request)
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="模板名为空")
    store.save_template(name, body.get("options") or {})
    return {"ok": True}


@app.delete("/api/templates/{name}")
def del_template(request: Request, name: str) -> dict:
    current_user(request)
    store.delete_template(name)
    return {"ok": True}


@app.get("/api/schedules")
def schedules(request: Request) -> dict:
    current_user(request)
    return {"ok": True, "items": store.list_schedules()}


@app.post("/api/schedules")
def save_schedule(request: Request, body: dict = Body(...)) -> dict:
    user = current_user(request)
    sid = body.get("id") or hashlib.md5(f"{time.time()}{body.get('target')}".encode()).hexdigest()[:12]
    item = {
        "id": sid, "name": body.get("name") or f"周期-{body.get('target')}",
        "target": body.get("target") or "",
        "options": body.get("options") or {},
        "interval_hours": int(body.get("interval_hours") or 24),
        "enabled": 1 if body.get("enabled", True) else 0,
        "next_run": time.time() + int(body.get("interval_hours") or 24) * 3600,
        "last_run": None,
    }
    store.save_schedule(item)
    audit("schedule_save", sid, user=user)
    return {"ok": True, "id": sid}


@app.delete("/api/schedules/{sid}")
def del_schedule(request: Request, sid: str) -> dict:
    current_user(request)
    store.delete_schedule(sid)
    return {"ok": True}


@app.patch("/api/schedules/{sid}")
def patch_schedule(request: Request, sid: str, body: dict = Body(...)) -> dict:
    """启用 / 暂停周期任务；重新启用时把 next_run 推到下一周期"""
    user = current_user(request)
    item = next((s for s in store.list_schedules() if s["id"] == sid), None)
    if not item:
        raise HTTPException(status_code=404, detail="计划任务不存在")
    if "enabled" in body:
        item["enabled"] = 1 if body["enabled"] else 0
        if item["enabled"] and (item.get("next_run") or 0) <= time.time():
            item["next_run"] = time.time() + int(item.get("interval_hours") or 24) * 3600
    if body.get("interval_hours"):
        item["interval_hours"] = int(body["interval_hours"])
    store.save_schedule(item)
    audit("schedule_patch", sid, detail=json.dumps(body, ensure_ascii=False), user=user)
    return {"ok": True}


@app.get("/api/audit")
def audit_log(request: Request, limit: int = 200) -> dict:
    current_user(request)
    rows = store.conn().execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"ok": True, "items": [dict(r) for r in rows]}


@app.get("/api/tools")
def tools(request: Request) -> dict:
    current_user(request)
    return {"ok": True, "items": {n: enterprise.tool_available(n) for n in enterprise.TOOL_PATHS}}


@app.get("/api/tools/catalog")
def tools_catalog(request: Request) -> dict:
    """外部工具清单：装没装、装在哪、怎么手动装。"""
    current_user(request)
    from .engine import installer

    items = installer.all_status()
    for k, v in items.items():
        if k not in enterprise.TOOL_PATHS:
            enterprise.TOOL_PATHS[k] = [Path(v["bin"]).name] if v.get("bin") else [k]
    return {"ok": True, "dir": str(installer.TOOLS_DIR), "items": items,
            "network": {"proxy": installer._proxy() or "",
                        "proxy_ok": installer._proxy_ok(),
                        "mirrors": list(installer.MIRRORS)}}


@app.post("/api/tools/install")
async def tools_install(request: Request, body: dict = Body(...)) -> dict:
    """一键安装：body 传 ``{"names": ["nuclei", "httpx"]}`` 或 ``{"name": "nuclei"}``。"""
    user = current_user(request)
    from .engine import installer

    names = body.get("names") or ([body["name"]] if body.get("name") else [])
    names = [str(n) for n in names if str(n) in installer.CATALOG]
    if not names:
        raise HTTPException(status_code=400, detail="没有可安装的工具名")
    res = await installer.install_many(names)
    return {"ok": all(v.get("ok") for v in res.values()), "results": res,
            "items": installer.all_status()}


@app.get("/api/tools/progress")
def tools_progress(request: Request) -> dict:
    """安装进度：长下载时前端轮询这个，看已经拉了多少字节。"""
    current_user(request)
    from .engine import installer

    return {"ok": True, "last": installer._LAST}


@app.get("/api/ports")
def ports(request: Request, preset: str = "top100") -> dict:
    current_user(request)
    return {"ok": True, "ports": ports_for_type(preset)}


@app.get("/api/utils/ports")
def parse_ports_api(request: Request, text: str = "") -> dict:
    current_user(request)
    return {"ok": True, "ports": parse_ports(text)}


@app.post("/api/utils/beautify")
def beautify_api(request: Request, body: dict) -> dict:
    """把压缩的 JS/HTML/JSON 还原成可读结构，并抽出字符串常量与接口地址。"""
    current_user(request)
    text = str(body.get("text") or "")
    if not text:
        return {"ok": False, "error": "text 为空"}
    if len(text) > 8_000_000:
        return {"ok": False, "error": "内容超过 8MB，请先截取"}
    lang = str(body.get("language") or "auto")
    try:
        indent = max(1, min(8, int(body.get("indent") or 2)))
    except (TypeError, ValueError):
        indent = 2
    res = beauty.beatify(text, lang, indent)
    return {"ok": not res["error"], **res}


@app.post("/api/utils/beautify/url")
async def beautify_url_api(request: Request, body: dict) -> dict:
    """直接抓一个 JS/页面地址来分析，省去手工复制。"""
    current_user(request)
    url = str(body.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "error": "需要 http(s) 地址"}
    text = await fetch_text(url, timeout=20)
    if not text:
        return {"ok": False, "error": "抓取失败或内容为空"}
    res = beauty.beatify(text, str(body.get("language") or "auto"),
                         int(body.get("indent") or 2))
    return {"ok": not res["error"], "url": url, "size": len(text), **res}


@app.post("/api/utils/handshake")
async def handshake_api(request: Request, body: dict) -> dict:
    """对一个地址取握手标记：JARM、TLS 版本、证书、CSP/HSTS、ASN。"""
    current_user(request)
    url = str(body.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "url 为空"}
    try:
        mk = await handshake.mark(url)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}
    row = mk.as_dict()
    return {"ok": True, "url": url, "mark": row,
            "jsonl": handshake.to_jsonl_row({"url": url, "extra": {"handshake": row}})}


@app.get("/api/export/jsonl")
def export_jsonl(request: Request, task_id: str = "", limit: int = 5000) -> dict:
    """存活站点按通用 JSONL 字段导出（jarm/hash、csp、asn、cert_issuer 等）。"""
    current_user(request)
    rows = store.query_assets(kind="site", task_id=task_id or None,
                              limit=max(1, min(limit, 20000)))
    items = [handshake.to_jsonl_row(r) for r in rows]
    return {"ok": True, "count": len(items), "preview": items[:20]}


# ─────────────── 计划任务调度 ───────────────
async def _scheduler_loop() -> None:
    while True:
        try:
            now = time.time()
            for s in store.list_schedules():
                if not s.get("enabled"):
                    continue
                if (s.get("next_run") or 0) <= now:
                    targets = [t.strip() for t in (s.get("target") or "").replace(",", "\n")
                               .split("\n") if t.strip()]
                    if targets:
                        await pipeline.start_task(targets, s.get("options") or {},
                                                  s.get("name") or "", schedule_id=s["id"])
                    s["last_run"] = now
                    s["next_run"] = now + int(s.get("interval_hours") or 24) * 3600
                    store.save_schedule(s)
        except Exception:
            pass
        await asyncio.sleep(60)


# ─────────────── 静态页 ───────────────
@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    # 每次重建都会换掉 chunk 文件名，旧文件同时被删。index.html 一旦进浏览器缓存，
    # 用户手里那份就会去 import 已不存在的 chunk，页面白屏且强刷前无法自愈。
    return HTMLResponse(_index_html(), headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    })


_BUILD_RE = re.compile(r"assets/index-([A-Za-z0-9_-]+)\.js")


def _build_id() -> str:
    """用前端入口 chunk 的哈希当构建号：重新构建后它会变，用来发现浏览器手里的旧页面。"""
    m = _BUILD_RE.search(_index_html())
    return m.group(1) if m else "unknown"


def _index_html() -> str:
    # Vite 产物在 arlx/static/index.html；web/ 下留给开发源码，不再放可服务的入口页
    for p in (STATIC_DIR / "index.html", WEB_DIR / "index.html"):
        if p.exists():
            return p.read_text(encoding="utf-8")
    # 前端还没构建时给一条明确提示，避免打开是白屏
    return ("<!doctype html><meta charset='utf-8'><body style='background:#060b11;color:#d9e7ef;"
            "font-family:Segoe UI,Microsoft YaHei;padding:40px'>"
            "<h2>前端未构建</h2><p>在 web 目录执行 <code>npm install &amp;&amp; npm run build</code>，"
            "或 <code>npm run dev</code> 走 5199 端口开发。</p></body>")


@app.get("/favicon.ico")
async def favicon():
    p = WEB_DIR / "favicon.ico"
    if p.exists():
        return FileResponse(p)
    return Response(status_code=204)


@app.get("/static/{rel:path}")
async def static_file(rel: str):
    """兜底：静态资源按实际文件返回；不存在的直接 404，不要被 SPA 回退成 HTML"""
    p = (STATIC_DIR / rel).resolve()
    if STATIC_DIR.resolve() in p.parents and p.is_file():
        return FileResponse(p)
    return Response(status_code=404)


def _unused(*args: Any) -> None:
    return is_ip, is_valid_domain, root_domain, Path, Query


# ─────────────── 带外回显（OOB） ───────────────
@app.get("/api/listener/hits")
def listener_hits(request: Request, task_id: str = "", token: str = "",
                        limit: int = 200) -> dict:
    current_user(request)
    return {"ok": True, **listener.status(), "hits": listener.hits(task_id, token, limit)}


@app.post("/api/listener/alloc")
def listener_alloc(request: Request, body: dict = Body(...)) -> dict:
    """给任务手工发一个 token（自动任务在 pipeline 里已经发过，这里是补发/自测用）。"""
    current_user(request)
    task_id = str(body.get("task_id") or "").strip()
    if not task_id:
        raise HTTPException(status_code=400, detail="缺 task_id")
    token = listener.alloc(task_id)
    return {"ok": True, "token": token, "payloads": listener.payloads(token)}


@app.get("/l/{token}")
@app.post("/l/{token}")
async def listener_callback(token: str, request: Request) -> Response:
    """公开回调入口：不带 token 鉴权，谁打过来都记录。响应极简，避免被当成探测特征。"""
    src = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not src:
        src = request.client.host if request.client else ""
    try:
        raw = (await request.body())[:8000].decode("utf-8", "replace")
    except Exception:
        raw = ""
    host = request.headers.get("host") or ""
    path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    hdr = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    listener.hit(token, "http", source_ip=src, host=host, path=path,
                 method=request.method, headers=hdr, body=raw)
    return Response(content="ok", media_type="text/plain")


@app.get("/api/status")
def app_status(request: Request) -> dict:
    """套壳（Electron）轮询用的就绪探针，不需要登录。"""
    return {"ok": True, "app": "天鉴·索舆", "version": "2.8.0", "build": _build_id()}


@app.get("/api/dashboard/stats")
def dashboard_stats(request: Request) -> dict:
    current_user(request)
    return {"ok": True, **store.overview()}


@app.post("/api/sources/relay")
def set_relay(request: Request, body: dict = Body(...)) -> dict:
    """一次性给多个数据源设置中转站（同一代理商的统一入口），relay=空串即回官方"""
    user = current_user(request)
    relay = str(body.get("relay") or "").strip().rstrip("/")
    names = [str(n) for n in (body.get("sources") or []) if str(n).strip()]
    if not names:
        raise HTTPException(status_code=400, detail="没有指定数据源")
    patch = {"sources": {n: {"relay": relay} for n in names}}
    config.persist(patch)
    config.reload()
    audit("relay_update", f"{relay or '官方'} -> {','.join(names)}", user=user)
    return {"ok": True, "relay": relay, "sources": names,
            "resolved": {n: src_base(n, "") for n in names}}


@app.get("/api/net/diagnose")
async def net_diagnose(request: Request, with_proxy: bool = True, timeout: float = 8.0) -> dict:
    """连通性诊断：直连 / 代理 / DNS 三段分别探一遍，给出可操作的结论。"""
    current_user(request)
    from .engine import netcheck

    return {"ok": True, **await netcheck.diagnose(timeout=min(max(timeout, 2.0), 20.0),
                                                   with_proxy=with_proxy)}


@app.get("/api/fofa/hot")
async def fofa_hot(request: Request, keyword: str = "", limit: int = 30) -> dict:
    """测绘引擎热点榜：近期高增长产品及其现成查询语法，免 key。只给起手灵感，不产资产。"""
    current_user(request)
    from .engine.sources.passive import fofa_hot_search

    res = await fofa_hot_search(keyword, limit)
    # 前端统一读 items；底层按行返回，这里补齐键名再透出
    return {"ok": True, **res, "items": res.get("rows") or [], "rows": res.get("rows") or []}


@app.get("/api/fofa/suggest")
async def fofa_suggest_api(request: Request, field: str, q: str = "", limit: int = 20) -> dict:
    """查询语法候选值，免登录可用。"""
    current_user(request)
    from .engine.sources.passive import fofa_suggest

    res = await fofa_suggest(field, q, limit)
    return {"ok": True, **res, "items": res.get("rows") or [], "rows": res.get("rows") or []}


def main() -> None:
    host = os.environ.get("ARLX_HOST") or config.get("server", "host") or "0.0.0.0"
    port = int(os.environ.get("ARLX_PORT") or config.get("server", "port") or 5113)
    # timeout_graceful_shutdown：默认无限等待，一旦有长连接（SSE）没断，进程会卡在
    # shutdown 里变成「监听已关、流水线还在跑」的僵尸，watchdog 也判不出来。限时退出。
    uvicorn.run(app, host=host, port=port, log_level="info",
                timeout_graceful_shutdown=8)


if __name__ == "__main__":
    main()
