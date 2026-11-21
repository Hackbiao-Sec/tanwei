"""AI 能力（OpenAI 兼容 /chat/completions：DeepSeek、OpenAI、中转站均可）。

所有 AI 功能点都在这里，前端「AI 工坊」页直接调：
  * generate_query   自然语言 / 企业名 → 空间测绘语法（FOFA / Hunter / Quake / ZoomEye）
  * triage           当前资产库 → 按侦察价值排序并给一句话理由
  * summarize_task   单个任务 → 侦察小结（面、可能的入口、下一步）
  * suggest_fingerprint  页面标题 / 头 → 可匹配的指纹正则
  * expand_entity    企业名 → 别名 / 产品 / App（任务 P1 阶段自动用）
  * guess_domains    零域名时猜根域（猜出来仍要走证据打分闸）
  * judge_domains    复核"待核验"段的域名归属（没有 key 时整段跳过，规则判定照常生效）
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..config import config, llm_engine
SYSTEM = (
    "你是国内授权渗透测试项目的信息收集助手，只做资产面梳理，不输出攻击载荷。"
    "回答必须简洁、可执行、事实优先；不确定就标注「待核验」，禁止编造具体域名或 IP。"
)


class AIError(RuntimeError):
    pass


def status() -> dict:
    eng = llm_engine()
    if not eng:
        return {"ready": False, "engine": "", "base": "", "model": "",
                "msg": "未配置大模型：在 系统设置 → AI 里填 DeepSeek / OpenAI / 中转站的 Key"}
    return {"ready": True, "engine": eng["name"], "base": eng["base"], "model": eng["model"],
            "msg": f"{eng['name']} · {eng['model']}"}


async def chat(prompt: str, system: str = SYSTEM, json_mode: bool = False,
               timeout: float | None = None, relay: str = "") -> str:
    eng = llm_engine()
    if not eng:
        raise AIError("未配置大模型 Key")
    timeout = timeout or float(config.get("ai", "timeout") or 90)
    payload: dict[str, Any] = {
        "model": eng["model"],
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": prompt}],
        "temperature": float(config.get("ai", "temperature") or 0.2),
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    headers = {"Authorization": f"Bearer {eng['key']}", "Content-Type": "application/json"}
    url = f"{(relay.strip().rstrip('/') or eng['base'])}/v1/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, trust_env=False,
                                     proxy=(config.get("proxy", "url")
                                            if config.get("proxy", "sources_via_proxy") else None)) as c:
            r = await c.post(url, headers=headers, json=payload)
    except Exception as e:
        raise AIError(f"请求失败：{str(e)[:160]}") from e
    if r.status_code == 401:
        raise AIError(f"Key 无效（401）：{url}")
    if r.status_code == 404:
        raise AIError(f"接口不存在（404）：{url} —— 中转站要能转发 /v1/chat/completions")
    if r.status_code != 200:
        raise AIError(f"HTTP {r.status_code}：{r.text[:200]}")
    try:
        return ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content", "") or ""
    except Exception as e:
        raise AIError(f"回包解析失败：{r.text[:200]}") from e


def _json_or_text(content: str) -> dict:
    m = re.search(r"\{.*\}", content, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {"text": content.strip()}


async def test() -> dict:
    """连通性测试：发一句最短请求，确认中转站真的把 /v1/chat/completions 转过去了"""
    try:
        txt = await chat("只回复两个字母：OK", timeout=45)
    except AIError as e:
        # status() 自带一个 msg，必须排在后面拼，否则真实报错会被它覆盖
        return {**status(), "ok": False, "msg": str(e)}
    return {**status(), "ok": True, "msg": f"连通正常，回包：{txt.strip()[:40]}"}


# ─────────────── 1. 测绘语法 ───────────────
QUERY_SYNTAX = {
    "fofa": 'domain="example.com" || cert="example.com"；可用 app= title= body= icon_hash= ip= 组合',
    "hunter": 'domain.suffix="example.com"；可用 web.title= ip= port= 组合',
    "quake": 'domain: "example.com"；可用 app: title: ip: 组合',
    "zoomeye": "仅支持域名检索：填根域名即可，例如 example.com",
}


async def generate_query(text: str, engine: str = "fofa") -> dict:
    engine = (engine or "fofa").lower()
    syn = QUERY_SYNTAX.get(engine, QUERY_SYNTAX["fofa"])
    prompt = (
        f"目标：{text}\n"
        f"请针对 {engine} 空间测绘引擎，给出 3~5 条最可能命中该目标资产面的检索语法。\n"
        f"{engine} 语法参考：{syn}\n"
        "要求：每条写清用途（主域 / 证书 / 产品指纹 / 旁站 IP），语法必须能被该引擎直接执行；"
        "只输出 JSON：{\"queries\":[{\"q\":\"...\",\"why\":\"...\"}]}"
    )
    raw = await chat(prompt, json_mode=True)
    data = _json_or_text(raw)
    qs = data.get("queries") if isinstance(data, dict) else None
    if not isinstance(qs, list):
        return {"engine": engine, "queries": [], "text": raw.strip()}
    out = []
    for it in qs[:6]:
        if isinstance(it, dict) and str(it.get("q") or "").strip():
            out.append({"q": str(it["q"]).strip(), "why": str(it.get("why") or "").strip()[:80]})
        elif isinstance(it, str) and it.strip():
            out.append({"q": it.strip(), "why": ""})
    return {"engine": engine, "queries": out, "text": raw.strip()}


# ─────────────── 2. 资产研判 ───────────────
_TRIAGE_HINT = {
    "leak": "代码/配置泄露",
    "leakfile": "敏感文件",
    "git": "Git 泄露",
    "api": "接口",
    "site": "站点",
    "domain": "域名",
    "js": "JS",
    "email": "邮箱",
    "bucket": "存储桶",
}


async def triage(kind: str = "", root_domain: str = "", limit: int = 120) -> dict:
    from ..db import store

    rows = store.query_assets(kind=kind or None, root_domain=root_domain or None, limit=limit,
                              order="last_seen DESC")
    if not rows:
        return {"items": [], "summary": "资产库没有匹配记录，先跑一个任务", "count": 0}
    lines = []
    for r in rows:
        lines.append(f'{r.get("id")}|{r.get("kind")}|{r.get("url")}|{(r.get("title") or "")[:40]}'
                     f'|{r.get("status_code") or ""}|{r.get("fingerprint") or ""}')
    prompt = (
        "以下是本轮信息收集拿到的资产（每行：id|类型|地址|标题|状态码|指纹）。"
        "按「对授权渗透最有价值的入口」排序，重点关注泄露、接口、后台、暴露的服务端口；"
        "只输出 JSON：{\"summary\":\"三句话以内的整体判断\","
        "\"items\":[{\"id\":123,\"risk\":\"高|中|低\",\"why\":\"一句话依据\"}]}，最多 15 条，id 必须来自输入。\n"
        + "\n".join(lines)
    )
    raw = await chat(prompt, json_mode=True, timeout=120)
    data = _json_or_text(raw)
    by_id = {int(r["id"]): r for r in rows if r.get("id") is not None}
    out = []
    for it in (data.get("items") or [])[:15]:
        if not isinstance(it, dict):
            continue
        try:
            rid = int(it.get("id"))
        except Exception:
            continue
        row = by_id.get(rid)
        if not row:
            continue
        out.append({"id": rid, "risk": str(it.get("risk") or "中")[:2],
                    "why": str(it.get("why") or "")[:120],
                    "kind": row.get("kind"), "url": row.get("url"),
                    "title": row.get("title") or ""})
    return {"items": out, "summary": str(data.get("summary") or raw.strip()[:300]),
            "count": len(rows), "text": raw.strip() if not out else ""}


# ─────────────── 3. 任务小结 ───────────────
async def summarize_task(task_id: str, top_n: int = 40) -> dict:
    from ..db import store

    task = store.get_task(task_id)
    if not task:
        raise AIError("任务不存在")
    targets = task.get("targets") or []
    if isinstance(targets, list):
        targets = "、".join(str(t) for t in targets)
    conn = store.conn()
    kinds = conn.execute(
        "SELECT a.kind, COUNT(*) c FROM task_assets ta JOIN assets a ON a.id=ta.asset_id "
        "WHERE ta.task_id=? GROUP BY a.kind ORDER BY c DESC", (task_id,)).fetchall()
    roots = conn.execute(
        "SELECT a.root_domain, COUNT(*) c FROM task_assets ta JOIN assets a ON a.id=ta.asset_id "
        "WHERE ta.task_id=? AND a.root_domain<>'' GROUP BY a.root_domain ORDER BY c DESC LIMIT 15",
        (task_id,)).fetchall()
    top = store.query_assets(task_id=task_id, limit=max(1, int(top_n or 40)),
                             order="kind ASC, last_seen DESC")
    stat = "、".join(f"{r[0]} {r[1]}" for r in kinds) or "无"
    roots_txt = "、".join(f"{r[0]}({r[1]})" for r in roots) or "无"
    sample = "\n".join(f'{r.get("kind")}|{r.get("url")}|{(r.get("title") or "")[:30]}' for r in top)
    prompt = (
        f"任务：{task.get('name') or task_id}\n目标：{targets}\n"
        f"资产分布：{stat}\n主要根域：{roots_txt}\n抽样资产：\n{sample}\n\n"
        "写一份中文侦察小结：1) 这摊资产属于哪些业务面；2) 最值得先看的 3 个入口及理由；"
        "3) 建议的下一步（补哪类资产、看哪类接口）。不要编造抽样里没有的域名。"
    )
    text = await chat(prompt, timeout=120)
    return {"task_id": task_id, "summary": text.strip(), "kinds": [{"kind": k, "count": c} for k, c in kinds],
            "roots": [{"root_domain": r, "count": c} for r, c in roots]}


# ─────────────── 4. 指纹建议 ───────────────
async def suggest_fingerprint(url: str) -> dict:
    from .http_engine import probe

    u = url if url.startswith(("http://", "https://")) else "http://" + url
    info = await probe(u)
    body = (getattr(info, "body", "") or "")[:6000]
    head = "\n".join(f"{k}: {v}" for k, v in list((getattr(info, "headers", {}) or {}).items())[:15])
    base = {"url": u, "title": getattr(info, "title", "") or "",
            "server": getattr(info, "server", "") or "",
            "status_code": getattr(info, "status", 0)}
    if not body:
        return {**base, "name": "", "regex": "", "msg": "页面无正文，无法建议指纹"}
    prompt = (
        f"页面：{u}\n标题：{base['title']}\n响应头：\n{head}\n正文片段：\n{body[:3000]}\n\n"
        "给出一个能稳定识别该产品/框架的 Web 指纹正则：只输出 JSON "
        '{"name":"产品名","regex":"只匹配正文或响应头里独有的字符串"}'
    )
    raw = await chat(prompt, json_mode=True, timeout=90)
    data = _json_or_text(raw)
    regex = str(data.get("regex") or "").strip()
    if regex:
        try:
            re.compile(regex)
        except re.error:
            regex = re.escape(regex)
    return {**base, "name": str(data.get("name") or "")[:40], "regex": regex}


# ─────────────── 5. 企业名扩展（任务 P1 用）───────────────
async def expand_entity(name: str) -> dict:
    prompt = (
        "你是信息收集助手。给定一个中国企业/机构名称，输出 JSON："
        '{"aliases":["简称/别称/英文名/曾用名"],"products":["对外产品/平台名"],'
        '"apps":["App/小程序/公众号名"],"keywords":["可用于测绘的关键词"]}。'
        "只输出 JSON，不要解释。名称：" + name
    )
    try:
        raw = await chat(prompt, timeout=45)
    except AIError:
        return {}
    return _json_or_text(raw)


async def guess_domains(name: str, hint: str = "") -> list[str]:
    """企业名 → 候选根域。

    ICP / 工商来源全挂时，一键收集只剩这条路能把"公司名"变成可下发的目标；
    结果只落到域名层，再由调用方做活域校验，猜错的最多白发几个请求。
    hint 是搜索引擎带出的域名，只用来让模型挑，不用它直接当结果——搜出来的可能同名无关站。
    """
    prompt = (
        "给一个中国企业/机构名称，列出它一定属于该主体的官网根域名，按可能性从高到低。"
        '只输出 JSON：{"domains":["example.com","example.cn"]}，最多 5 个，不要解释，不要带 http:// 或路径。'
        "拿不准就返回空数组，不要凑数。"
        "名称：" + name
    )
    if hint:
        prompt += '\n搜索引擎带出的候选（去掉与你判断不符的无关站）：' + hint
    try:
        raw = await chat(prompt, timeout=45)
    except AIError:
        return []
    data = _json_or_text(raw) or {}
    out = []
    for d in data.get("domains") or []:
        if not isinstance(d, str):
            continue
        d = d.strip().lower()
        for pre in ("https://", "http://"):
            if d.startswith(pre):
                d = d[len(pre):]
        d = d.split("/")[0].split(":")[0]
        if d and "." in d:
            out.append(d)
    return out[:5]


async def judge_domains(name: str, candidates: list[str], notes_hint: str = "") -> dict[str, dict]:
    """AI 复核企业名 → 域名归属（只处理规则打分落在"待核验"那一段的候选）。

    回报 {domain: {"belong": True/False, "why": "…"}}。返回空 dict 表示 AI 不可用或没给有效结论，
    调用方维持规则判定——这条链路不是必需项。
    """
    if not candidates:
        return {}
    prompt = (
        "判断下列域名是否属于这个中国企业主体的自有资产（官网、业务系统、子品牌站）。"
        "同名不同公司、行业门户、媒体转载站、招聘站、开发者社区都不算。"
        '只输出 JSON：{"results":[{"domain":"x.com","belong":true,"why":"一句话"}]}。'
        f"\n企业名称：{name}\n域名：{', '.join(candidates[:15])}"
    )
    if notes_hint:
        prompt += f"\n品牌简称：{notes_hint}"
    try:
        raw = await chat(prompt, timeout=60, json_mode=True)
    except AIError:
        return {}
    data = _json_or_text(raw) or {}
    out: dict[str, dict] = {}
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        d = str(item.get("domain") or "").strip().lower()
        if not d:
            continue
        out[d] = {"belong": item.get("belong") is True, "why": str(item.get("why") or "")}
    return out


async def merge_entities(names: list[str], hint: str = "") -> dict:
    """把同一主体的不同写法归组，给汇总去重用。

    返回 {"groups": [["全称","简称"], ...], "reason": "…"}；只保留输入里真实出现的名字，
    模型乱造或拿不准时调用方按规则档合并。
    """
    names = [str(n).strip() for n in (names or []) if str(n or "").strip()]
    if len(names) < 2:
        return {"groups": []}
    uniq = list(dict.fromkeys(names))[:300]
    listing = "\n".join(f"{i + 1}. {n}" for i, n in enumerate(uniq))
    prompt = (
        "下面是同一侦察任务里从工商 / 股权链路收集到的公司名。"
        "把明显指向同一主体的不同写法（全称、简称、别名、去掉「集团」「有限公司」的写法）归到一组；"
        "拿不准的各自单独一组，禁止把不同公司并在一起。\n"
        f"{hint}\n名称：\n{listing}\n"
        '只输出 JSON：{"groups":[["写法A","写法B"]],"reason":"一句话"}'
    )
    try:
        raw = await chat(prompt, timeout=90, json_mode=True)
    except AIError:
        return {"groups": []}
    data = _json_or_text(raw) or {}
    known = set(uniq)
    groups: list[list[str]] = []
    for grp in data.get("groups") or []:
        if not isinstance(grp, (list, tuple)):
            continue
        picked = [str(x).strip() for x in grp if str(x).strip() in known]
        picked = list(dict.fromkeys(picked))
        if len(picked) >= 2:
            groups.append(picked)
    return {"groups": groups, "reason": str(data.get("reason") or "")}


__all__ = ["AIError", "status", "chat", "test", "generate_query", "triage", "summarize_task",
           "suggest_fingerprint", "expand_entity", "guess_domains", "judge_domains",
           "merge_entities"]

