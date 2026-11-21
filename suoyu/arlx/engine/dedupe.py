"""任务资产合并去重。

一张任务里同一份东西经常被收两遍：P1 主体阶段和 P1a 股权阶段各出一张穿透图，
被动源 / 测绘 / 字典爆破又各捞一次同一批域名。这里在汇总时统一归并。

两档：
* 规则档（始终可用）：公司名归一 + 别名归组、域名小写去尾点、Web 按 host:port+path、
  C 段按 IP:端口 / CIDR 归一；同键的行合并成一条。
* AI 档（配置了大模型才走）：把疑似同一主体的写法交给模型判别名，失败自动回落规则档。

合并只动 ``assets`` / ``task_assets``，不碰其它表；被合并行的任务关联会迁到保留行。
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from collections import OrderedDict, defaultdict
from typing import Any, Iterable

from ..config import llm_engine
from ..db import store

# 公司类资产：url 里嵌着主体名，换个写法就是另一条记录
COMPANY_KINDS = {"equity", "branch", "holds", "invest", "partner"}
# 名字类资产：按 extra.name / title 归并
NAME_KINDS = COMPANY_KINDS | {"copyright", "mobileapp"}
# 出现这些词时 containment 不算同一主体，避免「中国」把半个库并成一家
_GENERIC = {
    "中国", "国际", "科技", "技术", "实业", "投资", "控股", "集团", "股份", "发展",
    "有限", "公司", "分公司", "子公司", "管理", "咨询", "服务", "网络", "信息",
}

_SUFFIX = re.compile(
    r"(?:股份有限公司|有限责任公司|集团有限公司|集团有限责任公司|有限公司|"
    r"有限合伙企业|有限合伙|股份公司|集团|公司)$"
)


def _clean(text: str) -> str:
    s = unicodedata.normalize("NFKC", str(text or ""))
    s = re.sub(r"[\s\u3000·•・,，。．.、'\"“”‘’()\[\]{}（）]", "", s)
    return s.lower()


def norm_company(name: str) -> str:
    """公司名归一：去空白标点、反复剥法律后缀。"""
    s = _clean(name)
    for _ in range(3):
        nxt = _SUFFIX.sub("", s)
        if nxt == s:
            break
        s = nxt
    return s


def _extra_of(row: dict) -> dict:
    raw = row.get("extra_json")
    if isinstance(raw, dict):
        return dict(raw)
    try:
        data = json.loads(raw or "{}")
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _node_key(item: Any) -> str:
    if isinstance(item, dict):
        for k in ("name", "pid", "softwareName", "title", "url"):
            if item.get(k):
                return str(item[k])
        try:
            return json.dumps(item, sort_keys=True, ensure_ascii=False)
        except Exception:
            return str(item)
    return str(item)


def _merge_value(a: Any, b: Any) -> Any:
    """画像合并：列表按 name 取并集，字典递归，标量保留先到的非空值。"""
    if a in (None, "", [], {}):
        return b
    if b in (None, "", [], {}):
        return a
    if isinstance(a, list) and isinstance(b, list):
        out = list(a)
        seen = {_node_key(x) for x in out}
        for x in b:
            k = _node_key(x)
            if k not in seen:
                seen.add(k)
                out.append(x)
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = _merge_value(out.get(k), v)
        return out
    return a


def _merge_extra(base: dict, more: dict) -> dict:
    out = dict(base)
    for k, v in more.items():
        out[k] = _merge_value(out.get(k), v)
    return out


def alias_map(names: Iterable[str], ai_groups: Iterable[Iterable[str]] | None = None) -> dict[str, str]:
    """公司名归组：返回 归一化名 → 组内最长写法。

    规则：短名被长名包含、长度 ≥ 4、长名只多出 ≤ 12 字、短名不是通用词。
    `ai_groups` 是模型给的别名组，只认输入里真实存在的名字。
    """
    keys: list[str] = []
    for n in names:
        k = norm_company(n)
        if k and k not in keys:
            keys.append(k)
    parent = {k: k for k in keys}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for k in keys:
        if len(k) < 4 or k in _GENERIC:
            continue
        for other in keys:
            if other == k or len(other) <= len(k) or len(other) > len(k) + 12:
                continue
            if k in other:
                union(k, other)

    for grp in ai_groups or []:
        ks = [norm_company(x) for x in (grp or [])]
        ks = [k for k in ks if k in parent]
        for k in ks[1:]:
            union(ks[0], k)

    buckets: dict[str, list[str]] = defaultdict(list)
    for k in keys:
        buckets[find(k)].append(k)
    out: dict[str, str] = {}
    for ks in buckets.values():
        canon = max(ks, key=len)
        for k in ks:
            out[k] = canon
    return out


def _norm_web(url: str) -> str:
    u = (url or "").strip().lower().rstrip("/")
    return re.sub(r"^(https?)://([^/]+)", lambda m: f"{m.group(1)}://{_norm_hostport(m.group(2))}", u)


def _norm_hostport(hp: str) -> str:
    hp = hp.strip().lower().rstrip(".")
    if hp.startswith("["):
        return hp
    if ":" in hp:
        host, _, port = hp.rpartition(":")
        if port.isdigit():
            return f"{host}:{int(port)}"
    return hp


def _norm_cidr(text: str) -> str:
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except Exception:
        return text.strip().lower()


def _norm_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except Exception:
        return text.strip().lower()


def _row_key(row: dict, alias) -> tuple[str, ...] | None:
    kind = str(row.get("kind") or "")
    url = str(row.get("url") or row.get("host") or row.get("ip") or "").strip()
    extra = _extra_of(row)
    if not (url or extra):
        return None

    if kind == "equity":
        nm = str(extra.get("name") or "").strip()
        if not nm:
            title = str(row.get("title") or "").replace(" 股权链路", "").strip()
            nm = title or (url.split(":", 1)[1] if ":" in url else url)
        return ("equity", alias(nm))

    if kind in COMPANY_KINDS:
        child = str(extra.get("name") or row.get("title") or "").strip()
        if not child and ":" in url:
            child = url.rsplit(":", 1)[-1]
        if kind in ("partner", "branch"):
            parent = str(extra.get("parent") or "").strip()
            return (kind, alias(parent), norm_company(child))
        return (kind, norm_company(child))

    if kind in ("copyright", "mobileapp"):
        nm = str(extra.get("name") or row.get("title") or "").strip()
        return (kind, _clean(nm)) if nm else None

    if kind in ("domain", "host"):
        u = url.lower().strip()
        if u.startswith("domain:"):
            u = u[7:]
        if u.startswith("*."):
            u = u[2:]
        return ("domain", u.rstrip("."))

    if kind in ("netblock", "cidr"):
        return ("netblock", _norm_cidr(url.split(":", 1)[1] if url.lower().startswith("netblock:") else url))

    m = re.match(r"^(service|sibling):([^:]+):(\d+)$", url, re.I)
    if m:
        return (kind, _norm_ip(m.group(2)), str(int(m.group(3))))

    if kind in ("site", "api", "js", "leak", "leakfile", "component", "git", "url"):
        return (kind, _norm_web(url))

    if kind == "ip":
        return ("ip", _norm_ip(url[3:] if url.lower().startswith("ip:") else url))

    return (kind, url.lower())


def _score(row: dict) -> tuple:
    """保留哪一行：画像字段多、主体字段全的优先；同分取更早的行。"""
    extra = _extra_of(row)
    filled = sum(1 for c in ("title", "host", "ip", "port", "status_code", "fingerprint") if row.get(c))
    return (len(extra), filled, -int(row.get("id") or 0))


async def merge_task(task_id: str, use_ai: bool = True) -> dict:
    """把本任务的重复资产合并掉，返回合并前后计数。

    AI 只在配置了大模型（`llm_engine()` 有值）且 `use_ai` 为真时参与判别名；
    任何异常都静默回落规则档，汇总流程不因模型挂了中断。
    """
    rows = store.query_assets(task_id=task_id, limit=200000)
    if not rows:
        return {"before": 0, "after": 0, "removed": 0, "groups": 0, "mode": "rule"}

    names: list[str] = []
    for r in rows:
        if r.get("kind") not in COMPANY_KINDS:
            continue
        extra = _extra_of(r)
        nm = str(extra.get("name") or r.get("title") or "").replace(" 股权链路", "").strip()
        if nm:
            names.append(nm)

    ai_groups: list[list[str]] = []
    mode = "rule"
    if use_ai and llm_engine():
        try:
            from .ai import merge_entities

            data = await merge_entities(sorted(set(names)))
            ai_groups = [g for g in (data.get("groups") or []) if isinstance(g, (list, tuple))]
            if ai_groups:
                mode = "rule+ai"
        except Exception:
            ai_groups = []

    amap = alias_map(names, ai_groups)

    def alias(name: str) -> str:
        k = norm_company(name)
        return amap.get(k, k)

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        key = _row_key(r, alias)
        if key:
            groups[key].append(r)

    removed = 0
    merged_groups = 0
    for items in groups.values():
        if len(items) < 2:
            continue
        items.sort(key=_score, reverse=True)
        keep = items[0]
        drops = [int(r["id"]) for r in items[1:]]
        merged = _extra_of(keep)
        for r in items[1:]:
            merged = _merge_extra(merged, _extra_of(r))
        n = store.merge_assets(int(keep["id"]), drops, extra=merged)
        if n:
            removed += n
            merged_groups += 1

    return {"before": len(rows), "after": len(rows) - removed,
            "removed": removed, "groups": merged_groups, "mode": mode}


# ───────── 穿透图归并（接口侧，老任务也能立刻看到去重结果） ─────────

def _node_name(node: Any) -> str:
    return str((node or {}).get("name") or "") if isinstance(node, dict) else ""


def _merge_node(a: dict, b: dict, canon) -> dict:
    out = dict(a)
    out["name"] = a.get("name") if len(_node_name(a)) >= len(_node_name(b)) else b.get("name")
    for k in ("ratio", "acc", "depth"):
        if out.get(k) is None and b.get(k) is not None:
            out[k] = b[k]
    kids: OrderedDict[str, dict] = OrderedDict()
    for node in list(a.get("children") or []) + list(b.get("children") or []):
        nm = _node_name(node)
        if not nm:
            continue
        k = canon(nm)
        if k in kids:
            kids[k] = _merge_node(kids[k], node, canon)
        else:
            kids[k] = node
    out["children"] = list(kids.values())
    return out


def _merge_tree(a: dict, b: dict, canon) -> dict:
    out = dict(a)
    out["name"] = a.get("name") if len(_node_name(a)) >= len(_node_name(b)) else b.get("name")

    def _uniq(items):
        seen, res = set(), []
        for x in items or []:
            k = _node_key(x)
            if k not in seen:
                seen.add(k)
                res.append(x)
        return res

    src = [s for s in (a.get("source"), b.get("source")) if s]
    if src:
        out["source"] = "/".join(dict.fromkeys(src))
    out["ratio_line"] = a.get("ratio_line") or b.get("ratio_line")
    out["depth"] = max(int(a.get("depth") or 0), int(b.get("depth") or 0)) or a.get("depth") or b.get("depth")
    out["notes"] = _uniq(list(a.get("notes") or []) + list(b.get("notes") or []))
    out["holders"] = _uniq(list(a.get("holders") or []) + list(b.get("holders") or []))
    out["full_owned"] = _uniq(list(a.get("full_owned") or []) + list(b.get("full_owned") or []))
    out["partial"] = _uniq(list(a.get("partial") or []) + list(b.get("partial") or []))
    out["ubo"] = a.get("ubo") or b.get("ubo")
    status = dict(a.get("source_status") or {})
    for k, v in (b.get("source_status") or {}).items():
        status[k] = v if k not in status else status[k]
    out["source_status"] = status
    if isinstance(a.get("tree"), dict) and isinstance(b.get("tree"), dict):
        out["tree"] = _merge_node(a["tree"], b["tree"], canon)
    return out


def merge_trees(trees: list[dict]) -> list[dict]:
    """把指向同一主体的多张穿透图并成一张，同一父节点下的重复子节点也去掉。"""
    trees = [t for t in (trees or []) if isinstance(t, dict) and _node_name(t)]
    if len(trees) < 2:
        return trees
    amap = alias_map([t.get("name") for t in trees])

    def canon(name: str) -> str:
        k = norm_company(name)
        return amap.get(k, k)

    buckets: OrderedDict[str, dict] = OrderedDict()
    for t in trees:
        k = canon(t.get("name"))
        if k in buckets:
            buckets[k] = _merge_tree(buckets[k], t, canon)
        else:
            buckets[k] = t
    return list(buckets.values())
