"""Web 应用指纹引擎（nuclei 风格模板）。

本项目原来只有 ARL 的 `webapp.json`（约 5 千条 `headers/html/title` 关键字），
对国产 OA、路由器、摄像头、工控面板这类「标题平淡、特征只在 body 某个 js 路径里」
的站几乎认不出来。这里接入一份 1.1 万条模板的指纹库（`dicts/fingerprints/
web_fingerprints.yaml`），支持四种 matcher：

- `word`：子串匹配，可配 `condition`（or/and）
- `regex`：正则匹配
- `dsl`：只支持 `contains(part, "x")` 及其 `&& / || / !` 组合（模板里 99% 是这种）
- `favicon`：对 favicon 的 mmh3 hash 比对

匹配粒度与 `utils.FingerPrint` 一致：对一份已抓好的响应（headers/body/title/证书）
做纯本地匹配，不发请求。

模板按「命中概率」做了剪枝：`_INDEX` 把 `word` matcher 里最长的那个词做成前缀索引，
匹配时先按索引取候选，再逐条跑完整判定，避免 1.1 万条 × 每次探测都全量正则。

误报控制（语料里混着大量「一条模板就一个超通用字面量」的残缺规则，例如
`words: [jquery]`、`words: [function]`、`words: [!important;]`，任何页面都会中）：

1. `_low_info` 把纯 HTML/JS/CSS 骨架词、纯符号、单字符这类字面量标记成低信息量；
2. 同一 id 的多条模板（同产品被拆成了好几条）先合并成一条，合起来判；
3. 如果一个模板里所有非负向 matcher 都是低信息量字面量，这条模板不进索引——
   宁可漏掉几个残缺模板，也不让「所有页面都中十几个指纹」淹掉真结果；
4. 同一模板内并存的几条低信息量 matcher 不叠加成证据。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(_ROOT, "dicts")
YAML_FILE = os.path.join(DATA_DIR, "fingerprints", "web_fingerprints.yaml")
# favicon hash → 产品名，由 build_favicon_index 生成（首次运行时自动补）
FAVICON_INDEX = os.path.join(DATA_DIR, "fingerprints", "favicon_index.json")

# DSL 里允许的函数，其余一律视为模板写法错误（不执行任何东西）。
# 覆盖指纹语料里实际出现的全部写法：字符串判定、哈希、编码、正则、版本比较。
_DSL_CALLS = (
    "contains", "contains_all", "contains_any",
    "starts_with", "ends_with", "regex", "trim", "tolower", "toupper",
    "to_lower", "to_upper", "len", "concat", "replace",
    "base64", "base64_decode", "hex",
    "md5", "sha1", "sha256", "mmh3",
    "compare_versions",
)
# 这些函数作用于「整个 part 的内容」，而不是在一个 part 里找子串
_PART_FUNCS = ("md5", "sha1", "sha256", "mmh3", "len", "base64", "hex")

# 纯 HTML/JS/CSS 骨架词：单独出现时任何页面都可能命中，不能作为产品判定依据
_GENERIC_WORDS = frozenset("""
html head body title meta link script style div span a p img ul ol li table tr td form
input button select textarea label iframe frame frameset noscript font br hr h1 h2 h3 h4 h5 h6
class id name href src style type value onclick onload onerror rel charset lang
javascript js css html5 jquery bootstrap vue react angular webpack polyfill
function var let const return new this document window console prototype
true false null undefined nan length indexof tostring charat substr
important webkit moz ms- transform transition animation flex grid
display position margin padding border width height color background font
text align float clear overflow visibility opacity cursor content
login logout password username user admin index home main content page
server cache proxy http https get post put delete
error success warning info debug
""".split())

# 单字符 / 标点 / 编号类，出现的概率与产品无关
_GENERIC_RE = re.compile(
    r"^(?:[^a-z0-9\u4e00-\u9fff]{1,4}"          # 纯符号，如 "!important;" "=" "??"
    r"|\d{1,3}"                                  # 一两位数字
    r"|(?:icon|fa|glyphicon|el|van|mdi|ant)-"    # 图标字体前缀
    r")$",
    re.I)

_DSL_TOKEN = re.compile(r"""
    (?P<ws>\s+)|
    (?P<lp>\()|(?P<rp>\))|
    (?P<comma>,)|
    (?P<cmp>==|!=|>=|<=|>|<)|
    (?P<and>&&)|(?P<or>\|\|)|(?P<not>!)|
    (?P<call>[a-z_][a-z0-9_]*)\s*\(|
    (?P<num>\d+\.\d+(?:\.\d+)*|\d+)|
    (?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|
    (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
""", re.X)


@dataclass
class Matcher:
    kind: str                      # word / regex / dsl / favicon
    part: str = "body"
    words: list[str] = field(default_factory=list)
    regexes: list[re.Pattern] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    condition: str = "or"
    negative: bool = False
    expr: Any = None               # dsl 解析后的语法树


@dataclass
class Template:
    tid: str
    name: str
    tags: list[str]
    paths: list[str]
    method: str
    matchers: list[Matcher]
    condition: str = "or"
    severity: str = ""

    def as_dict(self) -> dict:
        return {"id": self.tid, "name": self.name, "tags": self.tags,
                "severity": self.severity}


def _arg_literal(node: Any) -> str:
    if isinstance(node, str):
        if len(node) >= 2 and node[0] in "\"'" and node[-1] == node[0]:
            return _unquote(node)
        return node
    if isinstance(node, tuple) and node and node[0] == "call":
        for sub in node[2]:
            got = _arg_literal(sub)
            if got:
                return got
    return ""


def _matcher_literals(m: Matcher) -> list[str]:
    """一个 matcher 用来判定的字面量（只用于低信息量评估）。"""
    if m.kind == "word":
        return list(m.words)
    if m.kind == "dsl":
        out: list[str] = []

        def walk(node: Any) -> None:
            if not node:
                return
            if node[0] == "call":
                if node[1] == "contains" and len(node[2]) >= 2:
                    out.append(_arg_literal(node[2][1]))
                # starts_with / ends_with / regex 的字面量同样有信息量
                elif node[1] in ("starts_with", "ends_with", "regex") and len(node[2]) >= 2:
                    out.append(_arg_literal(node[2][1]))
                for sub in node[2]:
                    if isinstance(sub, tuple):
                        walk(sub)
                return
            for sub in node[1:]:
                if isinstance(sub, tuple):
                    walk(sub)

        walk(m.expr)
        return out
    if m.kind == "regex":
        return [p.pattern for p in m.regexes]
    return []


def _matcher_weak(m: Matcher) -> bool:
    """正向 matcher 是否全是低信息量字面量。负向 matcher 不参与判定，反着才更严。"""
    if m.negative:
        return False
    lits = _matcher_literals(m)
    if not lits:
        return False
    return all(_low_info(x, m.part) for x in lits)


def _merge(group: list[Template]) -> Template:
    """同一 id 的多条模板合成一条。

    原来每条是独立「or」，一条只有一个 `words: [jquery]` 的残缺规则就能让整站
    都判成该产品；合并后所有 matcher 一起判，模型按整体强度决定 and / or。
    """
    base = group[0]
    if len(group) == 1:
        return base
    matchers: list[Matcher] = []
    for tpl in group:
        for m in tpl.matchers:
            if not any(_same_matcher(m, x) for x in matchers):
                matchers.append(m)
    strong = [m for m in matchers if not _matcher_weak(m)]
    # 组里有一条够硬的 matcher 就用 and，靠它撑住；全是软的则保持 or（宁可弱也别全丢）
    condition = "and" if strong else base.condition
    if condition == "and":
        matchers.sort(key=_matcher_weak)          # 硬 matcher 排前面，证据更可信
    paths: list[str] = []
    for tpl in group:
        for p in tpl.paths:
            if p not in paths:
                paths.append(p)
    tags: list[str] = []
    for tpl in group:
        for t in tpl.tags:
            if t not in tags:
                tags.append(t)
    return Template(tid=base.tid, name=base.name, tags=tags, paths=paths,
                    method=base.method, matchers=matchers, condition=condition,
                    severity=base.severity)


def _same_matcher(a: Matcher, b: Matcher) -> bool:
    if a.kind != b.kind or a.part != b.part:
        return False
    return _matcher_literals(a) == _matcher_literals(b)


def _norm_part(part: str) -> str:
    p = (part or "body").strip().lower()
    # banner 在模板里是「整段响应文本」，等价于 body + title
    return {"banner": "body", "icon": "favicon"}.get(p, p)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value if str(x).strip()]
    return [str(value)]


def _compile_regex(text: str) -> re.Pattern | None:
    try:
        return re.compile(text, re.I)
    except re.error:
        return None


def _low_info(literal: str, part: str = "body") -> bool:
    """这个字面量单独出现，能不能当产品指纹用。

    `protocol`（响应头 + body 前 4KB）和 `header` 里的短词是有意义的服务特征
    （`ssh`、`redis`、`nginx`），只在 `body` / `title` / `cert` 上做通用词判定。
    """
    s = (literal or "").strip()
    if len(s) < 4:
        return True
    if _GENERIC_RE.match(s):
        return True
    low = s.lower()
    if part in ("header", "protocol"):
        return False
    if low in _GENERIC_WORDS:
        return True
    return False


# ───────────────────────── DSL ─────────────────────────
def _parse_dsl(expr: str) -> Any:
    """把 `contains(body,"x") && !contains(header,"y")` 解析成元组语法树。

    只接受白名单函数与 && || !（和括号）。返回 None 表示不支持的写法，
    调用方直接丢掉这条模板，绝不 eval 任何文本。
    """
    tokens: list[tuple[str, str]] = []
    pos = 0
    text = expr or ""
    while pos < len(text):
        m = _DSL_TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            return None
        kind = m.lastgroup or ""
        val = m.group(kind) if kind else ""
        if kind == "call":
            tokens.append(("call", val))
        elif kind in ("str", "ident", "lp", "rp", "comma", "and", "or", "not", "num"):
            tokens.append((kind, val))
        pos = m.end()
    tokens = [t for t in tokens if t[0]]
    if not tokens:
        return None

    idx = 0

    def peek() -> tuple[str, str] | None:
        return tokens[idx] if idx < len(tokens) else None

    def parse_or():
        nonlocal idx
        node = parse_and()
        if node is None:
            return None
        while peek() and peek()[0] == "or":
            idx += 1
            rhs = parse_and()
            if rhs is None:
                return None
            node = ("or", node, rhs)
        return node

    def parse_and():
        nonlocal idx
        node = parse_not()
        if node is None:
            return None
        while peek() and peek()[0] == "and":
            idx += 1
            rhs = parse_not()
            if rhs is None:
                return None
            node = ("and", node, rhs)
        return node

    def parse_not():
        nonlocal idx
        cur = peek()
        if cur and cur[0] == "not":
            idx += 1
            inner = parse_not()
            return ("not", inner) if inner else None
        return parse_atom()

    def parse_atom():
        nonlocal idx
        cur = peek()
        if cur is None:
            return None
        kind, val = cur
        if kind == "lp":
            idx += 1
            inner = parse_or()
            if inner is None:
                return None
            nxt = peek()
            if not nxt or nxt[0] != "rp":
                return None
            idx += 1
            return inner
        if kind == "call":
            fn = val
            idx += 1
            args: list[Any] = []
            while True:
                cur = peek()
                if cur is None:
                    return None
                if cur[0] == "rp":
                    idx += 1
                    break
                idx += 1
                if cur[0] == "comma":
                    continue
                if cur[0] == "ident":
                    args.append(cur[1])
                elif cur[0] == "str":
                    args.append(_unquote(cur[1]))
                elif cur[0] == "num":
                    args.append(cur[1])
                elif cur[0] == "call":
                    # 允许嵌套，如 ends_with(to_lower(body), "x")
                    idx -= 1
                    inner = parse_atom()
                    if inner is None:
                        return None
                    args.append(("node", inner))
                else:
                    return None
            if fn not in _DSL_CALLS:
                return None
            return ("call", fn, tuple(args))
        return None

    tree = parse_or()
    if tree is None or idx != len(tokens):
        return None
    return tree


def _unquote(s: str) -> str:
    body = s[1:-1]
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)),
                  body)


def _dsl_value(node: Any, views: dict[str, str]) -> Any:
    """求一个 DSL 子表达式的值：part 名 → 内容，函数调用 → 结果，字面量 → 原样。"""
    if isinstance(node, tuple) and len(node) == 2 and node[0] == "node":
        return _dsl_value(node[1], views)
    if isinstance(node, tuple) and node and node[0] == "call":
        return _call_dsl(node[1], node[2], views)
    # 裸标识符：part 名取内容，否则当普通字符串（如 true / false / 版本号字面量）
    if isinstance(node, str) and node in views:
        return views[node]
    if isinstance(node, str):
        return {"true": True, "false": False}.get(node.lower(), node)
    return node


def _arg_str(node: Any, views: dict[str, str]) -> str:
    val = _dsl_value(node, views)
    if isinstance(val, bool):
        return "true" if val else "false"
    return "" if val is None else str(val)


def _part_blob(part: str, views: dict[str, str]) -> str | None:
    part = _norm_part(part)
    if part in ("favicon", "favicon_hash", "icon_hash"):
        return views.get("icon_hash", "")
    return views.get(part)


def _to_int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _vtuple(s: str) -> list[Any]:
    out: list[Any] = []
    for seg in re.split(r"[._\-+]", str(s or "").strip().lower()):
        if not seg:
            continue
        out.append(int(seg) if seg.isdigit() else seg)
    return out


def _call_dsl(fn: str, args: tuple, views: dict[str, str]) -> Any:
    """执行白名单函数。任何一步出错都返回 False / 空串，不抛异常影响整轮匹配。"""
    try:
        if fn in ("contains", "starts_with", "ends_with", "regex"):
            if len(args) < 2:
                return False
            blob = _part_blob(str(args[0]), views)
            if blob is None:
                return False
            needle = _arg_str(args[1], views)
            if fn == "contains":
                return needle.lower() in blob.lower()
            if fn == "starts_with":
                return blob.lower().startswith(needle.lower())
            if fn == "ends_with":
                return blob.lower().endswith(needle.lower())
            return re.search(needle, blob, re.I) is not None

        if fn in ("contains_all", "contains_any"):
            if len(args) < 2:
                return False
            blob = _part_blob(str(args[0]), views)
            if blob is None:
                return False
            low = blob.lower()
            needles = [_arg_str(a, views).lower() for a in args[1:]]
            return all(n in low for n in needles) if fn == "contains_all" else any(n in low for n in needles)

        if fn == "len":
            blob = _part_blob(str(args[0]), views) if args else None
            return len(blob or "")

        if fn in ("trim", "tolower", "to_lower", "toupper", "to_upper", "base64", "hex"):
            val = _arg_str(args[0], views) if args else ""
            if fn == "trim":
                return val.strip()
            if fn in ("tolower", "to_lower"):
                return val.lower()
            if fn in ("toupper", "to_upper"):
                return val.upper()
            if fn == "base64":
                return base64.b64encode(val.encode("utf-8", "ignore")).decode()
            return val.encode("utf-8", "ignore").hex()

        if fn == "base64_decode":
            val = _arg_str(args[0], views) if args else ""
            try:
                return base64.b64decode(val + "=" * (-len(val) % 4)).decode("utf-8", "ignore")
            except Exception:
                return ""

        if fn in ("md5", "sha1", "sha256", "mmh3"):
            if not args:
                return ""
            raw = _arg_str(args[0], views).encode("utf-8", "ignore")
            if fn in ("md5", "sha1", "sha256"):
                return hashlib.new(fn, raw).hexdigest()
            try:
                import mmh3  # 可选依赖，缺失时用纯 Python 实现
                return str(mmh3.hash(raw))
            except Exception:
                return str(_mmh3_32(raw))

        if fn == "concat":
            return "".join(_arg_str(a, views) for a in args)

        if fn == "replace":
            if len(args) < 3:
                return ""
            return _arg_str(args[0], views).replace(_arg_str(args[1], views), _arg_str(args[2], views))

        if fn == "compare_versions":
            if len(args) < 2:
                return False
            a = _arg_str(args[0], views)
            b = _arg_str(args[1], views)
            op = _arg_str(args[2], views) if len(args) > 2 else ">"
            ta, tb = _vtuple(a), _vtuple(b)
            return {"==": ta == tb, "=": ta == tb, "!=": ta != tb,
                    ">": ta > tb, ">=": ta >= tb, "<": ta < tb, "<=": ta <= tb}.get(op, False)
    except Exception:
        return False
    return False


def _mmh3_32(raw: bytes) -> int:
    """murmur3 32 位有符号，与 favicon hash 口径一致；无 mmh3 扩展时兜底。"""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h, n = 0, len(raw)
    for i in range(0, n - n % 4, 4):
        k = int.from_bytes(raw[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = raw[n - n % 4:]
    if tail:
        k = int.from_bytes(tail + b"\x00" * (4 - len(tail)), "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def _eval_dsl(node: Any, views: dict[str, str]) -> bool:
    if node is None:
        return False
    op = node[0]
    if op == "and":
        return _eval_dsl(node[1], views) and _eval_dsl(node[2], views)
    if op == "or":
        return _eval_dsl(node[1], views) or _eval_dsl(node[2], views)
    if op == "not":
        return not _eval_dsl(node[1], views)
    if op == "call":
        # 顶层调用一律按布尔看待：哈希/长度类结果用来和字面量比，直接判真假没有意义，
        # 只有 contains / regex / starts_with 这类才可能出现在布尔位置。
        val = _call_dsl(node[1], node[2], views)
        return bool(val)
    return False


# ───────────────────────── 引擎 ─────────────────────────
class WebFingerprintEngine:
    """1.1 万条模板的本地匹配引擎。加载一次，常驻。"""

    def __init__(self, yaml_path: str = YAML_FILE, favicon_index: str = FAVICON_INDEX) -> None:
        self.templates: list[Template] = []
        self._index: dict[str, list[int]] = {}
        self._favicon_map: dict[str, str] = {}
        self.errors = 0
        self._load(yaml_path)
        self._load_favicon(favicon_index)

    # ---------- 加载 ----------
    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            return
        try:
            rows = yaml.safe_load(open(path, encoding="utf-8", errors="ignore").read())
        except Exception:
            return
        if not isinstance(rows, list):
            return
        groups: dict[str, list[Template]] = {}
        order: list[str] = []
        for row in rows:
            tpl = self._build(row)
            if tpl is None:
                continue
            if tpl.tid in groups:
                # 同产品被拆成多条（语料里 232 组）：合起来才能判真伪
                groups[tpl.tid].append(tpl)
            else:
                groups[tpl.tid] = [tpl]
                order.append(tpl.tid)
        for tid in order:
            self.templates.append(_merge(groups[tid]))
        self._build_index()

    def _build(self, row: Any) -> Template | None:
        if not isinstance(row, dict):
            return None
        tid = str(row.get("id") or "").strip()
        info = row.get("info") or {}
        if not tid or not isinstance(info, dict):
            return None
        name = str(info.get("name") or tid).strip()
        tags = _as_list(info.get("tags"))
        if isinstance(info.get("tags"), str):
            tags = [t.strip() for t in info["tags"].split(",") if t.strip()]
        matchers: list[Matcher] = []
        for m in row.get("matchers") or []:
            if not isinstance(m, dict):
                continue
            built = self._build_matcher(m)
            if built is not None:
                matchers.append(built)
        if not matchers:
            self.errors += 1
            return None
        paths = [str(p) for p in _as_list(row.get("path"))] or ["/"]
        return Template(tid=tid, name=name, tags=tags, paths=paths,
                        method=str(row.get("method") or "GET").upper(),
                        matchers=matchers,
                        condition=str(row.get("matchers-condition") or "or").lower(),
                        severity=str(info.get("severity") or ""))

    def _build_matcher(self, m: dict) -> Matcher | None:
        kind = str(m.get("type") or "").lower()
        part = _norm_part(str(m.get("part") or "body"))
        cond = str(m.get("condition") or "or").lower()
        neg = bool(m.get("negative"))
        # 模板里大量 `case-insensitive: true`；统一按不区分大小写处理
        if kind == "word":
            words = _as_list(m.get("words"))
            if not words:
                return None
            return Matcher("word", part, words=words, condition=cond, negative=neg)
        if kind == "regex":
            pats = [p for p in (_compile_regex(r) for r in _as_list(m.get("regex"))) if p]
            if not pats:
                return None
            return Matcher("regex", part, regexes=pats, condition=cond, negative=neg)
        if kind == "dsl":
            trees = [t for t in (_parse_dsl(e) for e in _as_list(m.get("dsl"))) if t]
            if not trees:
                return None
            tree = trees[0]
            for extra in trees[1:]:          # 多条 dsl 按 or 合并，等价于模板默认语义
                tree = ("or", tree, extra)
            return Matcher("dsl", part, expr=tree, condition=cond, negative=neg)
        if kind == "favicon":
            hashes = [h.strip() for h in _as_list(m.get("hash"))]
            if not hashes:
                for sub in m.get("hashes") or []:
                    if isinstance(sub, dict):
                        hashes.extend(_as_list(sub.get("hash")))
            hashes = [h for h in hashes if h]
            if not hashes:
                return None
            return Matcher("favicon", "favicon", hashes=hashes, condition=cond, negative=neg)
        # status / size：按数值精确比，语料里用于把同产品不同版本或错误页区分开
        if kind in ("status", "status_code"):
            nums = [_to_int(x) for x in _as_list(m.get("status"))]
            nums = [n for n in nums if n is not None]
            if not nums:
                return None
            return Matcher("status", "status_code", words=[str(n) for n in nums],
                           condition=cond, negative=neg)
        if kind == "size":
            nums = [_to_int(x) for x in _as_list(m.get("size"))]
            nums = [n for n in nums if n is not None]
            if not nums:
                return None
            return Matcher("size", "length", words=[str(n) for n in nums],
                           condition=cond, negative=neg)
        # binary 等其它类型：本项目用不到，静默跳过
        return None

    def _build_index(self) -> None:
        """`word` matcher 的第一个词做前缀索引；无可用键的进兜底桶。

        整条模板的正向 matcher 全是低信息量字面量（`words: [jquery]` 之类残缺规则）
        时直接不进索引：放进兜底桶会让每个页面都多认十几个产品。
        """
        self._index = {}
        self.dropped = 0
        for i, tpl in enumerate(self.templates):
            positive = [m for m in tpl.matchers if not m.negative]
            if positive and all(_matcher_weak(m) for m in positive):
                self.dropped += 1
                continue
            keys = []
            for m in tpl.matchers:
                if m.negative:
                    continue
                if m.kind == "word" and m.words:
                    if not _low_info(m.words[0], m.part):
                        keys.append(m.words[0].lower()[:24])
                elif m.kind == "dsl" and m.expr:
                    lit = _first_literal(m.expr)
                    if lit and not _low_info(lit):
                        keys.append(lit.lower()[:24])
                elif m.kind == "favicon":
                    keys.append("")           # favicon 类只在有这个 hash 时才有意义
            if not keys:
                self._index.setdefault("", []).append(i)
                continue
            for k in keys:
                self._index.setdefault(k, []).append(i)

    def _load_favicon(self, path: str) -> None:
        if not os.path.exists(path):
            return
        try:
            data = json.loads(open(path, encoding="utf-8").read())
        except Exception:
            return
        if isinstance(data, dict):
            self._favicon_map = {str(k): str(v) for k, v in data.items()}

    # ---------- 匹配 ----------
    def match(self, *, headers: dict | None = None, body: str = "", title: str = "",
              cert: str = "", favicon_hash: str | int = 0, status: int | str = 0,
              length: int | str = 0, host: str = "") -> list[dict]:
        """返回命中的模板列表（含名称/标签/证据），按命中 matcher 数降序。

        status / length 给的是响应状态码与长度，host 用于 vhost 类模板判定。
        """
        header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
        views = {
            "body": (body or "")[:400000].lower(),
            "header": header_blob,
            "title": (title or "").lower(),
            "cert": (cert or "").lower(),
            "protocol": f"{header_blob}\n{(body or '')[:4000].lower()}",
            "icon_hash": str(favicon_hash or ""),
            "status_code": str(status or ""),
            "length": str(length or ""),
            "host": (host or "").lower(),
        }
        hits: list[dict] = []
        seen: set[int] = set()
        for idx in self._candidates(views):
            if idx in seen:
                continue
            seen.add(idx)
            tpl = self.templates[idx]
            ok, ev = self._eval_template(tpl, views)
            if ok:
                hits.append({**tpl.as_dict(), "evidence": ev})
        hits.sort(key=lambda h: -len(h["evidence"]))
        return hits

    def _candidates(self, views: dict[str, str]) -> Iterable[int]:
        """按索引挑候选；索引取不到时退回全量（保证不漏，只是慢一点）。"""
        blobs = [views["body"], views["header"], views["title"], views["cert"]]
        picked: list[int] = list(self._index.get("", []))
        found = False
        for key, idxs in self._index.items():
            if not key:
                continue
            if any(key in blob for blob in blobs):
                picked.extend(idxs)
                found = True
        if not found:
            return range(len(self.templates))
        return picked

    def _eval_template(self, tpl: Template, views: dict[str, str]) -> tuple[bool, list[str]]:
        evidence: list[str] = []
        results: list[bool] = []
        for m in tpl.matchers:
            got, ev = self._eval_matcher(m, views)
            results.append(got)
            # 低信息量 matcher 不叠加成证据，否则「jquery 命中了」会被当成强证据排前面
            if got and ev and not _matcher_weak(m):
                evidence.append(ev)
        if not results:
            return False, []
        ok = all(results) if tpl.condition == "and" else any(results)
        return ok, evidence

    def _eval_matcher(self, m: Matcher, views: dict[str, str]) -> tuple[bool, str]:
        if m.kind == "word":
            blob = views.get(m.part, "")
            hit = [w for w in m.words if w.lower() in blob]
            got = (len(hit) == len(m.words)) if m.condition == "and" else bool(hit)
            if m.negative:
                got = not got
                return got, ""
            return got, (f"word:{hit[0][:60]}" if got else "")
        if m.kind == "regex":
            blob = views.get(m.part, "")
            hit = [p.pattern for p in m.regexes if p.search(blob)]
            got = (len(hit) == len(m.regexes)) if m.condition == "and" else bool(hit)
            if m.negative:
                got = not got
                return got, ""
            return got, (f"regex:{hit[0][:60]}" if got else "")
        if m.kind == "dsl":
            got = _eval_dsl(m.expr, views)
            if m.negative:
                return (not got), ""
            return got, ("dsl" if got else "")
        if m.kind == "favicon":
            h = str(views.get("icon_hash") or "")
            got = bool(h) and (h in m.hashes)
            if m.negative:
                return (not got), ""
            return got, ("favicon" if got else "")
        if m.kind in ("status", "size"):
            got = str(views.get(m.part) or "") in m.words
            if m.negative:
                return (not got), ""
            return got, (f"{m.kind}:{views.get(m.part)}" if got else "")
        return False, ""

    # ---------- 辅助 ----------
    def match_favicon(self, favicon_hash: str | int) -> str:
        return self._favicon_map.get(str(favicon_hash or ""), "")

    def by_tag(self, tag: str) -> list[Template]:
        t = (tag or "").lower()
        return [x for x in self.templates if t in [g.lower() for g in x.tags]]

    def stats(self) -> dict:
        kinds: dict[str, int] = {}
        for tpl in self.templates:
            for m in tpl.matchers:
                kinds[m.kind] = kinds.get(m.kind, 0) + 1
        return {"templates": len(self.templates), "matchers": kinds,
                "errors": self.errors, "dropped": getattr(self, "dropped", 0),
                "favicon_index": len(self._favicon_map)}


def _first_literal(node: Any) -> str:
    """取 DSL 树里第一个够长的字面量，用作前缀索引的键。"""
    if not node:
        return ""
    if node[0] == "call":
        if node[1] in ("contains", "starts_with", "ends_with", "regex") and len(node[2]) >= 2:
            lit = _arg_literal(node[2][1])
            return lit if len(lit) >= 4 else ""
        for sub in node[2]:
            got = _first_literal(sub) if isinstance(sub, tuple) else ""
            if got:
                return got
        return ""
    for sub in node[1:]:
        got = _first_literal(sub) if isinstance(sub, tuple) else ""
        if got:
            return got
    return ""


@lru_cache(maxsize=1)
def engine() -> WebFingerprintEngine:
    return WebFingerprintEngine()


def match(*, headers: dict | None = None, body: str = "", title: str = "",
          cert: str = "", favicon_hash: str | int = 0) -> list[dict]:
    return engine().match(headers=headers, body=body, title=title, cert=cert,
                          favicon_hash=favicon_hash)
