"""前端代码美化 / 格式化：把压缩成一行的 JS、HTML、JSON 还原成可读结构。

用途是逆向：从站上抓下来的包，压缩后没法按行读，也不方便找接口和参数。这里只做
结构重排，不改语义；解析失败原样返回并带上错误原因，不让调用方猜。
"""
from __future__ import annotations

import json
import re

# ───────────── 分词 ─────────────
_TOKEN_RE = re.compile(
    r"""(?P<str>'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`)"""
    r"""|(?P<lc>//[^\n]*)"""
    r"""|(?P<bc>/\*[\s\S]*?\*/)"""
    r"""|(?P<re>/(?![*/])(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[gimsuy]*)"""
    r"""|(?P<num>0[xXbBoO][0-9a-fA-F_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d+)(?:[eE][+-]?\d+)?)"""
    r"""|(?P<word>[A-Za-z_$\u00c0-\uffff][\w$\u00c0-\uffff]*)"""
    r"""|(?P<punc>[{}()\[\];,:.=+\-*/%<>!&|^~?@#\\])"""
    r"""|(?P<ws>\s+)"""
    r"""|(?P<other>.)""",
    re.S,
)


def _tokens(src: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _TOKEN_RE.finditer(src or ""):
        out.append((m.lastgroup or "other", m.group()))
    return out


_LITERAL_PREV_PUNC = set("=(:,[!&|?+-*/%<>^~")
_LITERAL_PREV_WORD = set(
    "return typeof in of instanceof new await void case yield delete throw".split()
)


def _in_literal_ctx(toks: list[tuple[str, str]], i: int) -> bool:
    """`{` 前面若是赋值 / 逗号 / 冒号这类位置，就当对象字面量，否则当代码块。"""
    j = i - 1
    while j >= 0 and toks[j][0] in ("lc", "bc"):
        j -= 1
    if j < 0:
        return False
    kind, text = toks[j]
    if kind == "punc":
        return text in _LITERAL_PREV_PUNC or text == "=>"
    if kind == "word":
        return text in _LITERAL_PREV_WORD
    return False


# ───────────── JS ─────────────
# 判断两个相邻 token 之间要不要空一格。除下面这些「贴在一起」的组合外，默认隔开。
_TIGHT_BEFORE = set(")]},;.:[")                 # 紧跟前面：`f(x)` / `a.b` / `b: 1`
_TIGHT_AFTER = set(".!([")                       # 紧跟后面：`o.a` / `f(x)` / `[1,2]`
_UNARY_PREV_PUNC = set("([{,;:=!&|?+-*/%<>^~")  # 这些位置后面的一元号与操作数贴住
_UNARY_PREV_WORD = set(
    "return typeof in of instanceof new await void case yield delete throw".split()
)


def _prev_is_operator_slot(prev) -> bool:
    """前一个 token 处于「后面该跟表达式」的位置（`=`、`(`、`return` 等）。"""
    if not prev:
        return True
    kind, text = prev
    if kind == "punc":
        return text in _UNARY_PREV_PUNC or text in ("=>", "==", "===", "!=", "!==")
    if kind == "word":
        return text in _UNARY_PREV_WORD
    return False


def _looks_like_param_list(toks: list[tuple[str, str]], i: int) -> bool:
    """`toks[i]` 是参数列表里的 `{`：往前找配对的开括号，看它后面跟 `=>` 还是 `{`。

    `function f({a})`、`({a}) => …`、`f(({a}) => …)` 算参数解构；
    `f({a: 1})`（调用实参里的对象字面量）不算。
    """
    depth = 0
    j = i - 1
    while j >= 0:
        kind, text = toks[j]
        if kind == "punc":
            if text in ")]}":
                depth += 1
            elif text in "([{":
                if depth == 0:
                    break
                depth -= 1
            elif text == ";" and depth == 0:
                return False
        j -= 1
    if j < 0 or toks[j][1] != "(":
        return False
    # 从内层 `{` 配对到它自己的 `}`，再跳过 `= 默认值`，最后看外层闭括号后跟什么
    depth = 0
    j = i
    while j < len(toks):
        kind, text = toks[j]
        if kind == "punc":
            if text in "([{":
                depth += 1
            elif text in ")]}":
                depth -= 1
                if depth == 0:
                    break
        j += 1
    j += 1
    while j < len(toks):
        kind, text = toks[j]
        if kind == "punc" and text == "=":
            # 参数默认值：跳过 `= 一个表达式`，直到外层逗号或右括号
            j += 1
            depth2 = 0
            while j < len(toks):
                k2, t2 = toks[j]
                if k2 == "punc" and t2 in "([{":
                    depth2 += 1
                elif k2 == "punc" and t2 in ")]}":
                    if depth2 == 0:
                        break
                    depth2 -= 1
                elif k2 == "punc" and t2 == "," and depth2 == 0:
                    break
                j += 1
            continue
        if kind == "punc" and text in ")]}":
            nxt = toks[j + 1] if j + 1 < len(toks) else None
            return bool(nxt and nxt[1] in ("=>", "{"))
        if kind == "punc" and text in "([{":
            break                          # 又冒出别的括号，说明不是参数列表
        j += 1
    return False


def _js_needs_space(a_kind: str, a: str, b_kind: str, b: str) -> bool:
    """两个相邻 token 之间是否需要留一个空格。`a` 是前一个 token。"""
    if a_kind in ("lc", "bc"):
        return True
    if a == "?." or a == "...":
        return False
    # 一元 `!` / `~` 贴住后面的操作数（`!a`、`~b`）
    if a_kind == "punc" and a in ("!", "~"):
        return False
    # 收尾符后面接运算符要留空格：`a[0] ?? 1` / `{} + x`；接调用和下标则贴住
    if a_kind == "punc" and a in ")]}":
        return not (b_kind == "punc" and b in "([{")
    if b_kind == "punc" and b in _TIGHT_BEFORE:
        return False
    if a_kind == "punc" and a in _TIGHT_AFTER:
        return False
    if a_kind == "punc" and b_kind == "punc":
        return False                       # `i++` / `a += b`：运算符连写不受空格影响
    return True


def _unary_operand_after_dash(toks, i: int) -> bool:
    """`-` / `+` 处在表达式起始位置时，是把它和后面的操作数贴住的一元号。"""
    j = i - 1
    while j >= 0 and toks[j][0] in ("lc", "bc"):
        j -= 1
    return _prev_is_operator_slot(toks[j] if j >= 0 else None)


def beauty_js(text: str, indent: int = 2, *, keep_comments: bool = True,
              max_lines: int = 60000) -> str:
    """JS/TS 美化：按语句与代码块重排缩进，字符串 / 正则 / 模板串整体保留。

    花括号一律展开缩进；括号内部的逗号不换行，只有语句结束（`;`）和代码块闭合处
    断行，保证输出能按行读。数组摊平在一行，对象字面量一项一行。
    """
    toks: list[tuple[str, str]] = []
    for kind, raw in _tokens(text or ""):
        if kind == "ws":
            continue
        if kind in ("lc", "bc") and not keep_comments:
            continue
        toks.append((kind, raw))

    pad = " " * max(1, indent)
    out: list[str] = []
    levels: list[int] = []
    segs: list[str] = []            # 当前行的片段
    spaces: list[bool] = []         # 片段与前一个片段之间要不要空格
    depth = 0
    paren = 0
    bracket = 0                     # `[...]` 内不断行，数组摊平更好读
    literal: list[bool] = []        # `{` 是对象字面量还是代码块
    line_level = 0
    skip = 0                        # 复合运算符已整段吐出，跳过后续成员
    force_next = False              # 下一个片段前强制空格（`1 + +2` 的第二个号）
    tie_next = False                # 下一个片段贴住前文（一元号与操作数）
    empty_block = False             # `{}` 左花括号已吐出，等右花括号贴住收尾
    destructure = 0                 # 正在 `const {a, b} = obj` 的解构花括号里
    declaring = False               # 正在 var/let/const 声明里，多个声明符保持一行
    last: tuple[str, str] | None = None   # 上一个真正吐出的 token（跳过复合运算符尾部）

    def flush() -> None:
        nonlocal segs, spaces, line_level
        row = "".join((" " if w else "") + s for s, w in zip(segs, spaces)).rstrip()
        if row.strip():
            out.append(row)
            levels.append(max(0, line_level))
        segs, spaces = [], []
        line_level = depth

    def emit(seg: str, want_space: bool = False, kind: str = "") -> None:
        nonlocal last, force_next, tie_next
        # 行首片段前面没有东西，不占空格位；其余按判定结果排
        spaces.append(((bool(want_space) or force_next) and not tie_next)
                      and bool(segs))
        force_next = False
        tie_next = False
        segs.append(seg)
        if kind:
            last = (kind, seg)

    def force_space() -> None:
        """强制当前片段前留一个空格（用于 `=>` 右侧这种一定要有空格的位置）。"""
        if spaces:
            spaces[-1] = True

    def spaced_by_prev(kind: str, tok: str, prev) -> bool:
        return bool(prev) and _js_needs_space(prev[0], prev[1], kind, tok)

    def line_text() -> str:
        return "".join((" " if w else "") + s for s, w in zip(segs, spaces)).strip()

    for i, (kind, tok) in enumerate(toks):
        if skip:
            skip -= 1
            continue
        if len(out) >= max_lines:
            flush()
            out.append("/* 输出已达行数上限，其余内容未展开 */")
            levels.append(0)
            break
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        prev = last

        if kind == "punc" and tok == "{":
            # `const {a, b} = obj` 这种解构留在同一行，按语句规则展开会把 `= obj` 断开
            destructuring = bool(
                prev and (
                    (prev[0] == "word" and prev[1] in ("const", "let", "var"))
                    or prev[1] == "=>"
                    # 函数参数解构：`function f({a})` / `({a}) => …`
                    or (prev[0] == "punc" and prev[1] == "("
                        and _looks_like_param_list(toks, i))
                ))
            literal.append(_in_literal_ctx(toks, i) and not destructuring)
            if destructuring:
                # `(`、`,` 后面的解构紧贴；`const {` / `=> {` 后面留一格
                emit("{", want_space=not (
                    prev and prev[0] == "punc" and prev[1] in ("(", ",")), kind="punc")
                depth += 1
                destructure += 1
                continue
            # `{}` 空对象 / 空函数体留成一行，等下一个 token `}` 收尾
            if nxt and nxt[0] == "punc" and nxt[1] == "}":
                emit("{", want_space=bool(prev) and not (
                    prev[0] == "punc" and prev[1] in "({["), kind="punc")
                literal.pop()
                literal.append(False)
                empty_block = True
                continue
            # 代码块和对象字面量的左花括号都跟前文隔一个空格（`){` 不隔）
            emit("{", want_space=bool(prev) and not (
                prev[0] == "punc" and prev[1] in "({["), kind="punc")
            flush()
            depth += 1
            line_level = depth
            continue

        if kind == "punc" and tok == "}":
            in_obj = bool(literal and literal[-1])
            if literal:
                literal.pop()
            if empty_block:
                # `{}` 已在上一轮把左花括号吐出，这里只贴右花括号收尾
                empty_block = False
                emit("}", kind="punc")
                if nxt and nxt[0] == "punc" and nxt[1] in "),;.=:":
                    continue
                flush()
                continue
            # 同一行里还没 flush 过（解构 / 内联对象收尾）就只贴右花括号
            inline = not out or line_level != depth
            if inline and segs:
                depth = max(0, depth - 1)
                line_level = depth
                if destructure:
                    destructure -= 1
                    emit("}", want_space=True, kind="punc")   # `{ a, b }` 收尾留一格
                else:
                    emit("}", kind="punc")
                if nxt and nxt[0] == "punc" and nxt[1] in "),;.=:":
                    continue
                flush()
                continue
            flush()
            depth = max(0, depth - 1)
            line_level = depth
            emit("}", kind="punc")
            if not in_obj and nxt and nxt[0] == "word" and nxt[1] in (
                    "else", "catch", "finally", "while"):
                continue
            if nxt and nxt[0] == "punc" and nxt[1] in "),;.=":
                continue
            flush()
            continue

        if kind == "punc" and tok == "?" and not (
                nxt and nxt[0] == "punc" and nxt[1] in (".", "?")):
            # `a ? b : c` 的问号两边各留一格；`?.` / `??` 在下面单独处理
            emit("?", want_space=True, kind="punc")
            force_next = True
            continue

        if kind == "punc" and tok == ":":
            # 三元 `a ? b : c` 的两侧留空格；对象键 `b: 1` 与解构 `{a, b: c}` 贴住
            ternary = "?" in segs and "{" not in segs
            emit(":", want_space=ternary, kind="punc")
            force_next = ternary
            continue

        if kind == "punc" and tok == ";":
            declaring = False
            emit(";", kind="punc")
            if paren <= 0 and not (literal and literal[-1]):
                flush()
            continue

        if kind == "punc" and tok == ",":
            emit(",", kind="punc")
            # 对象字面量一项一行（即使整段在调用括号里）；
            # 数组 / 解构 / 参数列表里的逗号留在行内，`const a=1,b=2` 也保持一行
            if destructure or declaring or bracket > 0:
                continue
            if paren > 0 and not (literal and literal[-1]):
                continue                   # 调用实参 / 普通括号里不断行
            flush()
            continue

        if kind == "punc" and tok == "[":
            bracket += 1
            # `a = [1]` / `f([1])` 里，只有紧跟标识符和右括号时才是下标（`a[0]`）
            tight = bool(prev) and (
                prev[0] in ("word", "num", "str", "re")
                or (prev[0] == "punc" and prev[1] in (")", "]"))
                or prev[1] in ("?.", "...", "?.["))
            # 数组开括号只跟自己的元素贴住，`a = [` 右侧仍要隔一格
            emit("[", want_space=not tight and not (
                prev and prev[0] == "punc" and prev[1] in ("[", "?.[")), kind="punc")
            continue

        if kind == "punc" and tok == "]":
            bracket = max(0, bracket - 1)
            emit("]", kind="punc")
            continue

        if kind == "punc" and tok == "(":
            # 关键字 / 赋值 / 逗号后面跟括号要隔开（`if (`、`= (`、`, (`）；
            # 函数调用与函数声明贴住（`f(`、`function f(`）
            tail = line_text()
            spaced = bool(
                re.search(r"\b(?:if|for|while|switch|catch|with|typeof|void)$", tail)
                or re.search(r"[=,:(]$", tail))
            emit("(", want_space=spaced, kind="punc")
            paren += 1
            continue

        if kind == "punc" and tok == ")":
            paren = max(0, paren - 1)
            emit(")", kind="punc")
            continue

        if kind in ("lc", "bc"):
            emit(tok, want_space=True, kind=kind)
            if tok.startswith("/*"):
                continue
            flush()
            continue

        if kind == "punc" and tok == "=" and nxt and nxt[0] == "punc" and nxt[1] in ("=", ">"):
            # `=>` / `==` / `===` / `=<` 这类复合运算符整段一次吐出，
            # 避免逐个符号各自判空格时把 `=>` 拆成 `= >`。
            seq = tok
            j = i + 1
            while j < len(toks) and toks[j][0] == "punc" and toks[j][1] in "=>=":
                seq += toks[j][1]
                j += 1
            emit(seq, want_space=spaced_by_prev(kind, tok, prev), kind="punc")
            if seq == "=>" and prev is not None:
                force_space()              # `(q) => …` 前面留空格更接近手写风格
            skip = j - i - 1
            continue

        if kind == "punc" and tok in "+-" and nxt and nxt[0] == "punc" and nxt[1] == tok:
            after = toks[i + 2] if i + 2 < len(toks) else None
            # 自增自减：前缀 `++i` 跟操作数贴住，后缀 `i++` 跟变量贴住
            if _prev_is_operator_slot(prev):
                emit(tok + tok, kind="punc")
                skip = 1
                continue
            # 第二个号后面直接跟操作数 → 它是一元号（`1 + +2`），必须跟第一个隔开
            unary = after is not None and (
                after[0] in ("num", "str")
                or (after[0] == "word" and after[1] not in ("instanceof", "in"))
                or (after[0] == "punc" and after[1] in "([{!")
            )
            if unary:
                emit(tok, want_space=spaced_by_prev(kind, tok, prev), kind="punc")
                force_next = True
            else:
                emit(tok + tok, kind="punc")
            skip = 0 if unary else 1
            continue

        if kind == "punc" and tok == "." and nxt and nxt[0] == "punc" and nxt[1] == ".":
            # `...` 展开运算符整段吐出
            j = i + 1
            seq = tok
            while j < len(toks) and toks[j][0] == "punc" and toks[j][1] == ".":
                seq += "."
                j += 1
            emit(seq, want_space=spaced_by_prev(kind, tok, prev), kind="punc")
            skip = j - i - 1
            continue

        if kind == "punc" and tok == ".":
            # 成员访问 / 链式调用一律贴住（`a.b`、`arr.map(…)`）
            emit(".", kind="punc")
            continue

        if kind == "punc" and tok == "?" and nxt and nxt[0] == "punc" and nxt[1] == ".":
            # `?.` 可选链，两边都贴住（`a?.b`）
            emit("?.", kind="punc")
            skip = 1
            continue

        if kind == "punc" and tok == "?" and nxt and nxt[0] == "punc" and nxt[1] == "?":
            # `??` 空值合并整段吐出
            emit("??", want_space=spaced_by_prev(kind, tok, prev), kind="punc")
            skip = 1
            continue

        if kind == "punc" and tok in "<>" and prev and prev[1] == tok:
            emit(tok, kind="punc")
            continue

        if kind == "punc" and tok in ("+", "-") and not (
                nxt and nxt[0] == "punc" and nxt[1] == tok):
            # 表达式起始处的一元号跟操作数贴住（`x = -1`），二元号照常隔开（`a - 1`）
            if _unary_operand_after_dash(toks, i):
                emit(tok, want_space=spaced_by_prev(kind, tok, prev), kind="punc")
                force_next = False
                tie_next = True
                continue

        if kind == "word" and tok in ("var", "let", "const") and paren <= 0:
            declaring = True

        emit(tok, want_space=spaced_by_prev(kind, tok, prev), kind=kind)

    flush()
    return "\n".join(pad * lv + row for lv, row in zip(levels, out))


# ───────────── JSON ─────────────
def beats_json(text: str, indent: int = 2) -> str:
    """JSON 美化；解析失败抛 ValueError 并说明位置。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON 解析失败：第 {exc.lineno} 行第 {exc.colno} 列，{exc.msg}") from exc
    return json.dumps(data, ensure_ascii=False, indent=indent)


def json_paths(text: str, limit: int = 500) -> list[str]:
    """把 JSON 的字段路径摊平，形如 `data.list[].id : int = 1`，便于找接口参数。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON 解析失败：第 {exc.lineno} 行第 {exc.colno} 列，{exc.msg}") from exc

    rows: list[str] = []

    def walk(node, path: str) -> None:
        if len(rows) >= limit:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                walk(val, f"{path}.{key}" if path else str(key))
        elif isinstance(node, list):
            if not node:
                rows.append(f"{path} : list = []")
                return
            for val in node[:3]:
                walk(val, f"{path}[]")
        else:
            rows.append(
                f"{path} : {type(node).__name__} = "
                f"{json.dumps(node, ensure_ascii=False)[:120]}")

    walk(data, "")
    return rows[:limit]


# ───────────── HTML ─────────────
_BLOCK_TAGS = {
    "html", "head", "body", "div", "section", "article", "header", "footer", "nav",
    "aside", "main", "ul", "ol", "li", "dl", "dt", "dd", "table", "thead", "tbody",
    "tfoot", "tr", "td", "th", "form", "fieldset", "figure", "figcaption", "p", "pre",
    "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "select", "option", "textarea",
    "button", "label", "video", "audio", "canvas", "template", "dialog", "details",
    "summary", "title",
}
_VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}
_INLINE_ATTR_TAGS = _VOID_TAGS | {
    "a", "b", "i", "em", "strong", "span", "code", "label", "button", "sub", "sup",
}
_TAG_RE = re.compile(r"""<(/?)([A-Za-z][\w:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>""")
_ATTR_RE = re.compile(r"""([\w:.-]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+))?""")


def _format_attrs(attrs: str) -> str:
    pairs = []
    for m in _ATTR_RE.finditer(attrs or ""):
        name, val = m.group(1), m.group(2)
        pairs.append(name if val is None else f"{name}={val}")
    return (" " + " ".join(pairs)) if pairs else ""


def beauty_html(text: str, indent: int = 2, *, beautify_inline: bool = True) -> str:
    """HTML 美化：标签逐层缩进，`<script>` / `<style>` 内容分别走 JS / CSS 缩进。"""
    src = text or ""
    pad = " " * max(1, indent)
    out: list[str] = []
    depth = 0

    def push(line: str, level: int | None = None) -> None:
        if line.strip():
            out.append(pad * max(0, depth if level is None else level) + line)

    pos = 0
    for m in _TAG_RE.finditer(src):
        gap = src[pos:m.start()]
        if gap.strip():
            push(re.sub(r"\s+", " ", gap).strip())
        pos = m.end()
        closing, tag, attrs = m.group(1) == "/", m.group(2).lower(), m.group(3)

        if tag in ("script", "style"):
            end = src.lower().find(f"</{tag}", pos)
            if end < 0:
                continue
            body = src[pos:end]
            tail_close = _TAG_RE.match(src, end)
            pos = tail_close.end() if tail_close else end
            push(f"<{tag}{_format_attrs(attrs)}>")
            depth += 1
            if body.strip() and beautify_inline:
                try:
                    inner = (beauty_js(body, indent, max_lines=20000)
                             if tag == "script" else _beauty_css(body, indent))
                except Exception:  # noqa: BLE001 - 美化失败就原样保留
                    inner = body.strip()
                for line in inner.splitlines():
                    push(line)
            elif body.strip():
                push(body.strip())
            depth = max(0, depth - 1)
            push(f"</{tag}>")
            continue

        if closing:
            depth = max(0, depth - 1)
            push(f"</{tag}>")
            continue

        if tag in _VOID_TAGS or attrs.rstrip().endswith("/"):
            push(f"<{tag}{_format_attrs(attrs)}>")
            continue

        close = src.find(f"</{tag}", pos)
        inner_text = src[pos:close] if close >= 0 else ""
        short = close >= 0 and "<" not in inner_text and len(inner_text) < 80
        if short and (tag not in _BLOCK_TAGS or tag in _INLINE_ATTR_TAGS):
            end = src.find(">", close)
            pos = end + 1 if end >= 0 else pos
            push(f"<{tag}{_format_attrs(attrs)}>{inner_text.strip()}</{tag}>")
            continue

        push(f"<{tag}{_format_attrs(attrs)}>")
        depth += 1

    tail = src[pos:]
    if tail.strip():
        push(re.sub(r"\s+", " ", tail).strip())
    return "\n".join(out)


def _beauty_css(text: str, indent: int = 2) -> str:
    """CSS 美化：按 `{ } ;` 断行缩进，选择器与值内部多余空白压成一个空格。"""
    pad = " " * max(1, indent)
    rows: list[str] = []
    buf = ""
    depth = 0

    def clean(seg: str) -> str:
        seg = re.sub(r"\s+", " ", seg).strip()
        return re.sub(r"\s*([:,>])\s*", r"\1 ", seg).strip()

    for ch in text or "":
        if ch == "{":
            rows.append(pad * depth + clean(buf) + " {")
            buf = ""
            depth += 1
        elif ch == "}":
            if buf.strip():
                rows.append(pad * depth + clean(buf))
            buf = ""
            depth = max(0, depth - 1)
            rows.append(pad * depth + "}")
        elif ch == ";":
            if buf.strip():
                rows.append(pad * depth + clean(buf) + ";")
            buf = ""
        else:
            buf += ch
    if buf.strip():
        rows.append(pad * depth + clean(buf))
    return "\n".join(r for r in rows if r.strip())


# ───────────── 通用入口 ─────────────
def js_strings(text: str, limit: int = 800) -> list[str]:
    """把 JS 里的字符串字面量去重；接口、密钥、演示账号常躺在这里。"""
    seen: set[str] = set()
    rows: list[str] = []
    for kind, raw in _tokens(text or ""):
        if kind != "str":
            continue
        body = raw[1:-1].strip()
        if 2 <= len(body) <= 500 and body not in seen:
            seen.add(body)
            rows.append(body)
            if len(rows) >= limit:
                break
    return rows


_API_RE = re.compile(r"^(?:https?://|//|/)[\w\-./{}:?=&%#@]+$")

# 压缩包里的字符串经常是「两个地址粘在一起」：`q.qq.comhttps://t-captcha.xxx.com`。
# 这种条目前缀没有 `/`，是厂商名、验证码域、SDK 域，不是本站接口路径，收进接口表就是脏数据。
_GLUED_RE = re.compile(r"^\w[\w.\-]*\w(?:https?://|//)")


def js_apis(text: str, limit: int = 400) -> list[str]:
    """从字符串字面量里挑出像接口地址的条目。"""
    seen: set[str] = set()
    rows: list[str] = []
    for body in js_strings(text, limit * 6):
        if len(body) > 300 or not _API_RE.match(body) or body in seen:
            continue
        if _GLUED_RE.match(body) or body.count("://") > 1:
            continue
        seen.add(body)
        rows.append(body)
        if len(rows) >= limit:
            break
    return rows


def _secret_reject(name: str, val: str) -> bool:
    """按类型挡掉明显不是凭据的值。

    `账号密码` 那条规则没有左边界，压缩包里 `'user/password'`、`'admin/login'`
    这类接口片段会被整段当账号密码收走；`密钥` 的 32 位以上字母数字规则也会
    命中纯 path 片段、base64 版号、hash 路由。挡的是形态，不是某个站。
    """
    low = val.lower()
    if name == "账号密码":
        if "/" in val.split(":", 1)[0] and ":" not in val:
            return True
        if low.endswith(("/", ".js", ".css", ".html", ".json", ".png", ".jpg", ".svg")):
            return True
        if any(tok in low for tok in ("login", "logout", "password", "passwd", "signin",
                                      "register", "user/", "api/", "admin/")):
            return True
        left = val.split(":", 1)[0].split("/", 1)[0]
        if left.lower() in _JS_SECRET_NOISE or len(left) < 3:
            return True
        return False
    if name == "密钥":
        if re.search(r"[./:]", val) or low.startswith(("http", "wx", "sha")):
            return True
        # 全同字符、递增/递减串是占位或填充，不是密钥
        if len(set(val)) <= 4:
            return True
        return False
    if name == "手机号":
        return bool(re.search(r"0{5,}|(\d)\1{6,}", val))
    return False


def js_secrets(text: str, limit: int = 600) -> list[dict]:
    """JS 正文里的敏感信息：账号密码、密钥、手机号、身份证、数据库串。

    只看字符串字面量：压缩包里的注释和变量名噪声太大，整篇正则会把
    `password` 这种字段名当成密码值收进来。规则表在 `JS_SECRET_RULES`。
    """
    rows: list[dict] = []
    seen: set[str] = set()
    for body in js_strings(text, limit * 4):
        if len(body) > 400:
            continue
        for name, rx in JS_SECRET_RULES:
            m = rx.search(body)
            if not m:
                continue
            val = (m.group(0) or "").strip()
            if not val or val.lower() in _JS_SECRET_NOISE or len(val) < 6:
                continue
            if _secret_reject(name, val):
                continue
            key = f"{name}:{val}"
            if key in seen:
                break
            seen.add(key)
            rows.append({"type": name, "value": val})
            break
        if len(rows) >= limit:
            break
    return rows


# 值长得像占位符的一律不要：这些是模板字符串与示例，报出来就是误报
_JS_SECRET_NOISE = {
    "password", "passwd", "pwd", "secret", "secretkey", "secret_key", "token",
    "access_token", "string", "undefined", "null", "none", "your_password",
    "123456", "admin", "root", "test", "demo",
}

JS_SECRET_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("账号密码", re.compile(r"^[\w.\-+]{2,32}@?[\w.\-]{0,32}\s*[:/,]\s*[^\s:]{6,40}$")),
    ("密钥", re.compile(r"^(?:AKID|LTAI)[A-Za-z0-9]{12,40}$")),
    ("密钥", re.compile(r"^[A-Za-z0-9_\-]{32,}$")),
    ("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("身份证", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
    ("数据库", re.compile(r"^(?:jdbc|mysql|postgresql|postgres|mongodb|redis|mssql|oracle|sqlserver)\S*://?[^\s]+$", re.I)),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def find_by_keyword(text: str, keyword: str, before: int = 80, after: int = 160,
                    limit: int = 50) -> list[str]:
    """在压缩代码里定位关键词上下文，用于快速看密钥 / 接口附近的写法。"""
    if not keyword:
        return []
    rows: list[str] = []
    start = 0
    while len(rows) < limit:
        idx = text.find(keyword, start)
        if idx < 0:
            break
        lo = max(0, idx - before)
        hi = min(len(text), idx + len(keyword) + after)
        rows.append(text[lo:hi].replace("\n", " "))
        start = idx + len(keyword)
    return rows


LANGUAGES = ("js", "ts", "html", "json", "css", "xml", "auto")


def _guess_language(text: str) -> str:
    head = (text or "").lstrip()[:200]
    if head.startswith("{") or head.startswith("["):
        return "json"
    if head.startswith("<"):
        low = head.lower()
        return "xml" if low.startswith("<?xml") else "html"
    return "js"


def beatify(text: str, language: str = "auto", indent: int = 2) -> dict:
    """统一入口：按语言美化，并附带抽出的字符串与接口。

    返回 `{"language", "output", "strings", "apis", "error"}`；出错时 output 保留原文。
    """
    lang = (language or "auto").lower()
    if lang == "auto":
        lang = _guess_language(text)
    if lang in ("ts", "typescript", "css"):
        lang = "js"
    if lang == "xml":
        lang = "html"
    if lang not in ("js", "html", "json"):
        lang = "js"

    result = {"language": lang, "output": text or "", "strings": [], "apis": [], "error": ""}
    try:
        if lang == "json":
            result["output"] = beats_json(text, indent)
        elif lang == "html":
            result["output"] = beauty_html(text, indent)
        else:
            result["output"] = beauty_js(text, indent)
    except ValueError as exc:
        result["error"] = str(exc)
        return result

    if lang in ("js", "html"):
        result["strings"] = js_strings(text)
        result["apis"] = js_apis(text)
    return result


def beaty_js(text: str, indent: int = 2) -> str:
    return beauty_js(text, indent)


beautify = beatify
