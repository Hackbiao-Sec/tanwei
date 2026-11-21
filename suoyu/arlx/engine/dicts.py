"""字典管理：内置字典只读，用户字典落到 DATA_DIR/dicts。

exe 打包后 arlx/dicts 在 _MEIPASS 里，写进去随进程结束就丢；所以用户在界面上
改过的字典统一落 DATA_DIR（安装目录下的 data/dicts），active.load_dict 先查
用户目录，没有再回落到内置目录。
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from ..config import DATA_DIR, ROOT, config

BUILTIN_DIR = ROOT / "arlx" / "dicts"
USER_DIR = DATA_DIR / "dicts"

# 字典名白名单：只允许一级文件名，堵住 ../ 之类的路径穿越
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,79}\.txt$")

# 会被采集流程直接引用的字典。key 是配置项名字，path 是它在 config 里的完整路径
BINDINGS = [
    {
        "key": "domain_dict",
        "path": "scan.domain_dict",
        "label": "子域名爆破字典",
        "scene": "P3 域名爆破按字典里的词逐个拼前缀",
    },
    {
        "key": "file_leak_dict",
        "path": "scan.file_leak_dict",
        "label": "敏感文件探测字典",
        "scene": "P8 敏感文件探测逐条请求这些路径",
    },
    {
        "key": "fuzz_dict",
        "path": "scan.fuzz_dict",
        "label": "目录扫描字典",
        "scene": "预留项：目录扫描使用，当前采集流程尚未调用",
    },
]

# 界面上给人看的用途说明；没登记的字典照样能管，只是不带说明
BUILTIN_LABELS = {
    "domain_2w.txt": "子域名字典（2 万条通用前缀）",
    "domain_dict_test.txt": "子域名字典（测试用小样本）",
    "file_top_200.txt": "敏感文件路径（200 条）",
    "file_top_2000.txt": "敏感文件路径（2000 条）",
    "file_test.txt": "敏感文件路径（测试用小样本）",
    "dir_default.txt": "目录扫描路径（通用目录 / 配置 / 备份）",
    "altdnsdict.txt": "dnsgen 变体词表（生成排列组合域名）",
    "blackdomain.txt": "黑名单域名（不进资产表）",
    "blackhexie.txt": "黑名单词（谐音/灰产关键词）",
    "black_asset_site.txt": "黑名单站点（探测结果为这些站点时丢弃）",
    "dnsserver.txt": "DNS 服务器列表（解析用）",
}


def name_ok(name: str) -> bool:
    return bool(NAME_RE.match(name or ""))


def user_dir() -> Path:
    USER_DIR.mkdir(parents=True, exist_ok=True)
    return USER_DIR


def locate(name: str) -> tuple[Path | None, str]:
    """返回 (实际生效的文件, 来源)。用户目录优先，覆盖同名内置字典。"""
    if not name_ok(name):
        return None, ""
    p = USER_DIR / name
    if p.exists():
        return p, "user"
    p = BUILTIN_DIR / name
    if p.exists():
        return p, "builtin"
    return None, ""


def clean_words(text: str) -> list[str]:
    """去空行、去注释、保序去重。"""
    out: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        w = raw.strip()
        if not w or w.startswith("#"):
            continue
        if w in seen:
            continue
        seen.add(w)
        out.append(w)
    return out


def _lines_of(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


def _bindings_map() -> dict[str, list[str]]:
    """字典名 → 引用了它的采集配置项。"""
    out: dict[str, list[str]] = {}
    for b in BINDINGS:
        cur = str(config.get(*b["path"].split("."), default="") or "")
        if cur:
            out.setdefault(cur, []).append(b["label"])
    return out


def _binding_state() -> list[dict]:
    rows = []
    for b in BINDINGS:
        cur = str(config.get(*b["path"].split("."), default="") or "")
        path, source = locate(cur)
        rows.append({
            "key": b["key"],
            "label": b["label"],
            "scene": b["scene"],
            "current": cur,
            "source": source,
            "present": bool(path),
        })
    return rows


def list_dicts() -> list[dict]:
    bound = _bindings_map()
    names: dict[str, dict] = {}
    for source, base in (("user", USER_DIR), ("builtin", BUILTIN_DIR)):
        if not base.exists():
            continue
        for p in sorted(base.glob("*.txt")):
            if not name_ok(p.name):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            item = names.get(p.name)
            if item is None:
                item = {
                    "name": p.name,
                    "source": source,
                    "lines": _lines_of(p),
                    "bytes": st.st_size,
                    "mtime": st.st_mtime,
                    "label": BUILTIN_LABELS.get(p.name, ""),
                    "bindings": bound.get(p.name, []),
                    "shadowed": False,
                }
                names[p.name] = item
            else:
                # 同名文件在用户目录里也有一份 → 生效的是用户那份
                item["shadowed"] = True
    return sorted(names.values(), key=lambda x: (-x["lines"], x["name"]))


def read_dict(name: str, offset: int = 0, limit: int = 2000, raw: bool = False) -> dict:
    path, source = locate(name)
    if not path:
        raise FileNotFoundError(name)
    text = path.read_text(encoding="utf-8", errors="ignore")
    if raw:
        # 编辑器要原样文本，行数按非空行统计
        return {
            "name": name,
            "source": source,
            "path": str(path),
            "total": sum(1 for line in text.splitlines() if line.strip()),
            "offset": 0,
            "lines": [],
            "text": text,
            "truncated": False,
        }
    words = clean_words(text)
    offset = max(0, int(offset or 0))
    limit = max(1, min(200000, int(limit or 2000)))
    chunk = words[offset: offset + limit]
    return {
        "name": name,
        "source": source,
        "path": str(path),
        "total": len(words),
        "offset": offset,
        "lines": chunk,
        "truncated": offset + len(chunk) < len(words),
    }


def write_dict(name: str, words: list[str], append: bool = False) -> dict:
    if not name_ok(name):
        raise ValueError("字典名只能用字母、数字、下划线、点、横线，且以 .txt 结尾")
    target = user_dir() / name
    merged = words
    if append and target.exists():
        merged = clean_words(target.read_text(encoding="utf-8", errors="ignore")) + list(words)
    merged = clean_words("\n".join(merged))
    if not merged:
        raise ValueError("字典内容为空")
    tmp = target.with_suffix(".txt.tmp")
    tmp.write_text("\n".join(merged) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    return {"name": name, "lines": len(merged), "bytes": target.stat().st_size}


def delete_dict(name: str) -> dict:
    if not name_ok(name):
        raise ValueError("字典名非法")
    target = USER_DIR / name
    if not target.exists():
        raise FileNotFoundError(name)
    for b in BINDINGS:
        cur = str(config.get(*b["path"].split("."), default="") or "")
        if cur == name:
            raise ValueError(f"这个字典正被「{b['label']}」使用，先切换再删除")
    target.unlink()
    # 用户目录那份删掉后会自动回落到同名内置字典
    fallback = (BUILTIN_DIR / name).exists()
    return {"name": name, "fallback_builtin": fallback}


def bind(name: str, key: str) -> dict:
    if not name_ok(name):
        raise ValueError("字典名非法")
    if not (USER_DIR / name).exists() and not (BUILTIN_DIR / name).exists():
        raise FileNotFoundError(name)
    hit = next((b for b in BINDINGS if b["key"] == key), None)
    if not hit:
        raise ValueError("未知的字典用途")
    section, field = hit["path"].split(".", 1)
    config.persist({section: {field: name}})
    return {"key": key, "current": name, "ts": time.time()}
