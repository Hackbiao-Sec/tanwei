"""从本机 data/config.yaml 生成打包用的凭据种子。

种子会随 exe 打包，首次启动自动填进空配置项，省得逐项手填；用户之后在
设置页改过的值不会被覆盖（种子只填空，且带版本号只跑一次）。

只带走「和默认值不一样」的字段：默认host/端口/扫描参数那些不重复打进去，
server.secret_key 也不带（每台机器各生成各的）。

用法（在 arl-x 目录下）：python scripts/build_seed.py
产物：build/seed_config.yaml，不进仓库、不含在 git 历史里。
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from arlx.config import DEFAULTS  # noqa: E402

SRC = ROOT / "data" / "config.yaml"
OUT = ROOT / "build" / "seed_config.yaml"
SKIP_TOP = {"server", "seed"}
SEED_REV = 20261120


def diff(node, default):
    """只留用户真改过、或凭据真填了的字段。"""
    if isinstance(node, dict):
        base = default if isinstance(default, dict) else {}
        out = {}
        for key, value in node.items():
            if key in SKIP_TOP:
                continue
            sub = diff(value, base.get(key))
            if sub not in (None, {}, []):
                out[key] = sub
        return out or None
    if isinstance(node, list):
        return node or None
    if node in ("", None):
        return None
    if node == default:
        return None
    return node


def main() -> int:
    if not SRC.exists():
        print(f"跳过：找不到 {SRC}")
        return 1
    raw = yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    seed = diff(raw, DEFAULTS) or {}
    seed["seed"] = {"rev": SEED_REV}
    # 固定顺序，方便肉眼核对种子内容
    ordered = {"seed": seed.pop("seed"), "sources": seed.pop("sources", None),
               "ai": seed.pop("ai", None)}
    for key in list(seed):
        ordered[key] = seed[key]
    ordered = {k: v for k, v in ordered.items() if v not in (None, {}, [])}

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(yaml.safe_dump(ordered, allow_unicode=True, sort_keys=False), encoding="utf-8")

    src_names = list((ordered.get("sources") or {}).keys())
    models = (ordered.get("ai") or {}).get("models") or []
    print(f"已写入 {OUT}")
    print(f"  sources: {', '.join(src_names) if src_names else '（无）'}")
    print(f"  ai.engine: {(ordered.get('ai') or {}).get('engine', '') or '（未设）'}"
          f"  ai.models: {len(models)} 条")
    print(f"  其它段: {[k for k in ordered if k not in ('seed', 'sources', 'ai')] or '（无）'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
