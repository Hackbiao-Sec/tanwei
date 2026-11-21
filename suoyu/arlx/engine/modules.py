"""五段式全收集口径：主体收集 → 域名收集 → 空间测绘 → 主动探测 → 深度挖掘。

任务列表、任务详情、功能自检三处都从这里取阶段分组，避免各写一套阶段表
（以前前端抄了一份 18 个阶段的数组，后端新增阶段前端就显示不出来）。

一个任务跑了哪几段由 ``options.only_stages`` 决定：空 = 全选；否则只跑了列出的阶段。
"""
from __future__ import annotations

MODULES: list[dict] = [
    {"key": "subject", "label": "主体收集",
     "hint": "企业主体、ICP 备案、股权穿透、小程序与 App",
     "stages": ["enterprise", "equity", "mobile"]},
    {"key": "domain", "label": "域名收集",
     "hint": "被动子域与字典爆破，扩出根域下全部子域",
     "stages": ["passive", "brute"]},
    {"key": "space", "label": "空间测绘",
     "hint": "测绘引擎按根域检索，产出带端口与标题的资产",
     "stages": ["space"]},
    {"key": "probe", "label": "主动探测",
     "hint": "DNS 解析、端口扫描、Web 存活与指纹",
     "stages": ["dns", "port", "web"]},
    {"key": "deep", "label": "深度挖掘",
     "hint": "爬虫、敏感文件、VHost、接管、旁站与纵深",
     "stages": ["crawl", "leak", "vhost", "takeover", "sibling", "deep"]},
]

# 一键收集的五步勾选 → 阶段。执行侧读 options["steps"]，从 MODULES 派生一份，
# 免得两处各抄一套阶段表。
STEP_OF_MODULE: dict[str, str] = {"subject": "p1", "domain": "p2", "space": "p3",
                                  "probe": "p4", "deep": "p5"}
STEP_STAGES: dict[str, list[str]] = {STEP_OF_MODULE[m["key"]]: list(m["stages"])
                                     for m in MODULES}


def stages_of_options(options: dict | None) -> list[str]:
    """这个任务实际会跑的阶段：显式 only_stages 优先，其次把一键收集的 steps 折算过来。

    以前展示侧只认 only_stages：一键收集里没勾的段，执行侧跳过、展示侧却当成
    「已选且跑完」，卡片一律写「100% 已完成 · 无产出」，和真跑了却空手而归
    分辨不出来。
    """
    options = options or {}
    picked = [str(s) for s in (options.get("only_stages") or []) if str(s) in STAGE_ORDER]
    if picked:
        return picked
    raw = options.get("steps")
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    steps = {str(s) for s in raw if str(s)}
    if len(steps & set(STEP_STAGES)) >= len(STEP_STAGES):
        return []
    return [s for step in STEP_STAGES for s in STEP_STAGES[step] if step in steps]


# 阶段里的细分项：重测时不必整段重跑，可以只挑其中几项。
# 编码是「阶段:子项」，写进 options["only_modules"]；某段一个子项都没写 = 整段照跑。
# 被动源与测绘引擎不进这张静态表，按各自注册表现取（见 stage_submodules）。
SUBMODULES: dict[str, list[dict]] = {
    "port": [
        {"key": "scan", "label": "开放端口", "hint": "按端口组扫每个 IP 的开放端口"},
        {"key": "service", "label": "协议指纹", "hint": "对已开端口握手认服务（Redis/Mongo/JDWP…）"},
    ],
    "leak": [
        {"key": "file", "label": "敏感文件", "hint": "按字典探备份、配置、swagger 这类路径"},
        {"key": "git", "label": "Git 泄露", "hint": "探 .git 目录可读与仓库泄露"},
    ],
    "sibling": [
        {"key": "ptr", "label": "PTR 反查", "hint": "落点 IP 反查主机名"},
        {"key": "cseg", "label": "同 C 段旁站", "hint": "扫同段 80/443 找关联业务页"},
        {"key": "asn", "label": "ASN 网段", "hint": "归集 ASN 与小网段并补扫"},
        {"key": "bucket", "label": "存储桶", "hint": "按根域猜云存储桶是否公开"},
    ],
    "deep": [
        {"key": "codeleak", "label": "代码泄露", "hint": "搜索代码托管上的本目标仓库"},
        {"key": "email", "label": "邮箱收集", "hint": "从页面与仓库里收邮箱"},
        {"key": "git", "label": "Git 仓库", "hint": "GitHub / Gitee 上的本目标仓库"},
        {"key": "component", "label": "组件识别", "hint": "FineReport / Shiro / 泛微 / xxl-job 等指纹"},
        {"key": "component_probe", "label": "组件未授权", "hint": "Actuator / Druid / Nacos / ES 等未授权探测"},
        {"key": "screenshot", "label": "站点截图", "hint": "给每个站点留一张图"},
        {"key": "nuclei", "label": "nuclei 复核", "hint": "对站点跑已知漏洞模板"},
    ],
}


def stage_submodules() -> dict[str, list[dict]]:
    """阶段 → 可单独重测的细分项。被动源、测绘引擎按注册表现取，不另抄名单。"""
    out = {k: [dict(x) for x in v] for k, v in SUBMODULES.items()}
    try:
        from . import space as space_mod
        out["space"] = [{"key": n, "label": space_mod.ENGINE_LABEL.get(n, n)}
                        for n in space_mod.QUERY_FUNCS]
    except Exception:
        pass
    try:
        from .sources import passive as passive_mod
        from . import source_health
        out["passive"] = [{"key": n, "label": source_health.label_source(n)}
                          for n in passive_mod.DOMAIN_SOURCES]
    except Exception:
        pass
    return out


MODULE_KEYS = [m["key"] for m in MODULES]
MODULE_LABEL = {m["key"]: m["label"] for m in MODULES}
MODULE_HINT = {m["key"]: m["hint"] for m in MODULES}
MODULE_STAGES = {m["key"]: list(m["stages"]) for m in MODULES}
MODULE_OF = {stage: m["key"] for m in MODULES for stage in m["stages"]}

# 收尾两阶段：不单独成模块，进度算在整条流程上
TAIL_STAGES = ["assetdiff", "report"]
STAGE_ORDER = [s for m in MODULES for s in m["stages"]] + TAIL_STAGES
STAGE_INDEX = {s: i for i, s in enumerate(STAGE_ORDER)}
STAGE_MODULE = dict(MODULE_OF)
for _s in TAIL_STAGES:
    STAGE_MODULE[_s] = "tail"

# 老任务没往 task_assets 里写阶段，只能靠资产类型认它属于哪一段
KIND_MODULE: dict[str, str] = {
    "enterprise": "subject", "equity": "subject", "holds": "subject", "branch": "subject",
    "invest": "subject", "partner": "subject", "icp": "subject", "copyright": "subject",
    "supplier": "subject", "job": "subject", "applet": "subject", "applet_icp": "subject",
    "applet_hint": "subject", "mobileapp": "subject", "mobile": "subject", "wxmp": "subject",
    "wechatoa": "subject", "weibo": "subject", "email": "subject", "mailinfo": "subject",
    "domain": "domain", "api": "domain", "subdomain": "domain",
    # 裸 IP 服务是测绘直接落的；站点和 IP 解析结果是探测阶段落的
    "service": "space",
    "port": "probe",
    "site": "probe", "ip": "probe",
    "leak": "deep", "leakfile": "deep", "js": "deep", "component": "deep", "git": "deep",
    "sibling": "deep", "url": "deep",
}

KIND_LABEL: dict[str, str] = {
    "enterprise": "企业主体", "equity": "股权", "holds": "控股企业", "branch": "分支机构",
    "invest": "对外投资", "partner": "股东", "icp": "ICP 备案", "copyright": "软件著作权",
    "supplier": "供应商", "job": "招聘", "applet": "小程序", "applet_icp": "小程序备案",
    "applet_hint": "小程序线索", "mobileapp": "APP", "mobile": "移动应用",
    "wxmp": "公众号", "wechatoa": "公众号", "weibo": "微博", "email": "邮箱",
    "mailinfo": "邮件信息", "domain": "域名", "api": "接口", "site": "站点",
    "service": "服务", "port": "端口", "ip": "IP", "leak": "泄露", "leakfile": "泄露文件",
    "js": "JS 文件", "component": "组件", "git": "代码仓库", "sibling": "旁站",
}

KIND_ORDER = list(KIND_LABEL)


def kind_label(kind: str) -> str:
    return KIND_LABEL.get(kind or "", kind or "未分类")


def stage_label(stage: str) -> str:
    """阶段中文名。取自流水线的 ``PHASE_LABEL``，这里不再抄一份阶段名单。"""
    from .pipeline import PHASE_LABEL

    return PHASE_LABEL.get(stage or "", stage or "")


def modules_payload() -> list[dict]:
    """给前端渲染用的静态口径（五段 + 各自阶段 + 提示）。"""
    return [{"key": m["key"], "label": m["label"], "hint": m["hint"],
             "stages": list(m["stages"]),
             "stage_labels": [stage_label(s) for s in m["stages"]]} for m in MODULES]


# 日志里的 module 名不全是流水线阶段：调度、存储、邮件 DNS 这些也要有中文名，
# 否则任务详情把 task / target / store 原样当阶段名显示出来
LOG_MODULE_LABEL = {
    "target": "目标归一", "target_parse": "目标归一", "task": "任务调度",
    "store": "数据存储", "maildns": "邮件 DNS", "system": "系统",
}
# 同一个环节在日志与阶段表里用了两个名字，明细里要合成一行，别出现两条「目标归一」
LOG_MODULE_ALIAS = {"target": "target_parse"}


def stage_labels_payload() -> dict[str, str]:
    """全部阶段（含收尾与日志别名）的中文名，任务详情的分组与 chip 共用一份。"""
    out = {s: stage_label(s) for s in STAGE_ORDER}
    for k, v in LOG_MODULE_LABEL.items():
        out.setdefault(k, v)
    return out


def _selected(only_stages, module_key: str) -> list[str]:
    # 认不出的阶段键不算选择：执行侧会忽略它们而照跑全流程，
    # 展示侧若仍按它筛，真跑过的段就会被标成「未选这一路」。
    picked = {str(s) for s in (only_stages or []) if str(s) in STAGE_ORDER}
    stages = MODULE_STAGES[module_key]
    if not picked:
        return list(stages)
    return [s for s in stages if s in picked]


def module_asset_counts(kinds: dict | None, stages: dict | None) -> dict[str, int]:
    """按阶段算各模块收了多少资产；没记阶段的老资产退回按类型归段。

    ``db.task_breakdown`` 里能给出精确的模块去重数，这里只是它的兜底（比如
    拿不到关联表的时候）。
    """
    out = {k: 0 for k in MODULE_KEYS}
    for stage, n in (stages or {}).items():
        key = STAGE_MODULE.get(stage or "")
        if key in out:
            out[key] += int(n or 0)
    for kind, n in (kinds or {}).items():
        key = KIND_MODULE.get(kind or "")
        if key in out:
            out[key] += int(n or 0)
    return out


def module_scopes() -> dict[str, dict]:
    """给 ``db.task_breakdown`` 用的模块口径：哪些阶段、哪些类型归这一段。

    第三项 ``claimed`` 是所有归段阶段的并集，db 拿它区分「阶段没写」和「阶段
    写了但不归任何一段」（``target_parse`` 这种），后者才退回按资产类型认。
    """
    kinds: dict[str, list[str]] = {k: [] for k in MODULE_KEYS}
    for kind, key in KIND_MODULE.items():
        kinds.setdefault(key, []).append(kind)
    claimed = list(STAGE_MODULE)
    return {m["key"]: {"stages": list(m["stages"]), "kinds": kinds.get(m["key"], []),
                       "claimed": claimed}
            for m in MODULES}



def task_modules(only_stages=None, phase: str = "", status: str = "",
                 counts: dict | None = None) -> list[dict]:
    """一个任务的五段进度：选没选、跑没跑完、收了多少资产。

    ``phase`` 是任务最后记录的阶段；阶段顺序取 ``STAGE_ORDER``，所以已经走过
    的阶段算完成，正落在某段里的算进行中，还没到的算待跑。
    """
    status = (status or "").lower()
    cur = STAGE_INDEX.get(phase or "", -1)
    success = status in ("done", "success", "finished", "ok")
    alive = status in ("running", "queued", "pending", "starting", "paused")
    counts = counts or {}
    out: list[dict] = []
    for m in MODULES:
        stages = _selected(only_stages, m["key"])
        if not stages:
            out.append({"key": m["key"], "label": m["label"], "hint": m["hint"],
                        "stages": [], "state": "skip", "pct": 0,
                        "assets": 0, "note": "未选这一路"})
            continue
        idxs = [STAGE_INDEX[s] for s in stages]
        if success:
            state, pct = "done", 100
        elif cur < 0:
            state, pct = "pending", 0
        elif cur >= max(idxs):
            # 最后一段正跑着时先别打勾：阶段落到了这一段，但它还没收尾
            if cur == max(idxs) and alive:
                state, pct = "running", 90
            else:
                state, pct = "done", 100
        elif cur < min(idxs):
            state, pct = "pending", 0
        else:
            state = "running" if alive else "partial"
            passed = len([i for i in idxs if i < cur])
            pct = int(round(100.0 * (passed + (0.5 if state == "running" else 0)) / len(idxs)))
            if status in ("failed", "stopped", "error", "interrupted"):
                state = "stalled"
        out.append({"key": m["key"], "label": m["label"], "hint": m["hint"],
                    "stages": stages, "state": state, "pct": max(0, min(100, int(pct))),
                    "assets": int(counts.get(m["key"], 0) or 0), "note": ""})
    return out


def is_partial(only_stages=None) -> bool:
    """只跑了一部分阶段的任务：列表里要标成「局部任务」，不是整条流程。

    只认真实阶段键：认不出的键在 executor 那边会被忽略而整条流程照跑，
    这里若还按它算「局部」，列表就会说局部、实际却是全流程。
    """
    picked = {str(s) for s in (only_stages or []) if str(s) in STAGE_ORDER}
    if not picked:
        return False
    return len(picked) < len([s for s in STAGE_ORDER if s not in TAIL_STAGES])
