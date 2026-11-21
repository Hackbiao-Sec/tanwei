"""功能单项执行：把平台能力拆成可以单独点一下就跑、单独看结果的条目。

排障顺序是先逐项单独跑通，再跑整条流水线。条目分两类：

- stage：流水线里的某个阶段（DNS 解析、端口扫描……）。按正常任务执行，产出照常
  入库，前端跳到任务详情看日志和资产。
- direct：一次调用就出结果的能力（企业主体、股权穿透、应用商店、测绘、单次
  DNS 与探针），不建任务，结果直接回给前端。

每一条都带自己的参数表。参数键和流水线里 `self.opt(...)` 读的键同名，点进来跑这一项
时改的就是这一项的行为；不填则回落全局配置的同名键。前端按 `type` 渲染控件。
"""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from ..utils import is_ip
from ..config import DATA_DIR, config
from ..db import store
from . import asset_rows
from . import source_health
from . import handshake
from . import space as space_mod
from .modules import MODULE_HINT, MODULE_KEYS, MODULE_LABEL, MODULE_STAGES, MODULE_OF
from .collectors import applet as applet_mod
from .collectors import enterprise, equity, mobile
from .collectors import probe as probe_mod
from .dns_engine import DnsEngine
from .http_engine import probe as http_probe
from .portscan import parse_ports
from .sources.passive import (DOMAIN_SOURCES, MIIT_KIND_LABEL, fofa_search,
                              source_meta)

# 阶段分组：前端左侧按这个顺序摆
STAGE_GROUP = {
    "enterprise": "目标与主体",
    "equity": "目标与主体",
    "mobile": "目标与主体",
    "passive": "资产扩展",
    "space": "资产扩展",
    "brute": "资产扩展",
    "dns": "解析与探测",
    "port": "解析与探测",
    "web": "解析与探测",
    "crawl": "站点挖掘",
    "leak": "站点挖掘",
    "vhost": "站点挖掘",
    "takeover": "站点挖掘",
    "sibling": "站点挖掘",
    "deep": "站点挖掘",
    "assetdiff": "汇总",
    "report": "汇总",
}

GROUP_ORDER = ["目标与主体", "资产扩展", "解析与探测", "站点挖掘", "网络与空间",
               "站点与协议", "数据源与工具", "汇总"]

# 「目标与主体」原来拆成主体 / 股权 / 移动端三段，各摆一排参数，跑一遍要开三次。
# 这里合成一个整段流程：一次输入，按开关把三段串起来跑在同一个任务里。
COMPOSITE_STAGES = {"subject": ("enterprise", "equity", "mobile")}
COMPOSITE_LABEL = {"subject": "主体整段流程"}
# 五段全收集：每个模块一个执行键 ``m_<模块>``，整段跑 = 按顺序排该模块下全部阶段。
# 前缀 m_ 是为了跟阶段名分开（空间测绘、深度挖掘本身就是阶段名，同名会串）。
for _mod in MODULE_KEYS:
    COMPOSITE_STAGES["m_" + _mod] = tuple(MODULE_STAGES[_mod])
    COMPOSITE_LABEL["m_" + _mod] = MODULE_LABEL[_mod] + "整段"
# 五段一次跑完：一条流水线按顺序排完 21 个阶段，不用点五次
COMPOSITE_STAGES["full"] = tuple(s for m in MODULE_KEYS for s in MODULE_STAGES[m])
COMPOSITE_LABEL["full"] = "全收集流程（五段）"
# 整段流程上的分段开关：参数名 → 阶段键；关掉的那段连阶段都不排。
COMPOSITE_SWITCHES = {"with_enterprise": "enterprise",
                      "with_equity": "equity",
                      "with_mobile": "mobile"}


def _dict_names() -> list[str]:
    try:
        from .collectors.active import DICT_DIR

        return sorted(p.name for p in DICT_DIR.glob("*.txt"))
    except Exception:
        return []


def _port_presets() -> list[dict]:
    try:
        from .portscan import PORT_PRESET_LABELS

        return [{"value": k, "label": v} for k, v in PORT_PRESET_LABELS.items()]
    except Exception:
        return []


def _space_engines() -> list[dict]:
    """测绘引擎：配了 key 的算主源，没配的进辅助栏并标灰，免得空点。"""
    try:
        from . import space as space_mod
    except Exception:
        return []
    try:
        sec = config.section("sources") or {}
    except Exception:
        sec = {}
    out: list[dict] = []
    for k, label in (space_mod.ENGINE_LABEL or {}).items():
        if k not in getattr(space_mod, "QUERY_FUNCS", {}):
            continue
        try:
            ready = bool(space_mod.keys_of(k))
        except Exception:
            ready = False
        on = bool((sec.get(k) or {}).get("enabled", True))
        out.append({"value": k, "label": label, "short": label,
                    "role": "primary" if (ready and on) else "aux",
                    "ready": ready})
    return out


def _kind_options() -> list[dict]:
    return [{"value": k, "label": v} for k, v in MIIT_KIND_LABEL.items()]


#: 备案类型的默认勾选：站备案之外把 APP / 小程序一起查。
#: 这两类备案没有域名，只有「服务名称 + 备案号」，是主体名下移动端资产
#: 唯一能按主体精确对上的来源；不查就只剩搜索引擎瞎猜。
_KINDS_DEFAULT = ["site", "app", "mapp"]


def _source_options() -> list[dict]:
    return [{"value": m["name"], "label": m["name"],
             "short": m.get("short") or m["name"],
             "role": m.get("role", "aux"),
             "need_key": bool(m.get("need_key"))}
            for m in source_meta()]


def _source_groups() -> list[dict]:
    """各模块的「主源 / 辅助」分组：界面上一栏勾选，勾了才发请求。

    哪些算主源一律由后端在采集器那边定，前端只按 role 画两栏，不自己猜。
    ``default`` 是该来源参数默认勾上的那几路，``empty_means_all`` 说明这个参数
    留空是「全开」而不是「全关」——两种语义界面要画得不一样，否则会骗人。
    """
    groups = [{
        "param": "equity_sources",
        "module": "subject",
        "title": "工商来源",
        "note": "主源是两家工商站，勾哪路打哪路；备案反查不需要登录态，默认和主源一起跑兜底。"
                "要凭据的辅助源只在主源一条都没取到时才补跑，额度不白烧",
        "options": _equity_source_options(),
        "default": _equity_source_defaults(),
        "roles": {"primary": "主源", "aux": "辅助"},
        "empty_means_all": False,
    }]
    passive = [o for o in _source_options()]
    if passive:
        groups.append({
            "param": "sources",
            "module": "domain",
            "title": "被动子域源",
            "note": "主源是要 key 的测绘与威胁情报源，辅助是免 key 的公开源；不勾 = 全部启用，只勾要用的那几路，没配 key 的那几路空跑只会拖时间",
            "options": passive,
            "default": [],
            "roles": {"primary": "主源", "aux": "辅助"},
            "empty_means_all": True,
        })
    engines = _space_engines()
    if engines:
        groups.append({
            "param": "space_engines",
            "module": "space",
            "title": "测绘引擎",
            "note": "不勾 = 配置里启用的全部引擎；标灰的是还没配 key 的那几台",
            "options": engines,
            "default": [],
            "roles": {"primary": "可用引擎", "aux": "待配 key"},
            "empty_means_all": True,
        })
    return groups


def _equity_source_options() -> list[dict]:
    """工商链路的可选来源：不勾的那一路连请求都不发，额度全留给要用的那条。

    ``role`` 让界面分成「主源 / 辅助」两组画：主源先并发打满，主源一条数据都没
    取到时才补跑辅助，所以哪些是主源由后端说了算，前端不自己猜。
    """
    try:
        from .collectors.equity import EQUITY_PRIMARY, EQUITY_SOURCES

        return [{"value": k, "label": v, "short": str(v).split("（")[0],
                 "role": "primary" if k in EQUITY_PRIMARY else "aux"}
                for k, v in EQUITY_SOURCES.items()]
    except Exception:
        return []


def _equity_source_defaults() -> list[str]:
    """默认勾上主源两家 + 备案兜底。

    要凭据的辅助源默认不勾：没配登录态的那几家每轮都会空转一轮，把时间耗在等
    超时上。主源一条都没取到时 ``collect`` 会自动补跑已勾的辅助源。
    """
    try:
        from .collectors.equity import EQUITY_DEFAULT

        return list(EQUITY_DEFAULT)
    except Exception:
        return []


def _tool_options() -> list[dict]:
    try:
        from . import installer

        return [{"value": k, "label": k} for k in installer.all_status()]
    except Exception:
        return []


def _p(key: str, label: str, kind: str = "text", default=None, **extra) -> dict:
    """一条参数声明。`kind` 决定前端画什么控件，`extra` 里放选项与说明。"""
    item = {"key": key, "label": label, "type": kind, "default": default}
    item.update(extra)
    return item


def _dict_param(key: str, label: str, default: str) -> dict:
    return _p(key, label, "select", default,
              options=[{"value": n, "label": n} for n in _dict_names()])


# ─────────────── stage：流水线阶段 ───────────────
def _module_params(stages: list[str]) -> list[dict]:
    """一个模块卡要画的参数：它包含的几个阶段的参数并起来。

    同名参数只留第一次出现的那一份（键名在各阶段间一致，默认值也一致），
    否则同一张卡上会画出两遍相同的开关。
    """
    seen: set[str] = set()
    out: list[dict] = []
    for stage in stages:
        for p in _stage_params(stage):
            key = str(p.get("key") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(p)
    return out


def _stage_params(key: str) -> list[dict]:
    """每个阶段自己的参数表。键与 `pipeline_stages.py` 里 `self.opt(...)` 的键一致。"""
    if key == "enterprise":
        return [
            _p("enterprise_mobile", "顺带查移动端线索", "bool", False,
               help="主体名会同时拿去查应用商店与小程序，多花十几秒"),
            _p("mail_dns", "查邮箱记录", "bool", False,
               help="按 MX/TXT 找邮箱服务商，带出邮件主机"),
            _p("icp_kinds", "备案类型", "multi", _KINDS_DEFAULT, options=_kind_options(),
               help="默认站备案 + APP + 小程序：不含域名的备案只能按类型查，"
                    "小程序 / APP 的名字全在这里"),
            _p("icp_pages", "备案翻页数", "number", 2, min=1, max=20),
            _p("icp_size", "每页条数", "number", 40, min=1, max=40, adv=True),
            _p("icp_alias", "自动补全称", "bool", True,
               help="简称先换工商登记全称再查，命中率高但多一次检索"),
            _p("icp_retry", "备案重试次数", "number", 4, min=1, max=10, adv=True),
            _p("icp_gap", "备案请求间隔(秒)", "number", 0, min=0, adv=True,
               help="0 表示用配置的节流间隔"),
            _p("icp_force", "忽略备案缓存", "bool", False, adv=True),
            _p("enterprise_icp_api", "备用备案接口地址", "text", "", adv=True,
               help="留空用内置地址；接口换了填这里"),
            _p("enterprise_concurrent", "同时补几个根域", "number", 1, min=1, max=16,
               help="主体是按根域逐个查备案 / 工商 / 反查的；1 = 串行最稳，"
                    "调大只快一点，被风控的概率跟着涨"),
            _p("enterprise_gap", "根域之间等待(秒)", "number", 0, min=0, max=300, adv=True,
               help="一个根域查完歇几秒再查下一个；备案自身还有 6~9 秒的站点级间隔"),
            _p("enterprise_timeout", "单主体时限(秒)", "number", 1800, min=60,
               max=14400, adv=True,
               help="一个企业主体查检索 / 域名取证 / 备案的总时限。集团级主体要几分钟到几十分钟，"
                    "调小会把还没走到域名的那一轮掐断，任务里只剩主体行"),
            _p("equity_ratio", "控股门槛(%)", "number", 100, min=1, max=100),
            _p("equity_sources", "工商来源", "multi", _equity_source_defaults(),
               options=_equity_source_options(),
               help="主源（爱企查/天眼查/备案）先跑；主源一条数据都没取到时，才补跑勾选的辅助源，省额度"),
        ]
    if key == "equity":
        # 常用只留「跑不跑、跑多深、按几成算、勾哪几路、跑多慢」这几档；
        # 其余超时 / 并发 / 各类上限都是调优项，收进高级，默认不占视线。
        return [
            _p("equity_expand", "启用穿透", "bool", True),
            _p("equity_sources", "工商来源", "multi", _equity_source_defaults(),
               options=_equity_source_options(),
               help="主源（爱企查/天眼查/备案）先跑；主源一条数据都没取到时，才补跑勾选的辅助源，省额度"),
            _p("equity_depth", "往下穿几层", "number", 2, min=1, max=6,
               help="1 层 = 只看直接控股的子公司；2 层 = 再往孙公司穿一层"),
            _p("equity_ratio", "控股门槛(%)", "number", 100, min=1, max=100,
               help="持股比例达到这个数才算「自家子公司」；100 = 只认全资，调低会多出参股公司"),
            _p("equity_branch", "查分支机构", "bool", True,
               help="关掉就少一次分支机构请求、少耗一次额度"),
            _p("equity_budget", "最多查多少次", "number", 0, min=0, max=2000,
               help="整趟允许发出的工商请求次数；翻对外投资、查上层股东、逐层子公司共用这一份额度。"
                    "填 0 = 不限次数（默认），集团子公司多的时候才不会穿到第二层就断"),
            _p("equity_gap", "每次请求等待(秒)", "number", 0, min=0, max=300,
               help="每一次工商请求前多等几秒；0 = 跟随「策略配置 → 查询间隔」（当前 30 秒）。"
                    "慢节奏是数据完整的前提，调小只会更容易被风控"),
            _p("equity_max_names", "主体上限", "number", 10, min=1, max=30, adv=True,
               help="一次最多穿透几个主体；候选比这个多时，面板会单列一行「主体上限截断」"),
            _p("equity_subs", "子公司并线上限", "number", 40, min=0, max=200, adv=True,
               help="达标的子公司最多并多少个回目标池；被砍掉的会记进「子公司上限截断」"),
            _p("equity_ubo_threshold", "受益所有人阈值(%)", "number", 25, min=1, max=100, adv=True),
            _p("equity_ubo_levels", "受益所有人层数", "number", 1, min=0, max=6, adv=True),
            _p("equity_stage_deadline", "整段总时限(秒)", "number", 900, min=60, max=7200, adv=True,
               help="股权穿透整段的总闸；跑不完的子公司会记进「总时限截断」，"
                    "单阶段重跑可以续"),
            _p("equity_join_wait", "收尾等穿透(秒)", "number", 0, min=0, max=7200, adv=True,
               help="股权是转后台并发跑的，域名 / 端口 / 网页会先出；这里只决定临收尾时"
                    "最多再等几分钟让子公司并进池。0 = 不额外设限，交给上面的整段总时限收口"),
            _p("equity_timeout", "单主体超时(秒)", "number", 240, min=30, max=1800, adv=True),
            _p("equity_sub_timeout", "单子公司超时(秒)", "number", 100, min=20, max=900, adv=True),
            _p("equity_sub_workers", "子公司并发", "number", 3, min=1, max=6, adv=True,
               help="同时扩线几家子公司；工商源有节流，调高不等于更快"),
            _p("equity_retry", "重试次数", "number", 1, min=1, max=10, adv=True,
               help="单个工商请求失败时的尝试次数；被限流时会自动退避，账号额度紧就调 1"),
        ]
    if key == "mobile":
        return [
            _p("mobile_app_limit", "App 条数", "number", 8, min=1, max=50),
            _p("mobile_mp_limit", "公众号条数", "number", 6, min=1, max=50),
            _p("mobile_applet_limit", "小程序条数", "number", 8, min=1, max=50),
            _p("mobile_weibo", "查微博账号", "bool", True,
               help="按品牌词搜对应微博号；关掉就一个请求都不发"),
            _p("mobile_concurrent", "并发检索词", "number", 4, min=1, max=16),
        ]
    if key == "passive":
        return [
            _p("sources", "只看这些源", "multi", [], options=_source_options(),
               help="留空表示全部启用"),
            _p("max_subdomain", "子域总数上限", "number", 200000, min=100),
        ]
    if key == "space":
        return [
            _p("space_mapping", "空间测绘", "bool", True),
            _p("space_engines", "引擎", "multi", [], options=_space_engines(),
               help="留空表示用配置里启用的引擎"),
            _p("space_size", "每个根域条数", "number", 100, min=20, max=1000),
            _p("space_max_roots", "根域上限", "number", 60, min=1, max=300),
        ]
    if key == "brute":
        return [
            _p("domain_brute", "字典爆破", "bool", True),
            _dict_param("domain_dict", "爆破字典", "domain_2w.txt"),
            _p("domain_brute_concurrent", "爆破并发", "number", 800, min=1, max=5000),
            _p("domain_brute_gap", "根域之间等待(秒)", "number", 0, min=0, max=300,
               help="一轮字典跑完一个根域后歇几秒再打下一个；0 = 不等"),
            _p("alt_dns", "备用 DNS 通道", "bool", True),
            _p("alt_dns_concurrent", "备用通道并发", "number", 1500, min=1, max=8000),
        ]
    if key == "dns":
        return [
            _p("dns_max_targets", "解析域名上限", "number", 0, min=0,
               help="0 表示不限"),
            _p("dns_resolve_ptr", "反查 PTR", "bool", True,
               help="对明确给的 IP 做反向解析，带出同机上的域"),
            _p("dns_cidr_limit", "网段展开上限", "number", 1024, min=16, max=65536),
        ]
    if key == "port":
        return [
            _p("port_scan", "端口扫描", "bool", True),
            _p("port_type", "端口档", "select", "top100", options=_port_presets()),
            _p("port_custom", "自定义端口", "text", "",
               help="逗号分隔，和端口档叠加"),
            _p("port_exclude", "排除端口", "text", ""),
            _p("port_exclude_ips", "排除 IP", "text", "",
               help="逗号分隔，写在这个任务里不扫的机器"),
            _p("port_timeout", "单端口超时(秒)", "number", 2, min=1, max=30),
            _p("port_concurrent", "并发", "number", 300, min=1, max=3000),
            _p("port_qps", "限速(QPS)", "number", 0, min=0,
               help="0 表示不限"),
            _p("port_ip_concurrent", "同时扫几台 IP", "number", 0, min=0, max=2000,
               help="IP 级线程数；0 = 不限，只靠上面的端口级并发控总量"),
            _p("port_ip_gap", "每台 IP 错开(秒)", "number", 0, min=0, max=60,
               help="第 n 台 IP 延迟 n×该值起扫，几千个 IP 不会同一毫秒砸过去；0 = 不错开"),
            _p("service_detect", "协议识别", "bool", True),
            _p("service_probe", "服务探针", "bool", True),
            _p("port_resume", "断点续扫", "bool", False),
        ]
    if key == "web":
        return [
            _p("probe_limit", "探测条数上限", "number", 0, min=0,
               help="0 表示不限"),
            _p("http_concurrent", "HTTP 并发", "number", 0, min=0,
               help="0 表示用全局配置"),
            _p("alt_exit_budget", "备用出口预算(秒)", "number", 0, min=0),
            _p("handshake_mark", "握手标记", "bool", True),
            _p("handshake_limit", "握手条数上限", "number", 0, min=0),
            _p("handshake_concurrent", "握手并发", "number", 0, min=0),
        ]
    if key == "crawl":
        return [
            _p("site_spider", "站点爬虫", "bool", True),
            _p("js_deep_scan", "JS 深挖", "bool", True),
            _p("js_fetch_concurrent", "JS 抓取并发", "number", 0, min=0,
               help="0 表示用默认值"),
            _p("js_api_limit", "每份 JS 抽接口上限", "number", 200, min=10, max=2000),
        ]
    if key == "leak":
        return [
            _p("file_leak", "敏感文件", "bool", True),
            _dict_param("file_leak_dict", "字典", "file_top_200.txt"),
        ]
    if key == "vhost":
        return [
            _p("vhost_collision", "VHost 碰撞", "bool", False),
            _p("vhost_max_ips", "IP 上限", "number", 20, min=1, max=200),
            _p("vhost_max_domains", "域名上限", "number", 5000, min=10, max=50000),
        ]
    if key == "takeover":
        return [
            _p("takeover", "子域接管", "bool", True),
            _p("takeover_limit", "判定条数上限", "number", 0, min=0,
               help="0 表示不限"),
        ]
    if key == "sibling":
        return [
            _p("sibling", "旁站 C 段", "bool", True),
            _p("asn_expand", "ASN 扩段", "bool", True),
            _p("asn_scan_blocks", "扫 ASN 网段", "bool", True),
            _p("asn_block_limit", "网段上限", "number", 6, min=1, max=64),
        ]
    if key == "deep":
        return [
            _p("deep", "深度挖掘", "bool", True),
            _p("component_identify", "组件识别", "bool", True),
            _p("component_probe", "组件探针", "bool", True),
            _p("code_leak", "代码泄露检索", "bool", True),
            _p("bucket_enum", "对象存储枚举", "bool", True),
            _p("screenshot", "截图", "bool", True),
            _p("nuclei", "模板扫描", "bool", True),
            _p("credential_lists", "口令字典目录", "text", "",
               help="留空用内置字典"),
        ]
    if key == "assetdiff":
        return [
            _p("assetdiff_snapshot", "写变更快照", "bool", True),
            _p("assetdiff_notify", "新资产通知", "bool", True),
            _p("assetdiff_limit", "读取条数上限", "number", 200000, min=1000),
        ]
    if key == "report":
        return [
            _p("ai_triage", "AI 研判", "bool", True,
               help="需要配置大模型 key，没有 key 自动跳过"),
            _p("report_top", "资产类型排行条数", "number", 10, min=1, max=50),
        ]
    return []


def _subject_params() -> list[dict]:
    """整段流程的参数：只留能决定「查多少」的那几个，其余同类单次调用里有。"""
    return [
        _p("with_enterprise", "工商主体 + 备案", "bool", True,
           help="按主体名/域名查工商档案、股东、备案，产出企业实体与同主体域名"),
        _p("with_equity", "股权穿透", "bool", True,
           help="按累计持股门槛往下穿，只把过户的主体并进资产池"),
        _p("with_mobile", "小程序 / App / 公众号", "bool", True,
           help="按品牌名查应用商店、小程序与公众号，产出移动端资产"),
        _p("equity_ratio", "控股门槛(%)", "number", 100, min=1, max=100,
           help="调到 51 就是控股，100 只留全资"),
        _p("equity_sources", "工商来源", "multi", _equity_source_defaults(),
           options=_equity_source_options(),
           help="主源先跑；主源一条都没取到时才补跑勾选的辅助源，省额度"),
        _p("equity_gap", "工商请求间隔(秒)", "number", 0, min=0, max=180,
           help="两次工商请求之间额外等待；0 用配置里的间隔，调大防封"),
        _p("icp_kinds", "备案类型", "multi", _KINDS_DEFAULT, options=_kind_options(),
           help="站备案 + APP + 小程序；小程序和 App 的备案名字都在这里"),
        _p("icp_pages", "备案翻页数", "number", 2, min=1, max=20),
        _p("equity_depth", "穿透层数", "number", 2, min=1, max=6, adv=True,
           help="往下穿几层子公司；层数越多请求越多"),
        _p("equity_budget", "工商请求额度(次)", "number", 40, min=5, max=200, adv=True,
           help="整趟允许的工商请求次数；集团主体找不全先加这里"),
        _p("equity_join_wait", "收尾等穿透(秒)", "number", 0, min=0, max=7200, adv=True,
           help="股权转后台并发跑，域名 / 端口 / 网页先出；这里只决定临收尾时最多再等几分钟。"
                "0 = 不额外设限"),
        _p("equity_max_names", "主体名上限", "number", 10, min=1, max=40, adv=True),
        _p("icp_retry", "备案重试次数", "number", 4, min=1, max=10, adv=True),
        _p("mail_dns", "查邮箱记录", "bool", False, adv=True,
           help="按 MX/TXT 找邮箱服务商，带出邮件主机"),
        _p("mobile_app_limit", "App 条数", "number", 8, min=1, max=50, adv=True),
        _p("mobile_mp_limit", "公众号条数", "number", 6, min=1, max=50, adv=True),
        _p("mobile_applet_limit", "小程序条数", "number", 8, min=1, max=50, adv=True),
        _p("enterprise_icp_api", "备用备案接口地址", "text", "", adv=True,
           help="留空用内置地址；接口换了填这里"),
    ]


def stage_keys_for(sub: str) -> list[str]:
    """一个执行键 → 真正要排的阶段。整段流程在这里展开成它包含的那几段。"""
    key = str(sub or "").strip()
    return list(COMPOSITE_STAGES.get(key) or [key])


def limit_stages(sub: str, stages: list[str], options: dict) -> list[str]:
    """整段流程按开关裁一遍。

    三段全关时原样返回：开关全关是「我还没点」，不该变成一个什么都不做的任务。
    """
    if str(sub or "").strip() not in COMPOSITE_STAGES:
        return stages
    off = {st for param, st in COMPOSITE_SWITCHES.items()
           if param in (options or {}) and not _bool(options, param, True)}
    keep = [s for s in stages if s not in off]
    return keep or list(stages)


def stage_items() -> list[dict]:
    from .pipeline import (PHASE_LABEL, PHASES, STAGE_CALL, STAGE_DEPS, STAGE_HINT,
                           STAGE_INPUT)

    out: list[dict] = [{
        "key": "stage:subject",
        "kind": "stage",
        "stage": "subject",
        "stages": list(COMPOSITE_STAGES["subject"]),
        "group": "目标与主体",
        "label": "主体整段流程",
        "input": "any",
        "deps": [],
        "deps_label": [],
        "hint": "一次输入跑完：工商主体 → 股权穿透 → 小程序/App/公众号；"
                "企业名、品牌名、域名都能喂",
        "params": _subject_params(),
    }]
    merged = set(COMPOSITE_STAGES["subject"])
    for _, key, label in PHASES:
        if key not in STAGE_CALL or key in merged:
            continue
        out.append({
            "key": f"stage:{key}",
            "kind": "stage",
            "stage": key,
            "module": MODULE_OF.get(key, "tail"),
            "group": STAGE_GROUP.get(key, "其它"),
            "label": label or PHASE_LABEL.get(key, key),
            "input": STAGE_INPUT.get(key, "any"),
            "deps": list(STAGE_DEPS.get(key, [])),
            "deps_label": [PHASE_LABEL.get(d, d) for d in STAGE_DEPS.get(key, [])],
            "hint": STAGE_HINT.get(key, ""),
            "params": _stage_params(key),
        })
    return out


# ─────────────── direct：一次调用出结果 ───────────────
def _need(p: dict, key: str = "target") -> str:
    v = str((p or {}).get(key) or "").strip()
    if not v:
        raise ValueError("这个功能需要一个目标")
    return v


def _num(p: dict, key: str, default: float) -> float:
    try:
        raw = (p or {}).get(key)
        if raw in (None, ""):
            return default
        return float(raw)
    except (TypeError, ValueError):
        return default


def _int(p: dict, key: str, default: int) -> int:
    return int(_num(p, key, default))


def _bool(p: dict, key: str, default: bool) -> bool:
    raw = (p or {}).get(key)
    if raw in (None, ""):
        return default
    if isinstance(raw, str):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return bool(raw)


def _list(p: dict, key: str) -> list[str]:
    raw = (p or {}).get(key)
    if raw in (None, ""):
        return []
    if isinstance(raw, (list, tuple, set)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw).replace("，", ",").split(",") if x.strip()]


async def _d_enterprise(p: dict) -> dict:
    kinds = tuple(_list(p, "icp_kinds")) or ("site", "app", "mapp")
    gap = _num(p, "icp_gap", 0)
    return await enterprise.collect_entity(
        _need(p),
        mobile=_bool(p, "mobile", True),
        equity_ratio=_num(p, "equity_ratio", 100),
        equity_sources=_list(p, "equity_sources") or None,
        icp_kinds=kinds,
        icp_pages=_int(p, "icp_pages", 2),
        icp_size=_int(p, "icp_size", 40),
        icp_retry=_int(p, "icp_retry", 0) or None,
        icp_gap=gap if gap > 0 else None,
        icp_alias=_bool(p, "icp_alias", True),
        icp_force=_bool(p, "icp_force", False),
        icp_api=str(p.get("icp_api") or ""),
    )


async def _d_children(p: dict) -> dict:
    rows = await enterprise.expand_sub_company(
        _need(p),
        ratio=_num(p, "ratio", 100),
        depth=_int(p, "depth", 2),
        ubo_threshold=_num(p, "ubo_threshold", 25),
        ubo_levels=_int(p, "ubo_levels", 1),
        branches=_bool(p, "branch", True),
        sources=_list(p, "sources") or None,
        gap=_num(p, "gap", 0) or None,
        retry=_int(p, "retry", 0) or None,
    )
    limit = _int(p, "limit", 50)
    if limit > 0:
        rows = rows[:limit]
    return {"items": rows, "count": len(rows)}


async def _d_equity(p: dict) -> dict:
    eq = await equity.collect(
        _need(p),
        depth=int(_num(p, "depth", 2)),
        ratio=float(_num(p, "ratio", 100)),
        ubo_threshold=float(_num(p, "ubo_threshold", 25)),
        ubo_levels=int(_num(p, "ubo_levels", 1)),
        branches=_bool(p, "branch", True),
        sources=_list(p, "sources") or None,
        gap=_num(p, "gap", 0) or None,
        retry=_int(p, "retry", 0) or None,
        budget=_int(p, "budget", 0) or None,
    )
    return eq.as_dict()


async def _d_icp(p: dict) -> dict:
    kinds = tuple(_list(p, "kinds")) or ("site", "app", "mapp")
    gap = _num(p, "gap", 0)
    return await enterprise.icp_lookup(
        _need(p),
        kinds=kinds,
        pages=_int(p, "pages", 2),
        size=_int(p, "size", 40),
        retry=_int(p, "retry", 0) or None,
        gap=gap if gap > 0 else None,
        alias=_bool(p, "alias", True),
        force=_bool(p, "force", False),
        site_limit=_int(p, "site_limit", 0),
        miit_api=str(p.get("miit_api") or ""),
    )


async def _d_mobile(p: dict) -> dict:
    return await mobile.collect_apps(_need(p),
                                     package_path=str((p or {}).get("package_path") or ""),
                                     limit=_int(p, "limit", 8))


async def _d_applet(p: dict) -> dict:
    # 默认 45s：检索回来只有名字，补接口还得去 CDN 拉包资源，25s 常在补内容前就到点。
    return await applet_mod.collect_applets(_need(p), limit=_int(p, "limit", 8),
                                            deadline=float(_num(p, "deadline", 45)))


async def _d_applet_local(p: dict) -> dict:
    """本机微信缓存里的小程序包：解密 → 解包 → 抽接口/域名/密钥。

    纯离线，不联网也不需登录；`target` 只当包内标题/主体/域名的比对词，
    留空就是全量粗扫。
    """
    from .collectors import wxscan

    word = str((p or {}).get("target") or "").strip()
    out_root = str((p or {}).get("out_root") or "").strip()
    if not out_root:
        out_root = str(DATA_DIR / "applet" / "direct")
    res = await asyncio.to_thread(
        wxscan.scan_local_mini, appid=str((p or {}).get("appid") or "").strip(),
        limit=min(100, max(1, _int(p, "limit", 20))), target=word,
        max_pkgs=min(16, max(1, _int(p, "max_pkgs", 6))),
        workers=min(16, max(1, _int(p, "workers", 6))),
        out_root=out_root if _bool(p, "unpack", True) else "",
        unpack=_bool(p, "unpack", True))
    if isinstance(res, dict) and not res.get("source_status"):
        apps = res.get("apps") or []
        res["source_status"] = {"local_wechat": {
            "status": "ok" if apps else "empty", "items": len(apps),
            "note": "本机微信缓存 → 解密 → 解包 → 抽接口"}}
    return res


async def _d_mp(p: dict) -> dict:
    from .collectors import mp as mp_mod

    return await mp_mod.collect_mps(_need(p), limit=_int(p, "limit", 8),
                                    deadline=float(_num(p, "deadline", 26)))


async def _d_weibo(p: dict) -> dict:
    from .collectors import weibo as weibo_mod

    return await weibo_mod.collect_weibo(_need(p), limit=_int(p, "limit", 8),
                                        cookie=str((p or {}).get("cookie") or ""),
                                        deadline=float(_num(p, "deadline", 26)))


async def _d_space_search(p: dict) -> dict:
    engines = _list(p, "engines")
    size = _int(p, "size", 20)
    if len(engines) > 1:
        got = await space_mod.search_many(engines, _need(p), size)
        rows = [r for res in got for r in res.rows]
        return {"items": rows, "count": len(rows),
                "engines": {res.engine: {"total": res.total, "error": res.error}
                            for res in got}}
    engine = (engines[0] if engines else str((p or {}).get("engine") or "fofa")).lower()
    res = await space_mod.search(engine, _need(p), size)
    return {**res.as_dict(), "items": res.rows}


async def _d_space_probe(p: dict) -> dict:
    engine = str((p or {}).get("engine") or "fofa").lower()
    return await space_mod.probe(engine, str((p or {}).get("query") or ""),
                                 _int(p, "size", 1))


async def _d_source(p: dict) -> dict:
    try:
        opts = [m["name"] for m in source_meta()]
    except Exception:
        opts = []
    name = str((p or {}).get("source") or "").strip() or (opts[0] if opts else "")
    if not name:
        raise ValueError("请选择要测的数据源")
    if name in ("fofa", "llm"):
        if name == "fofa":
            try:
                rows = await fofa_search('domain="qq.com"', size=1)
            except Exception as e:
                return {"ok": False, "msg": f"请求异常：{str(e)[:160]}", "count": 0}
            return {"ok": bool(rows), "count": len(rows),
                    "msg": f"命中 {len(rows)} 条" if rows else "有 key 但没有命中，检查账号权限"}
        return {"ok": False, "count": 0, "msg": "大模型测试请到 AI 工坊"}
    fn = DOMAIN_SOURCES.get(name)
    if not fn:
        return await equity.probe_source(name)
    try:
        res = await fn("example.com")
    except Exception as e:
        return {"ok": False, "count": 0, "msg": f"{type(e).__name__}: {str(e)[:160]}"}
    if res is None:
        return {"ok": False, "count": 0, "msg": "没有返回结果"}
    subs = getattr(res, "subdomains", set()) or set()
    return {"ok": not getattr(res, "error", ""),
            "count": len(subs),
            "msg": getattr(res, "error", "") or f"{len(subs)} 子域"}


async def _d_dns(p: dict) -> dict:
    host = _need(p)
    eng = DnsEngine()
    try:
        await eng.start()
        res = await eng.resolve_a(host)
        out = {"domain": res.domain, "ips": res.ips, "cnames": res.cnames}
        if _bool(p, "mail", False):
            out["mail"] = await eng.mail_records(host)
        if _bool(p, "ptr", True) and is_ip(host):
            out["ptr"] = await eng.resolve_ptr(host)
        return out
    finally:
        eng.close()


async def _d_port(p: dict) -> dict:
    host = _need(p)
    ports = parse_ports(str((p or {}).get("ports") or "80,443,8080,8443,22,3389,3306,6379"))
    if not ports:
        raise ValueError("端口为空")
    items = await probe_mod.tcp_probes(host, ports,
                                       concurrency=max(1, _int(p, "concurrency", 12)))
    return {"host": host, "scanned": len(ports), "items": items, "count": len(items)}


async def _d_probe(p: dict) -> dict:
    base = _need(p)
    port = _int(p, "port", 0)
    items = await probe_mod.http_probes(base, port=port or None,
                                        deep=_bool(p, "deep", False))
    return {"items": items, "count": len(items)}


async def _d_fingerprint(p: dict) -> dict:
    url = _need(p)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    info = await http_probe(url, want_body=True,
                            want_cert=_bool(p, "want_cert", True))
    return {"url": url, "final_url": info.final_url, "status": info.status,
            "title": info.title, "server": info.server, "cdn": info.cdn,
            "fingerprint": info.fingerprint, "web": info.web_fp_detail,
            "cert": info.cert, "error": info.error}


async def _d_handshake(p: dict) -> dict:
    url = _need(p)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    mk = await handshake.mark(url, jarm=_bool(p, "jarm", True),
                              asn=_bool(p, "asn", True))
    return {"url": url, "mark": mk.as_dict()}


async def _d_tools(p: dict) -> dict:
    from . import installer

    items = installer.all_status()
    only = _list(p, "only")
    if only:
        items = {k: v for k, v in items.items() if k in only}
    return {"dir": str(installer.TOOLS_DIR), "items": items,
            "count": len(items),
            "ready": [k for k, v in items.items() if v.get("installed")]}


DIRECT_RUN: dict[str, Callable[[dict], Awaitable[dict]]] = {
    "enterprise": _d_enterprise,
    "children": _d_children,
    "equity": _d_equity,
    "icp": _d_icp,
    "mobile": _d_mobile,
    "applet": _d_applet,
    "applet_local": _d_applet_local,
    "mp": _d_mp,
    "weibo": _d_weibo,
    "space_search": _d_space_search,
    "space_probe": _d_space_probe,
    "source": _d_source,
    "dns": _d_dns,
    "port": _d_port,
    "probe": _d_probe,
    "fingerprint": _d_fingerprint,
    "handshake": _d_handshake,
    "tools": _d_tools,
}


# 直连项归段：界面按五段摆，单项查询收在它所属那一段里，不再另拉一张大清单。
DIRECT_MODULE = {
    "enterprise": "subject", "children": "subject", "equity": "subject", "icp": "subject",
    "mobile": "subject", "applet": "subject", "applet_local": "subject",
    "mp": "subject", "weibo": "subject",
    "space_search": "space", "space_probe": "space",
    "port": "probe", "dns": "probe", "fingerprint": "probe", "probe": "probe",
    "handshake": "probe",
    "source": "tool", "tools": "tool",
}


def direct_items() -> list[dict]:
    engines = _space_engines()
    items = [
        {"key": "direct:enterprise", "kind": "direct", "run": "enterprise",
         "group": "目标与主体", "label": "企业主体查询", "input": "entity", "deps": [],
         "hint": "公司名或域名 → 工商主体、ICP、别名、应用与域名清单",
         "params": [
             _p("mobile", "带移动端线索", "bool", True),
             _p("equity_ratio", "控股门槛(%)", "number", 100, min=1, max=100),
             _p("icp_kinds", "备案类型", "multi", _KINDS_DEFAULT, options=_kind_options()),
             _p("icp_pages", "备案翻页数", "number", 2, min=1, max=20),
             _p("icp_size", "每页条数", "number", 40, min=1, max=40),
             _p("icp_retry", "备案重试次数", "number", 4, min=1, max=10),
             _p("icp_gap", "备案请求间隔(秒)", "number", 0, min=0,
                help="0 表示用配置的节流间隔"),
             _p("icp_force", "忽略备案缓存", "bool", False),
             _p("icp_api", "备用备案接口地址", "text", "",
                help="留空用内置地址；接口换了填这里"),
             _p("icp_alias", "自动补全称", "bool", True),
             _p("equity_sources", "工商来源", "multi", _equity_source_defaults(),
                options=_equity_source_options(),
                help="主源（爱企查/天眼查/备案）先跑；主源一条数据都没取到时，才补跑勾选的辅助源，省额度"),
         ]},
        {"key": "direct:children", "kind": "direct", "run": "children",
         "group": "目标与主体", "label": "全资子公司", "input": "entity", "deps": [],
         "hint": "按企业名列子公司与控股公司",
         "params": [
             _p("ratio", "控股门槛(%)", "number", 100, min=1, max=100,
                help="调到 51 就是控股子公司，100 只留全资"),
             _p("depth", "往下穿几层", "number", 2, min=1, max=6),
             _p("ubo_threshold", "受益所有人阈值(%)", "number", 25, min=1, max=100, adv=True),
             _p("ubo_levels", "受益所有人层数", "number", 1, min=0, max=6, adv=True),
             _p("branch", "查分支机构", "bool", True,
                help="关掉就少一次分支机构请求、少耗一次额度"),
             _p("sources", "工商来源", "multi", _equity_source_defaults(),
                options=_equity_source_options(),
                help="主源（爱企查/天眼查/备案）先跑；主源一条数据都没取到时，才补跑勾选的辅助源，省额度"),
             _p("gap", "请求间隔(秒)", "number", 0, min=0, max=180,
                help="每次工商请求之间额外等待；0 表示用配置里的穿透间隔"),
             _p("retry", "重试次数", "number", 1, min=1, max=10, adv=True,
                help="单个工商请求失败时的尝试次数；账号额度紧就调 1"),
             _p("limit", "返回条数", "number", 50, min=0),
         ]},
        {"key": "direct:equity", "kind": "direct", "run": "equity",
         "group": "目标与主体", "label": "股权穿透", "input": "entity", "deps": [],
         "hint": "投资链路、累计持股、股东与 UBO，可单次调层数与门槛",
         "params": [
             _p("depth", "往下穿几层", "number", 2, min=1, max=6),
             _p("ratio", "控股门槛(%)", "number", 100, min=1, max=100),
             _p("ubo_threshold", "UBO 阈值(%)", "number", 25, min=1, max=100, adv=True),
             _p("ubo_levels", "UBO 层数", "number", 1, min=0, max=6, adv=True),
             _p("branch", "查分支机构", "bool", True,
                help="关掉就少一次分支机构请求、少耗一次额度"),
             _p("sources", "工商来源", "multi", _equity_source_defaults(),
                options=_equity_source_options(),
                help="主源（爱企查/天眼查/备案）先跑；主源一条数据都没取到时，才补跑勾选的辅助源，省额度"),
             _p("gap", "请求间隔(秒)", "number", 0, min=0, max=180,
                help="每次工商请求之间额外等待；0 表示用配置里的穿透间隔"),
             _p("retry", "重试次数", "number", 1, min=1, max=10, adv=True,
                help="单个工商请求失败时的尝试次数；账号额度紧就调 1"),
             _p("budget", "请求额度(次)", "number", 40, min=5, max=200, adv=True,
                help="整趟穿透允许的工商请求次数；翻投资页 / 上层股东 / 逐层子公司共用，"
                     "集团主体找不全先加这里"),
         ]},
        {"key": "direct:icp", "kind": "direct", "run": "icp",
         "group": "目标与主体", "label": "ICP 备案", "input": "any", "deps": [],
         "hint": "公司名或域名 → 备案号与备案主体；主体备案查不到时会换全称再试",
         "params": [
             _p("kinds", "备案类型", "multi", _KINDS_DEFAULT, options=_kind_options()),
             _p("pages", "翻页数", "number", 2, min=1, max=20),
             _p("size", "每页条数", "number", 40, min=1, max=40),
             _p("retry", "重试次数", "number", 4, min=1, max=10),
             _p("gap", "请求间隔(秒)", "number", 0, min=0,
                help="0 表示用配置的节流间隔"),
             _p("alias", "自动补全称", "bool", True),
             _p("force", "忽略缓存重查", "bool", False),
             _p("site_limit", "网站备案出表上限", "number", 0, min=0,
                help="0 表示不限"),
             _p("miit_api", "备用备案接口地址", "text", "",
                help="留空用内置地址；接口换了填这里"),
         ]},
        {"key": "direct:mobile", "kind": "direct", "run": "mobile",
         "group": "目标与主体", "label": "应用商店", "input": "entity", "deps": [],
         "hint": "应用名或包名 → APP 清单、自有域与 SDK 域",
         "params": [
             _p("limit", "条数", "number", 8, min=1, max=50),
             _p("package_path", "本地安装包路径", "text", "",
                help="填了就直接解析这个包，不去商店搜"),
         ]},
        {"key": "direct:applet", "kind": "direct", "run": "applet",
         "group": "目标与主体", "label": "小程序", "input": "entity", "deps": [],
         "hint": "小程序名、主体名或 AppID → 档案、接口与域名；主体全称还会比对本机微信缓存",
         "params": [
             _p("limit", "条数", "number", 8, min=1, max=50),
             _p("deadline", "超时(秒)", "number", 45, min=5, max=180),
         ]},
        {"key": "direct:applet_local", "kind": "direct", "run": "applet_local",
         "group": "目标与主体", "label": "本机小程序解包", "input": "any", "deps": [],
         "hint": "读本机微信缓存里的小程序包 → 解密解包 → 抽接口/域名/密钥；"
                 "不联网、不要登录，断网也能跑",
         "params": [
             _p("appid", "只扫这个 AppID", "text", "",
                help="留空按缓存里的小程序按条数上限扫"),
             _p("limit", "最多扫几个", "number", 20, min=1, max=100),
             _p("max_pkgs", "每个包扫几份分包", "number", 6, min=1, max=16),
             _p("workers", "并行数", "number", 6, min=1, max=16),
             _p("unpack", "解包落盘 + 美化 JS", "bool", True,
                help="解到 data/applet 下，压缩脚本另存可读版"),
         ]},
        {"key": "direct:mp", "kind": "direct", "run": "mp",
         "group": "目标与主体", "label": "公众号", "input": "entity", "deps": [],
         "hint": "公众号名、主体名或文章链接 → 档案与正文域",
         "params": [
             _p("limit", "条数", "number", 8, min=1, max=50),
             _p("deadline", "超时(秒)", "number", 26, min=5, max=180),
         ]},
        {"key": "direct:weibo", "kind": "direct", "run": "weibo",
         "group": "目标与主体", "label": "微博账号", "input": "entity", "deps": [],
         "hint": "主体名 → 微博号、昵称、简介、头像、粉丝数；填登录态才走站内搜索",
         "params": [
             _p("limit", "条数", "number", 8, min=1, max=50),
             _p("deadline", "超时(秒)", "number", 26, min=5, max=180),
             _p("cookie", "微博登录态 Cookie", "text", "",
                help="填了就用站内搜索，一次拿昵称/简介/头像/粉丝数/认证；"
                     "留空只退到检索发现，命中率低。配置里可存默认值 weibo.cookie"),
         ]},

        {"key": "direct:space_search", "kind": "direct", "run": "space_search",
         "group": "网络与空间", "label": "空间测绘检索", "input": "any", "deps": [],
         "hint": "直接发一句测绘语法，看这个引擎这一句能出多少",
         "params": [
             _p("engine", "引擎", "select", "fofa", options=engines),
             _p("engines", "多引擎同查", "multi", [], options=engines,
                help="选了多个就一起发，结果合并"),
             _p("size", "条数", "number", 20, min=1, max=1000),
         ]},
        {"key": "direct:space_probe", "kind": "direct", "run": "space_probe",
         "group": "网络与空间", "label": "测绘引擎连通", "input": "none", "deps": [],
         "hint": "真打一次最小查询，看 key 是否可用、额度是否还在",
         "params": [
             _p("engine", "引擎", "select", "fofa", options=engines),
             _p("query", "测试语法", "text", ""),
             _p("size", "条数", "number", 1, min=1, max=100),
         ]},
        {"key": "direct:port", "kind": "direct", "run": "port",
         "group": "网络与空间", "label": "端口协议探针", "input": "ip", "deps": [],
         "hint": "按端口握手认服务，单次指定端口即可",
         "params": [
             _p("ports", "端口", "text", "80,443,8080,8443,22,3389,3306,6379"),
             _p("concurrency", "并发", "number", 12, min=1, max=200),
         ]},
        {"key": "direct:dns", "kind": "direct", "run": "dns",
         "group": "网络与空间", "label": "DNS 解析", "input": "domain", "deps": [],
         "hint": "A/AAAA/CNAME 一跳解析，可选带 MX/TXT 与 PTR",
         "params": [
             _p("mail", "带邮件记录", "bool", False),
             _p("ptr", "IP 反查 PTR", "bool", True),
         ]},

        {"key": "direct:fingerprint", "kind": "direct", "run": "fingerprint",
         "group": "站点与协议", "label": "存活与指纹", "input": "domain", "deps": [],
         "hint": "单 URL 探存活、抓标题、组件指纹与证书",
         "params": [_p("want_cert", "取证书", "bool", True)]},
        {"key": "direct:probe", "kind": "direct", "run": "probe",
         "group": "站点与协议", "label": "脆弱组件探针", "input": "domain", "deps": [],
         "hint": "对单个地址跑脆弱组件与暴露面探针",
         "params": [
             _p("deep", "深度", "bool", False),
             _p("port", "指定端口", "number", 0, min=0, max=65535,
                help="0 表示按 URL 里的端口"),
         ]},
        {"key": "direct:handshake", "kind": "direct", "run": "handshake",
         "group": "站点与协议", "label": "握手标记", "input": "domain", "deps": [],
         "hint": "JARM、TLS 版本、证书 SAN、CSP/HSTS、ASN",
         "params": [
             _p("jarm", "算 JARM", "bool", True),
             _p("asn", "查 ASN", "bool", True),
         ]},

        {"key": "direct:source", "kind": "direct", "run": "source",
         "group": "数据源与工具", "label": "信息源连通", "input": "none", "deps": [],
         "hint": "挑一个被动源真打一次，看是 key 问题还是网络问题",
         "params": [_p("source", "数据源", "select",
                       (_source_options() or [{"value": ""}])[0]["value"],
                       options=_source_options())]},
        {"key": "direct:tools", "kind": "direct", "run": "tools",
         "group": "数据源与工具", "label": "外部工具环境", "input": "none", "deps": [],
         "hint": "看本机工具装没装、装在哪、缺哪个要一键装",
         "params": [_p("only", "只看这些工具", "multi", [], options=_tool_options(),
                       help="留空列出全部")]},
    ]
    # 直连项自己不带阶段，靠这张表归到五段里的某一段（工具 / 数据源查连通性不算某一段）
    for it in items:
        it["module"] = DIRECT_MODULE.get(it.get("run") or "", "tool")
    return items


def modules_payload(items: list[dict] | None = None) -> list[dict]:
    """五段模块：界面按这五张卡画，不再把 30 多个杂项平铺成一张清单。

    每张卡自带「整段跑」的执行键、本段包含的阶段，以及归到本段的单项查询，
    前端只按 ``module`` 分组即可，不用再猜哪个单项属于哪一段。
    """
    from .pipeline import PHASE_LABEL

    pool = items if items is not None else (stage_items() + direct_items())
    out: list[dict] = []
    for idx, mkey in enumerate(MODULE_KEYS, 1):
        stages = list(MODULE_STAGES.get(mkey) or [])
        out.append({
            "key": mkey,
            "no": idx,
            "label": MODULE_LABEL.get(mkey, mkey),
            "hint": MODULE_HINT.get(mkey, ""),
            "run_key": f"stage:m_{mkey}",
            "stages": stages,
            "stage_labels": [PHASE_LABEL.get(s, s) for s in stages],
            # 本卡的参数：本段各阶段参数并起来，同名的只留一份，前端不再自己拼
            "params": _module_params(stages),
            # 本段「一次调用出结果」的直连项：界面上收进卡片里的折叠区
            "directs": [i for i in pool
                        if i.get("kind") == "direct" and i.get("module") == mkey],
            # 归到本段、但没列进整段阶段的散阶段（正常为空，留个兜底）
            "extra_stages": [i for i in pool
                             if i.get("kind") == "stage" and i.get("module") == mkey
                             and i.get("stage") not in stages],
        })
    return out


def catalog() -> dict:
    items = stage_items() + direct_items()
    groups = [g for g in GROUP_ORDER if any(i["group"] == g for i in items)]
    mods = modules_payload(items)
    return {"ok": True, "count": len(items), "items": items, "groups": groups,
            "modules": mods,
            # 数据源与工具不属于五段里的任何一段，单独一小组摆在最后
            "tools": [i for i in items if i.get("module") == "tool"],
            # 各模块的「主源 / 辅助」：哪些是主源由后端说了算，前端不自己猜
            "source_groups": _source_groups(),
            "equity_sources": _equity_source_options(),
            # 五段一键跑完的执行键
            "full_run_key": "stage:full",
            "options": []}


def _asset_rows_for(key: str, params: dict, data: dict) -> list[dict]:
    """单项直跑要落的资产行。

    `direct:*` 不建任务，但「点一下就跑」的结果一样是资产：以前只把 JSON 回给
    前端，资产页、分面统计和导出里一条都没有，跑完像什么都没发生。
    """
    if not isinstance(data, dict):
        return []
    name = str((params or {}).get("target") or "").strip()
    if key == "equity":
        return asset_rows.equity_rows(str(data.get("name") or name), data,
                                      float(_num(params, "ratio", 100)))
    if key == "icp":
        return asset_rows.icp_rows(data.get("items"), name)
    if key == "enterprise":
        rows: list[dict] = []
        nm = str(data.get("name") or data.get("brand") or name)
        # 主体行不放 host / root_domain：输入可能是企业全称，塞进域名列会污染按根域聚合的资产组
        if data.get("icp") or data.get("name"):
            rows.append({"kind": "enterprise", "url": f"enterprise:{name}", "host": "",
                         "title": nm, "extra": data, "sources": "enterprise"})
        rows.extend(asset_rows.icp_rows(data.get("icp"), nm))
        # 主体收集内部已经跑过一遍股权穿透，链路在 equity_detail 里。以前这里只取走
        # 备案那几条，控股 / 投资 / 股东 / 分支一条都不落，穿透图也就没数据。
        detail = data.get("equity_detail")
        if isinstance(detail, dict) and detail.get("chain"):
            rows.extend(asset_rows.equity_rows(
                str(detail.get("name") or nm), detail,
                float(detail.get("ratio") or _num(params, "ratio", 100) or 100)))
        return rows
    if key == "applet_local":
        return asset_rows.applet_rows(data.get("apps"), str(data.get("out_root") or ""))
    if key == "applet":
        # 单项跑小程序以前只回 JSON：条目里有名字 / AppID / 主体 / 域名，
        # 资产页和导出里却一条都没有。这里把条目和本机包解出来的记录并成一套行。
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        rows: list[dict] = []
        for it in items:
            one = {"appid": it.get("appid"), "name": it.get("name"),
                   "subject": it.get("subject"),
                   "license": it.get("license") or "",
                   "domains": it.get("domains") or [],
                   "notes": list(it.get("evidence") or []) + list(it.get("notes") or [])}
            for row in asset_rows.applet_rows([one]):
                # 条目来自公开检索，不是本机解包，来源别标成 applet-local
                row["sources"] = str(row.get("sources") or "").replace(
                    "applet-local", "applet")
                if row.get("kind") == "applet_icp":
                    row["sources"] = "miit"
                rows.append(row)
        rows.extend(asset_rows.applet_rows(data.get("apps")))
        have = {str(r.get("url") or "") for r in rows}
        doms: list[str] = list(data.get("domains") or [])
        for it in items:
            doms.extend(it.get("domains") or [])
        for dom in dict.fromkeys(str(x) for x in doms if x):
            if f"domain:{dom}" in have:
                continue
            rows.append({"kind": "domain", "url": f"domain:{dom}", "host": dom,
                         "title": "小程序后端域名", "sources": "applet"})
        return rows
    return []


async def run_direct(key: str, params: dict) -> dict:
    """同步跑一个 direct 功能，返回耗时、结果体与本次落库条数。"""
    fn = DIRECT_RUN.get(str(key or "").strip())
    if not fn:
        raise ValueError(f"不认识的功能：{key}")
    t0 = time.time()
    params = dict(params or {})
    data = await fn(params)
    saved = {}
    rows = _asset_rows_for(str(key or "").strip(), params, data)
    for row in rows:
        try:
            store.upsert_asset(row)
            saved[row["kind"]] = saved.get(row["kind"], 0) + 1
        except Exception:
            continue
    # 单项跑完也要能看见「这一枪调了哪几路、哪路是死的」。采集器把结果自报在
    # source_status 里，这里摊成和任务渠道面板同一套标签，没自报的就是空表。
    key_name = str(key or "").strip()
    smap = (data or {}).get("source_status") if isinstance(data, dict) else None
    raw_notes = (data or {}).get("notes") if isinstance(data, dict) else None
    note_map: dict[str, str] = {}
    item_map: dict[str, int] = {}
    chain = (data or {}).get("chain") if isinstance(data, dict) else None
    if isinstance(smap, dict):
        # 说明按渠道拆：点名了哪一路（``qichacha HTTP 302…``）就归哪一路，
        # 没点名的只挂给状态对得上的那一路，别把「额度已用尽」抄给没调额度的渠道。
        note_map = source_health.split_notes(raw_notes, smap)
    if isinstance(smap, dict) and isinstance(chain, list):
        # 条数按「这条链路里哪些节点是它给的」算，面板上才看得出一路是没数据还是出了几层。
        for k in smap:
            tail = str(k).split(":", 1)[-1]
            item_map[str(k)] = sum(
                1 for c in chain if isinstance(c, dict)
                and tail and tail in (str(c.get("src") or ""), str(c.get("via") or "")))
    channels = source_health.normalize(smap, stage=key_name, notes=note_map, items=item_map)
    if not channels and rows:
        # 有的采集器只回一条命中记录、不自报渠道（备案按域名就是这种），面板会整块
        # 空着，看着像没调外部来源。这里按落库行的 sources 列反推，至少写清这一枪
        # 的成绩是哪一路给的。
        derived: dict[str, int] = {}
        for row in rows:
            for one in str(row.get("sources") or "").split(","):
                one = one.strip()
                if one:
                    derived[one] = derived.get(one, 0) + 1
        if derived:
            channels = source_health.normalize(
                {k: "ok" for k in derived}, stage=key_name, items=derived)
    # 自设上限 / 请求额度把这一枪砍短了：补几行「截断」。混进上面那批会让
    # 面板把某一路整个标成失效，用户就去修一个根本没坏的渠道。
    cap = (data or {}).get("cap_notes") if isinstance(data, dict) else None
    if isinstance(cap, dict) and cap:
        channels = list(channels) + source_health.normalize(
            {f"cap:{k}": "partial" for k in cap}, stage=key_name,
            notes={f"cap:{k}": str(v) for k, v in cap.items()})
    return {"key": key, "elapsed_ms": int((time.time() - t0) * 1000),
            "result": data, "saved": saved, "saved_total": sum(saved.values()),
            "sources": channels}

