"""任务编排引擎：把各收集阶段串成流水线，实时写库。

阶段：

  P0   target_parse  目标归一（域名 / 企业名 / IP / IP 段 / URL）
  P1   enterprise    企业主体：ICP 反查、RDAP、MX/TXT/NS、AI 别名扩展
  P1a  equity        股权穿透（按控股比例逐层展开子公司）
  P1b  mobile        小程序 / 公众号 / App 资产
  P2   passive       被动子域（免费源多路并发：CT 多镜像、被动 DNS、归档索引等）
  P2a  space         空间测绘（按配置的测绘引擎查根域下的对外资产）
  P3   brute         字典爆破 + 变体生成（泛解析剔除）
  P4   dns           解析 + CNAME + CDN 判定 + PTR
  P5   port          端口扫描 + 服务识别
  P6   web           存活探测 + 标题 + 指纹 + 证书 + favicon
  P7   crawl         站点爬虫 + JS 接口 + 敏感信息
  P8   leak          敏感文件探测 + Git 泄露
  P9   vhost         vhost 碰撞
  P9a  takeover      子域接管
  P10  sibling       旁站 / C 段 / ASN 网段 / 存储桶
  P11  deep          代码泄露 / 邮箱 / 邮件 DNS / 截图 / 组件检测
  P12  assetdiff     与上一轮快照比对，标出新增与消失
  P13  report        汇总统计 + 通知
"""

from __future__ import annotations

# 一键收集的前置展开由 server 侧注册：引擎不反向 import server，避免循环导入
oneclick_expand = None

import asyncio
import contextvars
import ipaddress
import time
import uuid
import traceback
from collections import Counter

from ..config import config
from ..db import normalize_asset, store
from ..utils import host_of, idn_ascii, is_ip, is_valid_domain, root_domain
from .collectors import ownership

# 后台阶段（目前是股权穿透）资产归属用的阶段键。contextvar 是按协程任务各存一份的，
# 后台股权边穿边落资产时前台正在跑被动收集，用 self.current_phase 会把两边记成同一个阶段。
ASSET_PHASE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "asset_phase", default=None)
from .dns_engine import DnsEngine
from .pipeline_stages import StagesMixin

PHASES = [
    ("P0", "target_parse", "目标归一"),
    ("P1", "enterprise", "企业主体"),
    ("P1a", "equity", "股权穿透"),
    ("P1b", "mobile", "小程序/App"),
    ("P2", "passive", "被动子域"),
    ("P2a", "space", "空间测绘"),
    ("P3", "brute", "字典爆破"),
    ("P4", "dns", "DNS/CDN"),
    ("P5", "port", "端口扫描"),
    ("P6", "web", "存活探测"),
    ("P7", "crawl", "站点爬虫"),
    ("P8", "leak", "敏感文件"),
    ("P9", "vhost", "VHost碰撞"),
    ("P9a", "takeover", "子域接管"),
    ("P10", "sibling", "旁站C段"),
    ("P11", "deep", "深度挖掘"),
    ("P12", "assetdiff", "资产变更"),
    ("P13", "report", "汇总"),
]

PHASE_WEIGHT = {k: i for i, (_, k, _) in enumerate(PHASES)}
PHASE_LABEL = {k: label for _, k, label in PHASES}

# 可以单独重跑的阶段：键 → 执行体。目标归一是每轮入口，汇总恒定收尾，两者不单跑。
STAGE_CALL = {
    "enterprise": lambda s, p: s.p1_enterprise(_roots_of(s)),
    "equity": lambda s, p: s.p1c_equity(p),
    "mobile": lambda s, p: s.p1b_mobile(p),
    "passive": lambda s, p: s.p2_passive(_roots_of(s)),
    "space": lambda s, p: s.p2a_space(_roots_of(s)),
    "brute": lambda s, p: s.p3_brute(_roots_of(s)),
    "dns": lambda s, p: s.p4_dns(p),
    "port": lambda s, p: s.p5_port(p),
    "web": lambda s, p: s.p6_web(p),
    "crawl": lambda s, p: s.p7_crawl(),
    "leak": lambda s, p: s.p8_leak(),
    "vhost": lambda s, p: s.p9_vhost(),
    "takeover": lambda s, p: s.p9a_takeover(),
    "sibling": lambda s, p: s.p10_sibling(p),
    "deep": lambda s, p: s.p11_deep(),
    "assetdiff": lambda s, p: s.p12_assetdiff(p),
    "report": lambda s, p: s.p13_report(),
}
RERUN_STAGES = list(STAGE_CALL)

# 单项执行：每个阶段吃哪种输入、依赖哪些上游的结果。
# deps 只在「带上游」时用 —— 按依赖闭包补齐，执行顺序仍按 PHASES。
STAGE_DEPS = {
    "enterprise": [],
    "equity": [],
    "mobile": [],
    "passive": [],
    "space": [],
    "brute": [],
    "dns": [],
    "port": ["dns"],
    "web": [],
    "crawl": ["web"],
    "leak": ["web"],
    "vhost": ["dns", "web"],
    "takeover": ["dns"],
    "sibling": ["dns", "port"],
    "deep": ["web"],
    "assetdiff": [],
    "report": [],
}

# 阶段主输入形态：domain=域名/URL，entity=企业名，ip=IP/网段，any=都能喂
STAGE_INPUT = {
    "enterprise": "domain",
    "equity": "entity",
    "mobile": "entity",
    "passive": "domain",
    "space": "domain",
    "brute": "domain",
    "dns": "domain",
    "port": "ip",
    "web": "domain",
    "crawl": "domain",
    "leak": "domain",
    "vhost": "domain",
    "takeover": "domain",
    "sibling": "ip",
    "deep": "domain",
    "assetdiff": "any",
    "report": "any",
}

STAGE_HINT = {
    "enterprise": "按根域查工商主体、ICP 备案、邮件 DNS，产出企业实体与同主体域名",
    "equity": "按企业名查股权穿透，只把累计 100% 控股的主体并进目标池",
    "mobile": "按企业名/品牌查应用商店与小程序，产出 APP、小程序资产",
    "passive": "按根域跑被动子域与搜索源，源开关在数据源里配",
    "space": "按根域跑空间测绘引擎检索，产出带端口与标题的资产",
    "brute": "按根域跑字典爆破，字典在采集强度里选",
    "dns": "解析 A/AAAA/CNAME/MX/TXT，识别 CDN，产出 IP 与解析关系",
    "port": "扫开放端口与协议，产出 service 资产",
    "web": "逐个 URL/IP 探存活、抓标题与指纹，产出 site 资产",
    "crawl": "爬已存活站点，抽链接、JS 与隐藏路径",
    "leak": "探敏感文件与目录（git、备份、配置、swagger 等）",
    "vhost": "用字典撞同 IP 上的虚拟主机，找未登记站点",
    "takeover": "检查 CNAME 指向的第三方服务是否存在接管风险",
    "sibling": "按 IP 与 C 段找同段旁站与关联资产",
    "deep": "对站点跑深度挖掘，跟参数、接口与目录纵深",
    "assetdiff": "和上一次快照比，标出新增与消失的资产",
    "report": "汇总本任务资产、风险与统计，生成报告数据",
}


def expand_stages(keys, with_deps: bool = False) -> list[str]:
    """按 PHASES 顺序排好要跑的阶段；with_deps 时先把依赖闭包补齐。"""
    want = {str(k) for k in (keys or []) if str(k) in STAGE_CALL}
    if with_deps:
        todo = list(want)
        while todo:
            key = todo.pop()
            for dep in STAGE_DEPS.get(key, ()):
                if dep in STAGE_CALL and dep not in want:
                    want.add(dep)
                    todo.append(dep)
    return [k for _, k, _ in PHASES if k in want]


# 一键全收集的五个大步骤：前端勾选哪几步，_run_full 就只跑对应分组。
# 空 / 缺省 = 全开，保证老任务与直接调 API 的行为不变。
ONECLICK_STEPS = ("p1", "p2", "p3", "p4", "p5")
STEP_LABELS = {
    "p1": "主体穿透",
    "p2": "域名收集",
    "p3": "空间测绘",
    "p4": "主动探测",
    "p5": "深度挖掘",
}


def _roots_of(runner) -> list[str]:
    """域名池归约成根域：被动源、测绘、爆破都按根域整棵查，不按单个子域逐个查。"""
    roots: set[str] = set()
    for d in getattr(runner, "domains", ()):
        if d and not is_ip(d):
            r = runner._root(d)
            if r:
                roots.add(r)
    return sorted(roots)

RUNNING: dict[str, "TaskRunner"] = {}


class TaskRunner(StagesMixin):
    def __init__(self, task_id: str, targets: list[str], options: dict) -> None:
        self.task_id = task_id
        self.targets = targets
        self.options = options or {}
        self.stop_event = asyncio.Event()
        dns_conc = int((self.options or {}).get("domain_brute_concurrent")
                       or config.get("scan", "domain_brute_concurrent") or 800)
        self.dns = DnsEngine(concurrent=dns_conc)
        self.stats: Counter = Counter()
        # 已经计过数的资产 url。统计要的是「这个任务收了多少条」，不是「写了多少次库」：
        # 同一个 url 会被被动源、解析、探活各写一遍，股权链路更是边穿边反复交，
        # 只按调用次数累加会让任务页的数字比资产页大好几倍。
        self._counted_keys: set[str] = set()
        # 本轮真正入过库的资产类型，收尾时按资产表实际条数覆盖统计
        self._asset_kinds: set[str] = set()
        self.domains: set[str] = set()
        self.ips: dict[str, set[str]] = {}
        self.cnames: dict[str, list[str]] = {}
        self.hosts_to_probe: set[str] = set()
        self.ips_candidates: set[str] = set()
        # MX 指向的邮箱服务商服务器 IP：端口扫描能看到 25/993 这类端口，
        # 但那是服务商的设施，不算本任务的开放端口与业务面。
        self.mail_provider_ips: set[str] = set()
        # 邮件服务商的主机名：写入资产后，P4 解析、P6 探活、P7 爬虫都按主机名跳过
        self.mail_hosts: set[str] = set()
        # 自家根下的邮件主机（smtp/pop/imap 这类 MX 落点）：机器是邮箱托管商的，
        # 只探 Web、不报 25/993 这批邮件端口
        self.mail_roles: set[str] = set()
        # 邮件设施主机（mail/smtp/imap/pop）的落点 IP：邮件协议端口不发，Web 端口照扫
        self.mail_web_ips: set[str] = set()
        self.entities: list[dict] = []
        # 已认定为自家资产的根域。域名目标本身就是自家根；企业名走的实体扩线、
        # 股权穿透、小程序包、被动源都会往里加。后面按根域逐段扩线时只扩这里面的
        # 根，别把「解析出来 / 顺手收进 domains 的别人的根」一起扫。
        self.own_roots: set[str] = set()
        # 根域 → 归属来源（实体名 / 股权子公司 / 企业名直填），给报告和日志用
        self.root_owner: dict[str, str] = {}
        self.current_phase = "target_parse"
        # 阶段时间窗落库节流：同一个阶段 30 秒内只写一次，够给老任务兜底归属
        self._phase_recorded = ""
        self._phase_ts = 0.0
        self._last_pct: dict[str, int] = {}
        # 阶段并发后百分比会来回跳：旁站（权重靠后）报到 82 时端口（权重靠前）还在跑，
        # 端口再报就是 47，界面上看着像从头重跑。整体百分比只许涨不许跌。
        self._max_overall = 0
        # 直接开合的阶段：进入 / 退出各落一次时间戳，资产归属和阶段时长都按它算
        self._open_stage = ""
        self._stage_start = 0.0
        self.start_ts = time.time()
        # 单阶段异常只跳过该阶段，不判整任务失败；失败原因留在这里，收尾时写进日志与统计
        self.stage_errors: list[str] = []
        # 只跑指定阶段（单阶段重跑 / 功能单项测试）：空 = 整条流水线
        # options["with_deps"] 为真时连同上游一起补跑（单独测「爬虫」得先把站点探活）
        self.only_stages = expand_stages(self.options.get("only_stages") or [],
                                         bool(self.options.get("with_deps")))
        # 一键流程里「前置实体展开」已经跑过的企业：结果按企业名存这里，P0 再遇到
        # 同一个主体就直接复用，不再跑第二遍。以前 300 秒的两次超时就是同一主体
        # 先后被前置展开和 P0 各掐一次，域名一个都没落地。
        self.expand_entities: dict[str, dict] = {}

    # ───────── 基础能力 ─────────
    def _entity_timeout(self) -> float:
        """单个企业主体扩线的总时限。

        默认从 300 秒提到 1800 秒：一个省公司级主体要先搜域名、过取证闸，再挂股权
        穿透（一次 30 秒延时，一百多次就是大半个小时）。300 秒只够跑完股权、来不及
        出域名，现场表现是「主体收集做完了，域名 0 个、端口 0 个、web 资产全空」。
        """
        try:
            val = float(self.opt("enterprise_timeout", 1800) or 1800)
        except Exception:
            val = 1800.0
        return max(60.0, val)

    def log(self, module: str, msg: str, level: str = "info") -> None:
        store.add_log(self.task_id, module, msg, level)

    def _stage_enter(self, key: str) -> None:
        """阶段真开跑：把当前阶段切到 key，并落一条起点。

        以前只在各阶段自己调 `progress()` 的里程碑写时间戳，很多阶段（被动收集、
        存活探测…）整段只在结尾写一次，`task_phases` 里 start=end，界面算出来 0 秒；
        阶段外的资产还会沿用上一个阶段的标签（实测 IP 反查域被记成 `mobile`）。
        这里在阶段边界无条件切换，界面上的时长和资产归属都以真实开跑为准。
        """
        self._open_stage = key
        self._stage_start = time.time()
        self.current_phase = key
        try:
            store.record_phase(self.task_id, key, self._stage_start)
        except Exception:
            pass

    def _stage_exit(self, key: str) -> None:
        """阶段收尾：补一条结束时间，`task_phases` 才有真实跨度。"""
        if self._open_stage == key:
            self._open_stage = ""
        try:
            store.record_phase(self.task_id, key, time.time())
        except Exception:
            pass

    def progress(self, phase_key: str, pct: int, message: str = "",
                 record: bool = True) -> None:
        """推进进度并刷新阶段文字。

        ``record=False`` 只换界面标签、不写阶段时间窗：主体扩线是在 P0 里跑的，
        它把标签提前切成「企业主体」是对的，但再写一条 enterprise 时间戳就会和
        target_parse 完全重叠，两个阶段各显示同一段 179 秒。
        """
        idx = PHASE_WEIGHT.get(phase_key, 0)
        # 股权穿透在后台边穿边报进度，前台这时候已经在跑被动子域 / 端口扫描。
        # 分组更靠前的阶段不能把界面标签和整体百分比拉回去，只更新它自己的百分比。
        if PHASE_WEIGHT.get(self.current_phase, -1) > idx:
            self._last_pct[phase_key] = pct
            try:
                store.update_task(self.task_id, stats=dict(self.stats))
            except Exception:
                pass
            return
        total = len(PHASES)
        base = int((idx / total) * 100)
        span = int(100 / total)
        overall = min(99, base + int(span * max(0, min(100, pct)) / 100))
        overall = max(overall, self._max_overall)
        self._max_overall = overall
        self.current_phase = phase_key
        self._last_pct[phase_key] = pct
        now = time.time()
        if record and (phase_key != self._phase_recorded or now - self._phase_ts > 30):
            try:
                store.record_phase(self.task_id, phase_key, now)
            except Exception:
                pass
            self._phase_recorded = phase_key
            self._phase_ts = now
        store.update_task(self.task_id, progress=overall, message=message or phase_key,
                          phase=phase_key, stats=dict(self.stats))

    async def _with_heartbeat(self, coro, phase_key: str, message: str,
                              every: float = 15.0):
        """跑一个可能耗满超时的协程，期间按固定间隔把阶段文字往前刷。

        连不上的主机每个都要等满 http.timeout，几十个排在一起时任务详情里的
        阶段文字会几十分钟不变，用户看到的就是「卡死在存活探测」。
        """
        async def tick() -> None:
            while True:
                await asyncio.sleep(every)
                self.progress(phase_key, self._last_pct.get(phase_key, 0), message)

        beat = asyncio.create_task(tick())
        try:
            return await coro
        finally:
            beat.cancel()

    async def _until_stop(self, coro, label: str):
        """跑一段活，同时盯着停止信号：停止按下去就把这段掐断，不等它自己跑完。

        停止信号过去只在阶段之间生效。股权穿透这类阶段内部有整段总闸（配了请求间隔
        会放宽到几小时），每家子公司还要各自等满超时，页面上压一次停止，任务就挂在
        「正在停止」十几分钟，期间额度照烧、进度也不再动。这里把「停止」变成马上生效。
        """
        task = asyncio.ensure_future(coro)
        stop = asyncio.ensure_future(self.stop_event.wait())
        try:
            done, _ = await asyncio.wait({task, stop}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            for x in (task, stop):
                x.cancel()
            raise
        finally:
            stop.cancel()
        if task in done:
            return task.result()
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 15)
            self.log("task", f"{label} 已按停止请求中断，正在等的回包不再等", "warn")
        except asyncio.TimeoutError:
            self.log("task", f"{label} 中断用了超过 15s，不再等它退出", "warn")
        raise asyncio.CancelledError

    async def _guard(self, key: str, coro, label: str) -> None:
        """单个阶段炸掉不带走整条流水线。

        公网目标随时会给 RST / 半开连接 / 第三方网关的怪响应，任何一处没兜住就会把
        前面跑了几小时的结果判成「任务异常」。这里记下错误、继续后面的阶段，任务照常
        收尾出报告；失败原因进日志和 stats["stage_errors"]，不会被静默吞掉。
        """
        self._stage_enter(key)
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            msg = f"{label} 异常：{type(e).__name__}: {e}"
            self.stage_errors.append(msg)
            self.stats["stage_errors"] = len(self.stage_errors)
            self.log(key, msg + "（已跳过该阶段，后续阶段继续跑）", "error")
            try:
                store.update_task(self.task_id, stats=dict(self.stats))
            except Exception:
                pass
        finally:
            self._stage_exit(key)

    def save_asset(self, item: dict, count: bool = True) -> None:
        """写一条资产并挂到本任务。

        ``count=False`` 只更新不计数：股权链路这类会被「边穿边报」重复交好几遍，
        同一批节点每报一次就加一遍统计，任务页的资产数会越跑越虚。
        """
        try:
            aid = store.upsert_asset(item)
            store.link_task_asset(self.task_id, aid, ASSET_PHASE.get() or self.current_phase)
            kind = item.get("kind", "asset")
            self._asset_kinds.add(kind)
            if count:
                # 按归一化后的 url 去重计数，和 assets 表的唯一键保持一致
                norm = normalize_asset(item)
                key = str(norm.get("url") or norm.get("host") or norm.get("ip") or "")
                if key and key not in self._counted_keys:
                    self._counted_keys.add(key)
                    self.stats[kind] += 1
                elif not key:
                    self.stats[kind] += 1
        except Exception as e:
            self.log("store", f"入库失败 {item.get('url')}: {e}", "error")

    def reset_new_marks(self) -> None:
        """同一任务重跑时先清掉上一轮的新增标记，避免旧标记留到本轮"""
        try:
            store.clear_new(self.task_id)
        except Exception as e:
            self.log("store", f"清理新增标记失败: {e}", "warn")

    def _root(self, target: str) -> str:
        return root_domain(target) or target

    def claim_root(self, domain: str, owner: str = "") -> bool:
        """把一个根域登记成自家资产。只认有来源的根：域名目标、实体扩线、股权子公司、
        小程序包、被动源里挂在本目标下的子域。解析出来的裸 IP、IP 反查顺带捞到的
        别的站，不许走这里。"""
        if not domain or is_ip(domain):
            return False
        r = self._root(domain)
        if not r or is_ip(r):
            return False
        r = r.lower()
        self.own_roots.add(r)
        if owner and not self.root_owner.get(r):
            self.root_owner[r] = owner
        return True

    def _own_roots(self) -> set[str]:
        """本任务已认定的自家根域。判第三方时放行，免得自家根被误砍。

        来源只有 `claim_root` 登记过的；`self.domains` 里混进来的别人的根不算自家。
        """
        return set(self.own_roots)

    def _in_scope(self, host: str) -> bool:
        """这个主机是否算本任务的自家资产（自家根域下的子域，或裸 IP）。

        C 段里别人的站、IP 反查带出来的旁站、合作方域名都要写进来时先过这一道，
        否则任务资产表里会混进一堆和本目标无关的主机。
        """
        return ownership.in_scope(host, self._own_roots())

    def keep_domain(self, host: str) -> bool:
        """域名兜底闸：文件名误判、平台/CDN、搜索引擎自身一律不进自家资产表。"""
        if not host:
            return False
        if is_ip(host):
            return True
        return not ownership.is_non_domain(host) and not ownership.is_foreign(host, self._own_roots())

    def opt(self, key: str, default=None):
        if key in self.options and self.options[key] is not None:
            return self.options[key]
        return config.get("scan", key, default=default)

    def opt_scan_local_mini(self):
        """扫本机微信小程序缓存：开关 + 上限，认配置里的 mobile 段。"""
        if not self.opt("scan_local_mini", True):
            return 0
        try:
            return max(0, min(int(self.opt("scan_local_mini_limit", 20)), 100))
        except Exception:
            return 20

    def opt_equity_ratio(self):
        """控股门槛：任务里选的那一档优先，没选才回落到配置默认值。"""
        return self.opt("equity_ratio", 100)

    def _step_on(self, key: str) -> bool:
        """一键全收集的步骤勾选：p1 主体 / p2 域名 / p3 测绘 / p4 探测 / p5 深挖。

        options["steps"] 缺省或为空 = 五步全开；单阶段重跑（only_stages）不走这里。
        """
        picked = self.options.get("steps")
        if not picked:
            return True
        if isinstance(picked, str):
            picked = [picked]
        return key in {str(p) for p in picked}

    def sub_on(self, stage: str, key: str) -> bool:
        """阶段内的细分项要不要跑。

        ``options["only_modules"]`` 用「阶段:子项」编码（如 ``deep:nuclei``）。
        这一段一个子项都没写就整段照跑，保证老调用与「重跑整段」行为不变。
        """
        picked = self.options.get("only_modules") or []
        if isinstance(picked, str):
            picked = [picked]
        picked = {str(p).strip() for p in picked if str(p).strip()}
        marker = stage + ":"
        if not any(p.startswith(marker) for p in picked):
            return True
        return marker + key in picked

    def scope_targets(self) -> list[str]:
        """本次只重测哪些 host / IP；空 = 不设范围。"""
        raw = self.options.get("scope_targets") or []
        if isinstance(raw, str):
            raw = raw.replace(",", " ").replace("，", " ").split()
        out: list[str] = []
        for item in raw:
            v = str(item or "").strip().lower()
            v = v.split("://")[-1].split("/")[0].split(":")[0].strip(".")
            if v and v not in out:
                out.append(v)
        return out

    def in_scope(self, value: str) -> bool:
        """这个 host / IP 在不在本次重测范围里。没设范围时一律算在。"""
        cached = getattr(self, "_scope_cache", None)
        if cached is None:
            cached = self.scope_targets()
            self._scope_cache = cached
            nets = []
            for t in cached:
                if "/" in t:
                    try:
                        nets.append(ipaddress.ip_network(t, strict=False))
                    except ValueError:
                        pass
            self._scope_nets = nets
        if not cached:
            return True
        v = str(value or "").strip().lower().strip(".")
        v = v.split("://")[-1].split("/")[0].split(":")[0].strip(".")
        if not v:
            return False
        if v in cached:
            return True
        if is_ip(v):
            for net in getattr(self, "_scope_nets", []):
                try:
                    if ipaddress.ip_address(v) in net:
                        return True
                except ValueError:
                    pass
        for t in cached:
            if not is_ip(t) and not is_ip(v) and v.endswith("." + t):
                return True
        return False

    def absorb_targets(self, items: list[str]) -> int:
        """把扩展阶段新捞到的域名 / IP 并进本轮目标，返回真正新增的条数。"""
        from ..utils import is_ip, is_valid_domain

        added = 0
        for raw in items or []:
            d = (raw or "").strip().lower().strip(".")
            if not d:
                continue
            host = d.split("://")[-1].split("/")[0].split(":")[0]
            if not (is_ip(host) or is_valid_domain(host)):
                continue
            if host in self.targets:
                continue
            self.targets.append(host)
            added += 1
        if added:
            self.log("target", f"扩展带回 {added} 个新目标，已并入本轮")
        return added

    async def _run_expand(self) -> None:
        """一键收集的前置展开放在任务里跑：接口先回任务号，扩展结果边跑边入库。"""
        from .pipeline import oneclick_expand as hook

        if not hook:
            return
        self.progress("expand", 3, "主体 / 应用扩展")
        await hook(self.task_id, self, dict(self.expand_plan or {}))
        self.progress("expand", 100, "主体 / 应用扩展完成")

    # ───────── 单阶段重跑 ─────────
    async def _seed_state(self, parsed: dict) -> None:
        """按上个阶段的成果把资产池填回来。

        单阶段重跑不会再走前序阶段，池子是空的；不填的话重跑「存活探测」等于空扫。
        域名、解析关系、自家根域都从本任务已入库的资产还原，IP 目标并进 parsed。
        options["seed_task"] 指定别的任务时从那个任务回填 —— 单项测试新建的任务本身是空的。
        """
        seed_id = str(self.options.get("seed_task") or self.task_id)
        rows = store.query_assets(task_id=seed_id, limit=200000)
        ips: set[str] = set(parsed.setdefault("ips", []))
        dropped: set[str] = set()
        out_scope = 0
        for r in rows:
            kind = str(r.get("kind") or "")
            host = str(r.get("host") or "").strip().lower()
            ip = str(r.get("ip") or "").strip().lower()
            col_ips = [x.strip().lower() for x in str(r.get("ips") or "").split(",") if x.strip()]
            url = str(r.get("url") or "")
            name = host if host and not is_ip(host) else (host_of(url) or "")
            # 老任务里的 host 有「mi.中国」这类中文域名：转 punycode 才能查；
            # 转完仍不是域名的（``enterprise``、``icp`` 这种 kind 误当 host），丢掉。
            if name and not is_ip(name):
                name = idn_ascii(name)
                if not is_valid_domain(name):
                    dropped.add(name)
                    name = ""
            # 只重测指定 host / IP 时，回填也得圈住：不然范围外的一起被扫一遍
            if not self.in_scope(name or ip or host):
                out_scope += 1
                continue
            if name and name not in self.domains and self.keep_domain(name):
                self.domains.add(name)
                root = str(r.get("root_domain") or "").strip().lower() or self._root(name)
                if root and not is_ip(root):
                    self.claim_root(root, "历史资产")
                if ip and is_ip(ip):
                    self.ips.setdefault(name, set()).add(ip)
                if col_ips:
                    self.ips.setdefault(name, set()).update(i for i in col_ips if is_ip(i))
            if kind == "ip" and host and is_ip(host):
                ips.add(host)
                self.ips.setdefault(host, set()).add(host)
            for i in ([ip] if ip and is_ip(ip) else []) + col_ips:
                if kind in ("ip", "site", "service", "port", "cidr") and is_ip(i):
                    ips.add(i)
        base = set(parsed.get("ips") or [])
        parsed["ips"] = sorted(ips)
        parsed.setdefault("domains", sorted(d for d in self.domains if not is_ip(d)))
        parsed.setdefault("cidrs", [])
        self.log("task", f"单阶段执行：按{'指定任务' if seed_id != self.task_id else '历史'}资产回填域名 "
                         f"{len(self.domains)} 个 / IP {len(parsed['ips'])} 个"
                         f"（其中新补 {len(set(parsed['ips']) - base)} 个）")
        if dropped:
            self.log("task", f"{len(dropped)} 个历史 host 不是可查域名已跳过："
                             f"{'、'.join(sorted(dropped)[:4])}", "warn")
        if out_scope:
            self.log("task", f"按本次选定的重测范围过滤掉 {out_scope} 条范围外资产")

    async def _run_only(self, parsed: dict) -> None:
        """只跑选中的阶段，顺序仍按 PHASES，跳过的阶段不推进整体进度。"""
        # PHASES 元组是（分组号, 阶段键, 中文名），阶段键在第二位
        picked = [k for _, k, _ in PHASES if k in self.only_stages]
        skip = [k for k in self.only_stages if k not in STAGE_CALL]
        if skip:
            self.log("task", "这些阶段不单独重跑，已忽略：" + "、".join(PHASE_LABEL.get(k, k) for k in skip),
                     "warn")
        if not picked:
            raise ValueError("没有可重跑的阶段：" + "、".join(self.only_stages))
        self.log("task", "本轮只跑：" + "、".join(PHASE_LABEL.get(k, k) for k in picked))
        for key in picked:
            if self.stop_event.is_set():
                raise asyncio.CancelledError
            await self._guard(key, STAGE_CALL[key](self, parsed), PHASE_LABEL.get(key, key))

    async def _run_full(self, parsed: dict) -> None:
        """整条流水线：目标归一之后依次扩面、探测、收尾。

        一键全收集允许只勾其中几步（options["steps"]）：五步全开时行为和以前完全一致，
        少勾的步骤整组跳过，报告汇总与快照比对始终执行。
        """
        picked = [k for k in ONECLICK_STEPS if self._step_on(k)] or list(ONECLICK_STEPS)
        skipped = [STEP_LABELS[k] for k in ONECLICK_STEPS if k not in picked]
        if skipped:
            self.log("task", f"本次只跑 {len(picked)} 步，跳过：{'、'.join(skipped)}")
        do = set(picked)

        equity_task: asyncio.Task | None = None
        roots_before: set[str] = set()
        try:
            if "p1" in do:
                if getattr(self, "expand_plan", None):
                    await self._guard("enterprise", self._run_expand(), "主体扩线")
                    # 扩线后重跑一次目标归一：按 target_parse 开窗，新主体的资产别落到扩线上
                    self._stage_enter("target_parse")
                    try:
                        parsed = await self.p0_parse()
                    finally:
                        self._stage_exit("target_parse")
                if parsed["domains"] and self.opt("enterprise", True):
                    await self._guard("enterprise", self.p1_enterprise(parsed["domains"]), "主体穿透")
                # 股权穿透按 30 秒一次往下穿，一个省公司级主体要穿一个多小时。以前它串在
                # 被动收集前面，域名 / 端口 / web 全被堵在身后，现场就是「主体收集完就没了」。
                # 现在放后台并发：p2/p3/p4 立刻用已认根域开工，收尾前再等它并补跑新根域。
                if self.opt("equity_expand", True) or self.options.get("equity"):
                    roots_before = {self._root(d) for d in self.domains if not is_ip(d)}
                    equity_task = asyncio.create_task(self._equity_async(parsed))
                    self.log("equity", "股权穿透转后台并发：被动子域 / 端口 / 网页先用已认根域开工，"
                                       "穿出来的全资子公司收尾时补跑")
                if self.opt("mobile", True):
                    await self._guard("mobile", self.p1b_mobile(parsed), "移动端扩线")
            # 股权穿透与移动端扩线都会往 self.domains 里加新根域，被动收集吃合并后的全集
            seeds = list(parsed["domains"]) + [d for d in self.domains if d not in parsed["domains"]]
            if not seeds:
                # 没有根域时后面几步都是空转：日志里只有「阶段完成」，资产一行不出。
                # 这里点名原因，省得把「主体没出域名」当成「端口 / web 采集坏了」去查。
                self.log("task", "没有任何可收集的根域：主体扩线 / 备案 / 股权三路都没出域名，"
                                 "被动子域、字典爆破、DNS / 端口 / 网页无从开始；"
                                 "请核对主体全称、渠道登录态，或调大「单主体时限」", "error")
            if seeds:
                if "p2" in do:
                    await self._guard("passive", self.p2_passive(seeds), "被动收集")
                    if self.opt("domain_brute", True):
                        await self._guard("brute", self.p3_brute(seeds), "字典爆破")
                    else:
                        # 关掉爆破是个合法选择，但界面上少了一整个阶段且一条日志都没有，
                        # 复盘时看不出「域名少」是被自己的开关砍的。
                        self.log("brute", "字典爆破未启用（domain_brute=false），本轮不做子域爆破", "warn")
                if "p3" in do:
                    # 测绘吃上游已确认根域（p2 新收的也在 seeds 里），口径见 p2a_space
                    await self._guard("space", self.p2a_space(seeds), "空间测绘")
            if "p4" in do:
                await self._guard("dns", self.p4_dns(parsed), "DNS 解析")
                await self._guard("port", self.p5_port(parsed), "端口扫描")
                await self._guard("web", self.p6_web(parsed), "存活探测")
            if "p5" in do:
                if self.opt("site_spider", True):
                    await self._guard("crawl", self.p7_crawl(), "站点爬虫")
                if self.opt("file_leak", True):
                    await self._guard("leak", self.p8_leak(), "敏感文件")
                if self.opt("vhost_collision", False):
                    await self._guard("vhost", self.p9_vhost(), "VHost 碰撞")
                if self.opt("takeover", True):
                    await self._guard("takeover", self.p9a_takeover(), "子域接管")
                if self.opt("sibling", True):
                    await self._guard("sibling", self.p10_sibling(parsed), "旁站/C 段")
                if self.opt("deep", True):
                    await self._guard("deep", self.p11_deep(), "深度挖掘")
            # 收尾前等股权穿透收口：它并进来的根域没赶上前面几轮被动 / 解析 / 探测，这里补齐
            if equity_task is not None:
                await self._join_equity(equity_task)
                await self._backfill_late(parsed, roots_before, do)
            await self._guard("assetdiff", self.p12_assetdiff(parsed), "资产变更对比")
            await self._guard("report", self.p13_report(), "汇总报告")
        finally:
            if equity_task is not None and not equity_task.done():
                equity_task.cancel()
                # 停止 / 异常路径上等它落地再收尾：不然它会在任务已标结束之后继续写资产
                try:
                    await asyncio.wait({equity_task}, timeout=10)
                except Exception:
                    pass

    async def _equity_async(self, parsed: dict) -> None:
        """后台跑股权穿透。

        不借 `_guard`：那条路要切 `current_phase`，前台正在跑被动收集 / 端口扫描，
        切过去会把前台资产的阶段归属改掉。阶段时间窗单独落两条，资产归属走
        `ASSET_PHASE`（contextvar 按任务隔离）。
        """
        token = ASSET_PHASE.set("equity")
        try:
            store.record_phase(self.task_id, "equity", time.time())
        except Exception:
            pass
        try:
            await self.p1c_equity(parsed)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            msg = f"股权穿透 异常：{type(e).__name__}: {e}"
            self.stage_errors.append(msg)
            self.stats["stage_errors"] = len(self.stage_errors)
            self.log("equity", msg + "（已跳过该阶段，后续阶段继续跑）", "error")
            try:
                store.update_task(self.task_id, stats=dict(self.stats))
            except Exception:
                pass
        finally:
            try:
                store.record_phase(self.task_id, "equity", time.time())
            except Exception:
                pass
            ASSET_PHASE.reset(token)

    async def _join_equity(self, task: asyncio.Task) -> None:
        """收尾前等后台股权穿透跑完，等的时候每分钟说一句，别让界面像卡死。"""
        if task.done():
            task.result()
            return
        try:
            wait_cap = float(self.opt("equity_join_wait", 0) or 0)
        except (TypeError, ValueError):
            wait_cap = 0.0
        self.log("task", "等待后台股权穿透收口（延时照旧；域名 / 端口 / 网页已先出）")
        started = time.time()
        minutes = 0

        def _waiting_msg(extra: str = "") -> str:
            # 这一段能等几十分钟，只写日志不改 message，界面上就是「88% + 一句旧提示」
            # 定住不动，看着像卡死。每分钟把已等时长 / 已并进域数写回任务，进度条不动
            # 但文案在走，人知道是在等穿透而不是挂了。
            base = (f"等待后台股权穿透收口（已等 {minutes} 分钟，已并进 "
                    f"{len(self.domains)} 个域）；其余阶段已完成，穿完自动收尾")
            return base + extra

        try:
            store.update_task(self.task_id, message=_waiting_msg())
        except Exception:
            pass
        while not task.done():
            await asyncio.wait({task}, timeout=60)
            if task.done():
                break
            minutes += 1
            msg = _waiting_msg()
            self.log("equity", msg)
            try:
                store.update_task(self.task_id, message=msg)
            except Exception:
                pass
            if wait_cap > 0 and time.time() - started >= wait_cap:
                # 到点截断必须说清是被「等时上限」砍的，而不是渠道耗尽或这家没子公司，
                # 否则下一次看到的只是「股权穿透比上次少」，排查方向全错。
                task.cancel()
                try:
                    await asyncio.wait({task}, timeout=10)
                except Exception:
                    pass
                msg = (f"股权穿透等待已达上限 {int(wait_cap)} 秒，本轮收口"
                       f"（已并进 {len(self.domains)} 个域）；要穿完请调大 equity_join_wait"
                       f" 或单阶段重跑股权穿透")
                self.log("equity", msg, "warn")
                self.stage_errors.append(msg)
                self.stats["stage_errors"] = len(self.stage_errors)
                try:
                    from .. import source_health as _health
                    _health.record(store, self.task_id, "equity", "cap:join", "partial",
                                   note=msg[:300], items=0)
                except Exception:
                    pass
                return
        task.result()

    async def _backfill_late(self, parsed: dict, roots_before: set[str], do: set[str]) -> None:
        """股权穿透后台新并进来的根域，补跑一遍域名收集与探测。

        p2 / p4 开跑时这些全资子公司还没穿出来，不补这一段，任务页上就会是
        「股权穿透画得挺满、域名 / 端口 / web 资产只有母公司那几条」。
        """
        now_roots = {self._root(d) for d in self.domains if not is_ip(d)}
        late = sorted(r for r in now_roots - roots_before if r)
        if not late:
            return
        head = "、".join(late[:8]) + (" 等" if len(late) > 8 else "")
        self.log("task", f"股权穿透新并进 {len(late)} 个根域，补跑域名 / 端口 / 网页：{head}")
        if "p2" in do:
            await self._guard("passive", self.p2_passive(late), "补跑被动收集")
            if self.opt("domain_brute", True):
                await self._guard("brute", self.p3_brute(late), "补跑字典爆破")
        if "p4" in do:
            await self._guard("dns", self.p4_dns(parsed), "补跑 DNS 解析")
            await self._guard("port", self.p5_port(parsed), "补跑端口扫描")
            await self._guard("web", self.p6_web(parsed), "补跑存活探测")

    # ───────── 主流程 ─────────
    async def run(self) -> None:
        store.update_task(self.task_id, status="running", message="开始执行")
        # 第一行日志放最前面：清新增标记、起 DNS 长连接、主体扩线这几步都可能静默几分钟，
        # 少了这一行，任务看着就是「进度 0、零日志」，分不清是排队、卡住还是已经跑完。
        brief = "、".join(str(t) for t in self.targets[:6]) or "无目标"
        more = f" 等 {len(self.targets)} 个目标" if len(self.targets) > 6 else ""
        if self.only_stages:
            names = dict((k, v) for _, k, v in PHASES)
            pick = "只跑 " + "、".join(names.get(s, s) for s in self.only_stages)
        else:
            pick = "全流程"
        self.log("task", f"任务开始：{brief}{more} · {pick}")
        self.reset_new_marks()
        try:
            await asyncio.wait_for(self.dns.start(), 30)
        except asyncio.TimeoutError:
            self.log("dns", "DNS 长连接 30s 未就绪，降级单次查询", "warn")
        except Exception as e:
            self.log("dns", f"DNS 长连接初始化失败，降级单次查询: {e}", "warn")
        try:
            self._stage_enter("target_parse")
            try:
                parsed = await self._until_stop(self.p0_parse(), "目标解析与主体扩线")
            finally:
                self._stage_exit("target_parse")
            if self.stop_event.is_set():
                raise asyncio.CancelledError
            if self.only_stages:
                await self._seed_state(parsed)
                await self._until_stop(self._run_only(parsed), "本轮选中的阶段")
                if self.stage_errors:
                    # 单阶段重跑只有一个阶段：跳过它就等于什么都没做，仍按失败报出来
                    raise RuntimeError(self.stage_errors[0])
            else:
                await self._until_stop(self._run_full(parsed), "本轮剩余阶段")
            status = "stopped" if self.stop_event.is_set() else "done"
            note = "任务完成" if status == "done" else "任务已停止"
            if status == "done" and self.stage_errors:
                note = f"任务完成（{len(self.stage_errors)} 个阶段异常，详见日志）"
                self.log("task", f"{len(self.stage_errors)} 个阶段异常，其余阶段已完成："
                                 + "；".join(self.stage_errors[:6]), "warn")
            store.update_task(self.task_id, status=status,
                              progress=100, message=note,
                              stats=dict(self.stats))
            self.log("task", "任务完成")
            if status == "done":
                try:
                    from ..notify import notify_task_done

                    await notify_task_done(self.task_id, store.get_task(self.task_id) or {},
                                           dict(self.stats))
                except Exception as e:
                    self.log("notify", f"通知失败: {e}", "warn")
        except asyncio.CancelledError:
            store.update_task(self.task_id, status="stopped", message="任务已停止")
            self.log("task", "任务已停止")
        except Exception as e:
            self.log("task", f"任务异常: {e}\n{traceback.format_exc()}", "error")
            store.update_task(self.task_id, status="error", message=f"任务异常: {e}")
        finally:
            self.dns.close()
            try:
                from ..db import audit

                audit("task_finish", self.task_id, f"阶段 {self.current_phase}")
            except Exception:
                pass


async def start_task(targets: list[str], options: dict, name: str = "",
                     schedule_id: str = "", expand: dict | None = None) -> str:
    # 阶段键先对齐成真实阶段再落库：认不出的键会被 executor 当成空选择而整条流程跑，
    # 而列表却照原始键标「局部任务」，于是出现「说只跑主体、实际五段都跑了」。
    options = dict(options or {})
    if options.get("only_stages"):
        picked = expand_stages(options["only_stages"], bool(options.get("with_deps")))
        if picked:
            options["only_stages"] = picked
        else:
            options.pop("only_stages", None)
            options.pop("with_deps", None)
    task_id = uuid.uuid4().hex[:16]
    store.create_task(task_id, name or f"任务-{time.strftime('%m%d-%H%M')}",
                      ",".join(targets), targets, options, schedule_id=schedule_id)
    runner = TaskRunner(task_id, targets, options)
    runner.expand_plan = expand or {}
    RUNNING[task_id] = runner
    store.update_task(task_id, status="running", message="已加入执行队列")

    async def _wrap():
        try:
            await runner.run()
        finally:
            RUNNING.pop(task_id, None)

    asyncio.create_task(_wrap())
    return task_id


def stop_task(task_id: str) -> bool:
    runner = RUNNING.get(task_id)
    if not runner:
        store.update_task(task_id, status="stopped", message="任务未在运行（已标记停止）")
        return False
    runner.stop_event.set()
    store.update_task(task_id, status="stopping", message="正在停止…")
    return True


def _unused(*args):
    return is_ip, Counter
