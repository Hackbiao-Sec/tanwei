"""流水线各阶段实现。

TaskRunner 在 pipeline.py，本文件只放阶段方法（mixin），便于单测与阅读。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import Counter
from urllib.parse import urlparse

from ..config import DATA_DIR, config, llm_engine
from ..db import store
from ..utils import (CdnDetector, host_of, is_ip, is_ip_network, is_public_ip, is_valid_domain,
                     normalize_url, port_of, root_domain, same_site)
from .collectors import active, deep, enterprise, mobile
from .collectors import apkstatic
from .collectors import asnmap
from .collectors import applet as applet_mod
from .collectors import credential as cred
from .collectors import equity
from .collectors import mp as mp_mod
from .collectors import identify as comp_identify
from .collectors import probe as comp
from .collectors import svcmap
from .collectors import weibo as weibo_mod
from .collectors import wxscan
from .collectors.probe import PORT_SCOPED
from . import beauty, handshake
from . import naming
from . import asset_rows
from . import channels as channels_mod
from . import dedupe
from . import source_health
from . import space as space_mod
from .throttle import throttle
from .http_engine import HttpInfo, block_kind, fetch_text, is_error_page, probe, probe_alt

# 裸 IP 直接回的这些状态码表示「请求格式/方法不对」，页面本身没有业务内容：
# 400 纯 HTTP 到 HTTPS 端口、410 已下线、412 前置条件失败，都是端口活着而站点不在。
_BARE_IP_DEAD_STATUS = frozenset({400, 405, 408, 410, 411, 412, 413, 414, 415, 431, 501, 505})

# 子域接管：(CNAME 后缀, 未认领页特征串, 服务名)。后缀以 . 开头表示按包含匹配，
# 用于 s3-website / oss-cn- 这类中间段固定、区域可变的托管域名。
TAKEOVER_SIGNS: tuple[tuple[str, str, str], ...] = (
    ("github.io", "there isn't a github pages site here", "GitHub Pages"),
    ("github.com", "there isn't a github pages site here", "GitHub Pages"),
    ("herokuapp.com", "no such app", "Heroku"),
    ("herokudns.com", "no such app", "Heroku"),
    ("s3.amazonaws.com", "nosuchbucket", "Amazon S3"),
    (".s3-website", "nosuchbucket", "Amazon S3"),
    ("s3.dualstack", "nosuchbucket", "Amazon S3"),
    ("azurewebsites.net", "error 404 - web app not found", "Azure 应用服务"),
    ("cloudapp.azure.com", "error 404 - web app not found", "Azure 应用服务"),
    ("blob.core.windows.net", "blobnotfound", "Azure Blob"),
    ("trafficmanager.net", "error 404 - web app not found", "Azure 应用服务"),
    ("netlify.app", "not found - request id", "Netlify"),
    ("netlify.com", "not found - request id", "Netlify"),
    ("vercel.app", "the deployment could not be found", "Vercel"),
    ("vercel-dns.com", "the deployment could not be found", "Vercel"),
    ("now.sh", "the deployment could not be found", "Vercel"),
    ("fastly.net", "fastly error: unknown domain", "Fastly"),
    ("fastlylb.net", "fastly error: unknown domain", "Fastly"),
    ("statuspage.io", "there is no page configured", "Statuspage"),
    ("readthedocs.io", "unknown to read the docs", "Read the Docs"),
    ("readthedocs.org", "unknown to read the docs", "Read the Docs"),
    ("zendesk.com", "help center closed", "Zendesk"),
    ("tumblr.com", "there's nothing here", "Tumblr"),
    ("bitbucket.io", "repository not found", "Bitbucket"),
    ("wpengine.com", "this site is not currently available", "WP Engine"),
    ("pantheonsite.io", "the gods are wise", "Pantheon"),
    ("ghost.io", "domain not configured", "Ghost"),
    ("surge.sh", "project not found", "Surge"),
    ("myshopify.com", "only one step left", "Shopify"),
    ("webflow.io", "this site is not published", "Webflow"),
    ("freshdesk.com", "there is no helpdesk here", "Freshdesk"),
    ("ngrok.io", "tunnel not found", "ngrok"),
    (".oss-cn-", "nosuchbucket", "对象存储"),
    (".cos.ap-", "nosuchbucket", "对象存储"),
    (".obs.", "nosuchbucket", "对象存储"),
)

# 长后缀优先，避免 "s3.amazonaws.com" 被更短的规则抢走
_TAKEOVER_BY_LEN = tuple(sorted(TAKEOVER_SIGNS, key=lambda x: -len(x[0])))


def _takeover_service(cname: str) -> str:
    """CNAME 落在哪家可认领的托管服务上；不是托管域名返回空串。"""
    c = (cname or "").strip().lower().rstrip(".")
    if not c:
        return ""
    for suffix, _marker, name in _TAKEOVER_BY_LEN:
        if suffix.startswith("."):
            if suffix in c:
                return name
        elif c == suffix or c.endswith("." + suffix):
            return name
    return ""


def _takeover_markers(service: str) -> list[str]:
    out: list[str] = []
    for _s, m, name in TAKEOVER_SIGNS:
        if name == service and m not in out:
            out.append(m)
    return out


def _is_proxy_page(info) -> bool:
    """本机抓包代理 / 网关自己的占位页：标题与正文都不是目标站的。"""
    t = (getattr(info, "title", "") or "").lower()
    if "yakit" in t or "mitmproxy" in t or "fiddler" in t:
        return True
    body = (getattr(info, "body", "") or "")[:2000]
    return "yakit mitm" in body.lower()


def _need_alt_exit(info) -> bool:
    """直连结果是否值得换出口重试：连不上，或者拿到的是代理占位页。"""
    if not info:
        return False
    if getattr(info, "alt_exit", False):
        return False
    if not getattr(info, "status", 0):
        return True
    why = block_kind(info, info.body)
    return _is_proxy_page(info) or why.startswith(("防护/代理页", "网关占位页"))
from .portscan import (PORT_PRESET_LABELS, RateLimiter, ScanCheckpoint, WEB_PORTS, effective_ports,
                       filter_ips, parse_ip_ranges, scan_port)

TCP_PROBE_PORTS = {int(p) for p in PORT_SCOPED}
from .sources import passive

MAX_PROBE_DEFAULT = 3000   # 单任务存活探测上限（防 2 万子域 ×2 scheme 打爆目标）
# 备用出口重试的全任务预算。直连打不开的站每个都要吃掉一整轮超时，放开跑时
# 一个 10 IP × 99 端口的任务会卡在存活探测里几十分钟，后面的爬虫/JS/报告阶段全不跑。
ALT_EXIT_BUDGET = 12
ALT_EXIT_TIMEOUT = 8.0
PORT_CKPT_NAME = "port_checkpoint.txt"
# 邮件协议端口：MX 服务商服务器上这些端口开放属服务商正常设施，不算本任务资产
MAIL_PROTO_PORTS = {25, 110, 143, 465, 587, 993, 995}

# 托管商的通用登录入口：挂在客户域名下，但页面和接口都是服务商的产品。
# 认这些只为把「服务商的登录页」从客户业务站里摘出去，不针对某一家产品。
VENDOR_LOGIN_RE = re.compile(r"企业邮箱|邮件系统|mail\s*(?:login|system)|webmail|"
                             r"统一身份认证", re.I)
VENDOR_LOGIN_HOSTS = {"mail", "webmail", "email", "smtp", "pop", "imap", "exmail"}


def _name_affinity(root: str, host: str) -> float:
    """同名相似度：共用 IP 反查出来的站里，判断它像不像本目标的兄弟站。

    取最长公共子串长度 / 较短标签长度，`a.example.com` 与 `example` 系
    `admin.example.com` 这种共同段能拿到高分，`15dy.com` 与 `example.com` 拿不到。
    """
    a = (root or "").split(".")[0].lower()
    host = (host or "").lower()
    # 本身就挂在本根域下（如 www.<中文 IDN>）不用比标签：它的第一段是 www，
    # 标签比对会算出 0 分被当垃圾丢掉。先按后缀认亲。
    if root and (host == root or host.endswith("." + root.lower())):
        return 1.0
    b = host.split(".")[0].lower()
    if not a or not b:
        return 0.0
    if a in b or b in a:
        return 1.0
    best = 0
    for i in range(len(a)):
        for j in range(i + best + 1, len(a) + 1):
            if a[i:j] in b:
                best = max(best, j - i)
    return best / max(1, min(len(a), len(b)))



def _usable_subject_name(text: str) -> bool:
    """检索词能不能当「企业主体 / 应用名」去查工商、股权、应用商店。

    实体里的 `brand` 是 `_brand()` 从域名切出来的，`xiaomi.com` 会切出 `om`、`mi` 这种
    两三个字母的残渣。拿它去查股权和应用商店只会白跑一轮，日志里还会刷出「om: 全资 0 家」
    这种看不懂的行。这里统一收口：域名/IP 不算，纯拉丁短词不算。
    """
    text = (text or "").strip()
    if not text or _looks_like_domain(text):
        return False
    # 长度只卡拉丁词：中文两个字的品牌很常见（`小米`、`华为`），拉丁一两个字母必然是切偏的。
    if re.fullmatch(r"[A-Za-z0-9\-]+", text) and len(text) < 3:
        return False
    return True


def _looks_like_domain(text: str) -> bool:
    """判断检索词是不是域名/IP：应用名和小程序名不会长这样，拿它去搜商店必然是 0 结果。"""
    text = (text or "").strip().strip(".")
    if not text or " " in text:
        return False
    if is_ip(text):
        return True
    # 至少要有个能看的标签：`.com` 这种根域实体被截断的残渣不能当检索词
    if "." not in text or not root_domain(text):
        return False
    return host_of(text) is not None


def _is_full_company(text: str) -> bool:
    """工商全称形态（`XX 有限（责任）公司` / `XX 集团有限公司`）。

    这类词只适合查工商与备案，拿去搜应用商店和小程序名基本一条不中，
    而每查一次要等好几跳网络。简称（品牌）才是这两条面的检索词。
    """
    return bool(re.search(r"(?:有限责任公司|股份有限公司|有限公司|集团|工作室|研究院)$",
                          (text or "").strip()))


class StagesMixin:
    # 组件识别结果 {站点: [组件键…]}；p11_deep 里赋值，关闭识别时保持为空
    sites_identified: dict[str, list[str]] = {}

    def _icp_kinds(self) -> tuple:
        """备案类型：任务里选的优先，没选就查站备案 + APP + 小程序。

        APP / 小程序备案没有域名，只有服务名称与备案号；这两类恰恰是主体名下
        移动端资产唯一能按主体精确对上的来源，不查就只能靠搜索引擎猜名字。
        """
        raw = self.opt("icp_kinds", None)
        if isinstance(raw, str):
            raw = [x.strip() for x in raw.replace("，", ",").split(",") if x.strip()]
        kinds = tuple(x for x in (raw or []) if x)
        return kinds or ("site", "app", "mapp")

    def _save_asset_once(self, row: dict) -> bool:
        """同一个资产 url 全任务只计一次数；重复交进来的只刷新内容。

        股权链路会「边穿边交」同一批节点，备案与主体行也在里程碑快照里反复出现。
        以前每交一遍就加一遍统计，任务页的条数会越跑越虚；这里按 url 记账，
        返回 True 表示这次才真正新增。
        """
        seen = getattr(self, "_saved_keys", None)
        if seen is None:
            seen = self._saved_keys = set()
        key = str(row.get("url") or "")
        new = key not in seen
        self.save_asset(row, count=new)
        if new:
            seen.add(key)
        return new

    def _save_icp(self, items, owner: str = "") -> int:
        """备案记录单独入资产库：一条备案一行，资产页的「备案」分面直接可看。

        行怎么拼在 `asset_rows.icp_rows()` 里，和单项直跑共用一份口径。
        """
        rows = asset_rows.icp_rows(items, owner)
        return sum(1 for row in rows if self._save_asset_once(row))

    def _save_equity_detail(self, name: str, detail) -> int:
        """主体阶段顺带查到的股权链路摊成资产：控股 / 投资 / 股东 / 分支 / 备案 / 软著。

        `p0_parse`、`p1_enterprise` 查主体时已经跑过一遍股权穿透，链路就在
        `ent["equity_detail"]` 里。以前只把达标子公司名捞走、链路整份丢掉，任务资产
        只剩备案那几条，`kind=equity` 一行都没有，任务页的股权穿透图也跟着空白。

        穿透是当场边穿边交的（同一批节点会交好几遍、每遍都比上一遍长），所以这里按
        资产 url 记账：重来的键只刷新内容，不重复计数，返回的是本轮真正新增的条数。
        """
        if not isinstance(detail, dict) or not detail.get("chain"):
            return 0
        nm = str(detail.get("name") or name or "").strip()
        if not nm:
            return 0
        try:
            ratio = float(detail.get("ratio") or self.opt("equity_ratio", 100) or 100)
        except (TypeError, ValueError):
            ratio = 100.0
        rows = asset_rows.equity_rows(nm, detail, ratio)
        fresh = 0
        for row in rows:
            if self._save_asset_once(row):
                fresh += 1
        return fresh

    def _entity_part_taker(self, company: str, got: dict):
        """主体采集器的途中快照接成「边收边入库」。

        以前这里只是 ``got.update(snap)``：整段跑完、或者硬时限把人掐掉之后才去看这份
        快照。股权穿透逐层穿子公司一动就是十几分钟，跑的过程中任务资产一直是空的，
        界面上只看得到日志在滚（「翻到第 2 层 51%」），资产列表还是那几条。
        现在每收到一份就落一次：备案、主体行、股权链路。重复交来的按 url 刷新。
        """
        def _take(snap) -> None:
            if not isinstance(snap, dict):
                return
            got.update(snap)
            nm = str(snap.get("name") or company or "").strip() or company
            try:
                self._save_icp(snap.get("icp"), nm)
                if snap.get("name") or snap.get("domains") or snap.get("icp"):
                    # 快照里的链路单独摊成 equity / holds / invest 等行，别整份塞进主体行：
                    # 主体行每 8 秒刷新一次，塞进去等于把同一份大 JSON 反复写库。
                    self._save_asset_once({
                        "kind": "enterprise", "url": f"enterprise:{company}",
                        "title": snap.get("name") or company,
                        "extra": {k: v for k, v in snap.items() if k != "equity_detail"},
                        "sources": "enterprise",
                    })
                self._save_equity_detail(nm, snap.get("equity_detail"))
            except Exception as e:
                self.log("enterprise", f"{company} 快照入库失败: {e}", "warn")
        return _take

    def _ent_log(self, mod: str = "enterprise"):
        """把采集器内部的逐路回报接到任务日志上：哪一路回来就落一行，前端能实时看到。"""
        return lambda msg, level="info": self.log(mod, msg, level)

    def _deep_flag(self, key: str, default=False):
        """深度类开关：单项执行里显式设了就用它，没设回落配置 `deep` 段。"""
        v = self.opt(key, None)
        if v is not None:
            return v
        return config.get("deep", key, default=default)

    async def _bounded(self, coro, seconds: float, *, tag: str, log_mod: str = "task",
                       stage: str = "", partial=None):
        """给一路外部采集套硬时限：某一路卡住不能拖死整条流水线。

        超时不算失败——采集器已经把中途状态写进模块级 `LAST_STATUS`，这里照常
        记进渠道面板，用户看到的是「哪一路超时」而不是一个永远转圈的任务。
        """
        t0 = time.monotonic()
        limit = max(1.0, float(seconds))

        async def tick() -> None:
            # 主体扩线、股权穿透单跑就是几分钟，只在开头结尾各留一行，看板上像卡死。
            # 每 30 秒报一次还在跑，人一眼能看出是慢不是停。
            while True:
                await asyncio.sleep(30)
                self.log(log_mod, f"{tag} 进行中（已 {int(time.monotonic() - t0)}s，"
                                  f"上限 {int(limit)}s）")

        beat = asyncio.create_task(tick())
        try:
            return await asyncio.wait_for(coro, limit)
        except asyncio.TimeoutError:
            # 被掐掉的那一段自己是拿不回结果的：能留下的只有它已经交出来的快照。
            self.log(log_mod, f"{tag} 超过 {int(seconds)}s 未返回，跳过"
                              f"（已交出的中途快照照常入库，这一段没交到的部分不补）", "warn")
            if callable(partial):
                try:
                    st = partial() or {}
                    if st:
                        source_health.record_many(
                            store, self.task_id, stage or log_mod, st,
                            notes={k: f"单次调用未在 {int(seconds)}s 内返回，只记到中途状态"
                                   for k in st})
                    else:
                        # 一路都还没回来：至少留一条超时痕迹，面板上能看出是这一枪卡住
                        source_health.record_many(
                            store, self.task_id, stage or log_mod, {"call": "timeout"},
                            notes={"call": f"{tag} 未在 {int(seconds)}s 内返回"})
                except Exception:
                    pass
            return None
        finally:
            beat.cancel()

    # ───────── P0 目标归一 ─────────
    async def p0_parse(self) -> dict:
        self.progress("target_parse", 10, "解析目标")
        domains, ips, cidrs, companies = [], [], [], []
        for t in self.targets:
            t = (t or "").strip()
            if not t:
                continue
            # 网段与区间：`10.0.0.0/24`、`10.0.0.1-10.0.0.20`、`10.0.0.1-20` 都收，
            # 交给 P4 用同一套展开逻辑处理，避免区间写法被当成企业名去查工商
            if is_ip_network(t) or re.fullmatch(r"[0-9.]+\s*-\s*[0-9.]+", t):
                cidrs.append(t)
                continue
            if is_ip(t):
                ips.append(t)
                continue
            low = t.lower()
            if low.startswith(("http://", "https://")):
                host = host_of(low) or ""
                if is_ip(host):
                    ips.append(host)
                elif host:
                    domains.append(host)
                continue
            if "." in t and " " not in t and host_of(low):
                if is_ip(low):
                    ips.append(low)
                else:
                    domains.append(low)
            else:
                companies.append(t)
        # 企业名 → 域名
        self.entities = []
        # 门槛跟着任务走：一键收集里用户按次选的门槛，不能在这里被配置默认值顶掉
        try:
            ratio = float(self.opt_equity_ratio())
        except Exception:
            ratio = None
        # 企业名扩线是在 P0 里跑的，一段就要几分钟。阶段标签还停在「目标归一」时，
        # 人会以为卡在解析上；这里先把标签换成「企业主体」，和下面真正在干的活对上。
        if companies:
            # 只换界面标签，不写阶段时间戳：这段活本来就跑在 target_parse 窗口里，
            # 再记一条 enterprise 会让两个阶段显示同一段时间。
            self.progress("enterprise", 5, "企业主体", record=False)
        for company in companies:
            if self.only_stages and not self.options.get("ops_expand_entity"):
                # 单阶段重跑只补一个阶段的活：企业名不再查工商，域名从历史资产回填
                self.log("target", f"单阶段重跑不做主体扩线：{company}")
                continue
            try:
                self.log("enterprise", f"开始查主体 {company}（工商 / 备案 / 域名证据）")
                # 采集器按里程碑交快照：这一段的硬时限一到协程就被掐，
                # 已经查到的备案 / 控股子公司 / 移动端主体都在它的局部变量里，
                # 不接这份快照就等于白跑几分钟（现场表现：日志里命中一堆，任务最后 0 资产）。
                got: dict = {}
                cached = (getattr(self, "expand_entities", None) or {}).get(company)
                if isinstance(cached, dict) and cached:
                    # 一键流程的前置展开已经把这家查过一遍了。再跑第二遍，等于把同一份
                    # 工商额度再烧一次；第二遍还常常被硬时限掐在中途，最后落地的东西
                    # 比第一遍更少（现场表现：主体收集像做完了，域名 / 端口 / web 全空）。
                    self.log("enterprise", f"{company} 复用前置展开结果："
                                           f"域名 {len(cached.get('domains') or [])} 个 / "
                                           f"备案 {len(cached.get('icp') or [])} 条")
                    ent = cached
                else:
                    ent = await self._bounded(
                        enterprise.collect_entity(
                            company, equity_ratio=ratio, equity=False,
                            mobile=bool(self.opt("enterprise_mobile", True)),
                            equity_sources=self.opt("equity_sources", None) or None,
                            icp_kinds=self._icp_kinds(),
                            icp_pages=int(self.opt("icp_pages", 2) or 2),
                            icp_size=int(self.opt("icp_size", 40) or 40),
                            icp_retry=int(self.opt("icp_retry", 0) or 0) or None,
                            icp_gap=float(self.opt("icp_gap", 0) or 0) or None,
                            icp_alias=bool(self.opt("icp_alias", True)),
                            icp_force=bool(self.opt("icp_force", False)),
                            icp_api=str(self.opt("enterprise_icp_api", "") or ""),
                            on_log=self._ent_log(),
                            on_partial=self._entity_part_taker(company, got),
                            budget_s=max(30.0, self._entity_timeout() - 20)),
                        self._entity_timeout(),
                        tag=f"主体扩线 {company}", log_mod="enterprise", stage="enterprise",
                        partial=lambda: dict(getattr(enterprise, "LAST_STATUS", {}) or {}))
                if not isinstance(ent, dict):
                    # 超时 / 报错：把快照里已经过完证据闸的部分接着用，别整段丢掉。
                    ent = got or None
                    if isinstance(ent, dict):
                        self.log("enterprise",
                                 f"{company} 按快照入库：备案 {len(ent.get('icp') or [])} 条 / "
                                 f"控股 {len(ent.get('equity') or [])} 家 / "
                                 f"域名 {len(ent.get('domains') or [])} 个", "warn")
                if not isinstance(ent, dict):
                    continue
                ent["input"] = company
                self.entities.append(ent)
                # 主目标的备案先落一份：P1 会按根域重查一次，每条根域只有自己那一腿，
                # 主体名下的全部备案（含公益域、APP、小程序）只有这一次是全的。
                self._save_icp(ent.get("icp"), ent.get("name") or company)
                # 主体本身也要有一行。以前只有按根域那几条 `enterprise:<根域>`，
                # 主体名查出来的确认域 / 待核验域只进了日志，人翻任务资产时看不到
                # 「这家单位到底认下哪些域、哪些因为证据不足被压住了」。
                if ent.get("name") or ent.get("domains") or ent.get("icp"):
                    # 途中快照已经把这一行交过几遍了，整段跑完再交只刷新内容、不再计数
                    self._save_asset_once({
                        "kind": "enterprise", "url": f"enterprise:{company}",
                        "title": ent.get("name") or company,
                        "extra": ent, "sources": "enterprise",
                    })
                detail = ent.get("equity_detail") or {}
                n_eq = self._save_equity_detail(ent.get("name") or company, detail)
                if detail.get("chain"):
                    chain_n = len(detail.get("chain") or [])
                    # full_owned 含本体自己；这里报的是被控股的下游主体家数
                    holds_n = max(0, len(detail.get("full_owned") or []) - 1)
                    tail = f"，收尾补录 {n_eq} 条" if n_eq else "，穿透途中已边穿边入库"
                    self.log("enterprise", f"{company} 股权链路入库 {chain_n} 条"
                                           f"（控股 {holds_n} 家{tail}）")
                domains.extend(ent.get("domains") or [])
                self.log("enterprise", f"{company} → 域名 {len(ent.get('domains') or [])} 个"
                                       f"（来源 {'/'.join(ent.get('sources') or []) or '无'}）")
                if ent.get("domains_pending"):
                    pend = ent["domains_pending"]
                    self.log("enterprise", f"{company} 另有 {len(pend)} 个待核验域没进扫描："
                                           f"{'、'.join(pend[:6])}（证据不足，复核后可单跑企业主体补）",
                             "warn")
            except Exception as e:
                self.log("enterprise", f"主体扩线失败 {company}: {e}", "warn")
        domains = list(dict.fromkeys(d.strip().lower().strip(".") for d in domains if d))
        # 目标归一结果入库。域名目标本身就代表这家单位的资产，直接认作自家根。
        for d in domains:
            self.domains.add(d)
            self.claim_root(d, "目标域名")
        for ip in ips:
            self.domains.add(ip)
        self.stats["targets"] = len(domains) + len(ips) + len(cidrs)
        self.log("target", f"目标解析：{len(domains)} 域名 / {len(ips)} IP / {len(cidrs)} 网段"
                           f" / {len(companies)} 企业名")
        self.progress("target_parse", 100, "目标解析完成")
        # brand 回填用户原词：P1 遇到域名目标会走早退分支，实体里 name/brand 皆空，
        # 后面 P1b 只拿到根域，企业名检索词就断在这里了。
        return {"domains": domains, "ips": ips, "cidrs": cidrs, "companies": companies,
                "raw": [c for c in companies], "brand": (companies[0] if companies else "")}

    # ───────── P1 企业主体 ─────────
    async def p1_enterprise(self, domains: list[str]) -> None:
        self.progress("enterprise", 5, "企业主体")
        roots = sorted({self._root(d) for d in domains})
        # MX 指向的服务器 IP 先算出来，P5 才好在扫描前把服务商机器整台剔掉
        mx_ips: set[str] = set()
        mx_hosts: set[str] = set()
        mail_roles: set[str] = set()
        mail_ip_set: set[str] = set()
        mail_web_ips: set[str] = set()
        # P0 已经用企业名跑过 collect_entity，结果是带品牌与别名的实体。
        # 这里若整体清空再按根域重跑，企业名查出来的实体就被域名实体顶掉，
        # P1b 的检索词只剩根域（拿 lkcoffee.com 去查应用商店必然是 0 结果）。
        kept = list(self.entities or [])
        self.entities = kept
        # P0 用企业名查出来的实体已经覆盖了它的确认域。这些根域再按「根域当主体名」查一遍，
        # 等于把同一份工商 / 备案重跑；确认域一多，这一阶段能被拖到二十多分钟。
        covered: set[str] = set()
        for ent in kept:
            for dom in (ent.get("domains") or []):
                covered.add(self._root(dom) or dom)
        todo = [r for r in roots if r not in covered]
        limit = max(0, int(self.opt("enterprise_roots_limit", 8) or 0))
        if covered:
            self.log("enterprise", f"按根域补主体：{len(roots) - len(todo)} 个根域的业务主体"
                                   f"已由企业名那条线查到，跳过")
        if len(todo) > limit:
            self.log("enterprise", f"按根域补主体：{len(todo)} 个根域超过本轮上限 {limit}，"
                                   f"只补前 {limit} 个（其余照常进扫描根域）", "warn")
            todo = todo[:limit]
        root_timeout = float(self.opt("enterprise_root_timeout", 90) or 90)
        # 主体这一路是逐个根域去查备案 / 工商 / 反查的，同一个出口 IP 连着打会被判风控。
        # 取数和入库分开：取数按 enterprise_concurrent 限并发、按 enterprise_gap 拉开间隔，
        # 入库仍然串行，实体表 / 资产表不会被并发写乱。
        ent_concurrent = max(1, int(self.opt("enterprise_concurrent", 1) or 1))
        ent_gap = max(0.0, float(self.opt("enterprise_gap", 0) or 0))
        if ent_concurrent > 1 or ent_gap > 0:
            self.log("enterprise", f"按根域补主体：并发 {ent_concurrent}，"
                                   f"相邻根域间隔 {ent_gap:g}s")
        ent_sem = asyncio.Semaphore(ent_concurrent)

        async def _collect_root(root: str) -> dict:
            # 根域不是品牌名：它去查应用商店只会命中「以域名命名的山寨应用」，
            # 每条要等商店 + 搜索好几跳。移动端面由 P1b 用品牌词单独做。
            got: dict = {}
            async with ent_sem:
                if ent_gap:
                    await asyncio.sleep(ent_gap)
                try:
                    ent = await self._bounded(
                        enterprise.collect_entity(
                            root, mobile=False,
                            equity_sources=self.opt("equity_sources", None) or None,
                            icp_kinds=self._icp_kinds(),
                            icp_pages=int(self.opt("icp_pages", 2) or 2),
                            icp_size=int(self.opt("icp_size", 40) or 40),
                            icp_retry=int(self.opt("icp_retry", 0) or 0) or None,
                            icp_gap=float(self.opt("icp_gap", 0) or 0) or None,
                            icp_alias=bool(self.opt("icp_alias", True)),
                            icp_force=bool(self.opt("icp_force", False)),
                            icp_api=str(self.opt("enterprise_icp_api", "") or ""),
                            on_log=self._ent_log(),
                            on_partial=self._entity_part_taker(root, got),
                            budget_s=max(20.0, root_timeout - 10)),
                        root_timeout, tag=f"根域主体 {root}", log_mod="enterprise",
                        stage="enterprise",
                        partial=lambda: dict(getattr(enterprise, "LAST_STATUS", {}) or {}))
                except Exception as e:
                    return {"root": root, "ent": None, "got": got, "err": str(e)}
            return {"root": root, "ent": ent if isinstance(ent, dict) else None,
                    "got": got, "err": None}

        results = list(await asyncio.gather(*[_collect_root(r) for r in todo]))
        for i, hit in enumerate(results, 1):
            root, ent, got = hit["root"], hit["ent"], hit["got"]
            if hit["err"]:
                self.log("enterprise", f"{root}: {hit['err']}", "warn")
            if not isinstance(ent, dict):
                ent = got or None
                if not isinstance(ent, dict):
                    continue
                self.log("enterprise", f"{root} 按快照入库：备案 "
                                       f"{len(ent.get('icp') or [])} 条", "warn")
            self.entities.append(ent)
            # 渠道留痕：主体这一路内部还会分别走工信部备案 / 工商备案 / 反查页 / 搜索引擎，
            # 失败原因各不相同。逐条落库，任务页才说得出「这趟用了哪些渠道、哪条失效了」。
            try:
                source_health.record_many(store, self.task_id, "enterprise",
                                          ent.get("source_status") or {})
            except Exception:
                pass
            for dom in ent.get("domains") or []:
                if dom not in self.domains and same_site(dom, root):
                    self.domains.add(dom)
                    self.claim_root(dom, ent.get("name") or root)
            if ent.get("domains_pending"):
                pend = ent["domains_pending"]
                self.log("enterprise", f"{root} 另有 {len(pend)} 个待核验域没进扫描："
                                       f"{'、'.join(pend[:6])}", "warn")
            if ent.get("icp") or ent.get("name"):
                # 主体那一路的途中快照可能已经交过同一个 url，重复交只刷新、不计数
                self._save_asset_once({
                    "kind": "enterprise", "url": f"enterprise:{root}",
                    "root_domain": root, "host": root,
                    "title": ent.get("name") or root,
                    "extra": ent, "sources": "enterprise",
                })
            # 这一路也跑了股权穿透：链路要落成控股 / 投资 / 股东 / 分支资产，
            # 否则「按根域补主体」出来的任务是同一份空壳。
            self._save_equity_detail(ent.get("name") or root, ent.get("equity_detail"))
            if ent.get("icp"):
                self._save_icp(ent.get("icp"), ent.get("name") or root)
                for item in ent["icp"][:20]:
                    self.log("enterprise", f"  ICP {root}: {item.get('icp') or item.get('domain')}"
                                           f" {item.get('unit') or ''}")
            self.progress("enterprise", int(i * 100 / max(1, len(todo))), f"企业主体 {root}")
        # 邮件 DNS（MX/SPF/DMARC/DKIM）作为主体线索
        if self.opt("mail_dns", False):
            for root in roots[:10]:
                try:
                    info = await deep.mail_dns(root, self.dns)
                except Exception:
                    continue
                if info.get("mx") or info.get("spf") or info.get("dmarc"):
                    self.save_asset({"kind": "mailinfo", "url": f"mail:{root}", "host": root,
                                     "root_domain": root, "extra": info, "sources": "maildns"})
                # MX 主机名与它的落点 IP 是两件事：主机名挂在自家根下才算自家邮件主机，
                # 落点 IP 单独解析——MX 指向托管商（mxbiz1.qq.com）时，那些 IP 是服务商的机器。
                mx_list: list[str] = []
                for mx in info.get("mx") or []:
                    h = str(mx).split()[-1].rstrip(".")
                    if not h or is_ip(h):
                        continue
                    if self._root(h) == root:
                        # 自家根下的邮件主机：是不是托管商机器由下面按落点 IP 判
                        mx_list.append(h)
                    else:
                        # 托管邮箱服务商的域（如 mx.qq.com）只是「目标用谁家邮箱」的线索，
                        # 不是目标资产。写进资产库会把腾讯自己的 captcha / 静态域一路带出来。
                        self.log("enterprise", f"  邮件托管线索: {h}（第三方域名，仅记录）")
                # MX 解析出来的 IP 是邮箱服务商的服务器：端口扫描会在这上面看到
                # 25/993 这类邮件端口，那是服务商的设施，不能记成本任务的开放端口。
                # MX 记录常被托管商覆盖掉，自家真实的 mail/smtp/imap/pop 主机就漏网了。
                # 邮件设施端口是按这几台机器报的，所以固定几位候选名一起登记。
                for name in ("mail", "smtp", "imap", "pop", "pop3", "webmail"):
                    probe = f"{name}.{root}"
                    if probe in self.domains:
                        continue
                    try:
                        res = await self.dns.resolve_a(probe)
                    except Exception:
                        continue
                    if res and res.ips:
                        self.domains.add(probe)
                        mx_list.append(probe)
                for h in mx_list:
                    if is_ip(h):
                        continue
                    if self._root(h) == root:
                        # 自家根下的邮件主机：机器是不是托管商的不看 MX 记录，看它落在哪。
                        # 落在 MX 服务商（腾讯/阿里企业邮等）的 IP 上就是服务商机器；
                        # 自建邮箱落在自己机房里，照常扫 Web 与邮件面。
                        try:
                            res = await self.dns.resolve_a(h)
                        except Exception:
                            res = None
                        host_ips = [ip for ip in ((res.ips if res else []) or []) if is_ip(ip)]
                        if host_ips and set(host_ips) <= mx_ips:
                            for ip in host_ips:
                                self.mail_provider_ips.add(ip)
                                mail_ip_set.add(ip)
                            mail_roles.add(h.lower())
                            continue
                        mail_web_ips.update(host_ips)
                        mail_roles.add(h.lower())
                        continue
                    mx_hosts.add(h.lower())
                    try:
                        res = await self.dns.resolve_a(h)
                    except Exception:
                        continue
                    for ip in (res.ips if res else []) or []:
                        if is_ip(ip):
                            self.mail_provider_ips.add(ip)
                            mx_ips.add(ip)
        # 解析表里的主机：名字挂在邮箱服务商根下，或者解出来的 IP 就是 MX 落点，
        # 都不算目标机器。P5 按这份名单整台跳过。
        for d, ips in list(self.ips.items()):
            if not is_ip(d) and set(ips) & mx_ips:
                mx_hosts.add(d.lower())
        if mx_hosts:
            self.mail_hosts |= mx_hosts
            self.log("maildns", f"{len(mx_hosts)} 个主机是邮箱服务商服务器，端口扫描跳过："
                                f"{', '.join(sorted(mx_hosts)[:5])}")
        if mail_roles:
            self.mail_roles |= mail_roles
            self.mail_provider_ips |= mail_ip_set
            self.mail_web_ips |= mail_web_ips
            self.log("maildns", f"{len(mail_roles)} 个自家邮件主机登记完成："
                                f"{', '.join(sorted(mail_roles)[:5])}"
                                f"（其中 {len(mail_ip_set)} 台是托管商机器，整台不扫）")
        self.progress("enterprise", 100, "企业主体完成")

    # ───────── P1b 小程序 / App ─────────
    async def p1c_equity(self, parsed: dict) -> None:
        """股权穿透：把「全资控股闸」算成数据，只把累计持股 100% 的主体并进目标池。

        这是 P0/P1 的补线：企业名扩域只拿到一个主体，全资子公司（孙公司、曾孙公司）
        各有自己的域，不并进来就是整片漏挖。参股/联营默认不进池，只记进实体 extra
        供人工复核——写错主体的洞投不进本 SRC。
        """
        if not (self.opt("equity_expand", True) or self.options.get("equity")):
            return
        # 主体候选分硬软两层：
        #   硬 = 用户输入的原词、实体查到的工商全称，查到了就是这一摊的真主体；
        #   软 = `_brand()` 从全称剥出来的简称。剥法是按行业词逐段裁的，裁狠了会剩
        #        「人才」这种半截词（漳州人才发展集团有限公司 → 漳州人才发展 → 漳州 → 人才）。
        #        拿半截词去查工商，有概率命中同名的另一家公司，也会白烧一轮额度并建出假主体。
        hard: list[str] = []
        soft: list[str] = []

        def _push(bucket: list[str], val) -> None:
            v = (val or "").strip()
            if _usable_subject_name(v) and v not in hard and v not in soft:
                bucket.append(v)

        for k in list(parsed.get("raw") or []) + [parsed.get("brand")]:
            _push(hard, k)
        for ent in getattr(self, "entities", []) or []:
            _push(hard, ent.get("input"))
            _push(hard, ent.get("name"))
            _push(soft, ent.get("brand"))
        if not hard and not soft:
            return
        self.progress("equity", 5, "股权穿透")
        # 这两项优先取本次单项执行的表单值，没填才回落全局配置
        depth = int(self.opt("equity_depth", 2) or 2)
        ratio = float(self.opt("equity_ratio", 100) or 100)
        owned: list[str] = []
        # 子公司名 → 「⌈N⌋级投资⌈比例⌋-母体」：落资产时带上，导出和界面都能回答「怎么算进来的」
        owned_rel: dict[str, str] = {}
        ubo_threshold = float(self.opt("equity_ubo_threshold", 25) or 25)
        ubo_levels = int(self.opt("equity_ubo_levels", 1) or 0)
        # 只跑勾选的工商来源：不勾的那一路连请求都不发，额度留给要用的那条
        eq_sources = [str(s) for s in (self.opt("equity_sources", None) or [])] or None
        cap = max(1, int(self.opt("equity_max_names", 10) or 10))
        # 0 = 额度不限：翻页一直翻到没有下一页，只受每层页上限与下面这个总时限约束
        budget_opt = int(self.opt("equity_budget", 40) or 0)
        # 整段股权穿透的总时限：下面每个主体、每家子公司的工商查询都是外部串行活，
        # 不留总闸时一轮能拖到半小时，中途界面什么都不出，看着就像「什么都没找到」。
        # 但按次等待会成倍拉长耗时（30 秒 × 40 次 ≈ 20 分钟），时限不跟着放宽就变成
        # 「配了延时反而被总时限截断、拉得更不全」。所以只放大、不缩小用户填的值。
        stage_cap = float(self.opt("equity_stage_deadline", 900) or 900)
        eq_cap = float(self.opt("equity_timeout", 240) or 240)
        sub_cap = float(self.opt("equity_sub_timeout", 100) or 100)
        eq_gap = float(self.opt("equity_gap", 0) or 0)
        gap_s = equity.effective_gap(eq_gap or None)
        if gap_s > 2.0:
            # 不限额时按 240 次估：30 秒一次约两小时，正好是「慢节奏把一棵子树翻满」的量级。
            # 估算出来的时限最多放到 8 小时，别让一张任务挂成一天。
            times = budget_opt if budget_opt > 0 else 240
            est = min(8 * 3600.0, times * (gap_s + 2.0) + 120.0)
            if est > stage_cap:
                label = "额度不限·按 240 次估" if budget_opt <= 0 else f"预算 {times} 次"
                self.log("equity", f"请求间隔 {gap_s:g} 秒 × {label} 约需 "
                                   f"{est / 60:.0f} 分钟，总时限由 {stage_cap / 60:.0f} 分钟"
                                   f"放宽到 {est / 60:.0f} 分钟")
            stage_cap = max(stage_cap, est)
            eq_cap = max(eq_cap, stage_cap)
            # 单个子公司只做浅层（检索 + 股东 + 投资 + 取证），大约十次请求；按这个量级
            # 放大，别拿整段的 ``est / 2`` 当单子超时——那样一家子就敢占一小时。
            sub_cap = max(sub_cap, min(stage_cap, 10 * (gap_s + 2.0) * 2))
        stage_deadline = time.monotonic() + stage_cap
        # 并线段（全资子公司扩域）必须留一份时间：主穿透一个 163 节点的大主体在
        # 30 秒延时下就要八十多分钟，把总闸吃满之后 `_left()` 归零，子公司一家都并不进来。
        # 现场表现就是「穿透图画得挺全，域名却一个没多」。这里给并线段留三成。
        main_deadline = time.monotonic() + stage_cap * 0.7
        eq_timeout = eq_cap
        sub_timeout = sub_cap

        def _left() -> float:
            return stage_deadline - time.monotonic()

        def _left_main() -> float:
            return min(_left(), main_deadline - time.monotonic())

        async def _one(name: str, i: int, total: int) -> str:
            """跑一个候选主体：落股权资产、记渠道，返回工商对齐到的全称。"""
            self.log("equity", f"开始穿透 {name}（{depth} 层 / 控股门槛 {ratio:g}%）")
            try:
                eq = await self._bounded(
                    equity.collect(name, depth=depth, ratio=ratio,
                                   ubo_threshold=ubo_threshold,
                                   ubo_levels=ubo_levels,
                                   branches=bool(self.opt("equity_branch", True)),
                                   sources=eq_sources,
                                   gap=float(self.opt("equity_gap", 0) or 0) or None,
                                   retry=int(self.opt("equity_retry", 0) or 0) or None,
                                   budget=budget_opt,
                                   on_progress=lambda m: self.log("equity", m),
                                   # 链路是逐层长出来的：边穿边把已经穿到的节点摊进资产，
                                   # 整段跑完（或总时限到、协程被掐）时任务页和穿透图里
                                   # 已经有东西，不用等最后一刻才一次性出现。
                                   on_partial=lambda snap: self._save_equity_detail(
                                       name, snap)),
                    min(eq_timeout, max(20.0, _left_main())), tag=f"股权穿透 {name}",
                    log_mod="equity", stage="equity",
                    partial=lambda: dict(getattr(equity, "LAST_STATUS", {}) or {}))
            except Exception as e:
                self.log("equity", f"{name}: {e}", "warn")
                return ""
            if eq is None:
                return ""
            # 渠道面板：每一路工商 / 备案这次是什么状态都留痕，失效的写清原因，
            # 免得下次只看「找得不全」却不知道是额度尽还是被风控。
            # 备用工商源是一路多家的（``backup:<源>``），各家的失效原因不一样，
            # 所以按子渠道名去 eq.notes 里找它自己那一句，不能拿第一条说明糊全部。
            eq_status = dict(getattr(eq, "source_status", {}) or {})
            notes_map = source_health.split_notes(getattr(eq, "notes", None), eq_status)
            items_map: dict[str, int] = {}
            for k in eq_status:
                tail = k.split(":", 1)[-1]
                items_map[k] = sum(
                    1 for c in eq.chain
                    if tail in (str(c.get("src") or ""), str(c.get("via") or "")))
            source_health.record_many(store, self.task_id, "equity", eq_status,
                                      notes=notes_map, items=items_map)
            # 额度是「翻投资页 / 逐层穿子公司 / 追上游股东」三处共用的，被吃光时
            # 这一路工商源本身还是「可用」，清单却短了一截。单记一行截断，
            # 才能把「找得不全」指到真正该调的那个参数上。
            for ck, cv in (getattr(eq, "cap_notes", None) or {}).items():
                source_health.record(store, self.task_id, "equity", f"cap:{ck}", "partial",
                                     note=str(cv)[:300])
                self.log("equity", f"{name}: {cv}", "warn")
            full = equity.full_owned_children(name, eq.chain, ratio=ratio)
            partial = [c for c in eq.chain
                       if float(c.get("acc_ratio", c.get("ratio", 0)) or 0) < ratio]
            self.log("equity", f"{name}: 达标（≥{ratio:g}%）{len(full)} 家 / 低于门槛 {len(partial)} 家"
                               f"（来源 {eq.source or '无'}；分层 {len(eq.chain)} 条）")
            ubo = eq.ubo
            if ubo["holders"]:
                self.log("equity", f"{name}: 最终受益人 {len(ubo['holders'])} 位 / "
                                   f"达控制线（≥{ubo_threshold:g}%）{ubo['controls']} 位",
                         "info" if ubo["controls"] else "warn")
            owned.extend(full)
            rel = getattr(eq, "relation", {}) or {}
            for n in full:
                if n in rel:
                    owned_rel.setdefault(n, rel[n])
            for note in eq.notes[:3]:
                self.log("equity", f"  {note}", "warn")
            # 链路本体 + 分支 / 备案 / 控股 / 投资 / 股东 / 软著：行怎么拼在
            # `asset_rows.equity_rows()`，和单项直跑共用，避免两条路径口径漂移。
            for row in asset_rows.equity_rows(name, eq.as_dict(), ratio):
                self.save_asset(row)
            if eq.branches:
                self.log("equity", f"{name}: 分支机构 {len(eq.branches)} 家")
            if eq.icps:
                self.log("equity", f"{name}: 备案 {len(eq.icps)} 条")
            self.progress("equity", int(i * 100 / max(1, total)), f"股权穿透 {name}")
            return str(getattr(eq, "resolved", "") or "")

        queried: list[str] = []
        hit: list[str] = []
        plan = hard[:cap]
        if len(hard) > cap:
            # 「找得不全」最常见的真相就是这里：候选主体比上限多，后面的连请求都没发。
            # 不单记一条，用户只会看到工商来源「可用」，永远想不到是被自己的上限砍的。
            rest = "、".join(hard[cap:cap + 4])
            self.log("equity", f"候选主体 {len(hard)} 个，主体上限 {cap}，本轮只穿透前 {cap} 个"
                               f"（没跑：{rest}）；调「主体上限」或单阶段重跑补上", "warn")
            source_health.record(store, self.task_id, "equity", "cap:names", "partial",
                                 note=f"候选 {len(hard)} 个 / 上限 {cap}：{rest}"[:300],
                                 items=len(hard) - cap)
        for i, name in enumerate(plan, 1):
            queried.append(name)
            if await _one(name, i, len(plan)):
                hit.append(name)
        # 硬候选一个都没对上工商主体，才用简称兜底。被硬候选整体包含的短简称是剥词残渣
        # （「人才」之于「漳州人才发展集团有限公司」），拿它查必然命中别家，直接不查。
        if not hit:
            tail = [s for s in soft
                    if not any(s != h and s in h and len(s) <= 4 for h in hard)][:2]
            if tail:
                self.log("equity", "主候选没对上工商主体，改用简称兜底：" + "、".join(tail), "warn")
                for i, name in enumerate(tail, 1):
                    queried.append(name)
                    if await _one(name, i, len(tail)):
                        hit.append(name)
        names = list(dict.fromkeys(queried))
        owned = [n for n in dict.fromkeys(owned) if n and n not in names]
        if not owned:
            return
        # 默认 40 家并线：配置里这一项留空（None）时以前会算成 0，
        # 整段「全资主体并线」直接被自己的缺省值关掉，看着就像股权穿透只穿不并。
        subs_cap = max(0, int(self.opt("equity_subs", 40) or 40))
        subs = owned[:subs_cap]
        if len(owned) > len(subs):
            rest = "、".join(owned[len(subs):len(subs) + 4])
            self.log("equity", f"达标主体 {len(owned)} 家，并线上限 {len(subs)}，本轮只并前 "
                               f"{len(subs)} 家（没并：{rest}）；调「子公司并线上限」补上", "warn")
            source_health.record(store, self.task_id, "equity", "cap:subs", "partial",
                                 note=f"达标 {len(owned)} 家 / 上限 {len(subs)}：{rest}"[:300],
                                 items=len(owned) - len(subs))
        workers = max(1, min(6, int(self.opt("equity_sub_workers", 3) or 3)))
        sem = asyncio.Semaphore(workers)
        skipped: list[str] = []
        # 工商源被风控 / 额度耗尽时，每家子公司都会死等满 sub_timeout：
        # 24 家 / 3 并发 × 100 秒正好把整段总闸吃干，最后一条都没查成。
        # 连续几家超时说明这一路已经不可用，停派活、把剩下的记成没跑，留给单阶段重跑。
        breaker = max(1, int(self.opt("equity_breaker", 3) or 3))
        timed_out: list[str] = []
        dropped: list[str] = []
        attempted: set[str] = set()
        merged_ok: list[str] = []
        stop_subs = asyncio.Event()
        queue: asyncio.Queue[str] = asyncio.Queue()

        # 全资子公司名回到实体扩线：每个子公司单独搜品牌域，再走一次证据闸。
        # 一家一家串行时十几家能把一轮拖到半小时，中途什么都看不到；这里限并发、
        # 每条有硬时限、整段有总闸，跑不完的明说落下几家，单阶段重跑可以续。
        async def _sub(sub: str) -> str:
            """跑一家子公司；返回 ok / skip / timeout / error，给连续超时熔断计数。"""
            async with sem:
                attempted.add(sub)
                left = _left()
                if left <= 15:
                    skipped.append(sub)
                    return "skip"
                try:
                    got: dict = {}
                    ent = await self._bounded(
                        enterprise.collect_entity(
                            sub, mobile=False, equity=False,
                            equity_sources=eq_sources,
                            icp_retry=int(self.opt("icp_retry", 0) or 0) or None,
                            icp_gap=float(self.opt("icp_gap", 0) or 0) or None,
                            icp_api=str(self.opt("enterprise_icp_api", "") or ""),
                            on_log=self._ent_log("equity"),
                            on_partial=self._entity_part_taker(sub, got),
                            budget_s=max(20.0, min(sub_timeout, left) - 10)),
                        min(sub_timeout, left), tag=f"子公司扩线 {sub}",
                        log_mod="equity", stage="equity")
                except Exception as e:
                    self.log("equity", f"子公司扩线失败 {sub}: {e}", "warn")
                    return "error"
                if not isinstance(ent, dict):
                    # 这一家超时了，已经查到的备案 / 域名照快照入库。
                    ent = got or None
                if not isinstance(ent, dict):
                    return "timeout"
                source_health.record_many(store, self.task_id, "equity",
                                          ent.get("source_status") or {},
                                          items={"searchengine": len(ent.get("domains") or [])})
                ent["input"] = sub
                if sub in owned_rel:
                    ent["relation"] = owned_rel[sub]
                self.entities.append(ent)
                for dom in ent.get("domains") or []:
                    if dom and dom not in self.domains and self.keep_domain(dom):
                        self.domains.add(dom)
                        self.claim_root(dom, sub)
                        self.log("equity", f"  + {sub} → {dom}")
                self._save_asset_once({
                    "kind": "enterprise", "url": f"enterprise:{sub}", "host": "",
                    "title": ent.get("name") or sub, "extra": ent, "sources": "equity",
                })
                self._save_icp(ent.get("icp"), ent.get("name") or sub)
                merged_ok.append(sub)
                return "ok"

        async def _worker() -> None:
            while not stop_subs.is_set():
                try:
                    sub = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                state = await _sub(sub)
                if state != "timeout":
                    continue
                timed_out.append(sub)
                if len(timed_out) >= breaker and not stop_subs.is_set():
                    stop_subs.set()
                    self.log("equity",
                             f"子公司扩线连续 {len(timed_out)} 家超时"
                             f"（{int(sub_timeout)}s 上限），工商源大概率被风控 / 额度耗尽；"
                             f"本轮停止并线，剩下的留待单阶段重跑", "warn")

        if subs:
            for s in subs:
                queue.put_nowait(s)
            await asyncio.gather(*[_worker() for _ in range(min(workers, len(subs)))])
            if stop_subs.is_set():
                dropped = [s for s in subs if s not in attempted]
                source_health.record(store, self.task_id, "equity", "cap:subs_timeout", "partial",
                                     note=(f"连续 {len(timed_out)} 家超时熔断，"
                                           f"未跑 {len(dropped)} 家："
                                           + "、".join(dropped[:4]))[:300],
                                     items=len(dropped))
        if skipped:
            self.log("equity", f"总时限到，{len(skipped)} 家子公司没跑："
                               + "、".join(skipped[:6])
                               + "（调大 equity_stage_deadline 或单阶段重跑股权穿透补上）", "warn")
            source_health.record(store, self.task_id, "equity", "cap:deadline", "partial",
                                 note=f"总时限到，{len(skipped)} 家没跑：" + "、".join(skipped[:4]),
                                 items=len(skipped))
        if dropped:
            self.log("equity", f"连续超时熔断，{len(dropped)} 家子公司没跑："
                               + "、".join(dropped[:6])
                               + "（恢复工商源后单阶段重跑股权穿透补上）", "warn")
        done_subs = [s for s in merged_ok]
        if done_subs:
            self.log("equity", f"全资主体并入 {len(done_subs)} 家：" + "、".join(done_subs[:6]))
        else:
            self.log("equity", "全资主体并线：本轮没有可并入的子公司")

    async def p1b_mobile(self, parsed: dict) -> None:
        """小程序 / 公众号 / App 三条移动端面：主体名/应用名 → 包名、AppID、公众号、包内域名。

        不需要 AI，也不需要 key；拿不到就写在日志里，不编条目。
        新发现的域并回 self.domains，后面被动收集会继续扩。
        三类目标的检索词**分开**：企业主体名只适合查 App（开发者名能对上包名），
        拿去查小程序名只会拿工商全称去撞微信搜索，白等一轮超时。
        公众号按昵称回比门控，只留昵称/标题真的对上检索词的号。
        """
        self.progress("mobile", 5, "小程序 / 公众号 / App")
        # 移动端这一路新采到的域，统一在这一个集合里累加，函数末尾一次并进 self.domains。
        # 容器只原地改（add / update），全程不给这些名字再赋值：闭包里出现的
        # `x |= y` 会让编译器把 x 变成内层局部变量，和 `x.add()` 读到的不是同一个对象。
        found: set[str] = set()
        # 原地 update：`found |= ...` 会把 found 在内层协程里重新绑定成局部变量
        put = found.update
        devs: list[str] = []          # App 侧读到的中文开发主体，第二轮查小程序的检索词
        # P0 会把企业名扩成域名再塞进 entities，所以 entities 里的 input 可能全是域名。
        # 检索词要先取用户原词（parsed.raw/brand），再取实体里的中文名，域名只进 roots。
        names: list[str] = []
        for k in list(parsed.get("raw") or []) + [parsed.get("brand")]:
            k = (k or "").strip()
            if _usable_subject_name(k) and k not in names:
                names.append(k)
        for ent in getattr(self, "entities", []) or []:
            for k in (ent.get("input"), ent.get("name"), ent.get("brand")):
                k = (k or "").strip()
                if _usable_subject_name(k) and k not in names:
                    names.append(k)
        # 机构类主体（`厦门市特种设备检验检测院`）没有可用短名：品牌位会被剥成行业词
        # （`特种设备`），拿去查应用商店/小程序名只会撞到同行应用，把它们的域名并回流水线。
        # 这类只保留全称做检索词。
        names = [n for n in names if not enterprise._institution_only(n)] or names
        # 品牌词（搜索带出来的短名）比工商全称更容易命中应用商店和小程序名
        # 短名优先：企业全称拿去查小程序名基本撞不到
        brands: list[str] = []
        for ent in getattr(self, "entities", []) or []:
            for k in (ent.get("brand"),) + tuple(ent.get("aliases") or ()):
                k = (k or "").strip()
                if _usable_subject_name(k) and k not in brands:
                    brands.append(k)
        for n in names:
            if n not in brands:
                brands.append(n)
        # 实体里的 name 多半是域名（P1 按根域查出来的），这里只留中文品牌形态
        brands = [b for b in brands if _usable_subject_name(b)]
        roots: list[str] = []
        for t in parsed.get("domains") or []:
            root = self._root(t)
            if root and root not in roots:
                roots.append(root)
        if not brands:
            # 一个中文词都没有（P0 只给了域名，P1 按根域反查的实体 name 也是域名）：
            # 拿根域查 App，从市场详情页反查开发主体全称，再用它做下一轮的检索词。
            # 否则整条移动端面退化成一堆 `lkcoffee.com` 式的 0 结果检索。
            for root in roots[:2]:
                try:
                    probe = await mobile.collect_apps(root, limit=3)
                except Exception as e:
                    self.log("mobile", f"App 预查失败 {root}: {e}", "warn")
                    continue
                for ap in probe.get("items") or []:
                    dev = (ap.get("developer") or "").strip()
                    if not dev or dev in brands:
                        continue
                    if not naming.is_org_name(dev):
                        continue
                    brands.append(dev)
                    self.log("mobile", f"按根域查到开发主体「{dev}」"
                                       f"（{ap.get('name') or ap.get('package')}），用它做检索词")
                    # 应用名才是市场与微信里登记的短名：「瑞幸咖啡信息技术（厦门）有限公司」
                    # 拿去查小程序名一个也撞不到，剥成「瑞幸咖啡」才行
                    short = enterprise._brand(dev)
                    if short and short != dev and short not in brands:
                        brands.append(short)
            if not brands:
                # 反查也没读到主体：根域兜底（还能撞到以域名为名的应用）
                brands = list(roots[:1])
        # 备案库里的小程序 / APP 备案：主办单位就是本主体，服务名称是登记在册的名字，
        # 比搜出来的「同款」昵称硬得多。既是检索词，也在 _save_icp 里直接落成资产。
        miit_mobile: list[dict] = []
        for ent in getattr(self, "entities", []) or []:
            for it in ent.get("icp") or []:
                if not isinstance(it, dict) or str(it.get("kind") or "site") == "site":
                    continue
                nm = str(it.get("app") or "").strip()
                if not nm or any(x["name"] == nm for x in miit_mobile):
                    continue
                miit_mobile.append({"name": nm,
                                    "lic": str(it.get("icp") or "").strip(),
                                    "kind": str(it.get("kind") or ""),
                                    "unit": str(it.get("unit") or "").strip()})
        if miit_mobile:
            self.log("mobile", "备案库里的移动端登记：" + "、".join(
                f"{x['name']}（{x['lic'] or x['kind']}）" for x in miit_mobile[:6]))
        # 备案登记名是主体自己的名字，直接排在检索词前面：它们出的一定是自家资产。
        miit_mini = [x["name"] for x in miit_mobile if x["kind"] in ("mapp", "kapp")][:4]
        miit_apps = [x["name"] for x in miit_mobile if x["kind"] not in ("mapp", "kapp")][:4]
        # 品牌词排前面：应用商店与小程序都按名字登记，域名只有当名字用才命中
        app_targets = (miit_apps + brands + names + roots)[:8]
        # 小程序名不会长成工商全称：「瑞幸咖啡（中国）有限公司 小程序」一个字也撞不到，
        # 只会把搜索配额花在无关页上。所以小程序检索词只留简称（<=8 字）与域名形态。
        applet_targets = (miit_mini + brands[:1] + [n for n in brands[1:] if len(n) <= 8]
                          + roots)[:6]
        applet_targets = [t for t in applet_targets if t and not _is_full_company(t)]
        # 公众号按昵称/文章标题登记，检索词用短品牌词最灵；全称留给 App 面。
        # 条数压到 3：每个词要走站内检索 + 主页身份 + 代表文章，4s 起步。
        mp_targets = [t for t in (brands[:2] + roots[:2]) if t][:3]
        mp_targets = [t for t in mp_targets if not _is_full_company(t)] or mp_targets[:2]
        # 公众号 / 小程序的昵称是「名字」，不是域名。拿 `xm.gov.cn` 去搜，搜回来的是
        # 别人家同城账号（浙大妇院图书馆、成都市场监管这类），一条也挂不到主体上；
        # 机构类主体没有短名时尤其容易走到这一步。这里把域名形态的词整段剔掉：
        # 一个能当名字的词必须带中文，或至少是不含点的英文词。
        def _name_like(w: str) -> bool:
            w = (w or "").strip()
            if not w or "." in w:
                return False
            return bool(re.search(r"[\u4e00-\u9fff]", w)) or (w.isascii() and w.isalpha()
                                                              and len(w) >= 3)

        dropped = [t for t in applet_targets + mp_targets if not _name_like(t)]
        applet_targets = [t for t in applet_targets if _name_like(t)]
        mp_targets = [t for t in mp_targets if _name_like(t)]
        if dropped:
            self.log("mobile", "域名形态检索词不用于公众号/小程序（搜回来的是别家）："
                               + "、".join(dict.fromkeys(dropped)), "warn")
        self.log("mobile", f"检索词 App：{'、'.join(app_targets[:6]) or '无'}"
                           f"｜小程序：{'、'.join(applet_targets[:5]) or '无'}"
                           f"｜公众号：{'、'.join(mp_targets[:3]) or '无'}")
        if not app_targets and not applet_targets and not mp_targets:
            self.progress("mobile", 100, "无可用移动端检索词")
            return

        # 这个字典要在 p1b_mobile 最前面就建好：_consume 可能在第一条 await 返回前
        # 就被别的协程调度到，晚建就会抛 UnboundLocalError 把整轮移动端面打断。
        plan = [(t, "app") for t in app_targets] + [(t, "applet") for t in applet_targets] + \
               [(t, "mp") for t in mp_targets]
        # 微博账号按昵称登记，检索词用短品牌词最灵；两个词起步，关掉这一项就一个请求都不发
        weibo_targets = [t for t in brands[:2] if t] \
            if bool(self.opt("mobile_weibo", True)) else []
        plan += [(t, "weibo") for t in weibo_targets]
        # 渠道面板停用的内容平台不发请求，只记一行「未启用」让面板说得清为什么没结果
        off_plan = [k for k, src in (("mp", "weixin"), ("weibo", "weibo"))
                    if not channels_mod.source_on(src)]
        if off_plan:
            for k in off_plan:
                source_health.record(store, self.task_id, "mobile", k, "skip",
                                     "你停用了这一路，本次没发请求", 0)
            plan = [p for p in plan if p[1] not in off_plan]
            self.log("mobile", "按渠道开关跳过："
                     + "、".join("公众号" if k == "mp" else "微博" for k in off_plan), "warn")
        # 并发跑：每个检索词内部已经等了搜索/商店好几秒，串行 14 个词就是两三分钟。
        # 结果统一由主协程落库，避免多协程同时写 stats。
        # 三面各自的条数与并发都是单项执行的参数，没填走默认。
        app_limit = max(1, int(self.opt("mobile_app_limit", 8) or 8))
        mp_limit = max(1, int(self.opt("mobile_mp_limit", 6) or 6))
        applet_limit = max(1, int(self.opt("mobile_applet_limit", 8) or 8))
        sem = asyncio.Semaphore(max(1, int(self.opt("mobile_concurrent", 4) or 4)))

        async def _run(t: str, kind: str):
            async with sem:
                if kind == "app":
                    try:
                        # 单次 60s 上限：四路并发 + 内部多引擎，反爬变慢时整轮能到分钟级，
                        # 而 P1b 后面还有小程序两轮，到点先交已有结果
                        return t, kind, await mobile.collect_apps(t, limit=app_limit,
                                                                  deadline=60.0)
                    except Exception as e:
                        self.log("mobile", f"App 采集失败 {t}: {e}", "warn")
                        return t, kind, {"items": [], "domains": [], "sdk_domains": {}, "notes": [str(e)[:80]]}
                if kind == "mp":
                    try:
                        return t, kind, await mp_mod.collect_mps(t, limit=mp_limit,
                                                                 deadline=32.0)
                    except Exception as e:
                        self.log("mobile", f"公众号采集失败 {t}: {e}", "warn")
                        return t, kind, {"items": [], "domains": [], "notes": [str(e)[:80]]}
                if kind == "weibo":
                    try:
                        return t, kind, await weibo_mod.collect_weibo(t, limit=8,
                                                                       deadline=20.0)
                    except Exception as e:
                        self.log("mobile", f"微博采集失败 {t}: {e}", "warn")
                        return t, kind, {"items": [], "domains": [],
                                         "notes": [str(e)[:80]]}
                try:
                    return t, kind, await applet_mod.collect_applets(t, limit=applet_limit,
                                                                     deadline=75.0)
                except Exception as e:
                    self.log("mobile", f"小程序采集失败 {t}: {e}", "warn")
                    return t, kind, {"items": [], "domains": [], "notes": [str(e)[:80]]}

        async def _consume(t: str, kind: str, res: dict) -> None:
            """把一轮采集结果落库并收集域与开发主体名。"""
            if kind == "app":
                for ap in res.get("items") or []:
                    label = ap.get("name") or ap.get("package") or t
                    self.save_asset({
                        "kind": "mobile", "url": f"mobile:{ap.get('platform')}:{ap.get('package') or label}",
                        "host": ap.get("package") or "", "root_domain": ap.get("package") or "",
                        "title": f"{label}（{ap.get('platform')}）",
                        "extra": ap, "sources": "mobile:" + "/".join(ap.get("sources") or []),
                    })
                    for line in (apkstatic.brief(ap.get("apk") or {}) if ap.get("apk") else [])[:6]:
                        self.log("mobile", f"  · {label} {line}")
                    # 只收中文主体全称：应用商店里的英文发行商名拿去查小程序没有意义
                    dev = (ap.get("developer") or "").strip()
                    if dev and naming.is_org_name(dev) and dev not in devs:
                        devs.append(dev)
                for d in res.get("domains") or []:
                    # 应用商店里的「自有域」是按开发主体名匹配出来的，英文发行商名撞上的
                    # 可能是别人的站；只收能挂到已认自家根下的。
                    if d and any(same_site(d, r) for r in self._own_roots()):
                        found.add(d)
                    elif d:
                        self.log("mobile", f"  · App 侧域 {d} 挂不到已认主体根域，不并入扩线")
                self.log("mobile", f"App {t}: {len(res.get('items') or [])} 个应用 / "
                                   f"{len(res.get('domains') or [])} 个自有域 / "
                                   f"{len(res.get('sdk_domains') or {})} 个第三方 SDK 域")
            elif kind == "mp":
                kept = 0
                dropped_mp: list[str] = []
                for mp in res.get("items") or []:
                    key = mp.get("wxid") or mp.get("biz") or mp.get("name") or t
                    if not (mp.get("name") or mp.get("biz")):
                        continue
                    # 昵称对不上检索词的号一律不收：`site:` 检索对品牌词很宽松，
                    # 搜回来多半是第三方提到它的号。以前全量落库，一条任务能攒出
                    # 十几条别家公众号，看着像「主体名下资产」，实际全是噪声。
                    if str(mp.get("relevance") or "") == "low":
                        dropped_mp.append(str(mp.get("name") or key)[:24])
                        continue
                    kept += 1
                    # host / root_domain 留空：公众号不是域名资产，别污染按根域聚合的资产组
                    self.save_asset({
                        "kind": "wxmp", "url": f"mp:{mp.get('biz') or key}", "host": key,
                        "root_domain": "", "title": mp.get("name") or key,
                        "extra": mp, "sources": "mp:" + "/".join(mp.get("sources") or []),
                    })
                if dropped_mp:
                    self.log("mobile", f"公众号 {t}: 昵称对不上目标的 {len(dropped_mp)} 个已丢弃"
                                       f"（{'、'.join(dropped_mp[:5])}）")
                for d in res.get("domains") or []:
                    if d and any(same_site(d, r) for r in self._own_roots()):
                        found.add(d)
                    elif d:
                        self.log("mobile", f"  · 公众号侧域 {d} 挂不到已认主体根域，不并入扩线")
                self.log("mobile", f"公众号 {t}: {kept} 个号 / "
                                   f"{len(res.get('domains') or [])} 个自有域")
            elif kind == "weibo":
                for wb in res.get("items") or []:
                    uid = str(wb.get("uid") or "").strip()
                    if not uid:
                        continue
                    # host 留空：微博号不是域名资产，别进按根域聚合的分组
                    self.save_asset({
                        "kind": "weibo", "url": wb.get("url") or f"weibo:{uid}",
                        "host": "", "root_domain": "",
                        "title": wb.get("nick") or uid,
                        "extra": dict(wb, uid=uid), "sources": "weibo",
                    })
                for d in res.get("domains") or []:
                    if d and any(same_site(d, r) for r in self._own_roots()):
                        found.add(d)
                    elif d:
                        self.log("mobile", f"  · 微博侧域 {d} 挂不到已认主体根域，不并入扩线")
                self.log("mobile", f"微博 {t}: {len(res.get('items') or [])} 个号"
                                   f"（{res.get('status') or '-'}）")
            else:
                kept = 0
                for ap in res.get("items") or []:
                    # 只认带 AppID 或能带出后端域的条目。光有一个名字 + 一个「疑似主体」
                    # 是检索页上的推断，落库就变成别家小程序的档案。
                    if not (ap.get("appid") or ap.get("domains")):
                        continue
                    kept += 1
                    key = ap.get("appid") or ap.get("name") or t
                    self.save_asset({
                        "kind": "applet", "url": f"applet:{key}", "host": key, "root_domain": key,
                        "title": ap.get("name") or key, "extra": ap,
                        "sources": "applet:" + "/".join(ap.get("sources") or []),
                    })
                total_items = len(res.get("items") or [])
                if total_items > kept:
                    self.log("mobile", f"小程序 {t}: {total_items - kept} 个只有名字没 AppID / 无后端域，已丢弃")
                # 这一面是多入口拼的（主体站点 / 本机缓存 / 备案库 / 各家检索），每条入口
                # 失效原因不同。整份自报都落到渠道面板：一条 AppID 都没落库时，用户要能看出
                # 是「跑了但公开渠道没有」，而不是以为小程序这一段没跑。
                source_health.record_many(store, self.task_id, "mobile",
                                          res.get("source_status") or {})
                if not kept:
                    why = [f"{ck}·{source_health.text_of(str(cv.get('status') or ''))}"
                           for ck, cv in (res.get("source_status") or {}).items()
                           if isinstance(cv, dict) and str(cv.get("status") or "") != "ok"]
                    self.log("mobile", f"小程序 {t}: 本轮 0 个带 AppID 的结果"
                                       f"（{'、'.join(why[:6]) or '各渠道均无命中'}）")
                for d in res.get("domains") or []:
                    if d and any(same_site(d, r) for r in self._own_roots()):
                        found.add(d)
                    elif d:
                        self.log("mobile", f"  · 小程序侧域 {d} 挂不到已认主体根域，不并入扩线")
                # 小程序包正文里的接口与域名：档案名/主体只是线索，包里才是真的后端面。
                # 直接拉 wechat CDN 上的公开包，不登录、不依赖 key。
                # 取包放在独立协程里：`_consume` 首条 await 之后才读 `found` 的话，
                # 这个名字会退化成空单元，再点到就是 UnboundLocalError。
                if res.get("items"):
                    put(await self._applet_bundles(res.get("items") or []))
            # 渠道面板：这一路取到没有、空在哪一步（搜索没回、主页没身份、商店被拦）。
            # 子渠道（mp:homepage 这类）也各记一行，看得出是检索还是详情页断了。
            items = res.get("items") or []
            note = "；".join((res.get("notes") or [])[:2])[:200]
            status = "ok" if items else source_health.status_of_error(
                "；".join(res.get("notes") or []) or "无结果")
            source_health.record(store, self.task_id, "mobile", kind, status, note, len(items))
            subs: dict[str, int] = {}
            for it in items:
                for s in (it.get("sources") or []):
                    subs[str(s)] = subs.get(str(s), 0) + 1
            for s, n in subs.items():
                if s and s != kind:
                    source_health.record(store, self.task_id, "mobile", f"{kind}:{s}",
                                         "ok", "", n)
            for n in (res.get("notes") or [])[:4]:
                self.log("mobile", f"  · {n}")

        async def _drain(plans: list[tuple[str, str]], label: str) -> None:
            tasks = [asyncio.create_task(_run(t, kind)) for t, kind in plans]
            done = 0
            for fut in asyncio.as_completed(tasks):
                if self.stop_event.is_set():
                    for x in tasks:
                        x.cancel()
                    return
                t, kind, res = await fut
                done += 1
                await _consume(t, kind, res)
                self.progress("mobile", int(done * 40 / len(plans)) if label == "首轮" else 85,
                              f"移动端 {t}（{label}）")

        # 先查 App：应用商店的登记页会带出开发主体全称（如「瑞幸咖啡信息技术（厦门）有限公司」），
        # 这是查小程序最有效的检索词。小程序名检索在品牌词上基本只搜回「同款」营销页，
        # 所以顺序固定为先 App、后小程序——抢 App 的 25s，换小程序那轮有真主体可用。
        await _drain([(t, "app") for t in app_targets[:4]], "首轮")
        if self.stop_event.is_set():
            return

        # 品牌词已经拿到开发主体，剩下的域名形态检索词不必再花一轮；
        # 品牌词一无所获时才用根域兜底（以域名为名的应用确实存在）。
        rest_apps = app_targets[4:]
        if rest_apps and not devs:
            self.log("mobile", f"首轮未读到开发主体，用域名形态补查：{'、'.join(rest_apps)}")
            await _drain([(t, "app") for t in rest_apps], "补查App")

        extra_applets = [d for d in devs if d not in applet_targets][:3]
        if extra_applets:
            self.log("mobile", f"用 App 侧开发主体补查小程序：{'、'.join(extra_applets)}")
        await _drain([(t, "applet") for t in applet_targets] + [(d, "applet") for d in extra_applets],
                     "补查")

        # 公众号放最后一轮：站内检索最容易被限流，前面的 App/小程序结果先落库。
        if mp_targets and not self.stop_event.is_set():
            await _drain([(t, "mp") for t in mp_targets], "公众号")

        # 线上检索只给登记信息；包里才有接口和硬编码钥匙。本机缓存有的先解本机的。
        try:
            put(await self.p1b2_local_mini(parsed))
        except Exception as e:
            self.log("mobile", f"本机小程序解析异常：{type(e).__name__}: {str(e)[:80]}", "warn")

        added = 0
        for d in sorted(found):
            if is_ip(d) or not d:
                continue
            if not self.keep_domain(d):
                continue
            # 移动端带出的域只当「同一主体下的业务域」并线，根域也要认下来，
            # 否则 P2/P3 的根域闸会把它当外人踢掉
            self.claim_root(d, "移动端包 / 应用商店")
            if d not in self.domains:
                self.domains.add(d)
                added += 1
        if added:
            self.log("mobile", f"新增域 {added} 个，并入后续被动收集")
        self.progress("mobile", 100, "小程序 / 公众号 / App 完成")

    async def _applet_bundles(self, items: list[dict]) -> set[str]:
        """拿每个 AppID 的公开包，抽出接口、域名与命中（key/手机号/JDBC 等）。

        包在 servicewechat.com 上按版本号公开可取，不需要登录也不需要 AI。
        抽出来的域名并回流水线继续扩；接口进资产，供后面 web/爬虫阶段直接用。
        """
        appids = [str(ap.get("appid") or "").strip() for ap in items]
        appids = [a for a in dict.fromkeys(appids) if a.startswith("wx")]
        if not appids:
            return set()
        before = len(self.domains)
        sem = asyncio.Semaphore(4)
        found: set[str] = set()

        async def one(appid: str) -> None:
            async with sem:
                if self.stop_event.is_set():
                    return
                try:
                    got = await wxscan.scan_appid(appid)
                except Exception as e:
                    self.log("mobile", f"小程序包解析失败 {appid}: {str(e)[:80]}", "warn")
                    return
            res = got.as_dict()
            if not res.get("files"):
                for n in (res.get("notes") or [])[:1]:
                    self.log("mobile", f"小程序包 {appid} 未取到：{n}")
                return
            for url in (res.get("apis") or [])[:200]:
                self.save_asset({
                    "kind": "api", "url": url, "host": host_of(url) or "",
                    "title": f"小程序接口 {appid}", "sources": f"applet-bundle:{appid}",
                    "extra": {"appid": appid, "version": res.get("version")},
                })
            names = {r["id"]: r["name"] for r in wxscan.RULES}
            hit_n = 0
            for rid, vals in (res.get("hits") or {}).items():
                for val in (vals or [])[:40]:
                    hit_n += 1
                    self.save_asset({
                        "kind": "leak", "url": f"applet:{appid}:{rid}:{val[:60]}",
                        "host": appid, "title": f"{names.get(rid, rid)}（小程序包）",
                        "sources": f"applet-bundle:{appid}",
                        "extra": {"appid": appid, "rule": rid, "value": val},
                    })
            for d in res.get("domains") or []:
                # 包里的后端域要能挂到已认主体根下（`api.xxx.com` → `xxx.com`），
                # 或者本身就是本任务目标域名的变体；否则是包里嵌的 SDK / 第三方服务。
                if d and (any(same_site(d, r) for r in self._own_roots())
                          or any(same_site(d, t) for t in self.targets)):
                    found.add(d)
                elif d:
                    self.log("mobile", f"小程序包 {appid} 域 {d} 不属于本目标，不并入扩线")
            self.log("mobile", f"小程序包 {appid} v{res.get('version') or '?'}: "
                               f"{len(res.get('apis') or [])} 接口 / "
                               f"{len(res.get('domains') or [])} 域名 / {hit_n} 命中")

        await asyncio.gather(*(one(a) for a in appids[:8]))
        self.log("mobile", f"小程序包共抽出 {len(found)} 个域（并入后新增 {len(self.domains) - before}）")
        return found

    async def p1b2_local_mini(self, parsed: dict) -> set[str]:
        """本机微信缓存里的小程序包：离线解包，抽接口/域名/密钥命中。

        线上检索只能拿到小程序的登记名与开发者；真正的后端接口、硬编码 key、
        测试账号都在包里。包已经在微信缓存里时，解包是零请求、零登录的，
        断网也能跑。

        两段式：先整批粗扫（不解包）拿到每个包的标题 / 域名 / 接口，用「包里
        的域挂不挂得到已认主体」加包内标题比对来定性；只对真对上的那几个再解
        包落盘、美化 JS。以前是先拿主体词在包体字节里硬筛，业务名和代码里都
        不写主体词的小程序会被整批丢掉，最后看着就是「一个小程序都没找到」。
        """
        limit = self.opt_scan_local_mini()
        if not limit:
            self.log("mobile", "本机小程序离线解析已在设置里关闭，跳过")
            return set()
        words = self._mini_match_words(parsed)
        target_word = words[0] if words else ""
        out_root = str(DATA_DIR / "applet" / str(self.task_id))
        t0 = time.monotonic()
        self.progress("mobile", 60, "本机小程序包粗扫")
        try:
            rough = await asyncio.to_thread(
                wxscan.scan_local_mini, limit=limit, target=target_word,
                max_pkgs=4, workers=4, unpack=False)
        except Exception as e:
            self.log("mobile", f"本机小程序目录读取失败：{str(e)[:80]}", "warn")
            return set()
        apps = rough.get("apps") or []
        if not apps:
            self.log("mobile", "本机微信缓存里没有小程序包（在微信里打开目标小程序后重跑即可补上）")
            return set()
        own = self._own_roots()

        def _own_doms(app: dict) -> list[str]:
            keep: list[str] = []
            for d in app.get("domains") or []:
                if not d:
                    continue
                if (any(same_site(d, r) for r in own)
                        or any(same_site(d, t) for t in self.targets)):
                    keep.append(d)
            return keep

        picked: list[str] = []
        off: list[str] = []
        for app in apps:
            aid = str(app.get("appid") or "")
            if not aid:
                continue
            # 定性两把尺：包里的域落在已认主体上（最硬），或包内标题/主体/域名
            # 带着本轮的检索词。两把都不占的才是真的别人的小程序。
            if _own_doms(app) or app.get("match") == "high":
                picked.append(aid)
            else:
                off.append(aid)
        if off:
            self.log("mobile", f"本机另有 {len(off)} 个小程序包与本轮主体对不上，已跳过")
        if not picked:
            self.log("mobile", "本机没有与本轮主体相关的小程序包"
                               "（在微信里打开目标小程序后重跑即可补上）")
            return set()
        self.progress("mobile", 66, f"解包本机小程序 {len(picked)} 个")
        try:
            got = await asyncio.to_thread(
                wxscan.scan_local_mini, appids=picked, target=target_word,
                max_pkgs=6, workers=4, out_root=out_root, unpack=True)
        except Exception as e:
            self.log("mobile", f"本机小程序解包失败：{str(e)[:80]}", "warn")
            return set()
        new_domains: set[str] = set()
        names = {r["id"]: r["name"] for r in wxscan.RULES}
        done: list[str] = []
        sums = {"api": 0, "files": 0, "unpacked": 0, "pretty": 0, "hit": 0}
        for app in got.get("apps") or []:
            if self.stop_event.is_set():
                break
            aid = str(app.get("appid") or "")
            apis = app.get("apis") or []
            doms = app.get("domains") or []
            hits = app.get("hits") or {}
            files = int(app.get("files") or 0)
            if not (apis or doms or hits or files):
                why = "；".join([str(x) for x in (app.get("notes") or [])[:2]])[:120]
                self.log("mobile", f"本机小程序 {aid} 没解出内容"
                                   f"{('（' + why + '）') if why else ''}")
                continue
            nm = str(app.get("name") or "").strip()
            subj = str(app.get("subject") or "").strip()
            label = nm or aid
            title = f"小程序 {label}"
            if subj and subj not in (label, aid):
                title += f"（{subj}）"
            if files:
                title += f" · {files} 文件"
            self.save_asset({
                "kind": "applet", "url": f"applet:{aid}", "host": aid, "root_domain": aid,
                "title": title, "sources": "applet-local",
                "extra": {"appid": aid, "name": nm, "subject": subj,
                          "gh_ids": app.get("gh_ids") or [],
                          "version": app.get("version") or "",
                          "encrypted": app.get("encrypted"),
                          "packages": app.get("packages"), "files": files,
                          "bytes": app.get("bytes"),
                          "unpacked": app.get("unpacked"),
                          "pretty": app.get("pretty"),
                          "unpack_dir": app.get("unpack_dir") or "",
                          "pretty_dir": app.get("pretty_dir") or "",
                          "buckets": app.get("buckets") or [],
                          "counts": app.get("counts") or {},
                          "apis": apis[:40], "domains": doms[:40],
                          "notes": app.get("notes")},
            })
            for url in apis[:300]:
                self.save_asset({
                    "kind": "api", "url": url, "host": host_of(url) or "",
                    "title": f"小程序接口 {label}", "sources": f"applet-local:{aid}",
                    "extra": {"appid": aid, "applet": label},
                })
            hit_n = 0
            for rid, vals in hits.items():
                for val in (vals or [])[:40]:
                    hit_n += 1
                    self.save_asset({
                        "kind": "leak", "url": f"applet:{aid}:{rid}:{str(val)[:60]}",
                        "host": aid, "title": f"{names.get(rid, rid)}（小程序包）",
                        "sources": f"applet-local:{aid}",
                        "extra": {"appid": aid, "rule": rid, "value": val,
                                  "applet": label},
                    })
            for d in doms:
                if self.keep_domain(d):
                    new_domains.add(d)
            done.append(label)
            sums["api"] += len(apis)
            sums["files"] += files
            sums["unpacked"] += int(app.get("unpacked") or 0)
            sums["pretty"] += int(app.get("pretty") or 0)
            sums["hit"] += hit_n
            self.log("mobile", f"本机小程序 {label}（{aid}）：{len(apis)} 接口 / "
                               f"{len(doms)} 域名 / {hit_n} 命中 / "
                               f"{files} 文件{'（密文包已解）' if app.get('encrypted') else ''}")
        if done:
            self.log("mobile",
                     f"本机小程序：扫 {len(apps)} 个 → 相关 {len(done)} 个"
                     f"（{'、'.join(done[:6])}），{sums['api']} 接口 / "
                     f"{sums['files']} 文件 / 解包 {sums['unpacked']} 个"
                     f" / 美化 {sums['pretty']} 脚本 / {sums['hit']} 命中，"
                     f"用时 {time.monotonic() - t0:.0f}s")
        return new_domains

    def _mini_match_words(self, parsed: dict) -> list[str]:
        """判断本机小程序包是不是本轮目标的依据：品牌简称、主体名、根域。"""
        words: set[str] = set()
        for k in list(parsed.get("raw") or []) + [parsed.get("brand")]:
            k = (k or "").strip()
            if len(k) >= 2:
                words.add(k)
        for ent in getattr(self, "entities", []) or []:
            for k in (ent.get("brand"), ent.get("name"), ent.get("input")):
                k = (k or "").strip()
                if len(k) >= 2 and not k.startswith("www."):
                    words.add(k)
                short = enterprise._brand(k) if k else ""
                if short and len(short) >= 2:
                    words.add(short)
        for t in parsed.get("domains") or []:
            root = self._root(t)
            if root:
                words.add(root)
                label = root.split(".")[0]
                if len(label) >= 3:
                    words.add(label)
        return sorted(words, key=len, reverse=True)[:20]

    # ───────── P2 被动子域 ─────────
    async def _scoped_roots(self, domains: list[str], stage: str) -> list[str]:
        """按根域扩线前先过归属闸：只留已认自家的根。

        进入 `self.domains` 的域有多种来路：目标、实体扩线、股权子公司、小程序包、
        被动源、IP 反查。只要有一条路把别人的根带进来（实测是移动端与 RDAP 记录），
        后面就会拿整个别人的域去被动扩、字典爆破、扫端口，任务结果里全是别人家
        的资产。这里统一按 `claim_root` 登记过的根筛一遍，没认过的当场记日志丢弃。
        """
        own = self._own_roots()
        roots: list[str] = []
        dropped: list[str] = []
        for d in domains:
            if not d or is_ip(d):
                continue
            r = self._root(d)
            if r and r in own:
                if r not in roots:
                    roots.append(r)
            elif r:
                dropped.append(r)
        if dropped:
            self.log(stage, f"丢弃 {len(dropped)} 个归属未确认的根域，不参与扩线："
                            + "、".join(sorted(set(dropped))[:6]))
        return sorted(roots)

    async def p2_passive(self, domains: list[str]) -> None:
        roots = await self._scoped_roots(domains, "passive")
        enabled, skipped = passive.gate_sources(self.opt("sources") or None)
        # 只重测勾了的那几路被动源；一段都没勾就整段照跑（老行为不变）
        narrowed = [n for n in enabled if not self.sub_on("passive", n)]
        if narrowed:
            for name in narrowed:
                source_health.record(store, self.task_id, "passive", name, "skip",
                                     "本次只重测勾选的数据源，这一路没跑", 0)
            enabled = [n for n in enabled if self.sub_on("passive", n)]
            self.log("passive", f"本次只重测 {len(enabled)} 路被动源，其余 {len(narrowed)} 路跳过")
        if skipped:
            # 停用的源也记一行 skip，面板上能看出「没跑」和「跑了失败」的区别
            for name in skipped:
                source_health.record(store, self.task_id, "passive", name, "skip",
                                     "你停用了这一路，本次没发请求", 0)
            self.log("passive", f"按渠道开关跳过 {len(skipped)} 路被动源", "warn")
        if not enabled:
            self.log("passive", "被动源全部停用，本阶段不出子域", "warn")
            return
        for i, root in enumerate(roots, 1):
            if self.stop_event.is_set():
                return
            self.log("passive", f"[{i}/{len(roots)}] 被动收集 {root}")
            results = await passive.run_domain_sources(root, enabled, respect_channels=False)
            for res in results:
                # 渠道面板：每个源的成败与产出都记一行，超时 / 风控 / 未配置凭据分开算
                source_health.record(
                    store, self.task_id, "passive", res.source,
                    source_health.status_of_error(res.error),
                    res.error, len(res.subdomains) + len(res.records))
                if res.error:
                    self.log("passive", f"  - {res.source}: {res.error}", "warn")
                    continue
                new = 0
                for sub in res.subdomains:
                    if sub not in self.domains and self.keep_domain(sub):
                        # 被动源返回的子域都挂在本次查的根下，根已认 → 子域也认
                        self.claim_root(sub, self.root_owner.get(root) or "被动源")
                        self.domains.add(sub)
                        # 发现即入库：只并进域名池的话，要等 dns 阶段才落库，
                        # 「域名收集」这一段的产出就永远是 0
                        self.save_asset({
                            "kind": "domain", "url": f"domain:{sub}", "host": sub,
                            "root_domain": self._root(sub), "sources": res.source,
                            "extra": {"host": sub, "source": res.source},
                        })
                        new += 1
                self.log("passive", f"  + {res.source}: {len(res.subdomains)} 子域 / "
                                    f"{len(res.records)} 记录（新增 {new}）")
                junk = 0
                for rec in res.records[:3000]:
                    host = (rec.get("domain") or rec.get("host") or "").lower()
                    ip = rec.get("ip") or rec.get("address") or ""
                    if rec.get("via") == "ip_reverse":
                        # IP 反查捞到的是「同一台机器上的站」，只有名字像本目标的才算数：
                        # 共用云主机 / 域名停放 / CNIC 兜底页上的无关域（实测
                        # wildcard.cnnic.cn、随机个人域）以前也会以 domain 入库，
                        # 还把 root_domain 记成本目标的根，结果里凭空多出别家的根域。
                        score = _name_affinity(root, host)
                        if score < 0.6:
                            junk += 1
                            continue
                        self.save_asset({
                            "kind": "domain", "url": f"domain:{host}", "host": host,
                            "ip": str(ip) if is_ip(str(ip)) else None, "root_domain": root,
                            "sources": res.source,
                            "extra": {"host": host, "ip": ip, "source": res.source,
                                      "via": "ip_reverse", "affinity": round(score, 3),
                                      "shared_ip": str(ip),
                                      "location": rec.get("ip138_location"),
                                      "range": rec.get("range")},
                        })
                        if host not in self.domains and self.keep_domain(host):
                            self.domains.add(host)
                            self.log("passive", f"  + IP 反查并入子域：{host}（共用 {ip}）")
                            # 名字像本目标 → 这台机器是目标的落点，进 P5 扫端口；
                            # CDN 边缘节点只代表共享出口，扫它没有意义
                            if ip and is_ip(str(ip)) and not CdnDetector().detect_by_ip(str(ip)):
                                self.ips_candidates.add(str(ip))
                        continue
                    if host and is_ip(host) and is_public_ip(host):
                        # 空间测绘给出的裸 IP:端口
                        port = rec.get("port") or port_of(str(rec.get("raw") or ""))
                        self.save_asset({
                            "kind": "service", "url": f"service:{host}:{port or 0}",
                            "ip": host, "port": int(port or 0),
                            "extra": {"title": rec.get("title"), "source": res.source},
                            "sources": res.source,
                        })
                        for scheme in (("https",) if str(port) in ("443", "8443") else ("http", "https")):
                            if port:
                                self.hosts_to_probe.add(f"{scheme}://{host}:{port}")
                        continue
                    if not host:
                        continue
                    # ip138 这类解析历史里的 IP 就是源站线索：不参与子域扩线，但要进端口/Web 阶段
                    if is_ip(str(ip)) and is_public_ip(str(ip)) and rec.get("kind") in ("current", "history"):
                        self.ips.setdefault(host, set()).add(str(ip))
                        self.hosts_to_probe.add(f"http://{ip}")
                        self.hosts_to_probe.add(f"https://{ip}")
                        self.save_asset({
                            "kind": "ip", "url": f"ip:{ip}", "ip": str(ip), "host": host,
                            "root_domain": root, "sources": res.source,
                            "extra": {"resolved_from": host, "range": rec.get("range"),
                                      "kind": rec.get("kind")},
                        })
                        continue
                    if not self.keep_domain(host):
                        continue
                    extra = {"host": host, "ip": ip, "source": res.source}
                    # RDAP 回的是注册商 + 注册/到期日期：直接挂在域名资产上，
                    # 导出表「Whois」列和详情页就能看到，不用再单独查一遍
                    reg = rec.get("registrar") or ""
                    if isinstance(reg, (list, tuple)):
                        reg = "、".join(str(x) for x in reg if x)
                    ev = rec.get("events") or {}
                    if reg or ev:
                        if reg:
                            extra["whois"] = str(reg)[:200]
                        if ev.get("registration"):
                            extra["whois_created"] = ev.get("registration")
                        if ev.get("expiration"):
                            extra["whois_expires"] = ev.get("expiration")
                    self.save_asset({
                        "kind": "domain", "url": f"domain:{host}", "host": host,
                        "ip": ip if is_ip(str(ip)) else None, "root_domain": root,
                        "port": rec.get("port"), "title": rec.get("title"),
                        "extra": extra,
                        "sources": res.source,
                    })
                if junk:
                    # 丢弃也要留痕：不然「被动阶段合计域名：1」看不出是被过滤砍的
                    self.log("passive", f"  · {res.source}: {junk} 条 IP 反查域名与本目标不相关，已丢弃")
            self.progress("passive", int(i * 100 / len(roots)), f"被动收集 {root}")
            if len(self.domains) > int(self.opt("max_subdomain", 200000) or 200000):
                self.log("passive", "子域数量超过上限，停止被动扩线", "warn")
                break
        self.log("passive", f"被动阶段合计域名：{len(self.domains)}")

    # ───────── P2a 空间测绘 ─────────
    def _space_engines(self) -> list[str]:
        """这次真能查的引擎：有 key、没被关掉、代码里有实现。

        ``scan.space_engines`` 写了就按写的来（仍要过 key 检查），留空用全部就绪引擎。
        """
        sec = config.section("sources") or {}
        want = [str(e).strip().lower() for e in
                (self.opt("space_engines", []) or []) if str(e).strip()]
        out: list[str] = []
        for name in (want or list(space_mod.QUERY_FUNCS)):
            one = sec.get(name) or {}
            if name not in space_mod.QUERY_FUNCS or not space_mod.keys_of(name):
                continue
            if not one.get("enabled", True):
                continue
            if not channels_mod.source_on(name):
                continue
            out.append(name)
        return out

    async def _space_query(self, engines: list[str], query: str, size: int) -> list:
        """一句语法并发打各引擎；正在冷却的引擎这一轮不发，防连着撞墙。"""
        ready: list[str] = []
        for name in engines:
            if await throttle.acquire(name):
                ready.append(name)
            else:
                self.log("space", f"  - {name}: 冷却中，本轮跳过", "warn")
        if not ready:
            return []
        try:
            results = await space_mod.search_many(ready, query, size)
        except Exception as e:
            self.log("space", f"测绘检索异常（{query}）: {e}", "error")
            return []
        for res in results:
            if res.error:
                left = throttle.penalize(res.engine, res.error)
                self.log("space", f"  - {res.engine}: {res.error}"
                                  + (f"，冷却 {left:.0f} 秒" if left else ""), "warn")
            else:
                throttle.reward(res.engine)
        return results

    def _space_take(self, root: str, host: str, rec: dict, engine: str) -> int:
        """把一条测绘记录落成资产：域名并进子域池，裸 IP 记为服务。"""
        raw_port = str(rec.get("port") or "").strip()
        port = int(raw_port) if raw_port.isdigit() else 0
        ip = str(rec.get("ip") or "").split(",")[0].strip()
        title = str(rec.get("title") or "").strip()[:200]

        def _sv(k: str, n: int = 80) -> str:
            return str(rec.get(k) or "").strip()[:n]

        # 测绘平台一次就回了 OS/ISP/归属地/指纹/更新日期，全带进 extra，
        # 导出表和详情页才不用回头再查一遍平台
        extra = {"source": engine, "query_root": root, "title": title,
                 "server": str(rec.get("server") or "").strip()[:120],
                 "protocol": _sv("protocol", 20),
                 "os": _sv("os", 60),
                 "isp": _sv("isp", 80),
                 "product": _sv("product", 80) or _sv("app", 80),
                 "country": _sv("country", 40),
                 "province": _sv("province", 40),
                 "city": _sv("city", 40),
                 "updated": _sv("updated", 32),
                 "icp": _sv("icp", 80),
                 "cname": _sv("cname", 120),
                 "favicon": _sv("favicon_hash", 40),
                 "banner": _sv("banner", 400),
                 "raw": str(rec.get("raw") or "")[:400]}
        if is_ip(host):
            # 命中的是裸 IP：只代表「这台机器暴露了某服务」，共享出口同样会被搜到，
            # 所以只入库、不自动把这台机器塞进端口扫描候选。
            if not is_public_ip(host):
                # 引擎在没查到数据时会把 `0.0.0.0:0` 和防护提示当成一条记录返回
                return 0
            shared = bool(CdnDetector().detect_by_ip(host))
            self.save_asset({"kind": "service", "url": f"service:{host}:{port}",
                             "ip": host, "port": port, "root_domain": root,
                             "title": title or None, "sources": engine,
                             "extra": {**extra, "cdn": shared}})
            if port and not shared:
                scheme = "https" if port in (443, 8443) else "http"
                self.hosts_to_probe.add(f"{scheme}://{host}:{port}")
            return 1
        if not self.keep_domain(host):
            return 0
        self.domains.add(host)
        self.claim_root(host, f"空间测绘·{engine}")
        if is_ip(ip):
            self.ips.setdefault(host, set()).add(ip)
        self.save_asset({"kind": "domain", "url": f"domain:{host}", "host": host,
                         "ip": ip if is_ip(ip) else None, "root_domain": root,
                         "port": port or None, "title": title or None,
                         "sources": engine, "extra": {**extra, "host": host, "ip": ip}})
        if port and port not in (80, 443):
            scheme = "https" if port in (443, 8443) else "http"
            self.hosts_to_probe.add(f"{scheme}://{host}:{port}")
        return 1

    def _rank_roots(self, roots: list[str]) -> list[str]:
        """截断前排序：主目标根最先，其余按已收集到的 host 数降序。

        测绘是按上游资产（根域）反查的，被砍掉一棵根就等于少一整片资产，
        所以让资产最多的根先拿到配额。
        """
        primary = {self._root(t) for t in self.targets if t and not is_ip(t)}
        weight: dict[str, int] = {}
        for d in self.domains:
            if not d or is_ip(d):
                continue
            r = self._root(d)
            if r:
                weight[r] = weight.get(r, 0) + 1
        return sorted(roots, key=lambda r: (0 if r in primary else 1, -weight.get(r, 0), r))

    async def p2a_space(self, domains: list[str]) -> None:
        """拿已确认根域去测绘平台反查：补「域名不解析、但对外暴露过」的资产。"""
        if not self.opt("space_mapping", True):
            self.log("space", "空间测绘阶段已关闭，跳过")
            return
        engines = self._space_engines()
        picked = [n for n in engines if self.sub_on("space", n)]
        if picked != engines:
            self.log("space", "本次只重测选定引擎：" + ("、".join(picked) or "无"))
            if not picked:
                self.progress("space", 100, "勾选的测绘引擎都不可用")
                return
            engines = picked
        # 渠道面板：没参与本轮测绘的引擎也记一行「未启用」，看得出是没 key 还是被关了
        for n in space_mod.QUERY_FUNCS:
            if n not in engines:
                source_health.record(store, self.task_id, "space", n, "skip",
                                     "你停用了这一路" if not channels_mod.source_on(n)
                                     else "未填 key 或已关闭")
        if not engines:
            names = "、".join(space_mod.ENGINE_LABEL.get(n, n) for n in space_mod.QUERY_FUNCS)
            self.log("space", f"没有可用的测绘引擎：{names} 都还没填 key，或已被 enabled: false 关掉。"
                              "到「设置 → 数据源 → 空间测绘引擎」填 key 并点「连通测试」确认账号可用，"
                              "该阶段会自动参与", "warn")
            self.progress("space", 100, "无可用引擎")
            return
        roots = await self._scoped_roots(domains, "space")
        if not roots:
            self.progress("space", 100, "无已确认根域")
            return
        # 0（或负数）= 不截断，把本轮确认的根域全部反查一遍；填正数才启用熔断
        try:
            limit = int(self.opt("space_max_roots", 0) or 0)
        except (TypeError, ValueError):
            limit = 0
        if limit > 0 and len(roots) > limit:
            # 原来是字典序截断，大集团几十个根域时被砍掉的往往是资产最多那几棵
            roots = self._rank_roots(roots)[:limit]
            self.log("space", f"根域 {len(roots)} 棵超过你设的上限，按主目标 + 已收集资产量排序后只查前 {limit} 个；"
                              "被砍掉的根域这一轮不会有新资产。要全查就把「设置 → 采集参数 → 空间测绘 → 根域上限」改成 0",
                     "warn")
        elif limit <= 0:
            self.log("space", f"根域上限已关闭，本轮 {len(roots)} 棵根域全部反查（配额按根域 × 引擎消耗）")
        size = max(20, min(1000, int(self.opt("space_size", 100) or 100)))
        self.log("space", f"空间测绘开始：{len(roots)} 个根域 × {len(engines)} 台引擎"
                          f"（{', '.join(engines)}）")
        total = 0
        denied: set[str] = set()   # 被判 key 无效的引擎
        for i, root in enumerate(roots, 1):
            if self.stop_event.is_set():
                return
            results = await self._space_query(engines, f'domain="{root}"', size)
            for res in results:
                if res.error and space_mod._key_rejected(res.error):
                    denied.add(res.engine)
            hits = sum(len(r.rows) for r in results)
            if hits < 30:
                # 域名维度几乎没结果时，再用证书维度捞「域名已摘掉但证书还带过」的资产
                results += await self._space_query(engines, f'cert="{root}"', size)
            # 渠道面板：每台引擎这轮回了几条、报了什么错
            per_engine: dict[str, list] = {}
            for res in results:
                slot = per_engine.setdefault(res.engine, [0, []])
                slot[0] += len(res.rows)
                if res.error:
                    slot[1].append(res.error)
            for eng, (cnt, errs) in per_engine.items():
                err = (errs or [""])[0]
                # 「请求成功、这家没数据」和「真取到了」是两回事。以前 cnt=0 且无报错
                # 会落到 status_of_error("") 的 ok 上，面板显示「已取到数据」items=0，
                # 看着像引擎坏了又像有数据。
                if cnt:
                    st = "ok"
                elif err:
                    st = source_health.status_of_error(err)
                else:
                    st = "empty"
                source_health.record(store, self.task_id, "space", eng, st, err, cnt)
            seen: set[str] = set()
            local = 0
            for res in results:
                for rec in res.rows:
                    if not isinstance(rec, dict):
                        continue
                    host = str(rec.get("host") or rec.get("domain") or "")
                    host = host.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
                    if not host or host in seen:
                        continue
                    seen.add(host)
                    try:
                        local += self._space_take(root, host, rec, res.engine)
                    except Exception as e:
                        self.log("space", f"入库失败 {host}: {e}", "warn")
            total += local
            self.log("space", f"  [{i}/{len(roots)}] {root}: {hits} 条记录，新增 {local} 条")
            self.progress("space", int(i * 100 / len(roots)), f"空间测绘 {root}")
            if total == 0 and denied.issuperset(set(engines)):
                # 全部引擎都判 key 无效：后面的根域不用再挨个撞，直接收口
                self.log("space", "空间测绘：所有已配置引擎的 key 都被判无效（"
                                  f"{'、'.join(sorted(denied))}），本轮直接跳过。"
                                  "到「设置 → 数据源 → 空间测绘引擎」换 key 并点「连通测试」确认账号可用，"
                                  "下一轮任务会自动参与", "warn")
                break
        self.stats["space"] = total
        self.log("space", f"空间测绘完成：新增 {total} 条资产线索，域名池 {len(self.domains)}")

    # ───────── P3 字典爆破 ─────────
    async def p3_brute(self, domains: list[str]) -> None:
        roots = await self._scoped_roots(domains, "brute")
        dict_name = self.opt("domain_dict", "") or ""
        concurrent = int(self.opt("domain_brute_concurrent", 800) or 800)
        # 根域之间留间隔：一轮两万字典 × 几十个根域连着打，目标侧 DNS 和本机出口都容易被限
        gap = max(0.0, float(self.opt("domain_brute_gap", 0) or 0))
        for i, root in enumerate(roots, 1):
            if self.stop_event.is_set():
                return
            if gap and i > 1:
                await asyncio.sleep(gap)
            self.log("brute", f"字典爆破 {root}（{dict_name}）")
            try:
                found, wildcard = await active.brute_subdomains(root, dict_name, concurrent, self.dns)
            except Exception as e:
                self.log("brute", f"爆破异常 {root}: {e}", "error")
                found, wildcard = {}, set()
            for sub, ips in found.items():
                if not self.keep_domain(sub):
                    continue
                self.domains.add(sub)
                self.ips[sub] = set(ips)
                self.save_asset({"kind": "domain", "url": f"domain:{sub}", "host": sub,
                                 "ip": sorted(ips)[0], "ips": sorted(ips),
                                 "root_domain": root, "sources": "brute"})
            self.log("brute", f"  {root}: 新增 {len(found)}（泛解析 IP {len(wildcard)} 个已剔除）")
            if self.opt("alt_dns", True) and self.domains:
                try:
                    known = [d for d in self.domains if d.endswith(root)]
                    alt = await active.alt_dns_brute(root, known,
                                                     int(self.opt("alt_dns_concurrent", 1500) or 1500),
                                                     self.dns)
                    for sub, ips in alt.items():
                        if sub not in self.domains and self.keep_domain(sub):
                            self.domains.add(sub)
                            self.ips[sub] = set(ips)
                            self.save_asset({"kind": "domain", "url": f"domain:{sub}", "host": sub,
                                             "ip": sorted(ips)[0], "ips": sorted(ips),
                                             "root_domain": root, "sources": "altdns"})
                    self.log("brute", f"  {root}: dnsgen 变体新增 {len(alt)}")
                except Exception as e:
                    self.log("brute", f"  dnsgen 异常: {e}", "warn")
            self.progress("brute", int(i * 100 / len(roots)), f"爆破 {root}")

    # ───────── P4 DNS / CDN ─────────
    async def p4_dns(self, parsed: dict) -> None:
        if self.stop_event.is_set():
            return
        targets = [d for d in self.domains if not is_ip(d)]
        own = self._own_roots()
        outsider = [d for d in targets if self._root(d) not in own]
        if outsider:
            self.log("dns", f"{len(outsider)} 个域不属于已认主体根域，不解析："
                            + "、".join(sorted(outsider)[:6]))
            targets = [d for d in targets if self._root(d) in own]
        cap = int(self.opt("dns_max_targets", 0) or 0)
        if cap > 0 and len(targets) > cap:
            self.log("dns", f"域名数 {len(targets)} 超过本次上限，只解析前 {cap} 个", "warn")
            targets = targets[:cap]
        self.log("dns", f"解析 {len(targets)} 个域名")
        # 邮箱服务商主机（`smtp.xmaj.com` → 腾讯企业邮）：解出来的 IP 是服务商的机器，
        # 记成 IP 资产就是别人的设施；后面 P6 还会去探它的 80/443
        mail = {d for d in targets if d.lower() in self.mail_hosts}
        if mail:
            self.log("dns", f"{len(mail)} 个主机是邮箱服务商服务器，不解析："
                            + "、".join(sorted(mail)[:6]))
            targets = [d for d in targets if d.lower() not in self.mail_hosts]
        cdn = CdnDetector()
        # 解析到内网 / 占位地址的子域：资产表不记这些 IP，但要把域名和地址说出来，
        # 它们本身是「这套子域名指内网」的有效情报
        inner_ips: set[str] = set()
        pending = [d for d in targets if d not in self.ips]
        if pending:
            self.log("dns", f"  待解析 {len(pending)} 个（已有结果 {len(targets) - len(pending)}）")
        results = await self.dns.resolve_many(pending) if pending else {}
        for d in targets:
            res = results.get(d)
            if res:
                self.ips.setdefault(d, set()).update(res.ips)
                self.cnames[d] = res.cnames
            ips = sorted(self.ips.get(d, set()))
            cname = self.cnames.get(d, [])
            cdn_name = cdn.detect(cnames=cname, ips=ips)
            root = self._root(d)
            mail_box = (d.lower() in self.mail_roles or bool(set(ips) & self.mail_provider_ips))
            if mail_box and d.lower() not in self.mail_roles:
                # MX 只写在根域上，smtp/imap/pop 是爆破出来的；按落点 IP 认出同一台邮箱机器
                self.mail_roles.add(d.lower())
            for ip in ips:
                if mail_box and ip in self.mail_provider_ips:
                    # 托管商机器：只用来认这是邮箱落点，不进 IP 资产表
                    continue
                if mail_box and ip in self.mail_web_ips:
                    # 自家邮件主机：机器是本任务的，探 Web，但不报邮件协议端口
                    continue
                if not is_public_ip(ip):
                    # `127.0.0.1` / `169.254.x` / `10.x` 是内网占位或内网泄漏，
                    # 存成 IP 资产只会让端口扫描和存活探测去排永远连不上的地址
                    inner_ips.add(ip)
                    continue
                self.save_asset({"kind": "ip", "url": f"ip:{ip}", "ip": ip, "sources": "dns",
                                 "root_domain": root})
            self.save_asset({
                "kind": "domain", "url": f"domain:{d}", "host": d, "ip": ips[0] if ips else None,
                "ips": ips, "cnames": ",".join(cname), "cdn": cdn_name or None,
                "root_domain": root, "sources": "dns",
            })
        # 显式 IP 目标
        if inner_ips:
            self.log("dns", f"{len(inner_ips)} 个地址是内网 / 保留地址，不进 IP 资产也不扫描："
                            + "、".join(sorted(inner_ips)[:8]))
        want_ptr = bool(self.opt("dns_resolve_ptr", True))
        for ip in parsed["ips"]:
            self.ips.setdefault(ip, set()).add(ip)
            ptrs = await self.dns.resolve_ptr(ip) if want_ptr else []
            for name in ptrs:
                if not self.keep_domain(name):
                    # 云厂商 PTR（`ec2-…amazonaws.com`、`…aliyuncs.com`）只说明机器在谁家，
                    # 不是目标的域，进了清单会一路扩到第三方根域
                    continue
                self.domains.add(name)
                self.ips.setdefault(name, set()).add(ip)
                self.save_asset({"kind": "domain", "url": f"domain:{name}", "host": name, "ip": ip,
                                 "root_domain": self._root(name), "sources": "ptr"})
        # 网段 / 区间展开：CIDR 与两头区间走同一套解析，上限防打爆内存（可配）
        cidr_cap = max(1, int(self.opt("dns_cidr_limit", 1024) or 1024))
        for spec in parsed["cidrs"]:
            hosts = parse_ip_ranges(spec, limit=cidr_cap)
            if not hosts:
                self.log("dns", f"网段 {spec} 无法展开（写法不合法或超出上限）", "warn")
                continue
            self.log("dns", f"网段 {spec} 展开 {len(hosts)} IP")
            for ip in hosts:
                self.ips.setdefault(ip, set()).add(ip)
        resolved = len([d for d, s in self.ips.items() if s])
        self.log("dns", f"解析完成：{resolved} 个有 IP")
        self.progress("dns", 100, "DNS 解析完成")

    # ───────── P5 端口扫描 ─────────
    async def p5_port(self, parsed: dict) -> None:
        want_svc = self.opt("service_probe", True) is not False and self.sub_on("port", "service")
        if not self.sub_on("port", "scan"):
            # 只重测协议指纹：不重扫端口，拿已入库的开放端口重新握手
            rows = store.query_assets(kinds="service,port", task_id=self.task_id, limit=50000)
            probes: list[tuple[str, int]] = []
            for r in rows:
                ip = str(r.get("ip") or "")
                try:
                    port = int(r.get("port") or 0)
                except (TypeError, ValueError):
                    port = 0
                if ip and port in TCP_PROBE_PORTS and self.in_scope(ip):
                    pair = (ip, port)
                    if pair not in probes:
                        probes.append(pair)
            self.log("port", f"只重测协议指纹：跳过端口扫描，用已入库的 {len(probes)} 个端口重新握手")
            if want_svc:
                await self._tcp_probe_services(probes)
            self.progress("port", 100, "协议指纹重测完成")
            return
        if not self.opt("port_scan", True):
            self.progress("port", 100, "端口扫描已跳过（80/443 默认探测）")
            return
        all_ips: set[str] = set()
        own = self._own_roots()
        for ip in parsed["ips"]:
            all_ips.add(ip)
        for d, ips in self.ips.items():
            # 解析表里可能留着别人的域（目标之外的根），它解出来的 IP 不是本目标的落点
            if not is_ip(d) and self._root(d) in own:
                all_ips |= {ip for ip in ips if is_public_ip(ip)}
        # IP 反查带出的共用主机：先扫，它是旁站与同服漏洞的落点
        all_ips |= {ip for ip in (self.ips_candidates or ()) if is_public_ip(ip)}
        all_ips = {ip for ip in all_ips if is_ip(ip)}
        # 只重测指定 IP / 网段时，其余落点本轮不扫
        scoped_ips = {ip for ip in all_ips if self.in_scope(ip)}
        if len(scoped_ips) != len(all_ips):
            self.log("port", f"按本次选定的范围只扫 {len(scoped_ips)} 个 IP（共 {len(all_ips)} 个）")
            all_ips = scoped_ips
        if not all_ips:
            self.progress("port", 100, "无 IP 可扫描")
            return
        # 排除表：用户在目标里写了 `!10.0.0.5` 或策略里配了排除，命中的一律不扫
        excluded = str(self.options.get("port_exclude_ips") or self.opt("port_exclude", "") or "")
        before = len(all_ips)
        all_ips_list = filter_ips(sorted(all_ips), excluded)
        all_ips = set(all_ips_list)
        if before != len(all_ips):
            self.log("port", f"排除 {before - len(all_ips)} 个 IP（排除表命中）")
        if not all_ips:
            self.progress("port", 100, "IP 全部被排除表剔除")
            return
        ptype = self.opt("port_type", "top100")
        ports = effective_ports(ptype, self.opt("port_custom", "") or "",
                                str(self.opt("port_exclude", "") or ""))
        if not ports:
            self.log("port", "端口组被排除表清空，跳过端口扫描", "warn")
            self.progress("port", 100, "无可用端口")
            return
        timeout = float(self.opt("port_timeout", 2) or 2)
        concurrent = int(self.opt("port_concurrent", 300) or 300)
        qps = float(self.opt("port_qps", 0) or 0)
        detect = bool(self.opt("service_detect", True))
        limiter = RateLimiter(qps)
        label = PORT_PRESET_LABELS.get(ptype, ptype)
        # 邮箱服务商服务器整台剔出扫描集：25/110/143/465/587 是服务商自己的设施，
        # 它的整机端口面也不属于本任务资产。剩下的服务商 IP 只留 Web 端口。
        mx_ips = set(self.mail_provider_ips or ())
        # MX 可能晚于域名解析才登记（P1 的邮件 DNS 与 P4 并发不下来）：落点 IP 也要挡
        for d in self.mail_hosts:
            mx_ips |= set(self.ips.get(d) or ())
        if mx_ips & all_ips:
            n_mx = len(mx_ips & all_ips)
            all_ips = all_ips - mx_ips
            self.log("port", f"{n_mx} 个 IP 是邮箱服务商服务器，整台跳过端口扫描")
        self.log("port", f"端口扫描 {len(all_ips)} IP × {len(ports)} 端口（{label}）"
                         + (f"，限速 {qps:.0f} qps" if qps > 0 else ""))
        checkpoint = self._load_port_checkpoint() if self.opt("port_resume", True) else None
        if checkpoint and checkpoint.done:
            self.log("port", f"断点续扫：已有 {len(checkpoint.done)} 条扫描记录")
        sem = asyncio.Semaphore(concurrent)
        done = 0
        ports_per_ip = min(len(ports), 64)      # 每 IP 分片端口，避免 99 端口串行把任务拖死
        scan_errors: list[str] = []

        async def one(ip: str):
            res = []
            ip_ports = port_map.get(ip) or []

            async def try_port(p: int):
                async with sem:
                    if checkpoint is not None and checkpoint.seen(ip, p):
                        return None
                    await limiter.acquire()
                    # 目标侧的 RST / 半开连接会让底层探测抛异常；一个端口失败只跳过这一个，
                    # 不能把整轮端口扫描（乃至任务）判成异常。
                    try:
                        r = await scan_port(ip, p, None, timeout, detect)
                    except Exception as e:
                        scan_errors.append(f"{ip}:{p} {type(e).__name__}")
                        return None
                if checkpoint is not None:
                    checkpoint.mark(ip, p)
                return r

            for i in range(0, len(ip_ports), ports_per_ip):
                if self.stop_event.is_set():
                    break
                chunk = ip_ports[i:i + ports_per_ip]
                batch = await asyncio.gather(*[try_port(p) for p in chunk], return_exceptions=True)
                res.extend(r for r in batch if r is not None and getattr(r, "open", False))
            return ip, res

        targets = sorted(all_ips)
        # 自家邮件主机的 IP 不扫邮件协议端口：25/110/143/465/587/993/995 要么是托管商的，
        # 要么扫完也只是给资产表灌一堆「开放端口」。Web 侧照常扫。
        mail_ips: set[str] = set()
        for d in self.mail_roles:
            mail_ips |= set(self.ips.get(d) or ())
        mail_ips |= set(self.mail_web_ips or ())
        port_map = {}
        for ip in targets:
            port_map[ip] = [p for p in ports if not (ip in mail_ips and p in MAIL_PROTO_PORTS)]
        if mail_ips & all_ips:
            self.log("port", f"{len(mail_ips & all_ips)} 个 IP 是邮件主机，跳过邮件协议端口")
        # 起扫节奏：port_ip_concurrent 控同时扫几台，port_ip_gap 让每台错开一点起步，
        # 免得几千个 IP 在同一毫秒把对端防火墙打到判定为扫描
        ip_concurrent = max(0, int(self.opt("port_ip_concurrent", 0) or 0))
        ip_gap = max(0.0, float(self.opt("port_ip_gap", 0) or 0))
        ip_sem = asyncio.Semaphore(ip_concurrent) if ip_concurrent else None
        if ip_concurrent or ip_gap:
            self.log("port", f"起扫节奏：同时扫 {ip_concurrent or '不限'} 台，"
                             f"每台错开 {ip_gap:g}s")

        async def paced(ip: str, delay: float):
            if delay:
                await asyncio.sleep(delay)
            if ip_sem is None:
                return await one(ip)
            async with ip_sem:
                return await one(ip)

        tasks = [asyncio.create_task(paced(ip, idx * ip_gap))
                 for idx, ip in enumerate(targets)]
        probes: list[tuple[str, int]] = []
        gateways: list[str] = []
        for fut in asyncio.as_completed(tasks):
            ip, results = await fut
            done += 1
            if any(getattr(r, "gateway", False) for r in results):
                # 随机高端口也回握手：这台机器后面的「开放端口」是链路占位，
                # 存进资产表就成了一整屏不存在的 7001/9200/6379
                gateways.append(ip)
                results = []
            for r in results:
                if not r.banner and r.service == "unknown" and not r.is_web:
                    # 端口开了但什么都没说：既不是 Web 也不认得协议，
                    # 空壳行只会让资产表显得「有一堆服务」
                    continue
                self.save_asset({
                    "kind": "port", "url": f"service:{r.ip}:{r.port}", "ip": r.ip, "port": r.port,
                    "extra": {"service": r.service, "banner": r.banner, "is_web": r.is_web},
                    "sources": "portscan",
                })
                self.stats["open_ports"] += 1
                if r.is_web or r.service in ("http", "https"):
                    for scheme in (("https",) if r.port in (443, 8443, 9443) else ("http", "https")):
                        self.hosts_to_probe.add(f"{scheme}://{r.ip}:{r.port}")
                if r.port in TCP_PROBE_PORTS:
                    probes.append((r.ip, r.port))
            if done % 5 == 0:
                self.progress("port", int(done * 100 / max(len(targets), 1)),
                              f"端口扫描 {done}/{len(targets)}")
        if scan_errors:
            self.log("port", f"{len(scan_errors)} 个端口探测被对端重置/超时（示例："
                             f"{'、'.join(scan_errors[:3])}），已跳过，其余端口不受影响", "warn")
        if gateways:
            self.log("port", f"{len(gateways)} 个 IP 对任意端口都回握手（链路占位），"
                             f"开放端口不可信已跳过：{', '.join(gateways[:5])}", "warn")
        self.progress("port", 100, "端口扫描完成")
        if checkpoint is not None:
            self._save_port_checkpoint(checkpoint)

        # 端口探完立刻按协议握手认服务（Redis/Mongo/ZooKeeper/JDWP/Dubbo 等非 HTTP 面）
        if want_svc:
            await self._tcp_probe_services(probes)

    def _port_ckpt_path(self):
        path = DATA_DIR / "tasks" / str(self.task_id) / PORT_CKPT_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _load_port_checkpoint(self) -> ScanCheckpoint:
        """断点续扫：只认本任务上一轮写下的组合，脏行直接跳过。"""
        ckpt = ScanCheckpoint()
        path = self._port_ckpt_path()
        if not path.exists():
            return ckpt
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                ip, _, port = line.strip().partition(" ")
                if ip and port.isdigit():
                    ckpt.mark(ip, int(port))
        except Exception:
            pass
        return ckpt

    def _save_port_checkpoint(self, ckpt: ScanCheckpoint) -> None:
        try:
            path = self._port_ckpt_path()
            tmp = path.with_suffix(".tmp")
            tmp.write_text("\n".join(f"{ip} {p}" for ip, p in sorted(ckpt.done)), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            self.log("port", f"断点写入失败：{exc}", "warn")

    # ───────── P6 存活探测 ─────────
    # ───────── 同段关联判定 ─────────
    def _sibling_related(self, hits: list[dict]) -> tuple[list[dict], int]:
        """同 C 段扫出来的站，按「跟本目标有没有关系」筛一遍。

        C 段是机房的网段，不代表同一家单位：一个 IP 落在腾讯云的回源段上，整段扫下去
        收进来的全是腾讯自己的站，任务里就会出现别人的资产。这里只留能跟本任务主题
        （事业单位/公司名、品牌简称、自家根域、指向同段的自家子域）对得上的，其余丢弃。
        """
        name = (self.targets[0] if self.targets else "") or ""
        keys = self._subject_keys(name)
        own_roots = self._own_roots()
        out: list[dict] = []
        dropped = 0
        for h in hits:
            title = (h.get("title") or "").strip()
            flat = re.sub(r"\s+", "", title).lower()
            hit = False
            if keys and any(k.lower() in flat for k in keys):
                hit = True
            elif own_roots and any(r in flat for r in own_roots):
                hit = True
            if hit:
                out.append(h)
            else:
                dropped += 1
        return out, dropped

    def _subject_keys(self, name: str) -> set[str]:
        """任务主体名 → 站点上可能出现的自称写法（全称、去组织形式、品牌简称）。"""
        if not name or is_ip(name) or is_valid_domain(name):
            return set()
        from .collectors.enterprise import _brand, _name_keys

        keys = set(_name_keys(name))
        brand = _brand(name)
        if brand and len(brand) >= 2:
            keys.add(brand)
        return {k for k in keys if len(k) >= 2}

    async def p6_web(self, parsed: dict) -> None:
        urls: set[str] = set()
        cdn_det = CdnDetector()
        own = self._own_roots()
        in_scope = {d for d in self.domains
                    if is_ip(d) or self._root(d) in own}
        outside = [d for d in self.domains if not is_ip(d) and self._root(d) not in own]
        if outside:
            self.log("web", f"{len(outside)} 个域不属于已认主体根域，不探活："
                            + "、".join(sorted(outside)[:6]))
        for d in in_scope:
            if is_ip(d):
                continue
            urls.add(f"http://{d}")
            urls.add(f"https://{d}")
        for ip in parsed["ips"]:
            urls.add(f"http://{ip}")
            urls.add(f"https://{ip}")
        urls |= {u for u in self.hosts_to_probe
                 if is_ip(host_of(u) or "") or self._root(host_of(u) or "") in own}
        urls = {u for u in urls if normalize_url(u)}
        limit = int(self.opt("probe_limit", 0) or 0) or MAX_PROBE_DEFAULT
        if len(urls) > limit:
            # 先探域名（有意义的为主），再探 IP:端口
            dom_urls = sorted(u for u in urls if not is_ip(host_of(u) or ""))
            ip_urls = sorted(u for u in urls if is_ip(host_of(u) or ""))
            urls = set((dom_urls + ip_urls)[:limit])
            self.log("web", f"URL 数超上限，截取 {limit} 个（可用 probe_limit 调整）", "warn")
        self.log("web", f"存活探测 {len(urls)} 个 URL")
        http_conc = int(self.opt("http_concurrent", 0) or 0) or int(config.get("http", "concurrent") or 100)
        sem = asyncio.Semaphore(http_conc)
        # 备用出口同一时间只放两条：本机代理容量有限，挤在一起反而全部超时
        alt_sem = asyncio.Semaphore(2)
        alt_budget = [int(self.opt("alt_exit_budget", ALT_EXIT_BUDGET) or 0)]
        alt_skipped = [0]
        done = 0
        total = max(len(urls), 1)
        found = 0
        errs: Counter = Counter()
        alive: list[str] = []
        blocked_log: list[str] = []
        # 状态码回填用的对照表：host / ip + 端口 → 探测到的码
        live_marks: list[dict] = []

        def absorb(info) -> None:
            """把一条探测结果并进资产表 / 计数器。主出口与备用出口的结果走同一套判定。"""
            nonlocal found
            if not info:
                return
            if info.error and not info.status:
                errs[info.error.split(":")[0] or "unknown"] += 1
                return
            if not info.status:
                return
            _host = host_of(info.url) or ""
            live_marks.append({
                "host": _host,
                "ip": next(iter(self.ips.get(_host) or ()), "") if _host else "",
                "port": port_of(info.url) or 0,
                "status": info.status,
            })
            found += 1
            # 盾页 / 反代错误页 / 本机抓包代理占位页：有响应但正文不是这个站。
            # 存成 site 会让「拦截页」冒充资产，还会把盾的名字当成指纹与标题。
            why = block_kind(info, info.body)
            if why:
                errs["拦截:" + why.split("(")[0]] += 1
                if len(blocked_log) < 8:
                    blocked_log.append(f"{info.url} {why}")
                host = host_of(info.url) or ""
                if why.startswith("网关占位页"):
                    # 空正文的网关错误不是这个站给的页面：出口没到源站。
                    # 存成 site 会在资产表里留下一堆 502 空壳（还有裸 IP 端口），
                    # 既不是存活站点也不是业务面。
                    return
                # 源站被盾挡住也是「站在」，资产表要留一条，盾名不进标题/指纹。
                # 不留这条，任务里只剩同 C 段邻居和第三方域，看起来像「没检出院里的站」。
                if is_ip(host):
                    # 裸 IP 上的网关占位/代理页说明这台机器不对本任务生效，不当站点存
                    return
                self.save_asset({
                    "kind": "site", "url": normalize_url(info.url) or info.url,
                    "host": host, "port": port_of(info.url),
                    "scheme": info.url.split("://")[0],
                    "title": "", "status_code": info.status, "length": info.length,
                    "server": info.server, "sources": "web",
                    "root_domain": self._root(host) if host and not is_ip(host) else "",
                    "extra": {"waf": why, "final_url": info.final_url,
                              "note": "站点存活，正文被安全防护拦截，需换出口或人工确认"},
                })
                return
            # 裸 IP 上的 400/410/412 是「请求没被业务逻辑接收」的默认回执，标题只有
            # 状态短语本身（`400 Bad Request`）。端口开着不等于有站点，存成 site 只会
            # 把端口号当业务面堆进资产表。401/403 登录墙和 5xx 仍然保留。
            if is_ip(host_of(info.url) or "") and info.status in _BARE_IP_DEAD_STATUS:
                errs["HTTP%s" % info.status] += 1
                return
            # 反代 / 网关的默认错误页（状态码 ≥400 且标题只有一句「出错了」）：
            # 有响应但没有业务内容，存成 site 就是把空壳塞进资产表。
            if is_error_page(info.status, info.title):
                errs["错误页"] += 1
                return
            u = info.final_url or info.url
            host = host_of(info.url) or ""
            root = self._root(host) if host and not is_ip(host) else ""
            # cdn 字段在 ARL 语义里是「域名 CNAME 到了 CDN」，IP 直连探测不参与该判定
            self.save_asset({
                "kind": "site", "url": normalize_url(u) or info.url,
                "host": host, "port": port_of(info.url), "scheme": info.url.split("://")[0],
                "title": info.title, "status_code": info.status, "length": info.length,
                "cdn": "" if is_ip(host) else cdn_det.detect_by_ip(
                    next(iter(self.ips.get(host) or ()), "")),
                "fingerprint": ",".join(info.fingerprint), "server": info.server,
                "root_domain": root, "sources": "web",
                "extra": {"cert": info.cert, "favicon": info.favicon_hash,
                          "final_url": info.final_url, "title": info.title,
                          "fingerprint": info.fingerprint,
                          "cert_org": (info.cert or {}).get("org")},
            })
            alive.append(normalize_url(u) or info.url)
            for san in (info.cert or {}).get("san", []) or []:
                san = san.lower().lstrip("*.")
                if san and root and same_site(san, root) and san not in self.domains \
                        and self.keep_domain(san):
                    self.domains.add(san)

        async def alt_retry(info):
            """目标站活着、但直连出口拿不到正文（本机抓包代理回了 502 / 站点连不上）时换出口。

            不换出口的后果：整站被当「拦截页」丢掉，任务看起来一条资产都没有。
            所以这一步单独起协程，不占主循环：早先在主循环里 await，几十个连不上的
            IP:端口把它堵在队列头上，进度表卡在「存活探测 160/370」不动。
            """
            if alt_budget[0] <= 0:
                alt_skipped[0] += 1
                absorb(info)
                return
            alt_budget[0] -= 1
            async with alt_sem:
                try:
                    alt = await asyncio.wait_for(
                        probe_alt(host_of(info.url) or "", port_of(info.url) or 0),
                        timeout=ALT_EXIT_TIMEOUT + 2)
                except Exception:
                    alt = None
            # 换出口也拿不到正文时，直连那条结果不能丢（连不上的错误计数、盾页判定都要）
            absorb(alt if (alt and alt.status and not _is_proxy_page(alt)) else info)

        async def one(u: str):
            async with sem:
                # 连不上的主机每个都要吃满超时；期间按固定间隔推进度，免得看着像卡死
                try:
                    return await self._with_heartbeat(probe(u), "web", f"存活探测 {done}/{total}")
                except Exception as e:
                    info = HttpInfo(url=u)
                    info.error = f"{type(e).__name__}: {e}"[:200]
                    return info

        tasks = [asyncio.create_task(one(u)) for u in urls]
        alts: list[asyncio.Task] = []
        for fut in asyncio.as_completed(tasks):
            info = await fut
            done += 1
            if info and _need_alt_exit(info) and alt_budget[0] > 0:
                alts.append(asyncio.create_task(alt_retry(info)))
            else:
                absorb(info)
            if done % 20 == 0:
                self.progress("web", int(done * 100 / total), f"存活探测 {done}/{total}")
        # 备用出口还有在跑的，等它们把结果并进来再算存活数
        if alts:
            await asyncio.gather(*alts, return_exceptions=True)
        if alt_skipped[0]:
            self.log("web", f"{alt_skipped[0]} 个连不上的地址未换出口重试（本轮预算 "
                            f"{ALT_EXIT_BUDGET} 条，可用 alt_exit_budget 调整）；"
                            f"被盾挡住的站需要正文时把 http.scan_via_proxy 打开重跑", "warn")
        self.stats["sites"] = found
        # domain / ip / service / api 自己不发 HTTP，按这次探测结果回填状态码，
        # 资产列表才看得出哪一条是活的
        if live_marks:
            hit = store.mark_liveness(self.task_id, live_marks)
            if hit:
                self.log("web", f"状态码回填：{hit} 条域名/端口/接口资产补上存活码")
        # 网关占位页说明出口没到源站：探测方式错了，换出口重跑才拿得到业务站
        gate = sum(v for k, v in errs.items() if k.startswith("拦截:网关占位页"))
        if gate:
            self.log("web", f"{gate} 个地址只拿到网关空响应（出口没到源站）："
                            f"把 http.scan_via_proxy 打开换出口重跑", "warn")
        self.progress("web", 100, f"存活探测完成，存活 {found} 个站点")
        if blocked_log:
            self.log("web", "被盾/代理挡住、未计入站点：" + "；".join(blocked_log), "warn")
            if not found:
                self.log("web", "目标全部被安全防护拦截：说明站是活的，但本机出口拿不到页面正文，"
                                "爬虫/JS 阶段会空跑。需要正文时把 http.scan_via_proxy 打开换出口重跑", "warn")
        self.log("web", f"存活 {found} 个站点")
        # 一个站都没探到时要能看出是目标掐了出口，还是本机网络/代理坏了
        if not found and errs:
            top = "，".join(f"{k} {v}" for k, v in errs.most_common(4))
            self.log("web", f"全部探测失败：{top}。先用同一出口打开一个已知站点确认网络"
                            f"（http.scan_via_proxy 可把探测切到 proxy.url）", "warn")
        # 握手标记：JARM 认同源网关、CSP/HSTS 看信任边界、ASN 判归属。
        # 只读握手，不改页面状态；失败静默跳过。
        if alive and self.opt("handshake_mark", True) and handshake._enabled():
            await self._handshake_marks(alive)

    async def _handshake_marks(self, urls: list[str]) -> None:
        """对存活站点补一层握手特征，结果并进 site 资源的 extra_json。"""
        cap = int(self.opt("handshake_limit", 400) or 400)
        targets = urls[:cap]
        self.log("web", f"握手特征标记 {len(targets)} 个站点")
        sem = asyncio.Semaphore(int(self.opt("handshake_concurrent", 16) or 16))

        async def one(u: str):
            async with sem:
                try:
                    return u, await handshake.mark(u)
                except Exception:
                    return u, None

        marked = 0
        for fut in asyncio.as_completed([asyncio.create_task(one(u)) for u in targets]):
            u, mk = await fut
            if mk is None:
                continue
            row = mk.as_dict()
            if not any((row.get("jarm"), row.get("csp"), row.get("hsts"),
                        row.get("tls_versions"), row.get("asn"))):
                continue
            marked += 1
            self.save_asset({"kind": "site", "url": u, "host": host_of(u) or "",
                             "sources": "handshake",
                             "extra": {"handshake": row,
                                       "jarm_hash": row.get("jarm") or ""}})
            for san in row.get("san") or []:
                san = str(san).lower().lstrip("*.")
                root = self._root(san) if san else ""
                if san and root and same_site(san, root) and san not in self.domains \
                        and self.keep_domain(san):
                    self.domains.add(san)
        self.log("web", f"握手特征命中 {marked} 个站点")
        await self._drop_gateway_assets()

    def _site_urls(self, limit: int = 2000) -> list[str]:
        rows = store.query_assets(kind="site", task_id=self.task_id, limit=limit)
        own = self._own_roots()
        out: list[str] = []
        for r in rows:
            u = str(r.get("url") or "")
            if not u.startswith("http"):
                continue
            h = host_of(u) or ""
            # 同 C 段扫出来的 IP、以及别人的域不在这里爬：爬虫只看自家站的页面和 JS
            if is_ip(h) or self._root(h) in own:
                # 只重测指定 host 时，爬取 / 漏扫 / 深度这些下游阶段也跟着收窄
                if not self.in_scope(h):
                    continue
                out.append(u)
        return out

    async def _drop_gateway_assets(self) -> None:
        """删掉本任务里「链路对任意端口都回握手」的 IP 留下的站点与服务行。

        网关占位主机在端口阶段已经被拦住，但它们早先跑出来的行会留在资产表里：
        裸 IP 上那些 443/8443 二次探活能拿到握手（其实还是链路在应答），存成站点或服务
        就是不存在的业务面。这里按同一判据复核一遍，site 与 service 一起清。
        """
        from .portscan import _control_open

        rows = store.query_assets(kind="site", task_id=self.task_id, limit=2000)
        ips = {str(r.get("host") or "") or (host_of(str(r.get("url") or "")) or "") for r in rows}
        ips = {ip for ip in ips if is_ip(ip)}
        if not ips:
            return
        bad: set[str] = set()
        ordered = sorted(ips)
        hits = await asyncio.gather(*(_control_open(ip, 1.0) for ip in ordered),
                                    return_exceptions=True)
        for ip, ok in zip(ordered, hits):
            if ok is True:
                bad.add(ip)
        if not bad:
            return
        n = sum(store.unlink_task_assets(self.task_id, kind=k, host=ip)
                for ip in bad for k in ("service", "port", "site"))
        self.log("port", f"{len(bad)} 个 IP 对任意端口都回握手（链路占位），"
                         f"从本任务资产里删掉 {n} 条：{', '.join(sorted(bad)[:5])}", "warn")

    # ───────── P7 爬虫 + JS ─────────
    async def p7_crawl(self) -> None:
        urls = self._site_urls()[:80]
        self.log("crawl", f"站点爬虫 {len(urls)} 个")
        sem = asyncio.Semaphore(20)
        done = 0

        async def one(u: str):
            async with sem:
                host = host_of(u) or ""
                root = self._root(host) if not is_ip(host) else ""
                return u, await active.crawl_site(u, max_pages=15, root=root), root

        tasks = [asyncio.create_task(one(u)) for u in urls]
        apis_total = 0
        crawl_blocked: list[str] = []
        for fut in asyncio.as_completed(tasks):
            try:
                u, data, root = await fut
            except Exception as e:
                self.log("crawl", f"爬虫异常: {e}", "warn")
                done += 1
                continue
            done += 1
            host = host_of(u)
            why = data.get("blocked") or ""
            if why:
                crawl_blocked.append(f"{host} {why}")
                # 网关占位页 / 连不上：源站根本没给正文，这条不能当站点存进资产表
                if why.startswith("网关占位页") or not why.startswith(("拦截页", "防护/代理页")):
                    continue
                # 只记一条带原因的 site，不覆盖已有的存活记录（那条有真实状态码与证书）
                if not store.query_assets(kind="site", task_id=self.task_id, host=host, limit=1):
                    self.save_asset({"kind": "site", "url": u, "host": host,
                                     "title": "", "sources": "crawl",
                                     "root_domain": root if not is_ip(host) else "",
                                     "extra": {"blocked": why}})
            for api in data["apis"][:800]:
                path = api
                if "://" in api:
                    # 绝对地址只留 path，主机名单独归到域名资产，别拼成 hosthttps://…
                    try:
                        up = urlparse(api)
                    except Exception:
                        continue
                    path = up.path or "/"
                    if up.hostname and up.hostname != host:
                        if not self._in_scope(up.hostname) or not self.keep_domain(up.hostname):
                            continue
                        self.save_asset({"kind": "domain", "url": f"domain:{up.hostname}",
                                         "host": up.hostname,
                                         "root_domain": self._root(up.hostname),
                                         "sources": "crawl"})
                if not path.startswith("/"):
                    path = "/" + path
                self.save_asset({"kind": "api", "url": f"api:{host}{path}", "host": host,
                                 "root_domain": root, "extra": {"api": path, "page": u},
                                 "sources": "crawl"})
                apis_total += 1
            for d in data["domains"]:
                if not (is_valid_domain(d) or is_ip(d)):
                    continue
                if active.host_filter(d, self._own_roots()):
                    continue
                # 页面里指到别人家（合作方、上级单位）的域只算线索，不进自家资产表
                if not self._in_scope(d):
                    continue
                self.save_asset({"kind": "domain", "url": f"domain:{d}", "host": d,
                                 "root_domain": self._root(d), "sources": "crawl"})
            for js in data["js"][:200]:
                # 第三方脚本（邮箱服务商登录页、验证码、统计）是别人的包，不进自家清单
                if not self._in_scope(host_of(js) or ""):
                    continue
                self.save_asset({"kind": "js", "url": js, "host": host_of(js), "root_domain": root,
                                 "sources": "crawl"})
            for s in data["secrets"][:100]:
                if s.get("type") == "domain":
                    continue
                if not self._in_scope(s.get("where") or host):
                    continue
                self.save_asset({"kind": "leak", "url": f"leak:{s['type']}:{s['value'][:80]}",
                                 "host": host, "root_domain": root,
                                 "extra": s, "sources": "wih"})
            self.progress("crawl", int(done * 100 / max(len(urls), 1)), f"爬虫 {done}/{len(urls)}")
        self.log("crawl", f"爬虫完成：接口 {apis_total} 个")
        if crawl_blocked:
            self.log("crawl", f"{len(crawl_blocked)} 个站点被安全防护挡住、拿不到正文："
                              + "；".join(crawl_blocked[:6])
                              + "。这类站的接口/JS 不在 HTML 里，需要换出口或手工放行后再跑", "warn")
        if self.opt("js_deep_scan", True):
            await self._js_deep_scan()
        self._prune_foreign_pages()
        self.progress("crawl", 100, "爬虫完成")

    async def _js_deep_scan(self) -> None:
        """对已入库的 JS 逐个按 token 解析，补爬虫正则漏掉的接口和硬编码值。

        爬虫是在拼合 HTML 上跑正则，压缩代码里的拼接串（`'/api/'+'user'`）、
        `u = "/x"` 这种间接写法常漏。这里按语法切 token 再取字符串字面量，
        同时把 sourcemap 和演示账号一并收进来。
        """
        rows = store.query_assets(kind="js", task_id=self.task_id, limit=600)
        js_list = [r["url"] for r in rows
                   if str(r.get("url", "")).startswith("http")
                   and self._in_scope(host_of(str(r.get("url", ""))) or "")][:300]
        if not js_list:
            self.progress("crawl", 100, "无 JS 可分析")
            return
        self.log("crawl", f"JS 深度分析 {len(js_list)} 个文件")
        sem = asyncio.Semaphore(int(self.opt("js_fetch_concurrent", 12) or 12))

        async def one(u: str):
            async with sem:
                try:
                    return u, await fetch_text(u, timeout=12)
                except Exception:
                    return u, ""

        api_total = 0
        secret_total = 0
        for fut in asyncio.as_completed([asyncio.create_task(one(u)) for u in js_list]):
            u, text = await fut
            if not text or len(text) < 32:
                continue
            host = host_of(u) or ""
            root = self._root(host) if host and not is_ip(host) else ""
            try:
                apis = beauty.js_apis(text, limit=int(self.opt("js_api_limit", 200) or 200))
                strings = beauty.js_strings(text, limit=120)
            except Exception:
                continue
            for api in apis:
                path = api.split("://", 1)[-1]
                # 绝对地址取其中的 path 部分，主机名归到域名资产
                if "://" in api:
                    try:
                        up = urlparse(api)
                        path = up.path or "/"
                        # 包里写死的第三方绝对地址（邮箱、支付、统计）是别人的接口
                        if up.hostname and up.hostname != host:
                            if not self._in_scope(up.hostname) or not self.keep_domain(up.hostname):
                                continue
                            self.save_asset({"kind": "domain", "url": f"domain:{up.hostname}",
                                             "host": up.hostname,
                                             "root_domain": self._root(up.hostname),
                                             "sources": "js-deep"})
                    except Exception:
                        continue
                self.save_asset({"kind": "api", "url": f"api:{host}{path}", "host": host,
                                 "root_domain": root,
                                 "extra": {"api": path, "from_js": u},
                                 "sources": "js-deep"})
                api_total += 1
            lower = text.lower()
            if "sourcemappingurl" in lower or ".js.map" in lower:
                self.save_asset({"kind": "js", "url": f"{u}.map", "host": host,
                                 "root_domain": root, "sources": "js-deep",
                                 "extra": {"sourcemap_of": u}})
            # 演示账号 / 测试租户：写死在包里的可用身份，比字典试密稳
            for s in strings:
                low = s.lower()
                if len(s) > 120:
                    continue
                if re.search(r"(?:demo|test|guest|admin|default)\w*@", low) or re.search(
                        r"^(?:demo|test|guest)_?(?:user|account|login)$", low):
                    self.save_asset({"kind": "leak",
                                     "url": f"leak:demo:{s[:60]}", "host": host,
                                     "root_domain": root, "sources": "js-deep",
                                     "extra": {"type": "演示账号", "value": s, "from_js": u}})
            # 密钥 / 手机号 / 身份证 / 数据库串：前端包里写死的真实凭据
            try:
                secrets = beauty.js_secrets(text, limit=60)
            except Exception:
                secrets = []
            for sec in secrets:
                self.save_asset({"kind": "leak",
                                 "url": f"leak:js:{sec['type']}:{sec['value'][:60]}",
                                 "host": host, "root_domain": root, "sources": "js-deep",
                                 "extra": {"type": sec["type"], "value": sec["value"], "from_js": u}})
            secret_total += len(secrets)
        self.log("crawl", f"JS 深度分析补出接口 {api_total} 个，敏感信息 {secret_total} 条")

    def _prune_foreign_pages(self) -> int:
        """爬虫顺带打开的非本主体站点，整簇从本任务清掉。

        自家域下会挂着邮箱、托管站这类第三方（mail.xmaj.com 就是邮箱服务商），
        主体识别拿不到它们的归属，C 段阶段又会因为「同段」把它们放行。这里用
        页面标题做最后一道闸：标题里既没有本目标也没有它的简称，就整簇剔除，
        连同它名下爬出来的接口/JS。托管商的通用登录页即使标题带了客户站名也
        不算业务站：它的接口是这家服务商的产品，不是本院的系统。

        判归属先看主机落在哪个根域：本任务已认定的自家根域（`_own_roots`）下的
        子域一律保留，不再拿中文主体词去 `endswith` 主机名——中文永远匹配不上
        `mail.gs.sgcc.com.cn` 这种后缀，会把自家邮件、微信、ftp 站点整簇删光。
        """
        own = self._own_roots()
        keys = [k for k in self._subject_keys((self.targets[0] if self.targets else "") or "")
                if k and len(k) >= 2]
        if not own or not keys:
            # 没有自家根域或没有可用主体词时无从判断，宁可不动
            return 0
        rows = store.query_assets(kind="site", task_id=self.task_id, limit=4000)
        foreign: list[str] = []
        for r in rows:
            h = str(r.get("host") or "")
            title = str(r.get("title") or "")
            if not h or is_ip(h):
                continue
            # 自家根域下的子域：本院自己的系统，标题没写主体词也不算他人页面
            if self._root(h) in own:
                continue
            if not title:
                # 无标题的存活记录（被盾挡住、空壳）先留着，由命中率决定
                continue
            if any(k in title for k in keys):
                # 标题是本院的，但页面是托管商的登录入口：不算本院业务站
                if VENDOR_LOGIN_RE.search(title) or h.split(".", 1)[0].lower() in VENDOR_LOGIN_HOSTS:
                    foreign.append(h)
                continue
            foreign.append(h)
        if not foreign:
            return 0
        removed = 0
        for h in foreign:
            for kind in ("api", "js", "leak", "leakfile", "site", "component"):
                removed += store.unlink_task_assets(self.task_id, kind=kind, host=h)
        self.log("crawl", f"{len(foreign)} 个主机不是本院业务站（他人页面/托管登录入口），"
                          f"整簇剔除 {removed} 条：" + "、".join(foreign[:6]), "warn")
        return removed

    # ───────── P8 敏感文件 ─────────
    async def p8_leak(self) -> None:
        # 敏感文件是站点级的：同一主机只留一个挂载点，把名额让给更多主机
        picks: list[str] = []
        seen: set[str] = set()
        for u in self._site_urls():
            b = active._leak_base(u)
            if not b or b in seen:
                continue
            seen.add(b)
            picks.append(u)
        urls = picks[:80]
        # 只重测勾选的子项；一段都没勾就整段照跑
        want_file = self.sub_on("leak", "file")
        want_git = self.sub_on("leak", "git")
        file_urls = urls if want_file else []
        dict_name = self.opt("file_leak_dict", "file_top_200.txt") or "file_top_200.txt"
        if not want_file:
            self.log("leak", "本次没勾敏感文件，跳过字典探测")
        self.log("leak", f"敏感文件探测 {len(file_urls)} 个站点（{dict_name}）")
        sem = asyncio.Semaphore(8)
        done = 0

        async def one(u: str):
            async with sem:
                return u, await active.file_leak(u, dict_name, 20)

        tasks = [asyncio.create_task(one(u)) for u in file_urls]
        for fut in asyncio.as_completed(tasks):
            try:
                u, hits = await fut
            except Exception:
                done += 1
                continue
            done += 1
            host = host_of(u)
            for h in hits:
                self.save_asset({"kind": "leakfile", "url": h["url"], "host": host,
                                 "status_code": h["status"], "length": h["length"],
                                 "root_domain": self._root(host) if not is_ip(host) else "",
                                 "extra": h, "sources": "fileleak"})
            self.progress("leak", int(done * 100 / max(len(file_urls), 1)),
                          f"敏感文件 {done}/{len(file_urls)}")
        # Git 泄露
        if want_git and config.get("deep", "code_leak"):
            git_hits = await asyncio.gather(*[deep.git_leak(u) for u in urls[:60]],
                                            return_exceptions=True)
            for g in git_hits:
                if isinstance(g, dict) and g:
                    self.save_asset({"kind": "git", "url": g["url"], "host": host_of(g["url"]),
                                     "extra": g, "sources": "git"})
                    self.log("leak", f"  Git 泄露: {g['url']}", "warn")
        self.log("leak", "敏感文件探测完成")
        self.progress("leak", 100, "敏感文件探测完成")

    # ───────── P9 VHost ─────────
    async def p9_vhost(self) -> None:
        rows = store.query_assets(kind="domain", task_id=self.task_id,
                                  limit=max(1, int(self.opt("vhost_max_domains", 5000) or 5000)))
        domains = [r["host"] for r in rows if r.get("host") and not is_ip(r["host"])]
        ip_rows = store.query_assets(kinds="service,port", task_id=self.task_id, limit=500)
        ip_cap = max(1, int(self.opt("vhost_max_ips", 20) or 20))
        # 只重测指定 host / IP 时，碰撞集合跟着收窄
        domains = [d for d in domains if self.in_scope(d)]
        ips = sorted({r["ip"] for r in ip_rows
                      if r.get("ip") and self.in_scope(str(r["ip"]))})[:ip_cap]
        if not ips or not domains:
            self.progress("vhost", 100, "无可用 IP/域名，跳过 VHost")
            return
        self.log("vhost", f"VHost 碰撞 {len(ips)} IP × {len(domains)} 域名")
        done = 0
        for ip in ips:
            hits = await active.vhost_collision(ip, domains)
            done += 1
            for h in hits:
                self.save_asset({"kind": "vhost", "url": f"vhost:{ip}:{h['port']}:{h['host']}",
                                 "ip": ip, "port": h["port"], "host": h["host"], "title": h["title"],
                                 "extra": h, "sources": "vhost"})
                self.hosts_to_probe.add(f"http://{ip}:{h['port']}")
            self.progress("vhost", int(done * 100 / len(ips)), f"VHost {done}/{len(ips)}")
        self.progress("vhost", 100, "VHost 完成")

    # ───────── P9a 子域接管 ─────────
    async def p9a_takeover(self) -> None:
        """CNAME 指向可认领的托管服务、又落回未认领页 → 该子域可被他人抢注接管。

        只在 DNS 阶段真的拿到 CNAME 时才判，不做全网猜测：命中的证据是
        「CNAME 后缀属托管服务」+「正文出现该服务的未认领提示」两条同时成立。
        """
        if self.stop_event.is_set():
            return
        cands: dict[str, set[str]] = {}
        for d, cs in (self.cnames or {}).items():
            for c in cs or []:
                if c and _takeover_service(c):
                    cands.setdefault(d, set()).add(c)
        if not cands:
            # 续跑 / 单独重跑时内存里可能没有 DNS 结果，从已落库的域名资产补
            for r in store.query_assets(kind="domain", task_id=self.task_id, limit=8000):
                host = (r.get("host") or "").strip()
                for c in str(r.get("cnames") or "").split(","):
                    c = c.strip()
                    if host and c and _takeover_service(c):
                        cands.setdefault(host, set()).add(c)
        if not cands:
            self.progress("takeover", 100, "无托管服务 CNAME，跳过子域接管")
            return
        if not self.opt("takeover", True):
            self.progress("takeover", 100, "子域接管已跳过")
            return
        hosts = sorted(cands)
        cap = int(self.opt("takeover_limit", 0) or 0)
        if cap > 0 and len(hosts) > cap:
            self.log("takeover", f"疑似 {len(hosts)} 个，按本次上限只查前 {cap} 个", "warn")
            hosts = hosts[:cap]
        self.log("takeover", f"子域接管排查 {len(hosts)} 个疑似托管 CNAME")
        sem = asyncio.Semaphore(15)
        state = {"done": 0, "hits": 0}

        async def one(host: str) -> None:
            async with sem:
                if self.stop_event.is_set():
                    return
                cname = sorted(cands[host])[0]
                svc = _takeover_service(cname)
                marks = _takeover_markers(svc)
                for u in (f"https://{host}/", f"http://{host}/"):
                    try:
                        info = await probe(u, want_body=True, want_cert=False, timeout=12)
                    except Exception:
                        continue
                    body = (info.body or "").lower()
                    if not body or not any(m in body for m in marks):
                        continue
                    evidence = next(m for m in marks if m in body)
                    self.save_asset({"kind": "takeover", "url": f"takeover:{host}",
                                     "host": host, "status_code": info.status,
                                     "extra": {"cname": cname, "service": svc,
                                               "probe": u, "evidence": evidence,
                                               "final_url": info.final_url, "title": info.title},
                                     "sources": "takeover"})
                    state["hits"] += 1
                    self.log("takeover", f"  可接管: {host} → {svc}（{cname}）", "warn")
                    break
                state["done"] += 1
                self.progress("takeover", int(state["done"] * 100 / max(1, len(hosts))),
                              f"接管排查 {state['done']}/{len(hosts)}")

        await asyncio.gather(*[one(h) for h in hosts])
        self.log("takeover", f"子域接管排查完成，命中 {state['hits']} 个"
                 + ("（建议立即解绑 CNAME）" if state["hits"] else ""))
        self.progress("takeover", 100, f"子域接管 {state['hits']} 个")

    # ───────── P10 旁站 / C 段 ─────────
    async def p10_sibling(self, parsed: dict) -> None:
        if self.stop_event.is_set():
            return
        # 只重测勾选的子项；一段都没勾就整段照跑
        want_ptr = self.sub_on("sibling", "ptr")
        want_cseg = self.sub_on("sibling", "cseg")
        want_asn = self.sub_on("sibling", "asn")
        want_bucket = self.sub_on("sibling", "bucket")
        ip_rows = store.query_assets(kinds="service,port", task_id=self.task_id, limit=800)
        # 只拿本任务自己的落点做旁站：service 表里可能有第三方主机（别的根域解析出来的
        # 或其他阶段顺带写的），拿它们做 C 段会扩到与我们无关的机房
        own = self._own_roots()
        own_addrs: set[str] = set(parsed["ips"])
        for d, addrs in self.ips.items():
            if not is_ip(d) and self._root(d) in own:
                own_addrs |= set(addrs)
        own_addrs |= {ip for ip in (self.ips_candidates or ()) if is_ip(ip)}
        ips = sorted({r["ip"] for r in ip_rows
                      if r.get("ip") and (r["ip"] in own_addrs)})[:15] or parsed["ips"][:15]
        # 只重测指定 IP 时旁站也只就着这几个落点做
        ips = [ip for ip in ips if self.in_scope(ip)]
        cdn_net = CdnDetector()
        if ips:
            clean = [ip for ip in ips if not cdn_net.detect_by_ip(ip)]
            if len(clean) != len(ips):
                self.log("sibling", f"剔除 {len(ips) - len(clean)} 个 CDN/云 IP（不扩散 C 段）")
            ips = clean
        if ips:
            self.log("sibling", f"旁站/C 段 {len(ips)} 个 IP")
            done = 0
            for ip in ips:
                ptrs = await self.dns.resolve_ptr(ip) if want_ptr else []
                for name in ptrs:
                    self.save_asset({"kind": "domain", "url": f"domain:{name}", "host": name,
                                     "ip": ip, "root_domain": self._root(name), "sources": "ptr"})
                # 同 C 段 80/443：只收真正有业务页的，端口开着但套壳/盾页的不算旁站
                if want_cseg and self.opt("sibling", True):
                    found = await active.c_segment_scan(ip, 255, (80, 443), 100, want_title=True)
                    found, dropped = self._sibling_related(found)
                    if dropped:
                        self.log("sibling",
                                 f"  {ip} 同段 {dropped} 个站点与本目标无关联（他人业务页），不入表")
                    for h in found:
                        if not self.keep_domain(h["ip"]):
                            continue
                        self.save_asset({"kind": "sibling", "url": f"service:{h['ip']}:{h['port']}",
                                         "ip": h["ip"], "port": h["port"], "title": h.get("title", ""),
                                         "sources": "csegment",
                                         "extra": {"title": h.get("title", "")}})
                        scheme = "https" if h["port"] == 443 else "http"
                        self.hosts_to_probe.add(f"{scheme}://{h['ip']}:{h['port']}")
                    if found:
                        self.log("sibling", f"  {ip} 同段有效业务页 {len(found)} 个")
                done += 1
                self.progress("sibling", int(done * 100 / len(ips)), f"旁站 {done}/{len(ips)}")
        # ASN 归集：落点 IP 归到持有者 ASN，网段落成资产；成本可控的小段再扫一遍。
        # 同一家单位常把服务摊在同 ASN 的几个 /24 上，只扫落点那一个 C 段会漏掉邻居段。
        if want_asn and ips and self.opt("asn_expand", True):
            try:
                rows = await asnmap.collect(ips[:15], max_prefixes=40)
            except Exception as e:
                rows = []
                self.log("sibling", f"ASN 归集失败：{e}", "warn")
            seen_cidr: set[str] = set()
            asns: set[str] = set()
            for row in rows:
                asn = row.get("asn") or ""
                if not asn:
                    continue
                asns.add(asn)
                for cidr in (row.get("prefixes") or [])[:8]:
                    if cidr in seen_cidr or len(seen_cidr) >= 120:
                        continue
                    seen_cidr.add(cidr)
                    self.save_asset({"kind": "netblock", "url": f"netblock:{cidr}",
                                     "host": cidr, "ip": row.get("ip", ""), "sources": "asn",
                                     "extra": {"asn": asn, "holder": row.get("holder", ""),
                                               "seed_ip": row.get("ip", "")}})
            self.log("sibling", f"ASN 归集 {len(rows)} 个 IP / {len(asns)} 个 ASN / "
                                f"{len(seen_cidr)} 个网段")
            if seen_cidr and self.opt("asn_scan_blocks", True):
                try:
                    limit = int(self.opt("asn_block_limit", 6))
                except Exception:
                    limit = 6
                targets = asnmap.block_base_ips(asnmap.small_blocks(rows, 24, limit), limit)
                self.log("sibling", f"同 ASN 小网段扫描 {len(targets)} 个")
                for n, base in enumerate(targets, 1):
                    if self.stop_event.is_set():
                        break
                    net24 = base.rsplit(".", 1)[0] + ".0/24"
                    found = await active.c_segment_scan(base, 255, (80, 443), 100, want_title=True)
                    found, dropped = self._sibling_related(found)
                    if dropped:
                        self.log("sibling", f"  {net24} 有 {dropped} 个站点与本目标无关联，不入表")
                    for h in found:
                        if not self.keep_domain(h["ip"]):
                            continue
                        self.save_asset({"kind": "sibling", "url": f"service:{h['ip']}:{h['port']}",
                                         "ip": h["ip"], "port": h["port"],
                                         "title": h.get("title", ""), "sources": "asnblock",
                                         "extra": {"title": h.get("title", "")}})
                        scheme = "https" if h["port"] == 443 else "http"
                        self.hosts_to_probe.add(f"{scheme}://{h['ip']}:{h['port']}")
                    if found:
                        self.log("sibling", f"  {net24} 有效业务页 {len(found)} 个")
                    self.progress("sibling", min(99, int(n * 100 / len(targets))),
                                  f"ASN 网段 {n}/{len(targets)}")
        # 存储桶枚举：属主动探测第三方云（推测桶名），默认关，配置 deep.bucket_enum 打开
        roots = sorted({self._root(h) for h in self.domains if h and not is_ip(h)})
        if want_bucket and roots and self._deep_flag("bucket_enum", False):
            buckets = await deep.bucket_enum(roots[:20])
            for b in buckets:
                self.save_asset({"kind": "bucket", "url": b["url"], "host": b["bucket"],
                                 "extra": b, "sources": "bucket"})
                if b.get("public"):
                    self.log("sibling", f"  公开存储桶: {b['url']}", "warn")
        self.progress("sibling", 100, "旁站完成")

    # ───────── P11 深度挖掘 ─────────
    async def p11_deep(self) -> None:
        # 只重测勾选的子项；一段都没勾就整段照跑
        want_code = self.sub_on("deep", "codeleak")
        want_mail = self.sub_on("deep", "email")
        want_git = self.sub_on("deep", "git")
        want_comp = self.sub_on("deep", "component")
        want_cprobe = self.sub_on("deep", "component_probe")
        want_shot = self.sub_on("deep", "screenshot")
        want_nuclei = self.sub_on("deep", "nuclei")
        sites = self._site_urls(500)
        roots = sorted({self._root(h) for h in self.domains if h and not is_ip(h)})
        self.log("deep", f"深度挖掘：{len(sites)} 站点 / {len(roots)} 根域")
        # 深度阶段的开关：单项执行里改的那几项覆盖配置，其余照配置
        deep_opts = dict(config.section("deep"))
        for _k in ("code_leak", "bucket_enum", "credential_lists"):
            deep_opts[_k] = bool(self._deep_flag(_k, deep_opts.get(_k, False)))
        data = {}
        if want_code or want_mail or want_git:
            try:
                data = await deep.deep_collect(sites, self.dns, deep_opts)
            except Exception as e:
                self.log("deep", f"深度挖掘异常: {e}", "warn")
                data = {}
        host_keys = []
        for item in ((data.get("code_leak") or [])[:200] if want_code else []):
            self.save_asset({"kind": "codeleak",
                             "url": f"codeleak:{item.get('engine')}:{item.get('repo') or item.get('url')}",
                             "host": None, "extra": item, "sources": item.get("engine")})
        for item in ((data.get("emails") or [])[:500] if want_mail else []):
            mail_host = item["email"].split("@")[-1].lower()
            if not self.keep_domain(mail_host):
                # 邮件托管在第三方（企业邮 / 云邮）时不进自家域清单，邮件本身仍留档
                self.save_asset({"kind": "email", "url": f"email:{item['email']}",
                                 "host": mail_host, "extra": item, "sources": "email"})
                continue
            self.save_asset({"kind": "email", "url": f"email:{item['email']}",
                             "host": mail_host,
                             "root_domain": self._root(mail_host),
                             "extra": item, "sources": "email"})
        for item in ((data.get("mail_dns") or []) if want_mail else []):
            self.save_asset({"kind": "mailinfo", "url": f"mail:{item.get('root')}",
                             "host": item.get("root"), "root_domain": item.get("root"),
                             "extra": item, "sources": "maildns"})
        for item in ((data.get("git") or []) if want_git else []):
            self.save_asset({"kind": "git", "url": item["url"], "host": host_of(item["url"]),
                             "extra": item, "sources": "git"})
        self.log("deep", f"  代码泄露 {len(data.get('code_leak') or [])} / "
                         f"邮箱 {len(data.get('emails') or [])} / "
                         f"Git {len(data.get('git') or [])}")
        # 组件识别（FineReport / Shiro / 泛微 / xxl-job…）
        self.sites_identified = {}
        if self.opt("component_identify", True) and (want_comp or want_cprobe):
            self.sites_identified = await self._identify_components(sites)
        # 组件未授权访问（Actuator / Druid / Nacos / ES / etcd / Docker…）
        if want_cprobe and self.opt("component_probe", True):
            await self._http_component_probes(sites, self.sites_identified)
        # 截图
        if want_shot and self._deep_flag("screenshot", False) and sites:
            shot_dir = DATA_DIR / "shots" / self.task_id
            picks = [u for u in sites if u.startswith("http")][:30]
            for u in picks:
                fp = await deep.screenshot(u, shot_dir)
                if fp:
                    self.save_asset({"kind": "screenshot", "url": u, "host": host_of(u),
                                     "extra": {"file": fp}, "sources": "playwright"})
            self.log("deep", f"  截图 {len(picks)} 个（存 {shot_dir}）")
        # nuclei
        if want_nuclei and self._deep_flag("nuclei", False) and sites:
            self.log("deep", "  nuclei 复核中…")
            hits = await deep.run_nuclei(
                sites[:200],
                self.opt("nuclei_severity", None) or config.get("deep", "nuclei_severity") or "critical,high")
            for h in hits:
                self.save_asset({"kind": "nuclei", "url": f"nuclei:{h.get('matched')}",
                                 "host": host_of(str(h.get("host") or "")),
                                 "extra": h, "sources": "nuclei"})
            self.log("deep", f"  nuclei 命中 {len(hits)}")
        _ = host_keys
        self.progress("deep", 100, "深度挖掘完成")

    # ───────── 非 HTTP 服务指纹（协议握手）─────────
    async def _tcp_probe_services(self, probes: list[tuple[str, int]]) -> None:
        if not probes:
            return
        self.log("port", f"协议指纹：{len(probes)} 个非 HTTP 端口握手")
        sem = asyncio.Semaphore(20)
        found = 0

        async def one(ip: str, port: int):
            async with sem:
                try:
                    return ip, port, await comp.tcp_probe(ip, port)
                except Exception:
                    return ip, port, []

        tcp_hits: list[tuple[str, int, str]] = []
        for fut in asyncio.as_completed([asyncio.create_task(one(i, p)) for i, p in probes[:2000]]):
            ip, port, hits = await fut
            for h in hits:
                found += 1
                self.save_asset({
                    "kind": "component", "url": f"tcp:{ip}:{port}:{h['app']}", "ip": ip, "port": port,
                    "extra": {"app": h["app"], "detail": h["detail"], "noauth": h.get("noauth")},
                    "sources": "tcp-probe",
                })
                key = self._TCP_CRED.get(h["app"], "")
                if key:
                    tcp_hits.append((ip, port, key))
                if h.get("noauth"):
                    self.log("port", f"  未授权服务 {h['app']} {ip}:{port} — {h['detail']}", "warn")
        if found:
            self.log("port", f"协议指纹命中 {found} 个组件")
        else:
            # 27 条手写探针没认出来：退到 nmap 探针库，把冷门端口上的服务也标出来。
            await self._nmap_service_scan(probes)
        if tcp_hits:
            await self._verify_tcp_credentials(tcp_hits)
        if self._nmap_cred:
            await self._verify_tcp_credentials(self._nmap_cred)
            self._nmap_cred = []

    async def _nmap_service_scan(self, probes: list[tuple[str, int]]) -> None:
        """nmap service-probes 兜底识别：只补标签和版本，命中不等于洞。"""
        if not probes:
            return
        eng = svcmap.engine()
        if not eng.ok:
            return
        sem = asyncio.Semaphore(24)
        hits: list[dict] = []

        async def one(ip: str, port: int) -> None:
            async with sem:
                try:
                    for h in await svcmap.identify(ip, port):
                        hits.append(h)
                except Exception:
                    pass

        self.log("port", f"nmap 探针识别：{len(probes)} 个端口")
        await asyncio.gather(*(one(i, p) for i, p in probes[:3000]))
        named: dict[str, int] = {}
        for h in hits:
            svc = h.get("service") or ""
            prod = h.get("product") or svc
            named[svc] = named.get(svc, 0) + 1
            label = prod + (f" {h['version']}" if h.get("version") else "")
            self.save_asset({
                "kind": "component", "url": f"tcp:{h['target']}:{svc}", "ip": h["target"].split(":")[0],
                "port": h["port"],
                "extra": {"service": svc, "product": h.get("product"), "version": h.get("version"),
                          "os": h.get("os"), "cpe": h.get("cpe"), "probe": h.get("probe")},
                "sources": "nmap-probe",
            })
            key = self._NMAP_CRED.get(svc, "")
            if key:
                self._nmap_cred.append((h["target"].split(":")[0], h["port"], key))
            self.log("port", f"  服务 {label} @ {h['target']}", "info")
        if named:
            top = ", ".join(f"{k}×{v}" for k, v in sorted(named.items(), key=lambda x: -x[1])[:8])
            self.log("port", f"nmap 识别 {len(hits)} 条：{top}")

    # nmap 服务名 → credential.py 的键
    _NMAP_CRED = {"redis": "redis", "postgresql": "postgres", "mysql": "mysql", "mongodb": "mongo"}
    _nmap_cred: list[tuple[str, int, str]] = []

    # 协议指纹里认出的产品名 → credential.py 的键；认不出返回空串，跳过验证
    _TCP_CRED = {"Redis": "redis", "PostgreSQL": "postgres", "MySQL": "mysql", "MongoDB": "mongo"}

    async def _verify_tcp_credentials(self, hits: list[tuple[str, int, str]]) -> None:
        """数据库端口认出产品后，只在用户放了账号库时验一组凭据。"""
        lists_dir = self.opt("credential_lists", "") or ""
        if not lists_dir:
            return
        todo = [(ip, port, key) for ip, port, key in hits if key]
        if not todo:
            return
        seen: set[tuple[str, int, str]] = set()
        uniq = [t for t in todo if not (t in seen or seen.add(t))]
        self.log("port", f"数据库凭据验证：{len(uniq)} 个端口")
        sem = asyncio.Semaphore(4)

        async def one(ip: str, port: int, key: str):
            pairs = cred.load_list(lists_dir, key, limit=1)
            if not pairs:
                return None
            async with sem:
                try:
                    return await cred.verify(f"{ip}:{port}", key, pairs)
                except Exception:
                    return None

        for fut in asyncio.as_completed([asyncio.create_task(one(*t)) for t in uniq]):
            ok = await fut
            if not ok:
                continue
            self.save_asset({
                "kind": "component", "url": ok["url"], "ip": ok["url"].split(":")[0],
                "extra": {"app": ok["app"], "credential_valid": True, "username": ok["username"],
                          "probe": "tcp-credential"},
                "sources": "credential-verify",
            })
            self.log("port", f"  凭据可用 {ok['app']} {ok['url']}（账号 {ok['username']}）", "warn")

    # ───────── 组件识别（认产品，不判洞）─────────
    async def _identify_components(self, urls: list[str]) -> dict[str, list[str]]:
        """认出站点是什么产品；返回 {站点: [组件键…]}，供组件探针挑路径、也给凭据验证定目标。"""
        result: dict[str, list[str]] = {}
        if not urls:
            return result
        self.log("deep", f"组件识别：{len(urls)} 个站点")
        # 同样按站点数放大：识别单站要跑好几组指纹请求，8 条并发在 200+ 站时要磨十分钟
        sem = asyncio.Semaphore(20 if len(urls) > 40 else 8)

        async def one(u: str):
            async with sem:
                try:
                    return u, await asyncio.wait_for(
                        comp_identify.identify(u, port=port_of(u), deep=True), timeout=25)
                except Exception:
                    return u, []

        for fut in asyncio.as_completed([asyncio.create_task(one(u)) for u in urls[:400]]):
            u, rows = await fut
            for h in rows:
                result.setdefault(u, []).append(h["key"])
                self.save_asset({
                    "kind": "component", "url": h["url"], "host": host_of(u),
                    "root_domain": self._root(host_of(u)),
                    "extra": {"app": h["app"], "kind": h["kind"], "evidence": h["evidence"],
                              "probe": h["key"], "identified": True,
                              "next": list(comp_identify.NEXT_PATHS.get(h["key"], ()))},
                    "sources": "component-identify",
                })
                self.log("deep", f"  识别 {h['app']} {h['url']} — {h['evidence']}")
        if result:
            self.log("deep", f"组件识别命中 {sum(len(v) for v in result.values())} 处")
        return result

    # ───────── 组件未授权访问（HTTP）─────────
    async def _http_component_probes(self, urls: list[str],
                                     identified: dict[str, list[str]] | None = None) -> None:
        """对已确认存活的站点打组件探针。

        端口相关组件只在对应端口打；已识别出指纹是某组件时只打它自己的探针，
        避免每站几十条无关请求。
        """
        if not urls:
            return
        self.log("deep", f"组件未授权探测：{len(urls)} 个站点")
        # 站点级并发按站点数放大：每站只有 12 条并发、单请求 4s 上限，
        # 236 站按 8 条并发要跑二十分钟，光这一步就把整个任务拖到「看着像卡死」。
        sem = asyncio.Semaphore(20 if len(urls) > 40 else 8)
        hits = 0
        identified = identified or {}
        done_n = 0

        async def one(u: str):
            async with sem:
                try:
                    prt = port_of(u)
                    return u, await asyncio.wait_for(
                        comp.http_probes(u, port=prt, only=identified.get(u) or None,
                                         timeout=3.0), timeout=45)
                except Exception:
                    return u, []

        for fut in asyncio.as_completed([asyncio.create_task(one(u)) for u in urls[:400]]):
            u, rows = await fut
            done_n += 1
            if done_n % 10 == 0:
                self.progress("deep", int(done_n * 60 / max(1, len(urls[:400]))),
                              f"组件探测 {done_n}/{len(urls[:400])}")
            for h in rows:
                hits += 1
                self.save_asset({
                    "kind": "component", "url": h["url"], "host": host_of(h["url"]),
                    "root_domain": self._root(host_of(h["url"])),
                    "extra": {"app": h["app"], "evidence": h["evidence"], "hint": h["hint"],
                              "severity": h["severity"], "probe": h["key"], "noauth": True},
                    "sources": "component-probe",
                })
                self.log("deep", f"  {h['app']} 免认证 {h['url']} — {h['evidence']}", "warn")
        if hits:
            self.log("deep", f"组件未授权命中 {hits} 处")
        else:
            self.log("deep", "组件未授权：无命中")
        if identified:
            await self._verify_credentials(identified)

    # ───────── 凭据验证（仅用户自备账号库时）─────────
    async def _verify_credentials(self, identified: dict[str, list[str]]) -> None:
        """用户放了账号库，才去验证这些凭据在已识别组件上是否真的可用。"""
        lists_dir = self.opt("credential_lists", "") or ""
        if not lists_dir:
            return
        pairs: dict[str, list[tuple[str, str]]] = {}
        for site, keys in identified.items():
            for k in keys:
                if k in cred.CRED_TARGETS and k not in pairs:
                    pairs[k] = cred.load_list(lists_dir, k)
        todo = {k: v for k, v in pairs.items() if v}
        if not todo:
            self.log("deep", "凭据验证：账号库无匹配项，跳过")
            return
        self.log("deep", f"凭据验证：{len(todo)} 类组件（每类最多 {max(len(v) for v in todo.values())} 组）")
        sem = asyncio.Semaphore(4)
        done = 0

        async def one(site: str, key: str):
            async with sem:
                try:
                    return site, key, await cred.verify(site, key, todo[key])
                except Exception:
                    return site, key, None

        jobs = [asyncio.create_task(one(site, k)) for site, keys in identified.items()
                for k in keys if k in todo]
        for fut in asyncio.as_completed(jobs):
            site, key, ok = await fut
            if not ok:
                continue
            done += 1
            self.save_asset({
                "kind": "component", "url": ok["url"], "host": host_of(site),
                "root_domain": self._root(host_of(site)),
                "extra": {"app": ok["app"], "credential_valid": True, "username": ok["username"],
                          "probe": key},
                "sources": "credential-verify",
            })
            self.log("deep", f"  凭据可用 {ok['app']} {ok['url']}（账号 {ok['username']}）", "warn")
        if done:
            self.log("deep", f"凭据验证命中 {done} 处")

    # ───────── P12 汇总 ─────────
    # ───────── P12 资产变更（与上一轮对比）─────────
    async def p12_assetdiff(self, parsed: dict) -> None:
        """同一根域上一轮已知的 host/URL 与本次对比，新增的标 is_new，并写一份变更快照"""
        _ = parsed
        self.progress("assetdiff", 5, "资产变更对比")
        roots = {self._root(d) for d in self.domains if d and not is_ip(d)}
        if not roots:
            self.progress("assetdiff", 100, "无根域，跳过变更对比")
            return
        snaps = store.list_snapshots(sorted(roots))
        prev_index: dict[str, dict] = {}
        for s in snaps:
            prev_index.setdefault(s["root_domain"], s)   # list_snapshots 已按时间倒序，取最新一条
        cur_by_root: dict[str, set[str]] = {r: set() for r in roots}
        diff_cap = max(1, int(self.opt("assetdiff_limit", 200000) or 200000))
        for r in store.query_assets(task_id=self.task_id, limit=diff_cap):
            host = r.get("host") or ""
            for root in roots:
                if host == root or host.endswith("." + root):
                    cur_by_root[root].add(r["url"])
                    break
        added = 0
        write_snap = bool(self.opt("assetdiff_snapshot", True))
        for root, cur in cur_by_root.items():
            snap = prev_index.get(root)
            if not snap or not cur:
                continue
            try:
                old = set(json.loads(snap["items_json"]) or [])
            except Exception:
                old = set()
            new_items = sorted(cur - old)
            if new_items:
                store.mark_new_many(self.task_id, new_items)
            added += len(new_items)
            if write_snap:
                store.save_snapshot(root, sorted(cur), prev_id=snap["id"],
                                    new_count=len(new_items), task_id=self.task_id)
            if new_items:
                self.log("assetdiff", f"{root}: 新增 {len(new_items)} 条（如 {new_items[0]}）", "warn")
                if not bool(self.opt("assetdiff_notify", True)):
                    continue
                try:
                    from ..notify import notify_new_assets

                    notify_new_assets(root, new_items, self.task_id)
                except Exception as e:
                    self.log("notify", f"新资产通知失败: {e}", "warn")
        # 首轮根域也先记快照，第二轮才有得比
        for root, cur in cur_by_root.items():
            if write_snap and root not in prev_index and cur:
                store.save_snapshot(root, sorted(cur), prev_id=None, new_count=0,
                                    task_id=self.task_id)
        self.stats["new_assets"] = added
        self.progress("assetdiff", 100, f"变更对比完成，新增 {added} 条")

    # ───────── P13 汇总 ─────────
    async def p13_report(self) -> None:
        # 汇总前先合并去重：两张穿透图、各渠道重复捞到的域名/主机在这里归并成一条。
        # 配置了大模型就让它辅助判别名，没配 / 调用失败自动走纯规则。
        try:
            merged = await dedupe.merge_task(self.task_id,
                                             use_ai=bool(self.opt("dedupe_ai", True)))
            if merged.get("removed"):
                self.log("report", f"合并去重：{merged['before']} → {merged['after']} 条"
                                   f"（去掉 {merged['removed']} 条重复 / {merged['groups']} 组"
                                   f"，{'AI 辅助' if 'ai' in merged.get('mode', '') else '规则'}）")
            else:
                self.log("report", f"合并去重：{merged.get('before', 0)} 条资产无重复")
            # 没有重复也要落统计：界面靠这两个字段判断「去重到底跑没跑」，
            # 只在删过东西时才写，任务页会显示成从没去重。
            self.stats["dedupe_removed"] = int(merged.get("removed") or 0)
            self.stats["dedupe_mode"] = merged.get("mode") or "rule"
            self.stats["dedupe_before"] = int(merged.get("before") or 0)
            self.stats["dedupe_after"] = int(merged.get("after") or 0)
        except Exception as e:
            self.log("report", f"合并去重跳过：{str(e)[:120]}", "warn")

        kinds: Counter = Counter()
        # 爬虫 / 深挖新增的 api、domain 行没赶上 web 阶段那次回填，这里再补一遍
        try:
            filled = store.backfill_liveness_from_sites(self.task_id)
            if filled:
                self.log("report", f"状态码补齐：{filled} 条资产按同主机站点回填")
        except Exception as e:
            self.log("report", f"状态码补齐跳过：{str(e)[:100]}", "warn")
        cdn_count = 0
        rows = store.query_assets(task_id=self.task_id, limit=200000)
        for r in rows:
            kinds[r["kind"]] += 1
            if r.get("cdn"):
                cdn_count += 1
        # 资产表的实际条数是最终口径。`self.stats` 是 Counter，这里若用 update 就变成累加，
        # 把运行期间的入库次数再叠一遍，任务页会显示成实际条数的两倍上下。
        for k in self._asset_kinds:
            self.stats[k] = int(kinds.get(k, 0))
        self.stats["cdn_assets"] = cdn_count
        self.stats["elapsed"] = int(time.time() - self.start_ts)
        store.update_task(self.task_id, stats=dict(self.stats))
        self.log("report", f"汇总：{dict(kinds)}")
        self.log("report", f"CDN 资产 {cdn_count} / 耗时 {self.stats['elapsed']}s")
        if self._deep_flag("ai_triage", False) and llm_engine():
            self.log("report", "AI 研判中…")
            try:
                from .ai import AIError, summarize_task  # 延迟导入，避免无关站也加载

                r = await summarize_task(self.task_id,
                                         top_n=int(self.opt("report_top", 40) or 40))
                self.stats["ai_summary"] = r.get("summary") or ""
                store.update_task(self.task_id, stats=dict(self.stats))
                self.log("report", "AI 侦察小结已写入任务（任务详情页 / AI 工坊可见）")
            except AIError as e:
                self.log("report", f"AI 研判跳过：{e}", "warn")
            except Exception as e:
                self.log("report", f"AI 研判失败：{str(e)[:120]}", "warn")
        self.progress("report", 100, "汇总完成")
