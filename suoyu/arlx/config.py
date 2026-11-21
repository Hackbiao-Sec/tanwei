"""ARL-X 配置中心。

所有能力（数据源 key、扫描强度、通知、策略）都走这里；支持：
  * data/config.yaml 持久化
  * 环境变量覆盖（ARLX_FOFA_KEY 等）
  * 热重载（Web 配置页保存后立即生效）
"""

from __future__ import annotations

import copy
import os
import threading
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ARLX_DATA") or (ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA_DIR / "config.yaml"

# 打包进 exe 的凭据种子：首次启动把它填进空配置项，省得用户逐项手填。
# 由 scripts/build_seed.py 从本机 data/config.yaml 生成，产物在 build/ 不进仓库。
SEED_PATH = Path(__file__).resolve().parent / "seed_config.yaml"
SEED_FALLBACK = ROOT / "build" / "seed_config.yaml"

SECRET_PATH = ("key", "secret", "token", "cookie", "password", "sk", "ak", "api_key", "apikey")


def _cast_like(value, ref):
    """按参照值的类型归一；转不了就原样返回，不因配置写歪把服务打挂。"""
    if ref is None or value is None or isinstance(value, type(ref)):
        return value
    try:
        if isinstance(ref, bool):
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return bool(value)
        if isinstance(ref, int):
            return int(str(value).strip() or 0)
        if isinstance(ref, float):
            return float(str(value).strip() or 0)
        if isinstance(ref, str):
            return str(value)
    except (TypeError, ValueError):
        return value
    return value

DEFAULTS: dict = {
    "server": {
        "host": "0.0.0.0",
        "port": 5113,
        "auth": True,
        "secret_key": "",
        "allow_register": False,
    },
    "proxy": {
        # 留空则直连；示例 http://127.0.0.1:7897
        "url": "",
        "sources_via_proxy": False,   # 数据源经代理（可正常访问 Google / GitHub）
        "scan_via_proxy": False,      # 目标探测经代理（内网/国内目标建议关）
    },
    "sources": {
        # relay：中转站（代理商 / 自建转发）根地址，留空走官方；填了就优先用 relay，
        # 官方域名只是默认兜底。api 字段保留兼容，等价于 relay。
        "fofa": {"key": "", "email": "", "relay": "", "api": "https://fofa.info", "size": 1000, "enabled": True},
        "hunter": {"key": "", "relay": "", "api": "https://hunter.qianxin.com", "size": 100, "enabled": True},
        "quake": {"key": "", "relay": "", "api": "https://quake.360.net", "size": 100, "enabled": True},
        "zoomeye": {"key": "", "relay": "", "api": "https://api.zoomeye.org", "enabled": True},
        "shodan": {"key": "", "relay": "", "api": "https://api.shodan.io", "enabled": True},
        "censys": {"id": "", "secret": "", "relay": "", "api": "https://search.censys.io", "enabled": True},
        "virustotal": {"key": "", "relay": "", "api": "https://www.virustotal.com", "enabled": True},
        "securitytrails": {"key": "", "relay": "", "api": "https://api.securitytrails.com", "enabled": True},
        "passivetotal": {"user": "", "key": "", "relay": "", "api": "https://api.riskiq.net", "enabled": True},
        "threatbook": {"key": "", "relay": "", "api": "https://api.threatbook.cn", "enabled": True},
        "chaos": {"key": "", "relay": "", "api": "https://api.projectdiscovery.io", "enabled": True},
        "certspotter": {"key": "", "relay": "", "api": "https://api.certspotter.com", "enabled": True},
        # 0.zone 零零信安：site / domain / app / email 四类检索，免费额度需申请
        "zero_zone": {"key": "", "relay": "", "api": "https://0.zone/api/data/", "enabled": True},
        "github": {"token": "", "relay": "", "api": "https://api.github.com", "enabled": True},
        # 工商主体画像：股权穿透 / 股东 / 对外投资 / 分支机构。两者都要登录态
        "aiqicha": {"cookie": "", "api": "https://aiqicha.baidu.com", "enabled": True},
        # token / tycid 是天眼查网页与 capi 的登录态；open_token 是开放平台 API Key，
        # 填了走官方 API（额度另算），没有就只用网页登录态。
        "tianyancha": {"token": "", "cookie": "", "tycid": "", "open_token": "",
                       "api": "https://c.tianyancha.com", "enabled": True},
        # 其它工商 / 应用数据源：只有需要登录态的那几家才要配 cookie，配了就多一路证据，
        # 没配就跳过并在任务日志里写明白，不影响爱企查与天眼查。
        "qichacha": {"cookie": "", "tycid": "", "api": "https://www.qcc.com", "enabled": True},
        "qcctid": {"cookie": "", "tycid": "", "api": "https://api.qichacha.com", "enabled": True},
        "riskbird": {"cookie": "", "api": "https://www.riskbird.com", "enabled": True},
        "kuaicha": {"cookie": "", "api": "https://www.kuaicha365.com", "enabled": True},
        "qidian": {"cookie": "", "api": "https://www.qidianxin.com", "enabled": True},
        # 小蓝本：网页版接口要求登录态，未登录一律「验签错误」，所以只要 Cookie。
        # token 可选，填了会额外带 Authorization；api 换成镜像地址时改这里。
        "xiaolanben": {"cookie": "", "token": "", "api": "https://sou.xiaolanben.com",
                       "enabled": True},
        # 备案查询（工信部备案库）：接口换地址就填 api；滑块连续失败阈值、冷却时长、
        # 单条重试次数都可在这里调，单项执行时也能临时覆盖。
        "miit": {"api": "", "min_interval": 6.0, "max_interval": 9.0,
                 "retry_times": 4, "fail_limit": 3, "cool_seconds": 180,
                 "freq_cool_seconds": 120, "timeout": 20},
        # 微博：站内搜索要登录态才回用户卡，填一份有效 Cookie 默认值，
        # 单项执行时也可以在「微博登录态 Cookie」里临时覆盖。
        "weibo": {"cookie": "", "api": "https://m.weibo.cn"},
        "chinaz": {"cookie": "", "api": "https://www.chinaz.com", "enabled": True},
        # 应用 / 小程序市场：七麦看总榜与关键词，阿拉丁看小程序榜，appbk 看应用包信息
        "qimai": {"cookie": "", "api": "https://www.qimai.cn", "enabled": True},
        "aldzs": {"cookie": "", "api": "https://www.aldzs.com", "enabled": True},
        "appbk": {"cookie": "", "api": "https://www.appbk.com", "enabled": True},
        "deepseek": {"key": "", "relay": "", "api": "https://api.deepseek.com", "model": "deepseek-chat", "enabled": True},
        "openai": {"key": "", "relay": "", "api": "https://api.openai.com", "model": "gpt-4o-mini", "enabled": False},
    },
    "ai": {
        "engine": "",        # 空=自动（models 第一条，其次 deepseek，再 openai）
        "timeout": 90,
        "temperature": 0.2,
        # 可切换的多套 LLM：[{name, model, base, key, note}]。base 写根地址（不带 /v1）
        "models": [],
    },
    "http": {
        "timeout": 12,
        "concurrent": 100,
        "verify": False,
        "follow_redirects": True,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "max_body": 500000,
    },
    "scan": {
        "domain_brute": True,
        "domain_dict": "domain_2w.txt",
        "domain_brute_concurrent": 800,
        # 根域与根域之间的等待（秒）：字典爆破按根域串行，0 = 不等
        "domain_brute_gap": 0.0,
        "alt_dns": True,
        "alt_dns_concurrent": 1500,
        "port_scan": True,
        # 端口组：enterprise 企业端口 | slim 精简 | top100 常用 | top1000 扩展 | top10 最小 | all 全端口 | custom
        "port_type": "top100",
        "port_custom": "",
        # 排除端口：扫描时从端口组里剔掉（如内网有蜜罐的 22 / 3389）
        "port_exclude": "",
        "port_timeout": 2.0,
        "port_concurrent": 300,
        # 每秒新建连接上限，0 = 不限（只靠并发控制）。对速率敏感的目标用它压住
        "port_qps": 0,
        # 断点续扫：中断后重跑跳过已扫组合，适合全端口 / 大网段
        "port_resume": False,
        # 同时扫几台 IP（0 = 不限，只靠 port_concurrent 控端口级并发）
        "port_ip_concurrent": 0,
        # 每台 IP 起扫前额外等待（秒），给对端防火墙和链路留喘息；0 = 不等
        "port_ip_gap": 0.0,
        "service_detect": True,
        "site_spider": True,
        "file_leak": True,
        "file_leak_dict": "file_top_200.txt",
        "vhost_collision": False,
        "sibling": True,               # 旁站 / C 段
        # ASN 归集：把落点 IP 归到持有者 ASN，网段落成资产；
        # asn_scan_blocks 打开时再扫同 ASN 里 /24 及更小的网段（成本可控的那部分）
        "asn_expand": True,
        "asn_scan_blocks": True,
        "asn_block_limit": 6,          # 单任务最多扫几个小网段
        "fuzz_dict": "dir_default.txt",
        # 组件识别（18 类产品指纹）与未授权探针：命中只说明「是什么」，不等于是洞
        "component_identify": True,
        "component_probe": True,
        # 凭据验证：指向目录（内含 <组件名>.txt，每行 user:pass）；留空=不验证
        "credential_lists": "",
        "dns_source_policy": "all",    # all | arl13 | custom
        # 股权穿透：全资（累计持股 100%）子/孙公司并进目标池；参股只记不挖
        "equity_expand": True,
        "equity_depth": 2,             # 向下穿透层数
        "equity_ratio": 100,           # 入池门槛（累计持股百分比）
        # 最终受益人：股东树按有效持股折算，累计到控制线算控制
        "equity_ubo_threshold": 25,    # 控制线（百分比）；25 是工商常用口径
        "equity_ubo_levels": 1,        # 机构股东往上再穿几层（0 = 不额外请求）
        "equity_ubo_branches": 3,      # 每层最多展开几家机构股东
        "equity_budget": 0,            # 股权穿透允许的工商请求次数（一页 ≈ 100 条，0 = 不限）
        # 每一次工商请求之前额外等待的秒数（穿透防封）。慢节奏拉取是数据完整的前提：
        # 30 秒级（每分钟 2 次）能稳稳跑完几百次请求；调大只会更慢、不会更快。
        # 以前这里是 1.5 秒，赶上集团级主体很容易被判断成抓取，中途被风控吞掉半棵树。
        "equity_sleep": 30.0,
        # 收尾等后台股权穿透的上限（秒）：0 = 不额外设限，由股权阶段自己的总时限收口。
        # 股权是转后台并发的，域名 / 端口 / 网页已经先出，收尾这一段只影响「子公司还没
        # 穿完」。填正数才会到点取消，并留一条 warn 说明这次是被等时上限截断的。
        "equity_join_wait": 0,
        # 主体收集（备案 / 工商 / 反查）：同时补几个根域的主体，1 = 串行（最稳）
        "enterprise_concurrent": 1,
        # 单个企业主体扩线的总时限（秒）。一个省公司级主体要跑检索 + 取证 + 工商，
        # 300 秒只够跑完工商、来不及出域名，现场表现是「主体收集完了，域名一个没有」。
        "enterprise_timeout": 1800,
        # 根域与根域之间额外等待（秒）；备案自身还有 miit 的 6~9 秒间隔
        "enterprise_gap": 0.0,
        # 每次备案查询前额外等待（秒），0 = 用 throttle.per_source.miit 的 6~9 秒
        "icp_gap": 0.0,
        # 本机微信缓存的小程序包：离线解包抽接口/域名/硬编码钥匙，需先在本机微信打开过
        "scan_local_mini": True,
        "scan_local_mini_limit": 20,   # 最多解多少个包
        # 空间测绘：拿已确认根域去各引擎查，补「不解析但对外暴露」的资产（历史解析、旁路入口）
        "space_mapping": True,
        # 留空 = 用配置里已填 key 的全部引擎；也可写死，如 ["fofa","hunter"]
        "space_engines": [],
        "space_size": 100,             # 每个根域每台引擎取多少条
        "space_max_roots": 0,          # 单任务最多查多少个根域；0 = 不限（默认全查，填正数才熔断）
    },
    "deep": {
        # 深度挖掘阶段（对齐参考项目 P5）
        "code_leak": True,             # Bing / Sourcegraph / grep.app / GitHub 代码泄露
        "email_harvest": True,         # 邮箱 / 联系人收集
        "mail_dns": True,              # MX / SPF / DMARC / DKIM
        "bucket_enum": False,          # 存储桶枚举：会向 aws/aliyun/tencent 发大量推测请求，默认关
        "screenshot": False,           # Playwright 截图（需本机安装 playwright）
        "nuclei": False,               # 调用本地 nuclei
        "nuclei_path": "nuclei",
        "nuclei_severity": "critical,high",
        "ai_search": False,            # AI 扩展搜索关键词（需 deepseek/openai key）
        "ai_triage": True,             # 任务结束 AI 研判：资产 / 泄露按风险排序并写结论
    },
    "mobile": {
        # 包体静态分析：内置解析常开，外部反编译器按需勾选
        "deep": True,                  # 清单树 / 权限 / 导出组件 / 深链 / dex 字符串池
        "jadx": False,                 # 附加源码反编译，慢，需先装 jadx
        "apktool": False,              # 附加资源解包，需先装 apktool
    },
    "notification": {
        "webhook": "",
        "dingtalk": "",
        "feishu": "",
        "wecom": "",
        "on_task_done": True,
        "on_new_asset": True,          # 相对上一轮快照出现新资产时推送（周期任务场景主力）
    },
    "throttle": {
        # 要登录态的工商 / 备案 / 测绘站点：请求之间必须歇，否则很快会被判风控
        "enabled": True,
        "min_interval": 1.5,           # 同来源两次请求最小间隔（秒）
        "max_interval": 4.0,           # 上限；实际间隔在两者之间随机
        "concurrent": 1,               # 同来源并发上限
        "risk_threshold": 3,           # 连续命中风控几次后熔断
        "cooldown": 60,                # 首次熔断冷却秒数，之后逐次翻倍
        "cooldown_max": 900,           # 冷却封顶
        # 单来源覆盖；没写的走上面的全局值
        "per_source": {
            "aiqicha": {"min_interval": 2.5, "max_interval": 6.0},
            "tianyancha": {"min_interval": 2.5, "max_interval": 6.0},
            "qichacha": {"min_interval": 3.0, "max_interval": 7.0},
            "riskbird": {"min_interval": 2.5, "max_interval": 6.0},
            "kuaicha": {"min_interval": 2.5, "max_interval": 6.0},
            "qidian": {"min_interval": 2.5, "max_interval": 6.0},
            "zero_zone": {"min_interval": 1.0, "max_interval": 2.5},
            "miit": {"min_interval": 6.0, "max_interval": 9.0},
        },
    },
    "policy": {
        "scope_keywords": [],          # 名称黑名单：命中即剔除（ARL 同款）
        "exclude_domains": [],         # 域名黑名单
        "only_root_domain": False,     # 仅收集目标根域
        "allowed_suffix": "",          # 只收集指定后缀
        "max_subdomain": 200000,
        "cdn_exclude": True,           # 剔除 CDN 反解域名
    },
    "schedule": {
        "enabled": False,
        "default_interval_hours": 24,
    },
    # 数据渠道总开关：默认全开，停用的渠道 key 写进 off。
    # 与 sources.<名>.enabled 并存 —— 任一为关就不发请求；这里是「整类渠道」的
    # 显式停用表，采集流程读到它就给这一路记一行「未启用」。
    "channels": {"off": []},
    # 打包种子版本号：内部字段，记录本机配置被预填到哪一版，不对外展示。
    "seed": {"rev": 0},
}


def _deep_merge(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return not value
    return False


def _fill_empty(target: dict, patch: dict, skip: tuple = ()) -> bool:
    """只往空格里填：已有值一律不动，避免覆盖用户自己改过的配置。"""
    changed = False
    for key, value in (patch or {}).items():
        if key in skip:
            continue
        current = target.get(key)
        if isinstance(value, dict):
            if isinstance(current, dict):
                changed = _fill_empty(current, value) or changed
            else:
                target[key] = copy.deepcopy(value)
                changed = True
            continue
        if _is_blank(value) or not _is_blank(current):
            continue
        target[key] = copy.deepcopy(value)
        changed = True
    return changed


def _seed_fill(data: dict) -> bool:
    """把打包种子里的凭据填进空配置，返回是否要立即落盘。

    带版本号：种子 rev 比配置里记的新才跑一次。用户之后在设置页清空的项
    不会被下次启动又填回来，想重新预置就删掉 config.yaml 里的 seed.rev。
    """
    seed_file = SEED_PATH if SEED_PATH.exists() else SEED_FALLBACK
    if not seed_file.exists():
        return False
    try:
        seed = yaml.safe_load(seed_file.read_text(encoding="utf-8")) or {}
    except Exception:
        return False
    if not isinstance(seed, dict):
        return False
    rev = int((seed.get("seed") or {}).get("rev") or 0)
    if rev <= 0 or rev <= int((data.get("seed") or {}).get("rev") or 0):
        return False
    _fill_empty(data, seed, skip=("seed",))
    data.setdefault("seed", {})["rev"] = rev
    return True


class ConfigStore:
    def __init__(self, path: Path = CONFIG_PATH) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._data: dict = copy.deepcopy(DEFAULTS)
        self.reload()

    # ───────── 读写 ─────────
    def reload(self) -> None:
        with self._lock:
            data = copy.deepcopy(DEFAULTS)
            if self.path.exists():
                try:
                    raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
                    if isinstance(raw, dict):
                        data = _deep_merge(data, raw)
                except Exception:
                    pass
            seeded = _seed_fill(data)
            data = self._env_override(data)
            if not data["server"].get("secret_key"):
                import secrets

                data["server"]["secret_key"] = secrets.token_hex(32)
            self._data = data
            if seeded:
                # 预置值落盘一次，设置页里能看到、也能直接改
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                                     encoding="utf-8")

    def _env_override(self, data: dict) -> dict:
        mapping = {
            "ARLX_FOFA_KEY": ("sources", "fofa", "key"),
            "ARLX_HUNTER_KEY": ("sources", "hunter", "key"),
            "ARLX_QUAKE_KEY": ("sources", "quake", "key"),
            "ARLX_ZOOMEYE_KEY": ("sources", "zoomeye", "key"),
            "ARLX_SHODAN_KEY": ("sources", "shodan", "key"),
            "ARLX_VT_KEY": ("sources", "virustotal", "key"),
            "ARLX_ST_KEY": ("sources", "securitytrails", "key"),
            "ARLX_GITHUB_TOKEN": ("sources", "github", "token"),
            "ARLX_DEEPSEEK_KEY": ("sources", "deepseek", "key"),
            "ARLX_OPENAI_KEY": ("sources", "openai", "key"),
            "ARLX_FOFA_RELAY": ("sources", "fofa", "relay"),
            "ARLX_HUNTER_RELAY": ("sources", "hunter", "relay"),
            "ARLX_QUAKE_RELAY": ("sources", "quake", "relay"),
            "ARLX_ZOOMEYE_RELAY": ("sources", "zoomeye", "relay"),
            "ARLX_SHODAN_RELAY": ("sources", "shodan", "relay"),
            "ARLX_LLM_RELAY": ("sources", "deepseek", "relay"),
            "ARLX_ZERO_ZONE_KEY": ("sources", "zero_zone", "key"),
            "ARLX_PROXY": ("proxy", "url"),
        }
        for env, path in mapping.items():
            val = os.environ.get(env)
            if val:
                node = data
                for p in path[:-1]:
                    node = node.setdefault(p, {})
                node[path[-1]] = val
        return data

    def get(self, *path, default=None):
        node = self._data
        for p in path:
            if not isinstance(node, dict) or p not in node:
                return default
            node = node[p]
        return node

    def section(self, name: str) -> dict:
        return copy.deepcopy(self._data.get(name) or {})

    def all(self) -> dict:
        return copy.deepcopy(self._data)

    def persist(self, patch: dict) -> dict:
        """合并写盘；打码值（含 *）不覆盖原值"""
        with self._lock:
            clean = self._strip_masked(patch)
            return self._save(clean)

    def _save(self, clean: dict) -> dict:
        merged = _deep_merge(self._data, self._coerce(clean))
        self._data = merged
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(merged, allow_unicode=True, sort_keys=False),
                             encoding="utf-8")
        return merged

    def replace_section(self, name: str, value: dict) -> dict:
        """整段替换配置段（不做深合并）。

        深合并只会加键不会删键，需要「把某个来源恢复默认」这类删除语义时走这里。
        """
        with self._lock:
            data = copy.deepcopy(self._data)
            data[name] = copy.deepcopy(value or {})
            self._data = data
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                                 encoding="utf-8")
            return data

    def _coerce(self, patch: dict, base: dict | None = None, ref: dict | None = None) -> dict:
        """浏览器传来的数字是字符串，按默认值的类型归一，落盘后读出来就是数字。"""
        base = self._data if base is None else base
        ref = DEFAULTS if ref is None else ref
        out = {}
        for k, v in (patch or {}).items():
            sub_ref = ref.get(k) if isinstance(ref, dict) else None
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                out[k] = self._coerce(v, base[k], sub_ref if isinstance(sub_ref, dict) else {})
                continue
            out[k] = _cast_like(v, sub_ref)
        return out

    def _strip_masked(self, patch: dict, base: dict | None = None) -> dict:
        base = self._data if base is None else base
        out = {}
        for k, v in (patch or {}).items():
            if isinstance(v, dict):
                out[k] = self._strip_masked(v, base.get(k) or {})
                continue
            if isinstance(v, list):
                out[k] = self._strip_list(v, base.get(k))
                continue
            if isinstance(v, str) and v and set(v) == {"*"}:
                continue
            out[k] = v
        return out

    def _strip_list(self, value: list, base) -> list:
        """列表里被打码的值按原条目找回（先按 name 对，再按下标）。

        ``_deep_merge`` 对列表是整段替换，打码键不能像 dict 那样直接丢掉，
        否则设置页一保存，``ai.models[].key`` 就被写成 ``********``。
        """
        old = base if isinstance(base, list) else []
        out = []
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                # 字符串条目（如 cookie_pool: ["ck1", "ck2"]）打码后按原下标还原
                if isinstance(item, str) and item and set(item) == {"*"} and i < len(old):
                    out.append(old[i])
                else:
                    out.append(item)
                continue
            ref = None
            name = item.get("name")
            if name:
                ref = next((o for o in old if isinstance(o, dict) and o.get("name") == name), None)
            if ref is None and i < len(old) and isinstance(old[i], dict):
                ref = old[i]
            ref = ref or {}
            merged = self._strip_masked(item, ref)
            for k, orig in ref.items():
                if k in merged:
                    continue
                if isinstance(item.get(k), str) and set(item.get(k) or "") == {"*"}:
                    merged[k] = orig
            out.append(merged)
        return out

    # ───────── 打码输出 ─────────
    def masked(self) -> dict:
        def walk(node, key=""):
            if isinstance(node, dict):
                return {k: walk(v, k) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v, key) for v in node]
            if isinstance(node, str) and any(s in key.lower() for s in SECRET_PATH) and node:
                return "*" * min(len(node), 8)
            return node

        out = walk(self.all())
        # seed 是预置种子的内部版本号，不进前端、也不会被设置页回写
        out.pop("seed", None)
        return out

    def source_enabled(self, name: str) -> bool:
        sec = self.get("sources", name) or {}
        if not sec.get("enabled", True):
            return False
        key = sec.get("key") or sec.get("token") or sec.get("secret")
        return bool(key)


def _norm_base(url: str) -> str:
    url = (url or '').strip().rstrip('/')
    if url and not url.lower().startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def src_base(name: str, fallback: str) -> str:
    """数据源根地址：relay（中转站）优先，否则 api，再否则官方兜底。"""
    sec = config.get('sources', name) or {}
    return _norm_base(sec.get('relay') or sec.get('api') or fallback)


def ai_models() -> list[dict]:
    """``ai.models``：可切换的多套大模型，一条 = {name, model, base, key, note}。

    base 统一存根地址（不带 ``/v1``），调用方自己拼 ``/v1/chat/completions``；
    配置里照抄别处带 ``/v1`` 的写法也接得住，这里会削掉，免得拼成 ``/v1/v1/``。
    """
    raw = config.get('ai', 'models') or []
    if isinstance(raw, dict):           # 也允许写成 name: {...} 的字典
        raw = [dict(v, name=v.get('name') or k) for k, v in raw.items() if isinstance(v, dict)]
    out: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or item.get('model') or '').strip()
        model = str(item.get('model') or '').strip()
        key = str(item.get('key') or item.get('api_key') or '').strip()
        if not (name and model and key):
            continue
        base = _norm_base(item.get('base') or item.get('base_url') or '')
        if base.lower().endswith('/v1'):
            base = base[:-3].rstrip('/')
        out.append({'name': name, 'model': model, 'key': key, 'base': base,
                    'note': str(item.get('note') or '')})
    return out


def llm_engine() -> dict:
    """当前生效的 LLM：{name, key, base, model}；没有可用 Key 时返回 {}。

    优先级：``ai.engine`` 点名的 ``ai.models`` 条目 → ``ai.models`` 第一条 →
    原来的 ``sources.deepseek`` / ``sources.openai``（老配置继续能用）。
    """
    official = {"deepseek": "https://api.deepseek.com", "openai": "https://api.openai.com"}
    default_model = {"deepseek": "deepseek-chat", "openai": "gpt-4o-mini"}
    picks = ai_models()
    by_name = {p['name']: p for p in picks}
    want = str(config.get("ai", "engine") or "").strip()
    chosen = by_name.get(want) if want else (picks[0] if picks else None)
    if chosen:
        return {"name": chosen['name'], "key": chosen['key'],
                "base": chosen['base'] or official.get(chosen['name'], "https://api.openai.com"),
                "model": chosen['model']}
    order = [want, "deepseek", "openai"]
    seen: set[str] = set()
    for name in order:
        if not name or name in seen:
            continue
        seen.add(name)
        sec = config.get("sources", name) or {}
        if not sec.get("key"):
            continue
        return {"name": name, "key": sec["key"],
                "base": src_base(name, official.get(name, "https://api.openai.com")),
                "model": sec.get("model") or default_model.get(name, "gpt-4o-mini")}
    return {}


config = ConfigStore()
