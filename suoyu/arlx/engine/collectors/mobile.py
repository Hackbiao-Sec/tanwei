"""App 采集（Android / iOS，新增能力，ARL 与 ARL-Next2 都没有）。

思路：应用商店是最公开的"包名 → 主体"索引，包名是最干净的"域名 → 主体"反面证据。
    应用名 / 包名 → 应用市场详情页 → 包名 / 开发者 / 官网 → 包内域名与第三方 SDK
                                                    → 开发者名再走企业主体扩线

分层，任何一层缺失都不阻塞：
  1. **公开市场检索（不需要 key、不需要 AI）**
     · Google Play：`play.google.com/store/search?q=…&c=apps`，详情页带 developer / website
     · App Store：iTunes 公开 Search API（`itunes.apple.com/search`，免费无 key），给 bundleId / sellerName
     · 国内渠道（应用宝 / 华为 / 小米 / OPPO / vivo / 豌豆荚）：公开检索页解析包名，失败只记 notes
     · 多引擎：`{名称} apk 下载` / `{名称} app 官网` 里出现的 `package=` 或 `com.xxx` 形态包名
  2. **包体静态提取（本机有工具才开，没有就降级）**
     · 本地已有 apk/ipa → zipfile 解出 AndroidManifest.xml（二进制 XML 里的字符串池可直接抽域名）
       与 assets / res 里的字符串，抽域名 + 签名证书 SHA256
     · 可选联网下载渠道：只走用户自填的 apk 镜像前缀（config.mobile.apk_mirror），不猜镜像
  3. **证书 / 第三方 SDK**
     · 包内域名按 `_KNOWN_SDK` 归类，报告里区分"自有域"和"第三方 SDK 域"，避免噪声灌进资产库

产出：
  * kind=mobile  一条应用一个资产（包名 / bundleId / 开发者 / 市场链接 / 证书 / SDK 域名）
  * kind=domain  自有域交给主流水线
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import io
import json
import re
import threading
import zipfile
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import httpx

from ...utils import is_valid_domain, root_domain, run_blocking
from .. import naming
from ..sources import search as web
from ..sources.passive import _get
from . import apkstatic


def _cfg_flag(key: str) -> bool:
    """读 mobile.* 开关。默认关：反编译慢，清单 + 字符串面已够抽接口。"""
    try:
        from ...config import config
        return bool(config.get("mobile", key, default=False))
    except Exception:
        return False


def _deep_mode() -> tuple[bool, bool, bool]:
    """(deep, jadx, apktool)。

    deep 是内置解析，关掉只留包名和文件清单；jadx / apktool 是附加层，慢且依赖外部工具，
    由用户在设置里按需勾。默认只开 deep。
    """
    return _cfg_flag("deep"), _cfg_flag("jadx"), _cfg_flag("apktool")

PKG_ANDROID = re.compile(r"\b((?:[a-z][a-z0-9_]{1,30}\.){2,6}[a-z][a-z0-9_]{1,30})\b")
BUNDLE_IOS = re.compile(r"\bbundleId\s*:\s*[\"']([A-Za-z0-9.\-]{6,80})[\"']")

# 小程序/应用里必现的第三方域，不能当目标：统计、推送、地图、CDN、登录 SDK
# 企业核名里的「集团、科技、服务、网络」等高频后缀：主体名拿去市场检索命中几十上百条无关应用，
# 截到前 limit 条时真应用全被挤出去。只用跨行业都成立的通名，不列具体行业词（餐饮/咖啡 这类留着做品牌）
_ENTITY_GENERIC = re.compile(
    r"(?:信息技术|网络科技|网络技术|技术|科技|信息|服务|实业|投资|控股|管理|咨询|"
    r"商贸|电子商务|数字|智能|数据|软件|文化|传媒|发展|集团|股份|有限|责任|公司|"
    r"中国|国际|（|）|\(|\))")
_KNOWN_SDK = {
    "umeng.com": "友盟统计", "umengcloud.com": "友盟统计", "jpush.cn": "极光推送",
    "jiguang.cn": "极光推送", "getui.com": "个推", "igexin.com": "个推", "bugly.qq.com": "Bugly",
    "gtimg.com": "腾讯", "qlogo.cn": "微信", "weixin.qq.com": "微信", "qq.com": "腾讯",
    "aliyuncs.com": "阿里云 OSS", "myqcloud.com": "腾讯云 COS", "qiniu.com": "七牛",
    "qiniucdn.com": "七牛", "bcebos.com": "百度 BOS", "amap.com": "高德地图",
    "map.baidu.com": "百度地图", "bdstatic.com": "百度", "baidustatic.com": "百度",
    "google-analytics.com": "GA", "googletagmanager.com": "GTM", "googleapis.com": "Google",
    "gstatic.com": "Google", "facebook.com": "Facebook", "firebaseio.com": "Firebase",
    "crashlytics.com": "Crashlytics", "sentry.io": "Sentry", "umeng.co": "友盟",
    "mob.com": "MobTech", "sharesdk.cn": "ShareSDK", "pgyer.com": "蒲公英",
    "wjx.cn": "问卷星", "talkingdata.com": "TalkingData", "growingio.com": "GrowingIO",
    "zhugeio.com": "诸葛IO", "appsflyer.com": "AppsFlyer", "adjust.com": "Adjust",
    "apple.com": "Apple", "icloud.com": "Apple", "cdn-apple.com": "Apple",
}


# 包体里必现的公共基础设施：代码托管、文档站、标准组织、网关。它们出现在包里
# 只说明用了什么库，指不回目标主体；不单列的话会当成「自有域」灌进资产库。
_INFRA_HOSTS = frozenset({
    "github.com", "githubusercontent.com", "gitlab.com", "gitee.com",
    "google.com", "android.com", "xml.org", "w3.org", "spdx.org",
    "apache.org", "ipfs.io", "qos.ch", "slf4j.org", "kotlinlang.org",
    "jetbrains.com", "youtrack.com", "stackoverflow.com", "mozilla.org",
    "json-schema.org", "ietf.org", "openjsf.org", "npmjs.com",
    "goo.gle", "kotl.in", "ktor.io", "bit.ly", "tinyurl.com", "t.co",
    "onion", "invalid",
})


def _sdk_of(domain: str) -> str:
    d = domain.lower()
    for k, v in _KNOWN_SDK.items():
        if d == k or d.endswith("." + k):
            return v
    for k in _INFRA_HOSTS:
        if d == k or d.endswith("." + k):
            return "通用基础设施"
    return ""


@dataclass
class AppInfo:
    name: str = ""
    platform: str = ""          # android / ios
    package: str = ""           # 包名 或 bundleId
    developer: str = ""
    website: str = ""
    store_url: str = ""
    version: str = ""
    # 商店本来就回了这几样，早先只存在 notes 里，导表「分类/简介/Logo/更新时间」四列全空
    category: str = ""
    intro: str = ""
    logo: str = ""
    updated: str = ""
    # 应用商店上架时要填备案号，应用宝详情里就带 icp_number / icp_entity：
    # APP 这条线的备案不用再走工信部接口，商店登记值就是现成的
    icp: str = ""
    icp_entity: str = ""
    cert_sha256: str = ""
    domains: set = field(default_factory=set)
    sdk_domains: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    apk: dict = field(default_factory=dict)      # 本地包深度静态分析（清单/权限/深链/接口/凭据）

    def as_dict(self) -> dict:
        return {"name": self.name, "platform": self.platform, "package": self.package,
                "developer": self.developer, "website": self.website, "store_url": self.store_url,
                "version": self.version, "cert_sha256": self.cert_sha256,
                "category": self.category, "intro": self.intro, "logo": self.logo,
                "updated": self.updated,
                "icp": self.icp, "icp_entity": self.icp_entity,
                "domains": sorted(self.domains), "sdk_domains": self.sdk_domains,
                "sources": self.sources, "evidence": self.evidence[:8], "notes": self.notes,
                "apk": self.apk}


# ─────────────── 应用市场 ───────────────
def _ts_day(v) -> str:
    """商店的更新时间两种形态：unix 秒（应用宝 update_time）和日期串（七麦 / 豌豆荚）。

    统一成 YYYY-MM-DD；导表按天对齐，时间戳直接塞进去会变成一串数字。
    """
    s = str(v or "").strip()
    if not s:
        return ""
    if re.fullmatch(r"\d{10}|\d{13}", s):
        try:
            ts = int(s) / (1000 if len(s) == 13 else 1)
            return datetime.fromtimestamp(ts, timezone(timedelta(hours=8))).strftime("%Y-%m-%d")
        except Exception:
            return ""
    m = re.match(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", s)
    if m:
        return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return s[:19]


def _name_match(name: str, hit: str) -> bool:
    """应用名是否真的在结果里：iTunes 按 term 做模糊检索，会带来大量同名无关 App。

    商家给品牌起的长标题很常见（「瑞幸咖啡伙伴版」「瑞幸咖啡券」），品牌词在里面
    并不代表这就是官方应用；所以只认应用名**开头**就是这个词，且词要占到标题的
    大部分。像「XX 助手」这种后置的，靠开发者名对不对得上，交给 _dev_match。
    """
    n = re.sub(r"\s+", "", name or "").lower()
    h = re.sub(r"\s+", "", hit or "").lower()
    if not n or not h:
        return False
    if h == n:
        return True
    if h.startswith(n):
        tail = h[len(n):]
        # 尾巴必须是通用词（官方版 / 客户端 / Pro / 极速版…）且很短：
        # 「瑞幸咖啡伙伴版」「瑞幸咖啡券」这类是另一个产品，留给 _dev_match 判定
        return bool(len(tail) <= 8 and re.fullmatch(
            r"(?:官方|正式|最新|手机|移动|客户端|专业|企业|商家|极速|国际|"
            r"app|pro|plus|mob|hd|版|官方版|客户端版)+", tail))
    return False


def _dev_match(name: str, dev: str) -> bool:
    """开发者/公司名里带品牌词，说明这确实是这个主体出的应用。

    品牌词至少 4 个字符才认：`.com` 这种残渣会被 Hotels.com 这类开发者的名字蒙中，
    3 个字母的短词撞名概率也太高。
    纯英文短词（`hotels`、`travel` 这种）只靠开发者名撞出来的结果基本是别的品牌，
    要求至少 8 个字符才认；中文品牌名不受此限。
    域名形态的词（`hotels.com`）一律不认开发者名：域名是检索用的主体标识，
    开发者字段里带同名域名往往正是别人家的官网域名，命中率比品牌词撞名还低。
    """
    n = re.sub(r"\s+", "", name or "").lower()
    d = re.sub(r"\s+", "", dev or "").lower()
    if not (n and len(n) >= 4 and d and n in d):
        return False
    if not re.search(r"[\u4e00-\u9fff]", n) and ("." in n or len(n) < 8):
        return False
    return True


async def _itunes(name: str, limit: int = 5) -> list[AppInfo]:
    """iTunes 公开 Search API：免费、无 key、给 bundleId + sellerName + sellerUrl。

    取回后按应用名过滤：名称对不上的结果不进自有应用，只留在 notes 里当参考。
    """
    # 超时收紧到 8s：本机实测这里经常 3～5s 才回包（境外站 + 代理），给 15s 等于每个名字多等一倍
    r = await _get("https://itunes.apple.com/search",
                   {"term": name, "entity": "software", "country": "cn", "limit": limit},
                   timeout=8)
    if r is None or r.status_code != 200:
        return []
    try:
        data = r.json() or {}
    except Exception:
        return []
    out: list[AppInfo] = []
    for it in data.get("results") or []:
        if not isinstance(it, dict):
            continue
        track = str(it.get("trackName") or "")
        seller = str(it.get("sellerName") or "")
        if not (_name_match(name, track) or _dev_match(name, seller)):
            continue
        ap = AppInfo(name=str(it.get("trackName") or name), platform="ios",
                     package=str(it.get("bundleId") or ""), developer=str(it.get("sellerName") or ""),
                     website=str(it.get("sellerUrl") or ""), version=str(it.get("version") or ""),
                     store_url=str(it.get("trackViewUrl") or ""))
        # 这几样 iTunes 一次就回了：分类/简介/图标/上架时间，别让导表那四列空着
        ap.category = str(it.get("primaryGenreName") or "")
        ap.intro = re.sub(r"\s+", " ", str(it.get("description") or "")).strip()[:200]
        ap.logo = str(it.get("artworkUrl512") or it.get("artworkUrl100") or "")
        ap.updated = str(it.get("currentVersionReleaseDate") or it.get("releaseDate") or "")[:10]
        ap.sources.append("itunes")
        ap.evidence.append(f"iTunes 公开接口：{ap.name} / {ap.package}")
        if ap.website:
            d = re.match(r"https?://([^/]+)", ap.website)
            if d and is_valid_domain(d.group(1)):
                ap.domains.add(root_domain(d.group(1)) or d.group(1))
        out.append(ap)
    return out


# Play 检索页每个条目块：包名锚点之后紧跟两个 ubGTjb span，分别是应用名和开发者
_PLAY_ITEM = re.compile(
    r'href="/store/apps/details\?id=([A-Za-z0-9_.]+)"[^>]*>.{0,4000}?'
    r'<span class="DdYX5">([^<]{1,80})</span>'
    r'(?:<div class="ubGTjb"><span class="wMUdtb">([^<]{0,120})</span>)?', re.S)


async def _google_play(name: str, limit: int = 5) -> list[AppInfo]:
    """Google Play 检索页：直接从条目块抽「应用名 + 开发者 + 包名」。

    详情页对非浏览器 UA 一律回 404，只能靠检索页；检索页会给一堆同名无关 App
    （搜瑞幸咖啡能出 com.ludo.king），所以名称对不上的直接丢，别让这些包名进资产表。
    """
    q = re.sub(r"\s+", "+", name.strip())
    r = await _get("https://play.google.com/store/search",
                   {"q": q, "c": "apps", "hl": "zh_CN"}, timeout=10)
    if r is None or r.status_code != 200:
        return []
    out: list[AppInfo] = []
    seen: set[str] = set()
    for pkg, app_name, dev in _PLAY_ITEM.findall(r.text):
        if pkg in seen:
            continue
        seen.add(pkg)
        app_name = re.sub(r"\s+", " ", app_name).strip()
        dev_name = re.sub(r"\s+", " ", dev or "").strip()
        if not (_name_match(name, app_name) or _dev_match(name, dev_name)):
            continue
        ap = AppInfo(name=app_name, platform="android", package=pkg,
                     developer=dev_name,
                     store_url=f"https://play.google.com/store/apps/details?id={pkg}")
        ap.sources.append("google_play")
        ap.evidence.append(f"Google Play 检索页：{app_name} / {pkg}")
        out.append(ap)
        if len(out) >= limit:
            break
    return out


# 豌豆荚搜索结果的条目块：应用名和包名成对出现在同一个 <a> 的属性里
_WDJ_ITEM = re.compile(
    r'data-app-name="([^"]{1,80})"[^>]*?data-app-pname="([A-Za-z0-9_.]{4,80})"', re.S)
# 应用宝详情页的服务端渲染数据块：目标包名后紧跟应用名、下载地址和开发者主体
_YYB_BLOCK = re.compile(
    r'"pkg_name":"([A-Za-z0-9_.]+)".{0,400}?"name":"([^"]{1,80})".{0,400}?'
    r'"developer":"([^"]{0,120})"', re.S)


# 详情页正文里的上架备案号，形如「闽ICP备06000856号-15A」「粤B2-20090059-1623A」
_YYB_ICP = re.compile(
    r"(?:[\u4e00-\u9fa5]{0,6})?(?:ICP备\d{6,12}号?(?:-\d{1,4}[A-Z]?)?|B2-\d{8}(?:-\d{1,4}[A-Z]?)?)")


def _yyb_icp(text: str) -> str:
    """抽目标应用自己的备案号。

    应用宝详情页同时挂着应用宝自身的备案（粤B2-20090059…），那是腾讯的；
    不排掉就会把每个 APP 都标成腾讯备案，比空着更糟。
    """
    for m in _YYB_ICP.finditer(text or ""):
        v = m.group(0).strip()
        if "20090059" in v or "腾讯" in v:
            continue
        return v
    return ""


async def _yyb_detail(pkg: str) -> tuple[str, str, str, str]:
    """应用宝详情页 → (应用名, 开发者主体, iOS 详情链接, 上架备案号)。

    应用宝对包名有稳定的公开详情页，页面里内嵌了服务端渲染的数据块，
    `developer` 直接给企业主体名，这是 App 线索转域名最有效的一环；
    备案号在页面正文，顺手一起拿，APP 这条线不用再单独查工信部。
    """
    # 必须显式直连：config 里 sources_via_proxy=true 时，_get 默认把国内站也送进代理，
    # 应用宝对代理出口回 567 质询页（实测 200 ↔ 567 只差这一个参数），搜索页就永远拿不到数
    r = await _get(f"https://sj.qq.com/appdetail/{pkg}", timeout=10, proxy="")
    if r is None or r.status_code != 200:
        return "", "", "", ""
    icp = _yyb_icp(r.text)
    for got_pkg, name, dev in _YYB_BLOCK.findall(r.text):
        if got_pkg != pkg:
            continue
        ios = re.search(r'"ios_url":"(https?://[^"]+)"', r.text)
        return name.strip(), dev.strip(), (ios.group(1) if ios else ""), icp
    return "", "", "", icp


async def _yyb_search(name: str, limit: int = 8) -> list[AppInfo]:
    """应用宝搜索页 → 应用清单（名称 / 包名 / 开发者主体一次性拿全）。

    页面把搜索结果放在 `__NEXT_DATA__` 的 `dynamicCardResponse.data.components[].data.itemData` 里，
    每条自带 `pkg_name` / `name` / `developer` / `operator` / `ios_url`。
    这是「应用名 → 包名 → 中文企业主体」最稳的一环：拿到 developer 就能接着跑企业证据链。
    """
    url = f"https://sj.qq.com/search?q={quote(name)}"
    # 同 _yyb_detail：走代理会被 567 质询，直连才是正常搜索结果页
    r = await _get(url, timeout=10, proxy="")
    if r is None or r.status_code != 200:
        return []
    m = re.search(r'id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text or "", re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(1))
    except Exception:
        return []
    items: list[dict] = []
    comps = ((data.get("props") or {}).get("pageProps") or {})
    for comp in ((comps.get("dynamicCardResponse") or {}).get("data") or {}).get("components") or []:
        items.extend(((comp or {}).get("data") or {}).get("itemData") or [])
    out: list[AppInfo] = []
    seen: set[str] = set()
    for it in items:
        pkg = (it.get("pkg_name") or "").strip()
        app_name = (it.get("name") or "").strip()
        dev_name = (it.get("developer") or it.get("operator") or "").strip()
        if not pkg or pkg in seen:
            continue
        if not (_name_match(name, app_name) or _dev_match(name, dev_name)):
            continue
        seen.add(pkg)
        ap = AppInfo(name=app_name, platform="android", package=pkg,
                     store_url=f"https://sj.qq.com/appdetail/{pkg}")
        ap.developer = dev_name
        # 应用宝 itemData 的键名跟别家不一样：分类是 cate_name(_new)、简介是 editor_intro、
        # 版本是 version_name、更新时间是 unix 秒 update_time。硬套 categoryName/updateTime
        # 会全部落空，导表那四列就是空的
        ap.category = str(it.get("cate_name_new") or it.get("cate_name")
                          or it.get("categoryName") or "").strip()
        ap.intro = re.sub(r"\s+", " ", str(it.get("editor_intro") or it.get("editorWord")
                                          or it.get("intro") or it.get("description")
                                          or "")).strip()[:200]
        ap.logo = str(it.get("icon") or it.get("logo") or it.get("iconUrl") or "").strip()
        ap.version = ap.version or str(it.get("version_name") or it.get("versionName")
                                      or it.get("version") or "").strip()
        ap.updated = _ts_day(it.get("update_time") or it.get("publishTime")
                             or it.get("public_time") or "")
        # 搜索页的 icp_number 是应用宝自己那条（腾讯主体），不是被搜应用的上架备案；
        # 目标应用的备案只在它自己的详情页正文里，交给下面的详情页补
        ap.sources.append("yingyongbao")
        ap.evidence.append(f"应用宝检索页：{url[:110]} → {app_name} / {pkg}"
                           + (f"（开发者 {ap.developer}）" if ap.developer else ""))
        ios = it.get("ios_url") or ""
        if ios:
            ap.evidence.append(f"应用宝登记 iOS 版：{ios}")
        out.append(ap)
        if len(out) >= limit:
            break
    return out


async def _qimai_search(name: str, limit: int = 8) -> list[AppInfo]:
    """七麦检索 → 应用清单。只有配了登录态才走这一路，没配直接返回空。

    七麦的检索接口不公开匿名访问（无 Cookie 回 `Access Error`），
    但它的收录面比应用宝 / 豌豆荚宽：国内应用和小程序都能按品牌名命中，
    并且每条带 AppID / 包名 / 开发者，正好补另外两家搜不到的应用。
    """
    cookie = ""
    try:
        from ...config import config as _cfg
        from .. import channels as channels_mod

        if not channels_mod.source_on("qimai"):
            return []
        cookie = str(_cfg.get("sources", "qimai", "cookie", default="") or "").strip()
    except Exception:
        cookie = ""
    if not cookie:
        return []
    headers = {"Cookie": cookie,
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
               "Referer": "https://www.qimai.cn/", "Origin": "https://www.qimai.cn"}
    out: list[AppInfo] = []
    try:
        async with httpx.AsyncClient(timeout=12, trust_env=False, follow_redirects=True,
                                     headers=headers) as cli:
            r = await cli.post("https://api.qimai.cn/search/searchApp",
                               params={"analysis": ""}, data={"search": name, "type": "1"})
            data = r.json() if r.status_code == 200 else {}
    except Exception:
        return []
    if not isinstance(data, dict) or str(data.get("code")) not in ("10000", "0"):
        return []
    rows = ((data.get("data") or {}).get("list") or []) if isinstance(data.get("data"), dict) else []
    seen: set[str] = set()
    for it in rows if isinstance(rows, list) else []:
        if not isinstance(it, dict):
            continue
        app_name = str(it.get("appName") or it.get("name") or "").strip()
        dev_name = str(it.get("developer") or it.get("company") or "").strip()
        app_id = str(it.get("appId") or it.get("appleId") or "").strip()
        pkg = str(it.get("packageName") or it.get("package") or "").strip()
        if not app_name or (not app_id and not pkg):
            continue
        if not (_name_match(name, app_name) or _dev_match(name, dev_name)):
            continue
        key = (pkg or app_id)
        if key in seen:
            continue
        seen.add(key)
        ap = AppInfo(name=app_name, platform="android" if pkg else "ios",
                     package=pkg or app_id, store_url="https://www.qimai.cn/")
        ap.developer = dev_name
        ap.category = str(it.get("categoryName") or it.get("category") or "").strip()
        ap.intro = re.sub(r"\s+", " ", str(it.get("description") or it.get("subtitle")
                                          or "")).strip()[:200]
        ap.logo = str(it.get("icon") or it.get("logo") or "").strip()
        ap.version = ap.version or str(it.get("version") or "").strip()
        ap.updated = _ts_day(it.get("updateTime") or it.get("releaseTime")
                             or it.get("release_time") or "")
        ap.sources.append("qimai")
        ap.evidence.append(f"七麦检索：{name} → {app_name}"
                           + (f"（开发者 {dev_name}）" if dev_name else "")
                           + (f"（{pkg}）" if pkg else (f"（AppID {app_id}）" if app_id else "")))
        out.append(ap)
        if len(out) >= limit:
            break
    return out


def _hop(aw, timeout: float):
    """给单跳加硬上限。wait_for 会取消协程本身，所以调用方要用 `await _hop(_get(...))`，
    不能先造出协程再囤着 —— 那样超时后会有没被 await 过的协程泄漏。"""
    return asyncio.wait_for(aw, timeout=timeout)


# 「应用商店 → 官网」这一跳在应用详情页里藏得很深（应用宝详情页的 website 字段实测为空），
# 只能拿应用名去搜官网。搜索结果是下载站/媒体页居多，只有**官网词**形态的标题才信
_OWN_SITE = re.compile(r"https?://([a-z0-9][a-z0-9\-.]{2,60}\.[a-z]{2,10})(?:/|$)", re.I)
_OWN_TITLE = re.compile(r"(?:官网|官方网站|官方站点)", re.I)
_NOT_OWN_SITE = ("qq.com", "gtimg.com", "myapp.com", "apple.com", "google.com", "wandoujia.com",
                 "coolapk.com", "mi.com", "huawei.com", "vivo.com", "oppo.com", "baidu.com",
                 "sogou.com", "so.com", "bing.com", "toutiao.com", "zhihu.com", "csdn.net",
                 "wikipedia.org", "baike.com", "douban.com", "weibo.com", "xiaohongshu.com",
                 "36kr.com", "huxiu.com", "cngold.com", "qcc.com", "tianyancha.com")


_OWN_SITE_LOG: dict[str, list] = {}


async def _own_site(name: str, hits: list | None = None) -> str:
    """应用名 → 官网根域（拿不到返回空串）。

    只认官网词结果里标题自述「官网」的那一条（域名主干必须是注册根域，img./api. 这类子域不算官网）。
    `hits` 是调用方已经搜好的同名结果：引擎锁一次只放一个词进来，同一批里再排一遍官网词
    等于白等两个 `_INTERVAL`（实测这一跳合计 7.9s）。
    """
    if hits is None:
        brand = re.sub(r"[^0-9a-z\u4e00-\u9fa5]", "", (name or "").lower())[:6]
        if not brand:
            return ""
        try:
            hits = await web.search_many([f"{name} 官网"], engines=("toutiao", "bing_rss"),
                                         budget=5)
        except Exception:
            return ""
    for h in hits:
        if not _OWN_TITLE.search(h.title or ""):
            continue
        dom = (h.domain or "").lower()
        if not dom or any(dom == x or dom.endswith("." + x) for x in _NOT_OWN_SITE):
            continue
        # 只挡 CDN 型子域（img./api. 这类）：主干仍是品牌自己的根域，不影响归属；子域不算官网
        core = dom.split(".")[0]
        if core != (root_domain(dom) or "").split(".")[0]:
            continue
        if is_valid_domain(dom):
            return root_domain(dom) or dom
    # 主流程在 gather 之后才取官网，中途超时取消时这一批结果不该丢；只留官网自述形态，
    # 下一个应用来查时不必再从几百条结果里重新过一遍正则
    _OWN_SITE_LOG[name] = [h for h in hits if _OWN_TITLE.search(h.title or "")][:12]
    return ""


def _site_of(ap: AppInfo) -> str:
    """应用记录里已经带上的官网根域（iTunes sellerURL、搜索结果里的官网一条）。"""
    u = (ap.website or ap.store_url or "").strip()
    if not u:
        return ""
    m = _OWN_SITE.match(u)
    dom = m.group(1).lower() if m else ""
    if not dom or any(dom == x or dom.endswith("." + x) for x in _NOT_OWN_SITE):
        return ""
    return (root_domain(dom) or dom) if is_valid_domain(dom) else ""


async def _cn_markets(name: str, limit: int = 8) -> list[AppInfo]:
    """国内渠道：应用宝为主，豌豆荚兜底。

    搜索引擎和商店首页给的多是推荐位（能抓到 `com.popcap.pvz2cthdxm` 这种无关包），
    所以这里只认搜索结果条目里成对出现的「应用名 + 包名」，再用 `_name_match` 校验应用名。
    页面结构变了就跳过该渠道，不报错。

    两家并发：应用宝有结果时直接返回，等于把豌豆荚那 2～4s 白等着；
    而应用宝反爬回 567 时又只剩豌豆荚能出数，串行兜底两头都不讨好。
    """
    url = f"https://www.wandoujia.com/search?key={quote(name)}"

    async def _wdj() -> list[AppInfo]:
        r = await _hop(_get(url, timeout=8, proxy=""), 9)
        if r is None or r.status_code != 200:
            return []
        out: list[AppInfo] = []
        seen: set[str] = set()
        for app_name, pkg in _WDJ_ITEM.findall(r.text):
            if pkg in seen:
                continue
            if not _name_match(name, app_name):
                continue
            seen.add(pkg)
            ap = AppInfo(name=app_name, platform="android", package=pkg,
                         store_url=f"https://www.wandoujia.com/apps/{pkg}")
            ap.sources.append("wandoujia")
            ap.evidence.append(f"豌豆荚检索页：{url[:110]} → {app_name} / {pkg}")
            out.append(ap)
            if len(out) >= limit:
                break
        return out

    res = await asyncio.gather(_hop(_yyb_search(name, limit), 9), _wdj(),
                               _hop(_qimai_search(name, limit), 9),
                               return_exceptions=True)
    out: list[AppInfo] = []
    seen_pkg: set[str] = set()
    for got in res:
        if isinstance(got, BaseException):
            continue
        for ap in got:
            if ap.package in seen_pkg:
                continue
            seen_pkg.add(ap.package)
            out.append(ap)
    return out[:limit]


# ─────────────── 包体静态提取 ───────────────
def _domain_strings(blob: bytes) -> set[str]:
    text = blob.decode("utf-8", "ignore")
    out: set[str] = set()
    for m in re.finditer(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,10})\b", text, re.I):
        d = m.group(1).lower()
        if is_valid_domain(d) and not d.endswith((".png", ".jpg", ".gif", ".webp", ".xml", ".json",
                                                  ".html", ".js", ".css", ".svg", ".kt", ".java")):
            out.add(d)
    return out


def extract_package(path: str | Path) -> dict:
    """本地 apk / ipa 静态提取（同步，放线程里跑）。

    apk 的 AndroidManifest.xml 是二进制 XML，域名以内联 UTF-16 / UTF-8 字符串池存放，
    直接扫整个文件就能抽到；不依赖 aapt / apktool。
    """
    p = Path(path)
    info: dict = {"package": "", "cert_sha256": "", "domains": set(), "notes": []}
    if not p.exists():
        info["notes"].append("文件不存在")
        return info
    # 深度静态分析（清单树 / 权限 / 导出组件 / 深链 / 接口路径 / 凭据），解不出就当降级
    try:
        use_deep, use_jadx, use_apktool = _deep_mode()
        deep = apkstatic.analyze(p, deep=use_deep, use_jadx=use_jadx, use_apktool=use_apktool)
    except Exception as e:
        deep = {"ok": False, "notes": [f"包体深度分析失败：{str(e)[:80]}"]}
    if deep.get("ok"):
        info["apk"] = deep
        if deep.get("package"):
            info["package"] = deep["package"]
        info["domains"] |= set(deep.get("domains") or ())
        info["package_name"] = deep.get("package") or ""
        info["version"] = (deep.get("manifest") or {}).get("version_name") or \
            (deep.get("ios") or {}).get("version") or ""
    elif deep.get("notes"):
        info["notes"] += [str(n) for n in deep["notes"][:3]]
    try:
        zf = zipfile.ZipFile(p)
    except Exception as e:
        info["notes"].append(f"不是有效 zip/apk/ipa：{e}")
        return info
    with zf:
        names = zf.namelist()
        # 包名：AndroidManifest 字符串池里的第一个 com./cn. 形态
        for cand in ("AndroidManifest.xml", "Info.plist"):
            if cand in names:
                try:
                    blob = zf.read(cand)
                except Exception:
                    continue
                if cand == "AndroidManifest.xml":
                    pk = PKG_ANDROID.findall(blob.decode("utf-8", "ignore"))
                    if pk:
                        info["package"] = max(pk, key=len)
                else:
                    m = BUNDLE_IOS.search(blob.decode("utf-8", "ignore"))
                    if m:
                        info["package"] = m.group(1)
                if not deep.get("ok"):
                    info["domains"] |= _domain_strings(blob)
        # 签名证书摘要（apk v1/v2 都在 META-INF 下，这里只算整件文件的 SHA256 便于比对同包）
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            info["file_sha256"] = h.hexdigest()
        except Exception:
            pass
        # classes*.dex / assets / res：域名最密集的地方。
        # 深度分析已按字符串池扫过同一批文件时不再裸扫（裸切字节会灌进上万个假域）
        if deep.get("ok"):
            info["files_scanned"] = deep.get("files_scanned", 0)
            return info
        scanned = 0
        for n in names:
            if scanned >= 40:
                break
            if not (n.startswith("classes") and n.endswith(".dex")) \
                    and not n.startswith(("assets/", "res/raw/")) \
                    and not n.endswith((".json", ".xml", ".html", ".js")):
                continue
            try:
                blob = zf.read(n)
            except Exception:
                continue
            if len(blob) > 40 << 20:
                continue
            info["domains"] |= _domain_strings(blob)
            scanned += 1
        info["files_scanned"] = scanned
    return info


async def extract_package_async(path: str | Path) -> dict:
    return await run_blocking(extract_package, path, timeout=90)


# ─────────────── 主流程 ───────────────
_CACHE_TTL = 900.0
# 本程等开发者扩线的上限。扩线晚归的域只靠 _late_merge 补缓存，外面再等就是白占调用方的时限
_EXPAND_WAIT = 8.0
_done: dict[tuple[str, str, int], tuple[float, dict]] = {}
# 总时限到点时商店条目已经在手、只差扩线的目标：晚归的域挂到这份底稿上，下一轮直接命中
_PENDING: dict[tuple[str, str, int], dict] = {}
# 同一目标正在跑时直接共享这一趟。不能只按调用参数做键：一次采集里「品牌名 → 公司全名
# → 品牌名」和 L2 同名并发会同时各起一趟，引擎锁与扩线全部翻倍
_inflight: dict[str, asyncio.Task] = {}
# 已进入主体扩线的上下文。contextvar 而不是模块级 set：同一批名字是并发跑的，
# 用全局标志会把没在扩线的那个名字也一起挡掉
_DEPTH: contextvars.ContextVar[bool] = contextvars.ContextVar("arlx_apps_deep", default=False)
# 本程的品牌短名。扩线在总时限到点后才可能回来，得知道把域补进哪一条缓存
_BRAND_KEY: contextvars.ContextVar[str] = contextvars.ContextVar("arlx_apps_brand", default="")
# 扩线晚归写缓存、主协程写缓存，都是遍并发协程里跑的：同一事件循环里串行改写
_LATE_LOCK = threading.Lock()


async def collect_apps(target: str, *, package_path: str = "", limit: int = 8,
                       deadline: float = 35.0) -> dict:
    """应用名 / 包名 / 本地包文件 → 应用清单 + 自有域 + 第三方 SDK 域。

    外面套一层总时限：市场页、应用宝、多引擎、开发者扩线四段各自都有超时，但串起来
    在反爬变慢时能拖到几分钟。调用方（P1b 一次并发好几个名字）等不起，到点就交已有结果。
    默认 35s：各跳都已并发且单跳有上限，实测正常 5～15s，30s 上下是 iTunes 与引擎一起变慢，
    再长就不该让调用方等；扩线晚归的域会补进缓存，下一轮同名直接带上。
    """
    key = (re.sub(r"\s+", "", target or "").lower(), package_path or "", limit)
    now = asyncio.get_running_loop().time()
    old = _done.get(key)
    if old and now - old[0] < _CACHE_TTL:
        return old[1]
    pend = _PENDING.get(key)
    # 底稿要等手上没有同名在跑的扩线再交，否则这一轮又排一遍扩线，晚归那份就白等了
    if pend is not None and key[0] not in _inflight:
        _PENDING.pop(key, None)
        _done[key] = (now, pend)
        return _copy(pend)
    # 同一名称重复采集（品牌名一次、公司全名抽出品牌词又一次）在商店页和引擎队列上完全是白跑
    running = _inflight.get(key[0])
    if running is not None:
        return _copy(await asyncio.shield(running))
    for k in [k for k, (t, _) in _done.items() if now - t >= _CACHE_TTL]:
        _done.pop(k, None)
    for k in [k for k in _PENDING if k[0] == key[0] and k != key]:
        _PENDING.pop(k, None)
    task = asyncio.create_task(_run(key, target, package_path, limit, deadline))
    _inflight[key[0]] = task
    try:
        return _copy(await asyncio.shield(task))
    finally:
        if _inflight.get(key[0]) is task:
            _inflight.pop(key[0], None)


def _copy(out: dict) -> dict:
    """调用方会就地改 items / notes，交出去深拷贝，别把缓存里的条目改脏。"""
    return json.loads(json.dumps(out, ensure_ascii=False, default=str))


def _late_merge(brand: str, doms: list[str]) -> None:
    """扩线晚到的域补进缓存：一次晚到不该让下一轮再等一遍 30s 的扩线。

    缓存里没有这个品牌（首轮就没采到条目）时挂到 `_PENDING` 的底稿上，下一轮直接取。
    自带锁：这函数会被三个并发扩线协程同时调用，边遍历边改字典会抛
    `dictionary changed size during iteration`。
    """
    if not brand:
        return
    b = re.sub(r"\s+", "", brand).lower()
    with _LATE_LOCK:
        # 扩线确认「没有域」也要记一笔：否则下一轮又把同一轮 30s 的扩线跑一遍
        for (nm, _pp, lim), (_t, cached) in list(_done.items()):
            if nm == b:
                cached["domains"] = sorted(set(cached.get("domains") or []) | set(doms))
        for (nm, _pp, lim), base in list(_PENDING.items()):
            if nm == b:
                base["domains"] = sorted(set(base.get("domains") or []) | set(doms))


async def _run(key, target: str, package_path: str, limit: int, deadline: float) -> dict:
    box: dict = {}
    inner = asyncio.create_task(_collect_apps(target, package_path=package_path, limit=limit,
                                              box=box))
    try:
        res = await asyncio.wait_for(asyncio.shield(inner), timeout=deadline)
    except asyncio.TimeoutError:
        # 超时后把已收集到的条目交出去：任务还在跑，别取消（取消会让页面/检索半截丢结果）
        if inner.done() and not inner.cancelled() and inner.exception() is None:
            res = inner.result()
        else:
            got = box.get("out")
            if not got:
                res = {"items": [], "domains": [], "sdk_domains": {},
                       "notes": [f"采集超时 {deadline:.0f}s：市场页与搜索引擎均未在时限内回来"]}
            else:
                got.setdefault("notes", []).append(f"采集超时 {deadline:.0f}s，以下为已完成部分")
                res = got
    # 扩线晚到的域写在箱里，这里是唯一把这些域并进结果的地方：
    # 交给调用方的清单里每个键都得是列表/字典，箱本身不外传
    late = box.get("late_domains") or []
    if late:
        res["domains"] = sorted(set(res.get("domains") or []) | set(late))
    late_notes = box.get("late_notes") or []
    if late_notes:
        res["notes"] = list(dict.fromkeys(list(res.get("notes") or []) + late_notes))[:8]
    res.pop("_box", None)
    if res.get("items"):
        _done[key] = (asyncio.get_running_loop().time(), res)
        return res
    # 一条都没采到的清单不进缓存，但暂存一份带商店条目快照的底稿：晚归的扩线域
    # 只能挂到有 items 的缓存上，没有这份，下一轮又得为一轮扩线再等一次总时限
    seed = (box.get("apps") or {}) if box else {}
    if seed:
        base = {"items": [ap.as_dict() for ap in list(seed.values())[:max(limit, 1)]],
                "domains": [], "sdk_domains": {},
                "notes": [f"{int(deadline)}s 内未等到开发者扩线；扩线晚归的域会在下一轮带上"]}
        box["out"] = base
        _PENDING[key] = base
    return res


async def _collect_apps(target: str, *, package_path: str = "", limit: int = 8,
                        box: dict | None = None) -> dict:
    """应用名 / 包名 / 本地包文件 → 应用清单 + 自有域 + 第三方 SDK 域。

    target 形如 `com.example.app`（含两个以上点且全小写）视为包名，直接查；
    否则当应用名走市场检索。package_path 给了本地 apk/ipa 就走静态提取。
    """
    target = (target or "").strip()
    notes: list[str] = []
    # TLD 残渣（`.com` / `com`）拿去搜市场会命中 Hotels.com、CommBank 这类同名开发者，
    # 是纯噪声，直接判空
    if len(re.sub(r"^\.+|\.+$", "", target)) < 3:
        return {"items": [], "domains": [], "sdk_domains": {},
                "notes": [f"检索词「{target}」太短，不作为应用名使用"]}
    apps: dict[str, AppInfo] = {}

    def _put(ap: AppInfo) -> None:
        key = (ap.platform + ":" + ap.package) if ap.package else (ap.platform + ":" + ap.name)
        cur = apps.get(key)
        if cur:
            cur.domains |= ap.domains
            cur.evidence += [e for e in ap.evidence if e not in cur.evidence]
            cur.sources = list(dict.fromkeys(cur.sources + ap.sources))
            cur.developer = cur.developer or ap.developer
            cur.website = cur.website or ap.website
            cur.store_url = cur.store_url or ap.store_url
        else:
            apps[key] = ap

    # 包名形态（com.tencent.mm / cn.xxx.yyy）不要求全小写：真实包名里常有大小写混写
    is_pkg = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){2,}", target)) \
        and " " not in target and not target.lower().endswith(
            (".com", ".cn", ".net", ".org", ".io", ".co", ".com.cn"))

    # 企业主体名 / 域名：应用商店按「品牌名」收录，按公司全名搜命中率低，短名再补一轮。
    # 机构后缀（院 / 所 / 局 / 站…）统一走 naming，以前只认公司/集团/研究院/中心，
    # 「厦门市特种设备检验检测院」这类事业单位漏判，全名被当产品名整个丢进商店。
    looks_entity = naming.is_org_name(target)
    names = [target]
    if looks_entity:
        from .enterprise import _brand
        b = _brand(target)
        if b and b != target:
            names.append(b)
    is_entity = looks_entity and len(names) > 1
    # 主体名整串去搜商店时，`科技/服务/集团` 这类通名会按词切出成百上千条无关应用，
    # 截断后真应用一条不剩；所以只有剥掉通名之后还剩品牌词才搜
    if is_entity and len(_ENTITY_GENERIC.sub("", target)) < 3:
        names = names[1:]
    # 品牌短名在这一程里就是主体：它的开发者扩线只能排在采集总时限之外，到点把域名补进缓存
    _BRAND_KEY.set(names[-1])

    if is_pkg:
        # Play 与应用宝互不依赖，串行等于把两次境外/反爬等待叠起来
        yname, ydev, yios, yicp = "", "", "", ""
        res = await asyncio.gather(
            _hop(_get(f"https://play.google.com/store/apps/details?id={target}",
                      {"hl": "zh_CN", "gl": "CN"}, timeout=10), 11),
            _hop(_yyb_detail(target), 11), return_exceptions=True)
        r, ydet = res
        if isinstance(r, BaseException):
            notes.append(f"Play 直查失败：{str(r)[:60]}")
            r = None
        if isinstance(ydet, BaseException):
            notes.append(f"应用宝直查失败：{str(ydet)[:60]}")
        else:
            yname, ydev, yios, yicp = ydet
        try:
            ap = AppInfo(name=target, platform="android", package=target,
                         store_url=f"https://play.google.com/store/apps/details?id={target}")
            if r is not None and r.status_code == 200:
                t = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S)
                if t:
                    ap.name = re.sub(r"\s*-\s*.*$", "", re.sub(r"<[^>]+>", "", t.group(1))).strip()
                dev = re.search(r'href="/store/apps/dev(?:eloper)?\?id=([^"]+)"', r.text)
                if dev:
                    ap.developer = dev.group(1).replace("+", " ")
                ap.sources.append("google_play")
                ap.evidence.append(f"按包名直查 Play 详情页：{ap.store_url}")
                _put(ap)
        except Exception as e:
            notes.append(f"Play 直查失败：{str(e)[:60]}")
        # 国内包（无 Play 上架）：应用宝详情页同样能确认「包名 → 应用名」
        ap2 = AppInfo(name=target, platform="android", package=target,
                      store_url=f"https://sj.qq.com/appdetail/{target}")
        if yname:
            ap2.name = yname
            ap2.developer = ydev
            if yicp:
                ap2.icp = yicp
                ap2.evidence.append(f"应用宝详情页登记备案：{yicp}")
            ap2.sources.append("yingyongbao")
            ap2.evidence.append(f"应用宝详情页：{ap2.store_url}"
                                + (f"（开发者 {ydev}）" if ydev else ""))
            _put(ap2)
        elif yios:
            ap2.evidence.append(f"应用宝详情页：{ap2.store_url}（iOS 版 {yios}）")
            _put(ap2)
        if not apps:
            notes.append(f"包名 {target} 在公开市场未查到详情；可给本地 apk 走包体静态提取")
    else:
        # 三个市场互不依赖，串行等于把三次超时叠起来（实测每个名字 10s+ 全耗在等上）。
        # 协程在 gather 参数里当场造出来，外层取消时它们都已被 await 过，不会泄漏。
        # 名称类查询词共用同一个 search_many；每个词再各跑一次等于排两遍引擎锁队列。
        # 应用名只查一次商店：主体名抽出品牌词后，`company 包名` 那几行是同一批应用的不同写法，
        # 实测没有新包名，只把引擎锁再排一轮
        queries = [target] + ([f"{target} 包名 com."] if is_entity else []) + [f"{target} apk 下载"] \
            + [f"{target} 官网"]
        extra = asyncio.create_task(web.search_many(queries))
        for query in names[:1]:
            fails: list[str] = []
            tags = ("iTunes", "GooglePlay", "国内市场")
            fns = (_itunes, _google_play, _cn_markets)
            res = await asyncio.gather(*(_hop(fn(query, limit), 12) for fn in fns),
                                       return_exceptions=True)
            for tag, got in zip(tags, res):
                if isinstance(got, BaseException):
                    fails.append(f"{tag} {str(got)[:40]}")
                    continue
                for ap in got or []:
                    _put(ap)
            if fails:
                notes.append("市场检索失败：" + "；".join(fails))
        # 详情页要回两样：缺开发者时补主体名，**所有 Android 条目**都要补上架备案号。
        # 早先这里只挑「没开发者」的条目，搜索页已经给出开发者的应用就再也不回详情页，
        # 备案列因此永远是空的
        android = [a for a in apps.values() if a.platform == "android"]
        if android:
            async def _fill(ap: AppInfo) -> None:
                try:
                    # 详情页是逐包拉的外站页，不带硬顶时单个反爬页就能顶掉整个名字的时限
                    _n, dev, _ios, dicp = await _hop(_yyb_detail(ap.package), 8)
                except Exception:
                    return
                if dicp:
                    ap.icp = dicp
                    ap.evidence.append(f"应用宝详情页登记备案：{dicp}")
                if dev and not ap.developer:
                    ap.developer = dev
                    ap.evidence.append(f"应用宝详情页：https://sj.qq.com/appdetail/{ap.package}"
                                       f"（开发者 {dev}）")

        # 应用宝检索页已经给全名+开发者+包名，详情页只是补那些缺开发者的条目；
        # 超过 3 个还逐一拉页，纯粹是把引擎锁的时间耗在无关包名上
            await asyncio.gather(*(_fill(a) for a in android[:min(limit, 3)]))
        # 多引擎补包名：`com.` 形态 + 名称同时在一条结果里，可信度比单看包名高。
        # 引擎只留实测秒级出数的几家：360/baidu 对这一类词经常 0 条却照样耗满预算。
        # search_many 自己在 budget 内返回，外面这层只兜异常，加 wait_for 反而会漏掉已完成结果
        try:
            hits = await extra
        except Exception:
            hits = []
        for h in hits:
            text = h.title + h.snippet
            if not any(n[:2] in text for n in names if n[:2]):
                continue
            for pkg in PKG_ANDROID.findall(f"{h.title} {h.snippet} {h.url}"):
                if pkg.startswith(("com.", "cn.", "net.", "org.")) and pkg.count(".") >= 2:
                    ap = AppInfo(name=names[-1], platform="android", package=pkg)
                    ap.sources.append("search")
                    ap.evidence.append(f"搜索结果出现包名：{h.title[:50]}")
                    _put(ap)
                    break
        # 官网词的结果直接喂给下面的 _own_site：同名应用各搜一遍官网等于再排两轮引擎锁
        _OWN_SITE_LOG[names[-1]] = [h for h in hits if "官网" in h.title or "官网" in h.snippet] or hits
        if not apps:
            notes.append(f"公开渠道未检索到「{'/'.join(names)}」的应用；"
                         "可改用包名（com.xxx.yyy）或给本地 apk/ipa 走包体提取")
    # 本地包静态提取
    if package_path:
        try:
            ext = await extract_package_async(package_path)
            plat = "ios" if str(package_path).lower().endswith(".ipa") else "android"
            pkg = ext.get("package") or ""
            key = (plat + ":" + pkg) if pkg else ""
            ap = apps.get(key) or AppInfo(name=Path(package_path).stem, platform=plat, package=pkg)
            ap.domains |= ext.get("domains") or set()
            ap.cert_sha256 = ext.get("file_sha256", "") or ap.cert_sha256
            deep = ext.get("apk") or {}
            if deep:
                ap.apk = deep
                if deep.get("package"):
                    ap.package = deep["package"]
                if not ap.version:
                    ap.version = ext.get("version") or ""
            ap.sources.append("package")
            ap.evidence.append(f"本地包静态提取：{package_path}（扫 {ext.get('files_scanned', 0)} 个文件）")
            for line in apkstatic.brief(deep)[:4]:
                ap.evidence.append(f"包体分析：{line}")
            ap.notes += ext.get("notes") or []
            apps[key or f"{plat}:local"] = ap
        except Exception as e:
            notes.append(f"包体提取失败：{str(e)[:80]}")

    # 自有域 vs 第三方 SDK：AppInfo.domains 只留自有域，SDK 域单独归档
    own: set[str] = set()
    sdk: dict[str, str] = {}
    # 只发一次：调用方到点收工后这程还在跑，再交一次会把缓存的 notes 叠成两遍
    if box is not None:
        box["apps"] = apps
    for ap in apps.values():
        site = _site_of(ap)
        if site and not _sdk_of(site):
            ap.domains.add(site)
            own.add(site)
        for d in ap.domains:
            root = root_domain(d) or d
            tag = _sdk_of(root)
            if tag:
                sdk[root] = tag
                ap.sdk_domains[root] = tag
            else:
                own.add(root)
        # 按根域挡：sdk 里存的是根域，只比全名会让 developer.android.com 这类子域漏进自有域
        ap.domains = {d for d in ap.domains if root_domain(d) not in sdk}

    # 市场上架但没给官网字段（应用宝详情页的 website 实测为空），用包名再搜一次官网：
    # 没有自有域这条线只剩开发者名，主体扩线一旦超时就整条断掉
    if not own:
        # 先按应用名查：记录里 store_url 只指向商店页，拿不到品牌站；查询词用应用名而不是包名，
        # 包名切词会搜回 lucky666 这类无关站。同名应用共用同一批官网词结果，只查一次。
        cand = [a for a in apps.values() if a.package][:2]
        aname = (cand[0].name if cand and cand[0].name else names[-1])
        # 搜索词用的是 target，不是品牌短名
        hits = _OWN_SITE_LOG.pop(names[-1], None) or _OWN_SITE_LOG.pop(target, None)
        if aname == names[-1]:
            hits = hits or _OWN_SITE_LOG.pop(target, None)
        site = await _hop(_own_site(aname, hits), 8) if hits is not None else ""
        if isinstance(site, str) and site and not _sdk_of(site):
            # 一条应用都没采到时 cand 是空的：官网依然要收进自有域，只是没有条目可挂
            if cand:
                ap = cand[0]
                ap.domains.add(site)
                ap.evidence.append(f"官网检索：{aname} → {site}")
            own.add(site)

    # 开发者名 → 企业主体扩线（这是 App 线索转域名最有效的一步）
    # iTunes 的 sellerName 常是「某某科技有限公司」也有「XX Inc.」，只对中文主体形态扩线；
    # 英文发行商名拿去搜企业只会搜回 App Store 自己。
    # 主体扩线中途才设 _DEPTH，这里早于它读一次，整程结束时恢复
    deep = not _DEPTH.get()
    if deep:
        _DEPTH.set(True)
    domains: set[str] = set(own)
    # 扩线是本程最后一段，只做一次：从它开始由 _late_merge 把域补进缓存，这以后
    # 再写 box 会把「采集中」的清单盖回去
    if box is not None:
        box["out"] = {"items": [ap.as_dict() for ap in list(apps.values())[:max(limit, 1)]],
                      "domains": sorted(d for d in domains if is_valid_domain(d)),
                      "sdk_domains": sdk, "notes": list(notes)}
    # 主体扩线会把 collect_apps 连同本函数整串递归回来（品牌名 → 公司全名 → 品牌名），
    # 上一层已经在做主体扩线时这层只交市场结果，否则单次调用会被拖成分钟级
    devs = {ap.developer for ap in apps.values()
            if deep and ap.developer and naming.is_org_name(ap.developer)}
    # 公司全名只在包名类输入里才是「要扩的主体」：名称类输入这里已经是在给它找应用的上一程，
    # 拿全名回灌一轮主体扩线只剩重复的工商 + 备案 + 移动端五跳
    if is_entity:
        devs.discard(target)
    if devs:
        from . import enterprise

        # 主体扩线各跑各的搜索，串行会把 8 秒拉到一分多钟；并发后按主体名去重合并
        targets = list(devs)[:3]

        def _late(dev: str, ent: dict | None, err: str) -> None:
            # 三个扩线协程并发回来，要么只动箱（主协程不看）要么只动缓存（自带锁），
            # 不许在这里碰主协程的清单与 notes
            if err or not ent:
                box.setdefault("late_notes", []).append(err or f"开发者扩线无结果 {dev}")
                return
            got = [d for d in (ent.get("domains") or []) if is_valid_domain(d)]
            box.setdefault("late_domains", []).extend(got)
            if not got:
                # 扩线本身又被总时限截断时，只有打分确认的域先记下，别留成「无结果」
                box.setdefault("late_notes", []).append(f"开发者扩线未确认域 {dev}")
            box.setdefault("late_notes", []).extend(ent.get("notes") or [])
            # 晚到也算数：把域补进缓存，下次同名直接带上
            _late_merge(_BRAND_KEY.get(), got)

        async def _expand(dev: str) -> None:
            # 主体扩线内部是「工商 → 备案 → 评分 → 移动端」五跳串起来的，实测 18s 起步，
            # 工商接口慢时能拖到分钟级；扩线压在采集的总时限里跑，不如让它续到 30s
            try:
                ent, err = await _hop(enterprise.collect_entity(dev), 30), ""
            except asyncio.TimeoutError:
                ent, err = None, f"开发者扩线超时 {dev}（30s）"
            except Exception as e:
                ent, err = None, f"开发者扩线失败 {dev}: {str(e)[:60]}"
            _late(dev, ent, err)

        # 扩线拖过总时限时外层已经把箱里的清单交出去了，再等它只会让整程超时；
        # 这一程只让它跑完 _late 把域补进缓存，本函数立刻交已有的市场结果
        async def _all(ds: list[str]) -> None:
            await asyncio.gather(*(_expand(d) for d in ds))

        exp = asyncio.create_task(_all(targets))
        try:
            await asyncio.wait_for(asyncio.shield(exp), _EXPAND_WAIT)
        except asyncio.TimeoutError:
            notes.append("开发者扩线未完，域稍后补进缓存，同名下一轮直接带上")

    if deep:
        _DEPTH.set(False)

    out = {"items": [ap.as_dict() for ap in list(apps.values())[:limit]],
           "domains": sorted(d for d in domains if is_valid_domain(d)),
           "sdk_domains": sdk,
           "notes": list(dict.fromkeys(notes))[:8]}
    # 主协程收工时扩线可能还在跑：它回来会再写一遍箱，带上晚到的域与说明
    out["_box"] = box
    if box is not None:
        box["out"] = out
    return out
