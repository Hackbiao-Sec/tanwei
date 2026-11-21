"""小程序包敏感信息提取：解包 → 解密 → 按规则分桶（API / URL / 账号密码 / Key / 静态资源）。

抓小程序资产不能只看「名字 → AppID → 主体」，包内容才是接口和密钥的出处。
这里补齐包这一层，三条数据来源：

- 本地包：本机微信客户端缓存目录，`mini_cache_roots` / `mini_appids` 自动发现。
  4.1.6 之后客户端把包封成 `V1MM` 密文，密钥由 AppID（目录名）派生，纯本地可解，
  不需要登录态、不读别的进程内存。
- 线上包：`servicewechat.com` 上的公开静态资源（无鉴权），版本先探 `{appid}/0/` 跳转。
- 已解包目录：调用方直接 `scan_dir`。

容器格式（明文解出后）：`0xBE` + info1(4) + indexLen(4) + bodyLen(4) + `0xED`
+ fileCount(4)，随后是索引项（名字长度 + 名字 + 偏移 + 长度），再往后是文件体。

秘钥派生与封面全部走标准库：`hashlib.pbkdf2_hmac` + 本文件内的 AES-256-CBC 实现，
不新增运行依赖，打包成单文件 exe 也不会缺模块。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import httpx

from ...utils import run_blocking

UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.40")


# ─────────────── 纯标准库 AES-256-CBC ───────────────
# 只用来解包首那 1024 字节的密文头，量很小；不引 cryptography，避免打包缺 wheel。

def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = (q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^
             ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))) & 0xFF
        x ^= 0x63
        sbox[p] = x
        inv[x] = p
        if p == 1:
            break
    sbox[0] = 0x63
    inv[0x63] = 0
    return sbox, inv


_SBOX, _INV_SBOX = _build_sbox()


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _gmul(a: int, b: int) -> int:
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        b >>= 1
        a = _xtime(a)
    return out & 0xFF


_MUL: dict[int, list[int]] = {c: [_gmul(c, i) for i in range(256)] for c in (9, 11, 13, 14)}


def _round_keys(key: bytes) -> list[list[int]]:
    """AES-256 密钥扩展，返回 15 组按列展开的轮密钥。"""
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        prev = w[i - nk]
        w.append([prev[j] ^ temp[j] for j in range(4)])
    return [[b for word in w[4 * r:4 * r + 4] for b in word] for r in range(nr + 1)]


def _inv_shift_rows(s: list[int]) -> list[int]:
    # 扁平下标 i = 行 r + 4*列 c；逆移位后 new[r + 4c] = old[r + 4*((c-r) mod 4)]
    return [s[(i & 3) + 4 * (((i >> 2) - (i & 3)) % 4)] for i in range(16)]


def _inv_mix_columns(s: list[int]) -> list[int]:
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        out[4 * c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        out[4 * c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        out[4 * c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        out[4 * c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
    return out


def _decrypt_block(rks: list[list[int]], block: bytes) -> bytes:
    s = [a ^ b for a, b in zip(block, rks[14])]
    for rnd in range(13, 0, -1):
        s = [_INV_SBOX[b] for b in _inv_shift_rows(s)]
        s = [a ^ b for a, b in zip(s, rks[rnd])]
        s = _inv_mix_columns(s)
    s = [_INV_SBOX[b] for b in _inv_shift_rows(s)]
    return bytes(a ^ b for a, b in zip(s, rks[0]))


_KEY_CACHE: dict[bytes, list[list[int]]] = {}


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("密文长度不是 16 的倍数")
    rks = _KEY_CACHE.get(key)
    if rks is None:
        rks = _round_keys(key)
        _KEY_CACHE[key] = rks
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(rks, block), prev))
        prev = block
    return bytes(out)


# ─────────────── 抽取规则 ───────────────
# 只留对找洞有用的几类；字段沿用 id/name 便于前端展示，正则为 Python re 写法。
# bucket 决定前端分页（对齐本地小程序审计工具的五个页签）。
RULES: tuple[dict[str, Any], ...] = (
    {"id": "api", "name": "接口路径", "bucket": "API",
     # 小程序把接口写进字符串常量或对象字面量，两侧引号有无都可能；
     # 只要求「/xxx/api/...」这种带业务前缀的路径，避免把包内文件路径也收进来。
     "gate": ("api", "gw", "gateway", "service/", "openapi"),
     "re": r"""(?i)(?<![\w/])/(?:[a-z0-9_-]*/){0,2}(?:[a-z0-9_-]*)?(?:api|apis|gw|gateway|service|openapi)/[A-Za-z0-9_\-/{}.$:]{2,120}"""},
    {"id": "url", "name": "URL", "bucket": "URL",
     "gate": ("http",),
     # 字符集去掉引号和括号：否则会把 `x.png';return(nv_src` 这类代码尾巴一起吞进来
     "re": r"""https?://[A-Za-z0-9\-._~:/?#\[\]@!$&*+,;=%]{6,200}"""},
    {"id": "account", "name": "账号密码", "bucket": "账号密码",
     "gate": ("pass", "pwd", "user", "account", "secret", "key", "token"),
     "re": r"""(?i)\b((?:user_?name|account|passwd|password|pwd|secret|app_?secret|access_?key|appkey|token)["']?\s*[:=]\s*["'][^"'\s]{3,80}["'])"""},
    {"id": "key", "name": "密钥", "bucket": "Key",
     "gate": ("akia", "ltai", "akid", "sk-", "ghp_", "xox", "eyj", "private key",
              "secret", "key", "token"),
     # 云厂商 AK / 平台令牌 / PEM 私钥 / 赋值式的 appSecret、signKey、AES 密钥与 IV
     "re": (r"""(?i)(?:\b(?:AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,20}|AKID[0-9A-Za-z]{10,40}"""
            r"""|sk-[A-Za-z0-9]{20,64}|ghp_[A-Za-z0-9]{30,40}|xox[baprs]-[A-Za-z0-9\-]{10,60}"""
            r"""|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"""
            r"""|-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"""
            r"""|(?:app_?(?:secret|key)|secret_?key|sign_?key|aes_?key|des_?key|encrypt_?key"""
            r"""|client_?secret|api_?key|access_?key|access_?token|mch_?key|pay_?key)"""
            r"""\s*[:=]\s*['"]([0-9A-Za-z_\-+/=]{6,120})['"])""")},
    {"id": "static", "name": "静态资源", "bucket": "静态资源",
     "gate": (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".mp4",
              ".mp3", ".wav", ".woff", ".ttf", ".eot"),
     # 两侧必须带引号，避免把 `png';return` 这种代码尾巴当资源
     "re": r"""(?i)["'(]\s*(?:\.{0,2}/)?([A-Za-z0-9_\-./]{2,80}\.(?:png|jpe?g|gif|webp|svg|ico|mp4|mp3|wav|woff2?|ttf|eot))["')]"""},
    {"id": "phone", "name": "手机号", "bucket": "手机号",
     "gate": ("1",),
     "re": r"\b((?:\+?86)?1[3-9]\d{9})\b"},
    {"id": "idcard", "name": "身份证", "bucket": "身份证",
     "gate": ("1", "2", "3", "4", "5", "6", "7", "8", "9"),
     "re": r"\b([1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])\b"},
    {"id": "jdbc", "name": "连接串", "bucket": "连接串",
     "gate": ("jdbc", "://"),
     "re": r"""(?i)\b(?:jdbc:[a-z]+://[^\s"'<>]{8,200}|(?:mysql|postgres(?:ql)?|mongodb|redis|amqp)://[^\s"'<>]{8,200})"""},
    {"id": "inner_host", "name": "内网主机", "bucket": "内网主机",
     "gate": ("10.", "127.", "192.168", "172.1", "172.2", "172.3"),
     "re": r"""\b((?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b"""},
)

_COMPILED: tuple[tuple[dict[str, Any], re.Pattern[str]], ...] = tuple(
    (r, re.compile(r["re"])) for r in RULES)

# 分桶顺序与页签标题（前端按这个顺序渲染，缺桶不显示）
BUCKETS: tuple[tuple[str, str], ...] = (
    ("api", "API"), ("url", "URL"), ("account", "账号密码"), ("key", "Key"),
    ("static", "静态资源"), ("phone", "手机号"), ("idcard", "身份证"),
    ("jdbc", "连接串"), ("inner_host", "内网主机"),
)
_BUCKET_LABEL = dict(BUCKETS)

# 静态资源后缀：URL 规则里遇到就改投静态资源桶，不再当接口
_STATIC_TAIL = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".woff", ".woff2",
                ".ttf", ".eot", ".ico", ".mp4", ".mp3", ".wav")
# 二进制文件：只登记名字进静态资源，不进正则
_BINARY_EXTS = _STATIC_TAIL + (".zip", ".so", ".dll", ".br", ".gz", ".jar", ".pak")
# 第三方 SDK 的固定域名，扫出来也没法打
_NOISE_HOST = ("w3.org", "schema.org", "json-schema.org", "qq.com/miniprogram", "schema",
               "example.com", "localhost", "res.wx.qq.com", "dldir1.qq.com")

FILE_EXTS = (".js", ".json", ".wxml", ".wxss", ".wxs", ".html", ".txt", ".sitemap.json")

# 小程序包在微信 CDN 上的公开路径（无鉴权）
_BUNDLE_PATHS = ("page-frame.html", "app-config.json", "app-service.js", "app-wxss.js")

# 主体名：包里的「关于我们」「版权」常写全称，取出现次数最多的那个
_COMPANY_RE = re.compile(
    r"[\u4e00-\u9fa5]{2,18}(?:股份有限公司|有限责任公司|有限公司|集团|研究院|设计院|检测院|中心|工作室|医院|大学|学院|协会|事务所)")
_GH_RE = re.compile(r"\bgh_[0-9a-f]{6,20}\b", re.I)

# 页面通用标题：这些是栏目名，不是小程序名
_GENERIC_TITLES = frozenset("""
首页 主页 详情 我的 设置 消息 搜索 登录 注册 扫码 附近 服务 列表 更多 加载中
个人中心 欢迎使用 我的信息 我的办件 我的服务档案 购物车 我的订单 订单详情
订单填写 协议详情 服务单详情 用户协议 隐私政策 关于我们 版本信息 提示 错误
反馈 客服 提交 确认 编辑 新增 结果 支付 首页推荐 全部 分类 排行 帮助 帮助中心
""".split())

# 功能页标题的结尾词：这类标题描述的是这一页干什么，不是小程序叫什么
_FUNC_TITLE_RE = re.compile(
    r"(详情|列表|记录|进群|表单|须知|声明|介绍|排行|分类|全部|更多|帮助|客服|提示|错误|结果)$")


@dataclass
class ScanResult:
    appid: str = ""
    version: str = ""
    files: int = 0
    bytes: int = 0
    hits: dict[str, list[str]] = field(default_factory=dict)   # 规则 id → 命中值
    apis: list[str] = field(default_factory=list)
    domains: set = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    # 主体还原：包内标题、应用名候选、gh_ 号、入口页
    titles: list[str] = field(default_factory=list)
    name_votes: dict[str, int] = field(default_factory=dict)   # 页标题 → 出现页数
    page_titles: dict[str, str] = field(default_factory=dict)  # 页面路径 → 标题
    tab_texts: set = field(default_factory=set)                # 页签文案，功能名
    subject: str = ""
    gh_ids: list[str] = field(default_factory=list)
    entry: str = ""
    match: str = ""        # high / low / 空（未给目标）
    match_words: list[str] = field(default_factory=list)
    encrypted: bool = False

    def app_name(self) -> str:
        """从页标题里挑应用名：应用级标题优先，其次入口页，最后页数投票。"""
        entry_title = ""
        if self.entry:
            entry_title = (self.page_titles.get(self.entry)
                           or self.page_titles.get(self.entry + ".html") or "")
        cands: list[tuple[tuple[int, int], str]] = []
        for title, votes in self.name_votes.items():
            t = title.strip()
            if not (1 < len(t) <= 20):
                continue
            if t in _GENERIC_TITLES or t in self.tab_texts:
                continue
            if "/" in t or t.startswith("_") or t.startswith("."):
                continue
            if re.search(r"[A-Za-z]{3,}", t) or not re.search(r"[\u4e00-\u9fa5]", t):
                continue
            key = (votes + (3 if t == entry_title else 0), -len(t))
            cands.append((key, t))
        if not cands:
            return ""
        # 功能页标题（活动详情 / 进群 / 我的订单）不是应用名：有更像名字的候选就先排除；
        # 一个都不剩（整包只有功能页）再退回原候选，别把名字交白卷。
        good = [(k, t) for k, t in cands if not _FUNC_TITLE_RE.search(t)]
        return max(good or cands)[1]

    def counts(self) -> dict[str, int]:
        return {rid: len(self.hits.get(rid) or []) for rid, _ in BUCKETS}

    def buckets(self) -> list[dict[str, Any]]:
        out = []
        for rid, label in BUCKETS:
            vals = self.hits.get(rid) or []
            if vals:
                out.append({"id": rid, "label": label, "count": len(vals)})
        return out

    def merge(self, other: "ScanResult") -> None:
        """把另一个包的扫描结果并进来：一个 AppID 常拆主包 + 分包，各扫各的再合。"""
        self.files += other.files
        self.bytes += other.bytes
        self.encrypted = self.encrypted or other.encrypted
        for rid, vals in (other.hits or {}).items():
            bucket = self.hits.setdefault(rid, [])
            for v in vals:
                _push(bucket, v)
        for url in other.apis:
            if url not in self.apis and len(self.apis) < 2000:
                self.apis.append(url)
        self.domains.update(other.domains)
        for note in other.notes:
            if note and note not in self.notes:
                self.notes.append(note)
        for title in other.titles:
            if title not in self.titles:
                self.titles.append(title)
        for title, votes in (other.name_votes or {}).items():
            self.name_votes[title] = self.name_votes.get(title, 0) + votes
        for page, title in (other.page_titles or {}).items():
            self.page_titles.setdefault(page, title)
        self.tab_texts.update(other.tab_texts or ())
        for gh in other.gh_ids:
            if gh not in self.gh_ids and len(self.gh_ids) < 20:
                self.gh_ids.append(gh)
        if not self.entry and other.entry:
            self.entry = other.entry
        if len(other.subject) > len(self.subject):
            self.subject = other.subject
        if not self.version and other.version:
            self.version = other.version

    def as_dict(self) -> dict:
        return {"appid": self.appid, "version": self.version, "files": self.files,
                "bytes": self.bytes,
                "hits": {k: v[:40] for k, v in self.hits.items()},
                "apis": self.apis[:60], "domains": sorted(self.domains)[:60],
                "notes": self.notes,
                "name": self.app_name(),
                "titles": self.titles[:8], "subject": self.subject,
                "gh_ids": self.gh_ids[:8], "entry": self.entry,
                "match": self.match, "match_words": self.match_words[:6],
                "encrypted": self.encrypted,
                "counts": self.counts(), "buckets": self.buckets()}


def _push(bucket: list[str], val: str, cap: int = 200) -> bool:
    if len(bucket) >= cap or not val:
        return False
    if val in bucket:
        return False
    bucket.append(val)
    return True


def scan_text(box: ScanResult, text: str, source: str = "") -> None:
    """对一段文本跑全部规则；去重、限量，避免把整包塞进结果。"""
    if not text:
        return
    low = text.lower()
    for rule, rx in _COMPILED:
        rid = rule["id"]
        bucket = box.hits.setdefault(rid, [])
        if len(bucket) >= 200:
            continue
        # 前置字面量闸：整包几十兆时，靠它跳过绝大多数必然无命中的规则
        gate = rule.get("gate")
        if gate and not any(g in low for g in gate):
            continue
        for m in rx.finditer(text):
            # 一条正则里可能有多组候选，取第一个非空分组；都没分组就用整段命中
            val = ""
            for g in m.groups():
                if g:
                    val = g
                    break
            val = (val or m.group(0)).strip().strip("'\"").rstrip(".,;:")
            if not val:
                continue
            if rid == "url":
                vlow = val.lower()
                if any(n in vlow for n in _NOISE_HOST):
                    continue
                if vlow.endswith(_STATIC_TAIL):
                    _push(box.hits.setdefault("static", []), val)
                    continue
                host = re.sub(r"^https?://", "", vlow).split("/")[0]
                if host:
                    box.domains.add(host)
            elif rid == "api":
                if len(val) > 120:
                    continue
                if val not in box.apis:
                    box.apis.append(val)
            elif rid == "static":
                if len(val) < 5:
                    continue
                _push(box.hits.setdefault("static", []), val)
                continue
            elif rid == "account":
                # `account:"1042"` 这种纯数字是对象 id，当账号密码只会灌噪声
                if re.fullmatch(r"(?i)[^=:]*[=:]\s*['\"]\d+['\"]", val):
                    continue
            _push(bucket, val)
    for m in _GH_RE.finditer(text):
        _push(box.gh_ids, m.group(0), cap=20)


def _want(path: str) -> bool:
    low = path.lower()
    return low.endswith(FILE_EXTS) or low.endswith(".wxml") or "/" not in low


def scan_dir(root: str, *, appid: str = "", max_bytes: int = 60_000_000) -> ScanResult:
    """扫一份已解包的小程序目录。"""
    box = ScanResult(appid=appid)
    if not os.path.isdir(root):
        box.notes.append(f"目录不存在：{root}")
        return box
    total = 0
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            full = os.path.join(dirpath, name)
            if not _want(name):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > 8_000_000:
                continue
            total += size
            if total > max_bytes:
                box.notes.append("超过扫描上限，后续文件已跳过")
                break
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    scan_text(box, fh.read(), full)
                box.files += 1
            except OSError:
                continue
    box.bytes = total
    return box


# ─────────────── 包解密 ───────────────
# 4.1.6 起的客户端把包首换成 `V1MMWX` + 1 字节版本，随后 1024 字节是 AES-256-CBC
# 密文头，正文整体按单字节 XOR 处理。密钥由 AppID 派生（PBKDF2-HMAC-SHA1 / 1000 轮 /
# 32 字节），IV 固定；XOR 键取 AppID 倒数第二个字符。全部是本机文件，离线可解。
_ENCRYPTED_MAGIC = b"V1MM"
_SALT = b"saltiest"
_IV = b"the iv: 16 bytes"
_ENC_HEAD = 1030          # 6 字节前缀 + 1024 字节密文头
_WXAPKG_MAGIC = 0xBE
_WXAPKG_TAIL = 0xED
_APPID_DIR_RE = re.compile(r"^wx[0-9a-f]{16}$", re.I)
_XOR_CACHE: dict[int, bytes] = {}


def _xor_table(k: int) -> bytes:
    table = _XOR_CACHE.get(k)
    if table is None:
        table = bytes(b ^ k for b in range(256))
        _XOR_CACHE[k] = table
    return table


def is_encrypted_pkg(pkg_path: str) -> bool:
    """判断包是不是新版加密封装（`V1MM` 开头）。"""
    try:
        with open(pkg_path, "rb") as fh:
            return fh.read(4) == _ENCRYPTED_MAGIC
    except OSError:
        return False


def appid_from_path(path: str) -> str:
    """从缓存路径里认出 AppID（目录名形如 wx + 16 位十六进制）。"""
    parts = os.path.normpath(path).split(os.sep)
    for part in reversed(parts[:-1]):
        if _APPID_DIR_RE.match(part):
            return part
    return ""


def decrypt_pkg_bytes(appid: str, data: bytes) -> bytes:
    """解开 `V1MM` 封装，返回明文 wxapkg；明文包原样返回。"""
    if not data or data[:4] != _ENCRYPTED_MAGIC:
        return data
    if not appid or not _APPID_DIR_RE.match(appid):
        raise ValueError("加密包缺少 AppID（缓存目录名），无法派生密钥")
    if len(data) <= _ENC_HEAD:
        raise ValueError("加密包长度不足，已跳过")
    dk = hashlib.pbkdf2_hmac("sha1", appid.encode(), _SALT, 1000, 32)
    head = _aes_cbc_decrypt(dk, _IV, data[6:_ENC_HEAD])
    xk = ord(appid[-2]) if len(appid) >= 2 else 0x66
    body = data[_ENC_HEAD:].translate(_xor_table(xk))
    return head[:1023] + body


def load_pkg_bytes(pkg_path: str, appid: str = "") -> tuple[bytes, bool]:
    """读包并自动解密，返回 (明文, 是否解过密)。"""
    with open(pkg_path, "rb") as fh:
        data = fh.read()
    aid = appid or appid_from_path(pkg_path)
    sealed = data[:4] == _ENCRYPTED_MAGIC
    return decrypt_pkg_bytes(aid, data), sealed


def _pkg_index(pt: bytes) -> tuple[list[tuple[str, int, int]], int]:
    """解析容器索引，返回 [(名字, 偏移, 长度)] 与正文起点。"""
    if len(pt) < 18 or pt[0] != _WXAPKG_MAGIC or pt[13] != _WXAPKG_TAIL:
        return [], 0
    index_len = struct.unpack(">I", pt[5:9])[0]
    body_start = 18 + index_len
    if index_len <= 0 or body_start > len(pt):
        return [], 0
    out: list[tuple[str, int, int]] = []
    pos, end = 18, 18 + index_len
    while pos + 4 <= end:
        name_len = struct.unpack(">I", pt[pos:pos + 4])[0]
        if name_len <= 0 or name_len > 1024 or pos + 4 + name_len + 8 > end:
            break
        name = pt[pos + 4:pos + 4 + name_len].decode("utf-8", "ignore")
        pos += 4 + name_len
        off, size = struct.unpack(">II", pt[pos:pos + 8])
        pos += 8
        if name:
            out.append((name, off, size))
    return out, body_start


def unpack_bytes(pt: bytes, out_dir: str, *, text_only: bool = False) -> int:
    """把明文容器落到目录，返回写出文件数。"""
    entries, body_start = _pkg_index(pt)
    if not entries:
        return 0
    count = 0
    for name, off, size in entries:
        low = name.lower()
        if text_only and (low.endswith(_BINARY_EXTS) or "/" not in low):
            continue
        blob = pt[off:off + size] if off >= 0 else b""
        if not blob:
            continue
        safe = os.path.normpath(name).replace("..", "_").lstrip("\\/")
        target = os.path.join(out_dir, safe)
        try:
            os.makedirs(os.path.dirname(target) or out_dir, exist_ok=True)
            with open(target, "wb") as out:
                out.write(blob)
            count += 1
        except OSError:
            continue
    return count


def unpack_wxapkg(pkg_path: str, out_dir: str, appid: str = "") -> int:
    """解 wxapkg 到目录（密文自动解密），返回解出的文件数。"""
    try:
        pt, _sealed = load_pkg_bytes(pkg_path, appid=appid)
    except (OSError, ValueError):
        return 0
    return unpack_bytes(pt, out_dir)


def decrypt_pkg(pkg_path: str, out_path: str, limit: int = 200_000_000) -> bool:
    """解密单个包并写到 `out_path`，成功返回 True。"""
    try:
        pt, sealed = load_pkg_bytes(pkg_path)
    except (OSError, ValueError):
        return False
    if not sealed:
        return False
    if len(pt) > limit:
        return False
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(pt)
    except OSError:
        return False
    return True


def _add_static(box: ScanResult, name: str) -> None:
    _push(box.hits.setdefault("static", []), name.lstrip("/"), cap=200)


def _read_app_config(box: ScanResult, text: str) -> None:
    """从 app-config.json / 页面 json 取应用名、页签文案、入口页。"""
    try:
        cfg = json.loads(text)
    except Exception:
        return
    if not isinstance(cfg, dict):
        return

    def add_title(v: Any, weight: int = 1) -> None:
        if isinstance(v, str):
            v = v.strip()
            if 1 < len(v) <= 40:
                box.name_votes[v] = box.name_votes.get(v, 0) + max(1, weight)
                if v not in box.titles:
                    box.titles.append(v)

    def add_win(win: Any, weight: int = 1) -> None:
        if isinstance(win, dict):
            add_title(win.get("navigationBarTitleText"), weight)

    # 应用级标题（app-config 顶层的 navigationBarTitleText / window 里那个）就是小程序
    # 自己的名字；各页标题多是「活动详情」「进群」这类功能名。以前两者同票，页数一多
    # 功能名就压过品牌名，清单里的小程序名读出来全是「活动详情」。给应用级标题 6 票，
    # 品牌名在没有任何页标题时也能立住。
    add_title(cfg.get("navigationBarTitleText"), 6)
    add_win(cfg.get("window"), 6)
    tab = cfg.get("tabBar")
    if isinstance(tab, dict):
        for item in (tab.get("list") or [])[:12]:
            if isinstance(item, dict):
                label = item.get("text")
                if isinstance(label, str) and label.strip():
                    # 页签文案是功能名（首页/产品/我的），不参与应用名评选
                    box.tab_texts.add(label.strip())
    # 新版基础库把每页的 window 收进 app-config 的 page 表，顶层只有页面清单，
    # 标题（含小程序名）全在这一层；不看这里就只剩页数没有名字
    page = cfg.get("page")
    if isinstance(page, dict):
        for path, sub in list(page.items())[:200]:
            if not isinstance(sub, dict):
                continue
            title = sub.get("navigationBarTitleText")
            if not isinstance(title, str) and isinstance(sub.get("window"), dict):
                title = sub["window"].get("navigationBarTitleText")
            add_win(sub.get("window"))
            add_title(title)
            if isinstance(path, str) and isinstance(title, str) and title.strip():
                box.page_titles[path.strip()[:200]] = title.strip()
    if not box.entry:
        entry = cfg.get("entryPagePath")
        if isinstance(entry, str) and entry:
            box.entry = entry[:200]
        else:
            pages = cfg.get("pages")
            if isinstance(pages, list) and pages:
                box.entry = str(pages[0])[:200]
    for key in ("subPackages", "subpackages", "sub_packages"):
        subs = cfg.get(key)
        if isinstance(subs, list):
            for sub in subs[:12]:
                if isinstance(sub, dict):
                    add_title(sub.get("name"))


def scan_pkg_plain(pt: bytes, box: ScanResult, *, max_bytes: int = 60_000_000) -> None:
    """在已解密的容器上按索引抽文本文件跑规则。"""
    entries, body_start = _pkg_index(pt)
    if not entries:
        box.notes.append("包索引解析失败，按整包明文扫")
        text = pt.decode("utf-8", "ignore")
        box.bytes += len(text)
        scan_text(box, text)
        return
    total = 0
    companies: Counter[str] = Counter()
    for name, off, size in entries:
        low = name.lower()
        if low.endswith(_BINARY_EXTS):
            _add_static(box, name)
            continue
        # off 是绝对偏移（含容器头），不能再叠 body_start，否则整包文本都错位
        blob = pt[off:off + size]
        if not blob:
            continue
        if b"\x00" in blob[:2048]:
            _add_static(box, name)
            continue
        total += size
        if total > max_bytes:
            box.notes.append("包内文本超过扫描上限，后续文件已跳过")
            break
        text = blob.decode("utf-8", "ignore")
        box.bytes += len(text)
        scan_text(box, text, name)
        if low.endswith(".json"):
            if "app-config" in low:
                _read_app_config(box, text)
            elif len(text) < 200_000:
                _read_app_config(box, text)
        # 主体名只在配置/模板里找：JS 太长、收益低
        if low.endswith((".json", ".wxml", ".html", ".txt")):
            for m in _COMPANY_RE.finditer(text[:2_000_000]):
                companies[m.group(0)] += 1
        box.files += 1
    if companies:
        top = companies.most_common(3)
        box.subject = top[0][0]
        box.notes.append("主体候选：" + "、".join(f"{n}({c})" for n, c in top))


def scan_pkg_bytes(appid: str, data: bytes, box: ScanResult | None = None, *,
                   max_bytes: int = 60_000_000) -> ScanResult:
    """在内存里解一个包（密文自动解密）并扫描。"""
    box = box or ScanResult(appid=appid)
    if not data:
        return box
    sealed = data[:4] == _ENCRYPTED_MAGIC
    try:
        pt = decrypt_pkg_bytes(appid, data)
    except ValueError as e:
        box.notes.append(str(e))
        scan_text(box, data.decode("utf-8", "ignore"), "raw:utf8")
        scan_text(box, data.decode("latin-1", "ignore"), "raw:latin1")
        box.encrypted = True
        return box
    if sealed:
        box.encrypted = True
    scan_pkg_plain(pt, box, max_bytes=max_bytes)
    return box


def scan_pkg_raw(pkg_path: str, *, appid: str = "", max_bytes: int = 60_000_000) -> ScanResult:
    """单个包 → 扫描结果（能解就解，解不了按原始字节兜底）。"""
    box = ScanResult(appid=appid)
    try:
        with open(pkg_path, "rb") as fh:
            raw = fh.read(max_bytes)
    except OSError as e:
        box.notes.append(f"读取失败：{type(e).__name__}")
        return box
    box.bytes = len(raw)
    scan_pkg_bytes(appid or appid_from_path(pkg_path), raw, box)
    if not box.apis and not box.domains:
        box.notes.append("包内容解不出可读接口或域名")
    return box


def _beautify_tree(dest: str, *, limit: int = 3, max_bytes: int = 4_000_000,
                   workers: int = 4) -> tuple[int, str]:
    """把解出来的 JS 另存一份可读版本，返回 (个数, 目录)。

    小程序包里的脚本是压缩过的单行巨串，命中位置人眼看不了。原包原样保留，
    美化件统一落到 `_pretty/` 下同名文件，两边都能对着看。
    只挑体积最大的那几个：业务逻辑都在主包里，几百个小工具文件美化一遍
    纯烧时间（单核 Python 美化一个几兆的包就要秒级），对看接口没有帮助。
    """
    if not dest or not os.path.isdir(dest):
        return 0, ""
    try:
        from ..beauty import beauty_js
    except Exception:
        return 0, ""
    out_root = os.path.join(dest, "_pretty")
    cands: list[tuple[int, str]] = []
    for root, _dirs, files in os.walk(dest):
        if os.path.abspath(root).startswith(os.path.abspath(out_root)):
            continue
        for fname in files:
            if not fname.lower().endswith((".js", ".wxs")):
                continue
            src = os.path.join(root, fname)
            try:
                size = os.path.getsize(src)
            except OSError:
                continue
            if size < 2048 or size > max_bytes:
                continue
            cands.append((size, src))
    if not cands:
        return 0, ""
    cands.sort(reverse=True)
    picked = cands[:max(1, limit)]

    def _one(src: str) -> bool:
        try:
            with open(src, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            if not text.strip():
                return False
            pretty = beauty_js(text)
            rel = os.path.relpath(src, dest)
            target = os.path.join(out_root, rel)
            os.makedirs(os.path.dirname(target) or out_root, exist_ok=True)
            with open(target, "w", encoding="utf-8", newline="\n") as out:
                out.write(pretty or text)
            return True
        except Exception:
            return False

    count = 0
    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        for ok in pool.map(_one, [src for _size, src in picked]):
            if ok:
                count += 1
    finally:
        pool.shutdown(wait=True)
    return count, (out_root if count else "")


def _plain_pkg(appid: str, data: bytes) -> tuple[bytes, bool]:
    """→ (容器明文, 是否密文)。解不开就原样返回，交给兜底扫描。"""
    if data[:4] != _ENCRYPTED_MAGIC:
        return data, False
    try:
        return decrypt_pkg_bytes(appid, data), True
    except ValueError:
        return data, True


def _scan_pkg_file(appid: str, pkg: str, *, out_dir: str = "", max_bytes: int = 60_000_000,
                   unpack: bool = True) -> tuple[ScanResult, dict]:
    """一个 .wxapkg → (扫描结果, 文件级元信息)。可在线程里独立跑。"""
    box = ScanResult(appid=appid)
    info = {"pkg": os.path.basename(pkg), "plain": False, "sealed": False,
            "unpacked": 0, "size": 0}
    try:
        with open(pkg, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError as e:
        box.notes.append(f"读取失败：{type(e).__name__}")
        return box, info
    info["size"] = len(data)
    if not data:
        return box, info
    pt, sealed = _plain_pkg(appid, data)
    info["sealed"] = sealed
    info["plain"] = not sealed
    if sealed:
        box.encrypted = True
    try:
        scan_pkg_plain(pt, box, max_bytes=max_bytes)
    except Exception as e:      # 单个包坏掉不影响整批
        box.notes.append(f"{os.path.basename(pkg)} 解析异常：{type(e).__name__}")
    if unpack and out_dir:
        info["unpacked"] = unpack_bytes(pt, out_dir)
    return box, info


# ─────────────── 本机小程序缓存：发现 + 离线扫描 ───────────────
# 微信客户端把每个小程序的包按 AppID 落在用户目录下，4.1.6 之后换了存放位置
# 并改成按账号哈希分子目录。这里把两代路径都列出来，按存在与否逐个探。

def _cache_candidates() -> list[tuple[str, str]]:
    """所有可能的小程序缓存位置（含不存在的）+ 平台标签。

    不存在的目录也要留着：本机没装微信 / 装在别的账号下时，面板要能说清
    「这 7 个位置都翻过了、都不存在」，而不是只丢一句「没找到缓存」。
    """
    home = os.path.expanduser("~")
    win = [
        os.path.join(os.environ.get("APPDATA", ""), "Tencent", "xwechat", "radium", "users"),
        os.path.join(os.environ.get("APPDATA", ""), "Tencent", "xwechat", "radium", "Applet", "packages"),
        os.path.join(os.environ.get("APPDATA", ""), "Tencent", "WeChat", "Applet", "packages"),
        os.path.join(home, "Documents", "xwechat_files"),
    ]
    mac = [
        os.path.join(home, "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/Applet/packages"),
        os.path.join(home, "Library/Containers/com.tencent.xinWeChat/Data/.wxapplet/packages"),
        os.path.join(home, "Library/Group Containers/5A4RE8SF68.com.tencent.xinWeChat"),
    ]
    out: list[tuple[str, str]] = []
    for p in win:
        if p:
            out.append((p, "windows"))
    for p in mac:
        out.append((p, "macos"))
    return out


def mini_cache_hints() -> list[dict[str, Any]]:
    """缓存位置清单：哪些存在、各自挂几个 AppID。给面板解释「为什么一条都没扫到」。"""
    rows: list[dict[str, Any]] = []
    for path, plat in _cache_candidates():
        ok = os.path.isdir(path)
        apps = 0
        if ok:
            try:
                apps = sum(1 for n in os.listdir(path)
                           if _APPID_DIR_RE.match(n) and os.path.isdir(os.path.join(path, n)))
            except OSError:
                apps = 0
        rows.append({"path": path, "platform": plat, "exists": ok, "apps": apps})
    return rows


def mini_cache_roots() -> list[str]:
    """列出本机微信小程序包缓存可能所在的目录（当前用户，只留存在的）。"""
    cands: list[str] = [p for p, _plat in _cache_candidates() if p and os.path.isdir(p)]
    # 4.1.6+ 的 users\<账号哈希>\applet\packages 要多下一层才找得到
    out: list[str] = []
    for base in cands:
        out.append(base)
        if os.path.basename(base) == "users":
            try:
                for name in os.listdir(base):
                    for sub in ("applet/packages", "applet", "Applet/packages"):
                        p = os.path.join(base, name, sub)
                        if os.path.isdir(p):
                            out.append(p)
            except OSError:
                continue
    # 多个根会互相嵌套（applet/packages ⊂ applet），不归一会把同一批包扫三遍
    seen: set[str] = set()
    uniq: list[str] = []
    for p in out:
        key = os.path.normcase(os.path.realpath(p))
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def mini_appids(cache_roots: list[str] | None = None) -> dict[str, list[str]]:
    """扫缓存目录，返回 {AppID: [包文件路径...]}。

    缓存里的目录名就是 AppID（一个 AppID 常有多份历史版本），
    版本包文件名形如 `__APP__.wxapkg`、`-1.wxapkg`，只收 .wxapkg。
    """
    roots = cache_roots if cache_roots is not None else mini_cache_roots()
    found: dict[str, list[str]] = {}
    seen: set[str] = set()
    for root in roots:
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            if not _APPID_DIR_RE.match(name):
                continue
            d = os.path.join(root, name)
            if not os.path.isdir(d):
                continue
            pkgs = found.setdefault(name, [])
            for dp, _ds, fs in os.walk(d):
                for f in fs:
                    if not f.lower().endswith(".wxapkg"):
                        continue
                    full = os.path.join(dp, f)
                    key = os.path.normcase(os.path.realpath(full))
                    if key in seen:
                        continue
                    seen.add(key)
                    pkgs.append(full)
    return found


def _newest_first(pkgs: list[str]) -> list[str]:
    """同一 AppID 常留多版本，按「版本号 → 修改时间」倒序，最新那版排前面。"""
    groups: dict[str, list[str]] = {}
    for p in pkgs:
        ver = os.path.basename(os.path.dirname(p)) or "0"
        groups.setdefault(ver, []).append(p)

    def score(ver: str) -> tuple[int, float]:
        num = 0
        digits = re.sub(r"\D", "", ver)
        if digits:
            num = int(digits[:12])
        mt = 0.0
        for f in groups[ver]:
            try:
                mt = max(mt, os.path.getmtime(f))
            except OSError:
                pass
        return (num, mt)

    out: list[str] = []
    for ver in sorted(groups, key=score, reverse=True):
        out.extend(sorted(groups[ver]))
    return out


def _version_groups(pkgs: list[str]) -> list[tuple[str, list[str]]]:
    """按版本目录分组、最新在前：[(版本, [包文件名...]), ...]。

    一个小程序在本机常留好几代包，只扫最新一代会漏掉「新版删了、旧版还在」
    的接口；把版本目录全列出来，面板才能说清「一共有几代、扫的是哪一代」。
    """
    groups: dict[str, list[str]] = {}
    for p in _newest_first(pkgs):
        groups.setdefault(os.path.basename(os.path.dirname(p)) or "0", []).append(p)
    return list(groups.items())


_WORD_STOP = {
    "中国", "公司", "集团", "股份", "有限", "科技", "网络", "信息", "技术", "服务",
    "控股", "实业", "投资", "管理", "发展", "企业", "国际", "中心", "分公司",
    "有限公司", "股份有限公司", "有限责任公司", "集团有限公司",
}

_DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}")


def _rel_words(target: str) -> list[str]:
    """目标 → 比对词：整串、去法人后缀的主名、分词。

    域名输入只认整串和它的根域。以前一律按标点分词，「xmsei.cn」被拆成
    「xmsei」「cn」，于是本机上任何带 .cn 域名的小程序都算「域名命中」——
    一个机构跑出微保、抽奖助手、招聘会一堆别人的小程序，整页打偏。
    """
    t = (target or "").strip()
    if not t:
        return []
    if _DOMAIN_RE.fullmatch(t):
        low = t.lower()
        words = {low}
        parts = low.split(".")
        if len(parts) >= 2:
            words.add(".".join(parts[-2:]))
            # 根域的主名段长度够（≥5，如 xmsei）才当比对词；短段多是 shop/test
            # 这类通用词，放进来又会把别人的包算成命中
            if len(parts[-2]) >= 5:
                words.add(parts[-2])
        return sorted(words, key=len, reverse=True)
    words: set[str] = set()
    words.add(t)
    for suffix in ("股份有限公司", "有限责任公司", "集团有限公司", "有限公司",
                   "集团", "公司", "股份"):
        if t.endswith(suffix) and len(t) - len(suffix) >= 2:
            # 只剥最长的那个后缀：「…有限公司」再剥一次「公司」会留下「…有限」，
            # 那不是谁的名字，拼进来只是噪声
            words.add(t[:-len(suffix)])
            break
    for part in re.split(r"[^\w\u4e00-\u9fa5]+", t):
        part = part.strip()
        if len(part) >= 3 and part not in _WORD_STOP:
            words.add(part)
    return sorted(words, key=len, reverse=True)


def _relevance(box: ScanResult, words: list[str]) -> tuple[str, list[str]]:
    if not words:
        return "", []
    blob = " ".join([box.app_name()] + box.titles + [box.subject]
                    + sorted(box.domains)).lower()
    hit = [w for w in words if w.lower() in blob]
    return ("high" if hit else "low"), hit


def mini_app_record(appid: str, pkgs: list[str], *, max_pkgs: int = 6,
                    target: str = "", max_bytes: int = 60_000_000,
                    out_root: str = "", workers: int = 8,
                    unpack: bool = True) -> dict[str, Any]:
    """一个 AppID 的本地包 → 解密 → 扫描（分包并行）→ 解包落盘 + JS 美化。

    `out_root` 给了就把这一版的文件解到 `<out_root>/<AppID>/<版本>/`，
    压缩过的脚本另存一份可读版到该目录 `_pretty/`，人可以直接翻。
    """
    item: dict[str, Any] = {"appid": appid, "packages": len(pkgs), "files": 0, "bytes": 0,
                            "apis": [], "domains": [], "hits": {}, "notes": [],
                            "name": "", "titles": [], "subject": "", "gh_ids": [], "entry": "",
                            "counts": {}, "buckets": [], "match": "", "match_words": [],
                            "encrypted": False, "encrypted_count": 0, "plain_count": 0,
                            "unpacked": 0, "unpack_dir": "", "pretty_dir": "", "pretty": 0,
                            "version": "", "versions": [], "version_total": 0}
    if not pkgs:
        item["notes"].append("该 AppID 目录下没有 .wxapkg")
        return item
    exist = [p for p in pkgs if os.path.exists(p)]
    if not exist:
        item["notes"].append("包文件已不存在，可能是客户端清理过缓存")
        return item
    gens = _version_groups(exist)
    top_ver, top_pkgs = gens[0] if gens else ("", [])
    batch = top_pkgs[:max(1, max_pkgs)]
    dest = ""
    if out_root:
        dest = os.path.join(out_root, appid, re.sub(r"[^\w.\-]+", "_", top_ver or "0"))
    box = ScanResult(appid=appid)
    box.version = top_ver
    infos: list[dict] = []
    # 主包 + 分包彼此独立，串行解包在几十兆的包上很慢；这里按包并行，
    # 结果再并回一个 box（去重逻辑在 merge 里）。
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(batch))))
    try:
        futs = [pool.submit(_scan_pkg_file, appid, p, out_dir=dest, max_bytes=max_bytes,
                            unpack=unpack) for p in batch]
        for fut in futs:
            try:
                sub, info = fut.result()
            except Exception as e:
                box.notes.append(f"并行解包异常：{type(e).__name__}")
                continue
            box.merge(sub)
            infos.append(info)
    finally:
        pool.shutdown(wait=True)
    sealed = sum(1 for i in infos if i.get("sealed"))
    plain = sum(1 for i in infos if i.get("plain"))
    item["packages"] = len(batch)
    item["encrypted"] = bool(sealed) and not plain
    item["encrypted_count"] = sealed
    item["plain_count"] = plain
    item["version"] = top_ver
    item["unpacked"] = sum(int(i.get("unpacked") or 0) for i in infos)
    # 版本目录全登记：扫到的这一代给实际数字，其余标「仅登记」。旧版常留着新版
    # 已经删掉的接口，面板上能看出本机还有几代没扫，需要时再单独指定。
    item["versions"] = [{
        "version": ver,
        "dir": os.path.dirname((vp or [""])[0]),
        "packages": len(vp),
        "scanned": ver == top_ver,
        "status": "已扫" if ver == top_ver else "仅登记（旧版本未扫）",
        "encrypted": sealed if ver == top_ver else 0,
        "plain": plain if ver == top_ver else 0,
        "unpacked": item["unpacked"] if ver == top_ver else 0,
    } for ver, vp in gens]
    item["version_total"] = len(gens)
    if len(gens) > 1:
        item["notes"].append(f"本机留了 {len(gens)} 个版本目录，这次扫的是最新的 {top_ver}")
    if sealed:
        item["notes"].append(f"{sealed} 个加密包已用 AppID 派生密钥解开")
    if dest and item["unpacked"]:
        item["unpack_dir"] = dest
        pretty_n, pretty_dir = _beautify_tree(dest)
        item["pretty"] = pretty_n
        if pretty_dir:
            item["pretty_dir"] = pretty_dir
            item["notes"].append(f"解包 {item['unpacked']} 个文件，其中 {pretty_n} 个脚本已美化")
    match, words = _relevance(box, _rel_words(target))
    item.update({
        "files": box.files, "bytes": box.bytes,
        "apis": box.apis[:500], "domains": sorted(box.domains)[:500],
        "hits": {k: v[:40] for k, v in (box.hits or {}).items()},
        "name": box.app_name(),
        "titles": box.titles[:8], "subject": box.subject,
        "gh_ids": box.gh_ids[:8], "entry": box.entry,
        "counts": box.counts(), "buckets": box.buckets(),
        "match": match, "match_words": words[:6],
        "notes": item["notes"] + box.notes[:6],
    })
    return item


# ------------------------------------------------------------ 全量清单 + 磁盘缓存
# 本机缓存常躺几十个小程序，每个包第一次读要跑正则、分桶计数，全量一遍接近一分钟。
# 目标一变就重扫不现实，于是把「读包结果」按包指纹落盘：包没动就复用，只有新包 /
# 改过的包才重读。这样就不用靠少扫几个包来控耗时——少扫会让目标那个包根本没被看过，
# 于是「本机明明有它，结果一条都对不上」。扫不完就如实报 scanned / total / truncated。
_INDEX_VER = 2
_INDEX_KEEP = ("appid", "version", "versions", "version_total", "encrypted",
               "files", "bytes", "apis", "domains", "gh_ids", "entry", "name",
               "titles", "subject", "counts", "buckets", "notes")


def _index_file() -> str:
    from ...config import DATA_DIR
    d = os.path.join(str(DATA_DIR), "applet")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "local_index.json")


def _load_index() -> dict[str, dict]:
    try:
        with open(_index_file(), "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    if not isinstance(raw, dict) or raw.get("_ver") != _INDEX_VER:
        return {}
    apps = raw.get("apps")
    return apps if isinstance(apps, dict) else {}


def _save_index(apps: dict[str, dict]) -> None:
    try:
        path = _index_file()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"_ver": _INDEX_VER, "apps": apps}, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        pass


def _pkg_stamp(pkgs: list[str]) -> str:
    """包指纹：路径 + 大小 + 修改时间。任一变化就说明这代包换了，必须重读。"""
    parts = []
    for p in _newest_first(pkgs):
        try:
            st = os.stat(p)
        except OSError:
            parts.append(f"{p}|0|0")
            continue
        parts.append(f"{p}|{st.st_size}|{int(st.st_mtime)}")
    return "\x1f".join(parts)


def _relevance_dict(rec: dict, words: list[str]) -> tuple[str, list[str]]:
    """缓存记录上的相关度判定，口径与 `_relevance` 一致（只是输入换成了 dict）。"""
    if not words:
        return "", []
    blob = " ".join([str(rec.get("name") or "")] + list(rec.get("titles") or [])
                    + [str(rec.get("subject") or "")]
                    + [str(d) for d in (rec.get("domains") or [])]).lower()
    hit = [w for w in words if w.lower() in blob]
    return ("high" if hit else "low"), hit


def mini_inventory(*, target: str = "", refresh: bool = False,
                   max_pkgs: int = 2, workers: int = 8,
                   budget: float = 0.0) -> dict[str, Any]:
    """本机全部小程序的清单，带磁盘缓存，并按 target 打相关度。

    与 `scan_local_mini` 的差别在「不按数量截断」：先列全，再看哪几个包真的变过。
    `budget` 秒到点就停，停在哪如实报（`scanned` / `total` / `truncated`），
    调用方据此说「这轮扫了多少、还剩多少」，不再用隐形上限少扫然后说对不上。
    """
    t0 = time.time()
    root_map = mini_appids()
    dirs = mini_cache_hints()
    words = _rel_words(target)
    out: dict[str, Any] = {"apps": [], "total": len(root_map), "scanned": 0,
                           "cached": 0, "truncated": False, "elapsed": 0.0,
                           "roots": mini_cache_roots(), "dirs": dirs,
                           "errors": [], "target": target or "",
                           "matched": 0, "index": _index_file()}
    if not root_map:
        alive = [d for d in dirs if d["exists"]]
        if alive:
            out["errors"].append(
                f"{len(alive)} 个缓存目录存在但下面没有 AppID 目录"
                f"（例如 {alive[0]['path']}，挂 {alive[0]['apps']} 个）："
                "先在微信里打开目标小程序，让客户端把包拉下来再扫")
        else:
            out["errors"].append(
                f"{len(dirs)} 个微信小程序缓存位置都不存在（没装微信，或装在别的账号 / "
                "容器里）；这类情况拿不到本地包")
        out["elapsed"] = round(time.time() - t0, 1)
        return out

    idx: dict[str, dict] = {} if refresh else _load_index()
    stamps = {aid: _pkg_stamp(pkgs) for aid, pkgs in root_map.items()}
    dirty = [aid for aid in root_map
             if refresh or (idx.get(aid) or {}).get("_stamp") != stamps[aid]]
    # 新装 / 刚更新过的小程序更可能是这次要查的目标，先读它们
    dirty.sort(key=lambda a: -(max((os.path.getmtime(p) for p in root_map[a]), default=0.0)))
    records: dict[str, dict] = {aid: dict(idx[aid]) for aid in root_map if aid in idx}

    if dirty:
        pool = ThreadPoolExecutor(max_workers=max(1, min(int(workers or 8), len(dirty))))
        futs = {pool.submit(mini_app_record, aid, root_map[aid], max_pkgs=max_pkgs,
                            target="", unpack=False): aid for aid in dirty}
        left = (budget - (time.time() - t0)) if budget else None
        try:
            for fut in as_completed(futs, timeout=left):
                aid = futs[fut]
                try:
                    rec = fut.result()
                except Exception as e:
                    out["errors"].append(f"{aid}: {type(e).__name__}: {e}")
                    continue
                keep = {k: rec.get(k) for k in _INDEX_KEEP if k in rec}
                keep["_stamp"] = stamps[aid]
                keep["_ts"] = int(t0)
                records[aid] = keep
                out["scanned"] += 1
        except Exception:
            out["truncated"] = True
            out["errors"].append(
                f"扫描时间到点（{int(budget)} 秒），{len(dirty)} 个待读小程序里只读完了 "
                f"{out['scanned']} 个，其余下轮接着读（已读的已进缓存）")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    out["cached"] = len(records) - out["scanned"]
    if out["scanned"] or refresh:
        _save_index({a: r for a, r in records.items() if a in root_map})

    apps = []
    for aid in root_map:
        rec = records.get(aid)
        if not rec:
            continue
        row = {k: rec.get(k) for k in _INDEX_KEEP}
        row["appid"] = aid
        m, w = _relevance_dict(row, words)
        row["match"] = m
        row["match_words"] = w[:6]
        apps.append(row)
    if target:
        apps.sort(key=lambda a: (a.get("match") != "high", -len(a.get("apis") or [])))
    else:
        apps.sort(key=lambda a: -len(a.get("apis") or []))
    out["apps"] = apps
    out["matched"] = sum(1 for a in apps if a.get("match") == "high")
    out["elapsed"] = round(time.time() - t0, 1)
    return out


def scan_local_mini(*, appid: str = "", appids: list[str] | None = None,
                    limit: int = 20, target: str = "",
                    max_pkgs: int = 6, out_root: str = "", workers: int = 6,
                    unpack: bool = True) -> dict:
    """离线摸本机小程序：AppID 清单 → 解密解包 → 抽接口/域名/命中。

    全程只读本机文件、不联网，也不需要登录态；适合在内网/断网环境用。
    给了 `target` 就按包内标题/主体/域名打分，`high` 才算对得上。
    `appids` 指定只处理这几个（两段式扫描的第二段用：先不解包粗筛，再对上的解包）。
    `out_root` 给了就把包解到磁盘；`workers` 是同时处理的小程序个数。
    """
    root_map = mini_appids()
    if appids:
        keep = {a for a in appids if a}
        root_map = {k: v for k, v in root_map.items() if k in keep}
    if appid:
        root_map = {k: v for k, v in root_map.items() if k == appid}
    dirs = mini_cache_hints()
    got: dict[str, Any] = {"roots": mini_cache_roots(), "dirs": dirs, "apps": [], "errors": [],
                           "total": len(root_map), "target": target or "",
                           "version_total": 0, "out_root": out_root or ""}
    if not root_map:
        alive = [d for d in dirs if d["exists"]]
        if alive:
            got["errors"].append(
                f"{len(alive)} 个缓存目录存在但下面没有 AppID 目录"
                f"（例如 {alive[0]['path']}，挂 {alive[0]['apps']} 个）："
                "先在微信里打开目标小程序，让客户端把包拉下来再扫")
        else:
            got["errors"].append(
                f"{len(dirs)} 个微信小程序缓存位置都不存在（没装微信，或装在别的账号 / 容器里）；"
                "这类情况下拿不到本地包，只能按已知 AppID 走远端路径")
        return got
    # 指定了 AppID 就是调用方已经筛过的名单，不能再按 limit 截掉
    cap = len(root_map) if (appids or appid) else max(1, int(limit or 20))
    keys = list(root_map.keys())[:cap]
    # 每个 AppID 是独立目录，解包是纯 CPU + 磁盘活，并行数放大到 16 与
    # 参考实现同档；外层按小程序、内层按分包，两级都不空等。
    pool = ThreadPoolExecutor(max_workers=max(1, min(int(workers or 6), len(keys))))
    try:
        futs = {pool.submit(mini_app_record, aid, root_map[aid], max_pkgs=max_pkgs,
                            target=target, out_root=out_root, unpack=unpack): aid
                for aid in keys}
        records: dict[str, dict] = {}
        for fut, aid in futs.items():
            try:
                records[aid] = fut.result()
            except Exception as e:
                got["errors"].append(f"{aid}: {type(e).__name__}: {e}")
        # 保持清单顺序，方便对照日志
        got["apps"] = [records[a] for a in keys if a in records]
        got["version_total"] = sum(int(a.get("version_total") or 0) for a in got["apps"])
    finally:
        pool.shutdown(wait=True)
    if target:
        high = [a for a in got["apps"] if a.get("match") == "high"]
        got["matched"] = len(high)
        got["apps"].sort(key=lambda a: (a.get("match") != "high", -len(a.get("apis") or [])))
    else:
        got["apps"].sort(key=lambda a: -len(a.get("apis") or []))
    return got


async def scan_dir_async(root: str, *, appid: str = "") -> ScanResult:
    return await run_blocking(scan_dir, root, appid=appid, timeout=120)


async def fetch_bundle(appid: str, *, timeout: float = 12.0) -> tuple[dict[str, str], str]:
    """从微信 CDN 拉小程序公开静态资源。

    版本号不在 URL 里也能拿：先探 `{appid}/0/`，服务端会 302 到真实版本。拿不到
    就把 0 原样试一次——小程序更新后旧版本仍常可用。
    """
    files: dict[str, str] = {}
    version = ""
    async with httpx.AsyncClient(timeout=timeout, verify=False, trust_env=False,
                                 headers={"User-Agent": UA}, follow_redirects=False) as c:
        probe = f"https://servicewechat.com/{appid}/0/{_BUNDLE_PATHS[0]}"
        try:
            r = await c.get(probe)
            loc = r.headers.get("location") or ""
            m = re.search(rf"/{re.escape(appid)}/(\d+)/", loc)
            if m:
                version = m.group(1)
            if r.status_code == 200:
                files[_BUNDLE_PATHS[0]] = r.text
        except Exception:
            pass
        ver = version or "0"
        for name in _BUNDLE_PATHS:
            if name in files:
                continue
            url = f"https://servicewechat.com/{appid}/{ver}/{name}"
            try:
                r = await c.get(url)
            except Exception:
                continue
            if r.status_code == 200 and r.text:
                files[name] = r.text
    return files, version


async def scan_appid(appid: str, *, timeout: float = 12.0) -> ScanResult:
    """AppID → 拉公开包资源 → 扫敏感信息。"""
    box = ScanResult(appid=appid)
    files, version = await fetch_bundle(appid, timeout=timeout)
    box.version = version
    if not files:
        box.notes.append("微信 CDN 未取到小程序的公开静态资源（可能已下架或仅后台可拉）")
        return box
    for name, text in files.items():
        box.files += 1
        box.bytes += len(text)
        scan_text(box, text, name)
        if name.endswith("app-config.json"):
            _read_app_config(box, text)
    box.notes.append(f"已扫 {', '.join(files)}（版本 {version or '未知'}）")
    return box
