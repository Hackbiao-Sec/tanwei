"""包体深度静态分析：二进制清单解析 + dex / assets 字符串面抽接口与凭据。

纯标准库实现，不依赖 aapt / apktool / jadx，装没装工具都能跑：
  · AndroidManifest.xml 是安卓二进制 XML（AXML），自己解字符串池与元素树
    → 包名 / 版本 / minSdk / targetSdk / 权限 / 导出组件 / 深链 scheme+host /
      provider authorities / debuggable / allowBackup / 明文流量开关
  · classes*.dex 与 assets、res/raw 里的字符串面
    → 接口路径、完整 URL、自有域、硬编码凭据（私钥 / 云密钥 / JWT / 连接串）
  · Info.plist（二进制 plist，stdlib 可直接读）→ bundleId / URL Types / ATS
  · 本机装了 jadx 且配置 `mobile.jadx=true` 时，再反编译一层补源码里的接口串；
    没装、超时、失败都只是少一层，不影响上面结果

产出扁平 dict，供 AppInfo.apk 落库，前端按字段渲染。
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from ...utils import is_suffix_only, is_valid_domain, root_domain

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# 组件类型里我们关心的四类：能对外拉起 / 能被外部调用 / 能暴露数据
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# 高风险权限：拿到手就能发短信 / 读通信录 / 定位 / 装包 / 悬浮窗
_RISKY_PERMS = {
    "android.permission.SEND_SMS": "发短信",
    "android.permission.READ_SMS": "读短信",
    "android.permission.RECEIVE_SMS": "收短信",
    "android.permission.CALL_PHONE": "直拨电话",
    "android.permission.READ_CONTACTS": "读通信录",
    "android.permission.READ_CALL_LOG": "读通话记录",
    "android.permission.ACCESS_FINE_LOCATION": "精确定位",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "后台定位",
    "android.permission.CAMERA": "相机",
    "android.permission.RECORD_AUDIO": "录音",
    "android.permission.READ_PHONE_STATE": "设备标识",
    "android.permission.READ_EXTERNAL_STORAGE": "读外部存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写外部存储",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "全盘存储",
    "android.permission.REQUEST_INSTALL_PACKAGES": "安装应用",
    "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗",
    "android.permission.QUERY_ALL_PACKAGES": "枚举已装应用",
    "android.permission.GET_ACCOUNTS": "读账号列表",
}

# 接口路径：至少两段，首段落在常见网关词上，避免把文件路径、类名当接口
_API_PATH = re.compile(
    r"/(?:api|apis|openapi|rest|restful|gateway|service|services|app|"
    r"client|admin|wx|v\d{1,2}|prod-api|dev-api)(?:/[A-Za-z0-9_\-${}.:]{1,48}){1,6}")
_URL = re.compile(
    r"https?://([A-Za-z0-9][A-Za-z0-9._\-]{3,119})"
    r"(/[^\s\"'<>\\)\]}\x00-\x1f]{0,160})?")
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9._\-])((?:[a-z][a-z0-9\-]{0,61}[a-z0-9]?\.)+[a-z]{2,10})"
    r"(?![A-Za-z0-9\-])")
# 二进制容器里只取可打印串，避免把随机字节当域名 / 路径
_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
# Java 类名片段：驼峰、内部类，接口路径里不会这么写
_JAVA_SEG = re.compile(r"[A-Z][a-z]+(?:[A-Z][a-z]+)+|\$")
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf",
             ".otf", ".mp3", ".mp4", ".so", ".zip", ".apk", ".jar")
# Java 包名首段。dex 里 `android.app`、`android.media` 这类包名撞上新 gTLD，会被
# 当成真实域名；业务域名不会有这些首段。
_PKG_ROOTS = frozenset({
    "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik", "junit",
    "com", "org", "net", "io", "edu", "gov", "sun", "gnu", "okhttp3", "retrofit2",
    "okio", "gson", "slf4j", "log4j", "apache", "bouncycastle",
})
_LINE_DOMAIN = re.compile(r"^[a-z0-9*][a-z0-9\-.*]{1,80}$")

# 文档 / 示例里写死的占位域，任何包里都可能出现，收进来只会污染资产库
_PLACEHOLDER = frozenset({
    "example.com", "example.net", "example.org", "example.edu",
    "test.com", "test.net", "foo.com", "bar.com", "baz.com",
    "domain.com", "yourdomain.com", "mydomain.com", "localhost.localdomain",
    "sample.com", "dummy.com", "invalid", "example.local",
})

# 末段是这些词的「域名」几乎都是配置键或字段路径（`acra.user.email`、
# `config.value`），不是主机的后缀；这些词恰好都注册成了 gTLD，光看形态分不出来
_KEY_TAILS = frozenset({
    "email", "name", "date", "time", "title", "size", "level", "value",
    "text", "label", "status", "state", "message", "index", "type",
})

# 凭据形态：命中只说明包里出现了这串东西，值一律打码，别把包当凭证库
_SECRETS = (
    ("私钥", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("云访问密钥", re.compile(r"\b(?:AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,20}|AKID[0-9A-Za-z]{13,40})\b")),
    ("微信 AppID", re.compile(r"\bwx[0-9a-f]{16}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}")),
    ("数据库连接串", re.compile(
        r"(?i)\b(?:jdbc:[a-z0-9]+://|mongodb(?:\+srv)?://|redis://|amqp://|postgres(?:ql)?://)"
        r"[^\s\"'<>]{8,160}")),
    ("疑似密钥赋值", re.compile(
        r"(?i)\b(?:api[_\-]?key|app[_\-]?secret|secret[_\-]?key|access[_\-]?key|"
        r"client[_\-]?secret|private[_\-]?key|appkey|token)\b\s*[:=]\s*"
        r"[\"']([A-Za-z0-9_\-+/=]{16,72})[\"']")),
    ("Firebase 实时库", re.compile(r"\b[a-z0-9\-]{3,40}\.firebaseio\.com\b")),
)


# ─────────────── 二进制 XML（AXML）───────────────
def _varint(data: bytes, pos: int) -> tuple[int, int]:
    """AXML 字符串池里的长度前缀：高位为 1 表示占两个字节。"""
    b = data[pos]
    if b & 0x80:
        return ((b & 0x7F) << 8) | data[pos + 1], pos + 2
    return b, pos + 1


def _read_pool(data: bytes, start: int) -> list[str]:
    """解 ResStringPool。UTF-8 池多一层「UTF-16 长度」前缀，两家都要认。"""
    try:
        _t, header_size, _size = struct.unpack_from("<HHI", data, start)
        count, _styles, flags, strings_start, _ss = struct.unpack_from("<IIIII", data, start + 8)
        if not count:
            return []
        offsets = struct.unpack_from(f"<{count}I", data, start + header_size)
    except struct.error:
        return []
    utf8 = bool(flags & 0x100)
    base = start + strings_start
    out: list[str] = []
    for off in offsets:
        pos = base + off
        try:
            if utf8:
                _n16, pos = _varint(data, pos)
                n8, pos = _varint(data, pos)
                out.append(data[pos:pos + n8].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                out.append(data[pos:pos + n * 2].decode("utf-16-le", "replace"))
        except (struct.error, IndexError):
            out.append("")
    return out


def parse_axml(blob: bytes) -> list[tuple[str, tuple[str, ...], dict]]:
    """把二进制 XML 解成 (标签名, 父链, 属性表)。

    属性键：安卓命名空间下的写成 `android:name`，其它保持原名。
    这样调用侧 `attrs.get("android:exported")` 与 `attrs.get("scheme")` 都能对上。
    """
    if len(blob) < 8 or struct.unpack_from("<H", blob, 0)[0] != 0x0003:
        return []
    try:
        _type, header_size, _total = struct.unpack_from("<HHI", blob, 0)
    except struct.error:
        return []
    pool: list[str] = []
    stack: list[str] = []
    nodes: list[tuple[str, tuple[str, ...], dict]] = []
    pos = header_size
    total_len = len(blob)
    while pos + 8 <= total_len:
        try:
            ctype, _chsize, csize = struct.unpack_from("<HHI", blob, pos)
        except struct.error:
            break
        if csize < 8 or pos + csize > total_len:
            break
        if ctype == 0x0001:                       # 字符串池
            pool = _read_pool(blob, pos)
        elif ctype == 0x0102:                     # 开始标签
            try:
                ns_i, name_i = struct.unpack_from("<II", blob, pos + 16)
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", blob, pos + 24)
            except struct.error:
                break
            tag = pool[name_i] if name_i < len(pool) else ""
            attrs: dict = {}
            # attributeStart 是相对 ResXMLTree_attrExt 起点（pos+16）的偏移
            attr_base = pos + 16 + attr_start
            for i in range(attr_count):
                ap = attr_base + i * (attr_size or 20)
                if ap + 20 > total_len:
                    break
                a_ns, a_name, a_raw = struct.unpack_from("<III", blob, ap)
                data_type = blob[ap + 15]
                data_val = struct.unpack_from("<I", blob, ap + 16)[0]
                key = pool[a_name] if a_name < len(pool) else ""
                if a_ns < len(pool) and pool[a_ns] == ANDROID_NS:
                    key = "android:" + key
                if a_raw != 0xFFFFFFFF and a_raw < len(pool):
                    val = pool[a_raw]
                elif data_type == 0x03 and data_val < len(pool):
                    val = pool[data_val]
                elif data_type == 0x12:
                    val = "true" if data_val else "false"
                elif data_type == 0x11:
                    val = hex(data_val)
                elif data_type == 0x10:
                    val = str(struct.unpack("<i", struct.pack("<I", data_val))[0])
                else:
                    val = ""
                if key and not key.startswith("xmlns") and val != ANDROID_NS:
                    attrs[key] = val
            nodes.append((tag, tuple(stack), attrs))
            stack.append(tag)
        elif ctype == 0x0103:                     # 结束标签
            if stack:
                stack.pop()
        pos += csize
    return nodes


def axml_strings(blob: bytes) -> list[str]:
    """只取 AXML 字符串池，不拿原始字节当正文扫（否则长度字节会混出垃圾域名）。"""
    if len(blob) < 8 or struct.unpack_from("<H", blob, 0)[0] != 0x0003:
        return []
    try:
        _t, header_size, _total = struct.unpack_from("<HHI", blob, 0)
    except struct.error:
        return []
    out: list[str] = []
    pos = header_size
    while pos + 8 <= len(blob):
        try:
            ctype, _h, csize = struct.unpack_from("<HHI", blob, pos)
        except struct.error:
            break
        if csize < 8 or pos + csize > len(blob):
            break
        if ctype == 0x0001:
            out.extend(_read_pool(blob, pos))
        pos += csize
    return out


def summarize_manifest(nodes: list[tuple[str, tuple[str, ...], dict]]) -> dict:
    """把元素树压成一份人能读的清单画像。"""
    out: dict = {"package": "", "version_name": "", "version_code": "", "min_sdk": "",
                 "target_sdk": "", "debuggable": False, "allow_backup": False,
                 "cleartext": None, "permissions": [], "risky_permissions": [],
                 "components": [], "exported": [], "providers": [], "deeplinks": [],
                 "schemes": [], "custom_permissions": []}
    for tag, parents, attrs in nodes:
        if tag == "manifest":
            out["package"] = attrs.get("package") or out["package"]
            out["version_name"] = attrs.get("android:versionName") or out["version_name"]
            out["version_code"] = attrs.get("android:versionCode") or out["version_code"]
        elif tag == "uses-sdk":
            out["min_sdk"] = attrs.get("android:minSdkVersion") or out["min_sdk"]
            out["target_sdk"] = attrs.get("android:targetSdkVersion") or out["target_sdk"]
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            name = attrs.get("android:name") or ""
            if name and name not in out["permissions"]:
                out["permissions"].append(name)
                if name in _RISKY_PERMS:
                    out["risky_permissions"].append(
                        {"name": name, "why": _RISKY_PERMS[name]})
        elif tag == "permission":
            name = attrs.get("android:name") or ""
            if name:
                out["custom_permissions"].append(
                    {"name": name, "level": attrs.get("android:protectionLevel") or ""})
        elif tag == "application":
            out["debuggable"] = (attrs.get("android:debuggable") == "true")
            out["allow_backup"] = (attrs.get("android:allowBackup") == "true")
            for k in ("android:usesCleartextTraffic",):
                if k in attrs:
                    out["cleartext"] = (attrs.get(k) == "true")
        elif tag in _COMPONENT_TAGS and "application" in parents:
            name = attrs.get("android:name") or ""
            if not name:
                continue
            item = {"type": tag, "name": name,
                    "permission": attrs.get("android:permission") or "",
                    "authorities": attrs.get("android:authorities") or "",
                    "exported": attrs.get("android:exported") or "",
                    "process": attrs.get("android:process") or ""}
            out["components"].append(item)
            if tag == "provider":
                for a in re.split(r"[;,\s]+", item["authorities"]):
                    if a and a not in out["providers"]:
                        out["providers"].append(a)
        elif tag == "data" and "intent-filter" in parents:
            scheme = attrs.get("android:scheme") or ""
            host = attrs.get("android:host") or ""
            prefix = attrs.get("android:pathPrefix") or attrs.get("android:path") or ""
            if scheme:
                if scheme not in out["schemes"]:
                    out["schemes"].append(scheme)
                link = f"{scheme}://{host}{prefix}" if host else f"{scheme}://"
                if link not in out["deeplinks"] and len(out["deeplinks"]) < 60:
                    out["deeplinks"].append(link)
    # 导出判定：显式 exported 优先；没写但挂了 intent-filter 的按安卓默认算导出
    filter_of: dict[str, bool] = {}
    for tag, parents, _attrs in nodes:
        if tag == "intent-filter" and parents:
            filter_of[parents[-1]] = True
    for item in out["components"]:
        if item["exported"] == "true":
            item["is_exported"] = True
        elif item["exported"] == "false":
            item["is_exported"] = False
        else:
            item["is_exported"] = bool(filter_of.get(item["name"]))
        if item["is_exported"] and not item["permission"]:
            out["exported"].append(item)
    return out


# ─────────────── 字符串面 ───────────────
def _is_domain_list(text: str, limit: int = 400) -> bool:
    """整份文本是不是一张「域名 / 后缀清单」而不是配置。

    包里经常夹带公共后缀库、广告拦截域名表、CDN 白名单；整份当正文扫，一次
    就能灌进上千条与业务无关的域名。判据：行数够多，且几乎每行都是一个裸域名。
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 120:
        return False
    sample = lines[:limit]
    hits = sum(1 for ln in sample if _LINE_DOMAIN.match(ln) and "." in ln)
    return hits >= len(sample) * 0.85


def _domains_of(text: str, url_hosts: set[str] | None = None) -> set[str]:
    """抽域名。

    `app.name`、`vnd.android`、`baseline.prof` 这类 Android 资源键 / MIME 前缀
    的后缀段恰好也是新 gTLD，两段式字符串会被当成域名。两段式只有在 URL 或
    host/path 形态里出现过才收；三段以上（api.xx.com）直接收。
    """
    if url_hosts is None:
        url_hosts = {u.split("/", 1)[0] for u in _urls_of(text)}
    out: set[str] = set()
    for m in _DOMAIN.finditer(text):
        d = m.group(1).lower()
        if d.endswith(_SKIP_EXT):
            continue
        head = d.split(".", 1)[0]
        if len(head) < 3 or head in _PKG_ROOTS:
            continue
        if d.count(".") == 1 and d not in url_hosts:
            continue
        if is_suffix_only(d):
            continue
        if d in _PLACEHOLDER or root_domain(d) in _PLACEHOLDER:
            # `mirror.example.org` 这类示例主机：根域就是占位域，整支都不要
            continue
        if d.rsplit(".", 1)[-1] in _KEY_TAILS and d not in url_hosts:
            # `acra.user.email`、`config.value`：末段是配置字段名，只有真在 URL 里出现过才收
            continue
        if not is_valid_domain(d) or not root_domain(d):
            continue
        out.add(d)
    return out


def _paths_of(text: str) -> set[str]:
    out: set[str] = set()
    for m in _API_PATH.finditer(text):
        p = m.group(0)
        if p.endswith((".js", ".css", ".png", ".json", ".xml", ".html")):
            continue
        pre = text[max(0, m.start() - 200):m.start()]
        if pre[-1:].isalnum() and "://" not in pre.rsplit(None, 1)[-1]:
            # `Landroid/app/Activity;` 这类 dex 类描述符，不是接口路径
            continue
        if _JAVA_SEG.search(p.rsplit("/", 1)[-1]):
            continue
        if p.rsplit("/", 1)[-1][:1].isupper():
            continue
        out.add(p)
    return out


def _urls_of(text: str) -> set[str]:
    out: set[str] = set()
    for m in _URL.finditer(text):
        host, path = m.group(1).lower(), m.group(2) or ""
        if "." not in host or host.endswith(_SKIP_EXT):
            continue
        if not is_valid_domain(host) or host.replace(".", "").isdigit():
            continue
        if host in ("localhost", "127.0.0.1", "0.0.0.0"):
            continue
        out.add((host + path)[:200])
    return out


def _mask(val: str) -> str:
    v = val.strip()
    if len(v) <= 8:
        return v[:2] + "****"
    return f"{v[:4]}…{v[-4:]}"


def _secrets_of(text: str) -> list[dict]:
    out: list[dict] = []
    for kind, pat in _SECRETS:
        for m in pat.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            if not raw:
                continue
            out.append({"kind": kind, "value": _mask(raw)})
            if len(out) >= 40:
                return out
    return out


def _printable_text(blob: bytes, limit: int = 12 << 20) -> str:
    """dex / arsc 这类二进制只留可打印 ASCII 串再跑正则，噪声少一个量级。"""
    return "\n".join(m.group(0).decode("ascii", "ignore")
                     for m in _PRINTABLE.finditer(blob[:limit]))


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    val = shift = 0
    for _ in range(5):
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return val, pos


def dex_strings(blob: bytes, limit: int = 200_000) -> list[str]:
    """按 dex 头的 string_ids 表取字符串池。

    直接切可打印字节会把 uleb128 长度前缀（恰好落在 0x20-0x7e）粘到串首，
    冒出 `aandroidx.compose` 这种假域；走字符串池表就没有这类噪声。
    """
    if not blob.startswith(b"dex\n") or len(blob) < 0x70:
        return []
    try:
        count, off = struct.unpack_from("<II", blob, 0x38)
    except struct.error:
        return []
    out: list[str] = []
    for i in range(min(count, limit)):
        p = off + i * 4
        if p + 4 > len(blob):
            break
        sidx = struct.unpack_from("<I", blob, p)[0]
        if sidx >= len(blob):
            continue
        try:
            _n, sp = _uleb(blob, sidx)
        except (struct.error, IndexError):
            continue
        end = blob.find(b"\x00", sp)
        if end < 0 or end == sp:
            continue
        out.append(blob[sp:end].decode("utf-8", "ignore"))
    return out


def _scan_text(text: str, bag: dict) -> None:
    bag["domains"].update(_domains_of(text))
    bag["paths"].update(_paths_of(text))
    bag["urls"].update(_urls_of(text))
    for s in _secrets_of(text):
        if len(bag["secrets"]) < 40:
            bag["secrets"].append(s)


def _new_bag() -> dict:
    return {"domains": set(), "paths": set(), "urls": set(), "secrets": list()}


def _merge_bag(dst: dict, src: dict) -> None:
    dst["domains"].update(src.get("domains") or ())
    dst["paths"].update(src.get("paths") or ())
    dst["urls"].update(src.get("urls") or ())
    for s in src.get("secrets") or ():
        if len(dst["secrets"]) < 40:
            dst["secrets"].append(s)


# ─────────────── 可选：jadx / apktool 补源码与资源层 ───────────────
def _tool_bin(name: str, rels: tuple[str, ...]) -> str:
    """找已装好的外部工具。

    工具装在程序自带目录（安装器负责下载），便携版在 exe 旁，源码版在仓库根，
    两种位置都要认；最后再退回 PATH。
    """
    roots: list[Path] = []
    here = Path(__file__).resolve().parents[3]
    roots.append(here)
    try:
        from ..installer import TOOLS_DIR            # noqa: WPS433 惰性导入，避免启动环
        roots.append(Path(TOOLS_DIR).parent if Path(TOOLS_DIR).name == "tools" else Path(TOOLS_DIR))
        base = Path(TOOLS_DIR) / name
        for rel in rels:
            cand = base / rel
            if cand.exists():
                return str(cand)
    except Exception:
        pass
    for root in roots:
        for rel in rels:
            cand = root / "tools" / name / rel
            if cand.exists():
                return str(cand)
    exe = name + ".exe"
    return shutil.which(name) or shutil.which(name + ".bat") or shutil.which(exe) or ""


def _jadx_bin() -> str:
    return _tool_bin("jadx", ("bin/jadx.bat", "bin/jadx", "jadx.bat", "jadx"))


def _apktool_bin() -> str:
    return _tool_bin("apktool", ("apktool.jar", "apktool.bat", "apktool"))


def _run_tool(cmd: list[str], timeout: int) -> bool:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              cwd=str(Path(tempfile.gettempdir())))
        return proc.returncode == 0
    except Exception:
        return False


def jadx_sources(path: str | Path, timeout: int = 240) -> dict:
    """反编译到临时目录，扫 .java 里的接口与域名。装不上就返回空。"""
    exe = _jadx_bin()
    if not exe:
        return {}
    out_dir = Path(tempfile.mkdtemp(prefix="arlx_jadx_"))
    bag = _new_bag()
    try:
        ok = _run_tool([exe, "-d", str(out_dir), "--no-res", "-q", str(path)], timeout)
        files = 0
        if ok:
            for f in out_dir.rglob("*.java"):
                if files >= 4000:
                    break
                try:
                    _scan_text(f.read_text("utf-8", "ignore"), bag)
                except OSError:
                    continue
                files += 1
        return {"files": files, **bag}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def apktool_res(path: str | Path, timeout: int = 180) -> dict:
    """解出资源目录，扫 strings.xml / res/xml 里的域名与接口。"""
    exe = _apktool_bin()
    if not exe:
        return {}
    out_dir = Path(tempfile.mkdtemp(prefix="arlx_apktool_"))
    bag = _new_bag()
    try:
        cmd = [exe, "d", "-f", "-s", "-o", str(out_dir), str(path)]
        if exe.endswith(".jar"):
            java = shutil.which("java") or "java"
            cmd = [java, "-jar", exe] + cmd[1:]
        ok = _run_tool(cmd, timeout)
        files = 0
        if ok:
            pats = ("res/values/strings.xml", "res/values/*.xml", "res/xml/*.xml")
            seen: set[Path] = set()
            for pat in pats:
                for f in out_dir.glob(pat):
                    if f in seen or files >= 200:
                        continue
                    seen.add(f)
                    try:
                        _scan_text(f.read_text("utf-8", "ignore"), bag)
                    except OSError:
                        continue
                    files += 1
        return {"files": files, "ok": ok, **bag}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


# ─────────────── 主入口 ───────────────
def _manifest_bag(zf: zipfile.ZipFile, names: list[str]) -> tuple[dict, dict]:
    """读 AndroidManifest.xml：一份给清单画像，一份给字符串面。"""
    bag = _new_bag()
    summary: dict = {}
    if "AndroidManifest.xml" not in names:
        return summary, bag
    try:
        blob = zf.read("AndroidManifest.xml")
    except Exception:
        return summary, bag
    nodes = parse_axml(blob)
    if nodes:
        summary = summarize_manifest(nodes)
    else:
        # 解不出元素树（非常见打包器）时至少把字符串池当正文字符串扫一遍
        summary = {"notes": ["AndroidManifest 不是可识别的二进制 XML"]}
    bag["domains"].update(_domains_of("\n".join(axml_strings(blob))))
    return summary, bag


def _ios_bag(zf: zipfile.ZipFile, names: list[str]) -> dict:
    """Info.plist：二进制 plist 用 stdlib 读，拿 bundleId / URL Types / ATS。"""
    out: dict = {}
    target = next((n for n in names if n.endswith("Info.plist") and "Payload/" in n), "")
    if not target:
        return out
    try:
        blob = zf.read(target)
        pl = plistlib.loads(blob)
    except Exception:
        return out
    out["bundle_id"] = str(pl.get("CFBundleIdentifier") or "")
    out["version"] = str(pl.get("CFBundleShortVersionString") or "")
    schemes: list[str] = []
    for item in pl.get("CFBundleURLTypes") or []:
        for s in (item or {}).get("CFBundleURLSchemes") or []:
            if s and s not in schemes:
                schemes.append(s)
    out["schemes"] = schemes
    ats = pl.get("NSAppTransportSecurity") or {}
    if isinstance(ats, dict):
        out["cleartext_allowed"] = bool(ats.get("NSAllowsArbitraryLoads"))
    return out


def analyze(path: str | Path, *, deep: bool = True, use_jadx: bool = False,
            use_apktool: bool = False, max_bytes: int = 80 << 20) -> dict:
    """分析一个 apk / ipa / 微信小程序包，返回扁平结果。

    deep=False 时只解清单与轻量文本，跳过 dex 全扫（大包快速预览用）。
    """
    p = Path(path)
    res: dict = {"ok": False, "kind": "", "path": str(p), "package": "",
                 "domains": [], "api_paths": [], "urls": [], "secrets": [],
                 "paths_count": 0, "notes": []}
    if not p.exists():
        res["notes"].append("文件不存在")
        return res
    try:
        zf = zipfile.ZipFile(p)
    except Exception as e:
        res["notes"].append(f"不是有效压缩包：{e}")
        return res
    with zf:
        names = zf.namelist()
        low = p.suffix.lower()
        if low == ".ipa" or any(n.startswith("Payload/") for n in names):
            res["kind"] = "ipa"
            ios = _ios_bag(zf, names)
            res["ios"] = ios
            res["package"] = ios.get("bundle_id") or ""
        else:
            res["kind"] = "apk"
            summary, bag = _manifest_bag(zf, names)
            res["manifest"] = summary
            res["package"] = summary.get("package") or ""
            res["domains"] = sorted(bag["domains"])
            res["api_paths"] = sorted(bag["paths"])[:300]
            res["urls"] = sorted(bag["urls"])[:300]
            res["secrets"] = bag["secrets"]

        bag = _new_bag()
        scanned, budget = 0, max_bytes
        skipped_lists = 0
        for n in names:
            if not deep or budget <= 0 or scanned >= 60:
                break
            interesting = (n.startswith("classes") and n.endswith(".dex")) \
                or n.startswith(("assets/", "res/raw/")) \
                or n.endswith((".json", ".js", ".xml", ".html", ".properties"))
            if not interesting or n.endswith(_SKIP_EXT):
                continue
            try:
                if zf.getinfo(n).file_size > budget:
                    continue
                blob = zf.read(n)
            except Exception:
                continue
            budget -= len(blob)
            scanned += 1
            if n.endswith(".dex"):
                text = "\n".join(dex_strings(blob))
                if not text:
                    text = _printable_text(blob)
            else:
                text = blob.decode("utf-8", "ignore")
                if _is_domain_list(text):
                    # 后缀库 / 拦截表：整份都是无关域名，扫进来只会污染资产
                    skipped_lists += 1
                    continue
            _scan_text(text, bag)
        res["files_scanned"] = scanned
        if skipped_lists:
            res["notes"].append(f"跳过 {skipped_lists} 个域名清单类文件（后缀库/拦截表）")
        if res["kind"] == "apk":
            merged = set(res["domains"]) | bag["domains"]
            res["domains"] = sorted(merged)
            res["api_paths"] = sorted(set(res["api_paths"]) | bag["paths"])[:300]
            res["urls"] = sorted(set(res["urls"]) | bag["urls"])[:300]
            seen = {s["value"] for s in res["secrets"]}
            for s in bag["secrets"]:
                if s["value"] not in seen:
                    res["secrets"].append(s)
                    seen.add(s["value"])
        else:
            res["domains"] = sorted(bag["domains"])
            res["api_paths"] = sorted(bag["paths"])[:300]
            res["urls"] = sorted(bag["urls"])[:300]
            res["secrets"] = bag["secrets"][:40]

    if use_jadx and res["kind"] == "apk":
        jb = jadx_sources(str(p))
        if jb:
            res["jadx"] = {"files": jb.get("files", 0)}
            res["domains"] = sorted(set(res["domains"]) | jb["domains"])
            res["api_paths"] = sorted(set(res["api_paths"]) | jb["paths"])[:400]
            res["urls"] = sorted(set(res["urls"]) | jb["urls"])[:400]
            known = {s["value"] for s in res["secrets"]}
            for s in jb["secrets"]:
                if len(res["secrets"]) >= 40:
                    break
                if s["value"] not in known:
                    res["secrets"].append(s)
                    known.add(s["value"])
        else:
            res["notes"].append("jadx 未安装或反编译失败，源码层未并进来")
    if use_apktool and res["kind"] == "apk":
        ab = apktool_res(str(p))
        if ab.get("files"):
            res["apktool"] = {"files": ab.get("files", 0)}
            res["domains"] = sorted(set(res["domains"]) | ab["domains"])
            res["api_paths"] = sorted(set(res["api_paths"]) | ab["paths"])[:400]
            res["urls"] = sorted(set(res["urls"]) | ab["urls"])[:400]
            known = {s["value"] for s in res["secrets"]}
            for s in ab["secrets"]:
                if len(res["secrets"]) >= 40:
                    break
                if s["value"] not in known:
                    res["secrets"].append(s)
                    known.add(s["value"])
        elif not _apktool_bin():
            res["notes"].append("apktool 未安装，资源层未并进来")
    res["paths_count"] = len(res["api_paths"])
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        res["sha256"] = h.hexdigest()
    except OSError:
        pass
    res["ok"] = True
    return res


def brief(res: dict) -> list[str]:
    """给日志/证据用的两三行摘要，别把整份结果灌进日志。"""
    if not res:
        return []
    out: list[str] = []
    m = res.get("manifest") or {}
    if m.get("package"):
        out.append(f"包名 {m['package']}"
                   + (f" · v{m.get('version_name')}" if m.get("version_name") else "")
                   + (f" · targetSdk {m['target_sdk']}" if m.get("target_sdk") else ""))
    if m.get("risky_permissions"):
        out.append("高风险权限：" + "、".join(x["why"] for x in m["risky_permissions"][:6]))
    if m.get("exported"):
        names = "、".join(x["name"].split(".")[-1] for x in m["exported"][:5])
        out.append(f"导出组件 {len(m['exported'])} 个：{names}")
    if m.get("deeplinks"):
        out.append("深链：" + "、".join(m["deeplinks"][:4]))
    if m.get("providers"):
        out.append("provider authorities：" + "、".join(m["providers"][:4]))
    if m.get("debuggable"):
        out.append("清单里 debuggable=true")
    if res.get("paths_count"):
        out.append(f"接口路径 {res['paths_count']} 条")
    if res.get("secrets"):
        kinds: list[str] = []
        for s in res["secrets"]:
            if s["kind"] not in kinds:
                kinds.append(s["kind"])
        out.append("疑似凭据：" + "、".join(kinds[:5]))
    ios = res.get("ios") or {}
    if ios.get("schemes"):
        out.append("URL Scheme：" + "、".join(ios["schemes"][:4]))
    return out


def dumps(res: dict) -> str:
    """调试用：集合已转 list，直接序列化。"""
    return json.dumps(res, ensure_ascii=False, default=str)[:2000]
