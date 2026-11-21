"""外部工具的自动安装：下载官方发行包 → 解压到本地工具目录 → 记录可执行文件。

设计取舍：

* 装在本项目的 ``tools/`` 目录下，不改 PATH、不动系统环境，卸载就是删目录。
* 下载地址写死为各项目官方的发布源（GitHub Releases 为主）。地址失效时不猜不试，
  直接把「手动安装」的地址和落位一起吐给前端，用户自己下也一样用。
* 支持代理：``proxy.url`` 配了就跟着走，国内直连 GitHub 常常超时。
* 全过程不调用系统包管理器，也不 shell 执行任何东西。
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import httpx

from ..config import ROOT, config

def _tools_root() -> Path:
    """程序旁边优先：便携版解包目录只读、删了就没，工具要能留在原地反复用。"""
    cands: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        cands.append(Path(meipass).parent)
    if getattr(sys, "frozen", False):
        cands.append(Path(sys.executable).resolve().parent)
    cands.append(Path(ROOT))
    for base in cands:
        try:
            probe = base / "tools"
            probe.mkdir(parents=True, exist_ok=True)
            return probe
        except Exception:
            continue
    return Path(ROOT) / "tools"


TOOLS_DIR = _tools_root()
MANIFEST = "installed.json"

# 包名里的版本号在 "latest/download" 地址里必须对得上，所以每个工具配一串已知版本依次试，
# 且每次试之前都先问 release API 要当期真实 tag（见 _latest_tag）。

# 每个工具：给前端展示的说明、Windows 可直接下载的压缩包、手动安装指引
CATALOG: dict[str, dict] = {
    "nuclei": {
        "label": "nuclei",
        "desc": "漏洞模板扫描；深度挖掘阶段用它跑 CVE 与暴露面指纹",
        "kind": "zip",
        "bin": "nuclei.exe",
        "sources": [
            ("github", "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_{ver}_windows_amd64.zip"),
            ("gitee", "https://gitee.com/mirrors/nuclei/releases/download/v{ver}/nuclei_{ver}_windows_amd64.zip"),
        ],
        "versions": ["3.4.10", "3.4.7", "3.3.10", "3.3.5"],
        "manual": {
            "download": "https://github.com/projectdiscovery/nuclei/releases",
            "mirror": "https://www.microsoft.com/en-us/edge 之外请用浏览器打开上面的地址；国内打不开就搜「nuclei github 镜像」下载同名 zip",
            "pick": "选 nuclei_<版本>_windows_amd64.zip",
            "install_to": "解压出的 nuclei.exe 放到本程序目录下的 tools\\nuclei\\ 里",
        },
    },
    "httpx": {
        "label": "httpx",
        "desc": "HTTP 存活与指纹批量探测，比内置探测更快",
        "kind": "zip",
        "bin": "httpx.exe",
        "sources": [
            ("github", "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_{ver}_windows_amd64.zip"),
            ("gitee", "https://gitee.com/mirrors/httpx/releases/download/v{ver}/httpx_{ver}_windows_amd64.zip"),
        ],
        "versions": ["1.7.1", "1.6.10", "1.6.9"],
        "manual": {
            "download": "https://github.com/projectdiscovery/httpx/releases",
            "pick": "选 httpx_<版本>_windows_amd64.zip",
            "install_to": "解压出的 httpx.exe 放到本程序目录下的 tools\\httpx\\ 里",
        },
    },
    "ffuf": {
        "label": "ffuf",
        "desc": "高速目录与参数模糊测试",
        "kind": "zip",
        "bin": "ffuf.exe",
        "sources": [
            ("github", "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_{ver}_windows_amd64.zip"),
            ("gitee", "https://gitee.com/mirrors/ffuf/releases/download/v{ver}/ffuf_{ver}_windows_amd64.zip"),
        ],
        "versions": ["2.1.0"],
        "manual": {
            "download": "https://github.com/ffuf/ffuf/releases",
            "pick": "选 ffuf_<版本>_windows_amd64.zip",
            "install_to": "解压出的 ffuf.exe 放到本程序目录下的 tools\\ffuf\\ 里",
        },
    },
    "ehole": {
        "label": "EHole",
        "desc": "红队指纹识别",
        "kind": "zip",
        "bin": "EHole_windows_amd64.exe",
        "sources": [
            ("github", "https://github.com/EdgeSecurityTeam/EHole/releases/latest/download/EHole_windows_amd64.zip"),
        ],
        "versions": ["3.1"],
        "manual": {
            "download": "https://github.com/EdgeSecurityTeam/EHole/releases",
            "pick": "选 EHole_windows_amd64.zip",
            "install_to": "解压后的整个目录放到本程序目录下的 tools\\ehole\\ 里",
        },
    },
    "jadx": {
        "label": "jadx",
        "desc": "APK 反编译成 Java 源码，用来从安卓包里抽接口与密钥",
        "kind": "zip",
        "bin": "bin\\jadx.bat",
        "needs": "java",
        "sources": [
            ("github", "https://github.com/skylot/jadx/releases/latest/download/jadx-{ver}.zip"),
            ("maven", "https://repo1.maven.org/maven2/io/github/skylot/jadx-cli/{ver}/jadx-cli-{ver}.zip"),
            ("maven", "https://maven.aliyun.com/repository/central/io/github/skylot/jadx-cli/{ver}/jadx-cli-{ver}.zip"),
        ],
        "versions": ["1.5.1", "1.5.0"],
        "manual": {
            "download": "https://github.com/skylot/jadx/releases",
            "pick": "选 jadx-<版本>.zip",
            "install_to": "解压后的整个目录放到本程序目录下的 tools\\jadx\\ 里",
        },
    },
    "apktool": {
        "label": "apktool",
        "desc": "APK 资源与清单解包；拿 AndroidManifest 与资源里的域名",
        "kind": "jar",
        "bin": "apktool.bat",
        "needs": "java",
        "wrapper": True,
        "sources": [
            ("github", "https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool_{ver}.jar"),
            ("maven", "https://repo1.maven.org/maven2/org/apktool/apktool/{ver}/apktool-{ver}.jar"),
            ("maven", "https://maven.aliyun.com/repository/central/org/apktool/apktool/{ver}/apktool-{ver}.jar"),
        ],
        "versions": ["2.11.1", "2.10.0"],
        "manual": {
            "download": "https://github.com/iBotPeaches/Apktool/releases",
            "pick": "选 apktool_<版本>.jar",
            "install_to": "改名为 apktool.jar 放到本程序目录下的 tools\\apktool\\ 里（需要本机有 Java 运行环境）",
        },
    },
    "dirsearch": {
        "label": "dirsearch",
        "desc": "目录与文件爆破，补内置字典之外的隐藏入口",
        "kind": "zip",
        "bin": "dirsearch\\dirsearch.py",
        "sources": [("pypi", "dirsearch")],
        "versions": [],
        "entry": "dirsearch",
        "manual": {
            "download": "https://pypi.tuna.tsinghua.edu.cn/simple/dirsearch/",
            "pick": "下载页面里后缀为 .tar.gz 的源码包",
            "install_to": "解压后的目录改名成 dirsearch，放到本程序目录下的 tools\\dirsearch\\ 里",
        },
    },
}


_LAST: dict[str, dict] = {}


# 实测在这里唯一能稳定出网、又托管了同一份发行包的通道；每轮都先试它
MIRRORS = ("https://gh-proxy.com/", "https://github.moeyy.xyz/", "https://ghfast.top/")
# 一轮安装最多花多久：直连和坏镜像会挂着不回，卡住整轮安装，到点收工走手动指引
DOWNLOAD_BUDGET = 900.0
# 某条通道连续多少秒一个字节都没涨就判死（刚开始时用短值，先快速剔除死路）
STALL_SECONDS = 20.0
# 已经下过一段后再连续这么久不涨，才判定这条通道废了
SLOW_SECONDS = 45.0
# 通道测速：每条通道先拉这么多字节，用耗时排出从快到慢的顺序
PROBE_BYTES = 262144


def _proxy() -> str | None:
    url = str(config.get("proxy", "url") or "").strip()
    return url if url.startswith("http") else None


def _proxy_ok() -> bool:
    """代理配置了不等于能用：GitHub 常被代理自己拦成 403，这里先小探一下。"""
    proxy = _proxy()
    if not proxy:
        return False
    try:
        with httpx.Client(timeout=8, proxy=proxy, trust_env=False,
                          headers={"User-Agent": "suoyu-installer"}) as c:
            r = c.get("https://api.github.com/rate_limit")
            return r.status_code < 400
    except Exception:
        return False


def _run_bin(path: str, *args, timeout: float = 6.0) -> subprocess.CompletedProcess:
    """跑一下装好的工具取版本；不弹窗、不带 shell。"""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run([path, *args], capture_output=True, timeout=timeout,
                          creationflags=flags if os.name == "nt" else 0)


def _manifest_path() -> Path:
    return TOOLS_DIR / MANIFEST


def _read_manifest() -> dict:
    import json

    try:
        p = _manifest_path()
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}


def _write_manifest(data: dict) -> None:
    import json

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    _manifest_path().write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _resolve_bin(name: str) -> str:
    """按「本程序目录下的工具 → 系统 PATH」的顺序找可执行文件。

    系统 PATH 上可能装着同名的 Python 库脚本（httpx 就是这样），那不是同一个工具，
    所以只有本目录下装着的才算自动安装装的，PATH 上找到的标成「系统里已装」。
    """
    item = CATALOG.get(name) or {}
    rel = item.get("bin") or ""
    if not rel:
        return ""
    native_rel = rel.replace("/", os.sep)
    candidates = [TOOLS_DIR / native_rel, TOOLS_DIR / name / native_rel]
    recorded = (_read_manifest().get(name) or {}).get("bin")
    if recorded:
        candidates.insert(0, Path(recorded))
    for c in candidates:
        if c.exists():
            return str(c)
    # 源码包解压后的入口会带上包自己的目录层级，装完记下真实路径，下次直接认它
    for c in sorted(TOOLS_DIR.glob(f"{name}/**/{Path(native_rel).name}"), reverse=True):
        if c.is_file() and "__MACOSX" not in c.parts:
            return str(c)
    return ""


def _system_bin(name: str) -> str:
    """系统 PATH 上是否有同名可执行文件；同名不同物也只当「系统已装」提示。"""
    item = CATALOG.get(name) or {}
    rel = item.get("bin") or ""
    if not rel:
        return ""
    native_rel = rel.replace("/", os.sep)
    return shutil.which(native_rel) or shutil.which(Path(native_rel).name) or ""


def status(name: str) -> dict:
    """单个工具的安装状态：装没装、装在哪、版本能不能问出来、上一次安装卡在哪。"""
    item = dict(CATALOG.get(name) or {})
    path = _resolve_bin(name)
    system_path = "" if path else _system_bin(name)
    item.update({
        "name": name,
        "path": path,
        "installed": bool(path),
        "in_tools_dir": bool(path) and str(Path(path)).lower().startswith(str(TOOLS_DIR).lower()),
        "system_path": system_path,
        "system_installed": bool(system_path),
        "last": _LAST.get(name) or {},
    })
    if (path or system_path) and name in ("nuclei", "httpx", "ffuf"):
        try:
            r = _run_bin(path or system_path, "-version")
            text = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "ignore")
            m = re.search(r"v?(\d+\.\d+\.\d+)", text)
            if m:
                item["version"] = m.group(1)
        except Exception:
            pass
    # 依赖解释器的工具：装是装了，但要本机有对应运行时才能用
    needs = item.get("needs")
    if needs:
        item["runtime_ok"] = bool(shutil.which(needs))
    return item


def all_status() -> dict[str, dict]:
    return {n: status(n) for n in CATALOG}


# 元数据接口统一走 /pypi/<包名>/json 这一层，清华镜像不支持省略
PYPI_BASES = (
    "https://pypi.tuna.tsinghua.edu.cn/pypi",
    "https://mirrors.aliyun.com/pypi",
    "https://pypi.org/pypi",
)
# 纯 Python 工具在 PyPI 上的发行名（仓库名和发行名经常不是同一个词）
PYPI_PACKAGES = {
    "dirsearch": "dirsearch",
    "whatweb": "whatweb",
}


async def _pypi_url(pkg: str, wanted: str = "") -> str:
    """问镜像要某个包的发行文件地址；纯 Python 工具走这条路比 GitHub 快得多。"""
    for base in PYPI_BASES:
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, trust_env=False,
                                         headers={"User-Agent": "suoyu-installer"}) as c:
                r = await c.get(f"{base}/{pkg}/json")
                if r.status_code >= 400:
                    continue
                data = r.json() or {}
        except Exception:
            continue
        files = (data.get("urls") or [])
        if not files:
            ver = (data.get("info") or {}).get("version") or ""
            files = ((data.get("releases") or {}).get(ver) or [])
        # 纯脚本工具优先要源码包：wheel 装进来只有模块，没有顶层可执行文件
        srcs = [f for f in files if str(f.get("packagetype")) == "sdist"]
        wheels = [f for f in files if str(f.get("packagetype")) == "bdist_wheel"]
        for f in (srcs + wheels):
            url = str(f.get("url") or "")
            if url:
                return url
    return ""


async def _npm_tarball(pkg: str, wanted: str) -> str:
    """直接问 npm 注册表当前包的下载地址；版本对不上也算可用（二进制随包分发）。"""
    for base in ("https://registry.npmmirror.com", "https://registry.npmjs.org"):
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, trust_env=False,
                                         headers={"User-Agent": "suoyu-installer"}) as c:
                r = await c.get(f"{base}/{pkg}")
                if r.status_code >= 400:
                    continue
                data = r.json() or {}
        except Exception:
            continue
        versions = data.get("versions") or {}
        pick = versions.get(wanted) or (data.get("dist-tags") or {}).get("latest")
        if not pick:
            continue
        url = str(((pick.get("dist") or {}).get("tarball")) or "")
        if url:
            return url
    return ""


async def _expand_sources(item: dict, tag: str) -> list[str]:
    """把一份工具配置展开成这一轮真要试的下载地址。

    版本号用真实 tag 打头，再挂上配置里的已知版本兜底；GitHub 源额外挂国内镜像。
    顺序上先原站、后镜像，实际先试哪条由 _download 按通道实测决定。
    """
    vers = [tag] if tag else []
    vers += [v for v in (item.get("versions") or []) if v and v not in vers]
    out: list[str] = []
    for kind, tpl in item.get("sources") or []:
        if kind == "pypi":
            # 纯 Python 工具：直接问镜像要 wheel/源码包，不需要 GitHub
            url = await _pypi_url(str(tpl), vers[0] if vers else "")
            if url:
                out.append(url)
            continue
        if kind == "npm":
            url = await _npm_tarball(str(tpl), vers[0] if vers else "")
            if url:
                out.append(url)
            continue
        for v in vers or [""]:
            u = str(tpl).replace("{ver}", v)
            if not u or u in out:
                continue
            out.append(u)
            if kind == "github":
                for m in MIRRORS:
                    mu = m + u
                    if mu not in out:
                        out.append(mu)
    return out


async def _exists(url: str, proxy: str | None = None) -> bool:
    """先问一下这条地址在不在，避免把测速时间浪费在 404 的版本号上。"""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(6.0, read=8.0), follow_redirects=True,
                                     proxy=proxy, trust_env=False,
                                     headers={"User-Agent": "suoyu-installer"}) as c:
            r = await c.head(url)
        return r.status_code < 400
    except Exception:
        return False


async def _alive(urls: list[str], limit: int = 6) -> list[str]:
    """并发挑出真能下载的地址；一条都不通时把原列表还回去，交给下载阶段报错。"""
    if not urls:
        return []
    checked = urls[:limit]

    async def _one(u: str) -> str:
        if await _exists(u):
            return u
        px = _proxy()
        if px and await _exists(u, px):
            return u
        return ""

    hits = [u for u in await asyncio.gather(*[_one(u) for u in checked]) if u]
    return hits or urls


def _remember_source(url: str, proxy: str | None) -> None:
    """记下这条通道确实把文件下完了，下次安装直接排到前面。

    只用 host + 是否走代理做键：同一个镜像换文件名也用同一条路，
    这样装第二个工具不用再重新探一遍哪条路通。
    """
    try:
        man = _read_manifest()
        table = dict(man.get("__sources__") or {})
        key = _chan_key(url, proxy)
        table[key] = int(table.get(key, 0)) + 1
        man["__sources__"] = table
        _write_manifest(man)
    except Exception:
        pass


def _chan_key(url: str, proxy: str | None) -> str:
    host = url.split("/")[2] if "//" in url else url
    return f"{host}|{'proxy' if proxy else 'direct'}"


def _fastest_known() -> list[tuple[str, str | None]]:
    """历史上真下成功过的通道，按成功次数从多到少。

    国内网络下 GitHub 直连和坏镜像会卡住好几十秒，先试这些已知能下的通道，
    能省掉整轮测速，用户点完按钮很快就能看到进度。
    """
    try:
        table = _read_manifest().get("__sources__") or {}
    except Exception:
        table = {}
    rows = sorted(((int(v or 0), k) for k, v in table.items()), reverse=True)
    out: list[tuple[str, str | None]] = []
    for _, key in rows:
        host, _, mode = str(key).partition("|")
        if "gh-proxy.com" not in host and "ghfast.top" not in host and "ghproxy" not in host:
            continue
        out.append((host, _proxy() if mode == "proxy" and _proxy() else None))
    return out


def _rewrite_host(url: str, host: str, proxy: str | None) -> str:
    """把候选地址换成已知那条通道的域名，并保留原地址的路径。"""
    rest = url.split("/", 3)
    if len(rest) < 4:
        return url
    path = rest[3]
    # 镜像地址本身就以镜像域名开头，直接替换域名即可
    return f"https://{host}/{path}" if not url.startswith(f"https://{host}/") else url


async def _measure(url: str, proxy: str | None, want: int) -> tuple[float, int]:
    """拉最多 want 字节，返回 (耗时秒, 拿到字节)。"""
    headers = {"User-Agent": "Mozilla/5.0", "Range": f"bytes=0-{want - 1}"}
    t = time.perf_counter()
    got = 0
    async with httpx.AsyncClient(timeout=httpx.Timeout(6.0, read=10.0), follow_redirects=True,
                                 proxy=proxy, trust_env=False, headers=headers) as c:
        async with c.stream("GET", url) as r:
            if r.status_code >= 400 and r.status_code != 206:
                raise RuntimeError(f"HTTP {r.status_code}")
            async for chunk in r.aiter_bytes(65536):
                got += len(chunk)
                if got >= want:
                    break
    return time.perf_counter() - t, got


async def _channels(url: str, force: bool) -> list[tuple[str, str | None]]:
    """对这条地址的所有通道并发测速，按速度排好序返回 (地址, 代理)。

    历史上下成功过的通道先放前面；测速本身并发跑，十几秒就能排完，
    结果写进 manifest 缓存，六小时内同一个文件目录直接复用。
    """
    key = f"sources::{url.rsplit('/', 1)[0]}"
    try:
        man = _read_manifest()
        cached = man.get(key) or {}
        if not force and cached and time.time() - float(cached.get("ts") or 0) < 6 * 3600:
            out = []
            for row in cached.get("order") or []:
                u, px = str(row[0]), (row[1] or None)
                out.append((u, px))
            if out:
                return out
    except Exception:
        pass

    proxies = [None]
    px = _proxy()
    if px:
        proxies.append(px)
    pairs = [(url, p) for p in proxies]

    async def _one(u: str, p: str | None):
        try:
            t, got = await _measure(u, p, PROBE_BYTES)
        except Exception as e:
            _LAST.setdefault("__errs__", []).append(f"{_chan_key(u, p)}: {str(e)[:60]}")
            return 99.0, -1, u, p
        return t, got, u, p

    results = list(await asyncio.gather(*[_one(u, p) for u, p in pairs]))
    if not results:
        return [(url, None)]

    # 历史成功次数越多排得越前，同等条件下才看这次测速耗时
    known = {}
    try:
        for k2, v2 in ((_read_manifest().get("__sources__") or {})).items():
            known[str(k2)] = int(v2 or 0)
    except Exception:
        known = {}
    results.sort(key=lambda x: (-known.get(_chan_key(x[2], x[3]), 0), x[0]))
    order = [(u, p) for _, _, u, p in results]
    try:
        man = _read_manifest()
        man[key] = {"ts": int(time.time()), "order": [[u, p or ""] for u, p in order],
                    "probe": [[u, p or "", round(t, 3), g] for t, g, u, p in results]}
        _write_manifest(man)
    except Exception:
        pass
    _LAST.setdefault("__probe__", {})[url] = [
        {"chan": ("代理" if p else "直连"), "took": round(t, 2), "got": g}
        for t, g, u, p in results
    ]
    return order


def _now() -> float:
    return time.time()


async def _download(urls: list[str], dest: Path, on_progress=None,
                    budget: float = DOWNLOAD_BUDGET) -> str:
    """多路并发下一份文件：同一地址多开几路，各拉文件的不同段落，最后拼成整包。

    国内镜像对单条连接限速很死（实测一路只有 20~70KB/s，一个 46MB 的包要十几分钟），
    但并发几路时总吞吐能翻几倍。这里先问出文件大小，把文件切成若干段排队，
    几条连接各领一段去拉，写回同一个文件的对应位置；哪一段没拉完就放回队列重试。
    """
    if not urls:
        raise RuntimeError("无可下载地址")
    started = time.time()
    dest.parent.mkdir(parents=True, exist_ok=True)

    # 一：问文件大小，选能报出大小、响应最快的地址
    async def _head(u: str) -> tuple[str, str | None, int, float]:
        best = (u, None, 0, 99.0)
        for px in ([None] + ([_proxy()] if _proxy() else [])):
            t = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, read=6.0),
                                             follow_redirects=True, proxy=px, trust_env=False,
                                             headers={"User-Agent": "Mozilla/5.0"}) as c:
                    r = await c.head(u)
                took = time.perf_counter() - t
                if r.status_code < 400 and took < best[3]:
                    best = (u, px, int(r.headers.get("content-length") or 0), took)
            except Exception:
                continue
        return best

    heads = await asyncio.gather(*[_head(u) for u in urls[:6]])
    live = [h for h in heads if h[3] < 90]
    sized = [h for h in live if h[2] > 0]
    if not sized:
        return await _download_serial(urls, dest, on_progress, budget)
    sized.sort(key=lambda h: h[3])
    url, proxy, size, _ = sized[0]

    # 二：整份文件切成若干段，一条连接顺序拉完所有段（顺序读才能跑满带宽），
    #     多条连接各从一个起点出发、跨步领段；谁先慢下来就把它的段让给别人。
    ways = 6
    piece = 2 * 1024 * 1024
    total_pieces = max(1, (size + piece - 1) // piece)
    queue: list[tuple[int, int]] = [(i, min(i + piece, size)) for i in range(0, size, piece)]
    lock = asyncio.Lock()
    got_map: dict[int, int] = {s: 0 for s, _ in queue}
    offsets = [0] * total_pieces

    stage = {"stage": "download", "url": url, "via": "多路并发",
             "got": 0, "total": size, "attempt": 1,
             "budget_left": round(budget - (time.time() - started))}
    _LAST["__cur__"] = stage
    _LAST.setdefault("__stages__", []).append(
        f"{size // 1024 // 1024}MB，{ways} 路并发下载")

    def _report() -> None:
        stage["got"] = min(sum(got_map.values()), size)
        if on_progress:
            on_progress(stage["got"], size)

    fh = open(dest, "wb")
    fh.truncate(size)

    def _remaining() -> int:
        return sum(b - a for a, b in queue if a < b)

    async def _stream(worker: int) -> None:
        """一条连接：顺序拉自己领到的段，段之间不断开。"""
        while True:
            async with lock:
                if not queue or time.time() - started > budget:
                    return
                a, b = queue.pop(0)
            pos = a
            headers = {"User-Agent": "Mozilla/5.0", "Range": f"bytes={pos}-{b - 1}"}
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=30.0),
                                             follow_redirects=True, proxy=proxy,
                                             trust_env=False, headers=headers) as c:
                    async with c.stream("GET", url) as r:
                        if r.status_code == 416:
                            async with lock:
                                got_map[a] = b - a
                            continue
                        if r.status_code >= 400:
                            raise RuntimeError(f"HTTP {r.status_code}")
                        mark = [_now(), pos]
                        async for chunk in r.aiter_bytes(65536):
                            fh.seek(pos)
                            fh.write(chunk)
                            pos += len(chunk)
                            async with lock:
                                got_map[a] = pos - a
                            _report()
                            if pos >= b:
                                break
                            # 一段时间没涨或涨得慢，就把剩下的段还给队列，换快的人拉
                            now = _now()
                            if now - mark[0] > 8:
                                rate = (pos - mark[1]) / (now - mark[0])
                                if rate < 80 * 1024:
                                    async with lock:
                                        queue.append((pos, b))
                                    return
                                mark = [now, pos]
            except Exception:
                pass
            async with lock:
                if pos < b:
                    queue.append((pos, b))
            return

    async def _worker() -> None:
        # 每条连接循环领活，直到队列空或者整体超时
        while True:
            async with lock:
                if not queue or time.time() - started > budget:
                    return
            await _stream(id(asyncio.current_task()))

    try:
        await asyncio.gather(*[_worker() for _ in range(ways)])
    finally:
        fh.close()

    left = [q for q in queue if q[0] < q[1]]
    if left:
        need = sum(b - a for a, b in left)
        try:
            dest.unlink()
        except Exception:
            pass
        raise RuntimeError(f"还有 {need // 1024}KB 没下完，请重试或按手动安装指引操作")
    ok, why = _plausible(dest)
    if not ok:
        try:
            dest.unlink()
        except Exception:
            pass
        raise RuntimeError(why)
    _LAST["__cur__"] = {"stage": "done", "url": url, "via": "多路并发"}
    _remember_source(url, proxy)
    return url


async def _download_serial(urls: list[str], dest: Path, on_progress=None,
                           budget: float = DOWNLOAD_BUDGET) -> str:
    """拿不到文件大小时的退路：一条条试，靠 Range 续传接着下。"""
    started = time.time()
    errors: list[str] = []
    order: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for u in urls[:6]:
        for px in ([None] + ([_proxy()] if _proxy() else [])):
            k = _chan_key(u, px)
            if k not in seen:
                seen.add(k)
                order.append((u, px))
    stage = {"stage": "download", "url": order[0][0] if order else urls[0], "via": "",
             "got": 0, "total": 0, "attempt": 1}
    _LAST["__cur__"] = stage

    def _tick(got: int, tot: int) -> None:
        stage.update({"got": got, "total": tot})
        if on_progress:
            on_progress(got, tot)

    for u, px in order:
        left = budget - (time.time() - started)
        if left <= 5:
            break
        stage.update({"url": u, "via": "代理" if px else "直连"})
        try:
            await _fetch(u, dest, _tick, px, wait_budget=min(left, 300.0),
                         stall_limit=max(SLOW_SECONDS, min(left / 2, 120.0)))
        except Exception as e:
            errors.append(f"{u.split('/')[2] if '//' in u else u}：{str(e)[:40]}")
        ok, why = _plausible(dest)
        if ok:
            _LAST["__cur__"] = {"stage": "done", "url": u, "via": "代理" if px else "直连"}
            return u
    try:
        dest.unlink()
    except Exception:
        pass
    raise RuntimeError("；".join(errors[-4:]) or "所有下载源都没通")


async def _fetch(url: str, dest: Path, on_progress=None, proxy: str | None = None,
                 wait_budget: float = 240.0, stall_limit: float = STALL_SECONDS) -> None:
    """单条通道下载，支持断点续传。

    国内镜像对同一文件常限速，断线后从头再来可能永远下不完；这里记住已经拿到的
    字节数，换一路（或重试同一路）时带 Range 接着要。
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    have = dest.stat().st_size if dest.exists() else 0
    headers = {"User-Agent": "Mozilla/5.0"}
    if have > 0:
        headers["Range"] = f"bytes={have}-"
    deadline = time.time() + wait_budget
    mark = {"t": time.time(), "n": have}
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, read=stall_limit), follow_redirects=True,
                                 proxy=proxy, trust_env=False, headers=headers) as c:
        async with c.stream("GET", url) as r:
            if r.status_code == 416:
                return  # 范围越界：本地这份已经是完整的
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}")
            if have and r.status_code != 206:
                have = 0  # 服务端不支持续传，只能整份重下
            total = int(r.headers.get("content-length") or 0) + have
            got = have
            with dest.open("ab" if have else "wb") as f:
                async for chunk in r.aiter_bytes(65536):
                    f.write(chunk)
                    got += len(chunk)
                    mark["n"] = got
                    mark["t"] = time.time()
                    if on_progress:
                        on_progress(got, total)
                    if time.time() - deadline > 0:
                        raise RuntimeError("本次通道时限到")


def _plausible(path: Path) -> tuple[bool, str]:
    """下完的文件得真是压缩包，被网关塞了个错误页也算失败。"""
    size = path.stat().st_size if path.exists() else 0
    if size < 1024:
        return False, f"只有 {size} 字节"
    low = path.name.lower()
    if low.endswith((".zip", ".whl", ".jar", ".nupkg")):
        with path.open("rb") as f:
            magic = f.read(2)
        if magic != b"PK":
            return False, "内容不是压缩包"
    elif low.endswith((".tar.gz", ".tgz")):
        import tarfile

        try:
            with tarfile.open(path) as t:
                t.getmembers()
        except Exception:
            return False, "tar 包损坏"
    return True, ""


def _safe_extract_zip(src: Path, dest: Path) -> None:
    """解压时逐条校验路径，防止压缩包里的 ../ 写到工具目录外面。"""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(src) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(root)):
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as f, target.open("wb") as out:
                shutil.copyfileobj(f, out)


def _safe_extract_tar(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(src) as t:
        for m in t.getmembers():
            target = (dest / m.name).resolve()
            if not str(target).startswith(str(root)):
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            f = t.extractfile(m)
            if f:
                with target.open("wb") as out:
                    shutil.copyfileobj(f, out)


def _flatten(single_dir: Path, dest: Path) -> None:
    """压缩包里常套一层同名目录；把内容提到 dest 根，找 bin 时就不用猜层级。"""
    try:
        kids = list(single_dir.iterdir())
    except Exception:
        return
    if len(kids) != 1 or not kids[0].is_dir():
        return
    inner = kids[0]
    for p in list(inner.iterdir()):
        try:
            shutil.move(str(p), str(dest / p.name))
        except Exception:
            pass
    try:
        inner.rmdir()
    except Exception:
        pass


async def install(name: str) -> dict:
    """下载并安装一个工具；返回结果直接给前端展示。"""
    item = CATALOG.get(name)
    if not item:
        return {"ok": False, "error": f"未知工具 {name}"}
    if platform.system().lower() != "windows":
        return {"ok": False, "error": "自动安装目前只覆盖 Windows；其它系统按手动安装指引操作"}
    cur = status(name)
    if cur["installed"]:
        return {"ok": True, "skipped": True, "path": cur["path"],
                "msg": f"已经可用：{cur['path']}"}
    dest = TOOLS_DIR / name
    stage: dict = {"stage": "resolve", "got": 0, "total": 0, "started": time.time()}
    _LAST[name] = stage
    started = time.time()
    url = ""
    try:
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        tmp_dir = TOOLS_DIR / ".tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # 候选地址可能带版本号，先去 release API 要当期 tag；拿不到就用已知版本表
        tag = await _latest_tag(item)
        stage.update({"stage": "resolve", "tag": tag})
        candidates = await _expand_sources(item, tag)
        if not candidates:
            raise RuntimeError("没有可用的下载地址，请按手动安装指引操作")

        errors: list[str] = []
        archive: Path | None = None
        # 版本号对不上的候选地址直接丢掉，避免最后 404 白试
        suffix = ".zip"
        first = candidates[0].lower()
        if first.endswith(".tar.gz"):
            suffix = ".tar.gz"
        elif first.endswith(".jar"):
            suffix = ".jar"
        target = tmp_dir / f"{name}{suffix}"
        if target.exists():
            target.unlink()
        stage.update({"stage": "download", "url": candidates[0], "got": 0, "total": 0,
                      "candidates": len(candidates)})
        _LAST["__cur__"] = {}
        _LAST["__stages__"] = []

        def _prog(got: int, total: int) -> None:
            cur = _LAST.get("__cur__") or {}
            stage.update({"got": got, "total": total,
                          "url": cur.get("url") or stage.get("url"),
                          "via": cur.get("via") or "",
                          "attempt": cur.get("attempt") or 1})

        try:
            url = await _download(candidates, target, _prog)
            archive = target
        except Exception as e:
            errors.append(f"{type(e).__name__}: {str(e)[:300]}")
        if not archive:
            raise RuntimeError("下载失败：" + (" / ".join(errors) or "未知原因"))

        stage.update({"stage": "extract"})
        low = archive.name.lower()
        if low.endswith((".zip", ".whl")):
            _safe_extract_zip(archive, dest)
            _flatten(dest, dest)
        elif low.endswith(".tar.gz"):
            _safe_extract_tar(archive, dest)
            _flatten(dest, dest)
        else:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.move(str(archive), str(dest / "apktool.jar"))
            if item.get("wrapper"):
                (dest / "apktool.bat").write_text(
                    '@echo off\r\njava -jar "%~dp0apktool.jar" %*\r\n', encoding="ascii")

        # 源码包里的入口不叫 bin，而是包自己的命令行入口；按入口名找现成脚本
        want = str(item.get("entry") or "")
        if want:
            hits = [h for h in dest.rglob(f"{want}*.py")
                    if h.parent.name == "bin" or h.name == f"{want}.py"]
            if hits:
                # 优先要真正的入口脚本；包里还有个同名的模块文件，别把它当命令行入口
                hits.sort(key=lambda h: (h.parent.name != "bin", "lib" in h.parts, len(h.parts)))
                item = dict(item, bin=str(hits[0].relative_to(dest)))
        bin_path = dest / str(item["bin"]).replace("/", os.sep)
        if not bin_path.exists():
            # jar 包名里带版本号，或压缩包又多套了一层目录，这里兜底找（跳过 __MACOSX 这类垃圾目录）
            for pat in (Path(item["bin"]).name.replace(".jar", "*.jar"), Path(item["bin"]).name):
                hits = [h for h in dest.rglob(pat) if "__MACOSX" not in h.parts]
                if hits:
                    bin_path = hits[0]
                    break
        if not bin_path.exists():
            kids = [p.name for p in dest.iterdir()][:12] if dest.exists() else []
            raise RuntimeError(f"解压后没找到 {item['bin']}，目录里有：{', '.join(kids) or '空'}")

        try:
            bin_path.chmod(bin_path.stat().st_mode | stat.S_IEXEC)
        except Exception:
            pass

        man = _read_manifest()
        man[name] = {"bin": str(bin_path), "url": url, "ts": int(time.time())}
        _write_manifest(man)
        try:
            archive.unlink()
        except Exception:
            pass
        took = round(time.time() - started, 1)
        note = ""
        needs = item.get("needs")
        if needs and not shutil.which(needs):
            note = f"；注意本机还没装 {needs}，装了也只有命令本身可用"
        _LAST[name] = {"stage": "done", "took": took, "url": url}
        return {"ok": True, "path": str(bin_path), "url": url, "took": took,
                "msg": f"已装到 {bin_path}（{took}s）{note}"}
    except Exception as e:
        _LAST[name] = {"stage": "failed", "error": str(e)[:300], "url": url}
        return {"ok": False, "error": str(e)[:300], "url": url,
                "manual": item.get("manual") or {}}


async def _latest_tag(item: dict) -> str:
    """问 GitHub release API 当前 tag；只在真能连上时才有结果，连不上就返回空。"""
    repo = ""
    for kind, tpl in item.get("sources") or []:
        if kind == "github":
            m = re.search(r"github\.com/([^/]+/[^/]+)/releases", str(tpl))
            if m:
                repo = m.group(1)
                break
    if not repo:
        return ""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(6.0, read=8.0), follow_redirects=True,
                                     trust_env=False, headers={"User-Agent": "suoyu-installer"}) as c:
            r = await c.get(f"https://api.github.com/repos/{repo}/releases/latest")
            if r.status_code >= 400:
                return ""
            return str((r.json() or {}).get("tag_name") or "").lstrip("vV")
    except Exception:
        return ""


async def install_many(names: list[str]) -> dict:
    """串行装多个：并发下多个大包同时拉会互相拖慢，串行反而更快出结果。"""
    out = {}
    for n in names:
        out[n] = await install(n)
        await asyncio.sleep(0)
    return out
