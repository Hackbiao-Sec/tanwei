# -*- mode: python ; coding: utf-8 -*-
"""天鉴·索舆 服务端单文件打包。

用法（在 arl-x 目录下）：
    pyinstaller -y suoyu-server.spec

产物：dist/suoyu-server.exe —— Electron 外壳会把它解到 resources/bin 里拉起。
前端 Vite 产物（arlx/static）与字典（arlx/dicts）都要打进 exe，
否则解压后的进程找不到 index.html 与爆破字典。
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve()

import tldextract as _tldextract

datas = [
    (str(ROOT / "arlx" / "static"), "arlx/static"),
    (str(ROOT / "arlx" / "dicts"), "arlx/dicts"),
    # tldextract 的离线后缀快照：不打包的话解压进程里找不到，root_domain() 会直接抛异常
    (str(Path(_tldextract.__file__).parent / ".tld_set_snapshot"), "tldextract"),
]

# 本机已填配置的种子（AI 模型、爱企查/天眼查等登录态）：由 scripts/build_seed.py
# 生成到 build/，打完首次启动自动填空，省得用户重新填一遍。
_seed = ROOT / "build" / "seed_config.yaml"
if _seed.exists():
    datas.append((str(_seed), "arlx"))

# uvicorn / fastapi 的部分协议实现是运行时按字符串导入的，必须显式收集
hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("fastapi")
    + ["anyio._backends._asyncio", "httpx", "aiohttp", "mmh3", "yaml", "multipart"]
    # 滑块求解在函数里延迟导入，静态分析看不到，必须显式收集
    + ["arlx.engine.collectors.slider", "cv2", "numpy",
       # 各采集器按需导入的库，漏一个就是打包后整类源静默失效
       "dns", "dns.resolver", "dns.asyncresolver", "OpenSSL", "cryptography",
       "PIL", "PIL.Image", "bs4", "lxml", "lxml.etree", "tldextract"]
)

a = Analysis(
    ["launcher.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # numpy 不能排除：滑块求解（slider.py）依赖 cv2/numpy，排除后备案主路会静默失效
    excludes=["tkinter", "matplotlib", "pandas", "PyQt5", "PySide6"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="suoyu-server",
    debug=False,
    strip=False,
    upx=False,
    console=False,
    icon=None,
)
