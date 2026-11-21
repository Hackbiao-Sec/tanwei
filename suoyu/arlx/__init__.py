"""天鉴·索舆 后端包。

第一行必须保留：导入网络库前先关掉 platform 的 WMI 探测，否则 WMI 无响应时整个
进程会在 import 阶段挂住。
"""

from . import _platform_guard as _platform_guard  # noqa: F401
