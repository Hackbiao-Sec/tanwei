"""屏蔽 platform 的 WMI 探测。

CPython 在 Windows 上会优先用 WMI 取系统版本（``platform._wmi_query``）。本机 WMI
服务响应异常时这次调用会长时间不返回，而 urllib3 等网络库在导入阶段就会调
``platform.system()``，于是整个进程卡死在 import 上。

这里把 WMI 句柄提前置空，``platform`` 会自动回退到 ``sys.getwindowsversion()`` +
``ver`` 的官方分支，只影响版本字符串的取法，不影响其它功能。

必须在导入任何网络库之前执行，因此由 ``arlx/__init__.py`` 第一行引入。
"""

import platform

if getattr(platform, "_wmi", None):
    platform._wmi = None
