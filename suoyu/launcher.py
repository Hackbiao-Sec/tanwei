# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 冷启动入口：from arlx.server import main; main()

单独做一个只 import 的脚本，避免打包时把 arlx/__main__.py 当成包入口导致相对导入失败。
"""
import multiprocessing
import os
import sys

# 冻结后 sys.stdout 是 None，uvicorn 打日志会炸；给个黑洞顶上
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")


def _data_dir() -> str:
    """和 arlx.config 同一个口径：ARLX_DATA 优先，其次 Electron 外壳给的数据目录。"""
    if os.environ.get("ARLX_DATA"):
        return os.environ["ARLX_DATA"]
    appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(appdata, "suoyu-console", "data")


def _install_crash_log() -> str:
    """把崩溃写进 crash.log。

    窗口化 exe 没有控制台，主循环里冒出来的异常、C 层崩溃默认一句话都不留，
    现场只剩「exe 自己退了、任务停在某个百分比」。启动、退出、traceback 都落盘，
    下一次出问题直接看这个文件。
    """
    path = os.path.join(_data_dir(), "crash.log")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > 1024 * 1024:
            os.replace(path, path + ".old")
        fh = open(path, "a", encoding="utf-8", buffering=1)
    except Exception:
        return ""

    import datetime
    import traceback

    try:
        import faulthandler

        faulthandler.enable(file=fh, all_threads=True)
    except Exception:
        pass

    def _stamp(text: str) -> None:
        try:
            fh.write("%s %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text))
            fh.flush()
        except Exception:
            pass

    sys._crash_stamp = _stamp  # type: ignore[attr-defined]

    def _hook(exc_type, exc, tb) -> None:
        try:
            fh.write("".join(traceback.format_exception(exc_type, exc, tb)))
            fh.flush()
        except Exception:
            pass
        # 冻结后 stderr 是 devnull，走默认钩子不会再炸；保留是为了 python launcher.py 时也有输出
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook

    # 采集协程在后台线程里炸掉时进程还活着，但那条线等于没了；同样留证据
    import threading

    def _thread_hook(args) -> None:
        try:
            fh.write("thread %s died:\n" % (getattr(args.thread, "name", "?"),))
            fh.write("".join(traceback.format_exception(
                args.exc_type, args.exc_value, args.exc_traceback)))
            fh.flush()
        except Exception:
            pass

    threading.excepthook = _thread_hook
    _stamp("engine start pid=%s argv=%s" % (os.getpid(), " ".join(sys.argv[1:])))
    return path


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.argv = [sys.argv[0], "-m", "arlx"]
    _install_crash_log()
    stamp = getattr(sys, "_crash_stamp", lambda _t: None)
    # 放在保护块里 import：导入期的异常也能落 crash.log，打包分析也认得到 arlx 包
    from arlx.server import main

    try:
        main()
        stamp("engine stopped normally")
    except SystemExit as e:
        stamp("engine exit SystemExit code=%s" % (e.code,))
        raise
    except BaseException:
        stamp("engine died with exception, traceback follows")
        try:
            import traceback

            traceback.print_exc()
        except Exception:
            pass
        raise
