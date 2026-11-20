import React, { useCallback, useEffect, useState } from "react";
import type { MobileToolItem, MobileToolProgress, MobileToolReport } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";

const GROUP_LABEL: Record<MobileToolItem["group"], string> = {
  android: "Android 平台工具",
  reverse: "反编译与逆向",
  dynamic: "动态运行环境",
  runtime: "运行依赖",
};

const GROUP_HINT: Record<MobileToolItem["group"], string> = {
  android: "adb 负责和设备说话，装包、拉起、抓日志都靠它",
  reverse: "拆包静态分析：dex / 资源 / 清单 / 重打包",
  dynamic: "真机上 hook 与自动化，绕 pinning、抓加解密入参",
  runtime: "上面几件套的运行前提，缺了会直接跑不起来",
};

const PHASE_LABEL: Record<MobileToolProgress["phase"], string> = {
  download: "下载中",
  extract: "解压中",
  install: "安装中",
  done: "完成",
  error: "失败",
};

/**
 * 设置页的移动端工具链：检测 → 一键下载 / 单个下载 → 落到探微自己的工具目录，
 * 没网或下不动时给手工地址与「该放到哪个文件夹」，用户自己放进去也能被认出来。
 */
export function MobileToolkit() {
  const [report, setReport] = useState<MobileToolReport>();
  const [busy, setBusy] = useState<string>();
  const [progress, setProgress] = useState<Record<string, MobileToolProgress>>({});
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [openManual, setOpenManual] = useState<string>();
  const [probing, setProbing] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const next = await window.tanwei.toolkitReport();
      setReport(next);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const off = window.tanwei.onToolkitProgress((p) => {
      setProgress((prev) => ({ ...prev, [p.name]: p }));
      if (p.phase === "done") {
        setLogs((prev) => [`✓ ${p.name}：${p.message}`, ...prev].slice(0, 40));
        void refresh();
      }
      if (p.phase === "error") {
        setLogs((prev) => [`✕ ${p.name}：${p.message}`, ...prev].slice(0, 40));
      }
    });
    return off;
  }, [refresh]);

  const installOne = async (name: string) => {
    if (busy) return;
    setBusy(name);
    setError("");
    try {
      const res = await window.tanwei.toolkitInstall(name);
      setLogs((prev) =>
        [`${res.ok ? "✓" : "✕"} ${name}：${res.error ?? (res.log || (res.ok ? "已就绪" : "失败"))}`, ...prev].slice(0, 40),
      );
      if (!res.ok && res.error) setError(`${name}：${res.error}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(undefined);
      void refresh();
    }
  };

  const installAll = async () => {
    if (busy) return;
    const names = report?.missing ?? [];
    if (!names.length) return;
    setBusy("*");
    setError("");
    try {
      const list = await window.tanwei.toolkitInstallAll(names);
      const ok = list.filter((r) => r.ok).length;
      setLogs((prev) =>
        [`一键下载结束：成功 ${ok} / ${list.length}`, ...prev].slice(0, 40),
      );
      const bad = list.filter((r) => !r.ok && r.error);
      if (bad.length) setError(bad.map((r) => `${r.name}：${r.error}`).join("；"));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(undefined);
      void refresh();
    }
  };

  /** Python 最容易装错：探到多个版本时让主进程挑一个能起 jadx / frida 的接进来 */
  const probePython = async () => {
    if (probing) return;
    setProbing(true);
    try {
      const res = await window.tanwei.toolkitProbe();
      setLogs((prev) =>
        [
          `${res.ok ? "✓" : "✕"} Python：${
            res.hint ?? (res.ok ? `${res.version ?? ""} ${res.path ?? ""}`.trim() : "没找到可用的解释器")
          }`,
          ...prev,
        ].slice(0, 40),
      );
      if (!res.ok && res.hint) setError(res.hint);
      else setError("");
      void refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbing(false);
    }
  };

  const items = report?.items ?? [];
  const groups: MobileToolItem["group"][] = ["android", "reverse", "dynamic", "runtime"];
  const missing = report?.missing ?? [];

  return (
    <div className="card">
      <div className="card-top">
        <span className="card-title">移动端工具链</span>
        <span className={`chip ${missing.length ? "chip-off" : "chip-on"}`}>
          {report ? `就绪 ${report.ready}/${report.total}` : "检测中"}
        </span>
      </div>
      <div className="card-note">
        APP 动静态与小程序拆包要的这几件。点「一键下载缺失」探微自己下、自己解压到自己能读到的目录，
        下载完立刻可用，不用重启。网络不通或想自己装：展开每一项都有官方地址和该放的文件夹。
      </div>
      <div className="tool-root">
        <Icon name="folder" size={12} />
        <span className="mono tool-root-path" title={report?.root}>
          {report?.root ?? "读取中…"}
        </span>
        <button className="btn ghost sm" onClick={() => void window.tanwei.toolkitOpenRoot()}>
          <Icon name="external" size={11} />
          <span>打开目录</span>
        </button>
        <button className="btn ghost sm" onClick={() => void refresh()}>
          <Icon name="refresh" size={11} />
          <span>重新检测</span>
        </button>
        <button className="btn ghost sm" onClick={() => void probePython()} disabled={probing}>
          <Icon name="cpu" size={11} />
          <span>{probing ? "探测中…" : "探测本机 Python"}</span>
        </button>
      </div>

      <div className="card-actions">
        <button className="btn sm" onClick={() => void installAll()} disabled={Boolean(busy) || !missing.length}>
          <Icon name="upload" size={12} />
          <span>
            {busy === "*" ? "下载中…" : missing.length ? `一键下载缺失（${missing.length}）` : "全部就绪"}
          </span>
        </button>
        {report?.pathDirs.length ? (
          <button
            className="btn ghost sm"
            onClick={() => void copyText(report.pathDirs.join("\n"))}
            title={report.pathDirs.join("\n")}
          >
            <Icon name="copy" size={11} />
            <span>复制工具路径</span>
          </button>
        ) : null}
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      <div className="tool-groups">
        {groups.map((g) => {
          const rows = items.filter((i) => i.group === g);
          if (!rows.length) return null;
          return (
            <div className="tool-group" key={g}>
              <div className="tool-group-head">
                <span>{GROUP_LABEL[g]}</span>
                <span className="mono subtle">{GROUP_HINT[g]}</span>
              </div>
              {rows.map((item) => {
                const p = progress[item.name];
                const working = busy === item.name || busy === "*";
                const showBar = p && p.phase !== "done" && p.phase !== "error";
                return (
                  <div className={`tool-row${item.ok ? " ok" : ""}`} key={item.name}>
                    <div className="tool-main">
                      <span className="tool-name mono">{item.name}</span>
                      {item.title && item.title !== item.name ? (
                        <span className="tool-title">{item.title}</span>
                      ) : null}
                      <span className={`chip ${item.ok ? "chip-on" : "chip-off"}`}>
                        {item.ok ? (item.from === "tanwei" ? "探微目录" : "系统 PATH") : item.required ? "缺（必需）" : "缺"}
                      </span>
                      {item.version ? <span className="mono subtle">{item.version}</span> : null}
                      <div className="mob-spacer" />
                      {item.installable ? (
                        <button
                          className="btn ghost sm"
                          disabled={Boolean(busy)}
                          onClick={() => void installOne(item.name)}
                          title={item.ok ? "重新下载覆盖当前版本" : "下载并解压到探微工具目录"}
                        >
                          <Icon name="upload" size={11} />
                          <span>{working ? "处理中…" : item.ok ? "重装" : "下载"}</span>
                        </button>
                      ) : null}
                      <button
                        className="btn ghost sm"
                        onClick={() => setOpenManual(openManual === item.name ? undefined : item.name)}
                      >
                        <Icon name="file" size={11} />
                        <span>{openManual === item.name ? "收起" : "手工装"}</span>
                      </button>
                    </div>
                    <div className="tool-desc">
                      <span>{item.purpose}</span>
                      {item.path ? <span className="mono subtle tool-path">{item.path}</span> : null}
                    </div>
                    {item.launchError ? (
                      <div className="tool-warn">
                        找到了 {item.path ?? item.name}，但起不来：{item.launchError}
                      </div>
                    ) : null}
                    {showBar ? (
                      <div className="tool-prog-wrap">
                        <div className="tool-prog">
                          <span style={{ width: `${Math.max(2, Math.min(100, p.percent ?? 5))}%` }} />
                        </div>
                        <span className="mono subtle">
                          {PHASE_LABEL[p.phase]}
                          {typeof p.percent === "number" ? ` ${Math.round(p.percent)}%` : ""} · {p.message}
                        </span>
                      </div>
                    ) : null}
                    {openManual === item.name ? (
                      <div className="tool-manual">
                        <div className="tool-manual-line">
                          <span className="tool-manual-k">放到</span>
                          <span className="mono tool-manual-v">
                            {report?.root ? `${report.root}\\${item.folder}` : `<探微目录>\\${item.folder}`}
                          </span>
                          <button
                            className="btn ghost sm"
                            onClick={() => void window.tanwei.toolkitOpenDir(item.name)}
                          >
                            <Icon name="folder" size={11} />
                            <span>打开该目录</span>
                          </button>
                        </div>
                        <div className="tool-manual-line">
                          <span className="tool-manual-k">说明</span>
                          <span className="tool-manual-v">{item.manual}</span>
                        </div>
                        <div className="tool-manual-line">
                          <span className="tool-manual-k">地址</span>
                          <span className="mono tool-manual-v tool-manual-url">
                            {item.downloadUrl ?? item.homepage}
                          </span>
                          <button
                            className="btn ghost sm"
                            onClick={() =>
                              void window.tanwei.openExternal(item.downloadUrl ?? item.homepage)
                            }
                          >
                            <Icon name="external" size={11} />
                            <span>浏览器打开</span>
                          </button>
                          <button
                            className="btn ghost sm"
                            onClick={() => void copyText(item.downloadUrl ?? item.homepage)}
                          >
                            <Icon name="copy" size={11} />
                            <span>复制</span>
                          </button>
                        </div>
                        {item.hint ? <div className="tool-manual-note">{item.hint}</div> : null}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>

      {logs.length ? (
        <div className="tool-log">
          {logs.map((l, i) => (
            <div className="mono" key={`${i}-${l.slice(0, 12)}`}>
              {l}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
