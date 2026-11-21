import React, { useCallback, useEffect, useState } from "react";
import type { AdbAction, AdbActionResult, MobileDevice } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";

/**
 * ADB 连接中心：USB 设备、Android 11+ 无线配对、adb connect、tcpip、
 * 断开、重启服务都在这儿点，不用去命令行。
 * 连过的地址记在本机 localStorage，下次一点就填回来。
 */

const HIST_KEY = "tanwei.adb.history";

const STATE_LABEL: Record<string, string> = {
  device: "在线",
  unauthorized: "未授权",
  offline: "离线",
  authorizing: "待授权",
  connecting: "连接中",
  recovery: "recovery",
  sideload: "sideload",
};

function readHist(): string[] {
  try {
    const raw = window.localStorage.getItem(HIST_KEY);
    const list = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(list) ? list.filter((v): v is string => typeof v === "string").slice(0, 8) : [];
  } catch {
    return [];
  }
}

function writeHist(next: string[]): void {
  try {
    window.localStorage.setItem(HIST_KEY, JSON.stringify(next.slice(0, 8)));
  } catch {
    /* 隐私模式下写不进去就只留当前会话内存 */
  }
}

export function AdbCenter({
  serial,
  onSerial,
  onNotice,
  onError,
}: {
  serial: string;
  onSerial: (serial: string) => void;
  onNotice: (msg: string) => void;
  onError: (msg: string) => void;
}) {
  const [devices, setDevices] = useState<MobileDevice[]>([]);
  const [busy, setBusy] = useState<AdbAction>();
  const [missing, setMissing] = useState(false);
  const [result, setResult] = useState<AdbActionResult>();
  const [target, setTarget] = useState("");
  const [pairAddr, setPairAddr] = useState("");
  const [pairCode, setPairCode] = useState("");
  const [tcpPort, setTcpPort] = useState("5555");
  const [hist, setHist] = useState<string[]>([]);

  useEffect(() => setHist(readHist()), []);

  const remember = useCallback((addr: string) => {
    const value = addr.trim();
    if (!value) return;
    setHist((prev) => {
      const next = [value, ...prev.filter((v) => v !== value)].slice(0, 8);
      writeHist(next);
      return next;
    });
  }, []);

  const run = useCallback(
    async (action: AdbAction, extra?: { target?: string; code?: string; port?: number }) => {
      setBusy(action);
      onError("");
      try {
        const res = await window.tanwei.adbAction({
          action,
          target: extra?.target,
          code: extra?.code,
          port: extra?.port,
          serial: serial || undefined,
        });
        setResult(res);
        if (res.devices) {
          setDevices(res.devices);
          const online = res.devices.filter((d) => d.state === "device");
          if (online.length && !online.some((d) => d.serial === serial)) onSerial(online[0].serial);
        }
        setMissing(!res.cmd);
        if (res.hint) {
          onNotice(res.hint);
        } else if (action === "devices") {
          // adb 原始输出是整段设备表，提示条只留一句话就够
          const live = (res.devices ?? []).filter((d) => d.state === "device");
          onNotice(
            live.length
              ? `已连接 ${live.length} 台设备：${live.map((d) => d.serial).join("、")}`
              : "没检测到在线设备：插上 USB 数据线，或先用下面的无线调试配对",
          );
        } else {
          onNotice(res.out.split(/\r?\n/).filter(Boolean).slice(0, 2).join(" · "));
        }
      } catch (err) {
        onError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(undefined);
      }
    },
    [onError, onNotice, onSerial, serial],
  );

  useEffect(() => {
    void run("devices");
    // 只在打开面板时探一次，之后按需刷新
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const online = devices.filter((d) => d.state === "device");

  return (
    <div className="dyn-card adb-card">
      <div className="dyn-card-head">
        <Icon name="phone" size={12} />
        <span>ADB 连接</span>
        <span className={`chip ${missing ? "chip-off" : "chip-on"}`}>
          {missing ? "没装 adb" : `在线 ${online.length}`}
        </span>
        <div className="mob-spacer" />
        <button className="btn ghost sm" onClick={() => void run("devices")} disabled={Boolean(busy)}>
          <Icon name="refresh" size={11} />
          <span>{busy === "devices" ? "刷新中…" : "刷新设备"}</span>
        </button>
        <button
          className="btn ghost sm"
          onClick={() => void run("kill-server")}
          disabled={Boolean(busy)}
          title="设备列表卡住、端口被占时重启 adb 服务"
        >
          <Icon name="bolt" size={11} />
          <span>重启服务</span>
        </button>
        <button className="btn ghost sm" onClick={() => void window.tanwei.toolkitOpenDir("adb")}>
          <Icon name="folder" size={11} />
          <span>adb 目录</span>
        </button>
      </div>

      {missing ? (
        <div className="adb-missing">
          探微还没找到 adb。到 <b>设置 → 移动端工具链</b> 点「一键下载全部」，或者单独下 adb 那一项；
          装好会放到探微自己的工具目录，这里自动就能用。
        </div>
      ) : null}

      <div className="adb-devices">
        {devices.length === 0 ? (
          <div className="dyn-hint">
            还没有设备。USB 连接：手机开「开发者选项 → USB 调试」，插线后手机上点允许授权。
            无线连接：Android 11+ 在「无线调试」里配对后连，Android 10 及以下先用 USB 跑一次「切无线调试」。
          </div>
        ) : (
          devices.map((d) => (
            <button
              key={d.serial}
              className={`adb-device${serial === d.serial ? " on" : ""}${d.state === "device" ? "" : " bad"}`}
              onClick={() => onSerial(d.serial)}
              title={`${d.serial}${d.model ? ` · ${d.model}` : ""}`}
            >
              <span className="adb-device-serial mono">{d.serial}</span>
              <span className={`adb-device-state s-${d.state}`}>{STATE_LABEL[d.state] ?? d.state}</span>
              {d.model ? <span className="adb-device-model">{d.model}</span> : null}
            </button>
          ))
        )}
      </div>

      <div className="adb-grid">
        <div className="adb-box">
          <div className="adb-box-title">
            <Icon name="plug" size={11} />
            <span>无线连接</span>
            <span className="mono subtle">Android 11+ 先配对</span>
          </div>
          <div className="dyn-row">
            <input
              className="dyn-input mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.23:5555"
              spellCheck={false}
            />
          </div>
          <div className="adb-actions">
            <button
              className="btn ghost sm"
              onClick={() => {
                remember(target);
                void run("connect", { target });
              }}
              disabled={Boolean(busy) || !target.trim()}
            >
              <Icon name="plug" size={11} />
              <span>{busy === "connect" ? "连接中…" : "连接"}</span>
            </button>
            <button
              className="btn ghost sm"
              onClick={() => void run("disconnect", { target })}
              disabled={Boolean(busy) || !target.trim()}
              title="只断这个地址；留空会断开全部网络设备"
            >
              <Icon name="close" size={11} />
              <span>断开</span>
            </button>
          </div>
        </div>

        <div className="adb-box">
          <div className="adb-box-title">
            <Icon name="shield" size={11} />
            <span>无线配对</span>
            <span className="mono subtle">配对端口和连接端口不同</span>
          </div>
          <div className="dyn-row">
            <input
              className="dyn-input mono"
              value={pairAddr}
              onChange={(e) => setPairAddr(e.target.value)}
              placeholder="配对地址 192.168.1.23:41234"
              spellCheck={false}
            />
          </div>
          <div className="dyn-row">
            <input
              className="dyn-input mono adb-code"
              value={pairCode}
              onChange={(e) => setPairCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="6 位配对码"
              spellCheck={false}
            />
          </div>
          <div className="adb-actions">
            <button
              className="btn ghost sm"
              onClick={() => {
                const host = pairAddr.split(":")[0];
                if (host) remember(`${host}:${target.split(":")[1] ?? "5555"}`);
                void run("pair", { target: pairAddr, code: pairCode });
              }}
              disabled={Boolean(busy) || !pairAddr.trim() || pairCode.length < 6}
            >
              <Icon name="check" size={11} />
              <span>{busy === "pair" ? "配对中…" : "配对"}</span>
            </button>
          </div>
        </div>

        <div className="adb-box">
          <div className="adb-box-title">
            <Icon name="bolt" size={11} />
            <span>切无线调试</span>
            <span className="mono subtle">{serial || "先选一台 USB 设备"}</span>
          </div>
          <div className="dyn-row">
            <input
              className="dyn-input mono"
              value={tcpPort}
              onChange={(e) => setTcpPort(e.target.value.replace(/\D/g, "").slice(0, 5))}
              placeholder="5555"
              spellCheck={false}
            />
          </div>
          <div className="adb-actions">
            <button
              className="btn ghost sm"
              onClick={() => void run("tcpip", { port: Number(tcpPort) || 5555 })}
              disabled={Boolean(busy) || !serial}
              title="USB 连着时执行 adb tcpip，之后手机拔线也能用 IP 连"
            >
              <Icon name="phone" size={11} />
              <span>{busy === "tcpip" ? "切换中…" : "切到无线"}</span>
            </button>
            <button
              className="btn ghost sm"
              onClick={() => void run("ip")}
              disabled={Boolean(busy) || !serial}
              title="读设备自己的 IP，填到上面的无线连接里"
            >
              <Icon name="globe" size={11} />
              <span>读设备 IP</span>
            </button>
            <button
              className="btn ghost sm"
              onClick={() => void run("usb")}
              disabled={Boolean(busy) || !serial}
              title="切回 USB 模式"
            >
              <Icon name="terminal" size={11} />
              <span>回 USB</span>
            </button>
          </div>
        </div>
      </div>

      {hist.length ? (
        <div className="adb-hist">
          <span className="subtle">最近连过</span>
          {hist.map((h) => (
            <button key={h} className="adb-hist-chip mono" onClick={() => setTarget(h)} title="填进无线连接">
              {h}
            </button>
          ))}
          <button
            className="adb-hist-chip"
            onClick={() => {
              writeHist([]);
              setHist([]);
            }}
            title="只清地址记忆，不动设备和工具"
          >
            清空
          </button>
        </div>
      ) : null}

      {result ? (
        <div className="adb-out">
          <div className="adb-out-head">
            <span className={`dyn-state ${result.ok ? "ok" : "fail"}`}>{result.ok ? "成功" : "失败"}</span>
            <span className="mono subtle">{result.cmd || "没有执行命令"}</span>
            <div className="mob-spacer" />
            <button className="btn ghost sm" onClick={() => void copyText(result.out || result.cmd)}>
              <Icon name="copy" size={11} />
              <span>复制回显</span>
            </button>
          </div>
          <pre className="dyn-out">{result.out || result.hint || "（无输出）"}</pre>
          {result.hint ? <div className="dyn-hint">{result.hint}</div> : null}
        </div>
      ) : null}
    </div>
  );
}
