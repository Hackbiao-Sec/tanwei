import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { MobileAppEntry, MobileAppList, MobileDevice } from "@shared/types";
import { Icon } from "./Icons";
import { errText } from "./MobileShared";

type Filter = "third" | "all" | "system";

/**
 * 设备应用：连着的手机里装了什么，这里直接列出来。
 * 显示名按需从设备上的 APK 里解，先第三方后系统，后台慢慢补，不挡列表。
 */
export function DeviceApps({
  serial,
  devices,
  onSerial,
  activePkg,
  busyPkg,
  onPick,
  onAnalyze,
  onNotice,
  onError,
}: {
  serial: string;
  devices: MobileDevice[];
  onSerial: (serial: string) => void;
  activePkg?: string;
  /** 正在拉的包名：拉包 → 拆解期间按钮转圈 */
  busyPkg?: string;
  /** 设为动态目标：只带包名与路径，不拆 */
  onPick: (app: MobileAppEntry) => void;
  /** 拉包并拆解：手机里的 APK 复制到本机再走静态 */
  onAnalyze: (app: MobileAppEntry) => void;
  onNotice: (text: string) => void;
  onError: (text: string) => void;
}) {
  const [list, setList] = useState<MobileAppList>();
  const [apps, setApps] = useState<MobileAppEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [filter, setFilter] = useState<Filter>("third");
  const [kw, setKw] = useState("");
  const fillToken = useRef<{ stop: boolean }>({ stop: true });

  const startFill = useCallback((device: string, items: MobileAppEntry[]) => {
    fillToken.current.stop = true;
    const token = { stop: false };
    fillToken.current = token;
    // 第三方优先：用户关心的基本都在这一档，系统应用在后台慢慢补
    const queue = items
      .filter((a) => a.labelState !== "done")
      .sort((a, b) => Number(a.system) - Number(b.system));
    setProgress({ done: 0, total: queue.length });
    if (!queue.length) return;
    let cursor = 0;
    let finished = 0;
    const worker = async () => {
      for (;;) {
        if (token.stop) return;
        const app = queue[cursor];
        cursor += 1;
        if (!app) return;
        let label: string | undefined;
        let ok = false;
        try {
          const res = await window.tanwei.mobileAppLabel({
            serial: device,
            packageName: app.packageName,
            apkPath: app.apkPath,
            versionCode: app.versionCode,
          });
          label = res.label;
          ok = Boolean(res.ok);
        } catch {
          ok = false;
        }
        if (token.stop) return;
        finished += 1;
        setProgress({ done: finished, total: queue.length });
        setApps((prev) =>
          prev.map((x) =>
            x.packageName === app.packageName
              ? { ...x, label: label ?? x.label, labelState: ok ? "done" : "failed" }
              : x,
          ),
        );
      }
    };
    for (let i = 0; i < 3; i += 1) void worker();
  }, []);

  const load = useCallback(
    async (target?: string) => {
      setLoading(true);
      try {
        const res = await window.tanwei.mobileApps(target || undefined);
        setList(res);
        setApps(res.apps);
        if (!res.ok) {
          onError(res.hint ?? "列不出设备应用");
          return;
        }
        if (!target && res.serial) onSerial(res.serial);
        setFilter(res.thirdParty ? "third" : "all");
        startFill(res.serial, res.apps);
      } catch (err) {
        onError(errText(err));
      } finally {
        setLoading(false);
      }
    },
    [onError, onSerial, startFill],
  );

  useEffect(() => {
    void load(serial || undefined);
    // 只在挂载与换设备时重列：serial 由这里自己回写，不跟着抖
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serial]);

  useEffect(
    () => () => {
      fillToken.current.stop = true;
    },
    [],
  );

  const filtered = useMemo(() => {
    const key = kw.trim().toLowerCase();
    return apps.filter((a) => {
      if (filter === "third" && a.system) return false;
      if (filter === "system" && !a.system) return false;
      if (!key) return true;
      return (
        (a.label ?? "").toLowerCase().includes(key) ||
        a.packageName.toLowerCase().includes(key) ||
        (a.versionCode ?? "").includes(key)
      );
    });
  }, [apps, filter, kw]);

  const shown = filtered.slice(0, 150);
  const named = apps.filter((a) => a.label).length;
  const thirdParty = apps.filter((a) => !a.system).length;

  return (
    <div className="dapps">
      <div className="dapps-head">
        <Icon name="phone" size={12} />
        <span>设备应用</span>
        <span className="mono subtle">
          {apps.length ? `${apps.length} 个 · 第三方 ${thirdParty}` : loading ? "读取中…" : "未连接"}
        </span>
        <div className="mob-spacer" />
        <button
          className="icon-btn sm"
          title="重新读取设备应用列表"
          onClick={() => void load(serial || undefined)}
          disabled={loading}
        >
          <Icon name="refresh" size={12} />
        </button>
      </div>

      {devices.length > 1 ? (
        <div className="dapps-devices">
          {devices.map((d) => (
            <button
              key={d.serial}
              className={`dapps-device${serial === d.serial ? " on" : ""}`}
              onClick={() => onSerial(d.serial)}
              title={d.serial}
            >
              {d.model ?? d.serial}
            </button>
          ))}
        </div>
      ) : null}

      <div className="dapps-search">
        <Icon name="search" size={12} />
        <input
          value={kw}
          onChange={(e) => setKw(e.target.value)}
          placeholder="搜应用名 / 包名"
          spellCheck={false}
        />
        {kw ? (
          <button className="icon-btn sm" onClick={() => setKw("")} title="清空">
            <Icon name="close" size={11} />
          </button>
        ) : null}
      </div>

      <div className="dapps-filters">
        <button
          className={`dapps-chip${filter === "third" ? " on" : ""}`}
          onClick={() => setFilter("third")}
        >
          第三方 {thirdParty}
        </button>
        <button className={`dapps-chip${filter === "all" ? " on" : ""}`} onClick={() => setFilter("all")}>
          全部 {apps.length}
        </button>
        <button
          className={`dapps-chip${filter === "system" ? " on" : ""}`}
          onClick={() => setFilter("system")}
        >
          系统 {apps.length - thirdParty}
        </button>
        {progress.total > 0 && progress.done < progress.total ? (
          <span className="dapps-fill mono" title="显示名从设备安装包里解，走完就全有名字">
            补名 {progress.done}/{progress.total}
          </span>
        ) : apps.length ? (
          <span className="dapps-fill mono" title="有名字的应用数">
            已命名 {named}
          </span>
        ) : null}
      </div>

      <div className="dapps-list">
        {loading && !apps.length ? (
          <div className="module-empty">
            正在读设备上的应用列表…首次会慢一点，之后是缓存。
          </div>
        ) : shown.length ? (
          shown.map((app) => (
            <div
              key={app.packageName}
              className={`dapps-row${activePkg === app.packageName ? " on" : ""}`}
              role="button"
              tabIndex={0}
              title={app.apkPath ?? app.packageName}
              onClick={() => onPick(app)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onPick(app);
                }
              }}
            >
              <span className="dapps-avatar">{app.label ? app.label.slice(0, 1) : "?"}</span>
              <span className="dapps-main">
                <span className="dapps-name">{app.label ?? app.packageName}</span>
                <span className="dapps-pkg mono">{app.packageName}</span>
              </span>
              {app.system ? <span className="dapps-tag">系统</span> : null}
              <span className="dapps-ops">
                <button
                  className="btn ghost sm"
                  title="把这个应用设为动态测试目标（带包名与安装包路径）"
                  onClick={(e) => {
                    e.stopPropagation();
                    onPick(app);
                    onNotice(`已设为动态目标：${app.label ?? app.packageName}`);
                  }}
                >
                  <Icon name="terminal" size={11} />
                  <span>带上</span>
                </button>
                <button
                  className="btn primary sm"
                  title="把设备上的安装包拉到本机，直接做静态拆解"
                  disabled={busyPkg === app.packageName || Boolean(busyPkg)}
                  onClick={(e) => {
                    e.stopPropagation();
                    onAnalyze(app);
                  }}
                >
                  <Icon name="layers" size={11} />
                  <span>{busyPkg === app.packageName ? "拉包中…" : "拉包拆解"}</span>
                </button>
              </span>
            </div>
          ))
        ) : (
          <div className="module-empty">
            {kw.trim()
              ? "没有匹配的应用，换个关键词。"
              : filter === "third"
                ? "这台设备没有第三方应用。"
                : "没有应用列表：开 USB 调试并授权后点刷新。"}
          </div>
        )}
        {filtered.length > shown.length ? (
          <div className="dapps-more">还有 {filtered.length - shown.length} 个，缩小搜索范围再看</div>
        ) : null}
      </div>
    </div>
  );
}
