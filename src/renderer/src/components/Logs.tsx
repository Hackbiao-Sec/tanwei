import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { LogFile } from "@shared/types";
import { Icon } from "./Icons";

const LEVEL_RE = /"level"\s*:\s*"(\w+)"/i;
const BAD_RE = /error|warn|fail|exception|panic|fatal|denied|timeout/i;
/**
 * 每个进程启动都会打一遍、和功能无关的噪声：
 * 没有 x.ai 登录态时的 auth.json info、图片预算、逐阶段 debug。
 */
const NOISE_RE = /AuthManager::new|auth\.json load result|shell\.image_budget|turn\.phase_transition/;

function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function fmtTime(t: number): string {
  if (!t) return "—";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 尽量把 JSONL 压成一行可读文本；解析不了就原样显示。 */
function pretty(line: string): string {
  const text = line.trim();
  if (!text.startsWith("{")) return line;
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    const at = obj.ts ?? obj.time ?? obj.timestamp ?? obj.t;
    const level = obj.level ?? obj.severity;
    const msg = obj.msg ?? obj.message ?? obj.event;
    if (!msg) return line;
    const head = [typeof at === "string" ? at : "", typeof level === "string" ? level.toUpperCase() : ""]
      .filter(Boolean)
      .join(" ");
    const rest = Object.entries(obj)
      .filter(([k]) => !["ts", "time", "timestamp", "t", "level", "severity", "msg", "message", "event"].includes(k))
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join(" ");
    return `${head ? `${head} ` : ""}${String(msg)}${rest ? ` · ${rest}` : ""}`;
  } catch {
    return line;
  }
}

export function Logs() {
  const [files, setFiles] = useState<LogFile[]>([]);
  const [active, setActive] = useState<LogFile>();
  const [text, setText] = useState("");
  const [query, setQuery] = useState("");
  const [onlyBad, setOnlyBad] = useState(false);
  const [hideNoise, setHideNoise] = useState(true);
  const [auto, setAuto] = useState(true);
  const [size, setSize] = useState(0);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const timer = useRef<number>();

  const loadFiles = useCallback(async () => {
    try {
      const list = await window.tanwei.logs();
      setFiles(list);
      setActive((prev) => {
        if (prev && list.some((f) => f.path === prev.path)) return list.find((f) => f.path === prev.path);
        return list.find((f) => f.name.endsWith("unified.jsonl")) ?? list[0];
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  const loadTail = useCallback(async (target: LogFile) => {
    setLoading(true);
    setError(undefined);
    try {
      const res = await window.tanwei.logTail(target.path, 500);
      setText(res.text);
      setSize(res.size);
      setTruncated(res.truncated);
    } catch (err) {
      setText("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadFiles();
  }, [loadFiles]);

  useEffect(() => {
    if (active) void loadTail(active);
  }, [active, loadTail]);

  useEffect(() => {
    window.clearInterval(timer.current);
    if (!auto || !active) return;
    timer.current = window.setInterval(() => {
      void loadTail(active);
      void loadFiles();
    }, 3000);
    return () => window.clearInterval(timer.current);
  }, [auto, active, loadTail, loadFiles]);

  const lines = useMemo(() => {
    const q = query.trim().toLowerCase();
    const raw = text.split(/\r?\n/).filter((l) => l.length > 0);
    const rows = raw.map((rawLine, i) => ({ i, raw: rawLine, view: pretty(rawLine) }));
    return rows.filter((row) => {
      if (hideNoise && NOISE_RE.test(row.raw)) return false;
      if (onlyBad && !BAD_RE.test(row.view) && !BAD_RE.test(LEVEL_RE.exec(row.view)?.[1] ?? "")) return false;
      if (!q) return true;
      return row.view.toLowerCase().includes(q);
    });
  }, [text, query, onlyBad, hideNoise]);

  return (
    <div className="logs-page">
      <div className="logs-split">
        <aside className="logs-files">
          <header className="logs-files-head">
            <span>日志文件</span>
            <button className="mini-btn" title="刷新列表" onClick={() => void loadFiles()}>
              <Icon name="refresh" size={12} />
            </button>
          </header>
          <div className="logs-file-list">
            {files.length === 0 ? (
              <div className="panel-empty">没有日志文件。</div>
            ) : (
              files.map((f) => (
                <button
                  key={f.path}
                  className={`logs-file ${active?.path === f.path ? "on" : ""}`}
                  onClick={() => setActive(f)}
                  title={f.path}
                >
                  <span className="logs-file-name mono">{f.name}</span>
                  <span className="logs-file-meta">
                    {fmtSize(f.size)} · {fmtTime(f.updatedAt)}
                  </span>
                </button>
              ))
            )}
          </div>
        </aside>

        <section className="logs-view">
          <div className="logs-toolbar">
            <label className="search logs-search">
              <Icon name="search" size={13} />
              <input value={query} placeholder="过滤日志内容" onChange={(e) => setQuery(e.target.value)} />
            </label>
            <div className="seg">
              <button className={`seg-btn ${hideNoise ? "on" : ""}`} onClick={() => setHideNoise((v) => !v)}>
                隐藏噪声
              </button>
              <button className={`seg-btn ${onlyBad ? "on" : ""}`} onClick={() => setOnlyBad((v) => !v)}>
                只看问题
              </button>
              <button className={`seg-btn ${auto ? "on" : ""}`} onClick={() => setAuto((v) => !v)}>
                自动刷新
              </button>
            </div>
            <div className="logs-meta">
              {lines.length} 行
              {truncated ? "（尾部）" : ""} · {fmtSize(size)}
            </div>
            <div className="logs-ops">
              <button className="btn ghost sm" disabled={!active} onClick={() => active && void loadTail(active)}>
                <Icon name="refresh" size={12} />
                <span>{loading ? "读取中…" : "刷新"}</span>
              </button>
              <button className="btn ghost sm" disabled={!active} onClick={() => active && void window.tanwei.reveal(active.path)}>
                <Icon name="folder" size={12} />
                <span>定位</span>
              </button>
            </div>
          </div>

          {error ? <div className="module-error">{error}</div> : null}

          <div className="logs-body">
            {lines.length === 0 ? (
              <div className="panel-empty">{text ? "没有匹配的行。" : "选一个日志文件。"}</div>
            ) : (
              lines.map((row) => (
                <div key={row.i} className={`logs-line ${BAD_RE.test(row.view) ? "bad" : ""}`}>
                  <span className="logs-no">{row.i + 1}</span>
                  <span className="logs-text">{row.view}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
