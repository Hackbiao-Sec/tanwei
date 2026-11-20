import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { TaskFile } from "@shared/types";
import { Icon } from "./Icons";
import { Markdown } from "./Markdown";
import { FileViewer, type PreviewTarget } from "./FileViewer";
import { ScopeSwitch } from "./ScopeSwitch";
import { copyText } from "../lib/clipboard";
import { useSessionScope } from "../lib/sessionScope";

const GROUP_ORDER = ["报告", "资产", "js", "dig", "其它"];

const GROUP_TONE: Record<string, string> = {
  报告: "g-report",
  资产: "g-asset",
  js: "g-js",
  dig: "g-dig",
  其它: "g-other",
};

const MAX_PEEK = 400_000;

function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function fmtTime(t: number): string {
  if (!t) return "—";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function extOf(name: string): string {
  const m = /\.([a-z0-9]{1,6})$/i.exec(name);
  return m ? m[1].toLowerCase() : "txt";
}

function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

/**
 * 文件：把任务夹里真正产出的文件列出来（不再只是资产夹里的一张表），
 * 点一条就地预览，预览不了的一键丢给系统程序。
 */
export function Files() {
  const ctx = useSessionScope();
  const [allFiles, setAllFiles] = useState<TaskFile[]>([]);
  const [allBusy, setAllBusy] = useState(false);
  const [allLoaded, setAllLoaded] = useState(false);
  const allSeq = useRef(0);
  const allAt = useRef(0);
  const [error, setError] = useState("");
  const [scope, setScope] = useState<"session" | "all">("session");
  const [query, setQuery] = useState("");
  const [group, setGroup] = useState<string>("全部");
  const [task, setTask] = useState<string>("全部");
  const [active, setActive] = useState<string>();
  const [peek, setPeek] = useState("");
  const [peekBusy, setPeekBusy] = useState(false);
  const [peekError, setPeekError] = useState("");
  const [modal, setModal] = useState<PreviewTarget | null>(null);
  const [copied, setCopied] = useState("");

  const loading = ctx.loading || allBusy;

  // 全桌面清单只在真要看总览时才扫：本会话档位用的是会话快照，不碰桌面
  const loadAll = useCallback((force = false) => {
    const now = Date.now();
    if (!force && allLoaded && now - allAt.current < 15_000) return;
    const mine = ++allSeq.current;
    setAllBusy(true);
    void window.tanwei
      .taskFiles()
      .then((next) => {
        if (mine !== allSeq.current) return;
        setAllFiles(next);
        setAllLoaded(true);
        allAt.current = Date.now();
      })
      .catch((err) => {
        if (mine === allSeq.current) setError(errText(err));
      })
      .finally(() => {
        if (mine === allSeq.current) setAllBusy(false);
      });
  }, [allLoaded]);

  // 挂载 / 会话事件都不该扫全桌面；切到总览那一下才扫，15 秒内复用上次结果
  useEffect(() => {
    if (scope !== "all") return;
    loadAll();
  }, [scope, loadAll, ctx.version]);

  const files = scope === "session" ? ctx.files : allFiles;

  const load = () => {
    ctx.refresh();
    loadAll(true);
  };

  const scoped = files;

  const counts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const f of scoped) map[f.group] = (map[f.group] ?? 0) + 1;
    return map;
  }, [scoped]);

  const tasks = useMemo(() => {
    const set = new Set(scoped.map((f) => f.task));
    return Array.from(set).sort((a, b) => a.localeCompare(b, "zh"));
  }, [scoped]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = scoped
      .filter((f) => group === "全部" || f.group === group)
      .filter((f) => task === "全部" || f.task === task)
      .filter((f) => !q || f.name.toLowerCase().includes(q) || f.path.toLowerCase().includes(q))
      .sort((a, b) => b.updatedAt - a.updatedAt);
    const byTask = new Map<string, TaskFile[]>();
    for (const f of list) {
      const bucket = byTask.get(f.task);
      if (bucket) bucket.push(f);
      else byTask.set(f.task, [f]);
    }
    return Array.from(byTask.entries());
  }, [scoped, group, task, query]);

  const current = useMemo(() => scoped.find((f) => f.path === active), [scoped, active]);

  useEffect(() => {
    if (!current) {
      setPeek("");
      setPeekError("");
      return;
    }
    let alive = true;
    setPeekBusy(true);
    setPeekError("");
    setPeek("");
    void window.tanwei
      .readTaskFile(current.path)
      .then((text) => {
        if (!alive) return;
        setPeek(text.length > MAX_PEEK ? `${text.slice(0, MAX_PEEK)}\n\n…（文件较大，只显示前 ${MAX_PEEK} 字符，完整内容用外部打开）` : text);
      })
      .catch((err) => {
        if (alive) setPeekError(errText(err));
      })
      .finally(() => {
        if (alive) setPeekBusy(false);
      });
    return () => {
      alive = false;
    };
  }, [current]);

  const totalSize = scoped.reduce((n, f) => n + f.size, 0);
  const reportCount = counts["报告"] ?? 0;
  const shown = rows.reduce((n, [, list]) => n + list.length, 0);

  async function copy(path: string) {
    await copyText(path);
    setCopied(path);
    window.setTimeout(() => setCopied(""), 1500);
  }

  const isMarkdown = current ? /\.md$/i.test(current.name) : false;

  return (
    <div className="files-page">
      <div className="metric-row metric-row-sm">
        <div className="metric">
          <div className="metric-label">任务夹</div>
          <div className="metric-value">{tasks.length}</div>
          <div className="metric-foot">{scope === "session" ? "本会话认领的" : "桌面上全部"}</div>
        </div>
        <div className="metric">
          <div className="metric-label">文件</div>
          <div className="metric-value">{scoped.length}</div>
          <div className="metric-foot">按任务夹分组列出</div>
        </div>
        <div className="metric">
          <div className="metric-label">占用</div>
          <div className="metric-value">{fmtSize(totalSize)}</div>
          <div className="metric-foot">含 js、dig 产物</div>
        </div>
        <div className="metric">
          <div className="metric-label">报告</div>
          <div className="metric-value">{reportCount}</div>
          <div className="metric-foot">报告夹里的正式稿</div>
        </div>
      </div>

      <div className="files-toolbar">
        <div className="search find-search">
          <Icon name="search" size={13} />
          <input
            value={query}
            placeholder="搜文件名 / 路径"
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
          />
        </div>
        <div className="seg">
          <button className={`seg-btn ${group === "全部" ? "on" : ""}`} onClick={() => setGroup("全部")}>
            全部 · {scoped.length}
          </button>
          {GROUP_ORDER.filter((g) => counts[g]).map((g) => (
            <button key={g} className={`seg-btn ${group === g ? "on" : ""}`} onClick={() => setGroup(g)}>
              {g} · {counts[g]}
            </button>
          ))}
        </div>
        <select className="select sm" value={task} onChange={(e) => setTask(e.target.value)}>
          <option value="全部">全部任务夹</option>
          {tasks.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <ScopeSwitch scope={scope} onScope={setScope} total={allLoaded ? allFiles.length : undefined} scoped={ctx.files.length} />
        <button className="btn ghost sm" onClick={load} disabled={loading}>
          <Icon name="refresh" size={12} />
          <span>{loading ? "读取中…" : "刷新"}</span>
        </button>
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      <div className="files-split">
        <div className="files-list">
          {rows.length === 0 ? (
            <div className="module-empty">
              {loading
                ? "正在扫描桌面任务夹里的文件…（任务夹多的时候要等一两秒）"
                : scoped.length === 0
                  ? scope === "session"
                    ? "本会话还没认领任务夹，因此没有文件。点工具栏「归属」把任务夹勾给它；看全桌面点「总览」。"
                    : "桌面上还没扫到任务夹。"
                  : "当前筛选没有匹配的文件。"}
            </div>
          ) : (
            rows.map(([taskName, list]) => (
              <div className="files-group" key={taskName}>
                <div className="files-group-head">
                  <Icon name="folder" size={12} />
                  <span className="files-group-name">{taskName}</span>
                  <span className="files-group-count">{list.length}</span>
                </div>
                {list.map((f) => (
                  <div
                    key={f.path}
                    className={`file-row${active === f.path ? " on" : ""}`}
                    onClick={() => setActive(f.path)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setActive(f.path);
                      }
                    }}
                    title={f.path}
                  >
                    <span className={`file-ext ${GROUP_TONE[f.group] ?? "g-other"}`}>{extOf(f.name)}</span>
                    <span className="file-main">
                      <span className="file-name">{f.name}</span>
                      <span className="file-path mono">{f.path}</span>
                    </span>
                    <span className={`file-group ${GROUP_TONE[f.group] ?? "g-other"}`}>{f.group}</span>
                    <span className="file-meta mono">{fmtSize(f.size)}</span>
                    <span className="file-meta mono">{fmtTime(f.updatedAt)}</span>
                  </div>
                ))}
              </div>
            ))
          )}
          {rows.length > 0 && shown < scoped.length ? (
            <div className="asset-hosts-more">筛选后 {shown} 个，共 {scoped.length} 个</div>
          ) : null}
        </div>

        <div className="file-peek">
          {current ? (
            <>
              <div className="file-peek-head">
                <div className="file-peek-title">
                  <Icon name={isMarkdown ? "file" : "terminal"} size={13} />
                  <span className="mono">{current.name}</span>
                  <span className={`file-group ${GROUP_TONE[current.group] ?? "g-other"}`}>{current.group}</span>
                </div>
                <div className="file-peek-ops">
                  <button className="btn ghost sm" onClick={() => setModal({ path: current.path, name: current.name, size: current.size })}>
                    <Icon name="layers" size={12} />
                    <span>大窗预览</span>
                  </button>
                  <button className="btn ghost sm" onClick={() => void copy(current.path)}>
                    <Icon name="copy" size={12} />
                    <span>{copied === current.path ? "已复制" : "复制路径"}</span>
                  </button>
                  <button className="btn ghost sm" onClick={() => void window.tanwei.reveal(current.path)}>
                    <Icon name="folder" size={12} />
                    <span>定位</span>
                  </button>
                  <button className="btn ghost sm" onClick={() => void window.tanwei.openPath(current.path)}>
                    <Icon name="send" size={12} />
                    <span>外部打开</span>
                  </button>
                </div>
              </div>
              <div className="file-peek-sub mono">
                {current.task} · {fmtSize(current.size)} · {fmtTime(current.updatedAt)}
              </div>
              <div className="file-peek-body">
                {peekBusy ? <div className="panel-empty">读取中…</div> : null}
                {peekError ? <div className="module-error">{peekError}</div> : null}
                {!peekBusy && !peekError ? (
                  isMarkdown ? (
                    <Markdown text={peek} />
                  ) : (
                    <pre className="viewer-pre">{peek || "（空文件）"}</pre>
                  )
                ) : null}
              </div>
            </>
          ) : (
            <div className="module-empty">
              左边点一条文件就地预览。报告渲染成正文，日志、js、json 按原文等宽显示，需要全屏就点「大窗预览」。
            </div>
          )}
        </div>
      </div>

      <FileViewer file={modal} onClose={() => setModal(null)} />
    </div>
  );
}
