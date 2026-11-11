import React, { useEffect, useMemo, useState } from "react";
import type { SessionState, SessionSummary, TaskFile } from "@shared/types";
import { Icon } from "./Icons";
import { FileViewer, type PreviewTarget } from "./FileViewer";

function relTime(input?: number | string): string {
  if (!input) return "—";
  const t = typeof input === "number" ? input : Date.parse(input);
  if (!Number.isFinite(t)) return "—";
  const diff = Date.now() - t;
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const d = new Date(t);
  return `${d.getMonth() + 1}-${String(d.getDate()).padStart(2, "0")}`;
}

function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function baseName(p?: string): string {
  if (!p) return "—";
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

export function Tasks({
  live,
  history,
  loadingId,
  onOpenSession,
  onCreateSession,
}: {
  live: SessionState[];
  history: SessionSummary[];
  loadingId?: string;
  onOpenSession: (id: string) => void;
  onCreateSession: () => void;
}) {
  const [query, setQuery] = useState("");
  const [files, setFiles] = useState<TaskFile[]>([]);
  const [fileTask, setFileTask] = useState("全部");
  const [fileQuery, setFileQuery] = useState("");
  const [fileBusy, setFileBusy] = useState(false);
  const [preview, setPreview] = useState<PreviewTarget | null>(null);

  useEffect(() => {
    let cancelled = false;
    setFileBusy(true);
    void window.tanwei
      .taskFiles()
      .then((list) => {
        if (!cancelled) setFiles(list);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setFileBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const fileTasks = useMemo(() => [...new Set(files.map((f) => f.task))].sort(), [files]);

  const fileRows = useMemo(() => {
    const q = fileQuery.trim().toLowerCase();
    return files
      .filter((f) => fileTask === "全部" || f.task === fileTask)
      .filter((f) => !q || f.name.toLowerCase().includes(q) || f.group.toLowerCase().includes(q) || f.task.toLowerCase().includes(q))
      .slice(0, 400);
  }, [files, fileTask, fileQuery]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const liveRows = live.map((s) => ({
      id: s.id,
      title: s.title || "新会话",
      cwd: s.cwd,
      state: s.busy ? "进行中" : "空闲",
      busy: Boolean(s.busy),
      model: s.model ?? "—",
      tokens: s.usage?.totalTokens ?? 0,
      context: s.contextWindow,
      at: s.updatedAt,
      live: true,
    }));
    const liveIds = new Set(live.map((s) => s.id));
    const histRows = history
      .filter((h) => !liveIds.has(h.id))
      .map((h) => ({
        id: h.id,
        title: h.title || h.id.slice(0, 8),
        cwd: h.cwd ?? "",
        state: !h.status || h.status === "local" ? "历史" : h.status,
        busy: false,
        model: "—",
        tokens: 0,
        context: undefined as number | undefined,
        at: h.updated ? Date.parse(h.updated) : 0,
        live: false,
      }));
    return [...liveRows, ...histRows]
      .filter(
        (r) =>
          !q ||
          r.title.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q) ||
          (r.cwd ?? "").toLowerCase().includes(q),
      )
      .sort((a, b) => Number(b.live) - Number(a.live) || b.at - a.at);
  }, [live, history, query]);

  return (
    <div className="tasks">
      <div className="find-toolbar">
        <div className="search find-search">
          <Icon name="search" size={13} />
          <input value={query} placeholder="搜索会话 / 目录 / ID" onChange={(e) => setQuery(e.target.value)} />
        </div>
        <span className="subtle">{live.length} 个进行中 · {history.length} 个历史</span>
        <button className="btn primary" onClick={onCreateSession}>
          <Icon name="plus" size={13} />
          <span>新建任务</span>
        </button>
      </div>

      <div className="table task-table">
        <div className="table-head">
          <span>任务</span>
          <span>状态</span>
          <span>模型</span>
          <span>用量</span>
          <span>目录</span>
          <span>更新</span>
        </div>
        {rows.length === 0 ? (
          <div className="module-empty">没有会话。</div>
        ) : (
          rows.map((r) => (
            <button
              className="table-row"
              key={r.id}
              onClick={() => onOpenSession(r.id)}
              title={`${r.title}\n${r.id}`}
            >
              <span className="table-title">
                <span className={`live-dot ${r.busy ? "busy" : ""}`} />
                {r.title}
                {loadingId === r.id ? <span className="chip chip-ghost">载入中</span> : null}
              </span>
              <span className={`chip ${r.busy ? "chip-on" : "chip-ghost"}`}>{r.state}</span>
              <span className="mono subtle">{r.model}</span>
              <span className="mono subtle">
                {r.tokens ? `${(r.tokens / 1000).toFixed(1)}k${r.context ? ` / ${Math.round(r.context / 1000)}k` : ""}` : "—"}
              </span>
              <span className="mono subtle">{baseName(r.cwd)}</span>
              <span className="mono subtle">{relTime(r.at)}</span>
            </button>
          ))
        )}
      </div>

      <div className="task-files">
        <div className="find-toolbar">
          <span className="section-label">
            <Icon name="folder" size={13} />
            任务文件
          </span>
          <div className="search find-search">
            <Icon name="search" size={13} />
            <input
              value={fileQuery}
              placeholder="搜索文件名 / 目录"
              onChange={(e) => setFileQuery(e.target.value)}
            />
          </div>
          <select className="input scope-select" value={fileTask} onChange={(e) => setFileTask(e.target.value)}>
            <option value="全部">全部任务（{files.length}）</option>
            {fileTasks.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <span className="subtle">{fileBusy ? "读取中…" : `${fileRows.length} 个文件`}</span>
        </div>

        <div className="table file-table">
          <div className="table-head">
            <span>文件</span>
            <span>任务</span>
            <span>目录</span>
            <span>大小</span>
            <span>更新</span>
          </div>
          {fileRows.length === 0 ? (
            <div className="module-empty">任务夹里还没有文件，或筛选条件太窄。</div>
          ) : (
            fileRows.map((f) => (
              <button
                className="table-row file-row"
                key={f.path}
                title={f.path}
                onClick={() => setPreview({ path: f.path, name: f.name, size: f.size })}
              >
                <span className="table-title mono">
                  <Icon name="file" size={12} />
                  {f.name}
                </span>
                <span className="chip chip-ghost">{f.task}</span>
                <span className="mono subtle">{f.group}</span>
                <span className="mono subtle">{fmtSize(f.size)}</span>
                <span className="mono subtle">{relTime(f.updatedAt)}</span>
              </button>
            ))
          )}
        </div>
      </div>

      <FileViewer file={preview} onClose={() => setPreview(null)} />
    </div>
  );
}
