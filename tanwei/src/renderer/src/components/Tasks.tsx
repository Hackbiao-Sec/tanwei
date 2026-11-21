import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SessionState, SessionSummary, TaskFile } from "@shared/types";
import { Icon } from "./Icons";
import { FileViewer, type PreviewTarget } from "./FileViewer";
import { ScopeSwitch } from "./ScopeSwitch";
import { useSessionScope } from "../lib/sessionScope";

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
  // 任务文件默认只看本会话认领的任务夹，总览才扫全桌面
  const ctx = useSessionScope();
  const [fileScope, setFileScope] = useState<"session" | "all">("session");
  const fileSeq = useRef(0);
  const filesLoaded = useRef(false);
  const filesAt = useRef(0);
  // 首次扫全桌面要两三秒：这段时间别把「总览 · 0」亮出去，看起来像没有文件
  const [filesReady, setFilesReady] = useState(false);

  // 全桌面文件列表只在真要看总览时才反复扫：本会话压根不读它
  const loadFiles = useCallback(async () => {
    const mine = ++fileSeq.current;
    setFileBusy(true);
    try {
      const list = await window.tanwei.taskFiles();
      if (mine !== fileSeq.current) return;
      setFiles(list);
      filesLoaded.current = true;
      filesAt.current = Date.now();
      setFilesReady(true);
    } catch {
      /* 扫桌面失败就保持上一次的列表 */
    } finally {
      if (mine === fileSeq.current) setFileBusy(false);
    }
  }, []);

  // 本会话档位不读全桌面；切到总览才扫，扫过一次后 15 秒内不因会话事件重扫
  useEffect(() => {
    if (fileScope === "session" && filesLoaded.current) return;
    if (fileScope === "all" && filesLoaded.current && Date.now() - filesAt.current < 15_000) return;
    void loadFiles();
  }, [loadFiles, fileScope, ctx.version]);

  const sourceFiles = fileScope === "session" ? ctx.files : files;

  const fileTasks = useMemo(() => [...new Set(sourceFiles.map((f) => f.task))].sort(), [sourceFiles]);

  // 切范围后旧的任务筛选可能已经不在列表里，回落到「全部」而不是给出空结果
  useEffect(() => {
    if (fileTask !== "全部" && !fileTasks.includes(fileTask)) setFileTask("全部");
  }, [fileTasks, fileTask]);

  const fileRows = useMemo(() => {
    const q = fileQuery.trim().toLowerCase();
    return sourceFiles
      .filter((f) => fileTask === "全部" || f.task === fileTask)
      .filter((f) => !q || f.name.toLowerCase().includes(q) || f.group.toLowerCase().includes(q) || f.task.toLowerCase().includes(q))
      .slice(0, 400);
  }, [sourceFiles, fileTask, fileQuery]);

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
          <ScopeSwitch
            tasks={ctx.tasks}
            scope={fileScope}
            onScope={setFileScope}
            total={filesReady ? files.length : undefined}
            scoped={ctx.files.length}
          />
          <select className="input scope-select" value={fileTask} onChange={(e) => setFileTask(e.target.value)}>
            <option value="全部">全部任务（{sourceFiles.length}）</option>
            {fileTasks.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <span className="subtle">
            {fileScope === "session" && ctx.loading
              ? "读取中…"
              : fileBusy
                ? "读取中…"
                : fileRows.length < sourceFiles.length
                  ? `${fileRows.length} / ${sourceFiles.length} 个文件`
                  : `${fileRows.length} 个文件`}
          </span>
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
            <div className="module-empty">
              {fileScope === "session" && ctx.tasks.length === 0
                ? "这个会话还没认领任务夹。点上面「归属」把桌面上的任务夹勾给它；看全桌面点「总览」。"
                : fileBusy && !filesReady
                  ? "正在扫桌面任务夹里的文件，五千多个要两三秒…"
                  : fileScope === "session"
                    ? "本会话任务夹里还没有文件，或筛选条件太窄。"
                    : "任务夹里还没有文件，或筛选条件太窄。"}
            </div>
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
