import React, { useMemo, useState } from "react";
import type { SessionState, SessionSummary } from "@shared/types";
import type { ModuleId, View } from "../view";
import { MODULES } from "../view";
import { Icon } from "./Icons";

function baseName(p?: string): string {
  if (!p) return "";
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

function relTime(input?: string | number): string {
  if (!input) return "";
  const t = typeof input === "number" ? input : Date.parse(input);
  if (!Number.isFinite(t)) return "";
  const diff = Date.now() - t;
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const d = new Date(t);
  return `${d.getMonth() + 1}-${String(d.getDate()).padStart(2, "0")}`;
}

export function Sidebar({
  live,
  history,
  activeId,
  view,
  loadingId,
  onSelectSession,
  onNewSession,
  onModule,
  onRefresh,
}: {
  live: SessionState[];
  history: SessionSummary[];
  activeId?: string;
  view: View;
  loadingId?: string;
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onModule: (id: ModuleId) => void;
  onRefresh: () => void;
}) {
  const [query, setQuery] = useState("");

  const liveIds = useMemo(() => new Set(live.map((s) => s.id)), [live]);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const liveRows = live
      .filter((s) => !q || (s.title || "").toLowerCase().includes(q) || s.id.toLowerCase().includes(q))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .map((s) => ({
        id: s.id,
        title: s.title || "未命名会话",
        sub: baseName(s.cwd),
        busy: s.busy,
        updated: s.updatedAt,
        live: true,
      }));
    const histRows = history
      .filter((h) => !liveIds.has(h.id))
      .filter(
        (h) =>
          !q ||
          (h.title || "").toLowerCase().includes(q) ||
          h.id.toLowerCase().includes(q) ||
          (h.cwd || "").toLowerCase().includes(q),
      )
      .map((h) => ({
        id: h.id,
        title: h.title || h.id.slice(0, 8),
        sub: baseName(h.cwd),
        busy: false,
        updated: h.updated ? Date.parse(h.updated) : 0,
        live: false,
      }));
    return { liveRows, histRows };
  }, [live, history, liveIds, query]);

  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <button className="new-session" onClick={onNewSession}>
          <Icon name="plus" size={14} />
          <span>新建会话</span>
          <span className="kbd">Ctrl+N</span>
        </button>
        <div className="search">
          <Icon name="search" size={13} />
          <input
            value={query}
            placeholder="搜索会话 / 目录"
            onChange={(e) => setQuery(e.target.value)}
          />
          <button className="icon-btn tiny" onClick={onRefresh} title="重新读取会话列表">
            <Icon name="refresh" size={12} />
          </button>
        </div>
      </div>

      <div className="session-scroll">
        {rows.liveRows.length > 0 ? (
          <div className="session-group">
            <div className="group-label">
              <span>进行中</span>
              <span className="group-count">{rows.liveRows.length}</span>
            </div>
            {rows.liveRows.map((r) => (
              <button
                key={r.id}
                className={`session-row ${activeId === r.id && view.kind === "session" ? "active" : ""}`}
                onClick={() => onSelectSession(r.id)}
              >
                <span className={`live-dot ${r.busy ? "busy" : ""}`} />
                <span className="session-main">
                  <span className="session-title">{r.title}</span>
                  <span className="session-sub">
                    {r.sub || "会话"} · {relTime(r.updated)}
                  </span>
                </span>
              </button>
            ))}
          </div>
        ) : null}

        <div className="session-group">
          <div className="group-label">
            <span>历史会话</span>
            <span className="group-count">{rows.histRows.length}</span>
          </div>
          {rows.histRows.length === 0 ? (
            <div className="group-empty">没有更多会话</div>
          ) : (
            rows.histRows.map((r) => (
              <button
                key={r.id}
                className={`session-row ${activeId === r.id && view.kind === "session" ? "active" : ""}`}
                onClick={() => onSelectSession(r.id)}
              >
                <span className={`live-dot ${loadingId === r.id ? "busy" : ""}`} />
                <span className="session-main">
                  <span className="session-title">{r.title}</span>
                  <span className="session-sub">
                    {r.sub || "历史"} · {relTime(r.updated)}
                  </span>
                </span>
              </button>
            ))
          )}
        </div>
      </div>

      <div className="module-nav">
        {(["作战", "配置"] as const).map((group) => (
          <div className="module-group" key={group}>
            <div className="group-label">
              <span>{group}</span>
            </div>
            <div className="module-grid">
              {MODULES.filter((m) => m.group === group).map((m) => (
                <button
                  key={m.id}
                  className={`module-btn ${view.kind === "module" && view.id === m.id ? "active" : ""}`}
                  onClick={() => onModule(m.id)}
                  title={m.desc}
                >
                  <Icon name={m.icon} size={14} />
                  <span>{m.label}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
