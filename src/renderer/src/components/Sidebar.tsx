import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SessionState, SessionSummary } from "@shared/types";
import type { ModuleGroupId, ModuleId, View } from "../view";
import { MODULE_GROUPS, modulesOf } from "../view";
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

type SessionRow = {
  id: string;
  title: string;
  sub: string;
  busy: boolean;
  updated: number;
  live: boolean;
};

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
  onDeleteSession,
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
  onDeleteSession?: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  /** 待确认删除的会话 id，行内二次确认 */
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [pop, setPop] = useState<{ top: number; left: number; width: number }>();
  const [openGroups, setOpenGroups] = useState<Record<ModuleGroupId, boolean>>({
    situation: true,
    fight: true,
    config: true,
  });
  const toggleGroup = (id: ModuleGroupId) =>
    setOpenGroups((prev) => ({ ...prev, [id]: !prev[id] }));

  const pickerBtn = useRef<HTMLButtonElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);

  const openPicker = useCallback(() => {
    const rect = pickerBtn.current?.getBoundingClientRect();
    if (!rect) return;
    setQuery("");
    setPendingDelete(null);
    setPop({
      top: Math.round(rect.bottom + 6),
      left: Math.round(rect.left),
      width: Math.round(Math.min(400, window.innerWidth - rect.left - 14)),
    });
    setPickerOpen(true);
  }, []);

  const closePicker = useCallback(() => {
    setPickerOpen(false);
    setPendingDelete(null);
  }, []);

  useEffect(() => {
    if (!pickerOpen) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (!t) return;
      if (popRef.current?.contains(t) || pickerBtn.current?.contains(t)) return;
      closePicker();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closePicker();
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", closePicker);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", closePicker);
    };
  }, [pickerOpen, closePicker]);

  const liveIds = useMemo(() => new Set(live.map((s) => s.id)), [live]);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const liveRows: SessionRow[] = live
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
    const histRows: SessionRow[] = history
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

  const total = rows.liveRows.length + rows.histRows.length;
  const current = useMemo(
    () => [...rows.liveRows, ...rows.histRows].find((r) => r.id === activeId),
    [rows, activeId],
  );
  const activeLive = live.find((s) => s.id === activeId);

  const pick = (id: string) => {
    closePicker();
    onSelectSession(id);
  };

  const rowNode = (r: SessionRow) => {
    const confirming = pendingDelete === r.id;
    return (
      <div
        key={r.id}
        className={`session-row ${activeId === r.id && view.kind === "session" ? "active" : ""}`}
        role="button"
        tabIndex={0}
        aria-current={activeId === r.id && view.kind === "session" ? "true" : undefined}
        onClick={() => {
          if (!confirming) pick(r.id);
        }}
        onKeyDown={(e) => {
          if (e.key !== "Enter" && e.key !== " ") return;
          e.preventDefault();
          if (!confirming) pick(r.id);
        }}
      >
        <span className={`live-dot ${r.busy || loadingId === r.id ? "busy" : ""}`} />
        <span className="session-main">
          <span className="session-title">{r.title}</span>
          <span className="session-sub">
            {r.live ? "进行中" : "历史"} · {r.sub || "会话"} · {relTime(r.updated)}
          </span>
        </span>
        {onDeleteSession ? (
          confirming ? (
            // 行内二次确认：删会话会连磁盘目录一起删，先点一下再确认
            <span className="row-confirm" onClick={(e) => e.stopPropagation()}>
              <button
                className="row-yes"
                onClick={(e) => {
                  e.stopPropagation();
                  setPendingDelete(null);
                  onDeleteSession(r.id);
                }}
              >
                删除
              </button>
              <button
                className="row-no"
                onClick={(e) => {
                  e.stopPropagation();
                  setPendingDelete(null);
                }}
              >
                取消
              </button>
            </span>
          ) : (
            <button
              className="row-del"
              title="删除会话"
              onClick={(e) => {
                e.stopPropagation();
                setPendingDelete(r.id);
              }}
            >
              <Icon name="close" size={11} />
            </button>
          )
        ) : null}
      </div>
    );
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <button className="new-session" onClick={onNewSession}>
          <Icon name="plus" size={14} />
          <span>新建会话</span>
          <span className="kbd">Ctrl+N</span>
        </button>

        <button
          ref={pickerBtn}
          className={`session-picker ${pickerOpen ? "open" : ""}`}
          onClick={() => (pickerOpen ? closePicker() : openPicker())}
          title="切换会话"
          aria-expanded={pickerOpen}
        >
          <span className={`live-dot ${activeLive?.busy ? "busy" : loadingId === activeId ? "busy" : ""}`} />
          <span className="sp-main">
            <span className="sp-title">{current?.title ?? (activeId ? "载入中…" : "还没有会话")}</span>
            <span className="sp-sub">
              {current ? `${current.sub || "会话"} · ${relTime(current.updated)}` : "点开选择会话"}
            </span>
          </span>
          <span className="sp-badge">{total}</span>
          <Icon name="chevron" size={12} className={`sp-caret ${pickerOpen ? "open" : ""}`} />
        </button>
      </div>

      {pickerOpen && pop ? (
        <div className="session-pop" ref={popRef} style={{ top: pop.top, left: pop.left, width: pop.width }}>
          <div className="session-pop-head">
            <div className="search">
              <Icon name="search" size={13} />
              <input
                autoFocus
                value={query}
                placeholder="搜索会话 / 目录"
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <button className="icon-btn tiny" onClick={onRefresh} title="重新读取会话列表">
              <Icon name="refresh" size={12} />
            </button>
          </div>

          <div className="session-pop-list">
            {rows.liveRows.length > 0 ? (
              <div className="session-group">
                <div className="group-label">
                  <span>进行中</span>
                  <span className="group-count">{rows.liveRows.length}</span>
                </div>
                {rows.liveRows.map(rowNode)}
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
                rows.histRows.map(rowNode)
              )}
            </div>
          </div>

          <div className="session-pop-foot">
            {query ? `匹配 ${total} 个会话` : `共 ${total} 个会话`} · Esc 关闭
          </div>
        </div>
      ) : null}

      <div className="module-nav">
        {MODULE_GROUPS.map((group) => {
          const items = modulesOf(group.id);
          const activeHere = view.kind === "module" && items.some((m) => m.id === view.id);
          const open = openGroups[group.id] || activeHere;
          return (
            <div className={`module-group ${open ? "open" : ""}`} key={group.id}>
              <button
                className={`module-group-head ${activeHere ? "has-active" : ""}`}
                onClick={() => toggleGroup(group.id)}
                title={group.hint}
                aria-expanded={open}
              >
                <Icon name={group.icon} size={13} />
                <span className="mg-label">{group.label}</span>
                <span className="mg-count">{items.length}</span>
                <Icon name="chevron" size={12} className={`mg-chevron ${open ? "open" : ""}`} />
              </button>
              {open ? (
                <div className="module-rows">
                  {items.map((m) => (
                    <button
                      key={m.id}
                      className={`module-row ${view.kind === "module" && view.id === m.id ? "active" : ""}`}
                      onClick={() => onModule(m.id)}
                      title={m.desc}
                    >
                      <Icon name={m.icon} size={13} />
                      <span className="mr-label">{m.label}</span>
                      <span className="mr-short">{m.short}</span>
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
