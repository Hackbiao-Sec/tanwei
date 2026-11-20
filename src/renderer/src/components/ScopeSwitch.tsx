import React, { useState } from "react";
import type { SessionScopeSnapshot } from "@shared/types";
import { Icon } from "./Icons";
import { useSessionScope } from "../lib/sessionScope";

/**
 * 「本会话 / 总览」切换：本会话只认这个会话碰过的任务夹，总览才是全桌面。
 * 两个档位都点得开；本会话没任务夹时就展示空态，避免看起来像自动切到了全局。
 * 归属可以手动改：任务夹是引擎在运行中建的，自动认领可能慢半拍，这里给人一个确认入口。
 */
export function ScopeSwitch({
  scope,
  onScope,
  totalLabel,
  sessionLabel,
  total,
  scoped,
  tasks: tasksProp,
}: {
  scope: "session" | "all";
  onScope: (scope: "session" | "all") => void;
  totalLabel?: string;
  sessionLabel?: string;
  total?: number;
  scoped?: number;
  /** 面板自己算过的任务夹；不传就用会话的权威归属 */
  tasks?: string[];
}) {
  const ctx = useSessionScope();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string>();
  const tasks = tasksProp ?? ctx.tasks;
  const hasTasks = tasks.length > 0;

  const toggle = async (task: string) => {
    if (!ctx.sessionId) return;
    setBusy(task);
    try {
      if (tasks.includes(task)) await ctx.unbind(task);
      else await ctx.bind(task);
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <div className="scope-wrap">
      <div className="scope-switch" title={hasTasks ? tasks.join("、") : "本会话还没落到任何任务夹"}>
        <div className="seg">
          <button className={`seg-btn ${scope === "session" ? "on" : ""}`} onClick={() => onScope("session")}>
            {sessionLabel ?? "本会话"}
            {scope === "session" && typeof scoped === "number" ? ` · ${scoped}` : ""}
          </button>
          <button className={`seg-btn ${scope === "all" ? "on" : ""}`} onClick={() => onScope("all")}>
            {totalLabel ?? "总览"}
            {scope === "all" && typeof total === "number" ? ` · ${total}` : ""}
          </button>
        </div>
        <span className="scope-tasks mono">{hasTasks ? tasks.join(" / ") : "本会话暂无任务夹"}</span>
        <button
          className={`scope-bind ${open ? "on" : ""}`}
          onClick={() => setOpen((v) => !v)}
          disabled={!ctx.sessionId}
          title={ctx.sessionId ? "把桌面任务夹指定给这个会话" : "先选一个会话"}
        >
          <Icon name="node" size={12} />
          <span>归属</span>
        </button>
        <button className="scope-refresh" onClick={() => ctx.refresh()} title="重新读取本会话产物">
          <Icon name="refresh" size={12} />
        </button>
      </div>

      {open ? <BindMenu snapshot={ctx} own={tasks} busy={busy} onToggle={toggle} onClose={() => setOpen(false)} /> : null}
    </div>
  );
}

function BindMenu({
  snapshot,
  own,
  busy,
  onToggle,
  onClose,
}: {
  snapshot: SessionScopeSnapshot & { sessionId?: string };
  own: string[];
  busy?: string;
  onToggle: (task: string) => void;
  onClose: () => void;
}) {
  const rows = snapshot.available.length
    ? snapshot.available
    : snapshot.orphans.length
      ? snapshot.orphans
      : [];
  return (
    <div className="scope-bind-menu">
      <div className="scope-bind-head">
        <span>任务夹归属</span>
        <button className="scope-bind-close" onClick={onClose} title="收起">
          ×
        </button>
      </div>
      <p className="scope-bind-hint">
        勾上 = 这个任务夹算在本会话名下，发现 / 资产 / 文件 / 报告只展示勾中的。运行中新建的任务夹一般会自动认领，没认上就在这里补。
      </p>
      <div className="scope-bind-list">
        {rows.length === 0 ? <div className="scope-bind-empty">桌面上还没有任务夹。</div> : null}
        {rows.map((task) => {
          const checked = own.includes(task);
          const others = (snapshot.owners[task] ?? []).filter((id) => id !== snapshot.sessionId);
          return (
            <button
              key={task}
              className={`scope-bind-row ${checked ? "on" : ""}`}
              onClick={() => onToggle(task)}
              disabled={!snapshot.sessionId || busy === task}
            >
              <span className={`scope-bind-box ${checked ? "on" : ""}`}>{checked ? "✓" : ""}</span>
              <span className="scope-bind-name">{task}</span>
              {others.length ? <span className="scope-bind-tag">另有 {others.length} 个会话</span> : null}
              {!checked && !others.length ? <span className="scope-bind-tag ghost">未归属</span> : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}
