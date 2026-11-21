import React, { useEffect, useMemo, useRef, useState } from "react";
import type { ReportEntry } from "@shared/types";
import { Icon } from "./Icons";
import { ScopeSwitch } from "./ScopeSwitch";
import { useSessionScope } from "../lib/sessionScope";

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

const fmtSize = (n: number) => {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
};

const fmtTime = (ts: number) => {
  if (!ts) return "—";
  const d = new Date(ts);
  const pad = (v: number) => String(v).padStart(2, "0");
  return `${d.getMonth() + 1}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

/**
 * 报告模块：本会话只列这个会话认领任务夹里的正式报告，总览才是整张桌面。
 * 本会话档位不回落总览，空就是空，并指向「归属」让人自己把任务夹勾过来。
 */
export function Reports() {
  const ctx = useSessionScope();
  const [all, setAll] = useState<ReportEntry[]>([]);
  const [allBusy, setAllBusy] = useState(false);
  const [allLoaded, setAllLoaded] = useState(false);
  const allSeq = useRef(0);
  const allAt = useRef(0);
  const [scope, setScope] = useState<"session" | "all">("session");
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    // 总览要扫整张桌面的报告夹，本会话档位用的是会话快照；切到总览才扫
    if (scope !== "all") return;
    if (allLoaded && Date.now() - allAt.current < 15_000) return;
    const mine = ++allSeq.current;
    setAllBusy(true);
    void window.tanwei
      .reports()
      .then((next) => {
        if (mine !== allSeq.current) return;
        setAll(next);
        setAllLoaded(true);
        allAt.current = Date.now();
      })
      .catch((err) => {
        if (mine === allSeq.current) setError(errText(err));
      })
      .finally(() => {
        if (mine === allSeq.current) setAllBusy(false);
      });
  }, [scope, allLoaded, ctx.version]);

  const load = () => {
    ctx.refresh();
    setAllBusy(true);
    void window.tanwei
      .reports()
      .then((next) => {
        setAll(next);
        setAllLoaded(true);
        allAt.current = Date.now();
      })
      .catch((err) => setError(errText(err)))
      .finally(() => setAllBusy(false));
  };

  const list = scope === "session" ? ctx.reports : all;
  const loading = ctx.loading || allBusy;

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return list;
    return list.filter((r) => `${r.title} ${r.task} ${r.path}`.toLowerCase().includes(q));
  }, [list, query]);

  const taskCount = useMemo(() => new Set(list.map((r) => r.task)).size, [list]);
  const latest = useMemo(() => list.reduce((acc, r) => Math.max(acc, r.updatedAt), 0), [list]);

  return (
    <div className="files-page">
      <div className="metric-row metric-row-sm">
        <div className="metric">
          <div className="metric-label">正式报告</div>
          <div className="metric-value">{list.length}</div>
          <div className="metric-foot">{scope === "session" ? "本会话认领的" : "桌面上全部"}</div>
        </div>
        <div className="metric">
          <div className="metric-label">涉及任务夹</div>
          <div className="metric-value">{taskCount}</div>
          <div className="metric-foot">按任务夹归拢</div>
        </div>
        <div className="metric">
          <div className="metric-label">最近更新</div>
          <div className="metric-value">{latest ? fmtTime(latest) : "—"}</div>
          <div className="metric-foot">报告落盘时间</div>
        </div>
        <div className="metric">
          <div className="metric-label">筛选后</div>
          <div className="metric-value">{shown.length}</div>
          <div className="metric-foot">标题 / 任务夹 / 路径</div>
        </div>
      </div>

      <div className="files-toolbar">
        <div className="search find-search">
          <Icon name="search" size={13} />
          <input
            value={query}
            placeholder="搜报告标题、任务夹或路径"
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <ScopeSwitch
          scope={scope}
          onScope={setScope}
          total={allLoaded ? all.length : undefined}
          scoped={ctx.reports.length}
          totalLabel="总览"
          sessionLabel="本会话"
        />
        <button className="btn ghost sm" onClick={load} disabled={loading}>
          <Icon name="refresh" size={12} />
          <span>{loading ? "读取中…" : "刷新"}</span>
        </button>
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      <div className="table">
        <div className="table-head">
          <span>报告标题</span>
          <span>任务</span>
          <span>大小</span>
          <span>更新时间</span>
        </div>
        {shown.length === 0 ? (
          <div className="module-empty">
            {scope === "session"
              ? "本会话还没认领任务夹，因此没有报告。点工具栏「归属」把任务夹勾给它；看全桌面点「总览」。"
              : query
                ? "没有匹配的报告。"
                : "桌面上还没有正式报告。"}
          </div>
        ) : (
          shown.map((r) => (
            <button className="table-row" key={r.path} onClick={() => void window.tanwei.openPath(r.path)}>
              <span className="table-title">{r.title}</span>
              <span className="chip chip-ghost">{r.task}</span>
              <span className="mono subtle">{fmtSize(r.size)}</span>
              <span className="mono subtle">{fmtTime(r.updatedAt)}</span>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
