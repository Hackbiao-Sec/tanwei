import React, { useCallback, useEffect, useMemo, useState } from "react";
import type { AssetItem } from "@shared/types";
import { Icon } from "./Icons";
import { FileViewer, type PreviewTarget } from "./FileViewer";
import { ScopeSwitch } from "./ScopeSwitch";

function fmtTime(t: number): string {
  if (!t) return "—";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Assets({
  onAsk,
  sessionTasks = [],
  activeId,
}: {
  onAsk: (prompt: string) => void;
  sessionTasks?: string[];
  activeId?: string;
}) {
  // 本会话只读这个会话碰过的任务夹的 资产/；总览才是整个桌面
  const [sessionList, setSessionList] = useState<AssetItem[]>([]);
  const [globalList, setGlobalList] = useState<AssetItem[]>([]);
  const [resolvedTasks, setResolvedTasks] = useState<string[]>([]);
  const [scope, setScope] = useState<"session" | "all">("session");
  const [query, setQuery] = useState("");
  const [taskFilter, setTaskFilter] = useState("全部");
  const [preview, setPreview] = useState<PreviewTarget | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const knownKey = sessionTasks.join("|");

  const load = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const known = knownKey ? knownKey.split("|") : [];
      const [own, all] = await Promise.all([
        window.tanwei.sessionArtifacts(activeId, known),
        window.tanwei.assetItems(),
      ]);
      setSessionList(own.assets);
      setResolvedTasks(own.tasks);
      setGlobalList(all);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [activeId, knownKey]);

  useEffect(() => {
    void load();
  }, [load]);

  const scoped = scope === "session" ? sessionList : globalList;
  const taskNames = useMemo(() => [...new Set(scoped.map((i) => i.task))], [scoped]);

  useEffect(() => {
    if (taskFilter !== "全部" && !taskNames.includes(taskFilter)) setTaskFilter("全部");
  }, [taskNames, taskFilter]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scoped.filter((i) => {
      if (taskFilter !== "全部" && i.task !== taskFilter) return false;
      if (!q) return true;
      return (
        i.name.toLowerCase().includes(q) ||
        i.task.toLowerCase().includes(q) ||
        i.sample.some((s) => s.toLowerCase().includes(q))
      );
    });
  }, [scoped, query, taskFilter]);

  const totalEntries = scoped.reduce((sum, i) => sum + i.lines, 0);

  return (
    <div className="assets">
      <div className="metric-row metric-row-sm">
        <div className="metric">
          <div className="metric-label">{scope === "session" ? "本会话任务" : "任务"}</div>
          <div className="metric-value">{scope === "session" ? resolvedTasks.length : taskNames.length}</div>
          <div className="metric-foot">
            {scope === "session" ? "只有这些任务夹的资产算本会话" : "总览：桌面里全部 SRC 任务夹"}
          </div>
        </div>
        <div className="metric">
          <div className="metric-label">资产文件</div>
          <div className="metric-value">{scoped.length}</div>
          <div className="metric-foot">资产 / 目录下的清单</div>
        </div>
        <div className="metric">
          <div className="metric-label">条目</div>
          <div className="metric-value">{totalEntries}</div>
          <div className="metric-foot">域名 / URL / 种子行数</div>
        </div>
      </div>

      <div className="find-toolbar">
        <div className="search find-search">
          <Icon name="search" size={13} />
          <input value={query} placeholder="搜索文件名 / 任务 / 域名" onChange={(e) => setQuery(e.target.value)} />
        </div>
        <div className="seg">
          {["全部", ...taskNames.slice(0, 4)].map((t) => (
            <button key={t} className={`seg-btn ${taskFilter === t ? "on" : ""}`} onClick={() => setTaskFilter(t)}>
              {t}
            </button>
          ))}
        </div>
        <ScopeSwitch
          tasks={resolvedTasks}
          scope={scope}
          onScope={setScope}
          total={globalList.length}
          scoped={sessionList.length}
        />
        <button className="btn ghost" onClick={() => void load()}>
          <Icon name="refresh" size={13} />
          <span>{loading ? "读取中…" : "刷新"}</span>
        </button>
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      <div className="table asset-table">
        <div className="table-head">
          <span>文件</span>
          <span>任务</span>
          <span>条目</span>
          <span>样例</span>
          <span>更新</span>
          <span>操作</span>
        </div>
        {rows.length === 0 ? (
          <div className="module-empty">
            {scope === "session"
              ? resolvedTasks.length === 0
                ? "这个会话还没碰过任务夹。这里的资产只认本会话任务；看别的会话点上面「总览」。"
                : "本会话任务里还没有 `资产/` 清单；看别的会话点上面「总览」。"
              : "桌面还没有 `*_SRC挖洞` 任务夹，或任务夹里没有 `资产/`。"}
          </div>
        ) : (
          rows.map((a) => (
            <div className="table-row asset-row" key={a.path}>
              <button
                className="table-title mono asset-open"
                title={`预览 ${a.path}`}
                onClick={() => setPreview({ path: a.path, name: a.name, size: a.size })}
              >
                <Icon name="file" size={12} />
                {a.name}
              </button>
              <span className="chip chip-ghost">{a.task}</span>
              <span className="mono subtle">{a.lines}</span>
              <span className="mono subtle asset-sample" title={a.sample.join("\n")}>
                {a.sample[0] || "—"}
              </span>
              <span className="mono subtle">{fmtTime(a.updatedAt)}</span>
              <span className="asset-actions">
                <button className="mini-btn" onClick={() => void window.tanwei.openPath(a.path)} title="打开文件">
                  <Icon name="external" size={12} />
                </button>
                <button
                  className="mini-btn"
                  title="让 AI 以这份资产为范围继续"
                  onClick={() =>
                    onAsk(
                      `以这份资产清单为范围继续挖，先读文件再选目标：\n${a.path}\n\n任务：${a.task}\n按规则先清洗去重、去废、去非存活，再从高价值面开始；打到就落报告。`,
                    )
                  }
                >
                  <Icon name="bolt" size={12} />
                </button>
              </span>
            </div>
          ))
        )}
      </div>

      <FileViewer file={preview} onClose={() => setPreview(null)} />
    </div>
  );
}
