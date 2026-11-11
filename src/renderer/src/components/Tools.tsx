import React, { useMemo, useState } from "react";
import type { CommandInfo, McpServerInfo } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";

const SOURCE_LABEL: Record<string, string> = {
  builtin: "内置",
  skill: "技能",
  workflow: "工作流",
  mcp: "MCP",
};

export function Tools({ commands, mcp }: { commands: CommandInfo[]; mcp: McpServerInfo[] }) {
  const [query, setQuery] = useState("");
  const [source, setSource] = useState<"全部" | string>("全部");
  const [copied, setCopied] = useState<string>();

  const sources = useMemo(() => {
    const set = new Set(commands.map((c) => c.source ?? "builtin"));
    return ["全部", ...[...set].sort()];
  }, [commands]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return commands.filter((c) => {
      if (source !== "全部" && (c.source ?? "builtin") !== source) return false;
      if (!q) return true;
      return c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q);
    });
  }, [commands, query, source]);

  const copy = (name: string) => {
    void copyText(name)
      .then(() => {
        setCopied(name);
        window.setTimeout(() => setCopied(undefined), 1200);
      })
      .catch(() => undefined);
  };

  const mcpTools = mcp.reduce((sum, s) => sum + (s.tools ?? 0), 0);
  const readyMcp = mcp.filter((s) => s.status !== "failed" && s.status !== "disabled");

  return (
    <div className="tools-page">
      <div className="tools-metrics">
        <div className="metric metric-sm">
          <div className="metric-label">可用命令</div>
          <div className="metric-value">{commands.length}</div>
          <div className="metric-foot">会话输入框里以 / 触发</div>
        </div>
        <div className="metric metric-sm">
          <div className="metric-label">MCP 工具</div>
          <div className="metric-value">{mcpTools}</div>
          <div className="metric-foot">
            {readyMcp.length}/{mcp.length} 个服务就绪
          </div>
        </div>
        <div className="metric metric-sm">
          <div className="metric-label">技能 / 工作流</div>
          <div className="metric-value">
            {commands.filter((c) => c.source === "skill").length}
            <span className="metric-sub">/{commands.filter((c) => c.source === "workflow").length}</span>
          </div>
          <div className="metric-foot">技能命令 / 工作流命令</div>
        </div>
      </div>

      <div className="find-toolbar">
        <label className="search tools-search">
          <Icon name="search" size={13} />
          <input value={query} placeholder="搜索命令 / 说明" onChange={(e) => setQuery(e.target.value)} />
        </label>
        <div className="seg">
          {sources.map((s) => (
            <button key={s} className={`seg-btn ${source === s ? "on" : ""}`} onClick={() => setSource(s)}>
              {s === "全部" ? "全部" : (SOURCE_LABEL[s] ?? s)}
            </button>
          ))}
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="module-empty">引擎还没上报命令。等引擎就绪后点刷新，或直接在会话里输入 / 查看。</div>
      ) : (
        <div className="table tools-table">
          <div className="table-head">
            <span>命令</span>
            <span>来源</span>
            <span>说明</span>
            <span>操作</span>
          </div>
          {rows.map((c) => (
            <div className="table-row" key={`${c.name}-${c.source ?? ""}`}>
              <span className="table-title mono">/{c.name}</span>
              <span className="chip chip-ghost">{SOURCE_LABEL[c.source ?? "builtin"] ?? c.source}</span>
              <span className="tools-desc">
                <span className="tools-text">{c.description}</span>
                {c.hint ? <em className="tools-hint">{c.hint}</em> : null}
              </span>
              <span className="tools-ops">
                <button className="mini-btn" onClick={() => copy(`/${c.name}`)} title="复制命令">
                  <Icon name={copied === `/${c.name}` ? "check" : "copy"} size={12} />
                </button>
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
