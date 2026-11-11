import React, { useCallback, useEffect, useMemo, useState } from "react";
import type {
  BootstrapInfo,
  EngineStatus,
  Finding,
  McpServerInfo,
  SessionState,
  SessionSummary,
  WorkspaceStats,
} from "@shared/types";
import type { ModuleId } from "../view";
import { Icon } from "./Icons";

function relTime(input?: number | string): string {
  if (!input) return "";
  const t = typeof input === "number" ? input : Date.parse(input);
  if (!Number.isFinite(t)) return "";
  const diff = Date.now() - t;
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const d = new Date(t);
  return `${d.getMonth() + 1}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

const SEVERITY_CLASS: Record<string, string> = {
  严重: "sev-critical",
  高危: "sev-high",
  中危: "sev-medium",
  低危: "sev-low",
  未知: "sev-unknown",
};

export function Dashboard({
  boot,
  status,
  version,
  mcp,
  live,
  history,
  onOpenSession,
  onCreateSession,
  onModule,
}: {
  boot: BootstrapInfo | null;
  status: EngineStatus;
  version?: string;
  mcp: McpServerInfo[];
  live: SessionState[];
  history: SessionSummary[];
  onOpenSession: (id: string) => void;
  onCreateSession: () => void;
  onModule: (id: ModuleId) => void;
}) {
  const [stats, setStats] = useState<WorkspaceStats>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const [s, f] = await Promise.all([window.tanwei.stats(), window.tanwei.findings()]);
      setStats(s);
      setFindings(f);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const sessions = useMemo(() => {
    const liveRows = live.map((s) => ({
      id: s.id,
      title: s.title || "新会话",
      sub: s.busy ? "回合进行中" : "空闲",
      at: s.updatedAt,
    }));
    const liveIds = new Set(live.map((s) => s.id));
    const histRows = history
      .filter((h) => !liveIds.has(h.id))
      .slice(0, 6)
      .map((h) => ({
        id: h.id,
        title: h.title || h.id.slice(0, 8),
        sub: "历史",
        at: h.updated ? Date.parse(h.updated) : 0,
      }));
    return [...liveRows.slice(0, 4), ...histRows].slice(0, 7);
  }, [live, history]);

  const readyCount = mcp.filter((m) => m.status !== "failed" && m.status !== "disabled").length;
  const busy = live.filter((s) => s.busy).length;
  const totalFindings = stats ? stats.reports : 0;
  const tokenTotal = live.reduce((sum, s) => sum + (s.usage?.totalTokens ?? 0), 0);
  const tokenText = tokenTotal >= 1_000_000 ? `${(tokenTotal / 1_000_000).toFixed(1)}M` : tokenTotal.toLocaleString("en-US");

  return (
    <div className="dash">
      <div className="dash-head">
        <div>
          <h2>总览</h2>
          <p>系统全局状态 · 实时刷新</p>
        </div>
        <div className="dash-actions">
          <button className="btn ghost" onClick={() => void load()}>
            <Icon name="refresh" size={13} />
            <span>{loading ? "读取中…" : "刷新"}</span>
          </button>
          <button className="btn primary" onClick={onCreateSession}>
            <Icon name="plus" size={13} />
            <span>新建任务</span>
          </button>
        </div>
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      <div className="metric-row">
        <div className="metric">
          <div className="metric-label">活跃会话</div>
          <div className="metric-value">{live.length}</div>
          <div className="metric-foot">{busy > 0 ? `${busy} 个回合进行中` : "全部空闲"}</div>
        </div>
        <div className="metric">
          <div className="metric-label">确认发现</div>
          <div className="metric-value">{totalFindings}</div>
          <div className="metric-foot metric-chips">
            <span className="mini sev-critical">严重 {stats?.findings.severe ?? 0}</span>
            <span className="mini sev-high">高危 {stats?.findings.high ?? 0}</span>
            <span className="mini sev-medium">中危 {stats?.findings.medium ?? 0}</span>
            <span className="mini sev-low">低危 {stats?.findings.low ?? 0}</span>
          </div>
        </div>
        <div className="metric">
          <div className="metric-label">资产条目</div>
          <div className="metric-value">{stats?.assetEntries ?? 0}</div>
          <div className="metric-foot">{stats?.assets ?? 0} 个资产文件 · {stats?.tasks ?? 0} 个任务</div>
        </div>
        <div className="metric">
          <div className="metric-label">MCP 服务</div>
          <div className="metric-value">
            {readyCount}
            <span className="metric-sub">/{mcp.length}</span>
          </div>
          <div className="metric-foot">{mcp.length ? "就绪 / 已配置" : "未配置 MCP"}</div>
        </div>
        <div className="metric">
          <div className="metric-label">Token 用量</div>
          <div className="metric-value">{tokenText}</div>
          <div className="metric-foot">本次运行的会话累计</div>
        </div>
        <div className="metric">
          <div className="metric-label">引擎</div>
          <div className="metric-value metric-engine">{status === "ready" ? "就绪" : status === "starting" ? "启动中" : status === "error" ? "异常" : "停止"}</div>
          <div className="metric-foot">
            {version ? `grok ${version}` : "等待版本"} · {boot?.permissionMode ?? "ask"}
          </div>
        </div>
      </div>

      <div className="dash-cols">
        <section className="panel">
          <header className="panel-head">
            <span>
              <Icon name="shield" size={14} />
              最新发现
            </span>
            <button className="panel-link" onClick={() => onModule("findings")}>
              全部 <Icon name="chevron" size={12} />
            </button>
          </header>
          <div className="panel-body">
            {findings.length === 0 ? (
              <div className="panel-empty">还没有正式报告。挖到洞后用报告格式落盘，这里会自动汇总。</div>
            ) : (
              findings.slice(0, 7).map((f) => (
                <button className="activity-row" key={f.path} onClick={() => void window.tanwei.openPath(f.path)}>
                  <span className={`sev ${SEVERITY_CLASS[f.severity]}`}>{f.severity}</span>
                  <span className="activity-main">
                    <span className="activity-title">{f.title}</span>
                    <span className="activity-sub">
                      {f.target || f.task} · {relTime(f.updatedAt)}
                    </span>
                  </span>
                  <Icon name="external" size={12} />
                </button>
              ))
            )}
          </div>
        </section>

        <section className="panel">
          <header className="panel-head">
            <span>
              <Icon name="chat" size={14} />
              最近会话
            </span>
            <button className="panel-link" onClick={() => onModule("tasks")}>
              任务 <Icon name="chevron" size={12} />
            </button>
          </header>
          <div className="panel-body">
            {sessions.length === 0 ? (
              <div className="panel-empty">还没有会话。</div>
            ) : (
              sessions.map((s) => (
                <button className="activity-row" key={s.id} onClick={() => onOpenSession(s.id)}>
                  <span className={`live-dot ${s.sub === "回合进行中" ? "busy" : ""}`} />
                  <span className="activity-main">
                    <span className="activity-title">{s.title}</span>
                    <span className="activity-sub">
                      {s.sub} · {relTime(s.at)}
                    </span>
                  </span>
                  <Icon name="chevron" size={12} />
                </button>
              ))
            )}
          </div>
        </section>
      </div>

      <section className="panel">
        <header className="panel-head">
          <span>
            <Icon name="bolt" size={14} />
            快捷入口
          </span>
        </header>
        <div className="quick-row">
          <button className="quick" onClick={() => onModule("graph")}>
            <Icon name="radar" size={15} />
            <span>攻击面图谱</span>
            <em>任务 · 主机 · 漏洞</em>
          </button>
          <button className="quick" onClick={() => onModule("traffic")}>
            <Icon name="send" size={15} />
            <span>请求重放</span>
            <em>手工验证接口</em>
          </button>
          <button className="quick" onClick={() => onModule("assets")}>
            <Icon name="folder" size={15} />
            <span>资产清单</span>
            <em>任务夹里的可挖面</em>
          </button>
          <button className="quick" onClick={() => boot && void window.tanwei.openPath(boot.grokHome)}>
            <Icon name="settings" size={15} />
            <span>打开 .grok</span>
            <em>配置、技能、会话</em>
          </button>
          <button className="quick" onClick={() => void window.tanwei.launchTui(boot?.cwd)}>
            <Icon name="terminal" size={15} />
            <span>原生 TUI</span>
            <em>纯终端形态</em>
          </button>
        </div>
      </section>
    </div>
  );
}
