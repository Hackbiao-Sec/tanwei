import React from "react";
import type { EngineStatus, McpServerInfo, SessionState, TimelineItem, ToolCallView } from "@shared/types";
import { usedTokens } from "@shared/usage";
import { Icon } from "./Icons";

function tokens(n?: number): string {
  const v = n ?? 0;
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)}M`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return String(v);
}

function statusTone(status: string): string {
  if (status === "ready" || status === "configured" || status === "completed") return "ok";
  if (status === "failed" || status === "error") return "bad";
  if (status === "needs-auth") return "warn";
  if (status === "in_progress" || status === "pending") return "run";
  return "idle";
}

function RailSection({
  title,
  icon,
  extra,
  children,
}: {
  title: string;
  icon: React.ComponentProps<typeof Icon>["name"];
  extra?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rail-section">
      <div className="rail-head">
        <Icon name={icon} size={13} />
        <span>{title}</span>
        {extra ? <span className="rail-extra">{extra}</span> : null}
      </div>
      {children}
    </section>
  );
}

export function RightRail({
  state,
  mcp,
  status,
  version,
  onRefreshMcp,
}: {
  state?: SessionState;
  mcp: McpServerInfo[];
  status: EngineStatus;
  version?: string;
  onRefreshMcp?: () => void;
}) {
  const tools: Extract<TimelineItem, { type: "tool" }>[] = (state?.timeline ?? []).filter(
    (i): i is Extract<TimelineItem, { type: "tool" }> => i.type === "tool",
  );
  const recent = tools.slice(-7).reverse();
  const usage = state?.usage;
  const ctx = state?.contextWindow ?? 0;
  // 占窗口的是「这一轮发出去的那整段提示」：输入 + 缓存读 + 缓存写。
  // 引擎只在回合结束才回整包用量，光看 prompt 侧会一直不动；总用量含流式估算，取大者让计数跟着走。
  const used = usedTokens(usage);
  const ratio = ctx > 0 ? Math.min(1, used / ctx) : 0;
  const pct = ctx > 0 ? Math.round(ratio * 100) : 0;
  const compactAt = state?.compactAt ?? 85;
  const nearLimit = ctx > 0 && pct >= Math.max(1, compactAt - 10);
  const free = ctx > 0 ? Math.max(0, ctx - used) : 0;
  const ready = mcp.filter((m) => statusTone(m.status) === "ok").length;

  return (
    <aside className="rail">
      <RailSection
        title="行动方案"
        icon="layers"
        extra={state?.plan.length ? `${state.plan.filter((p) => p.status === "completed").length}/${state.plan.length}` : undefined}
      >
        {state?.plan.length ? (
          <ul className="rail-plan">
            {state.plan.map((p, i) => (
              <li key={`${i}-${p.content}`} className={`rail-plan-item ${p.status}`}>
                <span className="plan-mark" />
                <span>{p.content}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="rail-empty">暂无计划。用 /plan 进入规划模式。</div>
        )}
      </RailSection>

      <RailSection title="上下文与用量" icon="cpu" extra={ctx ? `${pct}%` : undefined}>
        <div className="ctx-bar">
          <div
            className={`ctx-fill ${nearLimit ? "hot" : ""}`}
            style={{ width: `${Math.max(ratio * 100, used ? 1.5 : 0)}%` }}
          />
        </div>
        <div className={`ctx-note ${pct >= compactAt ? "hot" : nearLimit ? "warn" : ""}`}>
          {ctx === 0
            ? "窗口大小未知：在「模型」里给这档模型填 context_window，百分比才准。"
            : pct >= compactAt
              ? `已到 ${compactAt}% 压缩线，下一轮引擎会先压缩历史再继续。`
              : `到 ${compactAt}% 引擎自动压缩：把早期内容收成摘要，最近对话和规则保留。`}
        </div>
        {state?.usageEstimated ? (
          <div className="ctx-est">输出按字符实时估算，回合结束用引擎回包校准</div>
        ) : null}
        <div className="metric-grid">
          <div className="metric">
            <span className="metric-k">已用</span>
            <span className="metric-v">
              {tokens(used)}
              {state?.usageEstimated ? <span className="metric-est">估</span> : null}
            </span>
          </div>
          <div className="metric">
            <span className="metric-k">窗口</span>
            <span className="metric-v">{ctx ? tokens(ctx) : "—"}</span>
          </div>
          <div className="metric">
            <span className="metric-k">剩余</span>
            <span className="metric-v">{ctx ? tokens(free) : "—"}</span>
          </div>
          <div className="metric">
            <span className="metric-k">输入</span>
            <span className="metric-v">{tokens(usage?.inputTokens)}</span>
          </div>
          <div className="metric">
            <span className="metric-k">输出</span>
            <span className="metric-v">{tokens(usage?.outputTokens)}</span>
          </div>
          <div className="metric">
            <span className="metric-k">缓存读</span>
            <span className="metric-v">{tokens(usage?.cacheReadTokens)}</span>
          </div>
          <div className="metric">
            <span className="metric-k">缓存写</span>
            <span className="metric-v">{tokens(usage?.cacheWriteTokens)}</span>
          </div>
          <div className="metric">
            <span className="metric-k">推理</span>
            <span className="metric-v">{tokens(usage?.reasoningTokens)}</span>
          </div>
        </div>
      </RailSection>

      <RailSection title="工具流" icon="bolt" extra={tools.length ? `${tools.length} 次` : undefined}>
        {recent.length ? (
          <ul className="tool-flow">
            {recent.map((t) => (
              <li key={t.id} className="tool-flow-row">
                <span className={`flow-dot ${statusTone(t.call.status)}`} />
                <span className="flow-title" title={t.call.title}>
                  {t.call.title}
                </span>
                <span className="flow-time">
                  {t.call.endedAt ? `${Math.max(1, Math.round((t.call.endedAt - t.call.startedAt) / 1000))}s` : "…"}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="rail-empty">本会话还没有工具调用。</div>
        )}
      </RailSection>

      <RailSection
        title="MCP"
        icon="plug"
        extra={
          <button className="rail-link" onClick={onRefreshMcp} title="刷新 MCP 配置">
            {ready}/{mcp.length || 0}
          </button>
        }
      >
        {mcp.length ? (
          <ul className="mcp-list">
            {mcp.slice(0, 8).map((m) => (
              <li key={m.name} className="mcp-row">
                <span className={`flow-dot ${statusTone(m.status)}`} />
                <span className="mcp-name">{m.name}</span>
                <span className="mcp-state">{m.status}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="rail-empty">未读取到 MCP 配置。</div>
        )}
      </RailSection>

      <RailSection title="会话" icon="terminal">
        <div className="kv">
          <span className="kv-k">引擎</span>
          <span className={`kv-v ${status === "ready" ? "ok" : status === "error" ? "bad" : ""}`}>
            {status === "ready" ? `就绪 ${version ?? ""}` : status}
          </span>
        </div>
        <div className="kv">
          <span className="kv-k">会话 ID</span>
          <button
            className="kv-v mono kv-copy"
            title="复制会话 ID"
            onClick={() => state && void navigator.clipboard.writeText(state.id)}
          >
            {state ? state.id.slice(0, 8) : "—"}
            <Icon name="copy" size={11} />
          </button>
        </div>
        <div className="kv">
          <span className="kv-k">目录</span>
          <button className="kv-v kv-copy" title={state?.cwd} onClick={() => state && void window.tanwei.openPath(state.cwd)}>
            {state?.cwd ? state.cwd.split(/[\\/]/).filter(Boolean).pop() : "—"}
          </button>
        </div>
        <div className="kv">
          <span className="kv-k">模型</span>
          <span className="kv-v mono">{state?.model ?? "默认"}</span>
        </div>
        <div className="kv">
          <span className="kv-k">状态</span>
          <span className="kv-v">{state ? (state.busy ? "回合进行中" : state.resumed ? "已载入历史" : "空闲") : "无会话"}</span>
        </div>
        {state?.pendingPermissions ? (
          <div className="kv">
            <span className="kv-k">待授权</span>
            <span className="kv-v warn">{state.pendingPermissions}</span>
          </div>
        ) : null}
      </RailSection>
    </aside>
  );
}
