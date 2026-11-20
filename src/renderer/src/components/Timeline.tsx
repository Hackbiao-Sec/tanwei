import React, { useEffect, useRef, useState } from "react";
import type { PermissionMode, SessionState, TimelineItem, ToolCallView } from "@shared/types";
import { Markdown } from "./Markdown";
import { Icon } from "./Icons";
import { banNotice } from "../lib/attackPlan";

const MODE_LABEL: Record<PermissionMode, string> = {
  ask: "逐项询问",
  auto: "自动审查",
  plan: "规划模式",
  "always-approve": "全部放行",
};

function clock(at: number): string {
  const d = new Date(at);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function duration(call: ToolCallView): string {
  if (!call.endedAt) return "进行中";
  const ms = call.endedAt - call.startedAt;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60000)}m`;
}

function pretty(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

const STATUS_LABEL: Record<string, string> = {
  pending: "等待",
  in_progress: "执行",
  completed: "完成",
  failed: "失败",
  cancelled: "取消",
};

function ToolCard({ call }: { call: ToolCallView }) {
  const [open, setOpen] = useState(call.status === "failed");
  const input = pretty(call.input);
  const output = call.output ?? "";
  const alert = call.status === "completed" ? banNotice(output) : undefined;
  const hasBody = Boolean(input || output || call.locations?.length);

  useEffect(() => {
    if (call.status === "failed") setOpen(true);
  }, [call.status]);

  return (
    <div className={`tool-card tool-${call.status}`}>
      <button className="tool-head" onClick={() => hasBody && setOpen((v) => !v)}>
        <span className={`tool-dot ${call.status}`} />
        <span className="tool-title">{call.title}</span>
        {call.kind ? <span className="chip chip-ghost">{call.kind}</span> : null}
        <span className={`chip chip-status st-${call.status}`}>{STATUS_LABEL[call.status] ?? call.status}</span>
        <span className="tool-dur">{duration(call)}</span>
        {hasBody ? (
          <span className={`tool-chev ${open ? "open" : ""}`}>
            <Icon name="chevron" size={13} />
          </span>
        ) : null}
      </button>
      {alert ? (
        <div className="tool-alert">
          <Icon name="shield" size={12} />
          <span>{alert}</span>
        </div>
      ) : null}
      {open && hasBody ? (
        <div className="tool-body">
          {call.locations?.length ? (
            <div className="tool-locations">
              {call.locations.slice(0, 6).map((l) => (
                <button key={l.path} className="tool-loc" onClick={() => void window.tanwei.reveal(l.path)}>
                  <Icon name="file" size={12} />
                  <span>{l.path}</span>
                </button>
              ))}
            </div>
          ) : null}
          {input ? (
            <div className="tool-block">
              <div className="tool-block-label">输入</div>
              <pre className="tool-pre">{input}</pre>
            </div>
          ) : null}
          {output ? (
            <div className="tool-block">
              <div className="tool-block-label">输出</div>
              <pre className="tool-pre">{output}</pre>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function Thought({ item }: { item: Extract<TimelineItem, { type: "thought" }> }) {
  const [open, setOpen] = useState(false);
  const chars = item.text.length;
  const tail = item.text.trim().split("\n").filter(Boolean).pop() ?? "";
  return (
    <div className={`thought ${item.streaming ? "live" : ""}`}>
      <button className="thought-head" onClick={() => setOpen((v) => !v)}>
        <span className="thought-pulse" />
        <span className="thought-label">{item.streaming ? "推理中" : "推理"}</span>
        <span className="thought-meta">
          {chars} 字 · {clock(item.at)}
        </span>
        <span className="thought-tail">{tail.slice(0, 90)}</span>
        <span className={`tool-chev ${open ? "open" : ""}`}>
          <Icon name="chevron" size={13} />
        </span>
      </button>
      {open ? <div className="thought-body">{item.text}</div> : null}
    </div>
  );
}

function PermissionCard({
  item,
  onRespond,
}: {
  item: Extract<TimelineItem, { type: "permission" }>;
  onRespond: (requestId: number, optionId: string) => void;
}) {
  const resolved = Boolean(item.resolvedOptionId);
  return (
    <div className={`perm-card ${resolved ? "resolved" : ""}`}>
      <div className="perm-head">
        <Icon name="shield" size={15} />
        <span>{item.title}</span>
        <span className="perm-state">{resolved ? "已处理" : "待授权"}</span>
      </div>
      {item.detail ? <pre className="perm-detail">{item.detail}</pre> : null}
      <div className="perm-actions">
        {item.options.map((o) => {
          const chosen = item.resolvedOptionId === o.optionId;
          const kind = (o.kind ?? "").toLowerCase();
          const tone = kind.includes("reject") || kind.includes("deny") ? "deny" : "allow";
          return (
            <button
              key={o.optionId}
              className={`btn perm-btn ${tone} ${chosen ? "chosen" : ""}`}
              disabled={resolved}
              onClick={() => onRespond(item.requestId, o.optionId)}
            >
              {o.name}
            </button>
          );
        })}
        {!resolved ? (
          <button className="btn perm-btn deny" onClick={() => onRespond(item.requestId, "__cancel__")}>
            拒绝并中止
          </button>
        ) : null}
      </div>
    </div>
  );
}

function PlanCard({ entries }: { entries: { content: string; status: string }[] }) {
  const done = entries.filter((e) => e.status === "completed").length;
  return (
    <div className="plan-card">
      <div className="plan-head">
        <Icon name="layers" size={14} />
        <span>行动方案</span>
        <span className="plan-count">
          {done}/{entries.length}
        </span>
      </div>
      <ul className="plan-list">
        {entries.map((e, i) => (
          <li key={`${i}-${e.content}`} className={`plan-item ${e.status}`}>
            <span className="plan-mark" />
            <span>{e.content}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function EmptyState({ mode }: { mode: PermissionMode }) {
  return (
    <div className="empty">
      <div className="empty-radar">
        <Icon name="radar" size={48} strokeWidth={1.1} />
      </div>
      <h2>天鉴·探微 · 安全测试工作台</h2>
      <p>
        从一句目标开始，到一份能交的报告结束：引擎自己拆资产、抽接口、发请求、验证漏洞，过程实时落到资金图谱、
        攻击面、流量、任务与报告面板里，不用在终端和表格之间来回搬。
      </p>
      <div className="empty-grid">
        <div className="empty-tile">
          <span className="empty-k">测试链路</span>
          <span>资产梳理 → 接口发现 → 越权 / 注入 / 逻辑验证 → 报告落盘；命令行、MCP、技能与子代理按需调用。</span>
        </div>
        <div className="empty-tile">
          <span className="empty-k">当前模式</span>
          <span>{MODE_LABEL[mode]}。计划模式先出方案；全部放行不再逐项询问工具。</span>
        </div>
        <div className="empty-tile">
          <span className="empty-k">开局</span>
          <span>直接说目标，或用 / 唤出命令面板，写 /plan、/model、/status。</span>
        </div>
      </div>
    </div>
  );
}

export function Timeline({
  state,
  onRespond,
}: {
  state?: SessionState;
  onRespond: (requestId: number, optionId: string) => void;
}) {
  const boxRef = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  const [atBottom, setAtBottom] = useState(true);

  const items = state?.timeline ?? [];
  let signature = items.length;
  for (const i of items) {
    if (i.type === "assistant" || i.type === "thought" || i.type === "user") signature += i.text.length;
    if (i.type === "tool") signature += (i.call.output?.length ?? 0) + i.call.status.length;
    if (i.type === "permission") signature += i.resolvedOptionId?.length ?? 0;
    if (i.type === "plan") signature += i.entries.length;
  }

  useEffect(() => {
    const el = boxRef.current;
    if (!el || !stick.current) return;
    el.scrollTop = el.scrollHeight;
  }, [signature, state?.id]);

  if (!state) {
    return (
      <div className="timeline empty-wrap">
        <div className="empty">
          <div className="empty-radar">
            <Icon name="radar" size={48} strokeWidth={1.1} />
          </div>
          <h2>未选择会话</h2>
          <p>左侧点击历史会话，或新建一个会话开始。</p>
        </div>
      </div>
    );
  }

  return (
    <div className="timeline-wrap">
      <div
        className="timeline"
        ref={boxRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          const bottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
          stick.current = bottom;
          setAtBottom(bottom);
        }}
      >
        {items.length === 0 ? <EmptyState mode={state.mode} /> : null}
        {items.map((item) => {
          switch (item.type) {
            case "user": {
              const isCmd = item.text.trim().startsWith("/");
              return (
                <div key={item.id} className={`row row-user ${isCmd ? "row-cmd" : ""}`}>
                  <div className="row-gutter">
                    <span className="mono-tag">操作员</span>
                    <span className="row-time">{clock(item.at)}</span>
                  </div>
                  <div className={`user-bubble ${isCmd ? "cmd" : ""}`}>
                    {isCmd ? <span className="cmd-mark">/</span> : null}
                    <span className="user-text">{item.text}</span>
                  </div>
                </div>
              );
            }
            case "assistant":
              return (
                <div key={item.id} className="row row-agent">
                  <div className="row-gutter">
                    <span className="mono-tag agent">GROK</span>
                    <span className="row-time">{clock(item.at)}</span>
                  </div>
                  <div className={`agent-bubble ${item.streaming ? "streaming" : ""}`}>
                    <Markdown text={item.text} />
                    {item.streaming ? <span className="caret" /> : null}
                  </div>
                </div>
              );
            case "thought":
              return <Thought key={item.id} item={item} />;
            case "tool":
              return <ToolCard key={item.id} call={item.call} />;
            case "permission":
              return <PermissionCard key={item.id} item={item} onRespond={onRespond} />;
            case "plan":
              return <PlanCard key={item.id} entries={item.entries} />;
            case "system":
              return (
                <div key={item.id} className={`system-line ${item.level ?? "info"}`}>
                  <span className="system-dot" />
                  <span>{item.text}</span>
                </div>
              );
            default:
              return null;
          }
        })}
      </div>
      {!atBottom && items.length > 0 ? (
        <button
          className="jump-bottom"
          onClick={() => {
            const el = boxRef.current;
            if (!el) return;
            stick.current = true;
            setAtBottom(true);
            el.scrollTop = el.scrollHeight;
          }}
        >
          <Icon name="chevron" size={13} />
          <span>回到底部</span>
        </button>
      ) : null}
    </div>
  );
}

export { MODE_LABEL };
