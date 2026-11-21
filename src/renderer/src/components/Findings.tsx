import React, { useEffect, useMemo, useRef, useState } from "react";
import type { Finding, FindingSeverity } from "@shared/types";
import { Icon } from "./Icons";
import { Markdown } from "./Markdown";
import { ScopeSwitch } from "./ScopeSwitch";
import { copyText } from "../lib/clipboard";
import { useSessionScope } from "../lib/sessionScope";

const SEVERITIES: FindingSeverity[] = ["严重", "高危", "中危", "低危", "未知"];

const SEVERITY_CLASS: Record<string, string> = {
  严重: "sev-critical",
  高危: "sev-high",
  中危: "sev-medium",
  低危: "sev-low",
  未知: "sev-unknown",
};

function fmtTime(t: number): string {
  if (!t) return "—";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Findings({ onAsk }: { onAsk: (prompt: string) => void }) {
  // 本会话 = 只读这个会话认领的任务夹；总览 = 全桌面。两份数据分开放，不互相顶替
  const ctx = useSessionScope();
  const [globalList, setGlobalList] = useState<Finding[]>([]);
  const [globalLoaded, setGlobalLoaded] = useState(false);
  const globalSeq = useRef(0);
  const globalAt = useRef(0);
  const [scope, setScope] = useState<"session" | "all">("session");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"全部" | FindingSeverity>("全部");
  const [selected, setSelected] = useState<Finding>();
  const [content, setContent] = useState("");
  const [previewLoading, setPreviewLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const sessionList = ctx.findings;
  const resolvedTasks = ctx.tasks;
  const loading = ctx.loading;
  const error = ctx.error;

  // 总览要把桌面所有报告正文读一遍，只在切到总览时才拉，15 秒内复用
  useEffect(() => {
    if (scope !== "all") return;
    if (globalLoaded && Date.now() - globalAt.current < 15_000) return;
    const mine = ++globalSeq.current;
    void window.tanwei
      .findings()
      .then((all) => {
        if (mine !== globalSeq.current) return;
        setGlobalList(all);
        setGlobalLoaded(true);
        globalAt.current = Date.now();
      })
      .catch(() => undefined);
  }, [scope, globalLoaded, ctx.version]);

  const scoped = scope === "session" ? sessionList : globalList;

  useEffect(() => {
    if (!selected) {
      setContent("");
      return;
    }
    let cancelled = false;
    setPreviewLoading(true);
    void window.tanwei
      .readTaskFile(selected.path)
      .then((text) => {
        if (!cancelled) setContent(text);
      })
      .catch((err) => {
        if (!cancelled) setContent(`读取失败：${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => {
        if (!cancelled) setPreviewLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  useEffect(() => {
    setSelected((prev) => {
      if (prev && scoped.some((f) => f.path === prev.path)) return prev;
      return scoped[0];
    });
  }, [scoped]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { 严重: 0, 高危: 0, 中危: 0, 低危: 0, 未知: 0 };
    for (const f of scoped) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [scoped]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scoped.filter((f) => {
      if (severity !== "全部" && f.severity !== severity) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.task.toLowerCase().includes(q) ||
        (f.target ?? "").toLowerCase().includes(q) ||
        f.type.toLowerCase().includes(q)
      );
    });
  }, [scoped, query, severity]);

  /** 漏洞复测：按报告原样重打，结论变了才改报告 */
  const retest = () => {
    if (!selected) return;
    onAsk(
      [
        `漏洞复测：这条结论先按报告原样重打一遍，确认现在环境里还成不成立。`,
        `标题：${selected.title}`,
        `等级：${selected.severity}`,
        `目标：${selected.target ?? "见报告"}`,
        `报告路径：${selected.path}`,
        ``,
        `要求：`,
        `1. 先读报告，把报告里写过的接口、参数、Cookie 状态原样照着打，记录 HTTP 码、回包里的条数/字段变化和耗时。`,
        `2. 还成立：只在原报告上补这次复测的时间和回包变化（修没修、链路有没有变长），不要另交一篇一样的报告。`,
        `3. 已经不成立：直接说哪一步被拦、返回了什么，不要重写报告；如果打出了更长的链，按报告格式改原篇。`,
      ].join("\n"),
    );
  };

  const copySummary = async () => {
    const lines = [
      `# 漏洞汇总（${rows.length} 条）`,
      "",
      "| 等级 | 类型 | 标题 | 目标 | 任务 |",
      "| --- | --- | --- | --- | --- |",
      ...rows.map((f) => `| ${f.severity} | ${f.type} | ${f.title.replace(/\|/g, "\\|")} | ${f.target || "-"} | ${f.task} |`),
    ];
    try {
      await copyText(lines.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      // 剪贴板不可用时静默失败，报告正文仍可手动复制
    }
  };

  const emptyHint =
    scope === "session"
      ? resolvedTasks.length === 0
        ? "这个会话还没认领任务夹。点上面「归属」把桌面上的任务夹勾给它；看全桌面点「总览」。"
        : "本会话任务还没有落盘报告。看别的会话点上面「总览」。"
      : "还没有正式报告。挖到洞后按报告格式落盘即可汇总。";

  return (
    <div className="findings">
      <div className="find-summary">
        <div className="metric">
          <div className="metric-label">发现总数</div>
          <div className="metric-value">{scoped.length}</div>
          <div className="metric-foot">
            {scope === "session"
              ? resolvedTasks.length
                ? `本会话 · ${resolvedTasks.length} 个任务夹`
                : "本会话还没有任务夹"
              : `总览 · ${new Set(scoped.map((f) => f.task)).size} 个任务`}
          </div>
        </div>
        {SEVERITIES.filter((s) => s !== "未知" || counts[s]).map((s) => (
          <button
            key={s}
            className={`metric metric-clickable ${severity === s ? "metric-on" : ""}`}
            onClick={() => setSeverity((prev) => (prev === s ? "全部" : s))}
          >
            <div className="metric-label">{s}</div>
            <div className={`metric-value ${SEVERITY_CLASS[s]}-text`}>{counts[s] ?? 0}</div>
            <div className="metric-foot">{severity === s ? "正在筛选" : "点击筛选"}</div>
          </button>
        ))}
      </div>

      <div className="find-toolbar">
        <div className="search find-search">
          <Icon name="search" size={13} />
          <input value={query} placeholder="搜索标题 / 目标 / 任务 / 类型" onChange={(e) => setQuery(e.target.value)} />
        </div>
        <div className="seg">
          {(["全部", "严重", "高危", "中危", "低危"] as const).map((s) => (
            <button key={s} className={`seg-btn ${severity === s ? "on" : ""}`} onClick={() => setSeverity(s)}>
              {s}
            </button>
          ))}
        </div>
        <ScopeSwitch
          tasks={resolvedTasks}
          scope={scope}
          onScope={setScope}
          total={globalLoaded ? globalList.length : undefined}
          scoped={sessionList.length}
        />
        <button className="btn ghost" onClick={() => ctx.refresh()}>
          <Icon name="refresh" size={13} />
          <span>{loading ? "读取中…" : "刷新"}</span>
        </button>
        <button className="btn ghost" onClick={() => void copySummary()} disabled={rows.length === 0}>
          <Icon name={copied ? "check" : "copy"} size={13} />
          <span>{copied ? "已复制" : "复制汇总"}</span>
        </button>
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      <div className="find-split">
        <div className="find-list">
          <div className="find-head">
            <span>严重度</span>
            <span>漏洞</span>
            <span>目标 / 任务</span>
            <span>时间</span>
          </div>
          {rows.length === 0 ? (
            <div className="panel-empty">{emptyHint}</div>
          ) : (
            rows.map((f) => (
              <button
                key={f.path}
                className={`find-row ${selected?.path === f.path ? "on" : ""}`}
                onClick={() => setSelected(f)}
              >
                <span className={`sev ${SEVERITY_CLASS[f.severity]}`}>{f.severity}</span>
                <span className="find-title">
                  <b>{f.title}</b>
                  <em>{f.type}</em>
                </span>
                <span className="find-target mono">{f.target || f.task}</span>
                <span className="find-time mono">{fmtTime(f.updatedAt)}</span>
              </button>
            ))
          )}
        </div>

        <div className="find-preview">
          {selected ? (
            <>
              <div className="find-preview-head">
                <div>
                  <div className="find-preview-title">{selected.title}</div>
                  <div className="find-preview-sub mono">{selected.path}</div>
                </div>
                <div className="find-preview-actions">
                  <button className="btn ghost sm" onClick={() => void window.tanwei.openPath(selected.path)}>
                    <Icon name="external" size={12} />
                    <span>打开</span>
                  </button>
                  <button className="btn primary sm" onClick={retest}>
                    <Icon name="refresh" size={12} />
                    <span>漏洞复测</span>
                  </button>
                </div>
              </div>
              <div className="find-preview-body">
                {previewLoading ? <div className="panel-empty">读取报告…</div> : <Markdown text={content} />}
              </div>
            </>
          ) : (
            <div className="panel-empty">左侧选择一条发现查看正文。</div>
          )}
        </div>
      </div>
    </div>
  );
}
