import React, { useCallback, useEffect, useRef, useState } from "react";
import type {
  MobileActionResult,
  MobileAnalysis,
  MobileEnvInfo,
  RendererEvent,
  TimelineItem,
} from "@shared/types";
import { Icon } from "./Icons";
import { Markdown } from "./Markdown";
import { errText } from "./MobileShared";

const QUICK = [
  { icon: "search", label: "读懂这个包", ask: "先把这个包的定位、入口组件、核心接口和数据面讲清楚，我关心它到底在做什么、值不值得往下打。" },
  { icon: "shield", label: "静态风险面", ask: "按拆解结果列出最可能成立的风险面，每条给出理由和下一步验证动作，按能出高价值的排在前面。" },
  { icon: "terminal", label: "动态验证计划", ask: "针对上面这些风险面，给我一份能直接在这台真机上跑的动态验证顺序，说明每步用哪个动作、看什么回显。" },
  { icon: "file", label: "复现与报告", ask: "把目前已经成立的结论整理成可复现的验证步骤和报告要点，缺的证据一起标出来。" },
] as const;

type Role = "idle" | "thinking";

/**
 * Grok 协作：把静态拆解、动态结果一起交给应用内的 grok 引擎，
 * 让它和人一起把这一轮 APP 测试做完。
 */
export function AppCopilot({
  analysis,
  env,
  actions,
  onNotice,
  onError,
}: {
  /** 静态拆解记录（带路口径），有它才接引擎 */
  analysis?: MobileAnalysis | Omit<MobileAnalysis, "log">;
  env?: MobileEnvInfo;
  /** 已经跑过的动态动作：带进上下文，免得它重复问 */
  actions?: MobileActionResult[];
  onNotice: (text: string) => void;
  onError: (text: string) => void;
}) {
  const [sid, setSid] = useState<string>();
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState("");
  const [creating, setCreating] = useState(false);
  const sidRef = useRef<string>();
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const analysisRef = useRef(analysis);
  const envRef = useRef(env);
  const actionsRef = useRef(actions);

  analysisRef.current = analysis;
  envRef.current = env;
  actionsRef.current = actions;

  useEffect(() => {
    const off = window.tanwei.onEngineEvent((ev: RendererEvent) => {
      const mine = sidRef.current;
      switch (ev.type) {
        case "session":
          if (!mine || ev.session.id !== mine) break;
          setItems(ev.session.timeline);
          setBusy(ev.session.busy);
          break;
        case "item":
          if (!mine || ev.sessionId !== mine) break;
          setItems((prev) => {
            const idx = prev.findIndex((i) => i.id === ev.item.id);
            if (idx < 0) return [...prev, ev.item];
            const next = prev.slice();
            next[idx] = ev.item;
            return next;
          });
          break;
        case "delta":
          if (!mine || ev.sessionId !== mine) break;
          setItems((prev) => {
            const idx = prev.findIndex((i) => i.id === ev.itemId);
            if (idx < 0) return prev;
            const cur = prev[idx];
            if (cur.type !== "assistant" && cur.type !== "thought") return prev;
            const next = prev.slice();
            next[idx] = { ...cur, text: cur.text + ev.text };
            return next;
          });
          break;
        case "meta":
          if (!mine || ev.sessionId !== mine) break;
          if (typeof ev.patch.busy === "boolean") setBusy(ev.patch.busy);
          break;
        case "reset":
          sidRef.current = undefined;
          setSid(undefined);
          setItems([]);
          setBusy(false);
          break;
        case "notice":
          if (ev.level === "error") onError(ev.text);
          break;
        default:
          break;
      }
    });
    return off;
  }, [onError]);

  // 换了目标就换一摊：旧会话继续留在侧栏历史里，面板本身从头开始
  const targetKey = analysis ? `${analysis.target.kind}:${analysis.target.path}` : "";
  useEffect(() => {
    sidRef.current = undefined;
    setSid(undefined);
    setItems([]);
    setBusy(false);
  }, [targetKey]);

  useEffect(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [items, busy, sid]);

  const ensureSession = useCallback(async (): Promise<string | undefined> => {
    if (sidRef.current) return sidRef.current;
    setCreating(true);
    try {
      const cwd = analysisRef.current?.outDir;
      const s = await window.tanwei.createSession(cwd || undefined);
      sidRef.current = s.id;
      setSid(s.id);
      setItems(s.timeline);
      return s.id;
    } catch (err) {
      onError(errText(err));
      return undefined;
    } finally {
      setCreating(false);
    }
  }, [onError]);

  const send = useCallback(
    async (text: string) => {
      const body = text.trim();
      if (!body) return;
      const cur = analysisRef.current;
      if (!cur) {
        onError("先在上面选一个目标拆解，我拿到结果才好一起分析");
        return;
      }
      const id = await ensureSession();
      if (!id) return;
      let payload = body;
      if (!sidRef.current || items.length === 0) {
        try {
          const ctx = await window.tanwei.mobilePrompt({
            analysis: { ...cur, log: [] } as MobileAnalysis,
            mode: "both",
            env: envRef.current,
          });
          const done = (actionsRef.current ?? [])
            .slice(-8)
            .map((a) => `- ${a.title}：${a.ok ? "通过" : "异常"}${a.hint ? `（${a.hint}）` : ""}`)
            .join("\n");
          payload = [
            "这一轮 APP 测试我们一起做：下面是静态拆解结果和已经跑过的动态动作，你按上面的目标和技术栈继续往下分析、指出下一步该验什么。",
            "",
            ctx,
            "",
            done ? `【已跑过的动态动作】\n${done}` : "",
            "【我的问题】",
            body,
          ]
            .filter(Boolean)
            .join("\n");
        } catch {
          // 上下文拼不出来也照发：引擎自己也能从产物目录里读
        }
      }
      try {
        setDraft("");
        const ok = await window.tanwei.prompt(id, payload);
        if (!ok) onError("引擎没接收这条消息，等一下再发");
      } catch (err) {
        onError(errText(err));
      }
    },
    [ensureSession, items.length, onError],
  );

  const stop = useCallback(async () => {
    const id = sidRef.current;
    if (!id) return;
    try {
      await window.tanwei.cancel(id);
    } catch (err) {
      onError(errText(err));
    }
  }, [onError]);

  const restart = useCallback(() => {
    sidRef.current = undefined;
    setSid(undefined);
    setItems([]);
    setBusy(false);
    onNotice("已开新的协作会话，旧会话留在侧栏历史里");
  }, [onNotice]);

  const turnLabel = busy ? "正在分析…" : creating ? "接入引擎…" : sid ? "在线 · 可追问" : "待接入";

  return (
    <div className="acp">
      <div className="acp-head">
        <span className={`acp-dot${busy ? " on" : ""}`} />
        <span className="acp-title">Grok 协作</span>
        <span className="mono subtle">{turnLabel}</span>
        <div className="mob-spacer" />
        {busy ? (
          <button className="btn ghost sm" onClick={() => void stop()} title="停下当前这一轮">
            <Icon name="stop" size={11} />
            <span>停止</span>
          </button>
        ) : null}
        <button className="icon-btn sm" onClick={restart} title="开一个新的协作会话">
          <Icon name="refresh" size={12} />
        </button>
      </div>

      <div className="acp-body" ref={bodyRef}>
        {!analysis ? (
          <div className="acp-empty">
            <div className="acp-empty-badge">
              <Icon name="bolt" size={17} />
            </div>
            <div className="acp-empty-title">拆完就把上下文交给 grok 引擎</div>
            <div className="acp-empty-text">
              左边选设备上的应用或本机 APK，拆解完成后这里自动接上引擎：它读同一份产物目录，
              我这边跑的每条动态动作也会同步过去。
            </div>
            <div className="acp-steps">
              <span><b>1</b> 选目标</span>
              <span><b>2</b> 拆解 APK</span>
              <span><b>3</b> 一起验证</span>
            </div>
          </div>
        ) : items.length === 0 ? (
          <div className="acp-empty">
            <div className="acp-empty-badge">
              <Icon name="chat" size={17} />
            </div>
            <div className="acp-empty-title">{analysis.packageName ?? analysis.target.name}</div>
            <div className="acp-empty-text">
              产物在 <span className="mono">{analysis.outDir}</span>，引擎读的是同一份。点下面的快捷提问，或者直接问。
            </div>
            <div className="acp-stats">
              <div><b>{analysis.endpoints.length}</b><span>接口</span></div>
              <div><b>{analysis.secrets.length}</b><span>密钥</span></div>
              <div><b>{analysis.components.length}</b><span>组件</span></div>
              <div><b>{analysis.permissions.length}</b><span>权限</span></div>
            </div>
          </div>
        ) : (
          items.map((it) => <Bubble key={it.id} item={it} onError={onError} />)
        )}
        {busy ? (
          <div className="acp-typing">
            <span />
            <span />
            <span />
          </div>
        ) : null}
      </div>

      <div className="acp-quick">
        {QUICK.map((q) => (
          <button
            key={q.label}
            className="acp-chip"
            disabled={!analysis || busy || creating}
            onClick={() => void send(q.ask)}
          >
            <Icon name={q.icon} size={11} />
            <span>{q.label}</span>
          </button>
        ))}
      </div>

      <div className="acp-compose">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={analysis ? "问它：这里为什么危险 / 下一步验什么 / 写个 frida hook" : "先选一个目标拆解"}
          rows={2}
          spellCheck={false}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void send(draft);
            }
          }}
        />
        <button
          className="btn primary sm acp-send"
          disabled={!analysis || !draft.trim() || busy || creating}
          onClick={() => void send(draft)}
          title="Enter 发送，Shift+Enter 换行"
        >
          <Icon name="send" size={12} />
        </button>
      </div>
    </div>
  );
}

function Bubble({ item, onError }: { item: TimelineItem; onError: (text: string) => void }) {
  switch (item.type) {
    case "user":
      return (
        <div className="acp-msg acp-me">
          <div className="acp-bubble">{item.text.length > 2400 ? `${item.text.slice(0, 2400)}…` : item.text}</div>
        </div>
      );
    case "assistant":
      return (
        <div className="acp-msg acp-bot">
          <Markdown text={item.text || "…"} />
        </div>
      );
    case "thought":
      return (
        <div className="acp-thought" title="引擎的思考过程">
          {item.text.length > 600 ? `${item.text.slice(0, 600)}…` : item.text}
        </div>
      );
    case "tool":
      return (
        <div className={`acp-tool v-${item.call.status}`}>
          <Icon name="terminal" size={11} />
          <span className="acp-tool-title">{item.call.title}</span>
          <span className="mono subtle">{item.call.kind ?? ""}</span>
        </div>
      );
    case "permission":
      return (
        <div className="acp-perm">
          <div className="acp-perm-title">{item.title}</div>
          {item.detail ? <div className="acp-perm-detail mono">{item.detail}</div> : null}
          <div className="acp-perm-ops">
            {item.options.map((op) => (
              <button
                key={op.optionId}
                className={`btn ${op.kind === "allow" || op.kind === "allow_always" ? "primary" : "ghost"} sm`}
                disabled={Boolean(item.resolvedOptionId)}
                onClick={() =>
                  void window.tanwei
                    .respondPermission(item.requestId, op.optionId)
                    .catch((err) => onError(errText(err)))
                }
              >
                {op.name}
              </button>
            ))}
          </div>
        </div>
      );
    case "system":
      return <div className={`acp-sys v-${item.level ?? "info"}`}>{item.text}</div>;
    case "plan":
      return (
        <div className="acp-sys v-info">
          {item.entries.filter((e) => e.status !== "completed").map((e) => `· ${e.content}`).join("\n")}
        </div>
      );
    default:
      return null;
  }
}
