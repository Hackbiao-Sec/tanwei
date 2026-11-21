import React, { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import type {
  BootstrapInfo,
  CommandInfo,
  EngineStatus,
  McpServerInfo,
  ModelInfo,
  PermissionMode,
  RendererEvent,
  SessionState,
  SessionSummary,
} from "@shared/types";
import { Sidebar } from "./components/Sidebar";
import { Timeline } from "./components/Timeline";
import { Composer } from "./components/Composer";
import type { ComposerDraft } from "./components/Composer";
import { RightRail } from "./components/RightRail";
import { ModulePage } from "./components/Modules";
import { SessionScopeProvider } from "./lib/sessionScope";
import { ThemeToggle } from "./components/ThemeToggle";import { Icon } from "./components/Icons";
import { usedTokens } from "@shared/usage";
import type { ModuleId, View } from "./view";

type Toast = {
  id: number;
  level: "info" | "warn" | "error" | "done";
  text: string;
  title?: string;
  detail?: string[];
  sessionId?: string;
};

function fmtTokens(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(Math.round(n));
}

function fmtDuration(ms: number): string {
  const s = Math.max(1, Math.round(ms / 1000));
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  const rest = s % 60;
  return rest ? `${m} 分 ${rest} 秒` : `${m} 分钟`;
}

/** ACP 只上报它自己见过的服务；CLI 读到的是配置全量。两边合并，ACP 的就绪状态优先。 */
function mergeMcp(prev: McpServerInfo[], next: McpServerInfo[]): McpServerInfo[] {
  if (!next.length) return prev;
  const merged = new Map(prev.map((m) => [m.name, m]));
  for (const m of next) {
    const old = merged.get(m.name);
    merged.set(m.name, {
      name: m.name,
      status: m.status || old?.status || "configured",
      source: m.source ?? old?.source,
      reason: m.reason ?? old?.reason,
      tools: m.tools ?? old?.tools ?? null,
    });
  }
  return [...merged.values()];
}

export function App() {
  const store = useRef(new Map<string, SessionState>());
  const [, force] = useReducer((x: number) => x + 1, 0);
  const raf = useRef<number | null>(null);
  const activeRef = useRef<string | undefined>(undefined);
  const openSeq = useRef(0);
  const toastSeq = useRef(1);

  const [activeId, setActiveId] = useState<string>();
  const [view, setView] = useState<View>({ kind: "session" });
  const [status, setStatus] = useState<EngineStatus>("starting");
  const [version, setVersion] = useState<string>();
  const [engineError, setEngineError] = useState<string>();
  const [models, setModels] = useState<ModelInfo[]>([]);
  /** config.toml 里自己配的模型 key；下拉只列这些，避免误选中转目录里的裸模型 */
  const [configModelKeys, setConfigModelKeys] = useState<Set<string>>(new Set());
  const [configDefaultKey, setConfigDefaultKey] = useState<string>();
  const [commands, setCommands] = useState<CommandInfo[]>([]);
  const [mcp, setMcp] = useState<McpServerInfo[]>([]);
  const [history, setHistory] = useState<SessionSummary[]>([]);
  const [boot, setBoot] = useState<BootstrapInfo | null>(null);
  const [draftCwd, setDraftCwd] = useState("");
  // 面板「发到当前会话对话框」塞进来的草稿；seq 递增才覆盖输入框
  const [composerDraft, setComposerDraft] = useState<ComposerDraft>();
  const draftSeq = useRef(0);
  const [loadingId, setLoadingId] = useState<string>();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [creating, setCreating] = useState(false);
  const [maximized, setMaximized] = useState(false);

  const toggleMaximize = async () => {
    setMaximized(await window.tanwei.toggleMaximizeWindow());
  };

  useEffect(() => {
    void window.tanwei.isWindowMaximized().then(setMaximized);
  }, []);

  useEffect(() => {
    // 首帧主题由 main.tsx 写在 <html data-theme>，这里把窗口底色同步过去
    void window.tanwei.setWindowTheme(
      document.documentElement.dataset.theme === "light" ? "light" : "dark",
    );
  }, []);

  const bump = useCallback(() => {
    if (raf.current != null) return;
    raf.current = requestAnimationFrame(() => {
      raf.current = null;
      force();
    });
  }, []);

  const select = useCallback((id?: string) => {
    activeRef.current = id;
    setActiveId(id);
  }, []);

  const toast = useCallback(
    (
      level: Toast["level"],
      text: string,
      extra?: { title?: string; detail?: string[]; sessionId?: string; ttl?: number },
    ) => {
      const id = toastSeq.current++;
      setToasts((prev) => [...prev.slice(-3), { id, level, text, ...extra }]);
      setTimeout(
        () => setToasts((prev) => prev.filter((t) => t.id !== id)),
        extra?.ttl ?? 6000,
      );
    },
    [],
  );

  const findState = (id?: string) => (id ? store.current.get(id) : undefined);

  // ------------------------------------------------------------------ events
  useEffect(() => {
    const off = window.tanwei.onEngineEvent((ev: RendererEvent) => {
      switch (ev.type) {
        case "status":
          setStatus(ev.status);
          if (ev.version) setVersion(ev.version);
          if (ev.error) setEngineError(ev.error);
          else if (ev.status === "ready") setEngineError(undefined);
          break;
        case "bootstrap":
          setModels(ev.models);
          setCommands(ev.commands);
          setMcp((prev) => mergeMcp(prev, ev.mcpServers));
          if (ev.agentVersion) setVersion(ev.agentVersion);
          break;
        case "session":
          store.current.set(ev.session.id, ev.session);
          if (!activeRef.current) select(ev.session.id);
          bump();
          break;
        case "delta": {
          const st = store.current.get(ev.sessionId);
          const item = st?.timeline.find((i) => i.id === ev.itemId);
          if (item && (item.type === "assistant" || item.type === "thought")) item.text += ev.text;
          bump();
          break;
        }
        case "item": {
          const st = store.current.get(ev.sessionId);
          if (!st) break;
          const idx = st.timeline.findIndex((i) => i.id === ev.item.id);
          if (idx >= 0) st.timeline[idx] = ev.item;
          else st.timeline.push(ev.item);
          bump();
          break;
        }
        case "meta": {
          const st = store.current.get(ev.sessionId);
          if (!st) break;
          Object.assign(st, ev.patch);
          bump();
          break;
        }
        case "sessions":
          setHistory(ev.sessions);
          break;
        case "mcp":
          setMcp((prev) => mergeMcp(prev, ev.servers));
          break;
        case "notice":
          toast(ev.level, ev.text);
          break;
        case "turn-done": {
          const r = ev.report;
          const head = r.failedTools > 0 ? `工具 ${r.toolCount} 次 · 失败 ${r.failedTools}` : `工具 ${r.toolCount} 次`;
          toast("done", r.excerpt || "本轮已结束，可以查看完整过程", {
            title: `任务完成 · ${r.title}`,
            detail: [
              `耗时 ${fmtDuration(r.durationMs)} · ${head}`,
              `上下文已用 ${fmtTokens(usedTokens(r.usage))} tokens · 输出 ${fmtTokens(r.usage.outputTokens)}`,
            ],
            sessionId: r.sessionId,
            ttl: 16000,
          });
          break;
        }
        case "reset":
          // 引擎重启后旧会话句柄全部失效，清空本地缓存等新的 session 事件
          store.current.clear();
          select(undefined);
          setHistory([]);
          bump();
          break;
        case "quit":
          setStatus("stopped");
          break;
        default:
          break;
      }
    });
    return off;
  }, [bump, select, toast]);

  // 风控事件全应用可见：盯着测试过程的时候也要当场知道被拦了，不用切到告警面板
  useEffect(
    () =>
      window.tanwei.onRiskEvent((sig) => {
        const evidence = sig.evidence.length > 90 ? `${sig.evidence.slice(0, 90)}…` : sig.evidence;
        toast("warn", `${sig.target ? `${sig.target} · ` : ""}${evidence}`, {
          title: `被目标风控 · ${sig.category}`,
          ttl: 14000,
        });
      }),
    [toast],
  );

  // ------------------------------------------------------------------- boot
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const info = await window.tanwei.bootstrap();
        if (cancelled) return;
        setBoot(info);
        setModels(info.models);
        setCommands(info.commands);
        setMcp(info.mcpServers);
        setStatus(info.engine.status);
        setVersion(info.grokVersion ?? info.engine.version);
        setHistory(info.sessions);
        setDraftCwd(info.cwd);

        await window.tanwei.startEngine();
        if (cancelled) return;
        // 引擎的 ready 事件可能早于渲染层订阅，这里用 startEngine 的返回值补齐状态
        const running = await window.tanwei.startEngine();
        if (!cancelled && running) {
          setStatus(running.status);
          if (running.version) setVersion(running.version);
          if (running.models?.length) setModels(running.models);
          if (running.mcpServers?.length) setMcp(running.mcpServers);
        }
        if (!cancelled) {
          const cliMcp = await window.tanwei.mcp().catch(() => []);
          if (!cancelled && cliMcp.length) setMcp((prev) => mergeMcp(prev, cliMcp));
        }
        const cfgModels = await window.tanwei.modelsConfig().catch(() => null);
        if (!cancelled && cfgModels) {
          setConfigModelKeys(new Set(cfgModels.models.map((m) => m.key)));
          if (cfgModels.defaultKey) setConfigDefaultKey(cfgModels.defaultKey);
        }
        await window.tanwei.refreshSessions();
        if (cancelled) return;

        const latest = info.sessions[0];
        if (latest) {
          setLoadingId(latest.id);
          try {
            const st = await window.tanwei.loadSession(latest.id);
            if (cancelled) return;
            store.current.set(st.id, st);
            // 载入期间用户可能已点了别的会话，别把选择顶掉
            if (!activeRef.current) select(st.id);
          } catch (err) {
            toast("warn", `载入最近会话失败：${err instanceof Error ? err.message : String(err)}`);
          } finally {
            setLoadingId(undefined);
          }
        } else {
          const st = await window.tanwei.createSession(info.cwd);
          if (cancelled) return;
          store.current.set(st.id, st);
          if (!activeRef.current) select(st.id);
        }
        bump();
      } catch (err) {
        if (!cancelled) setEngineError(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [bump, select, toast]);

  const active = findState(activeId);

  // 设置页读取的是启动时快照，引擎就绪后要把状态同步过去
  useEffect(() => {
    setBoot((prev) =>
      prev
        ? {
            ...prev,
            grokVersion: version ?? prev.grokVersion,
            models: models.length ? models : prev.models,
            mcpServers: mcp.length ? mcp : prev.mcpServers,
            engine: { status, version },
          }
        : prev,
    );
  }, [status, version, models, mcp]);

  // ----------------------------------------------------------------- actions
  const createSession = async (cwd?: string) => {
    if (creating) return;
    setCreating(true);
    try {
      const st = await window.tanwei.createSession(cwd || draftCwd || undefined);
      // 新会话一律从 config.toml 的默认模型起，不吃上一个会话残留的模型
      if (configDefaultKey) {
        await window.tanwei.setModel(st.id, configDefaultKey).catch(() => undefined);
      }
      store.current.set(st.id, st);
      select(st.id);
      setView({ kind: "session" });
      bump();
    } catch (err) {
      toast("error", `新建会话失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setCreating(false);
    }
  };

  const openSession = async (id: string) => {
    setView({ kind: "session" });
    if (store.current.has(id)) {
      select(id);
      return;
    }
    const token = ++openSeq.current;
    setLoadingId(id);
    try {
      const st = await window.tanwei.loadSession(id, draftCwd || undefined);
      // 期间又点了别的会话，这次载入结果不再抢焦点
      if (token !== openSeq.current) return;
      store.current.set(st.id, st);
      select(st.id);
      bump();
    } catch (err) {
      toast("error", `载入会话失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoadingId(undefined);
    }
  };

  const send = (text: string, attachments?: string[]) => {
    if (!activeId) return;
    const files = attachments ?? [];
    // 附件先按会话登记：APP / 小程序面板靠这份登记显示「已上传、待分析」
    if (files.length) void window.tanwei.uploadAdd(files, activeId).catch(() => undefined);
    const body = files.length
      ? `${files.map((p) => `[附件] ${p}`).join("\n")}\n\n${text}`
      : text;
    void window.tanwei.prompt(activeId, body).catch((err) => {
      toast("error", `发送失败：${err instanceof Error ? err.message : String(err)}`);
    });
  };

  const cancel = () => {
    if (!activeId) return;
    void window.tanwei.cancel(activeId);
  };

  // 删会话：主进程停回合 + 删磁盘目录；删的是当前会话就退到别的会话或新建
  const deleteSession = async (id: string) => {
    const wasActive = activeRef.current === id;
    const snapshot = store.current.get(id);
    const rest = [...store.current.keys()]
      .filter((key) => key !== id)
      .concat(history.map((h) => h.id).filter((hid) => hid !== id));

    // 删目录和重读会话列表都要等，先把行摘掉、切走，不然点了像没反应
    store.current.delete(id);
    setHistory((prev) => prev.filter((h) => h.id !== id));
    bump();

    if (wasActive) {
      select(undefined);
      if (rest[0]) await openSession(rest[0]);
      else await createSession();
    }

    try {
      await window.tanwei.deleteSession(id);
      toast("info", "会话已删除");
    } catch (err) {
      if (snapshot) store.current.set(id, snapshot);
      bump();
      void window.tanwei.refreshSessions().catch(() => undefined);
      toast("error", `删除会话失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const changeMode = (mode: PermissionMode) => {
    if (!activeId) return;
    void window.tanwei.setMode(activeId, mode).catch((err) => {
      toast("warn", `切换模式失败：${err instanceof Error ? err.message : String(err)}`);
    });
  };

  const changeModel = (modelId: string) => {
    if (!activeId || !modelId) return;
    void window.tanwei.setModel(activeId, modelId).catch((err) => {
      toast("warn", `切换模型失败：${err instanceof Error ? err.message : String(err)}`);
    });
  };

  // 只列 config.toml 里配过的模型：中转目录里的裸模型会绕过本地修片，工具名会被冲成空串
  const visibleModels = useMemo(
    () => (configModelKeys.size ? models.filter((m) => configModelKeys.has(m.modelId)) : models),
    [models, configModelKeys],
  );

  // 本会话的产物归属由主进程会话快照统一给出，渲染层不再自己从时间线文本里猜任务夹
  const activeState = findState(activeId);

  const respond = (requestId: number, optionId: string) => {
    void window.tanwei.respondPermission(requestId, optionId);
  };

  const refreshMcp = async () => {
    const list = await window.tanwei.mcp().catch(() => []);
    setMcp((prev) => {
      const merged = new Map(prev.map((m) => [m.name, m]));
      for (const m of list) {
        const old = merged.get(m.name);
        merged.set(m.name, { ...m, status: old?.status ?? m.status, tools: old?.tools ?? m.tools });
      }
      return [...merged.values()];
    });
  };

  const pickFolder = async () => {    const dir = await window.tanwei.pickFolder();
    if (dir) {
      setDraftCwd(dir);
      toast("info", `新会话将使用目录：${dir}`);
    }
  };

  /** 从面板把已经写好的渗透需求放进输入框，发不发由用户自己点 */
  const stagePrompt = (text: string) => {
    const put = () => {
      draftSeq.current += 1;
      setComposerDraft({ text, seq: draftSeq.current });
      setView({ kind: "session" });
    };
    if (activeId) {
      put();
      toast("info", "需求已写进当前会话输入框，确认后点发送");
      return;
    }
    void (async () => {
      try {
        const st = await window.tanwei.createSession(draftCwd || undefined);
        store.current.set(st.id, st);
        select(st.id);
        bump();
        put();
        toast("info", "已新建会话并写进输入框，确认后点发送");
      } catch (err) {
        toast("error", `准备会话失败：${err instanceof Error ? err.message : String(err)}`);
      }
    })();
  };

  /** 从「发现 / 资产」直接开一个会话，把上下文交给 agent 继续打 */
  const askAgent = (prompt: string) => {
    void (async () => {
      try {
        const st = await window.tanwei.createSession(draftCwd || undefined);
        store.current.set(st.id, st);
        select(st.id);
        setView({ kind: "session" });
        bump();
        await window.tanwei.prompt(st.id, prompt);
      } catch (err) {
        toast("error", `发起任务失败：${err instanceof Error ? err.message : String(err)}`);
      }
    })();
  };

  // ---------------------------------------------------------------- shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
        e.preventDefault();
        void createSession();
      }
      if (e.key === "Escape" && activeRef.current && findState(activeRef.current)?.busy) {
        void window.tanwei.cancel(activeRef.current);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const live = [...store.current.values()];
  const readyCount = mcp.filter((m) => m.status !== "failed" && m.status !== "disabled").length;
  const stateTitle = active?.title || "新会话";

  return (
    <SessionScopeProvider sessionId={activeId} revision={activeState?.updatedAt} busy={Boolean(activeState?.busy)}>
      <div className="app">
      <header className="titlebar">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="radar" size={17} />
          </span>
          <span className="brand-text">
            天鉴·探微<span className="brand-sub">安全测试平台</span>
          </span>
        </div>

        <div className="titlebar-mid">
          <span className={`status-pill ${status}`}>
            <span className={`status-dot ${status}`} />
            {status === "ready" ? "引擎就绪" : status === "starting" ? "引擎启动" : status === "error" ? "引擎异常" : "引擎停止"}
            {version ? <span className="status-ver">v{version}</span> : null}
          </span>
          <span className="tb-chip" title="当前会话">
            <Icon name="chat" size={12} />
            <span className="tb-chip-text">{stateTitle}</span>
            {active?.busy ? <span className="thinking-bars"><i /><i /><i /></span> : null}
          </span>
          <span className="tb-chip" title="MCP 就绪数">
            <Icon name="plug" size={12} />
            <span className="tb-chip-text">
              MCP {readyCount}/{mcp.length}
            </span>
          </span>
          {active?.pendingPermissions ? (
            <span className="tb-chip warn" title="待授权工具调用">
              <Icon name="shield" size={12} />
              <span className="tb-chip-text">待授权 {active.pendingPermissions}</span>
            </span>
          ) : null}
        </div>

        <div className="titlebar-right">
          <ThemeToggle />
          <button className="tb-btn" onClick={() => void window.tanwei.launchTui(active?.cwd || draftCwd)} title="打开原生 grok TUI">
            <Icon name="terminal" size={14} />
            <span>原生 TUI</span>
          </button>
          <button
            className="tb-btn icon-only"
            onClick={() => {
              void window.tanwei.refreshSessions();
              bump();
            }}
            title="刷新会话列表"
          >
            <Icon name="refresh" size={14} />
          </button>
          <button
            className="tb-btn icon-only"
            onClick={() => void window.tanwei.openPath(boot?.grokHome ?? "")}
            title="打开 ~/.grok"
          >
            <Icon name="folder" size={14} />
          </button>
        </div>

        <div className="window-controls">
          <button className="win-btn" onClick={() => void window.tanwei.minimizeWindow()} title="最小化">
            <Icon name="win-min" size={14} />
          </button>
          <button
            className="win-btn"
            onClick={() => void toggleMaximize()}
            title={maximized ? "向下还原" : "最大化"}
          >
            <Icon name={maximized ? "win-restore" : "win-max"} size={14} />
          </button>
          <button className="win-btn close" onClick={() => void window.tanwei.closeWindow()} title="关闭">
            <Icon name="win-close" size={14} />
          </button>
        </div>
      </header>

      {engineError && status === "error" ? (
        <div className="banner error">
          <Icon name="shield" size={14} />
          <span>引擎异常：{engineError}</span>
          <button
            className="btn ghost sm"
            onClick={() => {
              setEngineError(undefined);
              setStatus("starting");
              void window.tanwei.startEngine();
            }}
          >
            重试
          </button>
        </div>
      ) : null}

      <div className="workspace">
        <Sidebar
          live={live}
          history={history}
          activeId={activeId}
          view={view}
          loadingId={loadingId}
          onSelectSession={(id) => void openSession(id)}
          onNewSession={() => void createSession()}
          onModule={(id: ModuleId) => setView({ kind: "module", id })}
          onRefresh={() => void window.tanwei.refreshSessions()}
          onDeleteSession={(id) => void deleteSession(id)}
        />

        {view.kind === "session" ? (
          <main className="stage">
            <div className="stage-head">
              <div className="stage-title">
                <span className="stage-name">{stateTitle}</span>
                {active?.resumed ? <span className="chip chip-ghost">历史</span> : null}
                {active?.model ? <span className="chip chip-ghost mono">{active.model}</span> : null}
              </div>
              <div className="stage-meta">
                <button className="meta-link" onClick={() => active && void window.tanwei.openPath(active.cwd)} title={active?.cwd}>
                  <Icon name="folder" size={12} />
                  <span>{active?.cwd?.split(/[\\/]/).filter(Boolean).pop() ?? "未选目录"}</span>
                </button>
                <span className="meta-sep" />
                <span className="meta-text">{active?.timeline.length ?? 0} 条记录</span>
                <span className="meta-sep" />
                <span className="meta-text">{active?.busy ? "回合进行中" : "空闲"}</span>
              </div>
            </div>

            <Timeline state={active} onRespond={respond} />

            <Composer
              disabled={!activeId || status === "error"}
              busy={Boolean(active?.busy)}
              mode={active?.mode ?? "ask"}
              model={active?.model}
              models={visibleModels}
              commands={commands}
              cwd={active?.cwd ?? draftCwd}
              draft={composerDraft}
              onSend={send}
              onCancel={cancel}
              onMode={changeMode}
              onModel={changeModel}
              onPickFolder={() => void pickFolder()}
            />
          </main>
        ) : (
          <main className="stage stage-module">
            <ModulePage
              id={view.id}
              mcp={mcp}
              boot={boot}
              status={status}
              version={version}
              live={live}
              history={history}
              loadingId={loadingId}
              onRefreshSessions={() => void window.tanwei.refreshSessions()}
              onOpenSession={(id) => void openSession(id)}
              onCreateSession={() => void createSession()}
              onAsk={askAgent}
              onStage={stagePrompt}
              onModule={(id: ModuleId) => setView({ kind: "module", id })}
              commands={commands}
              activeId={activeId}
            />
          </main>
        )}

        {view.kind === "session" ? (
          <RightRail state={active} mcp={mcp} status={status} version={version} onRefreshMcp={() => void refreshMcp()} />
        ) : null}
      </div>

      <div className="toasts">
        {toasts.map((t) =>
          t.level === "done" ? (
            <div key={t.id} className="toast toast-done">
              <div className="toast-done-head">
                <span className="toast-done-check">
                  <Icon name="check" size={12} />
                </span>
                <span className="toast-done-title">{t.title ?? "任务完成"}</span>
                <button
                  className="toast-x"
                  onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
                >
                  <Icon name="close" size={11} />
                </button>
              </div>
              <div className="toast-done-text">{t.text}</div>
              {t.detail?.length ? (
                <div className="toast-done-meta">
                  {t.detail.map((d, i) => (
                    <span key={i}>{d}</span>
                  ))}
                </div>
              ) : null}
              {t.sessionId ? (
                <button
                  className="toast-done-open"
                  onClick={() => {
                    void openSession(t.sessionId!);
                    setToasts((prev) => prev.filter((x) => x.id !== t.id));
                  }}
                >
                  打开会话
                </button>
              ) : null}
            </div>
          ) : (
            <div key={t.id} className={`toast ${t.level}`}>
              <span className="toast-dot" />
              <span className="toast-body">
                {t.title ? <span className="toast-title">{t.title}</span> : null}
                <span className="toast-text">{t.text}</span>
              </span>
              <button
                className="toast-x"
                onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
              >
                <Icon name="close" size={11} />
              </button>
            </div>
          ),
        )}
      </div>
      </div>
    </SessionScopeProvider>
  );
}
