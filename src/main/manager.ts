import { EventEmitter } from "node:events";
import os from "node:os";
import type {
  CommandInfo,
  McpServerInfo,
  ModelInfo,
  PermissionMode,
  PlanEntry,
  RendererEvent,
  SessionState,
  TimelineItem,
  ToolCallView,
  UsageStats,
} from "../shared/types";
import { AcpClient, type AcpRequest } from "./acp";
import { readSessionHistory, readSessionSummary } from "./history";
import { readPermissionMode, sanitizeMcpServers } from "./system";

const ZERO_USAGE: UsageStats = {
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  reasoningTokens: 0,
  totalTokens: 0,
};

type ActiveItems = { assistant?: string; thought?: string };

function now(): number {
  return Date.now();
}

function textOf(block: any): string {
  if (!block) return "";
  if (typeof block === "string") return block;
  if (typeof block.text === "string") return block.text;
  if (block.content) return textOf(block.content);
  return "";
}

const KIND_LABEL: Record<string, string> = {
  execute: "执行命令",
  edit: "编辑文件",
  write: "写入文件",
  read: "读取文件",
  search: "搜索",
  fetch: "抓取网页",
  think: "思考",
  delete: "删除",
  move: "移动",
  create: "新建",
  list: "列目录",
};

function toolTitle(update: any, input: any, fallback = ""): string {
  // ACP 里 kind 在 _meta["x.ai/tool"] 下；顶层 title 通常只是工具名
  const meta = update?._meta?.["x.ai/tool"] ?? {};
  const kind = String(meta.kind ?? update?.kind ?? "").toLowerCase();
  const name = String(meta.name ?? update?.title ?? "").trim();
  const label = KIND_LABEL[kind] ?? (name || "工具调用");
  const hint =
    input?.command ??
    input?.cmd ??
    input?.path ??
    input?.file_path ??
    input?.target_file ??
    input?.query ??
    input?.pattern ??
    input?.url ??
    input?.description ??
    "";
  const raw = typeof hint === "string" ? hint : String(hint ?? "");
  const text = raw.replace(/\s+/g, " ").trim().slice(0, 90);
  if (!text && label === "工具调用") return fallback || label;
  return text ? `${label} · ${text}` : label;
}

function outputOf(rawOutput: any, content: any): string {
  const parts: string[] = [];
  if (Array.isArray(content)) {
    for (const c of content) {
      const t = textOf(c) || textOf(c?.content);
      if (t) parts.push(t);
    }
  }
  if (!parts.length && rawOutput !== undefined) {
    if (typeof rawOutput === "string") parts.push(rawOutput);
    else {
      const inner = rawOutput?.Content?.content ?? rawOutput?.content ?? rawOutput?.output;
      if (typeof inner === "string") parts.push(inner);
      else {
        try {
          parts.push(JSON.stringify(rawOutput, null, 2));
        } catch {
          parts.push(String(rawOutput));
        }
      }
    }
  }
  return parts.join("\n").slice(0, 40_000);
}

export class EngineManager extends EventEmitter {
  private client: AcpClient | null = null;
  private sessions = new Map<string, SessionState>();
  private order: string[] = [];
  private models: ModelInfo[] = [];
  private ctxFallback: Record<string, number> = {};
  private compactPercent = 85;
  private commands: CommandInfo[] = [];
  private mcp = new Map<string, McpServerInfo>();
  private activeItems = new Map<string, ActiveItems>();
  private permissions = new Map<number, { sessionId: string; itemId: string }>();
  private replayUsers = new Map<string, string>();
  private seq = 1;
  private agentVersion?: string;
  private status: "starting" | "ready" | "error" | "stopped" = "stopped";
  private mode: PermissionMode;
  private mcpToolCount = 0;
  private lastSessionRefresh = 0;
  private extraEnv: NodeJS.ProcessEnv = {};

  constructor(
    readonly grokPath: string,
    readonly defaultCwd: string,
  ) {
    super();
    this.mode = readPermissionMode();
  }

  /** 代理等附加环境变量；下次 start/restart 才生效 */
  setExtraEnv(env: NodeJS.ProcessEnv): void {
    this.extraEnv = env;
  }

  private emitEvent(ev: RendererEvent): void {
    this.emit("event", ev);
  }

  getStatus() {
    return {
      status: this.status,
      version: this.agentVersion,
      models: this.models,
      commands: this.commands,
      mcpServers: [...this.mcp.values()],
      mode: this.mode,
      cwd: this.defaultCwd,
    };
  }

  snapshotSessions(): SessionState[] {
    return this.order
      .map((id) => this.sessions.get(id))
      .filter((s): s is SessionState => !!s)
      .sort((a, b) => b.updatedAt - a.updatedAt);
  }

  getSession(id: string): SessionState | undefined {
    return this.sessions.get(id);
  }

  async start(): Promise<void> {
    if (this.status === "ready" || this.status === "starting") return;
    this.status = "starting";
    this.emitEvent({ type: "status", status: "starting" });

    const client = new AcpClient(this.grokPath, os.homedir(), this.extraEnv);
    this.client = client;
    client.on("notification", (n) => this.onNotification(n));
    client.on("request", (r: AcpRequest) => this.onRequest(r));
    client.on("stderr", (chunk: string) => this.onStderr(chunk));
    client.on("noise", (line: string) => {
      if (line.trim()) this.emitEvent({ type: "notice", level: "warn", text: line.slice(0, 400) });
    });
    client.on("exit", ({ code, expected }: { code: number | null; expected: boolean }) => {
      this.status = expected ? "stopped" : "error";
      this.emitEvent({
        type: "status",
        status: this.status,
        error: expected ? undefined : `grok agent 已退出（code ${code}）`,
      });
      if (!expected) {
        for (const s of this.sessions.values()) {
          if (s.busy) {
            s.busy = false;
            this.emitEvent({ type: "meta", sessionId: s.id, patch: { busy: false } });
          }
        }
      }
    });

    try {
      const init = await client.start();
      const meta = init?._meta ?? {};
      this.agentVersion = meta.agentVersion;
      this.models = (meta.modelState?.availableModels ?? []).map((m: any) => ({
        modelId: m.modelId,
        name: m.name || m.modelId,
        contextTokens: m?._meta?.totalContextTokens,
      }));
      this.commands = (meta.availableCommands ?? []).map((c: any) => ({
        name: c.name,
        description: c.description ?? "",
        hint: c?.input?.hint ?? null,
      }));
      for (const s of sanitizeMcpServers(meta.mcpServers ?? [])) {
        this.mcp.set(s.name, s);
      }
      this.status = "ready";
      this.emitEvent({
        type: "status",
        status: "ready",
        version: this.agentVersion,
      });
      this.emitEvent({
        type: "bootstrap",
        models: this.models,
        commands: this.commands,
        mcpServers: [...this.mcp.values()],
        cwd: this.defaultCwd,
        permissionMode: this.mode,
        agentVersion: this.agentVersion,
      });
    } catch (err) {
      this.status = "error";
      this.emitEvent({
        type: "status",
        status: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  stop(): void {
    this.client?.stop();
    this.client = null;
    this.status = "stopped";
  }

  /**
   * 重启 agent 进程：模型目录只在 initialize 时读取，改了 config.toml 必须重连。
   * 旧会话句柄随之失效，渲染层收到 reset 后清空本地会话缓存。
   */
  async restart(): Promise<void> {
    this.client?.stop();
    this.client = null;
    this.sessions.clear();
    this.order = [];
    this.models = [];
    this.commands = [];
    this.mcp.clear();
    this.activeItems.clear();
    this.permissions.clear();
    this.replayUsers.clear();
    this.agentVersion = undefined;
    this.status = "stopped";
    this.emitEvent({ type: "reset" });
    await this.start();
  }

  private onStderr(chunk: string): void {
    const line = chunk.trim();
    if (!line) return;
    if (/ERROR|error=|panic|failed/i.test(line)) {
      this.emitEvent({ type: "notice", level: "error", text: line.slice(0, 600) });
    }
  }

  // ---------------------------------------------------------------- sessions

  private newState(id: string, cwd: string): SessionState {
    const t = now();
    return {
      id,
      title: "新会话",
      cwd,
      mode: this.mode,
      busy: false,
      timeline: [],
      plan: [],
      usage: { ...ZERO_USAGE },
      contextWindow: this.windowFor(),
      compactAt: this.compactPercent,
      createdAt: t,
      updatedAt: t,
      pendingPermissions: 0,
    };
  }

  private applyConfig(state: SessionState, configOptions: any[]): void {
    const model = configOptions?.find((c) => c.id === "model");
    if (model?.currentValue) state.model = String(model.currentValue);
    state.contextWindow = this.windowFor(state.model);
  }

  /**
   * 上下文窗口：先认 config.toml 里给这个模型写死的 context_window（grok 自己
   * 压缩也按这个数），没有再退回引擎 init 报的 totalContextTokens。中转模型
   * 的目录常常只报 128k，压过配置会让界面和真实压缩线对不上。
   */
  private windowFor(modelId?: string): number | undefined {
    const id = modelId || this.models[0]?.modelId;
    if (id && this.ctxFallback[id] > 0) return this.ctxFallback[id];
    const fromEngine = this.models.find((m) => m.modelId === id || m.name === id)?.contextTokens;
    if (fromEngine && fromEngine > 0) return fromEngine;
    const def = this.models[0];
    if (def?.contextTokens) return def.contextTokens;
    return def ? this.ctxFallback[def.modelId] : undefined;
  }

  /** config.toml 的 [[model.X]] context_window，键是模型 id */
  setContextFallback(map: Record<string, number>): void {
    this.ctxFallback = { ...map };
    for (const state of this.sessions.values()) {
      const win = this.windowFor(state.model);
      if (!win || win === state.contextWindow) continue;
      state.contextWindow = win;
      this.emitEvent({ type: "meta", sessionId: state.id, patch: { contextWindow: win } });
    }
  }

  setCompactThreshold(percent?: number): void {
    if (!percent || percent <= 0 || percent > 100) return;
    this.compactPercent = percent;
    for (const state of this.sessions.values()) {
      state.compactAt = percent;
      this.emitEvent({ type: "meta", sessionId: state.id, patch: { compactAt: percent } });
    }
  }

  async createSession(cwd?: string): Promise<SessionState> {
    if (!this.client) throw new Error("引擎尚未启动");
    const target = cwd || this.defaultCwd;
    const resp = await this.client.request(
      "session/new",
      {
        cwd: target,
        mcpServers: [],
        _meta: { yoloMode: this.mode === "always-approve" },
      },
      120_000,
    );
    const id = String(resp.sessionId);
    const state = this.newState(id, target);
    this.applyConfig(state, resp.configOptions ?? []);
    this.sessions.set(id, state);
    this.order.unshift(id);
    this.emitEvent({ type: "session", session: structuredClone(state) });
    return state;
  }

  async loadSession(id: string, cwd?: string): Promise<SessionState> {
    if (!this.client) throw new Error("引擎尚未启动");
    const existing = this.sessions.get(id);
    if (existing) return existing;
    const target = cwd || this.defaultCwd;
    const summary = await readSessionSummary(id);
    const state = this.newState(id, target);
    state.title = summary?.title?.slice(0, 120) || "历史会话";
    if (summary?.model) state.model = summary.model;
    state.updatedAt = summary?.updatedAt && summary.updatedAt > 0 ? summary.updatedAt : state.updatedAt;
    state.resumed = true;
    this.sessions.set(id, state);
    this.order.unshift(id);
    this.emitEvent({ type: "session", session: structuredClone(state) });

    try {
      const resp = await this.client.request(
        "session/load",
        { sessionId: id, cwd: target, mcpServers: [] },
        240_000,
      );
      this.applyConfig(state, resp?.configOptions ?? []);
      state.resumed = true;
      // Replay arrives as session/update notifications. Fill in from disk only when it did not.
      setTimeout(() => {
        void (async () => {
          const current = this.sessions.get(id);
          if (!current || current.timeline.length > 0) return;
          const history = await readSessionHistory(id);
          if (!history) return;
          current.timeline = history.timeline;
          if (history.model) current.model = history.model;
          if (history.title && !summary?.title) current.title = history.title;
          current.updatedAt = now();
          this.emitEvent({ type: "session", session: structuredClone(current) });
        })();
      }, 2500);
      this.emitEvent({ type: "meta", sessionId: id, patch: { title: state.title, model: state.model, resumed: true } });
      return state;
    } catch (err) {
      const history = await readSessionHistory(id);
      if (history) {
        state.timeline = history.timeline;
        state.title = summary?.title || history.title || "历史会话";
        state.model = state.model || history.model;
        state.resumed = true;
        this.emitEvent({ type: "session", session: structuredClone(state) });
      }
      this.emitEvent({
        type: "notice",
        level: "warn",
        text: `载入会话失败：${err instanceof Error ? err.message : String(err)}`,
      });
      return state;
    }
  }

  async sendPrompt(sessionId: string, text: string): Promise<void> {
    if (!this.client) throw new Error("引擎尚未启动");
    const state = this.sessions.get(sessionId);
    if (!state) throw new Error("会话不存在");
    const trimmed = text.trim();
    if (!trimmed) return;

    this.closeActive(sessionId, "assistant");
    this.closeActive(sessionId, "thought");
    state.timeline.push({ type: "user", id: `i${this.seq++}`, text: trimmed, at: now() });
    state.busy = true;
    state.updatedAt = now();
    this.emitEvent({ type: "item", sessionId, item: state.timeline[state.timeline.length - 1] });
    this.emitEvent({ type: "meta", sessionId, patch: { busy: true, updatedAt: state.updatedAt } });

    try {
      const result = await this.client.request(
        "session/prompt",
        { sessionId, prompt: [{ type: "text", text: trimmed }] },
        0,
      );
      const stop = result?.stopReason;
      if (stop && stop !== "end_turn" && stop !== "cancelled") {
        this.emitEvent({ type: "notice", level: "warn", text: `回合结束：${stop}` });
      }
      // 用量在 prompt 回包的 _meta.usage 里（camelCase），通知里不一定有
      const meta = result?._meta;
      const u = meta?.usage ?? meta;
      if (u && Number(u.totalTokens) > 0) {
        state.usage = {
          inputTokens: Number(u.inputTokens ?? 0),
          outputTokens: Number(u.outputTokens ?? 0),
          cacheReadTokens: Number(u.cachedReadTokens ?? u.cacheReadTokens ?? 0),
          cacheWriteTokens: Number(u.cacheCreationTokens ?? u.cacheWriteTokens ?? 0),
          reasoningTokens: Number(u.reasoningTokens ?? 0),
          totalTokens: Number(u.totalTokens ?? 0),
          costUsd: state.usage.costUsd,
        };
        const modelId = meta?.modelId ? String(meta.modelId) : state.model;
        this.emitEvent({ type: "meta", sessionId, patch: { usage: state.usage, model: modelId } });
      }
    } catch (err) {
      this.emitEvent({
        type: "notice",
        level: "error",
        text: `发送失败：${err instanceof Error ? err.message : String(err)}`,
      });
      state.timeline.push({
        type: "system",
        id: `i${this.seq++}`,
        text: `发送失败：${err instanceof Error ? err.message : String(err)}`,
        at: now(),
        level: "error",
      });
      this.emitEvent({ type: "item", sessionId, item: state.timeline[state.timeline.length - 1] });
    } finally {
      this.finishTurn(sessionId);
    }
  }

  async cancel(sessionId: string): Promise<void> {
    this.client?.notify("session/cancel", { sessionId });
  }

  async setModel(sessionId: string, modelId: string): Promise<void> {
    if (!this.client) return;
    const resp = await this.client.request(
      "session/set_config_option",
      { sessionId, configId: "model", value: modelId },
      30_000,
    );
    const state = this.sessions.get(sessionId);
    if (state) {
      // 引擎不一定在回包里回显 configOptions，成功即以请求值为准
      const echoed = resp?.configOptions?.find?.((c: any) => c.id === "model")?.currentValue;
      state.model = echoed ? String(echoed) : modelId;
      state.contextWindow = this.windowFor(state.model);
      this.emitEvent({
        type: "meta",
        sessionId,
        patch: { model: state.model, contextWindow: state.contextWindow },
      });
    }
  }

  async setMode(sessionId: string, mode: PermissionMode): Promise<void> {
    const state = this.sessions.get(sessionId);
    const current = state?.mode ?? this.mode;
    let cmd = "";
    if (mode === "always-approve") cmd = "/always-approve";
    else if (mode === "auto") cmd = "/auto";
    else if (mode === "plan") cmd = "/plan";
    else if (mode === "ask") {
      if (current === "always-approve") cmd = "/always-approve";
      else if (current === "auto") cmd = "/auto";
      else if (current === "plan") cmd = "/plan";
    }
    if (cmd && current !== mode) {
      await this.sendPrompt(sessionId, cmd);
    }
    if (state) {
      state.mode = mode;
      this.emitEvent({ type: "meta", sessionId, patch: { mode } });
    }
    // ask 也要记下来，否则新建会话仍按上一次的非 ask 模式决定 yoloMode
    this.mode = mode;
  }

  respondPermission(requestId: number, optionId: string): void {
    if (!this.client) return;
    const meta = this.permissions.get(requestId);
    if (!meta) return;
    const result =
      optionId === "__cancel__"
        ? { outcome: { outcome: "cancelled" } }
        : { outcome: { outcome: "selected", optionId } };
    this.client.respond(requestId, result);
    this.permissions.delete(requestId);
    const state = this.sessions.get(meta.sessionId);
    if (!state) return;
    const item = state.timeline.find((i) => i.id === meta.itemId);
    if (item && item.type === "permission") {
      item.resolvedOptionId = optionId;
      state.pendingPermissions = Math.max(0, state.pendingPermissions - 1);
      this.emitEvent({ type: "item", sessionId: state.id, item: structuredClone(item) });
      this.emitEvent({
        type: "meta",
        sessionId: state.id,
        patch: { pendingPermissions: state.pendingPermissions },
      });
    }
  }

  // ------------------------------------------------------------- ACP events

  private onNotification({ method, params }: { method: string; params: any }): void {
    switch (method) {
      case "session/update":
      case "_x.ai/session/update":
        this.onSessionUpdate(params);
        break;
      case "x.ai/session_notification":
        this.onXaiSessionNotification(params);
        break;
      case "x.ai/sessions/changed":
        this.onSessionsChanged(params);
        break;
      case "x.ai/mcp/servers_updated":
        for (const s of sanitizeMcpServers(params?.mcpServers ?? [])) this.mcp.set(s.name, s);
        this.emitMcp();
        break;
      case "x.ai/mcp/server_status": {
        const name = String(params?.name ?? "");
        if (!name) break;
        const prev = this.mcp.get(name);
        this.mcp.set(name, {
          name,
          status: String(params?.status ?? prev?.status ?? "pending"),
          source: params?.source ?? prev?.source,
          reason: params?.reason,
          tools: typeof params?.tools === "number" ? params.tools : prev?.tools ?? null,
        });
        this.emitMcp();
        break;
      }
      case "_x.ai/mcp_initialized":
      case "x.ai/mcp_initialized":
        this.mcpToolCount = Number(params?.mcpToolCount ?? 0);
        break;
      case "x.ai/session/prompt_complete":
      case "_x.ai/session/prompt_complete":
        this.finishTurn(String(params?.sessionId ?? ""));
        break;
      case "x.ai/queue/changed": {
        const sid = String(params?.sessionId ?? "");
        const st = this.sessions.get(sid);
        if (st) {
          st.updatedAt = now();
          this.emitEvent({ type: "meta", sessionId: sid, patch: { updatedAt: st.updatedAt } });
        }
        break;
      }
      case "x.ai/session/setup":
      case "_x.ai/session/setup":
        break;
      default:
        break;
    }
  }

  private onSessionsChanged(params: any): void {
    for (const row of params?.upserted ?? []) {
      const st = this.sessions.get(String(row.sessionId));
      if (!st) continue;
      const patch: Partial<SessionState> = {};
      if (row.title) patch.title = row.title;
      if (row.cwd) patch.cwd = row.cwd;
      if (row.modelId) patch.model = row.modelId;
      if (row.activity === "working") patch.busy = true;
      if (row.activity === "idle" || row.activity === "completed") patch.busy = false;
      if (Object.keys(patch).length) {
        Object.assign(st, patch);
        st.updatedAt = now();
        this.emitEvent({ type: "meta", sessionId: st.id, patch });
      }
    }
  }

  private onSessionUpdate(params: any): void {
    const sessionId = String(params?.sessionId ?? "");
    const update = params?.update;
    if (!sessionId || !update) return;
    const state = this.sessions.get(sessionId);
    if (!state) return;

    switch (update.sessionUpdate) {
      case "user_message_chunk": {
        const text = textOf(update.content);
        if (!text) break;
        const idx = update?._meta?.promptIndex ?? "0";
        const key = `${sessionId}:${idx}`;
        let itemId = this.replayUsers.get(key);
        let item = itemId ? state.timeline.find((i) => i.id === itemId) : undefined;
        if (!item || item.type !== "user") {
          itemId = `u${this.seq++}`;
          item = { type: "user", id: itemId, text: "", at: now() };
          state.timeline.push(item);
          this.replayUsers.set(key, itemId);
        }
        item.text += text;
        this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
        break;
      }
      case "agent_message_chunk": {
        this.appendChunk(sessionId, "assistant", textOf(update.content));
        break;
      }
      case "agent_thought_chunk": {
        this.appendChunk(sessionId, "thought", textOf(update.content));
        break;
      }
      case "tool_call":
      case "tool_call_update": {
        this.closeActive(sessionId, "assistant");
        this.closeActive(sessionId, "thought");
        this.upsertTool(sessionId, update);
        break;
      }
      case "plan": {
        const entries: PlanEntry[] = (update.entries ?? []).map((e: any) => ({
          content: String(e.content ?? ""),
          status: String(e.status ?? "pending"),
          priority: e.priority ? String(e.priority) : undefined,
        }));
        state.plan = entries;
        this.emitEvent({ type: "item", sessionId, item: { type: "plan", id: `plan-${sessionId}`, entries, at: now() } });
        break;
      }
      case "session_info_update": {
        if (update.title) {
          state.title = String(update.title);
          this.emitEvent({ type: "meta", sessionId, patch: { title: state.title } });
        }
        break;
      }
      case "available_commands_update": {
        const cmds = update.availableCommands ?? [];
        this.commands = cmds.map((c: any) => ({
          name: c.name,
          description: c.description ?? "",
          hint: c?.input?.hint ?? null,
        }));
        this.emitEvent({
          type: "bootstrap",
          models: this.models,
          commands: this.commands,
          mcpServers: [...this.mcp.values()],
          cwd: this.defaultCwd,
          permissionMode: this.mode,
          agentVersion: this.agentVersion,
        });
        break;
      }
      case "config_option_update": {
        this.applyConfig(state, [update]);
        this.emitEvent({ type: "meta", sessionId, patch: { model: state.model } });
        break;
      }
      case "current_mode_update": {
        const id = String(update.currentModeId ?? "");
        const mapped: PermissionMode | undefined =
          id === "plan"
            ? "plan"
            : id === "always-approve" || id === "yolo"
              ? "always-approve"
              : id === "auto" || id === "auto-review"
                ? "auto"
                : id === "default" || id === "ask"
                  ? "ask"
                  : undefined;
        if (mapped) {
          state.mode = mapped;
          this.emitEvent({ type: "meta", sessionId, patch: { mode: mapped } });
        }
        break;
      }
      case "pending_interaction": {
        // The matching session/request_permission carries the options; nothing to render yet.
        break;
      }
      case "interaction_resolved": {
        break;
      }
      default:
        break;
    }
  }

  private onXaiSessionNotification(params: any): void {
    const sessionId = String(params?.sessionId ?? "");
    const update = params?.update;
    const state = this.sessions.get(sessionId);
    if (!state || !update) return;

    switch (update.sessionUpdate) {
      case "tool_call_delta_chunk": {
        const callId = String(update.tool_call_id ?? "");
        if (!callId) break;
        const id = `t-${callId}`;
        let item = state.timeline.find((i) => i.id === id);
        if (!item) {
          const call: ToolCallView = {
            id: callId,
            title: String(update.name ?? "tool"),
            status: "in_progress",
            startedAt: now(),
          };
          item = { type: "tool", id, call, at: now() };
          state.timeline.push(item);
          this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
        }
        break;
      }
      case "response_completed": {
        if (update.usage) {
          state.usage = {
            inputTokens: Number(update.usage.input_tokens ?? 0),
            outputTokens: Number(update.usage.output_tokens ?? 0),
            cacheReadTokens: Number(update.usage.cache_read_input_tokens ?? 0),
            cacheWriteTokens: Number(update.usage.cache_creation_input_tokens ?? 0),
            reasoningTokens: Number(update.usage.reasoning_tokens ?? 0),
            totalTokens:
              Number(update.usage.input_tokens ?? 0) +
              Number(update.usage.output_tokens ?? 0) +
              Number(update.usage.cache_read_input_tokens ?? 0) +
              Number(update.usage.cache_creation_input_tokens ?? 0),
          };
          this.emitEvent({ type: "meta", sessionId, patch: { usage: state.usage } });
        }
        break;
      }
      case "turn_completed": {
        const u = update.usage;
        const total = Number(u?.totalTokens ?? u?.total_tokens ?? 0);
        if (u && total > 0) {
          state.usage = {
            inputTokens: Number(u.inputTokens ?? u.input_tokens ?? 0),
            outputTokens: Number(u.outputTokens ?? u.output_tokens ?? 0),
            cacheReadTokens: Number(u.cachedReadTokens ?? u.cache_read_input_tokens ?? 0),
            cacheWriteTokens: Number(u.cacheCreationTokens ?? u.cache_creation_input_tokens ?? 0),
            reasoningTokens: Number(u.reasoningTokens ?? u.reasoning_tokens ?? 0),
            totalTokens: total,
          };
          this.emitEvent({ type: "meta", sessionId, patch: { usage: state.usage } });
        }
        this.finishTurn(sessionId);
        break;
      }
      case "session_summary_generated": {
        if (update.session_summary) {
          state.title = String(update.session_summary).slice(0, 120);
          this.emitEvent({ type: "meta", sessionId, patch: { title: state.title } });
        }
        break;
      }
      default:
        break;
    }
  }

  private onRequest(req: AcpRequest): void {
    if (req.method === "session/request_permission") {
      const p = req.params ?? {};
      const sessionId = String(p.sessionId ?? "");
      const state = this.sessions.get(sessionId);
      const options = (p.options ?? []).map((o: any) => ({
        optionId: String(o.optionId),
        name: String(o.name ?? o.optionId),
        kind: o.kind,
      }));
      if (!state) {
        this.client?.respond(req.id, { outcome: { outcome: "cancelled" } });
        return;
      }
      const title = p?.toolCall?.title || p?.toolCall?.kind || "工具调用需要授权";
      const detail = p?.toolCall?.rawInput
        ? JSON.stringify(p.toolCall.rawInput, null, 2).slice(0, 1600)
        : undefined;
      const item: TimelineItem = {
        type: "permission",
        id: `perm-${req.id}`,
        requestId: req.id,
        sessionId,
        title: String(title),
        detail,
        options,
        at: now(),
      };
      state.timeline.push(item);
      state.pendingPermissions += 1;
      this.permissions.set(req.id, { sessionId, itemId: item.id });
      this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
      this.emitEvent({
        type: "meta",
        sessionId,
        patch: { pendingPermissions: state.pendingPermissions },
      });
      return;
    }

    this.client?.respondError(req.id, -32601, `unsupported request: ${req.method}`);
    this.emitEvent({
      type: "notice",
      level: "warn",
      text: `未处理的引擎请求：${req.method}`,
    });
  }

  // ------------------------------------------------------------- primitives

  private appendChunk(sessionId: string, kind: "assistant" | "thought", text: string): void {
    if (!text) return;
    const state = this.sessions.get(sessionId);
    if (!state) return;
    const active = this.activeItems.get(sessionId) ?? {};
    let itemId = active[kind];
    let item = itemId ? state.timeline.find((i) => i.id === itemId) : undefined;
    if (!item || item.type !== kind || !item.streaming) {
      const other = kind === "assistant" ? "thought" : "assistant";
      if (active[other]) this.closeActive(sessionId, other);
      itemId = `i${this.seq++}`;
      item = {
        type: kind,
        id: itemId,
        text: "",
        at: now(),
        streaming: true,
      } as TimelineItem;
      state.timeline.push(item);
      this.activeItems.set(sessionId, { ...active, [kind]: itemId });
      this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
    }
    (item as any).text += text;
    this.emitEvent({ type: "delta", sessionId, itemId: itemId!, kind, text });
  }

  private closeActive(sessionId: string, kind: "assistant" | "thought"): void {
    const active = this.activeItems.get(sessionId);
    if (!active?.[kind]) return;
    const state = this.sessions.get(sessionId);
    const item = state?.timeline.find((i) => i.id === active[kind]);
    if (item && "streaming" in item) {
      item.streaming = false;
      this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
    }
    delete active[kind];
  }

  private finishTurn(sessionId: string): void {
    const state = this.sessions.get(sessionId);
    if (!state) return;
    this.closeActive(sessionId, "assistant");
    this.closeActive(sessionId, "thought");
    if (state.busy) {
      state.busy = false;
      state.updatedAt = now();
      this.emitEvent({ type: "meta", sessionId, patch: { busy: false, updatedAt: state.updatedAt } });
    }
  }

  private upsertTool(sessionId: string, update: any): void {
    const state = this.sessions.get(sessionId);
    if (!state) return;
    const callId = String(update.toolCallId ?? "");
    if (!callId) return;
    const itemId = `t-${callId}`;
    const existing = state.timeline.find((i) => i.id === itemId);
    const statusRaw = String(update.status ?? "in_progress");
    const status: ToolCallView["status"] =
      statusRaw === "completed" || statusRaw === "failed" || statusRaw === "cancelled"
        ? statusRaw
        : "in_progress";
    const input = update.rawInput ?? update?.input ?? update?._meta?.["x.ai/tool"]?.input;
    const output = outputOf(update.rawOutput, update.content);
    const locations = Array.isArray(update.locations) ? update.locations : undefined;
    const prevTitle = existing && existing.type === "tool" ? existing.call.title : "";
    const title = toolTitle(update, input, prevTitle);

    if (existing && existing.type === "tool") {
      existing.call = {
        ...existing.call,
        title,
        status,
        input: input ?? existing.call.input,
        output: output || existing.call.output,
        locations: locations ?? existing.call.locations,
        kind: update.kind ?? update?._meta?.["x.ai/tool"]?.kind ?? existing.call.kind,
        endedAt: status === "completed" || status === "failed" ? now() : existing.call.endedAt,
      };
      this.emitEvent({ type: "item", sessionId, item: structuredClone(existing) });
    } else {
      const call: ToolCallView = {
        id: callId,
        title,
        kind: update.kind ?? update?._meta?.["x.ai/tool"]?.kind,
        status,
        input,
        output: output || undefined,
        locations,
        startedAt: now(),
        endedAt: status === "completed" || status === "failed" ? now() : undefined,
      };
      const item: TimelineItem = { type: "tool", id: itemId, call, at: now() };
      state.timeline.push(item);
      this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
    }
    if (status === "completed" || status === "failed") {
      state.updatedAt = now();
    }
  }

  /** 仅用于自检：伪造一张权限卡，走与真实请求相同的渲染/应答路径 */
  debugPermission(): void {
    const sessionId = this.order[0];
    const state = sessionId ? this.sessions.get(sessionId) : undefined;
    if (!sessionId || !state) return;
    const requestId = 900000 + this.seq++;
    const item: TimelineItem = {
      type: "permission",
      id: `perm-${requestId}`,
      requestId,
      sessionId,
      title: "工具调用需要授权 · 写入文件 · D:\\demo\\report.md",
      detail: '{\n  "file_path": "D:\\\\demo\\\\report.md",\n  "content": "# 示例报告\\n"\n}',
      options: [
        { optionId: "allow_once", name: "允许一次", kind: "allow_once" },
        { optionId: "allow_always", name: "总是允许", kind: "allow_always" },
        { optionId: "reject_once", name: "拒绝", kind: "reject_once" },
      ],
      at: now(),
    };
    state.timeline.push(item);
    state.pendingPermissions += 1;
    this.permissions.set(requestId, { sessionId, itemId: item.id });
    this.emitEvent({ type: "item", sessionId, item: structuredClone(item) });
    this.emitEvent({ type: "meta", sessionId, patch: { pendingPermissions: state.pendingPermissions } });
  }

  private emitMcp(): void {
    this.emitEvent({ type: "mcp", servers: [...this.mcp.values()] });
  }
}

