export type EngineStatus = "starting" | "ready" | "error" | "stopped";

export type PermissionMode = "ask" | "auto" | "plan" | "always-approve";

export interface ModelInfo {
  modelId: string;
  name: string;
  contextTokens?: number;
}

export interface CommandInfo {
  name: string;
  description: string;
  hint?: string | null;
  source?: "builtin" | "skill" | "workflow" | "mcp";
}

export interface McpServerInfo {
  name: string;
  status: "pending" | "ready" | "failed" | "needs-auth" | "disabled" | string;
  source?: string;
  reason?: string;
  tools?: number | null;
}

export interface SessionSummary {
  id: string;
  title: string;
  cwd?: string;
  updated?: string;
  created?: string;
  status?: string;
}

export interface PlanEntry {
  content: string;
  status: "pending" | "in_progress" | "completed" | string;
  priority?: string;
}

export type ToolStatus = "pending" | "in_progress" | "completed" | "failed" | "cancelled";

export interface ToolCallView {
  id: string;
  title: string;
  kind?: string;
  status: ToolStatus;
  input?: unknown;
  output?: string;
  locations?: { path: string }[];
  startedAt: number;
  endedAt?: number;
}

export type TimelineItem =
  | { type: "user"; id: string; text: string; at: number }
  | {
      type: "assistant";
      id: string;
      text: string;
      at: number;
      streaming?: boolean;
      model?: string;
    }
  | { type: "thought"; id: string; text: string; at: number; streaming?: boolean }
  | { type: "tool"; id: string; call: ToolCallView; at: number }
  | {
      type: "permission";
      id: string;
      requestId: number;
      sessionId: string;
      title: string;
      detail?: string;
      options: { optionId: string; name: string; kind?: string }[];
      resolvedOptionId?: string;
      at: number;
    }
  | {
      type: "system";
      id: string;
      text: string;
      at: number;
      level?: "info" | "warn" | "error";
    }
  | { type: "plan"; id: string; entries: PlanEntry[]; at: number };

export interface UsageStats {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  reasoningTokens: number;
  totalTokens: number;
  costUsd?: number;
}

export interface SessionState {
  id: string;
  title: string;
  cwd: string;
  model?: string;
  mode: PermissionMode;
  busy: boolean;
  timeline: TimelineItem[];
  plan: PlanEntry[];
  usage: UsageStats;
  contextWindow?: number;
  /** 引擎自动压缩的阈值百分比（config.toml [session] auto_compact_threshold_percent），默认 85 */
  compactAt?: number;
  createdAt: number;
  updatedAt: number;
  pendingPermissions: number;
  resumed?: boolean;
}

export interface BootstrapInfo {
  grokPath: string;
  grokVersion?: string;
  grokHome: string;
  configPath: string;
  cwd: string;
  home: string;
  platform: string;
  permissionMode: PermissionMode;
  models: ModelInfo[];
  commands: CommandInfo[];
  mcpServers: McpServerInfo[];
  engine: { status: EngineStatus; version?: string; error?: string };
  sessions: SessionSummary[];
  current?: SessionState;
}

export type RendererEvent =
  | { type: "status"; status: EngineStatus; version?: string; error?: string }
  | {
      type: "bootstrap";
      models: ModelInfo[];
      commands: CommandInfo[];
      mcpServers: McpServerInfo[];
      cwd: string;
      permissionMode: PermissionMode;
      agentVersion?: string;
    }
  | { type: "session"; session: SessionState }
  | { type: "delta"; sessionId: string; itemId: string; kind: "assistant" | "thought"; text: string }
  | { type: "item"; sessionId: string; item: TimelineItem }
  | { type: "meta"; sessionId: string; patch: Partial<SessionState> }
  | { type: "sessions"; sessions: SessionSummary[] }
  | { type: "mcp"; servers: McpServerInfo[] }
  /** 引擎重启：之前持有的会话句柄全部失效 */
  | { type: "reset" }
  | { type: "notice"; level: "info" | "warn" | "error"; text: string }
  | { type: "quit" };

export interface AssetTask {
  task: string;
  root: string;
  assetCount: number;
  reportCount: number;
  latestReport?: string;
  updatedAt?: number;
}

export interface SkillEntry {
  name: string;
  description: string;
  source: "grok" | "claude" | "project";
  path: string;
  disabled?: boolean;
}

export interface NewSkillInput {
  name: string;
  description?: string;
  body?: string;
}

export interface SkillInstallResult {
  canceled?: boolean;
  installed: string[];
  skills: SkillEntry[];
}

export interface RuleEntry {
  name: string;
  title: string;
  path: string;
  tokens?: number;
}

export interface ReportEntry {
  task: string;
  title: string;
  path: string;
  updatedAt: number;
  size: number;
}

export type FindingSeverity = "严重" | "高危" | "中危" | "低危" | "未知";

export interface Finding {
  task: string;
  title: string;
  severity: FindingSeverity;
  type: string;
  target?: string;
  path: string;
  updatedAt: number;
  size: number;
}

export interface AssetItem {
  task: string;
  name: string;
  path: string;
  kind: string;
  size: number;
  updatedAt: number;
  lines: number;
  sample: string[];
}

export interface WorkspaceStats {
  tasks: number;
  reports: number;
  findings: { severe: number; high: number; medium: number; low: number; unknown: number };
  assets: number;
  assetEntries: number;
}

/** 一个会话自己的报告与资产；tasks 为空表示这个会话还没碰过任务夹 */
export interface SessionArtifacts {
  tasks: string[];
  findings: Finding[];
  assets: AssetItem[];
}

export interface HttpRequestInput {
  method: string;
  url: string;
  headers?: string;
  body?: string;
  followRedirects?: boolean;
  timeoutMs?: number;
}

export interface HttpResponseView {
  ok: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  bodyBytes: number;
  truncated: boolean;
  ms: number;
  finalUrl: string;
  error?: string;
}

export interface ModelConfig {
  /** [model.<key>] 的表名，也是会话下拉里的值 */
  key: string;
  /** 真正发给 API 的模型 ID；留空表示沿用同名内置模型 */
  model: string;
  name?: string;
  description?: string;
  baseUrl?: string;
  apiKey?: string;
  envKey?: string;
  apiBackend?: string;
  contextWindow?: number;
  temperature?: number;
  topP?: number;
  maxCompletionTokens?: number;
  reasoningSummary?: string;
  /** 块内未受管的原始行（注释与高级字段） */
  extra?: string;
  isDefault?: boolean;
  engineLoaded?: boolean;
}

export interface ModelsConfig {
  path: string;
  defaultKey?: string;
  models: ModelConfig[];
}

export interface ModelConfigInput {
  key: string;
  /** 改名时传旧表名 */
  originalKey?: string;
  model: string;
  name?: string;
  description?: string;
  baseUrl?: string;
  apiKey?: string;
  envKey?: string;
  apiBackend?: string;
  contextWindow?: number;
  temperature?: number;
  topP?: number;
  maxCompletionTokens?: number;
  reasoningSummary?: string;
  extra?: string;
  makeDefault?: boolean;
}

export interface EngineRuntime {
  status: EngineStatus;
  version?: string;
  models: ModelInfo[];
  commands: CommandInfo[];
  mcpServers: McpServerInfo[];
  mode: PermissionMode;
  cwd: string;
}

export interface LogFile {
  name: string;
  path: string;
  size: number;
  updatedAt: number;
}

export interface LogTail {
  path: string;
  text: string;
  size: number;
  truncated: boolean;
}

export interface ModelProbeInput {
  baseUrl?: string;
  apiKey?: string;
  /** 逗号分隔的环境变量名，apiKey 为空时按顺序取第一个有值的 */
  envKey?: string;
  model?: string;
  /** true = 发一条最小对话请求；false/省略 = 只拉 /models */
  chat?: boolean;
}

export interface ModelProbeResult {
  ok: boolean;
  url: string;
  status?: number;
  latencyMs: number;
  models?: string[];
  reply?: string;
  error?: string;
}

export interface TaskFile {
  task: string;
  /** 报告 / 资产 / js / dig / 其它 */
  group: string;
  name: string;
  path: string;
  size: number;
  updatedAt: number;
}

export interface McpServerConfig {
  /** [mcp_servers.<name>] 的表名 */
  name: string;
  command: string;
  args: string[];
  cwd?: string;
  enabled?: boolean;
  env: Record<string, string>;
  /** 块内未受管的原始行（startup_timeout_sec 之类） */
  extra?: string;
}

export interface McpServersConfig {
  path: string;
  servers: McpServerConfig[];
}

export interface McpServerConfigInput {
  name: string;
  /** 改名时传旧表名 */
  originalName?: string;
  command: string;
  args: string[];
  cwd?: string;
  enabled?: boolean;
  env?: Record<string, string>;
  extra?: string;
}

export type ProxyMode = "system" | "manual" | "pool" | "off";

export interface NetworkSettings {
  proxyMode: ProxyMode;
  proxyUrl: string;
}

export interface NetworkStatus extends NetworkSettings {
  /** 实际会传给引擎的代理地址；空字符串表示直连 */
  effective: string;
  /** 跟随系统时解析到的代理，便于排查 */
  systemProxy: string;
  /** 代理池模式下选中的那条，便于排查 */
  poolActive: string;
}

/** MCP 拉起的那个 Chrome 窗口怎么摆 */
export type ChromeMode = "hidden" | "headless" | "visible";

export interface BrowserSettings {
  /** hidden=真 Chrome 放屏幕外（默认）；headless=--headless=new；visible=照旧弹窗 */
  chromeMode: ChromeMode;
}

export type ProxySource = "config" | "free" | "manual";
export type ProxyHealth = "unknown" | "ok" | "bad";

export interface ProxyEntry {
  id: string;
  /** 归一化后的地址，形如 http://1.2.3.4:8080 或 socks5://1.2.3.4:1080 */
  url: string;
  /** 供应商文件里可能带的备注/地区 */
  label?: string;
  source: ProxySource;
  enabled: boolean;
  health: ProxyHealth;
  latencyMs?: number;
  checkedAt?: number;
  error?: string;
}

export interface ProxyPool {
  entries: ProxyEntry[];
  /** 当前选中的代理；空表示用第一条可用 */
  activeId?: string;
  /** 每次重启引擎换下一条（只影响本机 agent 子进程，不动系统代理） */
  rotate: boolean;
  updatedAt?: number;
}

/** 配置里声明的本机客户端端口（Clash 的 mixed-port 之类），本身就是一个可拨的出口 */
export interface ProxyLocalPort {
  port: number;
  /** 该端口认的协议：mixed 两种都认，http / socks5 只认一种 */
  scheme: string;
  /** 配置里的原始键，例如 mixed-port */
  key: string;
}

/** 一份代理配置解析出来长什么样，用来在界面上说清「认出了什么、哪些用不了」 */
export interface ProxyImportStats {
  /** 判定出的文件类型：clash / json / list / base64 / ai / unknown */
  kind: string;
  /** 能直接拨的协议计数，键是 http/https/socks4/socks5 */
  usable: Record<string, number>;
  /** 需要本机客户端转发的节点协议计数，键是 ss/vmess/trojan 等 */
  nodes: Record<string, number>;
  /** 配置里读到的本机客户端端口，例如 Clash 的 mixed-port */
  localPorts: ProxyLocalPort[];
  /** 给界面看的提示，例如「ss 节点要走本机 Clash」 */
  notes: string[];
}

export interface ProxyImportResult {
  pool: ProxyPool;
  added: number;
  /** 本次新入库的条目标识，便于只测新加的这些 */
  addedIds: string[];
  /** 解析到但格式不认识的行数 */
  skipped: number;
  source: string;
  stats: ProxyImportStats;
}

/** 让 AI 从没见过的格式里抽代理，返回它到底做了什么 */
export interface ProxyAiResult extends ProxyImportResult {
  /** 实际用的模型 ID */
  model: string;
  /** 模型自己的说明，例如「抽出 12 条，另有 30 个 ss 节点无法直连」 */
  note: string;
  /** 模型原始输出，抽不出结构化结果时给界面兜底展示 */
  raw?: string;
}

export interface ProxyFreeResult {
  pool: ProxyPool;
  added: number;
  addedIds: string[];
  fetched: number;
  errors: string[];
}

export interface EndpointProbe {
  url: string;
  proxy: string;
  ms: number;
  /** 拿到任何 HTTP 状态码都算网络通 */
  reachable: boolean;
  status?: number;
  error?: string;
}
