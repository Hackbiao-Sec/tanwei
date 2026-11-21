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
  /** usage 是流式阶段按输出字符估算的，回合结束会被引擎的真实回包校准 */
  usageEstimated?: boolean;
  contextWindow?: number;
  /** 引擎自动压缩的阈值百分比（config.toml [session] auto_compact_threshold_percent），默认 85 */
  compactAt?: number;
  createdAt: number;
  updatedAt: number;
  pendingPermissions: number;
  resumed?: boolean;
}

/** 一个回合（用户发一次 prompt → agent 停下来）的收尾报告，用于完成推送 */
export interface TurnReport {
  sessionId: string;
  title: string;
  durationMs: number;
  toolCount: number;
  failedTools: number;
  usage: UsageStats;
  excerpt: string;
  cancelled?: boolean;
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
  /** 一个回合结束：结果推送 + 用量校准 */
  | { type: "turn-done"; report: TurnReport }
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
  /** 关闭后文件改名为 *.md.disabled，引擎不再加载 */
  disabled?: boolean;
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

/**
 * 会话级产物快照：一个会话认领的任务夹，以及这些任务夹里的报告、资产、文件。
 * 界面里「本会话」档位只认这份数据；总览另走全局接口。
 */
export interface SessionScopeSnapshot {
  sessionId?: string;
  /** 这个会话认领的任务夹（只含桌面上真实存在的） */
  tasks: string[];
  findings: Finding[];
  assets: AssetItem[];
  files: TaskFile[];
  reports: ReportEntry[];
  /** 桌面上全部任务夹，供手动绑定用 */
  available: string[];
  /** 任务夹 → 认领它的会话 id，用来提示「这个夹是别的会话的」 */
  owners: Record<string, string[]>;
  /** 没有任何会话认领的任务夹 */
  orphans: string[];
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

/** 原始报文重放：按 Yakit 的用法，直接发一整段请求文本 */
export interface RawHttpInput {
  /** 完整原始报文（请求行 + 头 + 空行 + 体）；给了它就以它为准 */
  raw?: string;
  /** raw 里只有 path 时，用它补出协议与主机 */
  url?: string;
  method?: string;
  headers?: string;
  body?: string;
  /** 1.1 = 原始 HTTP/1.1 报文；2 = HTTP/2（ALPN h2） */
  version?: "1.1" | "2";
  skipTlsVerify?: boolean;
  followRedirects?: boolean;
  timeoutMs?: number;
  /** true 时走设置里当前生效的代理；默认不走 */
  useProxy?: boolean;
  proxyUrl?: string;
}

export interface RawHeaderPair {
  name: string;
  value: string;
}

export interface RawTlsInfo {
  protocol?: string;
  cipher?: string;
  alpn?: string;
  subject?: string;
  issuer?: string;
  validTo?: string;
  authorized?: boolean;
}

export interface RawHttpResult {
  ok: boolean;
  status: number;
  statusText: string;
  httpVersion: string;
  headers: RawHeaderPair[];
  /** 解码后的正文（超过上限会截断） */
  body: string;
  bodyBase64: string;
  bodyBytes: number;
  /** 压缩前的线上字节数 */
  wireBytes: number;
  truncated: boolean;
  decompressed: boolean;
  binary: boolean;
  ms: number;
  finalUrl: string;
  requestRaw: string;
  responseRaw: string;
  tls?: RawTlsInfo;
  remote?: string;
  proxy?: string;
  redirects: { status: number; location: string }[];
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

/** 一次 MCP 连接测试：绕过引擎，自己 spawn 子进程做 stdio 握手 */
export interface McpProbeInput {
  name?: string;
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  /** 未受管字段原文；用来读 startup_timeout_sec */
  extra?: string;
  timeoutMs?: number;
}

export interface McpProbeResult {
  ok: boolean;
  latencyMs: number;
  /** 握手用的协议版本，由服务端回包给出 */
  protocolVersion?: string;
  serverName?: string;
  serverVersion?: string;
  toolNames?: string[];
  toolCount?: number;
  error?: string;
  /** 服务端 stderr 尾部，失败时用来定位原因 */
  stderr?: string;
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
  /** 细分来源：付费配置文件的名字，或「免费源 / 手动添加」，界面按它分组 */
  provider?: string;
  enabled: boolean;
  health: ProxyHealth;
  latencyMs?: number;
  checkedAt?: number;
  /** 下载测速结果，单位 KB/s；只有延迟没有吞吐时留空 */
  speedKbps?: number;
  speedAt?: number;
  /** 连续失败次数，智能选路会先避开它 */
  failCount?: number;
  error?: string;
}

/** 自动换代理的策略：定时、按最快、或者被封禁时切 */
export type ProxyRotationMode = "interval" | "fastest" | "smart";

export interface ProxyRotation {
  enabled: boolean;
  /** interval 模式的间隔秒数 */
  intervalSec: number;
  mode: ProxyRotationMode;
  /** 流量被目标站拒绝（403/429/验证页）时自动换一条 */
  onBan: boolean;
  /** 换完是否顺带重启引擎让新出口立刻生效 */
  restartEngine: boolean;
  lastRotatedAt?: number;
}

export interface ProxyPool {
  entries: ProxyEntry[];
  /** 当前选中的代理；空表示用第一条可用 */
  activeId?: string;
  /** 每次重启引擎换下一条（只影响本机 agent 子进程，不动系统代理） */
  rotate: boolean;
  rotation?: ProxyRotation;
  /** 导入 Clash 配置时登记的节点池，靠本机 Clash 的 external-controller 切 */
  clash?: ClashProfile;
  updatedAt?: number;
}

/** Clash / mihomo 配置里读出来的一个节点：Electron 拨不了，但本机客户端能切 */
export interface ClashNode {
  name: string;
  type: string;
  server?: string;
  port?: number;
}

/**
 * 本机 Clash 的控制信息。切节点走 external-controller 的 REST 接口，
 * 出口地址始终是 mixed-port，所以换节点不用重启引擎。
 */
export interface ClashProfile {
  /** external-controller，例如 127.0.0.1:56530 */
  controller?: string;
  secret?: string;
  /** 配置里声明的节点；切换范围以客户端返回的 selector 组为准 */
  nodes: ClashNode[];
  /** 用来切节点的 selector 组名，导入时探测，之后可手改 */
  group?: string;
  /** 本机客户端的混合端口（或 socks 端口），引擎走它出网，换节点时地址不变 */
  port?: number;
  scheme?: "http" | "socks5";
  /** 当前选中的节点名 */
  selected?: string;
  switchedAt?: number;
  /** 最近一次连接 / 切换的错误，界面上直接展示 */
  error?: string;
  /** 从哪份文件读到的控制信息，便于排查 */
  from?: string;
}

/** 本机 Clash 的实时状态：连得上控制口才有，节点列表来自客户端而不是配置文件 */
export interface ClashStatus {
  connected: boolean;
  controller?: string;
  group?: string;
  selected?: string;
  /** 客户端运行模式：global 时只有 GLOBAL 组会换出口 */
  mode?: string;
  groups: { name: string; now?: string; nodes: number }[];
  /** 客户端当前所有可切节点名 */
  nodes: string[];
  error?: string;
}

export interface ClashSwitchResult {
  from?: string;
  to?: string;
  group?: string;
  status: ClashStatus;
  pool: ProxyPool;
}

/** 一次「测速」的结果统计 */
export interface ProxySpeedResult {
  pool: ProxyPool;
  tested: number;
  ok: number;
  failed: number;
}

/** 配置里声明的本机客户端端口（Clash 的 mixed-port 之类），本身就是一个可拨的出口 */
export interface ProxyLocalPort {
  port: number;
  /** 该端口认的协议：mixed 两种都认，http / socks5 只认一种 */
  scheme: "http" | "socks5";
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
  /** Clash 配置里读到的控制口与节点清单；别的格式没有这一项 */
  clash?: ClashProfile;
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

/* --------------------------------------------------------------- 告警通知 --- */

export type NotifyKind = "dingtalk" | "feishu" | "webhook";
export type NotifyEvent = "finding" | "ban" | "proxy" | "session";

export interface NotifyChannel {
  id: string;
  kind: NotifyKind;
  name: string;
  /** 钉钉 / 飞书机器人 webhook 地址，或自定义 webhook */
  url: string;
  /** 钉钉加签密钥 / 飞书签名校验密钥，可空 */
  secret?: string;
  enabled: boolean;
  /** 订阅哪些事件，空表示全部 */
  events: NotifyEvent[];
  lastTestAt?: number;
  lastTestOk?: boolean;
  lastError?: string;
  /** 实际发出去过多少条 */
  sent?: number;
  /** 发送失败的次数（webhook 失效、被限流等） */
  failed?: number;
}

/** 最近一次告警的投递结果，界面用来回答「为什么没收到」 */
export interface NotifyRecent {
  at: number;
  event: NotifyEvent;
  title: string;
  ok: boolean;
  /** 命中并尝试投递的渠道数 */
  channels: number;
  error?: string;
}

export interface NotifyConfig {
  channels: NotifyChannel[];
  /** 本地记录已经通知过的报告，避免重复刷屏 */
  onFinding: boolean;
  onBan: boolean;
  onProxy: boolean;
  /** 只推这档及以上，空表示全部 */
  minSeverity?: FindingSeverity;
  /** 最近 20 条告警记录，含被开关挡下来的 */
  recent?: NotifyRecent[];
  updatedAt?: number;
}

export interface NotifyTestResult {
  ok: boolean;
  channel: string;
  ms: number;
  status?: number;
  error?: string;
}

/** 风控演练：走完整广播链路（开关 + 事件订阅 + 严重度），用来验证勾选是否真的生效 */
export interface NotifyDrillResult {
  /** 有没有渠道被开关放行 */
  passed: boolean;
  reason?: string;
  results: NotifyTestResult[];
}

/* ------------------------------------------------------------- 风控告警 --- */

export type RiskCategory = "限流" | "人机验证" | "WAF 拦截" | "封禁";

/** 测试过程中被目标拦住：从工具输出里认出来的信号 */
export interface RiskSignal {
  sessionId: string;
  category: RiskCategory;
  /** 命中的原文片段，已压成单行 */
  evidence: string;
  /** 被拦的地址 / 主机，能从工具入参里认出来才带 */
  target?: string;
  /** 会话标题，用来在消息里说清是哪一摊在测 */
  task?: string;
  at: number;
}

/* ----------------------------------------------------------------- 资产 --- */

export type AssetKind = "domain" | "ip" | "endpoint" | "service";

export interface AssetRecord {
  id: string;
  /** 原始写法，例如 https://api.example.com/v1/user 或 1.2.3.4:8080 */
  value: string;
  kind: AssetKind;
  host: string;
  /** 接口方法，纯主机条目为空 */
  method?: string;
  /** 路径部分，纯主机条目为空 */
  path?: string;
  task: string;
  file: string;
  line: number;
  updatedAt: number;
}

/** 按主域名聚合，界面左边一列看域名，右边看它下面的接口 */
export interface AssetHostGroup {
  host: string;
  task: string;
  records: AssetRecord[];
  counts: Record<AssetKind, number>;
  updatedAt: number;
}

export interface AssetCatalog {
  records: AssetRecord[];
  hosts: AssetHostGroup[];
  tasks: string[];
  totals: Record<AssetKind, number> & { total: number; hosts: number; tasks: number };
  /** 扫过的资产文件与条数，便于确认「确实读过盘」 */
  files: { task: string; name: string; path: string; entries: number }[];
}

/** 代理池后台事件：轮换结果 / 测速进度 */
export type PoolEvent =
  | { kind: "rotated"; reason: string; activeId?: string }
  | { kind: "speed"; done: number; total: number }
  | { kind: "clash"; reason?: string; selected?: string; group?: string };

/* ---------------- 小程序 / APP 渗透 ---------------- */

export type MobileKind = "wechat" | "uniapp" | "taro" | "wxapkg" | "apk" | "ipa" | "unknown";

/** 扫目录扫到的一个可做目标：小程序源码工程、小程序包、APK 或 IPA */
export interface MobileTarget {
  id: string;
  name: string;
  kind: MobileKind;
  path: string;
  /** 包是文件大小，源码工程是文件数 */
  size: number;
  files?: number;
  appId?: string;
  note?: string;
}

export interface MobileScanResult {
  dir: string;
  scanned: number;
  targets: MobileTarget[];
  truncated: boolean;
  notes: string[];
}

export interface MobileSecret {
  kind: string;
  value: string;
  source: string;
}

export interface MobileComponent {
  type: string;
  name: string;
  exported: boolean;
  permission?: string;
  /** 这个组件自己 intent-filter 里的 scheme://host，可直接拉起 */
  deepLinks?: string[];
  /** 是否带 MAIN/LAUNCHER，桌面图标入口 */
  launcher?: boolean;
}

/** 小程序专属结构：面板按块展示，不再全靠 notes 一句话 */
export interface MiniProfile {
  /** wechat = 原生微信小程序，uniapp = uni-app / Taro 编译工程 */
  source: "wechat" | "uniapp" | "unknown";
  appId?: string;
  pages: string[];
  subPackages: { root: string; count: number; size?: number; independent?: boolean }[];
  tabBar: string[];
  plugins: string[];
  privateInfos: string[];
  /** 云开发环境 id */
  cloudEnv: string[];
  cloudDev: boolean;
  upload: boolean;
  /** 整包字节数（源码目录或解包产物） */
  packageSize?: number;
  /** 体积最大的文件，前 10 */
  heaviest?: { path: string; size: number }[];
  /** app.json 里声明了、但磁盘上没有对应文件的页面 */
  missingPages?: { page: string; missing: string[] }[];
  /** app.json.permission 里的 scope 与申请文案 */
  scopes?: { scope: string; desc: string }[];
  /** 调试残留：sourcemap、urlCheck 关闭、未压缩、私有配置 */
  debugResidue?: string[];
  /** 明文 http / 内网地址这类不可直接用出去的接口 */
  insecure?: string[];
  /** 认出来的框架与 SDK */
  sdks?: string[];
  /** 没被 tabBar 与页面跳转引用的页面（孤儿页） */
  orphanPages?: string[];
}

/** APP 静态结构：包信息、签名、加固、导出组件与深链 */
export interface AppProfile {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: string;
  targetSdk?: string;
  /** Android ABI 目录，IPA 为内嵌 Framework */
  abis: string[];
  signedV1: boolean;
  signedManifest: boolean;
  /** 命中加固特征 */
  guards: string[];
  providers: string[];
  /** intent-filter 里的 scheme / host，形如 https://host 或 myapp:// */
  deepLinks: string[];
  counts: { activity: number; service: number; receiver: number; provider: number };
  /** iOS 最低系统版本 */
  iosMinOs?: string;
  /** 签名方案：v1 = META-INF 证书，v2/v3 = APK Signing Block 里的块 */
  signature?: { v1: boolean; v2: boolean; v3: boolean };
  /** application 节点的安全开关；缺省 = 清单里没写，按平台默认值理解 */
  debugFlags?: {
    debuggable: boolean;
    allowBackup: boolean;
    cleartext: boolean;
    networkSecurityConfig?: string;
    backupAgent?: string;
    testOnly: boolean;
  };
  /** 桌面入口组件 */
  launcher?: string;
  /** native 库（lib/<abi>/xxx.so）的库名与体积 */
  nativeLibs?: { name: string; size: number }[];
  /** dex 与资源里认出来的第三方 SDK / 框架 */
  sdks?: string[];
  /** 证书固定 / 自定义 TrustManager 这类抓包对抗线索 */
  pinning?: string[];
  /** WebView JS 桥 / 动态加载 / 反调试这类运行期线索 */
  runtimeHints?: string[];
  /** dex 个数 */
  dexCount?: number;
  /** 静态看出来的风险基线，面板直接当徽章打 */
  risks?: { level: "high" | "mid" | "low"; text: string }[];
}

/** 一次解包 / 反编译 + 静态提取的结果：界面展示和引擎打法都吃这一份 */
export interface MobileAnalysis {
  target: MobileTarget;
  outDir: string;
  briefPath: string;
  files: number;
  /** true = 已解出源码，false = 只读了包内结构 */
  extracted: boolean;
  appId?: string;
  packageName?: string;
  pages: string[];
  endpoints: string[];
  secrets: MobileSecret[];
  permissions: string[];
  components: MobileComponent[];
  libraries: string[];
  notes: string[];
  log: string[];
  /** 小程序目标的专属结构；APP 目标为 undefined */
  mini?: MiniProfile;
  /** APP 目标的专属结构；小程序为 undefined */
  app?: AppProfile;
}

/**
 * 面板历史记录：拆过一次就留一条，重拆只更新。
 * 面板按 sessionId 过滤，和任务夹 / 发现 / 报告用同一套「本会话 ↔ 总览」语义。
 */
export type MobileHistoryRecord = Omit<MobileAnalysis, "log"> & {
  /** = target.id（sha1(kind + 路径)），列表和选中态都用它 */
  id: string;
  /** 归属会话；空 = 没归属，只出现在总览里 */
  sessionId?: string;
  createdAt: number;
  updatedAt: number;
};

export interface MobileEnvTool {
  name: string;
  ok: boolean;
  version?: string;
  path?: string;
  hint?: string;
  /** 找到了但起不来时的原因；有这一项界面必须标成不可用 */
  launchError?: string;
}

export interface MobileDevice {
  serial: string;
  state: string;
  model?: string;
}

export interface MobileEnvInfo {
  tools: MobileEnvTool[];
  devices: MobileDevice[];
  checkedAt: number;
}

/** 设备上装的一个应用：包名来自 pm，显示名要靠解包里的 label */
export interface MobileAppEntry {
  packageName: string;
  /** 应用显示名（解析 AndroidManifest + resources.arsc 得到） */
  label?: string;
  /** pending = 还没解析；failed = 解析过但读不到 */
  labelState?: "pending" | "done" | "failed";
  versionCode?: string;
  apkPath?: string;
  /** true = 系统预装（pm list packages -s） */
  system: boolean;
  /** 本机已经拆过这个包：静态记录 id */
  recordId?: string;
}

export interface MobileAppList {
  ok: boolean;
  serial: string;
  apps: MobileAppEntry[];
  total: number;
  thirdParty: number;
  cmd: string;
  hint?: string;
  at: number;
}

/**
 * 移动端工具链的一项：设置页「所需工具检测」和 APP 面板都吃这一份。
 * folder / manual 是为了「不自动下载也能装」——用户自己下完按目录放好，重新检测即可。
 */
export interface MobileToolItem {
  name: string;
  title: string;
  group: "android" | "reverse" | "dynamic" | "runtime";
  purpose: string;
  required: boolean;
  ok: boolean;
  version?: string;
  path?: string;
  /** 文件找到了、真启动失败（无扩展名 shim、缺运行时）时的首行错误 */
  launchError?: string;
  /** system = 系统 PATH 里找到；tanwei = 探微工具目录里 */
  from?: "system" | "tanwei";
  installable: boolean;
  installKind: "zip" | "jar" | "pip" | "manual";
  /** 探微工具目录下这一项的落点；手工下载也放这里 */
  folder: string;
  downloadUrl?: string;
  homepage: string;
  /** 手工安装：下什么、放哪、保持什么文件存在 */
  manual: string;
  hint?: string;
}

export interface MobileToolReport {
  root: string;
  /** 已注入到子进程 PATH 的目录 */
  pathDirs: string[];
  items: MobileToolItem[];
  ready: number;
  total: number;
  missing: string[];
  checkedAt: number;
}

export interface MobileToolInstallResult {
  name: string;
  ok: boolean;
  log: string;
  path?: string;
  error?: string;
}

export interface MobileToolProgress {
  name: string;
  phase: "download" | "extract" | "install" | "done" | "error";
  percent?: number;
  message: string;
}

export type AdbAction =
  | "devices"
  | "connect"
  | "pair"
  | "disconnect"
  | "tcpip"
  | "usb"
  | "kill-server"
  | "reconnect"
  | "mdns"
  | "ip";

export interface AdbActionInput {
  action: AdbAction;
  /** host:port 或纯 host（默认补 :5555） */
  target?: string;
  /** Android 11+ 无线调试的 6 位配对码 */
  code?: string;
  /** tcpip 端口，默认 5555 */
  port?: number;
  serial?: string;
}

export interface AdbActionResult {
  ok: boolean;
  action: string;
  cmd: string;
  out: string;
  hint?: string;
  devices?: MobileDevice[];
  at: number;
}

/** 对话里上传的文件：落在会话目录，归属跟着会话走 */
export interface MobileUpload {
  id: string;
  name: string;
  /** 探微会话目录里的绝对路径（引擎直接读这个） */
  path: string;
  /** 用户原始文件路径 */
  origin?: string;
  size: number;
  /** apk / ipa / wxapkg / zip / 其它扩展名 */
  kind: string;
  sessionId?: string;
  at: number;
}

/** 微信小程序包常见存放目录的探测结果 */
export interface MiniDirHint {
  label: string;
  path: string;
  exists: boolean;
  /** 该目录下（限深度）能找到的 *.wxapkg 数量 */
  wxapkg: number;
  note?: string;
}

export type MobilePentestMode = "static" | "dynamic" | "both";

/* ---------------- APP 动态测试：真机 / 模拟器上的可执行动作 ---------------- */

export type MobileDynamicAction =
  | "auto"
  | "devices"
  | "install"
  | "launch"
  | "component"
  | "broadcast"
  | "provider"
  | "proxy-on"
  | "proxy-off"
  | "storage"
  | "logcat"
  | "package"
  | "ports"
  | "backup"
  | "frida"
  | "shell";

export type FridaPreset = "ssl-pinning" | "crypto" | "root-check" | "webview";

export interface MobileDynamicInput {
  action: MobileDynamicAction;
  /** 探微会话 id：apkPath 留空时用它找回本会话上传的安装包 */
  sessionId?: string;
  /** 目标设备序列号；留空取第一台 state=device */
  serial?: string;
  packageName?: string;
  /** install 用：本地 apk 路径 */
  apkPath?: string;
  /** component / broadcast 用：组件全名或 action 名 */
  component?: string;
  /** provider 用：content:// URI */
  uri?: string;
  /** frida 用：脚本模板 */
  preset?: FridaPreset;
  /** shell 用：要在设备上执行的命令 */
  command?: string;
  /** proxy-on 用：host:port，默认 127.0.0.1:7890 */
  proxy?: string;
  /** auto 用：静态分析读到的组件全名（导出优先） */
  components?: string[];
  /** auto 用：静态分析读到的 Provider authority */
  providers?: string[];
  /** auto 用：静态分析读到的深链 URL */
  deepLinks?: string[];
}

/** 自动检测里单条暴露面的判定：hit 拿到东西，open 打通但没出数据，deny 被拦，skip 没测 */
export type MobileAutoVerdict = "hit" | "open" | "deny" | "skip";

export interface MobileAutoCheck {
  /** 被检查的对象：组件全名 / content:// URI / 深链 / 目录 */
  target: string;
  kind: "activity" | "service" | "receiver" | "provider" | "deeplink" | "storage" | "package" | "logcat";
  verdict: MobileAutoVerdict;
  /** 一句话结论：为什么归到这一档 */
  detail: string;
  /** 实际执行的命令 */
  cmd: string;
  /** 出数据的证据行（只留前几行） */
  rows?: string[];
}

export interface MobileActionResult {
  ok: boolean;
  action: MobileDynamicAction;
  title: string;
  /** 实际执行的命令，便于复制重跑 */
  cmd: string;
  out: string;
  /** frida 脚本落盘位置 */
  scriptPath?: string;
  /** 缺工具 / 缺设备 / 需要人工下一步时的说明 */
  hint?: string;
  /** auto 动作的逐条判定 */
  checks?: MobileAutoCheck[];
  at: number;
}
