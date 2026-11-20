import { contextBridge, ipcRenderer, webUtils } from "electron";
import type {
  AdbActionInput,
  AdbActionResult,
  AssetItem,
  TaskFile,
  AssetTask,
  BootstrapInfo,
  EngineRuntime,
  Finding,
  HttpRequestInput,
  HttpResponseView,
  RawHttpInput,
  RawHttpResult,
  LogFile,
  LogTail,
  McpServerConfigInput,
  McpServersConfig,
  McpServerInfo,
  McpProbeInput,
  McpProbeResult,
  ModelConfigInput,
  ModelProbeInput,
  ModelProbeResult,
  ModelsConfig,
  EndpointProbe,
  BrowserSettings,
  NetworkStatus,
  PermissionMode,
  ProxyFreeResult,
  ProxyAiResult,
  ProxyImportResult,
  ProxyPool,
  ProxyRotation,
  ProxySpeedResult,
  ClashStatus,
  ClashSwitchResult,
  PoolEvent,
  MobileActionResult,
  MobileAnalysis,
  MobileAppList,
  MobileDynamicInput,
  MobileEnvInfo,
  MobileHistoryRecord,
  MobileKind,
  MobilePentestMode,
  MobileScanResult,
  MobileToolInstallResult,
  MobileToolProgress,
  MobileToolReport,
  MobileUpload,
  MiniDirHint,
  NotifyChannel,
  NotifyConfig,
  NotifyDrillResult,
  NotifyTestResult,
  RiskSignal,
  AssetCatalog,
  RendererEvent,
  ReportEntry,  RuleEntry,
  SessionState,
  SessionArtifacts,
  SkillEntry,
  SkillInstallResult,
  NewSkillInput,
  SessionScopeSnapshot,
  WorkspaceStats,
} from "../shared/types";

const api = {
  bootstrap: (): Promise<BootstrapInfo> => ipcRenderer.invoke("app:bootstrap"),
  startEngine: () => ipcRenderer.invoke("app:start-engine"),
  paths: () => ipcRenderer.invoke("app:paths"),
  refreshSessions: () => ipcRenderer.invoke("app:refresh-sessions"),

  modelsConfig: (): Promise<ModelsConfig> => ipcRenderer.invoke("config:models"),
  saveModel: (input: ModelConfigInput): Promise<ModelsConfig> =>
    ipcRenderer.invoke("config:save-model", input),
  deleteModel: (key: string): Promise<ModelsConfig> => ipcRenderer.invoke("config:delete-model", key),
  setDefaultModel: (key: string): Promise<ModelsConfig> => ipcRenderer.invoke("config:set-default", key),
  probeModel: (input: ModelProbeInput): Promise<ModelProbeResult> =>
    ipcRenderer.invoke("config:probe-model", input),
  mcpConfig: (): Promise<McpServersConfig> => ipcRenderer.invoke("config:mcp"),
  saveMcpServer: (input: McpServerConfigInput): Promise<McpServersConfig> =>
    ipcRenderer.invoke("config:save-mcp", input),
  deleteMcpServer: (name: string): Promise<McpServersConfig> =>
    ipcRenderer.invoke("config:delete-mcp", name),
  probeMcpServer: (input: McpProbeInput): Promise<McpProbeResult> =>
    ipcRenderer.invoke("mcp:probe", input),
  setWindowTheme: (theme: "dark" | "light"): Promise<"dark" | "light"> =>
    ipcRenderer.invoke("window:theme", theme),
  minimizeWindow: (): Promise<boolean> => ipcRenderer.invoke("window:minimize"),
  toggleMaximizeWindow: (): Promise<boolean> => ipcRenderer.invoke("window:toggle-maximize"),
  closeWindow: (): Promise<boolean> => ipcRenderer.invoke("window:close"),
  isWindowMaximized: (): Promise<boolean> => ipcRenderer.invoke("window:is-maximized"),
  restartEngine: (): Promise<EngineRuntime> => ipcRenderer.invoke("engine:restart"),

  onEngineEvent: (cb: (ev: RendererEvent) => void): (() => void) => {
    const listener = (_e: Electron.IpcRendererEvent, ev: RendererEvent) => cb(ev);
    ipcRenderer.on("engine:event", listener);
    return () => ipcRenderer.removeListener("engine:event", listener);
  },

  createSession: (cwd?: string): Promise<SessionState> => ipcRenderer.invoke("session:create", cwd),
  loadSession: (id: string, cwd?: string): Promise<SessionState> =>
    ipcRenderer.invoke("session:load", { id, cwd }),
  prompt: (sessionId: string, text: string): Promise<boolean> =>
    ipcRenderer.invoke("session:prompt", { sessionId, text }),
  cancel: (sessionId: string): Promise<boolean> => ipcRenderer.invoke("session:cancel", sessionId),
  deleteSession: (sessionId: string): Promise<{ ok: boolean; id: string; removed: boolean }> =>
    ipcRenderer.invoke("session:delete", sessionId),
  setModel: (sessionId: string, modelId: string): Promise<boolean> =>
    ipcRenderer.invoke("session:set-model", { sessionId, modelId }),
  setMode: (sessionId: string, mode: PermissionMode): Promise<boolean> =>
    ipcRenderer.invoke("session:set-mode", { sessionId, mode }),
  respondPermission: (requestId: number, optionId: string): Promise<boolean> =>
    ipcRenderer.invoke("session:permission", { requestId, optionId }),
  debugPermission: (): Promise<boolean> => ipcRenderer.invoke("debug:permission"),

  pickFolder: (): Promise<string | undefined> => ipcRenderer.invoke("system:pick-folder"),
  openPath: (target: string): Promise<string> => ipcRenderer.invoke("system:open-path", target),
  reveal: (target: string): Promise<boolean> => ipcRenderer.invoke("system:reveal", target),
  openExternal: (url: string): Promise<boolean> => ipcRenderer.invoke("system:open-external", url),
  launchTui: (cwd?: string): Promise<boolean> => ipcRenderer.invoke("system:launch-tui", cwd),

  assets: (): Promise<AssetTask[]> => ipcRenderer.invoke("system:assets"),
  reports: (): Promise<ReportEntry[]> => ipcRenderer.invoke("system:reports"),
  findings: (): Promise<Finding[]> => ipcRenderer.invoke("system:findings"),
  assetItems: (): Promise<AssetItem[]> => ipcRenderer.invoke("system:asset-items"),
  stats: (): Promise<WorkspaceStats> => ipcRenderer.invoke("system:stats"),
  readTaskFile: (target: string): Promise<string> =>
    ipcRenderer.invoke("system:read-task-file", target),
  taskFiles: (task?: string): Promise<TaskFile[]> => ipcRenderer.invoke("system:task-files", task),
  tasks: (): Promise<string[]> => ipcRenderer.invoke("system:tasks"),
  sessionTasks: (sessionId: string): Promise<string[]> => ipcRenderer.invoke("session:tasks", sessionId),
  sessionArtifacts: (sessionId: string | undefined, known: string[]): Promise<SessionArtifacts> =>
    ipcRenderer.invoke("session:artifacts", { sessionId, known }),
  /** 会话级产物快照：任务夹 / 报告 / 资产 / 文件 / 绑定情况，界面「本会话」档位只吃这一份 */
  sessionScope: (sessionId?: string): Promise<SessionScopeSnapshot> =>
    ipcRenderer.invoke("session:scope", sessionId),
  sessionBind: (sessionId: string, task: string): Promise<boolean> =>
    ipcRenderer.invoke("session:bind", { sessionId, task }),
  sessionUnbind: (sessionId: string, task: string): Promise<boolean> =>
    ipcRenderer.invoke("session:unbind", { sessionId, task }),
  onScopeChanged: (cb: () => void): (() => void) => {
    const listener = () => cb();
    ipcRenderer.on("scope:changed", listener);
    return () => ipcRenderer.removeListener("scope:changed", listener);
  },
  logs: (): Promise<LogFile[]> => ipcRenderer.invoke("system:logs"),
  logTail: (target: string, lines?: number): Promise<LogTail> =>
    ipcRenderer.invoke("system:log-tail", target, lines),
  startupLog: (): Promise<{ path: string; text: string; safeMode: boolean }> =>
    ipcRenderer.invoke("system:startup-log"),
  relaunchSafe: (): Promise<boolean> => ipcRenderer.invoke("app:relaunch-safe"),
  sendRequest: (input: HttpRequestInput): Promise<HttpResponseView> =>
    ipcRenderer.invoke("http:send", input),
  sendRawRequest: (input: RawHttpInput): Promise<RawHttpResult> =>
    ipcRenderer.invoke("http:send-raw", input),
  skills: (): Promise<SkillEntry[]> => ipcRenderer.invoke("system:skills"),
  installSkillFolder: (): Promise<SkillInstallResult> => ipcRenderer.invoke("skills:install-folder"),
  installSkillZip: (): Promise<SkillInstallResult> => ipcRenderer.invoke("skills:install-zip"),
  createSkill: (input: NewSkillInput): Promise<SkillEntry[]> =>
    ipcRenderer.invoke("skills:create", input),
  openSkillsDir: (): Promise<boolean> => ipcRenderer.invoke("skills:open-dir"),
  setSkillDisabled: (name: string, skillPath: string, disabled: boolean): Promise<SkillEntry[]> =>
    ipcRenderer.invoke("config:set-skill-disabled", { name, path: skillPath, disabled }),
  network: (): Promise<NetworkStatus> => ipcRenderer.invoke("network:get"),
  saveNetwork: (input: { proxyMode: NetworkStatus["proxyMode"]; proxyUrl: string }): Promise<NetworkStatus> =>
    ipcRenderer.invoke("network:save", input),
  probeNetwork: (): Promise<EndpointProbe> => ipcRenderer.invoke("network:probe"),
  browserSettings: (): Promise<BrowserSettings> => ipcRenderer.invoke("browser:get"),
  saveBrowserSettings: (input: Partial<BrowserSettings>): Promise<BrowserSettings> =>
    ipcRenderer.invoke("browser:save", input),

  pool: (): Promise<ProxyPool> => ipcRenderer.invoke("pool:get"),
  poolPath: (): Promise<string> => ipcRenderer.invoke("pool:path"),
  importPoolFile: (): Promise<ProxyImportResult | undefined> => ipcRenderer.invoke("pool:import-file"),
  pickPoolFile: (): Promise<string | undefined> => ipcRenderer.invoke("pool:pick-file"),
  importPoolText: (text: string): Promise<ProxyImportResult> => ipcRenderer.invoke("pool:import-text", text),
  importPoolPath: (input: { file?: string; text?: string }): Promise<ProxyImportResult> =>
    ipcRenderer.invoke("pool:import-path", input),
  aiParseProxy: (input: { file?: string; text?: string }): Promise<ProxyAiResult> =>
    ipcRenderer.invoke("pool:ai-parse", input),
  addProxy: (url: string, label?: string): Promise<ProxyPool> => ipcRenderer.invoke("pool:add", { url, label }),
  removeProxies: (ids: string[]): Promise<ProxyPool> => ipcRenderer.invoke("pool:remove", ids),
  enableProxy: (id: string, enabled: boolean): Promise<ProxyPool> =>
    ipcRenderer.invoke("pool:enable", { id, enabled }),
  setPoolActive: (id?: string): Promise<ProxyPool> => ipcRenderer.invoke("pool:active", id),
  setPoolRotate: (rotate: boolean): Promise<ProxyPool> => ipcRenderer.invoke("pool:rotate", rotate),
  setPoolRotation: (patch: Partial<ProxyRotation>): Promise<ProxyPool> =>
    ipcRenderer.invoke("pool:rotation", patch),
  rotateNow: (
    input?: { reason?: "manual" | "ban" | "fastest" | "interval"; restart?: boolean },
  ): Promise<{ pool: ProxyPool; via: "clash" | "pool" | "none"; selected?: string; label?: string; error?: string }> =>
    ipcRenderer.invoke("pool:rotate-now", input),
  clashStatus: (): Promise<ClashStatus> => ipcRenderer.invoke("pool:clash"),
  setClashController: (input: {
    controller?: string;
    secret?: string;
    group?: string;
  }): Promise<{ pool: ProxyPool; status: ClashStatus }> => ipcRenderer.invoke("pool:clash-controller", input),
  clashSelect: (input: { name: string; group?: string }): Promise<ClashSwitchResult> =>
    ipcRenderer.invoke("pool:clash-select", input),
  clashRotate: (reason?: string): Promise<{ pool: ProxyPool; status: ClashStatus; to?: string; error?: string }> =>
    ipcRenderer.invoke("pool:clash-rotate", reason),
  clashFastest: (): Promise<{
    pool: ProxyPool;
    status: ClashStatus;
    to?: string;
    delays: Record<string, number>;
    error?: string;
  }> => ipcRenderer.invoke("pool:clash-fastest"),
  // 小程序 / APP 渗透
  mobileOutRoot: (): Promise<string> => ipcRenderer.invoke("mobile:out-root"),
  mobilePickDir: (): Promise<string | undefined> => ipcRenderer.invoke("mobile:pick-dir"),
  mobilePickApp: (): Promise<string[]> => ipcRenderer.invoke("mobile:pick-app"),
  mobileScan: (dir: string): Promise<MobileScanResult> => ipcRenderer.invoke("mobile:scan", dir),
  mobileAnalyze: (input: {
    path: string;
    kind?: MobileKind;
    name?: string;
    sessionId?: string;
  }): Promise<MobileAnalysis> => ipcRenderer.invoke("mobile:analyze", input),
  mobileHistory: (sessionId?: string): Promise<MobileHistoryRecord[]> =>
    ipcRenderer.invoke("mobile:history", sessionId),
  mobileHistoryForget: (id: string): Promise<boolean> => ipcRenderer.invoke("mobile:history-forget", id),
  mobileHistoryClaim: (id: string, sessionId?: string): Promise<boolean> =>
    ipcRenderer.invoke("mobile:history-claim", id, sessionId),
  mobileHistoryClear: (sessionId?: string): Promise<number> =>
    ipcRenderer.invoke("mobile:history-clear", sessionId),
  mobileEnv: (): Promise<MobileEnvInfo> => ipcRenderer.invoke("mobile:env"),
  mobileApps: (serial?: string): Promise<MobileAppList> => ipcRenderer.invoke("mobile:apps", serial),
  mobileAppLabel: (input: {
    serial?: string;
    packageName: string;
    apkPath?: string;
    versionCode?: string;
  }): Promise<{ ok: boolean; label?: string; apkPath?: string; hint?: string }> =>
    ipcRenderer.invoke("mobile:app-label", input),
  mobilePullApk: (input: {
    serial?: string;
    packageName: string;
    apkPath?: string;
  }): Promise<{ ok: boolean; path?: string; hint?: string }> =>
    ipcRenderer.invoke("mobile:pull-apk", input),
  mobileDynamic: (input: MobileDynamicInput): Promise<MobileActionResult> =>
    ipcRenderer.invoke("mobile:dynamic", input),
  mobilePrompt: (input: {
    analysis: MobileAnalysis;
    mode: MobilePentestMode;
    env?: MobileEnvInfo;
  }): Promise<string> => ipcRenderer.invoke("mobile:prompt", input),
  // 移动端工具链：整体检测 / 一键下载 / 单个下载
  toolkitReport: (): Promise<MobileToolReport> => ipcRenderer.invoke("toolkit:report"),
  toolkitInstall: (name: string): Promise<MobileToolInstallResult> =>
    ipcRenderer.invoke("toolkit:install", name),
  toolkitInstallAll: (names?: string[]): Promise<MobileToolInstallResult[]> =>
    ipcRenderer.invoke("toolkit:install-all", names),
  toolkitOpenRoot: (): Promise<boolean> => ipcRenderer.invoke("toolkit:open-root"),
  toolkitProbe: (): Promise<{ ok: boolean; path?: string; version?: string; hint?: string }> =>
    ipcRenderer.invoke("toolkit:probe"),
  toolkitOpenDir: (name?: string): Promise<boolean> => ipcRenderer.invoke("toolkit:open-dir", name),
  onToolkitProgress: (cb: (p: MobileToolProgress) => void): (() => void) => {
    const handler = (_e: unknown, p: MobileToolProgress) => cb(p);
    ipcRenderer.on("toolkit:progress", handler);
    return () => ipcRenderer.off("toolkit:progress", handler);
  },
  wechatDirs: (): Promise<MiniDirHint[]> => ipcRenderer.invoke("mobile:wechat-dirs"),
  // ADB 连接中心
  adbAction: (input: import("../shared/types").AdbActionInput): Promise<AdbActionResult> =>
    ipcRenderer.invoke("adb:action", input),
  // 对话上传
  uploadAdd: (files: string[], sessionId?: string): Promise<MobileUpload[]> =>
    ipcRenderer.invoke("upload:add", files, sessionId),
  uploadList: (sessionId?: string): Promise<MobileUpload[]> =>
    ipcRenderer.invoke("upload:list", sessionId),
  uploadClaim: (id: string, sessionId?: string): Promise<MobileUpload[]> =>
    ipcRenderer.invoke("upload:claim", id, sessionId),
  uploadForget: (id: string): Promise<MobileUpload[]> => ipcRenderer.invoke("upload:forget", id),
  uploadClear: (sessionId?: string): Promise<MobileUpload[]> => ipcRenderer.invoke("upload:clear", sessionId),
  uploadRoot: (): Promise<string> => ipcRenderer.invoke("upload:root"),
  pickFiles: (): Promise<string[]> => ipcRenderer.invoke("upload:pick"),
  pathOfFile: (file: File): string => webUtils.getPathForFile(file),
  markProxyFail: (id: string, error?: string): Promise<ProxyPool> =>
    ipcRenderer.invoke("pool:fail", { id, error }),  testProxies: (ids?: string[]): Promise<ProxyPool> => ipcRenderer.invoke("pool:test", ids),
  testSpeeds: (ids?: string[]): Promise<ProxySpeedResult> => ipcRenderer.invoke("pool:speed", ids),
  onPoolEvent: (cb: (ev: PoolEvent) => void): (() => void) => {
    const handler = (_e: unknown, ev: PoolEvent) => cb(ev);
    ipcRenderer.on("pool:event", handler);
    return () => ipcRenderer.off("pool:event", handler);
  },
  notifyConfig: (): Promise<NotifyConfig> => ipcRenderer.invoke("notify:get"),
  notifyPath: (): Promise<string> => ipcRenderer.invoke("notify:path"),
  saveNotifyChannel: (input: Partial<NotifyChannel> & { url: string }): Promise<NotifyConfig> =>
    ipcRenderer.invoke("notify:save-channel", input),
  removeNotifyChannel: (id: string): Promise<NotifyConfig> =>
    ipcRenderer.invoke("notify:remove-channel", id),
  setNotifyOptions: (patch: Partial<NotifyConfig>): Promise<NotifyConfig> =>
    ipcRenderer.invoke("notify:options", patch),
  testNotify: (input: { id?: string; kind?: string; url?: string; secret?: string; text?: string }): Promise<NotifyTestResult> =>
    ipcRenderer.invoke("notify:test", input),
  drillNotify: (event?: string): Promise<NotifyDrillResult> => ipcRenderer.invoke("notify:drill", event),
  onRiskEvent: (cb: (sig: RiskSignal) => void): (() => void) => {
    const handler = (_e: unknown, sig: RiskSignal) => cb(sig);
    ipcRenderer.on("risk:event", handler);
    return () => ipcRenderer.off("risk:event", handler);
  },
  assetCatalog: (scope?: string[]): Promise<AssetCatalog> => ipcRenderer.invoke("assets:catalog", scope),
  fetchFreeProxies: (limit?: number): Promise<ProxyFreeResult> => ipcRenderer.invoke("pool:fetch-free", limit),
  clearPool: (): Promise<ProxyPool> => ipcRenderer.invoke("pool:clear"),
  rules: (): Promise<RuleEntry[]> => ipcRenderer.invoke("system:rules"),
  setRuleDisabled: (rulePath: string, disabled: boolean): Promise<RuleEntry[]> =>
    ipcRenderer.invoke("rules:set-disabled", { path: rulePath, disabled }),
  mcp: (): Promise<McpServerInfo[]> => ipcRenderer.invoke("system:mcp"),
};

export type TanweiApi = typeof api;

contextBridge.exposeInMainWorld("tanwei", api);
