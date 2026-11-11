import { contextBridge, ipcRenderer } from "electron";
import type {
  AssetItem,
  TaskFile,
  AssetTask,
  BootstrapInfo,
  EngineRuntime,
  Finding,
  HttpRequestInput,
  HttpResponseView,
  LogFile,
  LogTail,
  McpServerConfigInput,
  McpServersConfig,
  McpServerInfo,
  ModelConfigInput,
  ModelProbeInput,
  ModelProbeResult,
  ModelsConfig,
  EndpointProbe,
  BrowserSettings,
  NetworkStatus,
  PermissionMode,
  ProxyFreeResult,
  ProxyImportResult,
  ProxyPool,
  RendererEvent,
  ReportEntry,  RuleEntry,
  SessionState,
  SessionArtifacts,
  SkillEntry,
  SkillInstallResult,
  NewSkillInput,
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
  logs: (): Promise<LogFile[]> => ipcRenderer.invoke("system:logs"),
  logTail: (target: string, lines?: number): Promise<LogTail> =>
    ipcRenderer.invoke("system:log-tail", target, lines),
  startupLog: (): Promise<{ path: string; text: string; safeMode: boolean }> =>
    ipcRenderer.invoke("system:startup-log"),
  relaunchSafe: (): Promise<boolean> => ipcRenderer.invoke("app:relaunch-safe"),
  sendRequest: (input: HttpRequestInput): Promise<HttpResponseView> =>
    ipcRenderer.invoke("http:send", input),
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
  importPoolText: (text: string): Promise<ProxyImportResult> => ipcRenderer.invoke("pool:import-text", text),
  addProxy: (url: string, label?: string): Promise<ProxyPool> => ipcRenderer.invoke("pool:add", { url, label }),
  removeProxies: (ids: string[]): Promise<ProxyPool> => ipcRenderer.invoke("pool:remove", ids),
  enableProxy: (id: string, enabled: boolean): Promise<ProxyPool> =>
    ipcRenderer.invoke("pool:enable", { id, enabled }),
  setPoolActive: (id?: string): Promise<ProxyPool> => ipcRenderer.invoke("pool:active", id),
  setPoolRotate: (rotate: boolean): Promise<ProxyPool> => ipcRenderer.invoke("pool:rotate", rotate),
  testProxies: (ids?: string[]): Promise<ProxyPool> => ipcRenderer.invoke("pool:test", ids),
  fetchFreeProxies: (limit?: number): Promise<ProxyFreeResult> => ipcRenderer.invoke("pool:fetch-free", limit),
  clearPool: (): Promise<ProxyPool> => ipcRenderer.invoke("pool:clear"),
  rules: (): Promise<RuleEntry[]> => ipcRenderer.invoke("system:rules"),
  mcp: (): Promise<McpServerInfo[]> => ipcRenderer.invoke("system:mcp"),
};

export type TanweiApi = typeof api;

contextBridge.exposeInMainWorld("tanwei", api);
