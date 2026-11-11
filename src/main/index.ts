import { app, BrowserWindow, dialog, ipcMain, shell } from "electron";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import os from "node:os";
import { EngineManager } from "./manager";
import {
  deleteModelConfig,
  readAutoCompactPercent,
  readModelsConfig,
  saveModelConfig,
  setDefaultModel,
  setSkillDisabled,
} from "./config";
import { listAssetItems, listFindings, listTaskFiles, readTaskFile, workspaceStats } from "./workspace";
import { listLogFiles, readLogTail } from "./logs";
import { sendHttpRequest } from "./http";
import {
  createSkill,
  grokHome,
  installSkillsFromDir,
  installSkillsFromZip,
  launchTui,
  listAssetTasks,
  listReports,
  listRules,
  listSessions,
  listSkills,
  listMcpSummary,
  openPath,
  readPermissionMode,
  resolveGrokPath,
  revealPath,
  skillsRoot,
  taskRoots,
} from "./system";
import { networkStatus, normalizeProxy, probeEndpoint, proxyEnv } from "./proxy";
import {
  addProxy,
  advancePool,
  clearPool,
  fetchFreeProxies,
  importProxyFile,
  importProxyText,
  poolPath,
  readPool,
  removeProxies,
  setPoolActive,
  setPoolRotate,
  setProxyEnabled,
  testProxies,
} from "./proxyPool";
import { readSettings, writeSettings } from "./appSettings";
import { deleteMcpServer, readMcpConfig, saveMcpServer } from "./mcpConfig";
import { probeModel } from "./modelProbe";
import { aiParseProxy } from "./proxyAi";
import { sessionTaskNames } from "./history";
import type {
  BootstrapInfo,
  ChromeMode,
  EndpointProbe,
  HttpRequestInput,
  McpServerConfigInput,
  ModelConfigInput,
  ModelProbeInput,
  ModelsConfig,
  NewSkillInput,
  PermissionMode,
  ProxyMode,
} from "../shared/types";

let win: BrowserWindow | null = null;
let manager: EngineManager | null = null;
const streamFixProxies: ChildProcess[] = [];

/** 中转在 SSE 后续分片里回传空的 tool name，会把工具名覆盖成空串；只有在配置确实指向本机中转时才起修片代理 */
const STREAM_FIX_PORTS = [8787, 8788];

/** 配置里没有 127.0.0.1:8787/8788 就完全不起本地中转，直连上游 */
function relayPortsInUse(): number[] {
  try {
    const text = fs.readFileSync(path.join(grokHome(), "config.toml"), "utf8");
    return STREAM_FIX_PORTS.filter(
      (port) => text.includes(`127.0.0.1:${port}`) || text.includes(`localhost:${port}`),
    );
  } catch {
    return [];
  }
}

/** 自定义标题栏按钮：窗口无边框，放大/最小化/关闭由渲染层画，颜色才能跟主题走 */
function applyWindowTheme(theme: "dark" | "light"): void {
  if (!win || win.isDestroyed()) return;
  const dark = theme !== "light";
  win.setBackgroundColor(dark ? "#060b11" : "#f3f7f9");
}

function portOpen(port: number, host = "127.0.0.1"): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host });
    const done = (open: boolean) => {
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(800);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

async function ensureStreamFixProxy(): Promise<void> {
  const ports = relayPortsInUse();
  if (!ports.length) {
    log("stream-fix proxy: config points at upstream directly, nothing to start");
    return;
  }
  const script = app.isPackaged
    ? path.join(process.resourcesPath, "tools", "stream-fix-proxy.mjs")
    : path.join(app.getAppPath(), "tools", "stream-fix-proxy.mjs");
  if (!fs.existsSync(script)) {
    log(`stream-fix proxy missing: ${script}`);
    return;
  }
  for (const port of ports) {
    if (await portOpen(port)) {
      log(`stream-fix proxy: port ${port} already served`);
      continue;
    }
    const child = spawn(
      process.execPath,
      [
        script,
        String(port),
        "https://api.autorouter.top",
        path.join(grokHome(), "logs", `stream-fix-proxy-${port}.log`),
      ],
      { env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }, windowsHide: true, stdio: "ignore" },
    );
    child.on("exit", (code) => {
      log(`stream-fix proxy ${port} exited: ${code}`);
      const index = streamFixProxies.indexOf(child);
      if (index >= 0) streamFixProxies.splice(index, 1);
    });
    streamFixProxies.push(child);
    log(`stream-fix proxy started port=${port} pid=${child.pid}`);
  }
}
let refreshTimer: NodeJS.Timeout | null = null;

const SEED_CONFIG = `# 天鉴·探微 便携版初始配置（不含任何密钥）
# 到「模型」页填 API Key 与模型，或在这里手写 [model.*]
[models]
default = "deepseek-flash"

[model.deepseek-flash]
model = "deepseek-flash"
name = "DeepSeek 官方 deepseek-flash"
base_url = "https://api.deepseek.com/v1"
env_key = "DEEPSEEK_API_KEY"
context_window = 128000
`;

/**
 * 便携版数据目录：electron-builder 的 portable 目标会把 exe 所在目录写进
 * PORTABLE_EXECUTABLE_DIR。优先用同目录 TanweiConsole-data（配置跟着 exe 走），
 * 本机已装 grok（~/.grok/config.toml 存在）时继续沿用用户目录。
 */
function applyPortableHome(): void {
  const portableDir = process.env.PORTABLE_EXECUTABLE_DIR;
  if (!portableDir || process.env.GROK_HOME) return;
  const local = path.join(portableDir, "TanweiConsole-data");
  const userHome = path.join(os.homedir(), ".grok");
  const hasLocal = fs.existsSync(path.join(local, "config.toml"));
  const hasUser = fs.existsSync(path.join(userHome, "config.toml"));
  if (hasUser && !hasLocal) return;
  try {
    fs.mkdirSync(local, { recursive: true });
    const configPath = path.join(local, "config.toml");
    if (!fs.existsSync(configPath)) fs.writeFileSync(configPath, SEED_CONFIG, "utf8");
  } catch {
    return;
  }
  process.env.GROK_HOME = local;
}

applyPortableHome();

const grokPath = resolveGrokPath();
const defaultCwd = process.env.TANWEI_CWD || os.homedir();
const startupLogPath = path.join(grokHome(), "tanwei-startup.log");
let lastProxyLog: string | undefined;

/** 启动过程落盘：窗口不出、引擎起不来时，用户有地方看原因 */
function log(message: string): void {
  try {
    fs.appendFileSync(startupLogPath, `[${new Date().toISOString()}] ${message}\n`, "utf8");
  } catch {
    /* 日志失败不影响启动 */
  }
}

/**
 * 兼容模式：虚拟机 / 远程桌面 / 显卡驱动异常时，Chromium 可能永远不画第一帧，
 * 于是 ready-to-show 不触发、窗口一直隐藏。此时关掉硬件加速，并靠定时器兜底显示窗口。
 */
const safeMode =
  process.argv.includes("--safe-mode") ||
  process.env.TANWEI_SAFE_MODE === "1" ||
  /^RDP-/i.test(process.env.SESSIONNAME ?? "");
if (safeMode) {
  app.disableHardwareAcceleration();
  app.commandLine.appendSwitch("disable-gpu-compositing");
}

process.on("uncaughtException", (err) => {
  log(`uncaughtException ${err?.stack || err}`);
});
process.on("unhandledRejection", (reason) => {
  log(`unhandledRejection ${reason instanceof Error ? reason.stack : String(reason)}`);
});

function sendEngineEvent(ev: unknown): void {
  if (win && !win.isDestroyed()) win.webContents.send("engine:event", ev);
}

/** 开发态从 build/icon.png 取窗口/任务栏图标；打包后由 exe 内嵌图标负责 */
function windowIcon(): string | undefined {
  if (app.isPackaged) return undefined;
  const candidate = path.join(__dirname, "../../build/icon.png");
  return fs.existsSync(candidate) ? candidate : undefined;
}

function createWindow(): void {
  log("createWindow");
  const icon = windowIcon();
  win = new BrowserWindow({
    width: 1500,
    height: 940,
    minWidth: 1180,
    minHeight: 720,
    show: false,
    backgroundColor: "#060b11",
    // icon 传 undefined 会让 Electron 打 native_image 警告，没图就不传这个键
    ...(icon ? { icon } : {}),
    title: "天鉴·探微 | 安全测试平台",
    titleBarStyle: "hidden",
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webviewTag: false,
      spellcheck: false,
    },
  });

  // 窗口必须可见：ready-to-show 在虚拟机/无 GPU 的会话里可能永远不触发
  const showWindow = (why: string) => {
    if (!win || win.isDestroyed()) return;
    if (win.isVisible()) return;
    log(`show window (${why})`);
    win.show();
  };

  win.once("ready-to-show", () => showWindow("ready-to-show"));
  win.webContents.on("did-finish-load", () => {
    log("did-finish-load");
    setTimeout(() => showWindow("did-finish-load"), 250);
  });
  win.webContents.on("did-fail-load", (_e, code, desc, url) => {
    log(`did-fail-load code=${code} desc=${desc} url=${url}`);
    showWindow("did-fail-load");
  });
  win.webContents.on("render-process-gone", (_e, details) => {
    log(`render-process-gone ${JSON.stringify(details)}`);
  });
  win.on("unresponsive", () => log("window unresponsive"));
  // 兜底：即使渲染层第一帧没画，3 秒后也把窗口显示出来
  setTimeout(() => showWindow("fallback"), 3000);

  win.on("closed", () => {
    win = null;
  });

  const devUrl = process.env["ELECTRON_RENDERER_URL"];
  if (devUrl) {
    void win.loadURL(devUrl);
  } else {
    void win.loadFile(path.join(__dirname, "../renderer/index.html"));
  }

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) void shell.openExternal(url);
    return { action: "deny" };
  });
}

async function ensureEngine(): Promise<EngineManager> {
  if (!manager) {
    manager = new EngineManager(grokPath, defaultCwd);
    manager.on("event", (ev: any) => {
      sendEngineEvent(ev);
      if (ev?.type === "status" && ev.status === "ready") scheduleSessionRefresh(600);
    });
  }
  // 每次拉起引擎前重新解析代理：设置里改过之后，重启引擎即生效
  const status = manager.getStatus().status;
  await applyEngineProxy(status !== "ready" && status !== "starting");
  await manager.start();
  await applyContextFallback();
  return manager;
}

/** config.toml 里的 context_window 兜底：中转模型经��不报窗口，界面不能一直显示「—」 */
async function applyContextFallback(): Promise<void> {
  if (!manager) return;
  try {
    const cfg = await readModelsConfig(grokHome());
    const map: Record<string, number> = {};
    for (const m of cfg.models) {
      if (m.contextWindow && m.contextWindow > 0) map[m.key] = m.contextWindow;
    }
    manager.setContextFallback(map);
    manager.setCompactThreshold(await readAutoCompactPercent(grokHome()));
  } catch {
    /* 读不到配置就只用引擎上报的窗口 */
  }
}

/** 把当前代理（含代理池轮换）写进引擎子进程环境；rotate 只在真正冷启动时换下一条 */
async function applyEngineProxy(rotate: boolean): Promise<void> {
  let net = await networkStatus();
  if (rotate && net.proxyMode === "pool") {
    const pool = readPool();
    const enabled = pool.entries.filter((e) => e.enabled);
    // 第一次进入代理池时先按池里顺序挑；之后每次重启再往后轮换
    if (pool.rotate && pool.activeId && enabled.length > 1) {
      advancePool();
      net = await networkStatus();
    }
  }
  manager?.setExtraEnv({
    ...proxyEnv(net.effective),
    // grok 再把它传给 playwright MCP 启动器，决定那个 Chrome 是隐藏/无头/可见
    TANWEI_CHROME_MODE: readSettings().browser.chromeMode,
  });
  if (net.effective !== lastProxyLog) {
    lastProxyLog = net.effective;
    log(`engine proxy: ${net.effective || "direct"} (${net.proxyMode})`);
  }
}

/** 探测当前默认模型的 /models，确认「这台机器 + 这档代理」真能连出去 */
async function probeNetwork(): Promise<EndpointProbe> {
  const net = await networkStatus();
  const cfg = await readModelsConfig(grokHome());
  const target = cfg.models.find((m) => m.isDefault) ?? cfg.models[0];
  const base = (target?.baseUrl ?? "").replace(/\/+$/, "");
  if (!base) {
    return {
      url: "",
      proxy: net.effective,
      ms: 0,
      reachable: false,
      error: "尚未配置带 base_url 的模型，没地方可探测",
    };
  }
  return probeEndpoint(`${base}/models`, net.effective);
}

function scheduleSessionRefresh(delay = 250): void {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    void refreshSessions();
  }, delay);
}

async function refreshSessions(): Promise<void> {
  try {
    const sessions = await listSessions(grokPath, 120);
    sendEngineEvent({ type: "sessions", sessions });
  } catch {
    /* listing is opportunistic */
  }
}

/** 配置里的模型 + 当前 agent 是否已经加载，用来在界面上标「重启后生效」 */
async function modelsWithEngine(): Promise<ModelsConfig> {
  const cfg = await readModelsConfig(grokHome());
  const loaded = new Set((manager?.getStatus().models ?? []).map((m) => m.modelId));
  return { ...cfg, models: cfg.models.map((m) => ({ ...m, engineLoaded: loaded.has(m.key) })) };
}

function bootstrapInfo(): BootstrapInfo {
  const engine = manager?.getStatus();
  return {
    grokPath,
    grokVersion: engine?.version,
    grokHome: grokHome(),
    configPath: path.join(grokHome(), "config.toml"),
    cwd: defaultCwd,
    home: os.homedir(),
    platform: process.platform,
    permissionMode: readPermissionMode(),
    models: engine?.models ?? [],
    commands: engine?.commands ?? [],
    mcpServers: engine?.mcpServers ?? [],
    engine: { status: engine?.status ?? "stopped", version: engine?.version },
    sessions: [],
  };
}

function registerIpc(): void {
  ipcMain.handle("app:bootstrap", async () => {
    const info = bootstrapInfo();
    info.sessions = await listSessions(grokPath, 120).catch(() => []);
    return info;
  });

  ipcMain.handle("app:start-engine", async () => {
    const m = await ensureEngine();
    return m.getStatus();
  });

  ipcMain.handle("app:refresh-sessions", async () => {
    await refreshSessions();
    return true;
  });

  ipcMain.handle("config:models", async () => modelsWithEngine());

  ipcMain.handle("config:save-model", async (_e, input: ModelConfigInput) => {
    await saveModelConfig(grokHome(), input);
    await applyContextFallback();
    return modelsWithEngine();
  });

  ipcMain.handle("config:delete-model", async (_e, key: string) => {
    await deleteModelConfig(grokHome(), key);
    await applyContextFallback();
    return modelsWithEngine();
  });

  ipcMain.handle("config:set-default", async (_e, key: string) => {
    await setDefaultModel(grokHome(), key);
    await applyContextFallback();
    return modelsWithEngine();
  });

  ipcMain.handle("config:probe-model", async (_e, input: ModelProbeInput) => probeModel(input));

  ipcMain.handle("config:mcp", async () => readMcpConfig(grokHome()));
  ipcMain.handle("config:save-mcp", async (_e, input: McpServerConfigInput) => {
    await saveMcpServer(grokHome(), input);
    return readMcpConfig(grokHome());
  });

  ipcMain.handle("config:delete-mcp", async (_e, name: string) => {
    await deleteMcpServer(grokHome(), name);
    return readMcpConfig(grokHome());
  });

  ipcMain.handle("window:theme", async (_e, theme: "dark" | "light") => {
    applyWindowTheme(theme);
    return theme;
  });

  ipcMain.handle("window:minimize", () => {
    win?.minimize();
    return true;
  });

  ipcMain.handle("window:toggle-maximize", () => {
    if (!win || win.isDestroyed()) return false;
    if (win.isMaximized()) win.unmaximize();
    else win.maximize();
    return win.isMaximized();
  });

  ipcMain.handle("window:close", () => {
    win?.close();
    return true;
  });

  ipcMain.handle("window:is-maximized", () => Boolean(win && !win.isDestroyed() && win.isMaximized()));

  ipcMain.handle("network:get", async () => networkStatus());

  ipcMain.handle(
    "network:save",
    async (_e, input: { proxyMode?: ProxyMode; proxyUrl?: string }) => {
      if (input.proxyMode === "manual") {
        const url = normalizeProxy(input.proxyUrl ?? "");
        if (!/^(https?|socks5?):\/\/[^\s/]+:\d+$/i.test(url)) {
          throw new Error("手动代理需填成 http://127.0.0.1:7897 这样的地址");
        }
        input.proxyUrl = url;
      }
      writeSettings({ network: input });
      const net = await networkStatus();
      log(`network settings saved: mode=${net.proxyMode} effective=${net.effective || "direct"}`);
      return net;
    },
  );

  ipcMain.handle("network:probe", async () => probeNetwork());

  ipcMain.handle("browser:get", () => readSettings().browser);

  ipcMain.handle("browser:save", async (_e, input: { chromeMode?: ChromeMode }) => {
    const saved = writeSettings({ browser: input });
    // 只换环境变量，下次 start/restart 生效；这里同步给 manager，重启即可用
    await applyEngineProxy(false);
    log(`browser settings saved: chromeMode=${saved.browser.chromeMode}`);
    return saved.browser;
  });

  ipcMain.handle("pool:get", () => readPool());

  ipcMain.handle("pool:path", () => poolPath());

  ipcMain.handle("pool:import-file", async () => {
    const res = await dialog.showOpenDialog(win!, {
      title: "导入代理配置文件",
      properties: ["openFile"],
      filters: [
        { name: "代理配置", extensions: ["txt", "json", "csv", "conf", "yaml", "yml"] },
        { name: "全部文件", extensions: ["*"] },
      ],
    });
    if (res.canceled || !res.filePaths[0]) return undefined;
    const result = importProxyFile(res.filePaths[0]);
    log(`proxy pool import: ${path.basename(res.filePaths[0])} +${result.added} skip ${result.skipped}`);
    return result;
  });

  ipcMain.handle("pool:import-text", (_e, text: string) => importProxyText(String(text ?? "")));

  ipcMain.handle("pool:pick-file", async () => {
    const res = await dialog.showOpenDialog(win!, {
      title: "选代理配置文件",
      properties: ["openFile"],
      filters: [
        { name: "代理配置", extensions: ["txt", "json", "csv", "conf", "yaml", "yml", "ini", "list"] },
        { name: "全部文件", extensions: ["*"] },
      ],
    });
    return res.canceled ? undefined : res.filePaths[0];
  });

  // 前端拖进来 / 手填路径的文件，不走系统对话框
  ipcMain.handle("pool:import-path", async (_e, input: { file?: string; text?: string }) => {
    const file = String(input?.file ?? "").trim();
    if (file) {
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) throw new Error(`文件不存在：${file}`);
      const result = importProxyFile(file);
      log(`proxy pool import path: ${path.basename(file)} +${result.added} skip ${result.skipped}`);
      return result;
    }
    return importProxyText(String(input?.text ?? ""));
  });

  ipcMain.handle("pool:ai-parse", async (_e, input: { file?: string; text?: string }) => {
    const file = String(input?.file ?? "").trim();
    if (file && (!fs.existsSync(file) || !fs.statSync(file).isFile())) throw new Error(`文件不存在：${file}`);
    const result = await aiParseProxy({ file: file || undefined, text: file ? undefined : String(input?.text ?? "") });
    log(`proxy pool ai parse: ${file ? path.basename(file) : "paste"} +${result.added} via ${result.model}`);
    return result;
  });

  ipcMain.handle("pool:add", (_e, input: { url: string; label?: string }) =>
    addProxy(String(input?.url ?? ""), input?.label),
  );

  ipcMain.handle("pool:remove", (_e, ids: string[]) => removeProxies(Array.isArray(ids) ? ids : []));

  ipcMain.handle("pool:enable", (_e, input: { id: string; enabled: boolean }) =>
    setProxyEnabled(String(input?.id ?? ""), input?.enabled !== false),
  );

  ipcMain.handle("pool:active", (_e, id?: string) => setPoolActive(id ? String(id) : undefined));

  ipcMain.handle("pool:rotate", (_e, rotate: boolean) => setPoolRotate(rotate === true));

  ipcMain.handle("pool:test", (_e, ids?: string[]) =>
    testProxies(Array.isArray(ids) && ids.length ? ids.map(String) : undefined),
  );

  ipcMain.handle("pool:fetch-free", async (_e, limit?: number) => {
    const result = await fetchFreeProxies(typeof limit === "number" ? limit : 40);
    log(`proxy pool free: +${result.added} (${result.fetched} 条抓到)`);
    return result;
  });

  ipcMain.handle("pool:clear", () => clearPool());

  ipcMain.handle(
    "config:set-skill-disabled",
    async (_e, input: { name: string; path?: string; disabled: boolean }) => {
      const aliases = input.path ? [path.basename(path.dirname(input.path))] : [];
      await setSkillDisabled(grokHome(), input.name, aliases, input.disabled);
      return listSkills();
    },
  );

  ipcMain.handle("engine:restart", async () => {
    const m = await ensureEngine();
    await applyEngineProxy(true);
    await m.restart();
    if (m.getStatus().status === "ready") {
      await m.createSession(defaultCwd).catch(() => undefined);
    }
    scheduleSessionRefresh(700);
    return m.getStatus();
  });

  ipcMain.handle("session:create", async (_e, cwd?: string) => {
    const m = await ensureEngine();
    const state = await m.createSession(cwd);
    scheduleSessionRefresh(400);
    return state;
  });

  ipcMain.handle("session:load", async (_e, { id, cwd }: { id: string; cwd?: string }) => {
    const m = await ensureEngine();
    return m.loadSession(id, cwd);
  });

  ipcMain.handle("session:prompt", async (_e, { sessionId, text }: { sessionId: string; text: string }) => {
    const m = await ensureEngine();
    await m.sendPrompt(sessionId, text);
    scheduleSessionRefresh(800);
    return true;
  });

  ipcMain.handle("session:cancel", async (_e, sessionId: string) => {
    await manager?.cancel(sessionId);
    return true;
  });

  ipcMain.handle("session:set-model", async (_e, { sessionId, modelId }: { sessionId: string; modelId: string }) => {
    await manager?.setModel(sessionId, modelId);
    return true;
  });

  ipcMain.handle("session:set-mode", async (_e, { sessionId, mode }: { sessionId: string; mode: PermissionMode }) => {
    await manager?.setMode(sessionId, mode);
    return true;
  });

  ipcMain.handle("session:permission", async (_e, { requestId, optionId }: { requestId: number; optionId: string }) => {
    manager?.respondPermission(requestId, optionId);
    return true;
  });

  if (process.env.TANWEI_DEBUG_PERM === "1") {
    ipcMain.handle("debug:permission", async () => {
      manager?.debugPermission();
      return true;
    });
  }

  ipcMain.handle("system:pick-folder", async () => {
    const res = await dialog.showOpenDialog(win!, {
      title: "选择工作目录",
      defaultPath: defaultCwd,
      properties: ["openDirectory", "createDirectory"],
    });
    return res.canceled ? undefined : res.filePaths[0];
  });

  ipcMain.handle("system:open-path", async (_e, target: string) => openPath(target));
  ipcMain.handle("system:reveal", async (_e, target: string) => {
    revealPath(target);
    return true;
  });
  ipcMain.handle("system:open-external", async (_e, url: string) => {
    if (/^https?:/i.test(url)) await shell.openExternal(url);
    return true;
  });

  ipcMain.handle("system:assets", async () => listAssetTasks());
  ipcMain.handle("system:reports", async () => listReports());
  ipcMain.handle("system:findings", async () => listFindings());
  ipcMain.handle("system:asset-items", async () => listAssetItems());
  ipcMain.handle("system:stats", async () => workspaceStats());
  ipcMain.handle("system:logs", async () => listLogFiles());
  ipcMain.handle("system:log-tail", async (_e, target: string, lines?: number) => readLogTail(target, lines));
  ipcMain.handle("system:read-task-file", async (_e, target: string) => readTaskFile(target));
  ipcMain.handle("system:task-files", async (_e, task?: string) => listTaskFiles(task));
  ipcMain.handle("system:tasks", async () => taskRoots().map((t) => t.task));
  ipcMain.handle("session:tasks", async (_e, sessionId: string) =>
    sessionTaskNames(sessionId, taskRoots().map((t) => t.task)),
  );
  // 本会话自己的报告与资产：任务夹取会话磁盘记录与渲染层已知的并集，没命中就返回空，不回落全局
  ipcMain.handle("session:artifacts", async (_e, input: { sessionId?: string; known?: string[] }) => {
    const known = Array.isArray(input?.known) ? input.known.filter(Boolean) : [];
    const all = taskRoots().map((t) => t.task);
    const fromDisk = input?.sessionId ? await sessionTaskNames(input.sessionId, all) : [];
    const tasks = [...new Set([...known, ...fromDisk])].filter((t) => all.includes(t));
    const [findings, assets] = await Promise.all([listFindings(tasks), listAssetItems(tasks)]);
    return { tasks, findings, assets };
  });
  ipcMain.handle("system:startup-log", async () => {
    let text = "";
    try {
      const raw = await fs.promises.readFile(startupLogPath, "utf8");
      text = raw.split(/\r?\n/).slice(-120).join("\n");
    } catch {
      text = "";
    }
    return { path: startupLogPath, text, safeMode };
  });
  ipcMain.handle("app:relaunch-safe", async () => {
    log("relaunch in safe mode");
    const args = process.argv.slice(1).filter((a) => a !== "--safe-mode");
    app.relaunch({ args: [...args, "--safe-mode"] });
    setTimeout(() => app.exit(0), 200);
    return true;
  });
  ipcMain.handle("system:skills", async () => listSkills());

  ipcMain.handle("skills:install-folder", async (event) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: "选择技能目录（目录里要有 SKILL.md）",
      properties: ["openDirectory"],
    };
    const picked = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    const dir = picked.filePaths?.[0];
    if (picked.canceled || !dir) return { canceled: true, installed: [], skills: await listSkills() };
    const installed = await installSkillsFromDir(dir);
    return { installed, skills: await listSkills() };
  });

  ipcMain.handle("skills:install-zip", async (event) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: "选择技能压缩包",
      properties: ["openFile"],
      filters: [{ name: "技能压缩包", extensions: ["zip"] }],
    };
    const picked = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    const file = picked.filePaths?.[0];
    if (picked.canceled || !file) return { canceled: true, installed: [], skills: await listSkills() };
    const installed = await installSkillsFromZip(file);
    return { installed, skills: await listSkills() };
  });

  ipcMain.handle("skills:create", async (_e, input: NewSkillInput) => {
    await createSkill(input);
    return listSkills();
  });

  ipcMain.handle("skills:open-dir", async () => {
    fs.mkdirSync(skillsRoot(), { recursive: true });
    await shell.openPath(skillsRoot());
    return true;
  });

  ipcMain.handle("system:rules", async () => listRules());
  ipcMain.handle("system:mcp", async () => listMcpSummary());

  ipcMain.handle("system:launch-tui", async (_e, cwd?: string) => {
    await launchTui(grokPath, cwd || defaultCwd);
    return true;
  });

  ipcMain.handle("http:send", async (_e, input) => sendHttpRequest(input));

  ipcMain.handle("app:paths", () => ({
    grokPath,
    grokHome: grokHome(),
    configPath: path.join(grokHome(), "config.toml"),
    cwd: defaultCwd,
    platform: process.platform,
    version: app.getVersion(),
    electron: process.versions.electron,
  }));
}

app.whenReady().then(() => {
  log(
    `ready v${app.getVersion()} electron=${process.versions.electron} safeMode=${safeMode} ` +
      `packaged=${app.isPackaged} grok=${grokPath} grokExists=${fs.existsSync(grokPath)}`,
  );
  registerIpc();
  void ensureStreamFixProxy();
  createWindow();
  void ensureEngine().catch((err) => {
    sendEngineEvent({
      type: "status",
      status: "error",
      error: err instanceof Error ? err.message : String(err),
    });
  });

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  manager?.stop();
  manager = null;
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  if (refreshTimer) clearTimeout(refreshTimer);
  manager?.stop();
  streamFixProxies.forEach((child) => child.kill());
  streamFixProxies.length = 0;
});
