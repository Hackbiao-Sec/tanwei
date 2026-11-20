import { app, BrowserWindow, dialog, ipcMain, Notification, shell } from "electron";
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
import { sendRawHttp } from "./rawHttp";
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
  setRuleDisabled,
  taskRoots,
} from "./system";
import { networkStatus, normalizeProxy, probeEndpoint, proxyEnv } from "./proxy";
import {
  addProxy,
  advancePool,
  clearPool,
  ensureClashActive,
  fetchFreeProxies,
  healClashController,
  importProxyFile,
  importProxyText,
  markProxyFailure,
  poolPath,
  readPool,
  removeProxies,
  rotateNow,
  setPoolActive,
  setPoolRotate,
  setPoolRotation,
  setProxyEnabled,
  testProxies,
  testSpeeds,
} from "./proxyPool";
import { clashFastest, clashRotate, clashSelect, clashStatus, setClashController } from "./clash";
import { readSettings, writeSettings } from "./appSettings";
import { buildAssetCatalog } from "./assetsView";
import {
  broadcastNotify,
  drillNotify,
  notifyConfigPath,
  readNotifyConfig,
  removeNotifyChannel,
  saveNotifyChannel,
  setNotifyOptions,
  testNotify,
} from "./notify";
import type { RiskSignal } from "./riskGuard";
import { deleteMcpServer, readMcpConfig, saveMcpServer } from "./mcpConfig";
import { probeMcpServer } from "./mcpProbe";
import {
  analyzeTarget,
  appLabel,
  buildMobilePrompt,
  listDeviceApps,
  mobileDynamic,
  mobileEnv,
  mobileOutRoot,
  pullDeviceApk,
  scanTargets,
} from "./mobile";
import {
  claimMobileRecord,
  clearMobileHistory,
  forgetMobileRecord,
  listMobileHistory,
  rememberMobileAnalysis,
} from "./mobileHistory";
import {
  adbAction,
  ensureToolPath,
  findToolPath,
  installTool,
  installTools,
  invalidateToolReport,
  miniLibraryDirs,
  openToolDir,
  probePython,
  toolReport,
} from "./mobileTools";
import { addUploads, claimUpload, clearUploads, forgetUpload, listUploads, uploadRoot } from "./uploads";
import { probeModel } from "./modelProbe";
import { aiParseProxy } from "./proxyAi";
import { deleteSessionDir, sessionTaskNames } from "./history";
import {
  allBindings,
  bindTask,
  boundTasks,
  excludedTasks,
  forgetSession,
  markSessionActive,
  noteSessionTools,
  onScopeChanged,
  startScopeWatch,
  stopScopeWatch,
  unbindTask,
} from "./sessionScope";
import type {
  AdbActionInput,
  BootstrapInfo,
  ChromeMode,
  EndpointProbe,
  HttpRequestInput,
  McpProbeInput,
  McpServerConfigInput,
  MobileAnalysis,
  MobileDynamicInput,
  MobileEnvInfo,
  MobileKind,
  MobilePentestMode,
  ModelConfigInput,
  ModelProbeInput,
  ModelsConfig,
  NewSkillInput,
  PermissionMode,
  ProxyMode,
  ProxyPool,
  TaskFile,
  TurnReport,
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
  const dark = theme === "dark";
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

/** 会话归属变了（新绑定 / 解绑 / 桌面新任务夹）就通知界面重拉，别等用户手动刷新 */
function broadcastScopeChanged(): void {
  if (win && !win.isDestroyed()) win.webContents.send("scope:changed", Date.now());
}

function formatTokens(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(Math.round(n));
}

function formatDuration(ms: number): string {
  const s = Math.max(1, Math.round(ms / 1000));
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  const rest = s % 60;
  return rest ? `${m} 分 ${rest} 秒` : `${m} 分钟`;
}

/** 回合跑完：窗口不在前台时弹系统通知，同时把结果推到已配置的外部渠道 */
function onTurnDone(report: TurnReport): void {
  const usage = report.usage;
  const lines = [
    `耗时 ${formatDuration(report.durationMs)} · 工具 ${report.toolCount} 次${
      report.failedTools > 0 ? `（失败 ${report.failedTools}）` : ""
    }`,
    `本轮累计 ${formatTokens(usage?.totalTokens ?? 0)} tokens · 输出 ${formatTokens(
      usage?.outputTokens ?? 0,
    )}${report.cancelled ? " · 已中止" : ""}`,
  ];
  if (report.excerpt) lines.push(report.excerpt);

  const foreground = !!win && !win.isDestroyed() && win.isVisible() && win.isFocused();
  if (!foreground && Notification.isSupported()) {
    const n = new Notification({
      title: `任务完成 · ${report.title}`,
      body: lines.join("\n"),
    });
    n.on("click", () => {
      if (!win || win.isDestroyed()) return;
      if (win.isMinimized()) win.restore();
      win.show();
      win.focus();
    });
    n.show();
  }

  try {
    broadcastNotify({ event: "session", title: `任务完成 · ${report.title}`, lines });
  } catch (err) {
    log(`notify turn-done failed ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * 测试过程中被目标风控：立刻推一条，并把证据同时交给界面。
 * 引擎侧已按会话去抖，这里只负责文案与投递，投递结果由 notify.json 的 recent 记录。
 */
async function onRiskDetected(sig: RiskSignal): Promise<void> {
  log(
    `risk hit [${sig.category}] session=${sig.sessionId} target=${sig.target ?? "-"} evidence=${sig.evidence.slice(0, 120)}`,
  );
  if (win && !win.isDestroyed()) win.webContents.send("risk:event", sig);
  const lines = [
    sig.task ? `会话：${sig.task}` : "",
    sig.target ? `目标：${sig.target}` : "目标：见下面这行证据",
    `证据：${sig.evidence}`,
    `时间：${new Date(sig.at).toLocaleString("zh-CN")}`,
    "建议：换一条出口代理再试；代理池里点「记失败」会顺手切走。",
  ].filter(Boolean);
  try {
    const results = await broadcastNotify({
      event: "ban",
      title: `测试被风控 · ${sig.category}`,
      lines,
    });
    if (!results.length) log("risk notify skipped：没有渠道订阅「被目标封禁 / 风控」，或总开关是关的");
    else if (results.every((r) => !r.ok)) log(`risk notify failed：${results.map((r) => r.error ?? "失败").join("；")}`);
  } catch (err) {
    log(`risk notify failed ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    await rotateOnRisk(sig);
  } catch (err) {
    log(`risk auto rotate failed ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** 风控已经抓到了，就按用户勾的「被封就换」真换一个出口 */
async function rotateOnRisk(sig: RiskSignal): Promise<void> {
  const pool = readPool();
  if (pool.rotation?.onBan === false) return;
  const res = await rotateExit("ban");
  if (res.via === "none") return;
  void broadcastNotify({
    event: "ban",
    title: "已自动换出口",
    lines: [
      `触发：${sig.category}`,
      res.via === "clash"
        ? `方式：切本机 Clash 节点 → ${res.selected ?? "已切换"}（引擎不用重启）`
        : `方式：换代理池条目 → ${res.label ?? "下一条"}`,
    ],
  });
}

/**
 * 导入完顺手把控制口校正一次：订阅文件里的 external-controller 常是模板默认值，
 * 本机客户端真正在跑的地址通常只写在运行配置里。
 */
async function settleClash<T extends { pool: ProxyPool }>(result: T): Promise<T> {
  try {
    const healed = await healClashController();
    if (healed.changed) {
      log(`clash controller: → ${healed.controller ?? "-"}（来自 ${healed.from ? path.basename(healed.from) : "运行配置"}）`);
      return { ...result, pool: healed.pool };
    }
  } catch (err) {
    log(`clash controller heal failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  return result;
}

/**
 * 真换出口：本机 Clash 能切就切节点，出口 IP 立刻变、引擎不用重启；
 * 切不动（没控制口 / 订阅全挂）再退回代理池条目轮换。
 */
async function rotateExit(
  reason: "manual" | "interval" | "ban" | "fastest",
): Promise<{ via: "clash" | "pool" | "none"; selected?: string; label?: string; error?: string }> {
  const pool = readPool();
  if (pool.clash?.controller || pool.clash?.nodes?.length) {
    // 引擎得先走本机 Clash 端口，切节点才算换出口
    const ensured = ensureClashActive();
    if (ensured.changed) log(`clash exit: 当前出口设为本机 ${ensured.url ?? "端口"}`);
    const res = reason === "fastest" ? await clashFastest() : await clashRotate(reason);
    if (!res.error) {
      log(`clash rotate: ${reason} → ${res.to ?? "?"} group=${res.status.group ?? "-"}`);
      win?.webContents.send("pool:event", {
        kind: "clash",
        reason,
        selected: res.to ?? "",
        group: res.status.group,
      });
      return { via: "clash", selected: res.to };
    }
    log(`clash rotate failed: ${res.error}；退回代理池条目`);
  }
  const next = rotateNow(reason === "fastest" ? "fastest" : reason);
  const entry = next.entries.find((e) => e.id === next.activeId);
  if (!entry) return { via: "none" };
  log(`proxy rotation: ${reason} → ${entry.url.replace(/\/\/[^@/]*@/, "//***@")}`);
  win?.webContents.send("pool:event", { kind: "rotated", reason, activeId: next.activeId });
  return { via: "pool", label: entry.label ?? entry.url.replace(/\/\/[^@/]*@/, "//***@") };
}

/** 开发态从 build/icon.png 取窗口/任务栏图标；打包后由 exe 内嵌图标负责 */function windowIcon(): string | undefined {
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
    backgroundColor: "#f3f7f9",
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
    manager.setRiskSink((sig) => void onRiskDetected(sig));
    manager.on("event", (ev: any) => {
      sendEngineEvent(ev);
      // 会话归属：只从这个事件里工具调用的结构化参数认任务夹（正文 / 输出不参与）
      const sid = typeof ev?.sessionId === "string" ? ev.sessionId : "";
      if (sid) {
        markSessionActive(sid);
        try {
          noteSessionTools(sid, ev);
        } catch {
          /* 事件里有循环引用就忽略，归属还有磁盘扫描兜底 */
        }
      }
      if (ev?.type === "turn-done" && ev.report) onTurnDone(ev.report as TurnReport);
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
    // 开了轮换策略就按策略挑（最快 / 避开失败节点），否则沿用原来的顺序轮换
    if (
      pool.rotation?.enabled &&
      (enabled.length > 1 || pool.clash?.controller || pool.clash?.nodes?.length)
    ) {
      await rotateExit(pool.rotation.mode === "fastest" ? "fastest" : "interval");
      net = await networkStatus();
    } else if (pool.rotate && pool.activeId && enabled.length > 1) {
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

/**
 * 定时轮换：只按用户设定的间隔换出口，换完按需重启引擎让 grok 子进程用上新代理。
 * 引擎重启会影响正在跑的会话，所以默认关（rotation.restartEngine）。
 */
let rotateTimer: NodeJS.Timeout | undefined;

function stopRotationTimer(): void {
  if (rotateTimer) {
    clearInterval(rotateTimer);
    rotateTimer = undefined;
  }
}

async function restartEngineForProxy(): Promise<void> {
  const m = await ensureEngine();
  await applyEngineProxy(false);
  await m.restart();
  if (m.getStatus().status === "ready") {
    await m.createSession(defaultCwd).catch(() => undefined);
  }
  scheduleSessionRefresh(700);
}

function scheduleRotationTimer(): void {
  stopRotationTimer();
  const pool = readPool();
  const rot = pool.rotation;
  const enabled = pool.entries.filter((e) => e.enabled);
  const hasClash = Boolean(pool.clash?.controller || pool.clash?.nodes?.length);
  if (!rot?.enabled || (enabled.length < 2 && !hasClash)) return;
  const everyMs = Math.max(30, rot.intervalSec) * 1000;
  rotateTimer = setInterval(() => {
    void (async () => {
      const res = await rotateExit(rot.mode === "fastest" ? "fastest" : "interval");
      log(
        `proxy rotation: interval ${rot.intervalSec}s → ${
          res.via === "clash" ? `clash:${res.selected ?? "?"}` : res.via === "pool" ? res.label : "none"
        }`,
      );
      if (rot.restartEngine && res.via === "pool") await restartEngineForProxy().catch(() => undefined);
      scheduleRotationTimer();
    })();
  }, everyMs);
  rotateTimer.unref?.();
}

/** 新报告落盘就推通知；只比对本进程见过的标题，重启后不重复刷屏 */
let findingSeen: Set<string> | undefined;
let findingTimer: NodeJS.Timeout | undefined;

const SEV_RANK_FOR_NOTIFY: Record<string, number> = { 严重: 4, 高危: 3, 中危: 2, 低危: 1, 未知: 0 };

async function pollFindings(): Promise<void> {
  const findings = await listFindings().catch(() => undefined);
  if (!findings) return;
  const keys = new Set(findings.map((f) => `${f.task}|${f.title}`));
  if (!findingSeen) {
    findingSeen = keys;
    return;
  }
  const fresh = findings.filter((f) => !findingSeen?.has(`${f.task}|${f.title}`));
  findingSeen = keys;
  if (!fresh.length) return;
  const top = [...fresh].sort(
    (a, b) => (SEV_RANK_FOR_NOTIFY[b.severity] ?? 0) - (SEV_RANK_FOR_NOTIFY[a.severity] ?? 0),
  )[0];
  void broadcastNotify({
    event: "finding",
    severity: top.severity,
    title: `新漏洞报告 · ${top.severity}`,
    lines: [
      `标题：${top.title}`,
      `任务：${top.task}`,
      top.target ? `目标：${top.target}` : "",
      fresh.length > 1 ? `另有 ${fresh.length - 1} 篇新报告` : "",
    ],
  });
}

function startFindingWatch(): void {
  if (findingTimer) clearInterval(findingTimer);
  findingTimer = setInterval(() => void pollFindings(), 45_000);
  findingTimer.unref?.();
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

  // 自己拉起 MCP 进程握手，不等引擎重启就能看到延迟、工具数和失败原因
  ipcMain.handle("mcp:probe", async (_e, input: McpProbeInput) => probeMcpServer(input));

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
    return settleClash(result);
  });

  ipcMain.handle("pool:import-text", async (_e, text: string) =>
    settleClash(importProxyText(String(text ?? ""))),
  );

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
      return settleClash(result);
    }
    return settleClash(importProxyText(String(input?.text ?? "")));
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

  ipcMain.handle("pool:speed", async (_e, ids?: string[]) => {
    const result = await testSpeeds(
      Array.isArray(ids) && ids.length ? ids.map(String) : undefined,
      (done, total) => win?.webContents.send("pool:event", { kind: "speed", done, total }),
    );
    log(`proxy speed: ${result.ok}/${result.tested} ok`);
    return result;
  });

  ipcMain.handle("pool:rotation", async (_e, patch: Record<string, unknown>) => {
    const pool = setPoolRotation(patch ?? {});
    scheduleRotationTimer();
    log(
      `proxy rotation: enabled=${pool.rotation?.enabled} every=${pool.rotation?.intervalSec}s mode=${pool.rotation?.mode}`,
    );
    return pool;
  });

  ipcMain.handle("pool:rotate-now", async (_e, input?: { reason?: string; restart?: boolean }) => {
    const reason =
      input?.reason === "ban" || input?.reason === "fastest" || input?.reason === "interval"
        ? input.reason
        : "manual";
    const res = await rotateExit(reason);
    const restart = input?.restart ?? readPool().rotation?.restartEngine === true;
    // 切 Clash 节点出口就变了，不用重启；只有换池条目才需要让引擎重新读代理
    if (restart && res.via === "pool")
      await restartEngineForProxy().catch((err) =>
        log(`proxy rotation restart failed: ${err instanceof Error ? err.message : String(err)}`),
      );
    return { pool: readPool(), via: res.via, selected: res.selected, label: res.label, error: res.error };
  });

  ipcMain.handle("pool:fail", async (_e, input: { id: string; error?: string }) => {
    const id = String(input?.id ?? "");
    let pool = markProxyFailure(id, input?.error ? String(input.error) : undefined);
    const entry = pool.entries.find((e) => e.id === id);
    const rot = pool.rotation;
    // 被封的信号：先记账，再按策略换一条，换完推告警
    if (rot?.onBan) {
      const res = await rotateExit("ban");
      pool = readPool();
      if (rot.restartEngine && res.via === "pool") await restartEngineForProxy().catch(() => undefined);
    }
    void broadcastNotify({
      event: "ban",
      title: "代理疑似被封，已切换出口",
      lines: [
        entry ? `失败节点：${entry.url.replace(/\/\/[^@/]*@/, "//***@")}` : "",
        input?.error ? `原因：${String(input.error).slice(0, 160)}` : "",
        `当前出口：${
          (pool.clash?.selected && `Clash 节点 ${pool.clash.selected}`) ||
          pool.entries.find((e) => e.id === pool.activeId)?.url.replace(/\/\/[^@/]*@/, "//***@") ||
          "无"
        }`,
      ],
    });
    return pool;
  });

  ipcMain.handle("pool:clash", async () => clashStatus());

  ipcMain.handle(
    "pool:clash-controller",
    async (_e, input: { controller?: string; secret?: string; group?: string }) => {
      const pool = setClashController(input ?? {});
      log(`clash controller: ${pool.clash?.controller ?? "-"} group=${pool.clash?.group ?? "auto"}`);
      return { pool, status: await clashStatus(pool.clash) };
    },
  );

  ipcMain.handle("pool:clash-select", async (_e, input: { name: string; group?: string }) => {
    const res = await clashSelect(String(input?.name ?? ""), { group: input?.group });
    log(`clash select: → ${res.to} group=${res.group ?? "-"}`);
    win?.webContents.send("pool:event", { kind: "clash", reason: "manual", selected: res.to, group: res.group });
    return res;
  });

  ipcMain.handle("pool:clash-rotate", async (_e, reason?: string) => {
    const res = await clashRotate(reason === "ban" ? "ban" : "manual");
    log(`clash rotate: ${reason ?? "manual"} → ${res.to ?? res.error ?? "?"}`);
    return res;
  });

  ipcMain.handle("pool:clash-fastest", async () => {
    const res = await clashFastest();
    log(`clash fastest: → ${res.to ?? res.error ?? "?"}（测了 ${Object.keys(res.delays).length} 个）`);
    return res;
  });

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
    // 刚建/刚打开的会话就是用户眼下在用的那个：桌面新任务夹归它
    if (state?.id) markSessionActive(state.id);
    scheduleSessionRefresh(400);
    return state;
  });

  ipcMain.handle("session:load", async (_e, { id, cwd }: { id: string; cwd?: string }) => {
    const m = await ensureEngine();
    // 只是打开会话不算「在跑」：否则用户随手点开一个会话，桌面新任务夹就串到它头上
    return m.loadSession(id, cwd);
  });

  ipcMain.handle("session:prompt", async (_e, { sessionId, text }: { sessionId: string; text: string }) => {
    const m = await ensureEngine();
    markSessionActive(sessionId);
    await m.sendPrompt(sessionId, text);
    scheduleSessionRefresh(800);
    return true;
  });

  ipcMain.handle("session:cancel", async (_e, sessionId: string) => {
    await manager?.cancel(sessionId);
    return true;
  });

  // 删会话：先停掉正在跑的回合、清内存状态，再删磁盘目录，最后广播真实列表
  ipcMain.handle("session:delete", async (_e, sessionId: string) => {
    const id = String(sessionId ?? "").trim();
    if (!id) throw new Error("会话 id 为空");
    // 先让引擎卸载；不卸载的话它握着目录里的文件，Windows 上删不动
    await manager?.closeSession(id);
    const removed = await deleteSessionDir(id);
    // 绑定表里这个会话的归属一起清掉，否则任务夹会一直挂着一个已经没了的会话
    await forgetSession(id);
    broadcastScopeChanged();
    // 重读会话列表要起一次 grok，放后台，别让渲染层的删除按钮等好几秒
    void refreshSessions();
    return { ok: true, id, removed };
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
  // 本会话到底认领了哪些任务夹：绑定表 + 会话落盘记录，只留桌面上真实存在的
  async function sessionTasks(sessionId?: string): Promise<{ all: string[]; tasks: string[] }> {
    const all = taskRoots().map((t) => t.task);
    if (!sessionId) return { all, tasks: [] };
    const [fromBindings, fromDisk, excluded] = await Promise.all([
      boundTasks(sessionId),
      sessionTaskNames(sessionId, all).catch(() => [] as string[]),
      excludedTasks(sessionId).catch(() => [] as string[]),
    ]);
    const ban = new Set(excluded);
    const tasks = [...new Set([...fromBindings, ...fromDisk])].filter((t) => all.includes(t) && !ban.has(t));
    // 落盘记录里认出来的也写进绑定表，下次不靠扫历史（用户解绑过的不再回绑）
    const fresh = tasks.filter((t) => !fromBindings.includes(t));
    if (fresh.length) await Promise.all(fresh.map((t) => bindTask(sessionId, t)));
    return { all, tasks };
  }

  // 会话级产物快照：任务夹 → 报告 / 资产 / 文件，界面「本会话」档位只吃这一份
  ipcMain.handle("session:scope", async (_e, sessionId?: string) => {
    const { all, tasks } = await sessionTasks(sessionId);
    const [findings, assets, files, reports, bindings] = await Promise.all([
      listFindings(tasks),
      listAssetItems(tasks),
      tasks.length
        ? Promise.all(tasks.map((task) => listTaskFiles(task).catch(() => [] as TaskFile[]))).then((rows) => rows.flat())
        : Promise.resolve([] as TaskFile[]),
      listReports(),
      allBindings(),
    ]);
    const owners: Record<string, string[]> = {};
    for (const [id, list] of Object.entries(bindings)) {
      for (const task of list) {
        if (!all.includes(task)) continue;
        (owners[task] ??= []).push(id);
      }
    }
    return {
      sessionId,
      tasks,
      findings,
      assets,
      files: files.slice().sort((a, b) => b.updatedAt - a.updatedAt),
      reports: reports.filter((r) => tasks.includes(r.task)),
      available: all,
      owners,
      orphans: all.filter((task) => !owners[task]?.length),
    };
  });
  ipcMain.handle("session:bind", async (_e, input: { sessionId?: string; task?: string }) => {
    if (!input?.sessionId || !input.task) return false;
    await bindTask(input.sessionId, input.task);
    return true;
  });
  ipcMain.handle("session:unbind", async (_e, input: { sessionId?: string; task?: string }) => {
    if (!input?.sessionId || !input.task) return false;
    await unbindTask(input.sessionId, input.task);
    return true;
  });
  // 兼容旧调用：任务夹取绑定表与落盘记录的并集，没命中就返回空，不回落全局
  ipcMain.handle("session:artifacts", async (_e, input: { sessionId?: string; known?: string[] }) => {
    const known = Array.isArray(input?.known) ? input.known.filter(Boolean) : [];
    const { all, tasks } = await sessionTasks(input?.sessionId);
    const merged = [...new Set([...known, ...tasks])].filter((t) => all.includes(t));
    const [findings, assets] = await Promise.all([listFindings(merged), listAssetItems(merged)]);
    return { tasks: merged, findings, assets };
  });
  // 结构化资产目录：域名 / IP / 接口 / 服务，按主机归组，scope 为会话级隔离的任务名
  ipcMain.handle("assets:catalog", async (_e, scope?: string[]) =>
    buildAssetCatalog(Array.isArray(scope) ? scope.map(String) : undefined),
  );

  ipcMain.handle("notify:get", () => readNotifyConfig());
  ipcMain.handle("notify:path", () => notifyConfigPath());
  ipcMain.handle("notify:save-channel", (_e, input) => saveNotifyChannel(input));
  ipcMain.handle("notify:remove-channel", (_e, id: string) => removeNotifyChannel(String(id ?? "")));
  ipcMain.handle("notify:options", (_e, patch) => setNotifyOptions(patch ?? {}));
  ipcMain.handle("notify:test", async (_e, input) => {
    const result = await testNotify(input ?? {});
    log(`notify test → ${result.channel}: ${result.ok ? "ok" : result.error ?? "failed"} (${result.ms}ms)`);
    return result;
  });
  // 演练：走完整的总开关 + 事件订阅链路，用来分辨「勾选没生效」和「webhook 发不出去」
  ipcMain.handle("notify:drill", async (_e, event?: string) => {
    const ev =
      event === "finding" || event === "ban" || event === "proxy" || event === "session" ? event : "ban";
    try {
      const result = await drillNotify(ev);
      log(`notify drill ${ev} → ${result.passed ? "ok" : result.reason ?? "failed"}`);
      return result;
    } catch (err) {
      log(`notify drill failed ${err instanceof Error ? err.message : String(err)}`);
      return { passed: false, reason: err instanceof Error ? err.message : String(err), results: [] };
    }
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
  ipcMain.handle("rules:set-disabled", async (_e, input: { path: string; disabled: boolean }) => {
    const next = await setRuleDisabled(input.path, input.disabled);
    log(`rules toggle ${input.disabled ? "disable" : "enable"} ${input.path}`);
    return next;
  });
  ipcMain.handle("system:mcp", async () => listMcpSummary());

  // 小程序 / APP 渗透：目标发现、静态拆解、环境探测、打法 prompt
  ipcMain.handle("mobile:out-root", () => mobileOutRoot());
  ipcMain.handle("mobile:pick-dir", async (event) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: "选择小程序目录（源码工程或 wxapkg 所在目录）",
      properties: ["openDirectory"],
    };
    const picked = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    return picked.canceled ? undefined : picked.filePaths[0];
  });
  ipcMain.handle("mobile:pick-app", async (event) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: "选择 APP 安装包",
      properties: ["openFile", "multiSelections"],
      filters: [
        { name: "安装包", extensions: ["apk", "apks", "xapk", "ipa", "wxapkg"] },
        { name: "全部文件", extensions: ["*"] },
      ],
    };
    const picked = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    return picked.canceled ? [] : picked.filePaths;
  });
  ipcMain.handle("mobile:scan", async (_e, dir: string) => {
    const res = await scanTargets(String(dir ?? ""));
    log(`mobile scan ${dir} → ${res.targets.length} 个目标`);
    return res;
  });
  ipcMain.handle(
    "mobile:analyze",
    async (_e, input: { path: string; kind?: MobileKind; name?: string; sessionId?: string }) => {
      const res = await analyzeTarget(input);
      // 拆完就落历史：带上来的会话 id 决定它属于哪个会话，没带就留在总览
      const sessionId = String(input?.sessionId ?? "").trim();
      try {
        await rememberMobileAnalysis(res, sessionId || undefined);
      } catch (err) {
        log(`mobile history 写入失败：${err instanceof Error ? err.message : String(err)}`);
      }
      log(`mobile analyze ${input?.path} → ${res.packageName ?? res.appId ?? "?"}（接口 ${res.endpoints.length}，密钥 ${res.secrets.length}）`);
      return res;
    },
  );
  ipcMain.handle("mobile:history", async (_e, sessionId?: string) => listMobileHistory(sessionId));
  ipcMain.handle("mobile:history-forget", async (_e, id: string) => forgetMobileRecord(String(id ?? "")));
  ipcMain.handle("mobile:history-claim", async (_e, id: string, sessionId?: string) =>
    claimMobileRecord(String(id ?? ""), sessionId),
  );
  ipcMain.handle("mobile:history-clear", async (_e, sessionId?: string) => clearMobileHistory(sessionId));
  ipcMain.handle("mobile:env", async () => mobileEnv());
  // 设备应用：列出已连接设备装的全部应用；显示名按需从设备 APK 里解，带缓存
  ipcMain.handle("mobile:apps", async (_e, serial?: string) => {
    const res = await listDeviceApps(serial ? String(serial) : undefined);
    log(`mobile apps ${res.serial || "?"} → ${res.total} 个（第三方 ${res.thirdParty}）`);
    return res;
  });
  ipcMain.handle(
    "mobile:app-label",
    async (_e, input: { serial?: string; packageName: string; apkPath?: string; versionCode?: string }) =>
      appLabel(input ?? { packageName: "" }),
  );
  // 设备应用 → 本机安装包：拉下来就能当本机 APK 走静态拆解
  ipcMain.handle(
    "mobile:pull-apk",
    async (_e, input: { serial?: string; packageName: string; apkPath?: string }) => {
      const res = await pullDeviceApk(input ?? { packageName: "" });
      log(`mobile pull-apk ${input?.packageName} → ${res.ok ? res.path : res.hint}`);
      return res;
    },
  );
  ipcMain.handle("mobile:dynamic", async (_e, input: MobileDynamicInput) => {
    const res = await mobileDynamic(input);
    log(`mobile dynamic ${input?.action} → ${res.ok ? "ok" : "fail"}${res.hint ? ` (${res.hint})` : ""}`);
    return res;
  });
  ipcMain.handle(
    "mobile:prompt",
    async (
      _e,
      input: { analysis: MobileAnalysis; mode: MobilePentestMode; env?: MobileEnvInfo },
    ) => buildMobilePrompt(input.analysis, input.mode, input.env),
  );

  // 移动端工具链：整体检测 / 一键下载 / 单个下载（都落到探微自己的工具目录）
  ipcMain.handle("toolkit:report", async () => toolReport());
  ipcMain.handle("toolkit:install", async (event, name: string) => {
    const res = await installTool(String(name ?? ""), (p) => {
      if (!event.sender.isDestroyed()) event.sender.send("toolkit:progress", p);
    });
    log(`toolkit install ${name} → ${res.ok ? "ok" : "fail"}`);
    return res;
  });
  ipcMain.handle("toolkit:install-all", async (event, names?: string[]) => {
    const list = Array.isArray(names) ? names.map((n) => String(n)).filter(Boolean) : undefined;
    const res = await installTools(list, (p) => {
      if (!event.sender.isDestroyed()) event.sender.send("toolkit:progress", p);
    });
    log(`toolkit install-all → ${res.filter((r) => r.ok).length}/${res.length}`);
    return res;
  });
  ipcMain.handle("toolkit:probe", async () => {
    const res = await probePython();
    invalidateToolReport();
    log(`toolkit probe python → ${res.ok ? res.path : "找不到"}`);
    return res;
  });
  ipcMain.handle("toolkit:open-root", async () => openToolDir());
  ipcMain.handle("toolkit:open-dir", async (_e, name?: string) =>
    openToolDir(name ? String(name) : undefined),
  );
  ipcMain.handle("mobile:wechat-dirs", async () => miniLibraryDirs());

  // ADB 连接中心：USB / 无线配对 / connect / tcpip / 断开
  ipcMain.handle("adb:action", async (_e, input: AdbActionInput) => {
    const res = await adbAction(input ?? { action: "devices" });
    const first = res.out.split(/\r?\n/).find(Boolean) ?? "";
    log(`adb ${res.action} → ${res.ok ? "ok" : "fail"} ${first}`);
    return res;
  });

  // 对话上传：APK / 小程序包 / 任意文件，按会话归属存到探微上传目录
  ipcMain.handle("upload:pick", async (event) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: "选择要交给探微的文件（APK / IPA / wxapkg / 抓包 / 任意文件）",
      properties: ["openFile", "multiSelections"],
      filters: [
        { name: "移动端安装包", extensions: ["apk", "apks", "xapk", "ipa", "wxapkg", "qapkg", "hap"] },
        { name: "全部文件", extensions: ["*"] },
      ],
    };
    const picked = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    return picked.canceled ? [] : picked.filePaths;
  });
  ipcMain.handle("upload:add", async (_e, files: string[], sessionId?: string) =>
    addUploads(Array.isArray(files) ? files.map((f) => String(f)) : [], sessionId),
  );
  ipcMain.handle("upload:list", async (_e, sessionId?: string) => listUploads(sessionId));
  ipcMain.handle("upload:claim", async (_e, id: string, sessionId?: string) =>
    claimUpload(String(id ?? ""), sessionId),
  );
  ipcMain.handle("upload:forget", async (_e, id: string) => forgetUpload(String(id ?? "")));
  ipcMain.handle("upload:clear", async (_e, sessionId?: string) => clearUploads(sessionId));
  ipcMain.handle("upload:root", () => uploadRoot());

  ipcMain.handle("system:launch-tui", async (_e, cwd?: string) => {
    await launchTui(grokPath, cwd || defaultCwd);
    return true;
  });

  ipcMain.handle("http:send", async (_e, input) => sendHttpRequest(input));
  ipcMain.handle("http:send-raw", async (_e, input) => sendRawHttp(input));

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
  // 探微工具目录前置进 PATH：之后拉起的 grok / adb / jadx 都能直接用
  ensureToolPath();
  scheduleRotationTimer();
  startFindingWatch();
  // 监听桌面新建的任务夹：新夹归最近活跃的会话，归属一变就推给界面
  onScopeChanged(broadcastScopeChanged);
  startScopeWatch();
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
  stopRotationTimer();
  stopScopeWatch();
  if (findingTimer) clearInterval(findingTimer);
  manager?.stop();
  streamFixProxies.forEach((child) => child.kill());
  streamFixProxies.length = 0;
});
