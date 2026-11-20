import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { app } from "electron";
import { taskRoots } from "./system";

/**
 * 会话 → 任务夹归属。
 *
 * 只靠会话落盘记录里搜 `*_SRC挖洞` 会漏两种情况：正在跑的会话还没落盘；刚建的任务夹还没被 agent 提到。
 * 所以这里存一份可持久化的绑定表，四个来源都往里写：
 *   1. 引擎事件里工具调用的结构化参数（写文件的路径 / 带落盘动作的命令）
 *   2. 会话落盘记录（history.ts 扫 chat_history 里的工具调用）
 *   3. 桌面上新出现的任务夹 + 当时只有一个会话在跑 → 归给它
 *   4. 界面里手动绑定 / 解绑
 * 归属只用来做界面隔离，不参与任何执行约束。
 *
 * 判断一律只看「这个会话真的写过 / 落过东西」的证据。正文、思考、工具输出里提到的路径
 * （贴别人的清单、复盘摘要、验证脚本回显）都不算 —— 否则一个会话会把聊过的目标全认领，
 * 那正是隔离失效的来源。
 */

const SUFFIX = "_SRC挖洞";
/** 会话多久没动静就不算「正在跑」：新任务夹不往它头上认领 */
const BUSY_WINDOW_MS = 5 * 60 * 1000;
/** 任务夹名缓存：事件很密，别每个事件都 readdir */
const NAMES_TTL = 1200;

interface SessionBinding {
  tasks: string[];
  /** 用户手动解绑过的任务夹：磁盘证据再命中也不许自动绑回来 */
  excluded?: string[];
  updatedAt: number;
}

interface BindingsFile {
  version: 1;
  sessions: Record<string, SessionBinding>;
}

let cache: BindingsFile | null = null;
let loading: Promise<void> | null = null;
let saving: Promise<void> | null = null;
let dirty = false;
const listeners = new Set<() => void>();
const busyAt = new Map<string, number>();
let namesCache: { at: number; names: string[] } = { at: 0, names: [] };
let lastForce = 0;
let watchers: fs.FSWatcher[] = [];
let watchTimer: NodeJS.Timeout | null = null;
/** 启动时桌面已存在的任务夹：这些是历史资产，不自动派给正在跑的会话 */
const seen = new Set<string>();

function bindingsPath(): string {
  return path.join(app.getPath("userData"), "session-bindings.json");
}

function notifyChanged(): void {
  for (const cb of listeners) {
    try {
      cb();
    } catch {
      /* 一个订阅者出错不影响其他 */
    }
  }
}

export function onScopeChanged(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

async function ensureLoaded(): Promise<BindingsFile> {
  if (cache) return cache;
  if (!loading) {
    loading = (async () => {
      const sessions: BindingsFile["sessions"] = {};
      try {
        const raw = await fsp.readFile(bindingsPath(), "utf8");
        const data = JSON.parse(raw);
        if (data && typeof data === "object" && data.sessions && typeof data.sessions === "object") {
          for (const [id, val] of Object.entries<any>(data.sessions)) {
            const tasks = Array.isArray(val?.tasks)
              ? [...new Set(val.tasks.filter((t: unknown) => typeof t === "string" && t.trim()))]
              : [];
            const excluded = Array.isArray(val?.excluded)
              ? [...new Set(val.excluded.filter((t: unknown) => typeof t === "string" && t.trim()))]
              : [];
            if (id && (tasks.length || excluded.length)) {
              sessions[id] = {
                tasks: tasks as string[],
                excluded: excluded as string[],
                updatedAt: Number(val?.updatedAt) || 0,
              };
            }
          }
        }
      } catch {
        /* 没有绑定表就是空表 */
      }
      cache = { version: 1, sessions };
    })().finally(() => {
      loading = null;
    });
  }
  await loading;
  return cache!;
}

function scheduleSave(): void {
  dirty = true;
  if (saving) return;
  saving = (async () => {
    while (dirty) {
      dirty = false;
      const data = cache;
      if (!data) continue;
      try {
        const file = bindingsPath();
        await fsp.mkdir(path.dirname(file), { recursive: true });
        const tmp = `${file}.tmp`;
        await fsp.writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
        await fsp.rename(tmp, file);
      } catch {
        /* 存不下不影响本次会话的隔离判断 */
      }
    }
    saving = null;
  })();
}

/** 桌面上现有的任务夹名（带 1.2s 缓存，供高频事件判定用） */
export function knownTaskNames(force = false): string[] {
  const now = Date.now();
  if (!force && now - namesCache.at < NAMES_TTL) return namesCache.names;
  namesCache = { at: now, names: taskRoots().map((t) => t.task) };
  return namesCache.names;
}

async function addTasks(sessionId: string, tasks: string[]): Promise<boolean> {
  const id = sessionId?.trim();
  if (!id || !tasks.length) return false;
  const data = await ensureLoaded();
  const entry: SessionBinding = data.sessions[id] ?? { tasks: [], updatedAt: 0 };
  const skip = new Set(entry.excluded ?? []);
  const set = new Set(entry.tasks);
  let changed = false;
  for (const task of tasks) {
    if (task && !set.has(task) && !skip.has(task)) {
      set.add(task);
      changed = true;
    }
  }
  if (!changed) return false;
  data.sessions[id] = { tasks: [...set], excluded: entry.excluded, updatedAt: Date.now() };
  scheduleSave();
  notifyChanged();
  return true;
}

/**
 * 任务夹是否被真正用过：文本里必须出现 `Desktop\<名>_SRC挖洞` 这种路径形态。
 * 只提到名字（清单、规则示例、复盘总结）不算 —— 否则一个会话会把聊过的所有目标都认领。
 */
export function folderEvidence(text: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`Desktop[\\\\/]+${escaped}${SUFFIX}`, "i").test(text);
}

/** 从一段文本里认出真正被用过的任务夹 */
export function matchTaskFolders(text: string, names: string[]): string[] {
  if (!text || !text.includes(SUFFIX)) return [];
  return names.filter((name) => folderEvidence(text, name));
}

/** 写文件类工具：只看路径字段，避免正文里提到的别的任务夹被当成自己干的 */
const WRITE_TOOLS = new Set(["write", "write_file", "search_replace", "apply_patch", "edit", "edit_file", "create_file"]);
/** 读/查类工具一律不产生归属：读到别处的路径、贴过别人的清单，都不代表这摊是这个会话干的 */
const READ_TOOLS = new Set([
  "read_file",
  "read",
  "list_dir",
  "list",
  "ls",
  "find",
  "grep",
  "glob",
  "web_fetch",
  "web_search",
  "读取文件",
  "列目录",
  "搜索",
  "抓取网页",
]);
const PATH_KEYS = ["file_path", "target_file", "path", "cwd", "dir", "target", "workdir"];
const EXEC_KEYS = ["command", "cmd", "script"];
/** 命令里得真有落东西的动作，才认「这个会话在这一摊干过活」；纯 cat/ls/curl/统计不算 */
const WRITE_HINTS: RegExp[] = [
  /(^|[\s;&|(])(mkdir|md|new-item|ni|touch|set-content|add-content|out-file|tee|tee-object|copy-item|cp|move-item|mv|remove-item|rm|del|sed\s+-i|git\s+(add|commit))\b/i,
  />>?\s*["']?[a-z]:[\\/]/i,
];

function shellWrites(text: string): boolean {
  return WRITE_HINTS.some((re) => re.test(text));
}

function asObject(args: unknown): Record<string, unknown> {
  if (!args) return {};
  if (typeof args === "string") {
    try {
      const parsed = JSON.parse(args);
      return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
    } catch {
      return { command: args };
    }
  }
  return typeof args === "object" ? (args as Record<string, unknown>) : {};
}

/**
 * 从一次工具调用里认出它动过的任务夹。
 * 写文件只认路径字段；执行类要求命令里既有这一摊的路径、又有真正落东西的动作；
 * 读文件 / 列目录 / 搜索 / 抓网页一概不算 —— 读到别处的路径不代表这个会话在这一摊干过活。
 */
export function tasksFromToolCall(name: string, args: unknown, force = false): string[] {
  const tool = (name || "").trim();
  if (!tool) return [];
  if (READ_TOOLS.has(tool.toLowerCase())) return [];
  const obj = asObject(args);
  const evidence: string[] = [];
  if (WRITE_TOOLS.has(tool)) {
    for (const key of PATH_KEYS) {
      const val = obj[key];
      if (typeof val === "string" && val.includes(SUFFIX)) evidence.push(val);
    }
  } else {
    for (const key of EXEC_KEYS) {
      const val = obj[key];
      if (typeof val === "string" && val.includes(SUFFIX) && shellWrites(val)) evidence.push(val);
    }
  }
  if (!evidence.length) return [];
  return matchTaskFolders(evidence.join("\n"), knownTaskNames(force));
}

const KIND_TO_TOOL: Record<string, string> = {
  execute: "run_terminal_command",
  edit: "write",
  write: "write",
  create: "write",
  move: "write",
};

/** 引擎事件里的工具调用：只认结构化的动作类型 + 参数，绝不扫正文、思考、工具输出 */
export function tasksFromEvent(ev: unknown, force = false): string[] {
  const item = (ev as { item?: { type?: string; call?: { kind?: string; title?: string; input?: unknown } } })?.item;
  if (!item || item.type !== "tool") return [];
  let kind = String(item.call?.kind ?? "").toLowerCase();
  if (!kind) {
    // 老版本事件只有标题（形如「写入文件 · 路径」），按标题首段认动作
    const label = String(item.call?.title ?? "").split("·")[0].trim();
    if (label === "编辑文件" || label === "写入文件" || label === "新建") kind = "write";
    else if (label === "执行命令") kind = "execute";
  }
  const tool = KIND_TO_TOOL[kind];
  if (!tool) return [];
  return tasksFromToolCall(tool, item.call?.input ?? {}, force);
}

/**
 * 把一次工具调用认到的任务夹记到会话名下。
 * 只吃结构化证据（见 tasksFromEvent / tasksFromToolCall），不再扫正文与工具输出。
 */
export function noteSessionTools(sessionId: string | undefined, ev: unknown): void {
  const id = sessionId?.trim();
  if (!id || !ev) return;
  const hits = tasksFromEvent(ev);
  if (hits.length) {
    void addTasks(id, hits);
    return;
  }
  // 缓存里没有：可能是刚建的任务夹。限频强制刷一次真实目录再看
  const now = Date.now();
  if (now - lastForce < 500) return;
  lastForce = now;
  const late = tasksFromEvent(ev, true);
  if (late.length) void addTasks(id, late);
}

/** 会话活动时间：桌面新任务夹归属给正在跑的那个会话 */
export function markSessionActive(sessionId: string | undefined): void {
  const id = sessionId?.trim();
  if (!id) return;
  busyAt.set(id, Date.now());
}

/**
 * 最近真的在跑的会话。
 * 只有唯一一个才认领新任务夹：多个会话同时在跑时，桌面新建的文件夹是谁的说不清，
 * 宁可留作未归属让用户手动绑，也不要串到别人的会话里。
 */
function activeSession(): string | undefined {
  const now = Date.now();
  const live = [...busyAt.entries()].filter(([, at]) => now - at <= BUSY_WINDOW_MS);
  if (live.length !== 1) return undefined;
  return live[0][0];
}

/** 新任务夹归给最近活跃的那个会话；没有活跃会话就留作未归属，等用户手动绑 */
async function adoptNewTasks(): Promise<void> {
  const names = knownTaskNames(true);
  const fresh = names.filter((name) => !seen.has(name));
  if (!fresh.length) return;
  for (const name of fresh) seen.add(name);
  const target = activeSession();
  if (target) {
    await addTasks(target, fresh);
  }
  notifyChanged();
}

function desktopDirs(): string[] {
  return [path.join(os.homedir(), "Desktop"), path.join(os.homedir(), "桌面")];
}

/** 盯桌面目录：agent 建任务夹时立刻归给正在跑的会话，不用等用户切模块 */
export function startScopeWatch(): void {
  if (watchers.length) return;
  seen.clear();
  for (const name of knownTaskNames(true)) seen.add(name);
  const handler = () => {
    if (watchTimer) clearTimeout(watchTimer);
    watchTimer = setTimeout(() => {
      watchTimer = null;
      void adoptNewTasks();
    }, 700);
  };
  for (const dir of desktopDirs()) {
    try {
      watchers.push(fs.watch(dir, { persistent: false }, handler));
    } catch {
      /* 这个桌面目录不存在就跳过 */
    }
  }
}

export function stopScopeWatch(): void {
  if (watchTimer) {
    clearTimeout(watchTimer);
    watchTimer = null;
  }
  for (const w of watchers) {
    try {
      w.close();
    } catch {
      /* ignore */
    }
  }
  watchers = [];
}

export async function boundTasks(sessionId: string): Promise<string[]> {
  const data = await ensureLoaded();
  return data.sessions[sessionId]?.tasks ?? [];
}

/** 用户手动解绑过的任务夹：这些不许被磁盘证据自动绑回来 */
export async function excludedTasks(sessionId: string): Promise<string[]> {
  const data = await ensureLoaded();
  return data.sessions[sessionId]?.excluded ?? [];
}

export async function allBindings(): Promise<Record<string, string[]>> {
  const data = await ensureLoaded();
  const out: Record<string, string[]> = {};
  for (const [id, entry] of Object.entries(data.sessions)) out[id] = [...entry.tasks];
  return out;
}

/** 手动绑定：同时解除排除，用户主动选择优先 */
export async function bindTask(sessionId: string, task: string): Promise<void> {
  const id = sessionId?.trim();
  const name = task?.trim();
  if (!id || !name) return;
  const data = await ensureLoaded();
  const entry: SessionBinding = data.sessions[id] ?? { tasks: [], updatedAt: 0 };
  if (entry.excluded?.includes(name)) {
    data.sessions[id] = {
      tasks: entry.tasks,
      excluded: entry.excluded.filter((t) => t !== name),
      updatedAt: Date.now(),
    };
    scheduleSave();
    notifyChanged();
  }
  await addTasks(id, [name]);
}

/** 手动解绑：同时记入排除表，之后磁盘证据再命中也不会自动绑回 */
export async function unbindTask(sessionId: string, task: string): Promise<void> {
  const id = sessionId?.trim();
  if (!id || !task) return;
  const data = await ensureLoaded();
  const entry: SessionBinding = data.sessions[id] ?? { tasks: [], updatedAt: 0 };
  const excluded = [...new Set([...(entry.excluded ?? []), task])];
  const tasks = entry.tasks.filter((t) => t !== task);
  const sameTasks = tasks.length === entry.tasks.length;
  const sameExcluded = (entry.excluded ?? []).includes(task);
  if (sameTasks && sameExcluded) return;
  data.sessions[id] = { tasks, excluded, updatedAt: Date.now() };
  scheduleSave();
  notifyChanged();
}

/** 会话被删掉后，别让它的归属一直留在表里 */
export async function forgetSession(sessionId: string): Promise<void> {
  const id = sessionId?.trim();
  if (!id) return;
  busyAt.delete(id);
  const data = await ensureLoaded();
  if (!data.sessions[id]) return;
  delete data.sessions[id];
  scheduleSave();
  notifyChanged();
}
