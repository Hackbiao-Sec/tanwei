import { app, net, shell } from "electron";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import type {
  AdbActionInput,
  AdbActionResult,
  MiniDirHint,
  MobileDevice,
  MobileToolInstallResult,
  MobileToolItem,
  MobileToolProgress,
  MobileToolReport,
} from "../shared/types";

/**
 * 移动端工具链：检测、下载、落盘、PATH 注入，以及 ADB 连接管理。
 *
 * 原则：探微自己管一个工具目录（<userData>/tools），下载的东西按工具分子目录放，
 * 把找到的可执行目录注进 process.env.PATH —— 引擎（grok.exe）是探微的子进程，
 * 会继承这份 PATH，所以它能在终端里直接敲 jadx / apktool / frida。
 * 用户手工下载时，把压缩包解到这个目录下同样能被识别。
 */

export function toolRoot(): string {
  return path.join(app.getPath("userData"), "tools");
}

/** Windows 控制台程序常按系统代码页输出：先按 UTF-8 解，出现替换字符再按 GBK 解一次 */
export function decodeConsole(buf: Buffer): string {
  const utf8 = buf.toString("utf8");
  if (!utf8.includes("\uFFFD")) return utf8;
  try {
    return new TextDecoder("gbk").decode(buf);
  } catch {
    return utf8;
  }
}

const WIN = process.platform === "win32";

/** .bat / .cmd 不是 PE 文件：Windows 直接 CreateProcess 会同步抛 EINVAL，只能交给 cmd.exe 解析 */
const SHELL_SCRIPT = /\.(bat|cmd)$/i;

function quoteForCmd(value: string): string {
  return `"${value.replace(/"/g, '""').replace(/[\r\n]/g, " ")}"`;
}

function runViaCmd(cmd: string, args: string[], timeout: number): Promise<{ ok: boolean; out: string }> {
  return new Promise((resolve) => {
    // /s /c 会剥掉最外层一对引号，所以整条命令整体再包一层
    const line = `""${cmd}" ${args.map(quoteForCmd).join(" ")}"`;
    const chunks: Buffer[] = [];
    let finished = false;
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", line], {
        windowsHide: true,
        windowsVerbatimArguments: true,
      });
    } catch (error) {
      resolve({ ok: false, out: `启动失败：${(error as Error).message}（${cmd}）` });
      return;
    }
    const finish = (ok: boolean, fallback: string) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      const out = decodeConsole(Buffer.concat(chunks)).trim();
      resolve({ ok, out: out || fallback });
    };
    const timer = setTimeout(() => {
      finished = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        /* 进程已自行退出 */
      }
      const out = decodeConsole(Buffer.concat(chunks)).trim();
      resolve({ ok: false, out: out || `执行超时（${Math.round(timeout / 1000)} 秒）：${cmd}` });
    }, timeout);
    child.stdout?.on("data", (data: Buffer) => chunks.push(data));
    child.stderr?.on("data", (data: Buffer) => chunks.push(data));
    child.on("error", (error) => finish(false, `启动失败：${error.message}（${cmd}）`));
    child.on("close", (code) => finish(code === 0, code === 0 ? "" : `退出码 ${code}：${cmd}`));
  });
}

/**
 * 启动外部工具的唯一入口：.bat/.cmd 走 cmd.exe，其余直接 CreateProcess。
 * 永不抛出 —— 启动异常折成可读中文回给界面，不再把 spaw EINVAL 抛到调用方。
 */
export function execTool(cmd: string, args: string[], timeout = 8_000): Promise<{ ok: boolean; out: string }> {
  if (WIN && SHELL_SCRIPT.test(cmd)) return runViaCmd(cmd, args, timeout);
  return new Promise((resolve) => {
    const finish = (err: { code?: string | number | null; message?: string } | null, stdout: Buffer | string, stderr: Buffer | string) => {
      const out = `${decodeConsole(toBuffer(stdout))}${decodeConsole(toBuffer(stderr))}`.trim();
      if (!err) {
        resolve({ ok: true, out });
        return;
      }
      const code = typeof err.code === "string" ? err.code : "";
      const reason =
        code === "ENOENT"
          ? "找不到这个程序"
          : code === "EACCES"
            ? "没有执行权限"
            : code === "EINVAL"
              ? "这个文件不能直接当程序启动（脚本请用 .bat/.cmd 方式或装对应运行时）"
              : err.message ?? `退出码 ${String(err.code ?? "")}`;
      resolve({ ok: false, out: out || `启动失败：${reason}（${cmd}）` });
    };
    try {
      execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 1_000_000, encoding: "buffer" }, finish);
    } catch (error) {
      resolve({ ok: false, out: `启动失败：${(error as Error).message}（${cmd}）` });
    }
  });
}

function toBuffer(value: Buffer | string): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
}

const run = execTool;

interface ToolSpec {
  name: string;
  title: string;
  group: MobileToolItem["group"];
  purpose: string;
  required: boolean;
  exe: string[];
  versionArgs?: string[];
  installKind: MobileToolItem["installKind"];
  folder: string;
  url?: string;
  gh?: { repo: string; asset: RegExp };
  fallback?: string[];
  pip?: string;
  homepage: string;
  manual: string;
  hint?: string;
}

const archSegment = process.arch === "arm64" ? "aarch64" : process.arch === "ia32" ? "x86" : "x64";

const SPECS: ToolSpec[] = [
  {
    name: "adb",
    title: "adb · Android Platform Tools",
    group: "android",
    purpose: "连设备、装包、拉组件、抓日志、开关代理",
    required: true,
    exe: ["adb.exe", "adb"],
    versionArgs: ["version"],
    installKind: "zip",
    folder: "adb",
    url: "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    fallback: ["https://dl-ssl.google.com/android/repository/platform-tools-latest-windows.zip"],
    homepage: "https://developer.android.com/tools/releases/platform-tools",
    manual: "下 platform-tools 的 Windows 压缩包，解压后把里面的 platform-tools 文件夹整个放到这里（保持 <此目录>\\platform-tools\\adb.exe 存在）",
  },
  {
    name: "jadx",
    title: "jadx",
    group: "reverse",
    purpose: "dex → Java 反编译，读业务逻辑与加密流程",
    required: false,
    exe: ["jadx.bat", "jadx.exe", "jadx"],
    versionArgs: ["--version"],
    installKind: "zip",
    folder: "jadx",
    gh: { repo: "skylot/jadx", asset: /^jadx-[\d.]+\.zip$/i },
    fallback: [
      "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
      "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip",
    ],
    homepage: "https://github.com/skylot/jadx/releases",
    manual: "下 jadx-x.y.z.zip 解压到这里，保持 <此目录>\\bin\\jadx.bat 存在；jadx 需要 Java",
  },
  {
    name: "apktool",
    title: "apktool",
    group: "reverse",
    purpose: "完整还原 AndroidManifest / 资源，改包重打包",
    required: false,
    exe: ["apktool.bat", "apktool"],
    versionArgs: ["--version"],
    installKind: "jar",
    folder: "apktool",
    gh: { repo: "iBotPeaches/Apktool", asset: /^apktool_[\d.]+\.jar$/i },
    fallback: ["https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar"],
    homepage: "https://github.com/iBotPeaches/Apktool/releases",
    manual: "下 apktool_x.y.z.jar 改名为 apktool.jar 放进这里；探微会自动生成 apktool.bat 入口（需要 Java）",
  },
  {
    name: "frida",
    title: "frida / frida-tools",
    group: "dynamic",
    purpose: "动态 hook：脱壳、绕 SSL Pinning、抓加密参数",
    required: false,
    exe: ["frida.exe", "frida", "frida.cmd"],
    versionArgs: ["--version"],
    installKind: "pip",
    folder: "frida",
    pip: "frida-tools",
    homepage: "https://frida.re/docs/installation/",
    manual: "需要先有 Python：pip install frida-tools。装完把 Python 的 Scripts 目录（默认 %APPDATA%\\Python\\Python3xx\\Scripts）加进 PATH",
  },
  {
    name: "objection",
    title: "objection",
    group: "dynamic",
    purpose: "免写脚本跑常见动态套路（绕 pinning、读偏好、导文件）",
    required: false,
    exe: ["objection.exe", "objection", "objection.cmd"],
    versionArgs: ["version"],
    installKind: "pip",
    folder: "objection",
    pip: "objection",
    homepage: "https://github.com/sensepost/objection",
    manual: "pip install objection，装完同样依赖 Python Scripts 目录在 PATH 里",
  },
  {
    name: "java",
    title: "Java 运行时（JRE 21）",
    group: "runtime",
    purpose: "jadx / apktool 的运行依赖",
    required: true,
    exe: ["java.exe", "java"],
    versionArgs: ["-version"],
    installKind: "zip",
    folder: "java",
    url: `https://api.adoptium.net/v3/binary/latest/21/ga/windows/${archSegment}/jre/hotspot/normal/eclipse`,
    homepage: "https://adoptium.net/temurin/releases/",
    manual: "下 Temurin JRE 的 zip 包解压到这里，保持 <此目录>\\bin\\java.exe 存在；也可以直接装系统版",
  },
  {
    name: "python",
    title: "Python 3",
    group: "runtime",
    purpose: "frida / objection 与脚本化工具的运行时",
    required: false,
    exe: ["python.exe", "python3.exe", "python"],
    versionArgs: ["--version"],
    installKind: "manual",
    folder: "python",
    url: "https://www.python.org/downloads/windows/",
    homepage: "https://www.python.org/downloads/windows/",
    manual: "装 python.org 的 3.11 / 3.12；安装时勾 Add python.exe to PATH。想放探微目录就选 Customize 指定 <此目录>",
  },
];

function specOf(name: string): ToolSpec | undefined {
  return SPECS.find((s) => s.name === name);
}

/* ---------------- PATH 注入 ---------------- */

const SKIP_DIR = new Set(["node_modules", "$recycle.bin", "system volume information"]);

function walkExecutables(dir: string, depth: number, out: string[]): void {
  if (depth > 5) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIR.has(entry.name.toLowerCase())) continue;
      walkExecutables(full, depth + 1, out);
      continue;
    }
    if (!/\.(exe|bat|cmd)$/i.test(entry.name)) continue;
    out.push(full);
  }
}

/** 探微工具目录里所有可执行文件所在的目录：注进 PATH 就能按名字调用 */
export function toolBinDirs(): string[] {
  const root = toolRoot();
  if (!fs.existsSync(root)) return [];
  const files: string[] = [];
  walkExecutables(root, 0, files);
  return [...new Set(files.map((f) => path.dirname(f)))];
}

let seeded: string[] = [];

/** pip 装出来的入口在 Python 自己的 Scripts 目录，不在探微工具目录：记下来一起注进 PATH */
function pipScriptsFile(): string {
  return path.join(toolRoot(), "pip-scripts.json");
}

function readPipDirs(): string[] {
  try {
    const json = JSON.parse(fs.readFileSync(pipScriptsFile(), "utf8")) as { dirs?: unknown };
    const list = Array.isArray(json.dirs) ? json.dirs : [];
    return list.filter((d): d is string => typeof d === "string" && fs.existsSync(d));
  } catch {
    return [];
  }
}

function rememberPipDir(dir: string): void {
  if (!fs.existsSync(dir)) return;
  const dirs = [...new Set([...readPipDirs(), dir])];
  try {
    fs.mkdirSync(toolRoot(), { recursive: true });
    fs.writeFileSync(pipScriptsFile(), JSON.stringify({ dirs }, null, 2), "utf8");
  } catch {
    // 写不进去也不影响这一次（下面直接改进程 PATH）
  }
}

export function ensureToolPath(): string[] {
  const dirs = [...toolBinDirs(), ...readPipDirs()];
  const parts = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const missing = dirs.filter((d) => !parts.includes(d));
  if (missing.length) {
    process.env.PATH = [...missing, ...parts].join(path.delimiter);
    // PATH 变了要重扫，否则上次的「找不到」一直粘着
    whereCache.clear();
  }
  seeded = dirs;
  return seeded;
}

/* ---------------- 检测 ---------------- */

function findInDir(dir: string, names: string[]): string | undefined {
  const lower = names.map((n) => n.toLowerCase());
  const hits: { file: string; depth: number; rank: number }[] = [];
  const scan = (current: string, depth: number): void => {
    if (depth > 5) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIR.has(entry.name.toLowerCase())) continue;
        scan(full, depth + 1);
        continue;
      }
      const rank = lower.indexOf(entry.name.toLowerCase());
      if (rank >= 0) hits.push({ file: full, depth, rank });
    }
  };
  scan(dir, 0);
  // 同一个目录里 jadx.bat 与无扩展名的 jadx 并存时，按声明顺序选能直接启动的那个
  hits.sort((a, b) => a.rank - b.rank || a.depth - b.depth || a.file.length - b.file.length);
  return hits[0]?.file;
}

const whereCache = new Map<string, string | undefined>();

/** PATH 上常有没扩展名的 shim（bash / python 脚本）：Windows 既启动不了也不报「找不到」 */
function extRank(ext: string): number {
  const e = ext.toLowerCase();
  if (e === ".exe") return 0;
  if (e === ".com") return 1;
  if (e === ".bat") return 2;
  if (e === ".cmd") return 3;
  if (!e) return 9;
  return 5;
}

/** 直接在 Node 里扫 PATH：不经过管道，含中文 / 空格的目录不会被系统代码页解坏 */
function scanPathFor(name: string): string | undefined {
  const exts = WIN
    ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean)
    : [""];
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const hasExt = path.extname(name) !== "";
  // 显式给了扩展名就照办；只给工具名时按 .exe > .com > .bat > .cmd > 无扩展名 排，
  // 否则先撞上无扩展名 shim 会一直「找到了但起不来」
  const ordered = hasExt ? [name] : [...exts.sort((a, b) => extRank(a) - extRank(b)), ""];
  for (const dir of dirs) {
    for (const ext of ordered) {
      const full = path.join(dir, hasExt ? name : `${name}${ext}`);
      try {
        if (fs.statSync(full).isFile()) return full;
      } catch {
        // 该候选不存在，继续扫
      }
    }
  }
  return undefined;
}

async function findOnPath(names: string[]): Promise<string | undefined> {
  for (const name of names) {
    if (whereCache.has(name)) {
      const hit = whereCache.get(name);
      if (hit) return hit;
      continue;
    }
    const local = scanPathFor(name);
    if (local) {
      whereCache.set(name, local);
      return local;
    }
    const res = WIN
      ? await run("where", [name], 4_000)
      : await run("which", [name], 4_000);
    const raw = res.ok
      ? res.out
          .split(/\r?\n/)
          .map((s) => s.trim())
          .find(Boolean)
      : undefined;
    // 这里是兜底：`where` 的输出走管道时按代码页解码，出现替换字符说明路径已坏，宁可不认
    const line = raw && !raw.includes("\uFFFD") ? raw : undefined;
    whereCache.set(name, line);
    if (line) return line;
  }
  return undefined;
}

/** Python 自带的 Scripts 目录：pip 装的 frida / objection 入口都在这儿 */
function pythonScriptsDir(python: string): string {
  return path.join(path.dirname(python), "Scripts");
}

export async function findToolPath(name: string): Promise<string | undefined> {
  const spec = specOf(name);
  if (!spec) return undefined;
  ensureToolPath();
  const local = findInDir(path.join(toolRoot(), spec.folder), spec.exe);
  if (local) return local;
  const onPath = await findOnPath(spec.exe);
  if (onPath) return onPath;
  if (spec.installKind === "pip") {
    // 用户在探微外面 pip install 过、或者刚装完还没进 PATH：直接去 Python 的 Scripts 里认一次
    for (const dir of readPipDirs()) {
      const hit = findInDir(dir, spec.exe);
      if (hit) return hit;
    }
    const python = await findOnPath(["python.exe", "python"]);
    if (python) {
      const scripts = pythonScriptsDir(python);
      const hit = findInDir(scripts, spec.exe);
      if (hit) {
        rememberPipDir(scripts);
        ensureToolPath();
        return hit;
      }
    }
  }
  return undefined;
}

async function versionOf(file: string, args?: string[]): Promise<string | undefined> {
  if (!args?.length) return undefined;
  // .bat / .cmd 走 cmd.exe（execTool 已处理），以前只认 .exe 导致 jadx / apktool 永远没版本号
  if (!/\.(exe|bat|cmd|com)$/i.test(file) && WIN) return undefined;
  const res = await execTool(file, args, 20_000);
  if (!res.out) return undefined;
  // 有些工具先把「正在检查更新」之类的提示打在最前面，真正的版本号在后面；
  // 版本参数不被支持时会吐 Usage，这种情况宁可不显示版本
  const lines = res.out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const noisy = /^(usage|try\b|error\b|options\b|commands\b|info\b|traceback\b|no module)/i;
  const line = lines.find((l) => /\d+\.\d+/.test(l) && !noisy.test(l));
  if (!line) return undefined;
  return line.replace(/^Android Debug Bridge version\s*/i, "").replace(/^objection:\s*/i, "").slice(0, 60) || undefined;
}

/** 找到文件不等于能跑：真起一次，起不来把原因带回界面，别再显示一个绿色的勾 */
async function launchCheck(file: string, args?: string[]): Promise<string | undefined> {
  if (!args?.length) {
    if (!/\.(exe|bat|cmd|com)$/i.test(file) && WIN) {
      return "这个文件在 Windows 上不能直接启动（没有 .exe / .bat / .cmd 扩展名）";
    }
    return undefined;
  }
  const res = await execTool(file, args, 20_000);
  if (res.ok) return undefined;
  const text = res.out.split(/\r?\n/).filter(Boolean)[0] ?? "启动失败";
  return text.slice(0, 160);
}

async function resolveGithubAsset(repo: string, asset: RegExp): Promise<string | undefined> {
  // 没网 / GitHub 被挡时最多等 8 秒，不能把「下载」按钮拖成永远转圈
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  try {
    const res = await net.fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers: { "User-Agent": "TanweiConsole", Accept: "application/vnd.github+json" },
      signal: controller.signal,
    });
    if (!res.ok) return undefined;
    const json = (await res.json()) as { assets?: { name: string; browser_download_url: string }[] };
    const hit = (json.assets ?? []).find((a) => asset.test(a.name));
    return hit?.browser_download_url;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

function mirrorUrls(url: string): string[] {
  if (!/^https:\/\/github\.com\//i.test(url) && !/^https:\/\/objects\.githubusercontent\.com\//i.test(url)) return [url];
  return [url, `https://ghproxy.net/${url}`, `https://gh-proxy.com/${url}`];
}

/* ---------------- 下载 / 解压 ---------------- */

function mb(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

async function downloadTo(
  urls: string[],
  file: string,
  onProgress: (percent: number | undefined, message: string) => void,
): Promise<string> {
  const errors: string[] = [];
  for (const url of urls) {
    const controller = new AbortController();
    // 卡住才放弃：90 秒没有新数据就换下一个镜像；慢速但仍在走的下载不砍
    let lastByteAt = Date.now();
    const watch = setInterval(() => {
      if (Date.now() - lastByteAt > 90_000) controller.abort();
    }, 5_000);
    try {
      onProgress(undefined, `连接 ${new URL(url).host}…`);
      const res = await net.fetch(url, {
        headers: { "User-Agent": "TanweiConsole/1.0 (+mobile toolkit)" },
        redirect: "follow",
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
      const total = Number(res.headers.get("content-length") ?? 0);
      const reader = res.body.getReader();
      const out = fs.createWriteStream(file);
      let got = 0;
      let lastAt = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        lastByteAt = Date.now();
        const chunk = Buffer.from(value);
        got += chunk.length;
        if (!out.write(chunk)) {
          await new Promise<void>((resolve) => out.once("drain", () => resolve()));
        }
        const now = Date.now();
        if (now - lastAt > 320) {
          lastAt = now;
          onProgress(total ? Math.min(99, Math.round((got / total) * 100)) : undefined, `${mb(got)}${total ? ` / ${mb(total)}` : ""}`);
        }
      }
      await new Promise<void>((resolve, reject) => out.end((err?: Error | null) => (err ? reject(err) : resolve())));
      onProgress(100, mb(got));
      return url;
    } catch (err) {
      const aborted = err instanceof Error && (err.name === "AbortError" || /abort/i.test(err.message));
      const reason = err instanceof Error ? (aborted ? "90 秒没有新数据，已跳过" : err.message) : String(err);
      errors.push(`${new URL(url).host}：${reason}`);
      await fsp.rm(file, { force: true });
    } finally {
      clearInterval(watch);
    }
  }
  throw new Error(`所有下载地址都失败（${errors.join("；")}）。可用「官网」按钮手工下载后按说明放进工具目录。`);
}

interface ZipEntryLite {
  name: string;
  method: number;
  csize: number;
  size: number;
  offset: number;
}

function zipEntries(buf: Buffer): ZipEntryLite[] {
  let eocd = -1;
  const floor = Math.max(0, buf.length - 70_000);
  for (let i = buf.length - 22; i >= floor; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("不是有效的 zip（找不到中央目录）");
  const total = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  const entries: ZipEntryLite[] = [];
  for (let i = 0; i < total; i += 1) {
    if (offset + 46 > buf.length) break;
    if (buf.readUInt32LE(offset) !== 0x02014b50) break;
    const method = buf.readUInt16LE(offset + 10);
    const csize = buf.readUInt32LE(offset + 20);
    const size = buf.readUInt32LE(offset + 24);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localOffset = buf.readUInt32LE(offset + 42);
    const name = buf.subarray(offset + 46, offset + 46 + nameLen).toString("utf8").replace(/\\/g, "/");
    entries.push({ name, method, csize, size, offset: localOffset });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function extractZip(buf: Buffer, dest: string): number {
  const entries = zipEntries(buf);
  let written = 0;
  for (const entry of entries) {
    const safe = entry.name.replace(/^\/+/, "");
    if (!safe || safe.includes("..")) continue;
    const target = path.join(dest, safe);
    if (safe.endsWith("/")) {
      fs.mkdirSync(target, { recursive: true });
      continue;
    }
    if (entry.size > 400 * 1024 * 1024) continue;
    const at = entry.offset;
    if (at + 30 > buf.length || buf.readUInt32LE(at) !== 0x04034b50) continue;
    const nameLen = buf.readUInt16LE(at + 26);
    const extraLen = buf.readUInt16LE(at + 28);
    const start = at + 30 + nameLen + extraLen;
    const raw = buf.subarray(start, start + entry.csize);
    let data: Buffer | undefined;
    if (entry.method === 0) data = raw;
    else if (entry.method === 8) {
      try {
        data = zlib.inflateRawSync(raw);
      } catch {
        data = undefined;
      }
    }
    if (!data) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
    written += 1;
  }
  return written;
}

/* ---------------- 安装 ---------------- */

async function resolveUrls(spec: ToolSpec): Promise<string[]> {
  const direct: string[] = [];
  if (spec.gh) {
    const gh = await resolveGithubAsset(spec.gh.repo, spec.gh.asset);
    if (gh) direct.push(gh);
  }
  if (spec.url) direct.push(spec.url);
  direct.push(...(spec.fallback ?? []));
  const out: string[] = [];
  for (const url of direct) for (const u of mirrorUrls(url)) if (!out.includes(u)) out.push(u);
  return out;
}

async function writeBat(dir: string, name: string, body: string): Promise<string> {
  const file = path.join(dir, `${name}.bat`);
  await fsp.writeFile(file, `@echo off\r\n${body}\r\n`, "utf8");
  return file;
}

export async function installTool(
  name: string,
  onProgress?: (p: MobileToolProgress) => void,
): Promise<MobileToolInstallResult> {
  const spec = specOf(name);
  const emit = onProgress ?? (() => {});
  if (!spec) return { name, ok: false, log: "", error: `不认识的工具：${name}` };
  invalidateToolReport();

  const dir = path.join(toolRoot(), spec.folder);
  await fsp.mkdir(dir, { recursive: true }).catch(() => {});
  const log: string[] = [];

  try {
    if (spec.installKind === "manual") {
      const msg = `这个工具需要安装程序（可能要 UAC），探微不代装。下载地址：${spec.url ?? spec.homepage}；${spec.manual}`;
      emit({ name, phase: "error", message: msg });
      return { name, ok: false, log: msg, error: msg, path: dir };
    }

    if (spec.installKind === "pip") {
      const python = (await findToolPath("python")) ?? (await findOnPath(["python.exe", "python"]));
      if (!python) {
        const msg = `先装 Python 3（设置页可查阅手动地址），再回来装 ${spec.name}`;
        emit({ name, phase: "error", message: msg });
        return { name, ok: false, log: msg, error: msg, path: dir };
      }
      emit({ name, phase: "install", message: `pip install ${spec.pip}` });
      const res = await run(python, ["-m", "pip", "install", "--upgrade", "--disable-pip-version-check", spec.pip ?? spec.name], 600_000);
      log.push(`$ ${python} -m pip install ${spec.pip ?? spec.name}`);
      log.push(res.out.slice(-4000));
      // pip 的入口落在 Python 的 Scripts 目录：记进探微的 PATH，下次启动也能直接认出来
      const scripts = pythonScriptsDir(python);
      if (fs.existsSync(scripts)) {
        rememberPipDir(scripts);
        whereCache.clear();
        ensureToolPath();
      }
      const found = await findToolPath(name);
      const hint = found
        ? undefined
        : "pip 说装好了但这儿还找不到入口：把 Python 的 Scripts 目录加进 PATH 后重新检测";
      emit({ name, phase: found ? "done" : "error", message: found ? "装好了" : hint ?? "装完了但没找到入口" });
      return { name, ok: Boolean(found), log: log.join("\n"), path: found, error: found ? undefined : hint };
    }

    const urls = await resolveUrls(spec);
    if (!urls.length) {
      const msg = "没有可用的自动下载地址，请按说明手工安装";
      emit({ name, phase: "error", message: msg });
      return { name, ok: false, log: msg, error: msg, path: dir };
    }

    const fileName = decodeURIComponent(new URL(urls[0]).pathname.split("/").pop() ?? `${spec.name}.zip`);
    emit({ name, phase: "download", percent: 0, message: `下载 ${fileName}` });
    log.push(`下载：${urls[0]}`);
    const tmp = path.join(dir, `_${spec.name}-download${path.extname(fileName) || ".zip"}`);
    const usedUrl = await downloadTo(urls, tmp, (percent, message) => emit({ name, phase: "download", percent, message }));
    if (usedUrl !== urls[0]) log.push(`实际来源：${usedUrl}`);

    if (spec.installKind === "jar") {
      const jar = path.join(dir, `${spec.name}.jar`);
      await fsp.rm(jar, { force: true });
      await fsp.rename(tmp, jar);
      const bat = await writeBat(dir, spec.name, `java -jar "%~dp0${spec.name}.jar" %*`);
      log.push(`写入入口：${bat}`);
      emit({ name, phase: "extract", message: "解压 / 写入入口" });
    } else {
      emit({ name, phase: "extract", message: "解压中" });
      const buf = await fsp.readFile(tmp);
      const count = extractZip(buf, dir);
      log.push(`解压 ${count} 个文件 → ${dir}`);
      await fsp.rm(tmp, { force: true });
    }

    whereCache.clear();
    ensureToolPath();
    const found = await findToolPath(spec.name);
    const rel = found ? path.relative(toolRoot(), found) : "";
    if (found) log.push(`可执行：${rel}`);
    emit({
      name,
      phase: found ? "done" : "error",
      message: found ? "装好了" : "文件解出来了但没找到可执行文件，检查目录结构（看说明里的目标路径）",
    });
    return {
      name,
      ok: Boolean(found),
      log: log.join("\n"),
      path: found,
      error: found ? undefined : "解压完成但没找到入口文件，按说明检查目录结构",
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.push(msg);
    emit({ name, phase: "error", message: msg });
    return { name, ok: false, log: log.join("\n"), error: msg, path: dir };
  }
}

/** 缺什么装什么；指定 names 就只装这些 */
export async function installTools(
  names: string[] | undefined,
  onProgress?: (p: MobileToolProgress) => void,
): Promise<MobileToolInstallResult[]> {
  const target = names?.length
    ? names
    : (await toolReport()).items.filter((i) => !i.ok && i.installable).map((i) => i.name);
  const results: MobileToolInstallResult[] = [];
  for (const name of target) results.push(await installTool(name, onProgress));
  return results;
}

/* ---------------- 报告 ---------------- */

async function inspect(spec: ToolSpec): Promise<MobileToolItem> {
  const dir = path.join(toolRoot(), spec.folder);
  const found = await findToolPath(spec.name);
  const from: "system" | "tanwei" | undefined = found
    ? found.toLowerCase().startsWith(toolRoot().toLowerCase())
      ? "tanwei"
      : "system"
    : undefined;
  const version = found ? await versionOf(found, spec.versionArgs) : undefined;
  // 找到了但起不来（无扩展名 shim、缺运行时）要当场说清，界面不能再显示成可用
  const launchError = found ? await launchCheck(found, spec.versionArgs) : undefined;
  return {
    name: spec.name,
    title: spec.title,
    group: spec.group,
    purpose: spec.purpose,
    required: spec.required,
    ok: Boolean(found) && !launchError,
    version,
    path: found,
    from,
    launchError,
    installable: spec.installKind !== "manual",
    installKind: spec.installKind,
    folder: dir,
    downloadUrl: spec.url ?? spec.fallback?.[0],
    homepage: spec.homepage,
    manual: spec.manual,
    hint: spec.hint,
  };
}

/** 探测本机已经装好的 Python，并把它的 Scripts 目录接进 PATH（frida / objection 落在这里） */
export async function probePython(): Promise<{ ok: boolean; path?: string; version?: string; hint?: string }> {
  ensureToolPath();
  const python = await findOnPath(["python.exe", "python3.exe", "python"]);
  if (!python) return { ok: false, hint: "系统里没找到 python：去 python.org 装 3.11 以上，安装时勾 Add python.exe to PATH" };
  const version = await versionOf(python, ["--version"]);
  const scripts = pythonScriptsDir(python);
  if (fs.existsSync(scripts)) {
    rememberPipDir(scripts);
    ensureToolPath();
  }
  return {
    ok: true,
    path: python,
    version,
    hint: fs.existsSync(scripts)
      ? `已接入 ${python}，并把 ${scripts} 加进工具 PATH（frida / objection 从这里认）`
      : `已接入 ${python}，但它没有 Scripts 目录，pip 装完工具后会生成`,
  };
}

let reportCache: { at: number; value: MobileToolReport } | undefined;

export async function toolReport(force = false): Promise<MobileToolReport> {
  ensureToolPath();
  // 每次点开设置都重跑 7 个工具太贵（jadx / apktool 要起 JVM），半分钟内复用上一次
  if (!force && reportCache && Date.now() - reportCache.at < 30_000) return reportCache.value;
  const items: MobileToolItem[] = [];
  for (const spec of SPECS) items.push(await inspect(spec));
  const missing = items.filter((i) => !i.ok).map((i) => i.name);
  const value: MobileToolReport = {
    root: toolRoot(),
    pathDirs: seeded,
    items,
    ready: items.length - missing.length,
    total: items.length,
    missing,
    checkedAt: Date.now(),
  };
  reportCache = { at: Date.now(), value };
  return value;
}

/** 装完东西要让下一次检测看到变化 */
export function invalidateToolReport(): void {
  reportCache = undefined;
}

export async function openToolDir(name?: string): Promise<boolean> {
  const spec = name ? specOf(name) : undefined;
  const dir = spec ? path.join(toolRoot(), spec.folder) : toolRoot();
  fs.mkdirSync(dir, { recursive: true });
  await shell.openPath(dir);
  return true;
}

/* ---------------- ADB 连接 ---------------- */

function normalizeTarget(raw: string, port = 5555): string {
  const value = raw.trim().replace(/^adb:\/\//i, "");
  if (!value) return "";
  if (/:\d+$/.test(value)) return value;
  return `${value}:${port}`;
}

export function parseDevices(out: string): MobileDevice[] {
  const devices: MobileDevice[] = [];
  for (const line of out.split(/\r?\n/).slice(1)) {
    const trimmed = line.trim();
    if (!trimmed || /^\*/.test(trimmed)) continue;
    const [serial, state, ...rest] = trimmed.split(/\s+/);
    if (!serial || !state) continue;
    const model = rest.find((r) => r.startsWith("model:"))?.slice(6);
    devices.push({ serial, state, model });
  }
  return devices;
}

async function listDevices(adb: string): Promise<MobileDevice[]> {
  const res = await run(adb, ["devices", "-l"], 10_000);
  return res.ok ? parseDevices(res.out) : [];
}

async function firstUsableSerial(adb: string): Promise<string | undefined> {
  const devices = await listDevices(adb);
  return devices.find((d) => d.state === "device")?.serial;
}

export async function adbAction(input: AdbActionInput): Promise<AdbActionResult> {
  const action = input.action;
  const at = Date.now();
  const fail = (hint: string, cmd = ""): AdbActionResult => ({ ok: false, action, cmd, out: "", hint, at });

  ensureToolPath();
  const adb = await findToolPath("adb");
  if (!adb) {
    return fail("没找到 adb：到「设置 → 移动端工具」点一键下载，或装 Android Platform Tools 后加进 PATH");
  }
  const cmdOf = (args: string[]): string => `${adb} ${args.join(" ")}`;

  if (action === "devices") {
    const res = await run(adb, ["devices", "-l"], 12_000);
    const devices = parseDevices(res.out);
    return {
      ok: res.ok,
      action,
      cmd: cmdOf(["devices", "-l"]),
      out: res.out,
      devices,
      hint: devices.length
        ? undefined
        : "一个都没认到：插 USB 后在手机上允许「USB 调试」，或先对 Android 11+ 走无线调试配对",
      at,
    };
  }

  if (action === "connect") {
    const target = normalizeTarget(input.target ?? "", input.port ?? 5555);
    if (!target) return fail("填设备地址，例如 192.168.1.23:5555");
    const res = await run(adb, ["connect", target], 25_000);
    const devices = await listDevices(adb);
    const ok = /connected to|already connected/i.test(res.out) && !/failed|unable|cannot/i.test(res.out);
    return {
      ok,
      action,
      cmd: cmdOf(["connect", target]),
      out: res.out,
      devices,
      hint: ok
        ? "连上了就用上面的设备号做动态测试；adb connect 在 Android 11+ 要在开发者选项里先开「无线调试」"
        : "连不上：确认手机和电脑同网段、已开无线调试，且先用 adb pair 配对过（Android 11+）",
      at,
    };
  }

  if (action === "pair") {
    const target = normalizeTarget(input.target ?? "", 0);
    const code = (input.code ?? "").trim();
    if (!target || !code) return fail("配对要两个值：IP:端口（无线调试页上那个）和 6 位配对码");
    const res = await run(adb, ["pair", target, code], 40_000);
    const ok = /Successfully paired/i.test(res.out);
    return {
      ok,
      action,
      cmd: cmdOf(["pair", target, code]),
      out: res.out,
      devices: await listDevices(adb),
      hint: ok
        ? "配对成功。接着用「连接」填同一个 IP + 无线调试页的「端口」（不是配对端口）连上去"
        : "配对失败：配对端口和连接端口是两个；码会过期，回手机重新生成",
      at,
    };
  }

  if (action === "disconnect") {
    const target = (input.target ?? "").trim();
    const args = target ? ["disconnect", normalizeTarget(target)] : ["disconnect"];
    const res = await run(adb, args, 15_000);
    return {
      ok: res.ok,
      action,
      cmd: cmdOf(args),
      out: res.out || "已断开",
      devices: await listDevices(adb),
      hint: target ? undefined : "已断开全部网络设备；USB 设备不受影响",
      at,
    };
  }

  if (action === "kill-server") {
    const res = await run(adb, ["kill-server"], 15_000);
    return {
      ok: true,
      action,
      cmd: cmdOf(["kill-server"]),
      out: res.out || "adb 服务已停止，下次调用会自动拉起",
      devices: [],
      hint: "设备列表异常、端口占用时用它重置",
      at,
    };
  }

  if (action === "reconnect") {
    const res = await run(adb, ["reconnect"], 15_000);
    return {
      ok: res.ok,
      action,
      cmd: cmdOf(["reconnect"]),
      out: res.out || "已重连",
      devices: await listDevices(adb),
      at,
    };
  }

  if (action === "mdns") {
    const res = await run(adb, ["mdns", "services"], 15_000);
    return {
      ok: res.ok,
      action,
      cmd: cmdOf(["mdns", "services"]),
      out: res.out || "（没有 mDNS 服务）",
      devices: await listDevices(adb),
      hint: "这里列出来的是同一网段里开了无线调试的设备，端口就是连接端口",
      at,
    };
  }

  const serial = (input.serial ?? "").trim() || (await firstUsableSerial(adb));
  if (!serial) return fail("还没有已连接设备。先 USB 连上或无线配对后再做这一步。");

  if (action === "tcpip") {
    const port = input.port ?? 5555;
    const res = await run(adb, ["-s", serial, "tcpip", String(port)], 25_000);
    const ok = /restarting in TCP mode port/i.test(res.out);
    return {
      ok,
      action,
      cmd: cmdOf(["-s", serial, "tcpip", String(port)]),
      out: res.out,
      devices: await listDevices(adb),
      hint: ok
        ? `设备已切到无线模式。用「读取设备 IP」拿到地址后点连接（端口 ${port}），之后 USB 可以不插`
        : "切换失败：模拟器一般本来就支持；真机要开发者选项允许，切完 IP 可能变",
      at,
    };
  }

  if (action === "usb") {
    const res = await run(adb, ["-s", serial, "usb"], 20_000);
    return {
      ok: res.ok,
      action,
      cmd: cmdOf(["-s", serial, "usb"]),
      out: res.out || "已切回 USB 模式",
      devices: await listDevices(adb),
      hint: "无线不好使时用它退回 USB",
      at,
    };
  }

  if (action === "ip") {
    const res = await run(adb, ["-s", serial, "shell", "ip", "-f", "inet", "addr", "show"], 15_000);
    const ips = [...res.out.matchAll(/inet\s+(\d+\.\d+\.\d+\.\d+)/g)]
      .map((m) => m[1])
      .filter((ip) => ip !== "127.0.0.1");
    const wlan = ips.find((ip) => !/^10\.0\.2\./.test(ip)) ?? ips[0];
    return {
      ok: Boolean(wlan),
      action,
      cmd: cmdOf(["-s", serial, "shell", "ip", "-f", "inet", "addr", "show"]),
      out: res.out,
      devices: await listDevices(adb),
      hint: wlan
        ? `设备地址：${wlan}（模拟器 10.0.2.2 是宿主机）——填进连接框再点连接`
        : "没读到 IPv4：设备没连 Wi-Fi，或 adb 权限不足",
      at,
    };
  }

  return fail(`不认识的 ADB 动作：${String(action)}`);
}

/* ---------------- 微信 / 小程序目录 ---------------- */

const WXAPKG_SCAN = { depth: 5, dirs: 900 };

function countWxapkg(root: string): number {
  let count = 0;
  let dirs = 0;
  const scan = (dir: string, depth: number): void => {
    if (depth > WXAPKG_SCAN.depth || dirs > WXAPKG_SCAN.dirs) return;
    dirs += 1;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        scan(path.join(dir, entry.name), depth + 1);
        continue;
      }
      if (/\.(wxapkg|qapkg)$/i.test(entry.name)) count += 1;
    }
  };
  scan(root, 0);
  return count;
}

export function miniLibraryDirs(): MiniDirHint[] {
  const home = process.env.USERPROFILE ?? os.homedir();
  const docs = path.join(home, "Documents");
  const roam = process.env.APPDATA ?? path.join(home, "AppData", "Roaming");
  const local = process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local");
  const candidates: { label: string; path: string; note?: string }[] = [
    {
      label: "微信 3.x 小程序包（Applet）",
      path: path.join(docs, "WeChat Files", "Applet"),
      note: "每个 appid 一个文件夹，里面的 __APP__.wxapkg 就是小程序包；扫这个目录能直接列出可反编译的目标",
    },
    {
      label: "微信 4.x 数据目录（xwechat_files）",
      path: path.join(docs, "xwechat_files"),
      note: "新版微信把聊天、文件和小程序包都收在这里；直接扫这个目录，探微会自己找出所有 wxapkg",
    },
    {
      label: "微信旧版用户目录",
      path: path.join(docs, "WeChat Files"),
      note: "含 Applet 与各账号配置；不确定版本时扫这个最稳",
    },
    {
      label: "微信 4.x 程序数据",
      path: path.join(roam, "Tencent", "xwechat"),
      note: "客户端配置目录，一般没有小程序包",
    },
    {
      label: "微信 3.x 程序数据",
      path: path.join(roam, "Tencent", "WeChat"),
      note: "客户端配置目录，一般没有小程序包",
    },
    {
      label: "QQ 小程序数据",
      path: path.join(docs, "Tencent Files"),
      note: "QQ / QQ 小程序的包（qapkg）在这里",
    },
    {
      label: "微信缓存（Local）",
      path: path.join(local, "Tencent", "WeChat"),
      note: "缓存目录，偶尔能捡到旧版本包",
    },
  ];
  return candidates.map((c) => {
    const exists = fs.existsSync(c.path);
    return {
      label: c.label,
      path: c.path,
      exists,
      wxapkg: exists ? countWxapkg(c.path) : 0,
      note: c.note,
    };
  });
}
