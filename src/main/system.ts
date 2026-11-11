import { spawn, spawnSync } from "node:child_process";
import { app, shell } from "electron";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type {
  AssetTask,
  McpServerInfo,
  NewSkillInput,
  ReportEntry,
  RuleEntry,
  SessionSummary,
  SkillEntry,
} from "../shared/types";

export function grokHome(): string {
  return process.env.GROK_HOME || path.join(os.homedir(), ".grok");
}

export function resolveGrokPath(): string {
  const candidates = [
    process.env.GROK_EXE,
    app.isPackaged ? path.join(process.resourcesPath, "grok", "grok.exe") : undefined,
    path.join(grokHome(), "bin", "grok.exe"),
    path.join(os.homedir(), ".grok", "bin", "grok.exe"),
  ].filter(Boolean) as string[];

  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch {
      /* keep looking */
    }
  }
  const which = spawnSync("where.exe", ["grok.exe"], { encoding: "utf8" });
  const found = (which.stdout || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean)[0];
  return found || "grok.exe";
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export function runGrok(
  grokPath: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(grokPath, args, {
      cwd: opts.cwd || os.homedir(),
      env: { ...process.env, GROK_DISABLE_AUTOUPDATER: "1", ...opts.env },
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d: string) => (stdout += d));
    child.stderr?.on("data", (d: string) => (stderr += d));
    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
    }, opts.timeoutMs ?? 20_000);
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: String(err) });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

const SESSION_LINE =
  /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s+(\d{4}-\d{2}-\d{2})\s+(\d{4}-\d{2}-\d{2})\s+(\S+)\s*(.*)$/;

export async function listSessions(grokPath: string, limit = 100): Promise<SessionSummary[]> {
  const { stdout } = await runGrok(grokPath, ["sessions", "list", "-n", String(limit)], {
    timeoutMs: 25_000,
  });
  const out: SessionSummary[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const m = SESSION_LINE.exec(line.trim());
    if (!m) continue;
    const title = (m[5] || "").trim();
    out.push({
      id: m[1],
      created: m[2],
      updated: m[3],
      status: m[4],
      title: title && title !== "(no summary)" ? title : "（无摘要）",
    });
  }
  return out;
}

function stripFrontmatter(text: string): { meta: Record<string, string>; body: string } {
  if (!text.startsWith("---")) return { meta: {}, body: text };
  const end = text.indexOf("\n---", 3);
  if (end < 0) return { meta: {}, body: text };
  const head = text.slice(3, end).split(/\r?\n/);
  const meta: Record<string, string> = {};
  let key = "";
  for (const line of head) {
    const m = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (m) {
      key = m[1];
      meta[key] = m[2].trim().replace(/^["']|["']$/g, "");
    } else if (key && line.trim()) {
      meta[key] = `${meta[key]} ${line.trim()}`.trim();
    }
  }
  return { meta, body: text.slice(end + 4) };
}

async function walkForFiles(root: string, fileName: string, maxDepth: number): Promise<string[]> {
  const found: string[] = [];
  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules") {
        await walk(full, depth + 1);
      } else if (e.isFile() && e.name.toLowerCase() === fileName.toLowerCase()) {
        found.push(full);
      }
    }
  }
  await walk(root, 0);
  return found;
}

export async function listSkills(): Promise<SkillEntry[]> {  const roots: { dir: string; source: SkillEntry["source"] }[] = [
    { dir: path.join(grokHome(), "skills"), source: "grok" },
    { dir: path.join(os.homedir(), ".claude", "skills"), source: "claude" },
  ];
  const disabled = readDisabledSkills();
  const out: SkillEntry[] = [];
  const seen = new Set<string>();
  for (const r of roots) {
    const files = await walkForFiles(r.dir, "SKILL.md", 4);
    for (const file of files) {
      let text = "";
      try {
        text = await fsp.readFile(file, "utf8");
      } catch {
        continue;
      }
      const { meta } = stripFrontmatter(text);
      const dirName = path.basename(path.dirname(file));
      const name = meta.name || dirName;
      if (seen.has(name)) continue;
      seen.add(name);
      out.push({
        name,
        description: (meta.description || "").slice(0, 240),
        source: r.source,
        path: file,
        disabled: disabled.includes(name) || disabled.includes(dirName),
      });
    }
  }
  return out.sort((a, b) => Number(!!a.disabled) - Number(!!b.disabled) || a.name.localeCompare(b.name));
}

export function skillsRoot(): string {
  return path.join(grokHome(), "skills");
}

function sanitizeSkillDir(name: string): string {
  const cleaned = name
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, "-")
    .replace(/^\.+/, "")
    .replace(/[. ]+$/, "");
  if (!cleaned) throw new Error("技能目录名不能为空");
  return cleaned;
}

function yamlValue(value: string): string {
  if (!value) return '""';
  return /[:#"'\r\n]/.test(value)
    ? `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
    : value;
}

/** 复制一个含 SKILL.md 的目录进 ~/.grok/skills，重名自动加序号。 */
async function copySkillDir(root: string, used: Set<string>): Promise<string> {
  const destRoot = skillsRoot();
  const rootAbs = path.resolve(root);
  const destAbs = path.resolve(destRoot);
  if (rootAbs === destAbs || rootAbs.startsWith(destAbs + path.sep)) {
    throw new Error("该目录已经在技能目录里，不用重复安装");
  }
  await fsp.mkdir(destRoot, { recursive: true });
  const base = sanitizeSkillDir(path.basename(root));
  let name = base;
  let n = 1;
  while (fs.existsSync(path.join(destRoot, name)) || used.has(name)) {
    name = `${base}-${++n}`;
  }
  used.add(name);
  const dest = path.join(destRoot, name);
  await fsp.cp(root, dest, { recursive: true });
  return dest;
}

/** 选中目录或解压目录里可能有多套技能，取最外层的 SKILL.md 各装一份。 */
export async function installSkillsFromDir(sourceDir: string): Promise<string[]> {
  if (!fs.existsSync(sourceDir)) throw new Error(`目录不存在：${sourceDir}`);
  const files = await walkForFiles(sourceDir, "SKILL.md", 3);
  if (!files.length) throw new Error("这个目录里没有找到 SKILL.md");
  const roots = [...new Set(files.map((f) => path.dirname(f)))];
  const top = roots.filter((r) => !roots.some((o) => o !== r && r.startsWith(o + path.sep)));
  const used = new Set<string>();
  const installed: string[] = [];
  for (const root of top) installed.push(await copySkillDir(root, used));
  return installed;
}

export async function installSkillsFromZip(zipFile: string): Promise<string[]> {
  if (!fs.existsSync(zipFile)) throw new Error(`压缩包不存在：${zipFile}`);
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), "tanwei-skill-zip-"));
  try {
    const quote = (v: string) => v.replace(/'/g, "''");
    const script = `Expand-Archive -LiteralPath '${quote(zipFile)}' -DestinationPath '${quote(tmp)}' -Force`;
    const res = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { windowsHide: true, encoding: "utf8" },
    );
    if (res.status !== 0) {
      throw new Error(`解压失败：${(res.stderr || res.stdout || "").trim().slice(0, 300)}`);
    }
    return await installSkillsFromDir(tmp);
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
}

export async function createSkill(input: NewSkillInput): Promise<string> {
  const name = input.name.trim();
  if (!name) throw new Error("技能名不能为空");
  if (name.length > 80) throw new Error("技能名太长（最多 80 字）");
  const dirName = sanitizeSkillDir(name);
  const dest = path.join(skillsRoot(), dirName);
  if (fs.existsSync(dest)) throw new Error(`技能目录已存在：${dirName}`);
  const description = (input.description ?? "").trim().replace(/\r?\n/g, " ");
  const body =
    (input.body ?? "").trim() || `# ${name}\n\n## 何时使用\n\n- 待补充\n\n## 怎么做\n\n1. 待补充\n`;
  const text = [
    "---",
    `name: ${yamlValue(name)}`,
    `description: ${yamlValue(description)}`,
    "---",
    "",
    body,
    "",
  ].join("\n");
  await fsp.mkdir(dest, { recursive: true });
  await fsp.writeFile(path.join(dest, "SKILL.md"), text, "utf8");
  return dest;
}

function readDisabledSkills(): string[] {
  try {
    const cfg = fs.readFileSync(path.join(grokHome(), "config.toml"), "utf8");
    const block = /\[skills\]([\s\S]*?)(\n\[|$)/.exec(cfg)?.[1] ?? "";
    const arr = /disabled\s*=\s*\[([\s\S]*?)\]/.exec(block)?.[1] ?? "";
    return [...arr.matchAll(/"([^"]+)"|'([^']+)'/g)].map((m) => m[1] || m[2]);
  } catch {
    return [];
  }
}

export async function listRules(): Promise<RuleEntry[]> {
  const dir = path.join(grokHome(), "rules");
  let entries: fs.Dirent[] = [];
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: RuleEntry[] = [];
  for (const e of entries) {
    if (!e.isFile() || !e.name.toLowerCase().endsWith(".md")) continue;
    const file = path.join(dir, e.name);
    let text = "";
    try {
      text = await fsp.readFile(file, "utf8");
    } catch {
      continue;
    }
    const title = /^#\s+(.+)$/m.exec(text)?.[1]?.trim() || e.name.replace(/\.md$/i, "");
    out.push({
      name: e.name.replace(/\.md$/i, ""),
      title,
      path: file,
      tokens: Math.ceil(text.length / 3.2),
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export function taskRoots(): { task: string; root: string }[] {
  const roots: { task: string; root: string }[] = [];
  const desktops = [path.join(os.homedir(), "Desktop"), path.join(os.homedir(), "桌面")];
  for (const desktop of desktops) {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(desktop, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (!/_SRC挖洞$/i.test(e.name)) continue;
      const root = path.join(desktop, e.name);
      if (roots.some((r) => r.root.toLowerCase() === root.toLowerCase())) continue;
      roots.push({ task: e.name.replace(/_SRC挖洞$/i, ""), root });
    }
  }
  return roots;
}

export async function listAssetTasks(): Promise<AssetTask[]> {
  const out: AssetTask[] = [];
  for (const { task, root } of taskRoots()) {
    const assetDir = path.join(root, "资产");
    const reportDir = path.join(root, "报告");
    let assetCount = 0;
    try {
      assetCount = (await fsp.readdir(assetDir, { withFileTypes: true })).filter((e) => e.isFile()).length;
    } catch {
      /* missing */
    }
    let reportCount = 0;
    let latestReport: string | undefined;
    let updatedAt = 0;
    try {
      const reports = (await fsp.readdir(reportDir, { withFileTypes: true }))
        .filter((e) => e.isFile() && e.name.toLowerCase().endsWith(".md"))
        .map((e) => path.join(reportDir, e.name));
      reportCount = reports.length;
      const stats = await Promise.all(
        reports.map(async (p) => ({ p, st: await fsp.stat(p).catch(() => undefined) })),
      );
      const newest = stats
        .filter((s) => s.st)
        .sort((a, b) => (b.st!.mtimeMs || 0) - (a.st!.mtimeMs || 0))[0];
      if (newest?.st) {
        latestReport = path.basename(newest.p, ".md");
        updatedAt = newest.st.mtimeMs;
      }
    } catch {
      /* missing */
    }
    out.push({ task, root, assetCount, reportCount, latestReport, updatedAt });
  }
  return out.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

export async function listReports(): Promise<ReportEntry[]> {
  const out: ReportEntry[] = [];
  for (const { task, root } of taskRoots()) {
    const dir = path.join(root, "报告");
    let entries: fs.Dirent[] = [];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isFile() || !e.name.toLowerCase().endsWith(".md")) continue;
      const full = path.join(dir, e.name);
      const st = await fsp.stat(full).catch(() => undefined);
      out.push({
        task,
        title: e.name.replace(/\.md$/i, ""),
        path: full,
        updatedAt: st?.mtimeMs ?? 0,
        size: st?.size ?? 0,
      });
    }
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

export function readPermissionMode(): "ask" | "auto" | "plan" | "always-approve" {
  try {
    const cfg = fs.readFileSync(path.join(grokHome(), "config.toml"), "utf8");
    const section = /\[ui\]([\s\S]*?)(\n\[|$)/.exec(cfg)?.[1] ?? "";
    const mode = /permission_mode\s*=\s*"([^"]+)"/.exec(section)?.[1];
    if (mode === "always-approve" || mode === "auto" || mode === "plan") return mode;
    return "ask";
  } catch {
    return "ask";
  }
}

export async function openPath(target: string): Promise<string> {
  const err = await shell.openPath(target);
  return err;
}

export function revealPath(target: string): void {
  shell.showItemInFolder(target);
}

export async function launchTui(grokPath: string, cwd: string): Promise<void> {
  if (process.platform !== "win32") {
    spawn(grokPath, [], { cwd, detached: true, stdio: "ignore" }).unref();
    return;
  }
  const hasWt = spawnSync("where.exe", ["wt.exe"], { encoding: "utf8" }).status === 0;
  if (hasWt) {
    const child = spawn(
      "wt.exe",
      ["-d", cwd, "cmd.exe", "/k", `"${grokPath}"`],
      { cwd, detached: true, stdio: "ignore", windowsHide: false },
    );
    child.unref();
    return;
  }
  const child = spawn(
    "cmd.exe",
    ["/c", "start", '"天鉴·探微 | 安全测试平台 TUI"', "cmd.exe", "/k", `"${grokPath}"`],
    { cwd, detached: true, stdio: "ignore", windowsHide: false },
  );
  child.unref();
}

export function sanitizeMcpServers(raw: any[]): McpServerInfo[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((s) => ({
    name: String(s?.name ?? "unknown"),
    status: String(s?.status ?? "pending"),
    source: s?.source,
    reason: s?.reason,
    tools: typeof s?.tools === "number" ? s.tools : null,
  }));
}

export async function listMcpSummary(): Promise<McpServerInfo[]> {
  const { stdout } = await runGrok(resolveGrokPath(), ["mcp", "list"], { timeoutMs: 15_000 });
  const out: McpServerInfo[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = /^([^:\s]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push({
      name: m[1],
      status: "configured",
      source: "local",
      reason: m[2].slice(0, 160),
      tools: null,
    });
  }
  return out;
}
