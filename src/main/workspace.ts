import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import type { AssetItem, Finding, FindingSeverity, TaskFile, WorkspaceStats } from "../shared/types";
import { taskRoots } from "./system";

const SEVERITY_RE = /漏洞等级\s*[：:]\s*(严重|高危|中危|低危)/;
const TARGET_RE = /目标网站URL\s*[：:]\s*(\S+)/;

const TYPE_RULES: { re: RegExp; type: string }[] = [
  { re: /SQL|注入/i, type: "SQL 注入" },
  { re: /XSS|跨站脚本/i, type: "XSS" },
  { re: /SSRF|服务端请求伪造/i, type: "SSRF" },
  { re: /RCE|命令执行|代码执行|反序列化/i, type: "RCE" },
  { re: /越权|IDOR|越权访问|水平权限|垂直权限/i, type: "越权 / IDOR" },
  { re: /未授权|匿名/i, type: "未授权访问" },
  { re: /上传/i, type: "文件上传" },
  { re: /穿越|跨目录/i, type: "路径穿越" },
  { re: /弱口令|默认口令|默认密码/i, type: "弱口令" },
  { re: /接管|任意登录|认证绕过|重置/i, type: "认证 / 接管" },
  { re: /逻辑|支付|竞态|并发|绕过的/i, type: "业务逻辑" },
  { re: /信息泄露|泄露|敏感/i, type: "信息泄露" },
  { re: /JWT/i, type: "JWT" },
  { re: /SSO|OAuth/i, type: "OAuth / SSO" },
];

function severityOf(text: string): FindingSeverity {
  const m = SEVERITY_RE.exec(text);
  return (m?.[1] as FindingSeverity) ?? "未知";
}

function typeOf(title: string): string {
  for (const rule of TYPE_RULES) if (rule.re.test(title)) return rule.type;
  return "其他";
}

async function readHead(file: string, bytes = 4096): Promise<string> {
  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(file, "r");
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await handle.read(buf, 0, bytes, 0);
    return buf.subarray(0, bytesRead).toString("utf8");
  } catch {
    return "";
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** scope 传任务名列表时只扫这些任务夹，用会话级隔离；不传才是总览 */
export async function listFindings(scope?: string[]): Promise<Finding[]> {
  const out: Finding[] = [];
  const only = scope ? new Set(scope) : undefined;
  for (const { task, root } of taskRoots()) {
    if (only && !only.has(task)) continue;
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
      const [st, head] = await Promise.all([fsp.stat(full).catch(() => undefined), readHead(full)]);
      const title = e.name.replace(/\.md$/i, "");
      // 等级优先读正文，正文缺了再退回文件名里的关键字
      let severity = severityOf(head);
      if (severity === "未知") severity = severityOf(title);
      out.push({
        task,
        title,
        severity,
        type: typeOf(title),
        target: TARGET_RE.exec(head)?.[1],
        path: full,
        updatedAt: st?.mtimeMs ?? 0,
        size: st?.size ?? 0,
      });
    }
  }
  const rank: Record<FindingSeverity, number> = { 严重: 0, 高危: 1, 中危: 2, 低危: 3, 未知: 4 };
  return out.sort((a, b) => rank[a.severity] - rank[b.severity] || b.updatedAt - a.updatedAt);
}

function looksLikeEntry(line: string): boolean {
  return /https?:\/\//i.test(line) || /^[\w.-]+\.[a-z]{2,}(\/|$)/i.test(line.trim());
}

export async function listAssetItems(scope?: string[]): Promise<AssetItem[]> {
  const out: AssetItem[] = [];
  const only = scope ? new Set(scope) : undefined;
  for (const { task, root } of taskRoots()) {
    if (only && !only.has(task)) continue;
    const dir = path.join(root, "资产");
    let entries: fs.Dirent[] = [];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isFile() || e.name.startsWith(".")) continue;
      const full = path.join(dir, e.name);
      const st = await fsp.stat(full).catch(() => undefined);
      let text = "";
      if ((st?.size ?? 0) <= 2 * 1024 * 1024) {
        text = await fsp.readFile(full, "utf8").catch(() => "");
      }
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const entriesFound = lines.filter(looksLikeEntry);
      out.push({
        task,
        name: e.name,
        path: full,
        kind: path.extname(e.name).replace(".", "").toLowerCase() || "file",
        size: st?.size ?? 0,
        updatedAt: st?.mtimeMs ?? 0,
        lines: lines.length,
        sample: entriesFound.slice(0, 3),
      });
    }
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

export async function workspaceStats(): Promise<WorkspaceStats> {
  const [findings, assets] = await Promise.all([listFindings(), listAssetItems()]);
  const counts = { severe: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of findings) {
    if (f.severity === "严重") counts.severe++;
    else if (f.severity === "高危") counts.high++;
    else if (f.severity === "中危") counts.medium++;
    else if (f.severity === "低危") counts.low++;
    else counts.unknown++;
  }
  return {
    tasks: taskRoots().length,
    reports: findings.length,
    findings: counts,
    assets: assets.length,
    assetEntries: assets.reduce((sum, a) => sum + a.lines, 0),
  };
}

const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__"]);

/** 任务夹里的文件清单（两层深），给「文件预览」用 */
export async function listTaskFiles(taskName?: string): Promise<TaskFile[]> {
  // 先只走目录把路径收齐，再并发取 stat：桌面任务多时串行 stat 会拖到三四秒
  const pending: { task: string; group: string; name: string; path: string }[] = [];

  const walk = async (task: string, dir: string, group: string, depth: number) => {
    let entries: fs.Dirent[] = [];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth > 1 || SKIP_DIRS.has(e.name)) continue;
        await walk(task, full, group, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      pending.push({ task, group, name: e.name, path: full });
    }
  };

  for (const { task, root } of taskRoots()) {
    if (taskName && task !== taskName) continue;
    let entries: fs.Dirent[] = [];
    try {
      entries = await fsp.readdir(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      if (e.isDirectory()) await walk(task, path.join(root, e.name), e.name, 0);
      else if (e.isFile()) await walk(task, root, "根目录", 2);
    }
  }

  const out: TaskFile[] = new Array(pending.length);
  let cursor = 0;
  const statWorker = async () => {
    while (cursor < pending.length) {
      const i = cursor++;
      const item = pending[i];
      const st = await fsp.stat(item.path).catch(() => undefined);
      out[i] = { ...item, size: st?.size ?? 0, updatedAt: st?.mtimeMs ?? 0 };
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, pending.length) }, statWorker));

  // 每个任务夹的每个子目录最多留 300 个最新文件，避免 js/ 之类大目录把 IPC 撑爆
  const perGroup = new Map<string, TaskFile[]>();
  for (const item of out.sort((a, b) => b.updatedAt - a.updatedAt)) {
    const key = `${item.task}|${item.group}`;
    const list = perGroup.get(key) ?? [];
    if (list.length >= 300) continue;
    list.push(item);
    perGroup.set(key, list);
  }

  return [...perGroup.values()]
    .flat()
    .sort((a, b) => a.task.localeCompare(b.task) || a.group.localeCompare(b.group) || b.updatedAt - a.updatedAt);
}

/** 只允许读任务目录里的文件，供报告预览用 */export async function readTaskFile(target: string, limit = 400_000): Promise<string> {
  const resolved = path.resolve(target);
  const allowed = taskRoots().some((t) => {
    const root = path.resolve(t.root) + path.sep;
    return resolved.toLowerCase().startsWith(root.toLowerCase());
  });
  if (!allowed) throw new Error("只允许读取任务目录内的文件");
  const st = await fsp.stat(resolved);
  if (!st.isFile()) throw new Error("不是文件");
  const buf = await fsp.readFile(resolved);
  const text = buf.subarray(0, limit).toString("utf8");
  return buf.length > limit ? `${text}\n\n…（已截断，共 ${buf.length} 字节）` : text;
}
