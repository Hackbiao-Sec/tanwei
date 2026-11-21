import type { Dirent } from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import type { LogFile, LogTail } from "../shared/types";
import { grokHome } from "./system";

const MAX_FILES = 60;
const MAX_TAIL_BYTES = 512 * 1024;

function logsRoot(): string {
  return path.join(grokHome(), "logs");
}

async function walk(dir: string, depth: number, root: string, out: LogFile[]): Promise<void> {
  if (depth > 3) return;
  let entries: Dirent[] = [];
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, depth + 1, root, out);
      continue;
    }
    if (!entry.isFile()) continue;
    const st = await fsp.stat(full).catch(() => undefined);
    if (!st) continue;
    out.push({ name: path.relative(root, full).split(path.sep).join("/"), path: full, size: st.size, updatedAt: st.mtimeMs });
  }
}

/** 引擎与 MCP 的日志文件，按更新时间倒序。 */
export async function listLogFiles(): Promise<LogFile[]> {
  const root = logsRoot();
  const out: LogFile[] = [];
  await walk(root, 0, root, out);
  const startup = path.join(grokHome(), "tanwei-startup.log");
  const startupStat = await fsp.stat(startup).catch(() => undefined);
  if (startupStat) {
    out.push({ name: "tanwei-startup.log", path: startup, size: startupStat.size, updatedAt: startupStat.mtimeMs });
  }
  out.sort((a, b) => b.updatedAt - a.updatedAt);
  return out.slice(0, MAX_FILES);
}

/** 只允许读日志目录（或本程序自己的启动日志），按字节从尾部截取。 */
export async function readLogTail(target: string, lines = 400): Promise<LogTail> {
  const root = logsRoot();
  const startup = path.join(grokHome(), "tanwei-startup.log");
  const abs = path.resolve(target);
  if (abs !== startup && abs !== root && !abs.startsWith(root + path.sep)) {
    throw new Error("只能读取 .grok/logs 下的日志");
  }
  const st = await fsp.stat(abs);
  const start = Math.max(0, st.size - MAX_TAIL_BYTES);
  const handle = await fsp.open(abs, "r");
  try {
    const length = Math.max(0, st.size - start);
    const buf = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buf, 0, length, start);
    const text = buf.subarray(0, bytesRead).toString("utf8");
    const want = Math.max(1, Math.min(lines, 2000));
    const tail = text.split(/\r?\n/).slice(-want).join("\n");
    return { path: abs, text: tail, size: st.size, truncated: start > 0 };
  } finally {
    await handle.close().catch(() => undefined);
  }
}
