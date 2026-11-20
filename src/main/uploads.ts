import { app } from "electron";
import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import type { MobileUpload } from "../shared/types";

/**
 * 对话里上传的 APK / IPA / 小程序包 / 任意文件。
 * 文件复制到 <userData>/uploads/<会话>/ 下，注册表带 sessionId，保证会话隔离。
 */

const MAX_RECORDS = 200;
const MAX_COPY = 1_500_000_000; // 单文件 1.5 GB 上限，超过只登记路径不复制

function storeFile(): string {
  return path.join(app.getPath("userData"), "uploads.json");
}

function rootDir(): string {
  return path.join(app.getPath("userData"), "uploads");
}

function bucket(sessionId?: string): string {
  const id = String(sessionId ?? "").trim();
  return id ? id.replace(/[^\w.-]+/g, "_").slice(0, 80) : "_shared";
}

export function uploadRoot(): string {
  return rootDir();
}

function kindOf(file: string): string {
  const ext = path.extname(file).slice(1).toLowerCase();
  if (["apk", "apks", "xapk", "ipa", "wxapkg", "qapkg", "hap"].includes(ext)) return ext;
  if (["har", "pcap", "txt", "log", "json", "xml", "html", "csv", "md", "zip", "jar", "js", "pdf"].includes(ext))
    return ext;
  return ext || "file";
}

function readAll(): MobileUpload[] {
  try {
    const raw = fs.readFileSync(storeFile(), "utf8");
    const json = JSON.parse(raw) as { items?: MobileUpload[] };
    return Array.isArray(json.items) ? json.items : [];
  } catch {
    return [];
  }
}

function serialize(task: () => void): Promise<void> {
  const prev = pending;
  pending = prev.then(task, task);
  return pending;
}
let pending: Promise<void> = Promise.resolve();

async function writeAll(items: MobileUpload[]): Promise<void> {
  const file = storeFile();
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify({ items }, null, 2), "utf8");
  await fsp.rename(tmp, file);
}

export function listUploads(sessionId?: string): MobileUpload[] {
  const all = readAll();
  const id = String(sessionId ?? "").trim();
  const mine = id ? all.filter((u) => u.sessionId === id) : all;
  return mine.sort((a, b) => b.at - a.at);
}

export function uploadFile(file: string, sessionId?: string): MobileUpload | undefined {
  const src = String(file ?? "").trim();
  if (!src) return undefined;
  let stat: fs.Stats;
  try {
    stat = fs.statSync(src);
  } catch {
    return undefined;
  }
  if (!stat.isFile()) return undefined;
  const id = createHash("sha1").update(`${src}:${stat.size}:${stat.mtimeMs}`).digest("hex").slice(0, 16);
  const existing = readAll().find((u) => u.id === id && u.path === src);
  const sid = String(sessionId ?? "").trim() || undefined;
  const name = path.basename(src);
  if (existing) {
    if (!sid || existing.sessionId === sid) return existing;
  }
  let dest = src;
  if (stat.size <= MAX_COPY) {
    const dir = path.join(rootDir(), bucket(sid));
    try {
      fs.mkdirSync(dir, { recursive: true });
      dest = path.join(dir, `${id}-${name}`);
      if (!fs.existsSync(dest) || fs.statSync(dest).size !== stat.size) fs.copyFileSync(src, dest);
    } catch {
      dest = src;
    }
  }
  const record: MobileUpload = {
    id,
    sessionId: sid,
    name,
    path: dest,
    origin: dest === src ? undefined : src,
    size: stat.size,
    kind: kindOf(src),
    at: Date.now(),
  };
  void serialize(async () => {
    const all = readAll().filter((u) => !(u.id === id && u.sessionId === sid));
    all.unshift(record);
    await writeAll(all.slice(0, MAX_RECORDS));
  });
  return record;
}

export function addUploads(files: string[], sessionId?: string): MobileUpload[] {
  const out: MobileUpload[] = [];
  for (const file of files ?? []) {
    const rec = uploadFile(file, sessionId);
    if (rec) out.push(rec);
  }
  return out;
}

export function claimUpload(id: string, sessionId?: string): MobileUpload[] {
  const target = String(id ?? "").trim();
  if (!target) return readAll();
  void serialize(async () => {
    const all = readAll();
    for (const item of all) if (item.id === target) item.sessionId = String(sessionId ?? "").trim() || undefined;
    await writeAll(all);
  });
  return readAll();
}

export function forgetUpload(id: string): MobileUpload[] {
  const target = String(id ?? "").trim();
  void serialize(async () => {
    const all = readAll();
    const hit = all.find((u) => u.id === target);
    // 只删探微自己复制进来的副本，用户原始文件绝不动
    if (hit?.origin && hit.path.startsWith(rootDir()) && fs.existsSync(hit.path)) {
      try {
        fs.rmSync(hit.path, { force: true });
      } catch {
        /* 副本删不掉不影响记录清理 */
      }
    }
    await writeAll(all.filter((u) => u.id !== target));
  });
  return readAll();
}

export async function clearUploads(sessionId?: string): Promise<MobileUpload[]> {
  const sid = String(sessionId ?? "").trim();
  await serialize(async () => {
    const all = readAll();
    const keep: MobileUpload[] = [];
    for (const item of all) {
      const mine = sid ? item.sessionId === sid : true;
      if (!mine) {
        keep.push(item);
        continue;
      }
      if (item.origin && item.path.startsWith(rootDir()) && fs.existsSync(item.path)) {
        try {
          fs.rmSync(item.path, { force: true });
        } catch {
          /* ignore */
        }
      }
    }
    await writeAll(keep);
  });
  return readAll();
}
