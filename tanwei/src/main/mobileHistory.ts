import fsp from "node:fs/promises";
import path from "node:path";
import { app } from "electron";
import type { MobileAnalysis, MobileHistoryRecord } from "../shared/types";

/**
 * 小程序 / APP 面板的拆解历史。
 *
 * 面板切「本会话」时只能看到归属该会话的记录，和任务夹 / 发现 / 报告同一套语义：
 * 拆解时带上当前会话 id 就归属过去，没带就留在总览里等用户手动归属。
 * 只存精简版（去掉逐行解包日志），两百多条也才几百 KB。
 */

const MAX_RECORDS = 300;

function storeFile(): string {
  return path.join(app.getPath("userData"), "mobile-history.json");
}

let cache: MobileHistoryRecord[] | null = null;
let queue: Promise<unknown> = Promise.resolve();

/** 同一目标重拆只留一条：target.id = sha1(kind + 路径) */
function slim(
  analysis: MobileAnalysis,
  sessionId: string | undefined,
  prev?: MobileHistoryRecord,
): MobileHistoryRecord {
  const { log: _log, ...rest } = analysis;
  const now = Date.now();
  return {
    ...rest,
    id: analysis.target.id,
    sessionId,
    createdAt: prev?.createdAt ?? now,
    updatedAt: now,
  };
}

async function readAll(): Promise<MobileHistoryRecord[]> {
  if (cache) return cache;
  try {
    const raw = await fsp.readFile(storeFile(), "utf8");
    const parsed: unknown = JSON.parse(raw);
    // 老文件没有顶层 id，按 target.id 补上
    cache = Array.isArray(parsed)
      ? (parsed as MobileHistoryRecord[])
          .filter((r) => r && r.target && typeof r.target.id === "string")
          .map((r) => (r.id ? r : { ...r, id: r.target.id }))
      : [];
  } catch {
    cache = [];
  }
  return cache;
}

async function writeAll(list: MobileHistoryRecord[]): Promise<void> {
  const sorted = [...list].sort((a, b) => b.updatedAt - a.updatedAt).slice(0, MAX_RECORDS);
  cache = sorted;
  const file = storeFile();
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(sorted, null, 2), "utf8");
  await fsp.rename(tmp, file);
}

/** 读写串成一条链：面板可能连点重拆，别让两次写入互相覆盖 */
function serialize<T>(work: () => Promise<T>): Promise<T> {
  const next = queue.then(work, work);
  queue = next.catch(() => undefined);
  return next;
}

export function listMobileHistory(sessionId?: string): Promise<MobileHistoryRecord[]> {
  return serialize(async () => {
    const all = await readAll();
    const sid = sessionId?.trim();
    return sid ? all.filter((r) => r.sessionId === sid) : all;
  });
}

export function rememberMobileAnalysis(
  analysis: MobileAnalysis,
  sessionId?: string,
): Promise<MobileHistoryRecord> {
  return serialize(async () => {
    const all = await readAll();
    const prev = all.find((r) => r.target.id === analysis.target.id);
    // 没带会话的这次（比如总览里重拆）沿用原归属，别把记录从会话里挤出去
    const sid = sessionId?.trim() || prev?.sessionId;
    const record = slim(analysis, sid, prev);
    await writeAll([record, ...all.filter((r) => r.target.id !== analysis.target.id)]);
    return record;
  });
}

export function forgetMobileRecord(id: string): Promise<boolean> {
  return serialize(async () => {
    const all = await readAll();
    const next = all.filter((r) => r.target.id !== id);
    if (next.length === all.length) return false;
    await writeAll(next);
    return true;
  });
}

export function clearMobileHistory(sessionId?: string): Promise<number> {
  return serialize(async () => {
    const all = await readAll();
    const sid = sessionId?.trim();
    const next = sid ? all.filter((r) => r.sessionId !== sid) : [];
    const removed = all.length - next.length;
    if (removed) await writeAll(next);
    return removed;
  });
}

/** 按会话归属某条记录；sessionId 留空 = 退回未归属（只在总览里出现） */
export function claimMobileRecord(id: string, sessionId?: string): Promise<boolean> {
  return serialize(async () => {
    const all = await readAll();
    const hit = all.find((r) => r.target.id === id);
    if (!hit) return false;
    hit.sessionId = sessionId?.trim() || undefined;
    hit.updatedAt = Date.now();
    await writeAll(all);
    return true;
  });
}
