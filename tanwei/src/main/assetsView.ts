import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import type { AssetCatalog, AssetHostGroup, AssetKind, AssetRecord } from "../shared/types";
import { taskRoots } from "./system";

const MAX_RECORDS = 30_000;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_LINE = 4_000;

const URL_RE = /\bhttps?:\/\/[^\s,;"'`<>()[\]\\]+/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
const HOSTPORT_RE = /\b(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z]{2,24}(?::\d{1,5})?\b/gi;
const WILDCARD_RE = /\*\.[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi;
const HEADING_RE = /^#{1,6}\s+(.+?)\s*#*$/;
const METHOD_PATH_RE = /^(?:(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(\/[\w./{}:~%\-*?=&+@]*)$/i;
const LABELED_RE = /^(?:域名|主机|host|target|目标|资产|接口|url|地址)\s*[:：=]\s*(\S+)/i;

function isIp(value: string): boolean {
  const host = value.replace(/:\d+$/, "");
  const parts = host.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function cleanToken(raw: string): string {
  return raw.replace(/[)\]}>）】，。；、"'`]+$/g, "").replace(/^[<("'`]+/g, "");
}

function stripBullet(line: string): string {
  return line
    .replace(/^\s*[-*•·>]+\s+/, "")
    .replace(/^\s*\d+[.)、]\s+/, "")
    .trim();
}

function hostOfUrl(value: string): { host: string; path: string } {
  try {
    const u = new URL(value);
    return { host: u.hostname + (u.port ? `:${u.port}` : ""), path: u.pathname + u.search };
  } catch {
    return { host: "", path: "" };
  }
}

function kindRank(kind: AssetKind): number {
  return kind === "domain" ? 0 : kind === "ip" ? 1 : kind === "service" ? 2 : 3;
}

interface Bucket {
  records: Map<string, AssetRecord>;
}

function addRecord(
  bucket: Bucket,
  base: { value: string; kind: AssetKind; host: string; task: string; file: string; line: number; at: number; method?: string; path?: string },
): void {
  if (bucket.records.size >= MAX_RECORDS) return;
  const value = base.value.trim();
  if (!value) return;
  const key = `${base.kind}|${base.host}|${base.method ?? ""}|${value}`;
  const existing = bucket.records.get(key);
  if (existing) {
    if (base.at > existing.updatedAt) existing.updatedAt = base.at;
    return;
  }
  bucket.records.set(key, {
    id: key,
    value: value.slice(0, 400),
    kind: base.kind,
    host: (base.host || value).slice(0, 200),
    method: base.method,
    path: base.path?.slice(0, 400),
    task: base.task,
    file: base.file,
    line: base.line,
    updatedAt: base.at,
  });
}

/** 一行里可能同时出现域名、IP、接口：逐个抽，抽不出就跳过 */
function parseLine(
  line: string,
  fallbackHost: string,
  out: { value: string; kind: AssetKind; host: string; method?: string; path?: string }[],
): string {
  const seen = new Set<string>();
  let lastHost = fallbackHost;
  const push = (value: string, kind: AssetKind, host: string, extra?: { method?: string; path?: string }) => {
    const key = `${kind}|${host}|${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ value, kind, host: host || fallbackHost, ...extra });
  };

  const urls = line.match(URL_RE) ?? [];
  for (const raw of urls) {
    const value = cleanToken(raw);
    if (!value) continue;
    const parts = hostOfUrl(value);
    if (!parts.host) continue;
    const isRoot = !parts.path || parts.path === "/";
    push(value, isRoot ? (isIp(parts.host) ? "ip" : "domain") : "endpoint", parts.host, {
      path: parts.path || "/",
    });
    lastHost = parts.host;
  }

  const withoutUrls = line.replace(URL_RE, " ");

  // 方法 + 纯路径（GET /api/user/list）
  const mp = METHOD_PATH_RE.exec(stripBullet(withoutUrls));
  if (mp) {
    const p = cleanToken(mp[2]);
    if (p.length > 1) push(p, "endpoint", fallbackHost, { method: mp[1]?.toUpperCase(), path: p });
  }

  for (const raw of withoutUrls.match(IPV4_RE) ?? []) {
    const value = cleanToken(raw);
    if (!value || !isIp(value)) continue;
    push(value, value.includes(":") ? "service" : "ip", value.replace(/:\d+$/, ""));
  }

  for (const raw of withoutUrls.match(WILDCARD_RE) ?? []) {
    const value = cleanToken(raw).toLowerCase();
    if (value) push(value, "domain", value.replace(/:\d+$/, ""));
  }

  for (const raw of withoutUrls.match(HOSTPORT_RE) ?? []) {
    const value = cleanToken(raw).toLowerCase();
    if (!value || isIp(value)) continue;
    // 文件名 / 版本号之类不当地址：至少要有两个点或带端口
    const hasPort = /:\d+$/.test(value);
    const dots = value.replace(/:\d+$/, "").split(".").length;
    if (!hasPort && dots < 2) continue;
    push(value, hasPort ? "service" : "domain", value.replace(/:\d+$/, ""));
  }

  return lastHost;
}

async function scanFile(
  bucket: Bucket,
  task: string,
  file: string,
  meta: { at: number },
): Promise<number> {
  const st = await fsp.stat(file).catch(() => undefined);
  if (!st?.size || st.size > MAX_FILE_BYTES) return 0;
  const text = await fsp.readFile(file, "utf8").catch(() => "");
  if (!text) return 0;
  const before = bucket.records.size;
  let currentHost = "";
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw || raw.length > MAX_LINE) continue;
    const line = raw.trim();
    if (!line) continue;

    const heading = HEADING_RE.exec(line);
    if (heading) {
      const title = stripBullet(heading[1]);
      const hostHit = HOSTPORT_RE.exec(title) ?? WILDCARD_RE.exec(title);
      HOSTPORT_RE.lastIndex = 0;
      WILDCARD_RE.lastIndex = 0;
      if (hostHit) currentHost = cleanToken(hostHit[0]).toLowerCase();
      continue;
    }

    const labeled = LABELED_RE.exec(stripBullet(line));
    if (labeled) {
      const target = cleanToken(labeled[1]);
      const hostOnly = hostOfUrl(target);
      if (hostOnly.host) currentHost = hostOnly.host;
      else if (!isIp(target) && target.includes(".")) currentHost = target.toLowerCase();
    }

    const found: { value: string; kind: AssetKind; host: string; method?: string; path?: string }[] = [];
    const lastHost = parseLine(line, currentHost, found);
    for (const item of found) {
      // 表格式清单：| 域名 | 接口 | 状态 | 只取前两列里的地址
      addRecord(bucket, {
        value: item.value,
        kind: item.kind,
        host: item.host,
        method: item.method,
        path: item.path,
        task,
        file,
        line: i + 1,
        at: meta.at,
      });
    }
    if (lastHost) currentHost = lastHost;
  }
  return bucket.records.size - before;
}

async function collectAssetFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (target: string, depth: number) => {
    let entries: fs.Dirent[] = [];
    try {
      entries = await fsp.readdir(target, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      const full = path.join(target, e.name);
      if (e.isDirectory()) {
        if (depth > 1) continue;
        await walk(full, depth + 1);
        continue;
      }
      if (e.isFile()) out.push(full);
    }
  };
  await walk(dir, 0);
  return out;
}

/** 把 资产/ 里的清单正文拆成域名 / IP / 接口 / 服务，按主机归组给前端做可视化 */
export async function buildAssetCatalog(scope?: string[]): Promise<AssetCatalog> {
  const bucket: Bucket = { records: new Map() };
  const files: AssetCatalog["files"] = [];
  const only = scope ? new Set(scope) : undefined;

  for (const { task, root } of taskRoots()) {
    if (only && !only.has(task)) continue;
    const dir = path.join(root, "资产");
    const list = await collectAssetFiles(dir);
    for (const file of list) {
      const st = await fsp.stat(file).catch(() => undefined);
      const added = await scanFile(bucket, task, file, { at: st?.mtimeMs ?? Date.now() });
      files.push({
        task,
        name: path.relative(root, file) || path.basename(file),
        path: file,
        entries: added,
      });
    }
  }

  const records = [...bucket.records.values()];
  const byHost = new Map<string, AssetHostGroup>();
  for (const record of records) {
    const key = record.host.toLowerCase();
    const group = byHost.get(key) ?? {
      host: record.host,
      task: record.task,
      records: [],
      counts: { domain: 0, ip: 0, endpoint: 0, service: 0 },
      updatedAt: 0,
    };
    group.records.push(record);
    group.counts[record.kind] += 1;
    group.updatedAt = Math.max(group.updatedAt, record.updatedAt);
    if (record.task < group.task) group.task = record.task;
    byHost.set(key, group);
  }

  const hosts = [...byHost.values()]
    .map((g) => ({
      ...g,
      records: g.records.sort(
        (a, b) => kindRank(a.kind) - kindRank(b.kind) || a.value.localeCompare(b.value) || a.method?.localeCompare(b.method ?? "") || 0,
      ),
    }))
    .sort((a, b) => b.counts.endpoint - a.counts.endpoint || b.records.length - a.records.length);

  const totals = {
    domain: 0,
    ip: 0,
    endpoint: 0,
    service: 0,
    total: records.length,
    hosts: hosts.length,
    tasks: new Set(records.map((r) => r.task)).size,
  };
  for (const record of records) totals[record.kind] += 1;

  return {
    records,
    hosts,
    tasks: [...new Set(records.map((r) => r.task))].sort(),
    totals,
    files: files.sort((a, b) => b.entries - a.entries),
  };
}
