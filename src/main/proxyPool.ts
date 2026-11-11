import { app, net, session } from "electron";
import fs from "node:fs";
import path from "node:path";
import type {
  ProxyEntry,
  ProxyFreeResult,
  ProxyImportResult,
  ProxyPool,
  ProxySource,
} from "../shared/types";

/**
 * 代理池：只对本机 grok agent 子进程生效（HTTP(S)_PROXY / ALL_PROXY），
 * 不改 Windows 系统代理，也不碰浏览器配置。池本身落盘在 userData/proxy-pool.json。
 */

const MAX_ENTRIES = 3000;
const MAX_IMPORT_BYTES = 6 * 1024 * 1024;
/** 测活走 204，任何 2xx/3xx 都算这条代理能用 */
const HEALTH_URL = "http://www.gstatic.com/generate_204";
const HEALTH_TIMEOUT_MS = 7_000;
const HEALTH_SLOTS = 6;
/** 一次「测活」最多测这么多条，免费源整批入库时几千条测不完 */
const MAX_TEST = 400;

/** 免费源：纯文本一行一条，host:port 或 scheme://host:port */
const FREE_SOURCES: { url: string; scheme: "http" | "socks5" }[] = [
  { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", scheme: "http" },
  { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", scheme: "socks5" },
  { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", scheme: "http" },
  { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", scheme: "socks5" },
  {
    url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=8000&country=all&ssl=all&anonymity=all",
    scheme: "http",
  },
  { url: "https://proxyspace.pro/http.txt", scheme: "http" },
  { url: "https://proxyspace.pro/socks5.txt", scheme: "socks5" },
];

const DEFAULT_POOL: ProxyPool = { entries: [], rotate: false };

export function poolPath(): string {
  return path.join(app.getPath("userData"), "proxy-pool.json");
}

function normalizeHealth(value: unknown): ProxyEntry["health"] {
  return value === "ok" || value === "bad" ? value : "unknown";
}

function normalizeSource(value: unknown): ProxySource {
  return value === "free" || value === "manual" ? value : "config";
}

export function readPool(): ProxyPool {
  try {
    const raw = JSON.parse(fs.readFileSync(poolPath(), "utf8"));
    const list = Array.isArray(raw?.entries) ? raw.entries : [];
    const entries: ProxyEntry[] = [];
    for (const item of list) {
      const url = normalizeProxyUrl(String(item?.url ?? ""));
      if (!url) continue;
      entries.push({
        id: typeof item?.id === "string" && item.id ? item.id : makeId(url),
        url,
        label: typeof item?.label === "string" && item.label ? item.label : undefined,
        source: normalizeSource(item?.source),
        enabled: item?.enabled !== false,
        health: normalizeHealth(item?.health),
        latencyMs: typeof item?.latencyMs === "number" ? item.latencyMs : undefined,
        checkedAt: typeof item?.checkedAt === "number" ? item.checkedAt : undefined,
        error: typeof item?.error === "string" ? item.error : undefined,
      });
    }
    const activeId = entries.some((e) => e.id === raw?.activeId) ? String(raw.activeId) : undefined;
    return { entries, activeId, rotate: raw?.rotate === true, updatedAt: raw?.updatedAt };
  } catch {
    return { ...DEFAULT_POOL };
  }
}

function writePool(pool: ProxyPool): ProxyPool {
  const next: ProxyPool = { ...pool, updatedAt: Date.now() };
  fs.mkdirSync(path.dirname(poolPath()), { recursive: true });
  fs.writeFileSync(poolPath(), `${JSON.stringify(next, null, 2)}\n`, "utf8");
  return next;
}

let seq = 0;
function makeId(url: string): string {
  seq += 1;
  return `px-${Date.now().toString(36)}-${seq.toString(36)}-${url.length.toString(36)}`;
}

/** host 形如 IPv4、域名；不接受空串和带空白的垃圾 */
function hostOk(host: string): boolean {
  return /^[a-z0-9._-]{3,80}$/i.test(host) && !/^\.|\.$/.test(host);
}

function portOk(port: string): boolean {
  const n = Number(port);
  return Number.isInteger(n) && n > 0 && n <= 65535;
}

/** 统一成 scheme://[user:pass@]host:port */
export function normalizeProxyUrl(raw: string): string {
  let value = raw.trim().replace(/^["'<[(]+|["'>\])]+$/g, "");
  if (!value || value.length > 200) return "";
  value = value.replace(/\/+$/, "");
  const schemeMatch = value.match(/^([a-z][a-z0-9+.-]*):\/\/(.+)$/i);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (!["http", "https", "socks4", "socks5", "socks5h"].includes(scheme)) return "";
    const rest = schemeMatch[2];
    const at = rest.lastIndexOf("@");
    const creds = at >= 0 ? rest.slice(0, at) : "";
    const hostPart = at >= 0 ? rest.slice(at + 1) : rest;
    const [host, port] = hostPart.split(":");
    if (!hostOk(host ?? "") || !portOk(port ?? "")) return "";
    return `${scheme}://${creds ? `${creds}@` : ""}${host.toLowerCase()}:${port}`;
  }
  // user:pass@host:port
  if (value.includes("@")) {
    const at = value.lastIndexOf("@");
    const creds = value.slice(0, at);
    const [host, port] = value.slice(at + 1).split(":");
    if (!hostOk(host ?? "") || !portOk(port ?? "")) return "";
    return `http://${creds}@${host.toLowerCase()}:${port}`;
  }
  const parts = value.split(":").map((p) => p.trim());
  if (parts.length === 2 && hostOk(parts[0]) && portOk(parts[1])) {
    return `http://${parts[0].toLowerCase()}:${parts[1]}`;
  }
  // host:port:user:pass
  if (parts.length === 4 && hostOk(parts[0]) && portOk(parts[1])) {
    return `http://${parts[2]}:${parts[3]}@${parts[0].toLowerCase()}:${parts[1]}`;
  }
  // user:pass:host:port
  if (parts.length === 4 && hostOk(parts[2]) && portOk(parts[3])) {
    return `http://${parts[0]}:${parts[1]}@${parts[2].toLowerCase()}:${parts[3]}`;
  }
  return "";
}

function stripComment(line: string): string {
  return line.replace(/\s#.*$/, "").replace(/\s\/\/.*$/, "").replace(/^\s*#.*$/, "").replace(/^\s*\/\/.*$/, "");
}

interface ParsedToken {
  url: string;
  label?: string;
}

/** 解析一份代理配置文本：纯文本一行一条、CSV、JSON（数组/对象/供应商常见嵌套）都吃 */
/**
 * 付费代理常见的两种订阅：base64 包一层的 txt，和 Clash/YAML 的 proxies 列表。
 * 先各自解成「普通文本」再走一遍解析，这样 CLI 订阅和手抄清单共用同一套归一化。
 */
function tryBase64Text(body: string): string | undefined {
  if (!/^[A-Za-z0-9+/=\r\n]+$/.test(body)) return undefined;
  const compact = body.replace(/\s+/g, "");
  if (compact.length < 16 || compact.length % 4 !== 0) return undefined;
  try {
    const decoded = Buffer.from(compact, "base64").toString("utf8");
    if (!decoded || decoded.includes("\uFFFD")) return undefined;
    return /[\w.-]+:\d{2,5}/.test(decoded) ? decoded : undefined;
  } catch {
    return undefined;
  }
}

/** Clash / mihomo 订阅：只要 server + port 这两行，同块的 type/username/password 当配料 */
function parseYamlProxies(
  body: string,
  defaultScheme: "http" | "socks5",
  push: (url: string, label?: string) => void,
  onSkip: () => void,
): number {
  let hits = 0;
  let block: { server?: string; port?: string; type?: string; user?: string; pass?: string } | null = null;
  const flush = () => {
    if (!block) return;
    const { server, port } = block;
    if (server && port && hostOk(server) && portOk(port)) {
      const rawType = (block.type ?? "").toLowerCase();
      const scheme = rawType.includes("socks5")
        ? "socks5"
        : rawType.includes("socks4")
          ? "socks4"
          : rawType.includes("http")
            ? "http"
            : defaultScheme;
      const creds = block.user
        ? `${encodeURIComponent(block.user)}${block.pass ? `:${encodeURIComponent(block.pass)}` : ""}@`
        : "";
      const url = normalizeProxyUrl(`${scheme}://${creds}${server}:${port}`);
      if (url) {
        push(url);
        hits += 1;
      } else onSkip();
    }
    block = null;
  };
  for (const rawLine of body.split(/\r?\n/)) {
    const line = stripComment(rawLine.replace(/\t/g, " ")).trimEnd();
    if (!line.trim()) continue;
    const newItem = /^\s*-\s/.test(line);
    if (newItem) flush();
    const clean = line.replace(/^\s*-\s*/, "").trim();
    const match = clean.match(/^([A-Za-z_]+)\s*:\s*(.+)$/);
    if (!match) continue;
    const key = match[1].toLowerCase();
    const value = match[2].trim().replace(/^["']|["']$/g, "");
    if (!["server", "port", "type", "username", "password", "protocol", "user", "pass"].includes(key)) continue;
    block = block ?? {};
    if (key === "server") block.server = value;
    else if (key === "port") block.port = value;
    else if (key === "type" || key === "protocol") block.type = value;
    else if (key === "username" || key === "user") block.user = value;
    else if (key === "password" || key === "pass") block.pass = value;
  }
  flush();
  return hits;
}

export function parseProxyText(text: string, defaultScheme: "http" | "socks5" = "http"): {
  tokens: ParsedToken[];
  skipped: number;
} {
  return parseProxyTextDepth(text, defaultScheme, 0);
}

function parseProxyTextDepth(
  text: string,
  defaultScheme: "http" | "socks5",
  depth: number,
): {
  tokens: ParsedToken[];
  skipped: number;
} {
  const tokens: ParsedToken[] = [];
  let skipped = 0;
  const seen = new Set<string>();
  const push = (url: string, label?: string) => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    tokens.push({ url, label });
  };
  const pushRaw = (raw: string, label?: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    const normalized = normalizeProxyUrl(trimmed) || normalizeProxyUrl(`${defaultScheme}://${trimmed}`);
    if (normalized) push(normalized, label);
    else skipped += 1;
  };

  const body = text.replace(/^\uFEFF/, "").trim();
  if (!body) return { tokens, skipped };

  if (depth < 2) {
    const inner = tryBase64Text(body);
    if (inner) return parseProxyTextDepth(inner, defaultScheme, depth + 1);
  }

  // YAML 订阅里必然有 server:/port: 成对出现，命中就直接走 YAML 解析，避免把 key 当垃圾计入 skipped
  if (/^\s*[-]?\s*server\s*:/im.test(body) && /^\s*[-]?\s*port\s*:/im.test(body)) {
    const before = tokens.length;
    parseYamlProxies(body, defaultScheme, push, () => (skipped += 1));
    if (tokens.length > before) return { tokens, skipped };
  }

  const asJson = (() => {
    const first = body[0];
    if (first !== "{" && first !== "[") return undefined;
    try {
      return JSON.parse(body) as unknown;
    } catch {
      return undefined;
    }
  })();

  if (asJson !== undefined) {
    const walk = (node: unknown, depth = 0): void => {
      if (depth > 8 || node == null) return;
      if (Array.isArray(node)) {
        for (const item of node) walk(item, depth + 1);
        return;
      }
      if (typeof node === "string") {
        pushRaw(node);
        return;
      }
      if (typeof node !== "object") return;
      const obj = node as Record<string, unknown>;
      const host = obj.host ?? obj.ip ?? obj.server ?? obj.hostname ?? obj.addr ?? obj.address;
      const port = obj.port ?? obj.https_port ?? obj.http_port;
      if (typeof host === "string" && (typeof port === "number" || typeof port === "string")) {
        const schemeRaw = String(obj.protocol ?? obj.scheme ?? obj.type ?? defaultScheme).toLowerCase();
        const scheme = schemeRaw.includes("socks5") ? "socks5" : schemeRaw.includes("socks4") ? "socks4" : "http";
        const user = obj.username ?? obj.user ?? obj.login ?? obj.account;
        const pass = obj.password ?? obj.pass ?? obj.pwd ?? obj.secret;
        const creds =
          typeof user === "string" && user
            ? `${encodeURIComponent(user)}${typeof pass === "string" && pass ? `:${encodeURIComponent(pass)}` : ""}@`
            : "";
        const url = normalizeProxyUrl(`${scheme}://${creds}${host}:${port}`);
        if (url) push(url, typeof obj.region === "string" ? obj.region : undefined);
        else skipped += 1;
        return;
      }
      const label = typeof obj.label === "string" ? obj.label : undefined;
      for (const value of Object.values(obj)) {
        if (typeof value === "string") pushRaw(value, label);
        else walk(value, depth + 1);
      }
    };
    walk(asJson);
    return { tokens, skipped };
  }

  for (const rawLine of body.split(/\r?\n/)) {
    const line = stripComment(rawLine).trim();
    if (!line) continue;
    if (line.includes(",")) {
      const fields = line.split(",").map((f) => f.trim()).filter(Boolean);
      if (fields.length === 2 && hostOk(fields[0]) && portOk(fields[1])) {
        pushRaw(`${fields[0]}:${fields[1]}`);
        continue;
      }
      if (fields.length >= 4 && hostOk(fields[0]) && portOk(fields[1])) {
        pushRaw(`${fields[0]}:${fields[1]}:${fields[2]}:${fields[3]}`);
        continue;
      }
      for (const field of fields) pushRaw(field);
      continue;
    }
    const chunks = line.split(/\s+/).filter(Boolean);
    if (chunks.length === 2 && hostOk(chunks[0]) && portOk(chunks[1])) {
      pushRaw(`${chunks[0]}:${chunks[1]}`);
      continue;
    }
    for (const chunk of chunks) pushRaw(chunk);
  }
  return { tokens, skipped };
}

function uniqueById(pool: ProxyPool): ProxyEntry[] {
  const byUrl = new Map<string, ProxyEntry>();
  for (const entry of pool.entries) {
    const url = entry.url.toLowerCase();
    const existing = byUrl.get(url);
    if (!existing) {
      byUrl.set(url, entry);
      continue;
    }
    // 重复项保留已有的测活结果，补上备注
    byUrl.set(url, { ...existing, label: existing.label ?? entry.label });
  }
  return [...byUrl.values()];
}

function mergeEntries(pool: ProxyPool, tokens: ParsedToken[], source: ProxySource): { pool: ProxyPool; addedIds: string[] } {
  const existing = new Map(pool.entries.map((e) => [e.url.toLowerCase(), e]));
  const added: ProxyEntry[] = [];
  for (const token of tokens) {
    if (existing.size + added.length >= MAX_ENTRIES) break;
    const key = token.url.toLowerCase();
    if (existing.has(key)) continue;
    if (added.some((e) => e.url.toLowerCase() === key)) continue;
    const entry: ProxyEntry = {
      id: makeId(token.url),
      url: token.url,
      label: token.label,
      source,
      enabled: true,
      health: "unknown",
    };
    added.push(entry);
  }
  const entries = uniqueById({ ...pool, entries: [...pool.entries, ...added] });
  return {
    pool: writePool({ entries, activeId: pool.activeId, rotate: pool.rotate }),
    addedIds: added.map((e) => e.id),
  };
}

export function importProxyFile(file: string): ProxyImportResult {
  const stat = fs.statSync(file);
  if (stat.size > MAX_IMPORT_BYTES) throw new Error("配置文件超过 6 MB，先裁一下再导入");
  const text = fs.readFileSync(file, "utf8");
  const { tokens, skipped } = parseProxyText(text);
  if (!tokens.length) throw new Error("这份文件里没有认出代理地址，支持 host:port、host:port:user:pass、scheme://user:pass@host:port、JSON 和 CSV");
  const { pool, addedIds } = mergeEntries(readPool(), tokens, "config");
  return { pool, added: addedIds.length, addedIds, skipped, source: file };
}

export function importProxyText(text: string): ProxyImportResult {
  const { tokens, skipped } = parseProxyText(text);
  if (!tokens.length) throw new Error("没有认出代理地址，支持 host:port、host:port:user:pass、scheme://user:pass@host:port、JSON 和 CSV");
  const { pool, addedIds } = mergeEntries(readPool(), tokens, "manual");
  return { pool, added: addedIds.length, addedIds, skipped, source: "paste" };
}

export function addProxy(raw: string, label?: string): ProxyPool {
  const url = normalizeProxyUrl(raw);
  if (!url) throw new Error("地址要形如 1.2.3.4:8080、http://user:pass@1.2.3.4:8080 或 socks5://1.2.3.4:1080");
  return mergeEntries(readPool(), [{ url, label }], "manual").pool;
}

export function removeProxies(ids: string[]): ProxyPool {
  const drop = new Set(ids);
  const pool = readPool();
  const entries = pool.entries.filter((e) => !drop.has(e.id));
  return writePool({ ...pool, entries, activeId: drop.has(pool.activeId ?? "") ? undefined : pool.activeId });
}

export function setProxyEnabled(id: string, enabled: boolean): ProxyPool {
  const pool = readPool();
  return writePool({ ...pool, entries: pool.entries.map((e) => (e.id === id ? { ...e, enabled } : e)) });
}

export function setPoolActive(id?: string): ProxyPool {
  const pool = readPool();
  const activeId = id && pool.entries.some((e) => e.id === id) ? id : undefined;
  return writePool({ ...pool, activeId });
}

export function setPoolRotate(rotate: boolean): ProxyPool {
  return writePool({ ...readPool(), rotate });
}

export function clearPool(): ProxyPool {
  return writePool({ ...DEFAULT_POOL });
}

/** 代理池当前会给引擎用的那一条（没选就取第一条启用的，优先测活通过的） */
export function poolProxy(pool: ProxyPool = readPool()): string {
  const enabled = pool.entries.filter((e) => e.enabled);
  if (!enabled.length) return "";
  if (pool.activeId) {
    const picked = enabled.find((e) => e.id === pool.activeId);
    if (picked) return picked.url;
  }
  return (enabled.find((e) => e.health === "ok") ?? enabled[0]).url;
}

/** 轮换：重启引擎前换下一条，只动 agent 子进程的出口 */
export function advancePool(): ProxyPool {
  const pool = readPool();
  const enabled = pool.entries.filter((e) => e.enabled);
  if (enabled.length < 2) return pool;
  const idx = enabled.findIndex((e) => e.id === pool.activeId);
  const next = enabled[(idx + 1) % enabled.length];
  return writePool({ ...pool, activeId: next.id });
}

/** 走指定代理的轻量探测；每个并发槽一个独立分区，避免互相改代理 */
function probeViaSlot(slot: number, url: string, proxy: string): Promise<{ ok: boolean; ms: number; status?: number; error?: string }> {
  const started = Date.now();
  const ses = session.fromPartition(`tanwei-pool-${slot}`);
  return ses
    .setProxy({ proxyRules: proxy, proxyBypassRules: "localhost,127.0.0.1,::1" })
    .catch(() => undefined)
    .then(
      () =>
        new Promise((resolve) => {
          let settled = false;
          const finish = (value: { ok: boolean; ms: number; status?: number; error?: string }) => {
            if (settled) return;
            settled = true;
            resolve(value);
          };
          const timer = setTimeout(
            () => finish({ ok: false, ms: Date.now() - started, error: "超时" }),
            HEALTH_TIMEOUT_MS,
          );
          try {
            const req = net.request({ url: HEALTH_URL, method: "GET", session: ses, useSessionCookies: false });
            req.on("response", (res) => {
              clearTimeout(timer);
              const status = res.statusCode;
              finish({ ok: status > 0 && status < 400, ms: Date.now() - started, status });
              res.on("data", () => undefined);
              res.on("end", () => undefined);
              res.on("error", () => undefined);
            });
            req.on("error", (err) => {
              clearTimeout(timer);
              finish({ ok: false, ms: Date.now() - started, error: err.message });
            });
            req.end();
          } catch (err) {
            clearTimeout(timer);
            finish({ ok: false, ms: Date.now() - started, error: (err as Error).message });
          }
        }),
    );
}

export async function testProxies(ids?: string[], onTick?: (done: number, total: number) => void): Promise<ProxyPool> {
  const pool = readPool();
  const wanted = ids?.length ? new Set(ids) : undefined;
  // 没指定就用池里启用的那些，但一轮最多测 400 条：免费源整批入库时几千条测不完
  const targets = pool.entries.filter((e) => (wanted ? wanted.has(e.id) : e.enabled)).slice(-MAX_TEST);
  if (!targets.length) return pool;

  const results = new Map<string, ProxyEntry>();
  let cursor = 0;
  let done = 0;
  const worker = async (slot: number) => {
    for (;;) {
      const idx = cursor;
      cursor += 1;
      const entry = targets[idx];
      if (!entry) return;
      const res = await probeViaSlot(slot, HEALTH_URL, entry.url);
      results.set(entry.id, {
        ...entry,
        health: res.ok ? "ok" : "bad",
        latencyMs: res.ok ? res.ms : undefined,
        checkedAt: Date.now(),
        error: res.ok ? undefined : res.error ?? `HTTP ${res.status ?? "?"}`,
      });
      done += 1;
      onTick?.(done, targets.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(HEALTH_SLOTS, targets.length) }, (_, i) => worker(i)));

  const fresh = readPool();
  return writePool({
    ...fresh,
    entries: fresh.entries.map((e) => results.get(e.id) ?? e),
  });
}

function fetchText(url: string, proxy: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const ses = session.fromPartition("tanwei-freefetch");
    ses
      .setProxy(proxy ? { proxyRules: proxy, proxyBypassRules: "localhost,127.0.0.1,::1" } : { mode: "direct" })
      .catch(() => undefined)
      .then(() => {
        const req = net.request({ url, method: "GET", session: ses, useSessionCookies: false });
        const chunks: Buffer[] = [];
        let size = 0;
        let settled = false;
        const done = (fn: () => void) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          fn();
        };
        const timer = setTimeout(() => done(() => reject(new Error("超时"))), 12_000);
        req.on("response", (res) => {
          if (res.statusCode >= 400) {
            done(() => reject(new Error(`HTTP ${res.statusCode}`)));
            return;
          }
          res.on("data", (chunk) => {
            size += chunk.length;
            if (size <= 2 * 1024 * 1024) chunks.push(chunk);
          });
          res.on("end", () => done(() => resolve(Buffer.concat(chunks).toString("utf8"))));
          res.on("error", (err) => done(() => reject(err)));
        });
        req.on("error", (err) => done(() => reject(err)));
        req.end();
      });
  });
}

/**
 * 抓免费源。直连优先，失败再依次试系统代理和当前已配置的代理；
 * 抓回来只做入库，测活由「一键测活」单独跑，避免拖住 UI。
 */
export async function fetchFreeProxies(limit = 40): Promise<ProxyFreeResult> {
  const { resolveSystemProxy } = await import("./proxy");
  const { readSettings } = await import("./appSettings");
  const { normalizeProxy } = await import("./proxy");
  const systemProxy = await resolveSystemProxy();
  const settings = readSettings();
  const configured = settings.network.proxyMode === "manual" ? normalizeProxy(settings.network.proxyUrl) : "";
  const routes: string[] = [];
  for (const candidate of ["", systemProxy, configured, poolProxy()]) {
    if (!routes.includes(candidate)) routes.push(candidate);
  }

  const errors: string[] = [];
  const texts: { text: string; scheme: "http" | "socks5" }[] = [];
  for (const route of routes) {
    for (const source of FREE_SOURCES) {
      try {
        const text = await fetchText(source.url, route);
        if (text.trim()) texts.push({ text, scheme: source.scheme });
        break;
      } catch (err) {
        errors.push(`${new URL(source.url).host}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (texts.length) break;
  }

  if (!texts.length) {
    throw new Error(`免费源都抓不到（可先配好系统代理或手动代理再抓）：${errors.slice(0, 3).join("；")}`);
  }

  const tokens: ParsedToken[] = [];
  for (const item of texts) {
    const parsed = parseProxyText(item.text, item.scheme);
    for (const token of parsed.tokens) {
      if (tokens.length >= limit) break;
      tokens.push(token);
    }
    if (tokens.length >= limit) break;
  }
  const { pool, addedIds } = mergeEntries(readPool(), tokens, "free");
  return { pool, added: addedIds.length, addedIds, fetched: tokens.length, errors: errors.slice(0, 4) };
}
