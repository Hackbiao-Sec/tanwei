import { app, net, session } from "electron";
import fs from "node:fs";
import path from "node:path";
import { probeCredentialedProxy } from "./proxyProbe";
import type {
  ProxyEntry,
  ProxyFreeResult,
  ProxyImportResult,
  ProxyImportStats,
  ProxyLocalPort,
  ProxyPool,
  ProxySource,
} from "../shared/types";

/**
 * 代理池：只对本机 grok agent 子进程生效（HTTP(S)_PROXY / ALL_PROXY），
 * 不改 Windows 系统代理，也不碰浏览器配置。池本身落盘在 userData/proxy-pool.json。
 */

const MAX_ENTRIES = 3000;
const MAX_IMPORT_BYTES = 6 * 1024 * 1024;
/** 测活走 204，任何 2xx/3xx 都算这条代理能用；付费节点偶发 502 时换第二个地址再判一次 */
const HEALTH_URLS = ["http://www.gstatic.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace"];
/** 代理本身通了、只是上游那一段挂了，才值得换地址重试 */
const UPSTREAM_FAIL = /ERR_TUNNEL_CONNECTION_FAILED|ERR_EMPTY_RESPONSE|ERR_INCOMPLETE_CHUNKED_ENCODING|ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET/;
/**
 * Chromium 不给用带账号密码的代理：规则里塞 userinfo 会被判成无效规则，
 * Electron 的 app「login」事件在 net.request 上也不触发。这类条目交给 socket 探针。
 */
const WITH_CREDENTIALS = /^[a-z0-9]+:\/\/[^/@]+@/i;

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

export interface ParsedToken {
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

/** Clash/mihomo 节点协议里，Electron 的 net 自己就能拨的几种 */
const DIAL_TYPES: Record<string, string> = {
  http: "http",
  https: "https",
  socks: "socks5",
  socks5: "socks5",
  socks4: "socks4",
};

interface NodeDraft {
  type?: string;
  name?: string;
  server?: string;
  port?: string;
  user?: string;
  pass?: string;
}

interface ClashScan {
  tokens: ParsedToken[];
  usable: Record<string, number>;
  nodes: Record<string, number>;
  localPorts: ProxyLocalPort[];
  notes: string[];
  /** 命中过 proxies 块或本机端口，说明这确实是一份客户端配置 */
  structured: boolean;
}

/** 去掉行尾注释；引号里的 # 不当注释（ss 的 password 里可能就有） */
function stripYamlComment(line: string): string {
  let out = "";
  let quote = "";
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      out += ch;
      if (ch === quote && line[i - 1] !== "\\") quote = "";
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]))) return out;
    out += ch;
  }
  return out;
}

/** 按顶层逗号切 flow 内容；{} [] 里的逗号、引号里的逗号都不切 */
function splitFlow(body: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let quote = "";
  let depth = 0;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (quote) {
      cur += ch;
      if (ch === quote && body[i - 1] !== "\\") quote = "";
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "{" || ch === "[") {
      depth += 1;
      cur += ch;
      continue;
    }
    if (ch === "}" || ch === "]") {
      depth -= 1;
      cur += ch;
      continue;
    }
    if (ch === "," && depth <= 0) {
      parts.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

/** 括号开合度：内联 map / 数组跨行写的时候靠它判断有没有写完 */
function flowBalance(text: string): number {
  let depth = 0;
  let quote = "";
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === quote && text[i - 1] !== "\\") quote = "";
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "{" || ch === "[") depth += 1;
    else if (ch === "}" || ch === "]") depth -= 1;
  }
  return depth;
}

function unquoteYaml(raw: string): string {
  const value = raw.trim();
  const paired =
    value.length >= 2 &&
    ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")));
  return paired ? value.slice(1, -1).replace(/\\(["'\\])/g, "$1") : value;
}

function applyNodeField(draft: NodeDraft, rawKey: string, value: string): void {
  const key = rawKey.toLowerCase();
  if (key === "name") draft.name = value;
  else if (key === "type" || key === "protocol") draft.type = value;
  else if (key === "server" || key === "host" || key === "address") draft.server = value;
  else if (key === "port") draft.port = value;
  else if (key === "username" || key === "user") draft.user = draft.user ?? value;
  else if (key === "password" || key === "pass" || key === "pwd") draft.pass = draft.pass ?? value;
}

/**
 * Clash / mihomo 订阅：两种写法都认——单行内联 map（`- { name: …, type: ss, … }`）和块式。
 * 能拨的 http/socks 转成池里的地址；ss/vmess/trojan 这些 Electron 拨不了，
 * 记进清单，交给本机 Clash 已经在跑的 mixed-port 当出口。
 */
function scanClashConfig(body: string): ClashScan {
  const scan: ClashScan = { tokens: [], usable: {}, nodes: {}, localPorts: [], notes: [], structured: false };
  const seen = new Set<string>();
  let draft: NodeDraft | null = null;
  let inProxies = false;
  let flow = "";
  let flowArray = false;

  const finish = () => {
    if (!draft) return;
    const node = draft;
    draft = null;
    const server = (node.server ?? "").trim();
    const port = (node.port ?? "").trim();
    if (!hostOk(server) || !portOk(port)) return;
    const type = (node.type ?? "").toLowerCase();
    const scheme = DIAL_TYPES[type] ?? "";
    if (!scheme) {
      const key = type || "unknown";
      scan.nodes[key] = (scan.nodes[key] ?? 0) + 1;
      return;
    }
    const creds = node.user
      ? `${encodeURIComponent(node.user)}${node.pass ? `:${encodeURIComponent(node.pass)}` : ""}@`
      : "";
    const url = normalizeProxyUrl(`${scheme}://${creds}${server}:${port}`);
    if (!url || seen.has(url)) return;
    seen.add(url);
    scan.tokens.push({ url, label: node.name || undefined });
    scan.usable[scheme] = (scan.usable[scheme] ?? 0) + 1;
  };

  const absorb = (text: string) => {
    const inner = text.trim().replace(/^\{/, "").replace(/\}$/, "");
    draft = draft ?? {};
    for (const pair of splitFlow(inner)) {
      const match = pair.match(/^\s*([A-Za-z0-9_-]+)\s*:\s*([\s\S]+?)\s*$/);
      if (!match) continue;
      applyNodeField(draft, match[1], unquoteYaml(match[2]));
    }
  };

  const absorbArray = (text: string) => {
    const inner = text.trim().replace(/^\[/, "").replace(/\]$/, "");
    for (const chunk of splitFlow(inner)) {
      if (!chunk.trim()) continue;
      draft = {};
      absorb(chunk);
      finish();
    }
  };

  for (const rawLine of body.split(/\r?\n/)) {
    const line = stripYamlComment(rawLine.replace(/\t/g, "  "));
    if (!line.trim()) continue;
    const indent = line.match(/^ */)?.[0].length ?? 0;

    if (flow) {
      const merged = `${flow} ${line.trim()}`;
      if (flowBalance(merged) > 0) {
        flow = merged;
        continue;
      }
      flow = "";
      if (flowArray) {
        absorbArray(merged);
      } else {
        draft = {};
        absorb(merged);
        finish();
      }
      continue;
    }

    const top = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (indent === 0 && top) {
      const key = top[1].toLowerCase();
      const value = top[2].trim();
      finish();
      inProxies = key === "proxies" && !value;
      if (inProxies || key === "proxy-providers") scan.structured = true;
      if (key === "proxies" && value.startsWith("[")) {
        if (flowBalance(value) > 0) {
          flow = value;
          flowArray = true;
        } else {
          absorbArray(value);
        }
      }
      if (["mixed-port", "port", "socks-port", "http-port"].includes(key)) {
        const port = Number(unquoteYaml(value));
        if (Number.isInteger(port) && port > 0 && port <= 65535) {
          scan.localPorts.push({ port, scheme: key === "socks-port" ? "socks5" : "http", key });
          scan.structured = true;
        }
      }
      continue;
    }

    if (!inProxies) continue;

    const trimmed = line.trim();
    if (trimmed.startsWith("-")) {
      finish();
      const rest = trimmed.replace(/^-\s*/, "");
      if (!rest) {
        draft = {};
        continue;
      }
      if (rest.startsWith("{")) {
        if (flowBalance(rest) > 0) {
          flow = rest;
          flowArray = false;
        } else {
          draft = {};
          absorb(rest);
          finish();
        }
        continue;
      }
      draft = {};
      const pair = rest.match(/^([A-Za-z0-9_-]+)\s*:\s*([\s\S]+)$/);
      if (pair) applyNodeField(draft, pair[1], unquoteYaml(pair[2]));
      continue;
    }

    if (!draft) continue;
    const pair = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*([\s\S]*)$/);
    if (pair) applyNodeField(draft, pair[1], unquoteYaml(pair[2]));
  }
  finish();

  const nodeTotal = Object.values(scan.nodes).reduce((sum, n) => sum + n, 0);
  if (nodeTotal > 0) {
    const kinds = Object.keys(scan.nodes).join("/");
    const port = scan.localPorts[0];
    scan.notes.push(
      port
        ? `${nodeTotal} 个 ${kinds} 节点 Electron 拨不了，已登记本机 ${port.key}=${port.port} 作为出口`
        : `${nodeTotal} 个 ${kinds} 节点 Electron 拨不了，让本机 Clash/mihomo 跑起来后导入配置才能读到 mixed-port`,
    );
  }
  if (scan.tokens.length) scan.notes.push(`${scan.tokens.length} 个 HTTP/SOCKS 代理可以直接拨`);
  return scan;
}

export function emptyStats(kind = "unknown"): ProxyImportStats {
  return { kind, usable: {}, nodes: {}, localPorts: [], notes: [] };
}

export function parseProxyText(
  text: string,
  defaultScheme: "http" | "socks5" = "http",
): { tokens: ParsedToken[]; skipped: number; stats: ProxyImportStats } {
  return parseProxyTextDepth(text, defaultScheme, 0);
}

function parseProxyTextDepth(
  text: string,
  defaultScheme: "http" | "socks5",
  depth: number,
): {
  tokens: ParsedToken[];
  skipped: number;
  stats: ProxyImportStats;
} {
  const tokens: ParsedToken[] = [];
  const stats = emptyStats();
  let skipped = 0;
  const seen = new Set<string>();
  const push = (url: string, label?: string) => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    tokens.push({ url, label });
    const scheme = url.slice(0, url.indexOf("://")).toLowerCase();
    stats.usable[scheme] = (stats.usable[scheme] ?? 0) + 1;
  };
  const pushRaw = (raw: string, label?: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    const normalized = normalizeProxyUrl(trimmed) || normalizeProxyUrl(`${defaultScheme}://${trimmed}`);
    if (normalized) push(normalized, label);
    else skipped += 1;
  };

  const body = text.replace(/^\uFEFF/, "").trim();
  if (!body) return { tokens, skipped, stats };

  if (depth < 2) {
    const inner = tryBase64Text(body);
    if (inner) {
      const nested = parseProxyTextDepth(inner, defaultScheme, depth + 1);
      if (nested.tokens.length || nested.stats.nodes && Object.keys(nested.stats.nodes).length) {
        return { ...nested, stats: { ...nested.stats, kind: "base64" } };
      }
    }
  }

  // Clash/mihomo 配置：有 proxies 块，或者有成对的 server:/port:，或者读到了本机端口
  const looksClash =
    /^\s*(proxies|proxy-providers)\s*:/im.test(body) ||
    /^\s*(mixed-port|socks-port)\s*:\s*\d/im.test(body) ||
    (/^\s*-?\s*server\s*:/im.test(body) && /^\s*-?\s*port\s*:/im.test(body));
  if (looksClash) {
    const scan = scanClashConfig(body);
    if (scan.structured) {
      for (const token of scan.tokens) {
        if (seen.has(token.url)) continue;
        seen.add(token.url);
        tokens.push(token);
      }
      // scan 已经按协议计过数，覆盖 push 里按 url 前缀记的那份
      stats.kind = "clash";
      stats.usable = { ...scan.usable };
      stats.nodes = { ...scan.nodes };
      stats.localPorts = [...scan.localPorts];
      stats.notes = [...scan.notes];
      return { tokens, skipped, stats };
    }
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
    stats.kind = "json";
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
    return { tokens, skipped, stats };
  }

  stats.kind = "list";
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
  return { tokens, skipped, stats };
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

/** 配置里声明的本机端口本身就是可拨的出口，Clash 的 ss/vmess 节点全靠它 */
function localPortTokens(stats: ProxyImportStats): ParsedToken[] {
  const out: ParsedToken[] = [];
  for (const item of stats.localPorts) {
    const url = normalizeProxyUrl(`${item.scheme}://127.0.0.1:${item.port}`);
    if (url) out.push({ url, label: `本机 ${item.key} ${item.port}` });
  }
  return out;
}

function commitImport(
  tokens: ParsedToken[],
  source: ProxySource,
  sourceLabel: string,
  skipped: number,
  stats: ProxyImportStats,
): ProxyImportResult {
  const all = [...tokens, ...localPortTokens(stats)];
  const { pool, addedIds } = mergeEntries(readPool(), all, source);
  return { pool, added: addedIds.length, addedIds, skipped, source: sourceLabel, stats };
}

function emptyParseMessage(stats: ProxyImportStats): string {
  const nodeTotal = Object.values(stats.nodes).reduce((sum, n) => sum + n, 0);
  if (nodeTotal > 0) {
    return `这份配置里 ${nodeTotal} 个 ${Object.keys(stats.nodes).join("/")} 节点 Electron 不能直接拨；让本机 Clash/mihomo 跑起来，配置里带 mixed-port 时我会自动登记本机那个端口`;
  }
  return "没有认出代理地址：认 host:port、host:port:user:pass、scheme://user:pass@host:port、Clash YAML、JSON、CSV；别的格式交给「AI 解析」";
}

export function importProxyFile(file: string): ProxyImportResult {
  const stat = fs.statSync(file);
  if (stat.size > MAX_IMPORT_BYTES) throw new Error("配置文件超过 6 MB，先裁一下再导入");
  const text = fs.readFileSync(file, "utf8");
  const { tokens, skipped, stats } = parseProxyText(text);
  if (!tokens.length && !stats.localPorts.length) throw new Error(emptyParseMessage(stats));
  return commitImport(tokens, "config", file, skipped, stats);
}

export function importProxyText(text: string): ProxyImportResult {
  const { tokens, skipped, stats } = parseProxyText(text);
  if (!tokens.length && !stats.localPorts.length) throw new Error(emptyParseMessage(stats));
  return commitImport(tokens, "manual", "paste", skipped, stats);
}

/** AI 从陌生格式里抽出来的地址，入库逻辑和本地解析共用一条路 */
export function importProxyTokens(
  tokens: ParsedToken[],
  origin: string,
  stats: ProxyImportStats = emptyStats("ai"),
): ProxyImportResult {
  const usable = emptyStats(stats.kind || "ai");
  const merged: ProxyImportStats = {
    ...usable,
    ...stats,
    notes: stats.notes ?? [],
    localPorts: stats.localPorts ?? [],
  };
  const clean = tokens.filter((t) => normalizeProxyUrl(t.url));
  if (!clean.length && !merged.localPorts.length) throw new Error("AI 没抽到可用的代理地址");
  return commitImport(clean, "config", origin, 0, merged);
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
function probeOnce(
  ses: Electron.Session,
  url: string,
  started: number,
): Promise<{ ok: boolean; ms: number; status?: number; error?: string }> {
  return new Promise((resolve) => {
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
      const req = net.request({ url, method: "GET", session: ses, useSessionCookies: false });
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
  });
}

function probeViaSlot(slot: number, proxy: string): Promise<{ ok: boolean; ms: number; status?: number; error?: string }> {
  const started = Date.now();
  const ses = session.fromPartition(`tanwei-pool-${slot}`);
  return ses
    .setProxy({ proxyRules: proxy, proxyBypassRules: "localhost,127.0.0.1,::1" })
    .catch(() => undefined)
    .then(async () => {
      let last: { ok: boolean; ms: number; status?: number; error?: string } = {
        ok: false,
        ms: 0,
        error: "无响应",
      };
      for (const url of HEALTH_URLS) {
        last = await probeOnce(ses, url, started);
        if (last.ok) return last;
        // 代理自己通了、是上游那一段挂了才会换地址再判一次；超时不重试，免得一轮测活拖太久
        const upstream = (last.status ?? 0) >= 400 || UPSTREAM_FAIL.test(last.error ?? "");
        if (!upstream) return last;
      }
      return last;
    });
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
      // Chromium 吃不下带账号密码的代理，这类条目换 socket 探针，SOCKS 认证也一并支持
      const res = WITH_CREDENTIALS.test(entry.url)
        ? await probeCredentialedProxy(entry.url)
        : await probeViaSlot(slot, entry.url);
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
