import type { PlanEntry, SessionState, TimelineItem } from "@shared/types";

/**
 * 渗透方向视图：把会话时间线归成「方向 → 测试 → 证据」。
 * 方向 = 这一步在验什么（未授权 / 越权 / 认证接管 / 注入 …），测试 = 一次规范化描述的动作。
 * 纯前端推导，只读 SessionState，不改引擎、不发请求。
 */

export type DirectionId =
  | "recon"
  | "unauth"
  | "idor"
  | "auth"
  | "injection"
  | "ssrf"
  | "xss"
  | "upload"
  | "rce"
  | "logic"
  | "report"
  | "other";

export interface DirectionDef {
  id: DirectionId;
  /** 规范名，树上一行 */
  label: string;
  /** 这个方向在验什么，展开时当说明 */
  goal: string;
  cls: string;
}

export const DIRECTION_DEFS: DirectionDef[] = [
  { id: "recon", label: "信息收集", goal: "资产、指纹、前端 JS、目录与接口清单：先把入口摸清", cls: "pdt-fam-recon" },
  { id: "unauth", label: "未授权访问", goal: "不带会话直调业务接口，看回不回业务数据", cls: "pdt-fam-unauth" },
  { id: "idor", label: "越权换 ID", goal: "带自己的会话换对象、用户、租户 ID，看能不能碰到别人的", cls: "pdt-fam-idor" },
  { id: "auth", label: "认证与接管", goal: "登录、发码、重置、改绑、换票：能不能进号或改掉别人的密/绑", cls: "pdt-fam-auth" },
  { id: "injection", label: "注入", goal: "查询、过滤、排序参数投 SQL / NoSQL / 模板 / 命令探针，看条数与回显差分", cls: "pdt-fam-injection" },
  { id: "ssrf", label: "SSRF", goal: "URL、回调、导入类参数让它回连内网或云元数据", cls: "pdt-fam-ssrf" },
  { id: "xss", label: "XSS", goal: "回显与存储点投标签，看是否原样落地", cls: "pdt-fam-xss" },
  { id: "upload", label: "上传与穿越", goal: "上传类型与路径绕过、下载与文件 key 穿越", cls: "pdt-fam-upload" },
  { id: "rce", label: "命令执行", goal: "命令、表达式、反序列化、危险上传跟到能不能执行", cls: "pdt-fam-rce" },
  { id: "logic", label: "业务逻辑", goal: "金额、状态、库存、券、审核：改值、跳步、并发", cls: "pdt-fam-logic" },
  { id: "report", label: "报告与整理", goal: "落盘报告、整理资产、写清单", cls: "pdt-fam-report" },
  { id: "other", label: "其它动作", goal: "还没归到上面方向的动作", cls: "pdt-fam-other" },
];

export const DIRECTION_MAP: Record<DirectionId, DirectionDef> = DIRECTION_DEFS.reduce(
  (acc, def) => ({ ...acc, [def.id]: def }),
  {} as Record<DirectionId, DirectionDef>,
);

export type TestVerdict =
  | "hit"
  | "blocked"
  | "clean"
  | "missed"
  | "unclear"
  | "failed"
  | "running";

export const VERDICT_LABEL: Record<TestVerdict, string> = {
  hit: "打穿",
  blocked: "被拦",
  clean: "无异常",
  missed: "未命中",
  unclear: "待判",
  failed: "失败",
  running: "进行中",
};

export type DirectionStatus = "running" | "hit" | "unclear" | "excluded" | "planned";

export const STATUS_LABEL: Record<DirectionStatus, string> = {
  running: "进行中",
  hit: "有命中",
  unclear: "待确认",
  excluded: "已排除",
  planned: "计划中",
};

export interface AttackTest {
  id: string;
  direction: DirectionId;
  at: number;
  round: number;
  host?: string;
  hosts: string[];
  /** 工具原名，展开证据时看 */
  title: string;
  /** 规范化一句话：这个方向下做了哪次测试 */
  description: string;
  method?: string;
  path?: string;
  params: string[];
  probe?: string;
  verdict: TestVerdict;
  /** 这一步到底拿到了什么：一行可直接看的结果 */
  result: string;
  /** 解析出来的 HTTP 状态码 */
  code?: number;
  kind?: string;
  status: string;
  /** 这一步是不是真发了请求：决定它算不算摸到一个接口 */
  isRequest: boolean;
  input?: string;
  output?: string;
  ms?: number;
}

/** 摸到的接口：真调用过的，和从前端文件 / 回包里认出来的 */
export interface EndpointInfo {
  key: string;
  path: string;
  host?: string;
  method?: string;
  count: number;
  firstAt: number;
  lastAt: number;
  verdict: TestVerdict;
  /** 最后一次调用的结果，一行 */
  result?: string;
  /** called = 真打过；seen = 从前端文件或回包里认出来，还没打 */
  status: "called" | "seen";
  source: string;
  directions: DirectionId[];
  testIds: string[];
  sample?: string;
}

export type GainKind = "hit" | "finding" | "report";

export const GAIN_LABEL: Record<GainKind, string> = {
  hit: "有回显",
  finding: "结论",
  report: "报告",
};

/** 黑板上的成果：真出数的动作、模型写下的结论、落盘的报告 */
export interface Gain {
  id: string;
  kind: GainKind;
  direction: DirectionId;
  at: number;
  title: string;
  detail?: string;
  host?: string;
  testId?: string;
}

export interface Blackboard {
  live: boolean;
  startedAt?: number;
  lastAt?: number;
  doing?: {
    direction: DirectionId;
    label: string;
    cls: string;
    text: string;
    at?: number;
    verdict?: TestVerdict;
  };
  next?: string;
  stats: {
    gains: number;
    endpoints: number;
    discovered: number;
    hosts: number;
    tests: number;
    rounds: number;
  };
}

/** 每个方向在树上固定按这四段铺开，名字与顺序都固定 */
export type BoardGroupId = "doing" | "gains" | "assets" | "tried";

export const BOARD_GROUPS: Array<{ id: BoardGroupId; label: string; hint: string }> = [
  { id: "doing", label: "正在做", hint: "这一步在验什么" },
  { id: "gains", label: "成果", hint: "有回显、结论、报告" },
  { id: "assets", label: "发现", hint: "接口、主机、线索" },
  { id: "tried", label: "试过", hint: "其余动作与判定" },
];

export interface AttackDirection {
  id: DirectionId;
  def: DirectionDef;
  tests: AttackTest[];
  hosts: string[];
  firstAt: number;
  lastAt: number;
  rounds: number[];
  verdicts: Record<TestVerdict, number>;
  status: DirectionStatus;
  summary: string;
  trimmed: number;
  /** 这个方向此刻在做的一步：有进行中的就是它，否则取最后一步 */
  doing?: AttackTest;
  gains: Gain[];
  endpoints: EndpointInfo[];
}

export interface Conclusion {
  id: string;
  at: number;
  title: string;
  text: string;
  streaming: boolean;
  /** 说这段话时正在跑的方向，用来把它挂到树上 */
  direction?: DirectionId;
}

export interface NextAction {
  id: string;
  text: string;
  source: "plan" | "assistant" | "gap";
  direction?: DirectionId;
}

export interface AttackGraphData {
  directions: AttackDirection[];
  tests: AttackTest[];
  hosts: { host: string; count: number; lastAt: number }[];
  conclusions: Conclusion[];
  next: NextAction[];
  active?: { direction: AttackDirection; test?: AttackTest };
  /** 全会话合并后的接口清单，按路径去重 */
  endpoints: EndpointInfo[];
  gains: Gain[];
  blackboard: Blackboard;
  counts: {
    directions: number;
    tests: number;
    hit: number;
    running: number;
    planned: number;
    gains: number;
    endpoints: number;
  };
  busy: boolean;
  trimmed: number;
  startedAt?: number;
  lastAt?: number;
}

/* ------------------------------- 文本工具 ------------------------------- */

function clipText(text: string, max: number): string {
  const clean = text.replace(/\r/g, "").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function headline(text: string, max = 90): string {
  const line =
    text
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.length > 0) ?? "";
  return clipText(line, max);
}

const INPUT_KEYS = [
  "command", "cmd", "script", "url", "target", "endpoint", "query", "pattern", "path",
  "file_path", "target_file", "description", "prompt", "content", "text", "body", "data",
];

/** 工具参数压成一段可读文本，证据区看细节用 */
export function summarizeInput(input: unknown): string {
  if (input == null) return "";
  if (typeof input === "string") return clipText(input, 900);
  if (typeof input === "number" || typeof input === "boolean") return String(input);
  if (Array.isArray(input)) {
    return clipText(input.map((v) => summarizeInput(v)).filter(Boolean).join("\n"), 900);
  }
  if (typeof input === "object") {
    const obj = input as Record<string, unknown>;
    const picked: string[] = [];
    for (const key of INPUT_KEYS) {
      const value = obj[key];
      if (typeof value === "string" && value.trim()) picked.push(value.trim());
    }
    if (picked.length) return clipText(picked.join("\n"), 900);
    try {
      return clipText(JSON.stringify(input, null, 0), 900);
    } catch {
      return "";
    }
  }
  return "";
}

/* ------------------------------- 主机抽取 ------------------------------- */

const FILE_EXT = new Set([
  "js", "mjs", "cjs", "ts", "tsx", "jsx", "css", "scss", "less", "html", "htm", "xhtml",
  "json", "json5", "xml", "yaml", "yml", "toml", "ini", "conf", "cfg", "properties", "env",
  "php", "phtml", "asp", "aspx", "jsp", "jspx", "do", "action", "cgi", "pl", "py", "rb",
  "go", "rs", "java", "kt", "c", "h", "cpp", "hpp", "cs", "swift", "m", "sh", "bash",
  "zsh", "bat", "cmd", "ps1", "vbs", "lua", "sql", "db", "sqlite", "lock", "log", "map",
  "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico", "tif", "tiff", "avif",
  "mp3", "mp4", "m4a", "wav", "ogg", "webm", "mov", "avi", "flv", "mkv",
  "woff", "woff2", "ttf", "otf", "eot", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "jar", "war", "ear", "exe", "msi", "dll",
  "apk", "ipa", "dmg", "iso", "bin", "dat", "tmp", "bak", "swp", "orig", "rej", "patch",
  "md", "markdown", "txt", "rst", "csv", "tsv", "pem", "key", "crt", "cer", "csr", "p12",
  "pfx", "jks", "keystore", "sig", "asc", "gpg", "sha256", "sigstore",
]);

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

// 裸词只认这批后缀，避免把 obj.prop 当域名
const BARE_TLDS = new Set([
  "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "xyz", "top", "vip",
  "club", "icu", "cyou", "bond", "ltd", "group", "shop", "store", "site", "online", "cloud",
  "tech", "wiki", "blog", "ink", "wang", "ren", "run", "plus", "today", "center", "city",
  "company", "global", "guru", "host", "link", "ninja", "works", "team", "tools", "watch",
  "win", "chat", "download", "review", "science", "social", "support", "website", "academy",
  "institute", "care", "health", "legal", "lawyer", "engineer", "estate", "house", "homes",
  "farm", "garden", "cafe", "bar", "pub", "food", "hotel", "taxi", "cars", "auto", "bike",
  "yachts", "soccer", "racing", "ski", "fit", "camera", "photos", "photography", "design",
  "agency", "media", "press", "life", "world", "zone", "space", "fun", "games", "play",
  "video", "music", "art", "page", "monster", "lol", "wtf", "cyber", "show", "stream",
  "movie", "film", "fashion", "style", "beauty", "careers", "job", "expert", "security",
  "secure", "protect", "software", "solutions", "services", "studio", "digital", "network",
  "systems", "computer", "capital", "finance", "fund", "bank", "market", "trading", "email",
  "cn", "io", "co", "tw", "hk", "jp", "kr", "uk", "de", "ru", "br", "in", "au", "ca", "ch",
  "nl", "eu",
]);

function looksLikeHost(raw: string, fromUrl = false): boolean {
  const host = raw.toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 120) return false;
  if (IPV4_RE.test(host)) {
    return host.split(".").every((part) => Number(part) <= 255);
  }
  if (!host.includes(".")) return false;
  const parts = host.split(".");
  if (parts.some((p) => !p || p.length > 63)) return false;
  const tld = parts[parts.length - 1];
  if (tld.length < 2 || tld.length > 24) return false;
  if (FILE_EXT.has(tld)) return false;
  if (/^\d+(?:\.\d+)+$/.test(host)) return false;
  if (fromUrl) return true;
  return BARE_TLDS.has(tld);
}

function cleanHost(raw: string): string {
  let host = raw.trim().toLowerCase().replace(/\.$/, "");
  if (host.startsWith("www.")) host = host.slice(4);
  return host;
}

const URL_HOST_RE = /\b(?:https?|wss?|ftp):\/\/([a-z0-9._-]+|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?/gi;
const BARE_HOST_RE =
  /(?<![\w./@\\-])((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9_-]{0,61})?\.)+[a-z]{2,24})(?::\d{1,5})?(?![\w-])/gi;

/** 从命令、参数、回包里抠出主机/IPv4；同一段文本最多返回 max 个 */
export function extractHosts(text: string, max = 8): string[] {
  if (!text) return [];
  const out: string[] = [];
  const push = (candidate: string, fromUrl: boolean) => {
    if (out.length >= max) return;
    const host = cleanHost(candidate);
    if (out.includes(host) || !looksLikeHost(host, fromUrl)) return;
    out.push(host);
  };
  for (const m of text.matchAll(URL_HOST_RE)) push(m[1], true);
  if (out.length < max) {
    for (const m of text.matchAll(BARE_HOST_RE)) {
      push(m[1], false);
      if (out.length >= max) break;
    }
  }
  return out;
}

/* ------------------------------- 请求解析 ------------------------------- */

export interface RequestInfo {
  method?: string;
  url?: string;
  path?: string;
  host?: string;
  params: string[];
  probe?: string;
  hasSession: boolean;
  isRequest: boolean;
}

const HEADER_WORDS = new Set([
  "host", "content-type", "content-length", "accept", "accept-language", "accept-encoding",
  "user-agent", "connection", "cache-control", "origin", "referer", "cookie", "authorization",
  "pragma", "x-requested-with", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "te",
  "upgrade-insecure-requests", "method", "url", "body", "headers", "data", "curl", "status",
  "message", "msg", "code", "errcode", "errmsg", "success", "timestamp", "type", "name",
]);

const METHOD_RE = [
  /(?:-X|--request)\s+['"]?([A-Za-z]{3,7})/,
  /"method"\s*:\s*"([A-Za-z]{3,7})"/,
  /\bmethod\s*[:=]\s*['"]?([A-Za-z]{3,7})/,
  /^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S/m,
];

const REQUEST_TOOL_RE =
  /\b(curl|wget|iwr|invoke-webrequest|httpie|http_request|http-get|http_post|web_fetch|webfetch|fetch_url|browser_navigate|postman|httpx|nuclei)\b|^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/|Host:\s*\S+/i;

const FILE_KINDS = new Set(["write", "edit", "create", "delete", "move"]);
const READ_KINDS = new Set(["read", "list", "search", "fetch"]);

const SESSION_RE =
  /(?:-H|--header)\s+['"]?(?:cookie|authorization)|\b(?:cookie|authorization|x-token|accesstoken|access_token)\s*:|\bbearer\s+[a-z0-9._-]{8,}|\bsession(?:id)?=\S+/i;

const SQL_PROBE =
  /(?:'|%27|")\s*(?:or|and)\b|\bor\s+1\s*=\s*1|union\s+(?:all\s+)?select|sleep\(\s*\d|benchmark\(|extractvalue|updatexml|information_schema|waitfor\s+delay|%0a\s*or\b/i;
const NOSQL_PROBE = /\$(?:ne|gt|gte|lt|regex|where|expr|exists|nin)\b/i;
const SSTI_PROBE = /\{\{[^}]{1,40}\}\}|\$\{[^}]{1,40}\}|<%=|#\{[^}]{1,40}\}/;
const CMD_PROBE = /(?:;|\||`|\$\()\s*(?:id|whoami|ls|cat|uname|ping|curl|wget)\b|%0a(?:id|whoami)|^\s*(?:id|whoami)\s*$/im;
const XSS_PROBE = /<script|onerror\s*=|onload\s*=|alert\(|prompt\(|confirm\(|javascript:/i;
const TRAV_PROBE = /\.\.\/|%2e%2e|\.\.\\|%252e/i;
const SSRF_PROBE =
  /(?:127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\]|0\.0\.0\.0|file:\/\/|gopher:\/\/|dict:\/\/|metadata\.google|100\.100\.100\.200)/i;

function probeName(text: string): string | undefined {
  if (CMD_PROBE.test(text)) return "命令拼接串";
  if (SSRF_PROBE.test(text)) return "内网回连地址";
  if (XSS_PROBE.test(text)) return "脚本标签";
  if (SSTI_PROBE.test(text)) return "模板表达式";
  if (NOSQL_PROBE.test(text)) return "NoSQL 操作符";
  if (SQL_PROBE.test(text)) return "SQL 探针";
  if (TRAV_PROBE.test(text)) return "路径穿越串";
  if (/%0a|%0d/i.test(text)) return "换行绕过串";
  return undefined;
}

/** 只取参数值区域：query 值、JSON 字符串值、-d 载荷。命令行里的裸地址、配置里的键值不算探针。 */
function paramZone(input: string): string {
  const parts: string[] = [];
  const push = (raw?: string) => {
    const v = (raw ?? "").trim();
    if (v && v.length <= 300) parts.push(v);
  };
  for (const m of input.matchAll(/[?&][A-Za-z_][\w.-]{0,23}=([^&\s'"<>]{1,300})/g)) push(m[1]);
  for (const m of input.matchAll(/["'][A-Za-z_][\w.-]{0,23}["']\s*:\s*"([^"\\]{1,300})"/g)) push(m[1]);
  for (const m of input.matchAll(
    /(?:-d|--data(?:-raw|-binary)?|--body)\s+(?:'([^']{1,300})'|"([^"]{1,300})"|(\S{1,300}))/gi,
  )) {
    push(m[1] ?? m[2] ?? m[3]);
  }
  const seen = new Set<string>();
  return parts
    .filter((p) => (seen.has(p) ? false : (seen.add(p), true)))
    .join("\n");
}

const STATIC_EXT_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?|txt|xml)$/i;

function readRequest(title: string, input: string, kind?: string): RequestInfo {
  const hay = `${title}\n${input}`;
  const urlMatch = input.match(/https?:\/\/[^\s'"<>）)]+/i);
  const url = urlMatch ? urlMatch[0].replace(/[),.;]+$/, "") : undefined;

  let method: string | undefined;
  for (const re of METHOD_RE) {
    const m = hay.match(re);
    if (m) {
      method = m[1].toUpperCase();
      break;
    }
  }

  let path: string | undefined;
  if (url) {
    try {
      const u = new URL(url);
      path = `${u.pathname}${u.search}`;
    } catch {
      path = undefined;
    }
  }
  if (!path) {
    const m = input.match(/(?:^|[\s'"])(\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,120})/);
    if (m) path = m[1];
  }

  // 本地写文件 / 改配置：正文里出现地址也只是素材，不算发请求
  const fileAction = Boolean(kind && FILE_KINDS.has(kind));
  const isShell =
    kind === "execute" ||
    /^(run_terminal_command|run_command|terminal|shell|bash|powershell)\b/i.test(title);
  const isRequest = !fileAction && (REQUEST_TOOL_RE.test(hay) || (!isShell && Boolean(url)));

  const params: string[] = [];
  const addParam = (raw?: string) => {
    if (!raw) return;
    const key = raw.trim();
    if (!key || key.length > 24 || params.includes(key)) return;
    if (HEADER_WORDS.has(key.toLowerCase())) return;
    if (params.length < 3) params.push(key);
  };
  if (isRequest) {
    for (const m of input.matchAll(/[?&]([A-Za-z_][\w.-]{0,23})=/g)) addParam(m[1]);
    if (params.length === 0) {
      for (const m of input.matchAll(/["']([A-Za-z_][\w.-]{0,23})["']\s*:/g)) addParam(m[1]);
    }
  }

  const zone = isRequest ? paramZone(input) : "";
  return {
    method,
    url,
    path,
    host: url ? extractHosts(url, 1)[0] : extractHosts(input, 1)[0],
    params,
    probe: zone ? probeName(zone) : undefined,
    hasSession: isRequest && SESSION_RE.test(input),
    isRequest,
  };
}

/* ------------------------------- 接口识别 ------------------------------- */

function normalizePath(raw: string): string {
  let path = (raw ?? "").trim();
  const q = path.search(/[?#]/);
  if (q >= 0) path = path.slice(0, q);
  path = path.replace(/[),.;:'"\]}]+$/, "");
  if (path.length > 1) path = path.replace(/\/+$/, "");
  return path;
}

// 只认业务接口前缀，避免把静态目录、日期、版本号当接口
const API_PATH_RE =
  /\/(?:api|apis|prod-api|admin|gateway|gw|rest|open|openapi|inner|internal|service|services|system|sys|auth|oauth|user|users|file|files|upload|download|export|import|v1|v2|v3)\/[A-Za-z0-9._~!$&'()*+,;=:@%$/-]{1,90}/gi;

/** 从前端文件、回包、命令里认出接口路径，按出现顺序去重 */
export function extractApiPaths(text: string, max = 8): string[] {
  if (!text) return [];
  const out: string[] = [];
  for (const m of text.matchAll(API_PATH_RE)) {
    const path = normalizePath(m[0]);
    if (!path || path.length < 6) continue;
    const tail = path.split(".").pop()?.toLowerCase() ?? "";
    if (tail && FILE_EXT.has(tail)) continue;
    if (out.includes(path.toLowerCase())) continue;
    out.push(path.toLowerCase());
    if (out.length >= max) break;
  }
  return out;
}

const VERDICT_RANK: Record<TestVerdict, number> = {
  hit: 5,
  running: 4,
  blocked: 3,
  unclear: 2,
  clean: 1,
  missed: 1,
  failed: 0,
};

interface EndpointHit {
  path: string;
  host?: string;
  method?: string;
  at: number;
  verdict?: TestVerdict;
  result?: string;
  called: boolean;
  source: string;
  direction: DirectionId;
  testId: string;
  sample?: string;
}

function collectEndpoint(store: Map<string, EndpointInfo>, hit: EndpointHit): void {
  const key = hit.path.toLowerCase();
  const prev = store.get(key);
  if (!prev) {
    store.set(key, {
      key,
      path: hit.path,
      host: hit.host,
      method: hit.method?.toUpperCase(),
      count: 1,
      firstAt: hit.at,
      lastAt: hit.at,
      verdict: hit.verdict ?? "unclear",
      result: hit.result,
      status: hit.called ? "called" : "seen",
      source: hit.source,
      directions: [hit.direction],
      testIds: [hit.testId],
      sample: hit.sample,
    });
    return;
  }
  prev.count += 1;
  prev.firstAt = Math.min(prev.firstAt, hit.at);
  prev.lastAt = Math.max(prev.lastAt, hit.at);
  if (hit.host && !prev.host) prev.host = hit.host;
  if (hit.method && !prev.method) prev.method = hit.method.toUpperCase();
  if (hit.called) {
    prev.status = "called";
    prev.source = hit.source;
  }
  if (hit.verdict && VERDICT_RANK[hit.verdict] > VERDICT_RANK[prev.verdict]) {
    prev.verdict = hit.verdict;
  }
  if (hit.result) prev.result = hit.result;
  if (!prev.directions.includes(hit.direction)) prev.directions.push(hit.direction);
  if (!prev.testIds.includes(hit.testId)) prev.testIds.push(hit.testId);
  if (hit.sample) prev.sample = hit.sample;
}

const ENDPOINT_MAX_PER_DIRECTION = 40;
const ENDPOINT_MAX = 80;

/** 接口按「有回显 → 还没打 → 其余」排，未打的排前面方便直接接着打 */
function sortEndpoints(list: EndpointInfo[]): EndpointInfo[] {
  return [...list].sort((a, b) => {
    if (a.status !== b.status) return a.status === "seen" ? -1 : 1;
    if (a.verdict !== b.verdict) return VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict];
    return b.lastAt - a.lastAt;
  });
}

/** 一条测试里能认出来的接口：真打过的算 called，前端文件和回包里认出来的算 seen */
function scanTestEndpoints(
  test: AttackTest,
  into: Map<string, EndpointInfo>,
  mirror?: Map<string, EndpointInfo>,
): void {
  const push = (hit: EndpointHit) => {
    collectEndpoint(into, hit);
    if (mirror) collectEndpoint(mirror, hit);
  };
  if (test.isRequest && test.path && test.path !== "/") {
    push({
      path: test.path,
      host: test.host,
      method: test.method,
      at: test.at,
      verdict: test.verdict,
      result: test.result,
      called: true,
      source: "直接调用",
      direction: test.direction,
      testId: test.id,
      sample: test.output,
    });
  }
  const fromOutput = extractApiPaths(test.output ?? "", 6);
  const outputHost = fromOutput.length ? extractHosts(test.output ?? "", 1)[0] : undefined;
  for (const path of fromOutput) {
    push({
      path,
      host: outputHost,
      at: test.at,
      called: false,
      source: "回包",
      direction: test.direction,
      testId: test.id,
    });
  }
  if (test.kind && READ_KINDS.has(test.kind)) {
    const inputHost = extractHosts(test.input ?? "", 1)[0];
    for (const path of extractApiPaths(test.input ?? "", 6)) {
      if (fromOutput.includes(path)) continue;
      push({
        path,
        host: inputHost,
        at: test.at,
        called: false,
        source: "前端文件",
        direction: test.direction,
        testId: test.id,
      });
    }
  }
}

const GAIN_MAX_PER_DIRECTION = 10;

/** 真出数的动作才记成果：有回显、落盘的报告 */
function gainOfTest(test: AttackTest): Gain | undefined {
  if (test.verdict !== "hit" && test.direction !== "report") return undefined;
  if (test.direction === "report") {
    return {
      id: `gain-${test.id}`,
      kind: "report",
      direction: "report",
      at: test.at,
      title: test.path ? `写入 ${test.path}` : test.description,
      detail: test.output ? clipText(test.output, 200) : undefined,
      host: test.host,
      testId: test.id,
    };
  }
  return {
    id: `gain-${test.id}`,
    kind: "hit",
    direction: test.direction,
    at: test.at,
    title: test.description,
    detail: test.output ? clipText(test.output, 200) : test.path,
    host: test.host,
    testId: test.id,
  };
}

/* ------------------------------- 方向判定 ------------------------------- */

const FILE_WRITE_RE = /write_file|create_file|edit_file|apply_patch|set-content|out-file|>>|\bmv\b|\brm\b/i;

/** 取静态资源 / 首页 / 探测文件：算信息收集，不算对业务接口的未授权访问 */
function isStaticFetch(req: RequestInfo): boolean {
  const p = (req.path ?? "").split("?")[0];
  if (!p || p === "/") return true;
  if (STATIC_EXT_RE.test(p)) return true;
  return /\/(?:robots\.txt|sitemap\.xml|favicon\.ico|\.well-known\/)/i.test(p);
}

const AUTH_RE =
  /登录|登陆|认证|接管|重置密码|找回密码|改绑|换绑|绑定手机|验证码|滑块|oauth|sso|cas\b|jwt|2fa|otp|signin|sign-in|signup|register|refresh_token|accesstoken|access_token|会话失效/i;
const IDOR_RE = /越权|idor|换\s*id|换对象|邻号|遍历\s*id|别人的|其他(?:用户|租户|主体)|跨租户|跨用户/i;
const LOGIC_RE =
  /\b(?:amount|price|money|balance|status|state|role|is_?admin|admin|vip|level|coupon|stock|quantity|audit|approve|refund|pay|payment|discount)\b\s*[:=]|金额|改价|退款|库存|优惠券|审核|并发|跳步|提权|绕过验证/i;
const OBJECT_ID_RE =
  /[?&](?:id|uid|user_?id|order_?id|tenant_?id|org_?id|account_?id|member_?id|file_?id|doc_?id|task_?id|pid|sid)=|["'](?:id|uid|user_?id|order_?id|tenant_?id|org_?id|account_?id|member_?id|file_?id|doc_?id|task_?id)["']\s*:/i;
const UPLOAD_RE = /multipart\/form-data|(?:^|\s)-F\s|filename=|上传|upload|下载|download|fileKey|file_key|fileName/i;
const EXEC_RE = /os-shell|os-pwn|sql-shell|--file-write|反序列化|命令执行|代码执行|代码注入|rce\b|execute\s+command|cmd\.exe|\/bin\/sh|child_process|Runtime\.getRuntime|模板注入/i;
const RECON_TOOL_RE =
  /\b(fofa|shodan|zoomeye|subfinder|amass|nmap|masscan|ffuf|dirsearch|gobuster|feroxbuster|wfuzz|httpx|katana|whatweb|nslookup|whois|playwright)\b|browser_navigate|crt\.sh/i;

/** 本地读到的前端包 / JS 目录：抽接口用，算信息收集；其余本地文件属于准备动作 */
const CODE_FILE_RE = /[\\/]js[\\/]|[\\/]js(?=\s|$)|\/(?:js|static)\/|\.(?:js|mjs|cjs|json|html?|har)\b/i;

function classifyDirection(title: string, input: string, kind?: string): DirectionId {
  const hay = `${title}\n${input}`;
  const pathHint = `${title}\n${input.split("\n")[0] ?? ""}`;
  const req = readRequest(title, input, kind);

  // 报告 / 资产整理：写 .md、整理清单
  const fileWrite = kind ? FILE_KINDS.has(kind) : FILE_WRITE_RE.test(hay);
  if (fileWrite && /报告|report|\.md\b|findings?\.|资产|种子队列|清单/i.test(pathHint)) {
    return "report";
  }
  if (/^(todo_write|update_plan|plan_write|write_todos|set_plan|task_write)\b/i.test(title.trim())) {
    return "other";
  }
  if (/^(todo_write|update_plan|plan_write|write_todos|set_plan)\b/i.test(title.trim())) return "other";

  // 本地读写：读前端包算抽接口，其余（笔记、脚本、教材）属于准备动作
  const localFile =
    !req.isRequest && Boolean(kind && (FILE_KINDS.has(kind) || READ_KINDS.has(kind)));
  if (localFile) return CODE_FILE_RE.test(pathHint) ? "recon" : "other";

  // 探针类先判：动作本身说明在验什么
  if (req.probe === "命令拼接串" || EXEC_RE.test(hay)) return "rce";
  if (req.probe === "内网回连地址") return "ssrf";
  if (req.probe === "脚本标签") return "xss";
  if (req.probe === "模板表达式" || req.probe === "NoSQL 操作符" || req.probe === "SQL 探针") {
    return "injection";
  }
  if (req.probe === "路径穿越串") return "upload";
  // 上传 / 下载口：只认真在打文件接口，取首页或前端包不算
  if (UPLOAD_RE.test(hay) && req.isRequest && !isStaticFetch(req)) return "upload";

  // 认证口：路径或参数里带登录/重置/改绑
  if (AUTH_RE.test(hay) && (req.isRequest || /login|auth|token|session|reset|bind/i.test(hay))) {
    return "auth";
  }

  if (IDOR_RE.test(hay)) return "idor";
  if (LOGIC_RE.test(hay) && req.isRequest) return "logic";
  if (OBJECT_ID_RE.test(hay) && req.isRequest && req.hasSession) return "idor";

  if (req.isRequest) {
    if (isStaticFetch(req)) return "recon";
    if (!req.hasSession) return "unauth";
    return "recon";
  }

  // 侦察工具按工具名认，命令里的中文旁白不算方向
  if (RECON_TOOL_RE.test(title) || RECON_TOOL_RE.test(input)) return "recon";
  return "other";
}

/** 只按意图词判方向，用于计划条目（没有请求可解析） */
function classifyIntent(text: string): DirectionId | undefined {
  const t = text ?? "";
  if (!t.trim()) return undefined;
  if (/登录|认证|接管|重置|改绑|换绑|验证码|会话|token|jwt|oauth|sso/i.test(t)) return "auth";
  if (/越权|idor|换\s*id|邻号|跨用户|跨租户/i.test(t)) return "idor";
  if (/注入|sql|nosql|模板|ssti|hql|spel/i.test(t)) return "injection";
  if (/ssrf|回连|内网|元数据/i.test(t)) return "ssrf";
  if (/xss|脚本|回显/i.test(t)) return "xss";
  if (/上传|下载|穿越|文件读|file/i.test(t)) return "upload";
  if (/rce|命令执行|反序列化|代码执行|shell/i.test(t)) return "rce";
  if (/逻辑|金额|支付|退款|库存|券|审核|并发|状态机|提权/i.test(t)) return "logic";
  if (/未授权|未登录|匿名/i.test(t)) return "unauth";
  if (/资产|指纹|子域|接口|js|目录|信息收集|测绘|报告|整理/i.test(t)) return "recon";
  return undefined;
}

/* ------------------------------- 结果判定 ------------------------------- */

/** 被风控 / 封禁 / 限流 / 人机验证拦下：这一步没进业务，但结果是明确的 */
const BAN_RE =
  /(?<![\d.])429(?![\d.])|too many requests|rate ?limit|请求过于频繁|请求太多|限流|IP\s*(?:已|被)?\s*(?:封|禁|拉黑|限制)|封禁|风控|人机验证|captcha|cf-chl|cloudflare|just a moment|访问被拦截|已拦截|触发拦截|intercepted/i;

/** 认证 / 权限墙 */
const BLOCK_RE =
  /(?<![\d.])(?:401|403)(?![\d.])|\bunauthorized\b|\bforbidden\b|请先?登录|please (?:log|sign) ?in|未登录|无权限|权限不足|拒绝访问|访问被拒绝|access denied|not authorized|invalid (?:token|session|credential)|token (?:无效|失效|过期)|会话(?:已)?(?:失效|过期)|认证失败|鉴权失败|账号登录|用户登录|请输入(?:用户名|账号|密码)/i;

/** 真出数的回显 */
const HIT_RE =
  /"total"\s*:\s*"?[1-9]|"(?:count|totalCount|total_count)"\s*:\s*"?[1-9]|"(?:data|rows|list|records|items)"\s*:\s*\[\s*[{\["]|"success"\s*:\s*true|登录成功|已登录|越权成功|未授权可访问|成功读取|命令执行成功|\buid=0\(root\)/i;

/** 报错回显：注入 / 模板 / 解析错误，是最有价值的差分 */
const ERR_ECHO_RE =
  /SQL syntax|sqlstate|ORA-\d{4,5}|MySQLSyntaxError|Unclosed quotation|syntax error at or near|near\s+"[^"]{1,30}"\s*:\s*syntax|invalid input syntax|TemplateSyntaxError|TemplateInputException|FreeMarker|SpelEvaluationException|javax\.el\.|ognl/i;

const FAIL_RE =
  /ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|getaddrinfo|connection (?:refused|reset)|timed? ?out|超时|连接失败|命令未找到|command not found|no route to host|network is unreachable|ssl(?:v3)?_?get_error|certificate (?:verify|has expired)/i;

function bytesText(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function firstLine(text: string, max = 110): string {
  const line =
    text
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.length > 0) ?? "";
  return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}

/** 在命中位置附近取原话，贴进结果里 */
function quoted(text: string, match: RegExpMatchArray, max = 64): string {
  const at = match.index ?? 0;
  const raw = text
    .slice(Math.max(0, at - 16), Math.min(text.length, at + 84))
    .replace(/\s+/g, " ")
    .trim();
  return raw.length > max ? `${raw.slice(0, max - 1)}…` : raw;
}

/**
 * 聊天里直接说一句：这一枪被限流 / 封 IP / 人机验证 / 权限墙挡了。
 * 工具输出默认折叠，封 IP 这种关键状态不能等人展开才看见。
 */
export function banNotice(output?: string): string | undefined {
  const out = (output ?? "").replace(/\r/g, "").trim();
  if (!out) return undefined;
  const code = findHttpCode(out);
  if (code === 429 || /too many requests|rate ?limit|请求过于频繁|请求太多|限流/i.test(out)) {
    const head = code === 429 ? "429 被限流" : "被限流";
    return `${head}：这个出口 IP 很可能已经被封，先换代理或等冷却再打`;
  }
  const ban = out.match(
    /IP\s*(?:已|被)?\s*(?:封|禁|拉黑|限制)|\bip\b[^.\n]{0,24}\b(?:blocked|banned|blacklisted|denied)\b|封禁|风控|访问被拦截|已拦截|触发拦截|\bblocked\b|intercepted/i,
  );
  if (ban) return `被风控 / 封禁拦下：${quoted(out, ban)}`;
  if (/人机验证|captcha|cf-chl|cloudflare|just a moment/i.test(out)) {
    return "撞到人机验证 / Cloudflare 盾：这一枪没进业务，换出口或降速再试";
  }
  if (code === 401 || code === 403 || /\baccess denied\b/i.test(out)) {
    return `${code ? `${code}：` : ""}要登录或当前身份没权限，这是权限墙，先别当洞`;
  }
  return undefined;
}

function findHttpCode(out: string): number | undefined {
  const patterns = [
    /\bHTTP\/\d(?:\.\d)?\s+"?(\d{3})\b/i,
    /^\s*(?:status(?:\s*code)?|http[_-]?code|statusCode)\s*[:=]\s*"?(\d{3})\b/im,
    /"(?:status|statusCode|httpCode)"\s*:\s*(\d{3})\b/,
    /\b(\d{3})\s+(?:OK|Created|No Content|Bad Request|Unauthorized|Forbidden|Not Found|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Moved Permanently|Found)\b/,
  ];
  for (const re of patterns) {
    const m = out.match(re);
    if (!m) continue;
    const code = Number(m[1]);
    if (code >= 100 && code <= 599) return code;
  }
  return undefined;
}

function findExit(out: string): number | undefined {
  const m = out.match(/\bexit(?:\s*code)?\s*[:=]\s*(-?\d+)/i);
  return m ? Number(m[1]) : undefined;
}

interface JsonSignal {
  total?: number;
  code?: number;
  success?: boolean;
  rows?: string;
}

function jsonSignal(out: string): JsonSignal {
  const sig: JsonSignal = {};
  const total = out.match(/"(?:total|totalCount|total_count|count)"\s*:\s*"?(\d{1,9})"?(?=[,}\]])/i);
  if (total) sig.total = Number(total[1]);
  const code = out.match(/"(?:code|errcode|errCode|status)"\s*:\s*"?(\d{1,6})"?(?=[,}\]])/);
  if (code) sig.code = Number(code[1]);
  if (/"success"\s*:\s*(?:true|false)/i.test(out)) sig.success = /"success"\s*:\s*true/i.test(out);
  const list = out.match(/"(list|rows|records|items|data)"\s*:\s*\[([\s\S]{0,4000}?)\]/i);
  if (list) {
    const n = (list[2].match(/\{/g) ?? []).length;
    sig.rows = n > 0 ? `${list[1]} ${n} 条` : `${list[1]} 为空`;
  }
  return sig;
}

export interface OutputAnalysis {
  verdict: TestVerdict;
  /** 一行结论：这一步拿到了什么，直接给人看 */
  result: string;
  code?: number;
}

/**
 * 把一次工具回包翻成结论。
 * 请求类按状态码 + 业务字段 + 拦截特征判；本地读写命令按退出码和输出量判。
 */
export function analyzeOutput(
  status: string,
  output?: string,
  opts: { isRequest?: boolean } = {},
): OutputAnalysis {
  const out = (output ?? "").replace(/\r/g, "").trim();
  if (status === "pending" || status === "in_progress") {
    return { verdict: "running", result: "已发出，等回包" };
  }
  if (status === "failed" || status === "cancelled") {
    return { verdict: "failed", result: out ? `中断：${firstLine(out, 90)}` : "工具中断，没有回包" };
  }
  if (!out) return { verdict: "unclear", result: "没有回包内容" };

  const size = bytesText(out.length);
  const exit = findExit(out);
  const fail = out.match(FAIL_RE);

  if (!opts.isRequest) {
    // 读文件、grep、组装命令：按执行结果说话，不把文件内容里的字样当回包
    if (fail && exit === undefined) return { verdict: "failed", result: `执行失败：${quoted(out, fail)}` };
    if (exit !== undefined && exit !== 0) {
      return { verdict: "failed", result: `退出码 ${exit}：${firstLine(out, 90)}` };
    }
    const lines = out.split("\n").filter((l) => l.trim()).length;
    if (exit === 0) return { verdict: "clean", result: `执行成功 · 退出码 0 · 输出 ${lines} 行` };
    return { verdict: "clean", result: `拿到内容 · ${lines} 行 · ${size}` };
  }

  const code = findHttpCode(out);
  const sig = jsonSignal(out);
  const ban = out.match(BAN_RE);
  const block = out.match(BLOCK_RE);
  const echo = out.match(ERR_ECHO_RE);
  const hit = out.match(HIT_RE);

  const head = code ? `HTTP ${code} · ` : "";
  if (ban) return { verdict: "blocked", result: `${head}被风控拦下：${quoted(out, ban)}`, code };
  if (code === 429) return { verdict: "blocked", result: "HTTP 429 限流，IP 可能已经被封", code };
  if (code === 401 || code === 403) {
    return { verdict: "blocked", result: `${head}要登录 / 无权限：${firstLine(out, 78)}`, code };
  }
  if (block) return { verdict: "blocked", result: `${head}被挡：${quoted(out, block)}`, code };
  if (fail && code === undefined) return { verdict: "failed", result: `连不上：${quoted(out, fail)}` };
  if (echo) return { verdict: "hit", result: `${head}报错回显：${quoted(out, echo)}`, code };
  if (hit) {
    const bits = [
      code ? `HTTP ${code}` : undefined,
      sig.total !== undefined ? `total=${sig.total}` : undefined,
      sig.rows,
      `回包 ${size}`,
    ].filter(Boolean);
    return { verdict: "hit", result: `${bits.join(" · ")} · 有业务数据`, code };
  }
  if (code !== undefined) {
    if (code >= 500) {
      return { verdict: "missed", result: `${head}服务端报错：${firstLine(out, 78)}（有差分，换参再打一次）`, code };
    }
    if (code >= 400) return { verdict: "missed", result: `${head}${firstLine(out, 78)}`, code };
    if (code >= 300) return { verdict: "clean", result: `${head}跳转：${firstLine(out, 78)}`, code };
    if (sig.total === 0) return { verdict: "missed", result: `${head}total=0 空列表（结构在，换参再打）`, code };
    if (sig.success === false) {
      return { verdict: "missed", result: `${head}success=false：${firstLine(out, 70)}`, code };
    }
    const shape = out.length <= 40 ? `空回包 ${size}` : `回包 ${size}`;
    return { verdict: "clean", result: `${head}${shape} · 没有业务数据字段`, code };
  }
  if (sig.code !== undefined && sig.code >= 400) {
    return { verdict: "missed", result: `业务码 ${sig.code}：${firstLine(out, 78)}` };
  }
  // 没有状态码的回包里多半是搜索引擎 / 网页正文 / 纯文本，照样把拿到什么写出来
  const lines = out.split("\n").filter((l) => l.trim()).length;
  if (lines >= 2 || out.length >= 160) {
    return { verdict: "clean", result: `拿到${contentKind(out)} · ${lines} 行 · ${size} · 没有状态码` };
  }
  return { verdict: "unclear", result: `回包 ${size} · 没有状态码也没有业务字段` };
}

function contentKind(out: string): string {
  if (/百度一下|搜索结果|约\s*[\d,]+\s*条结果|bing\.com\/search|\/s\?wd=|<\/h3>/i.test(out)) return "搜索结果";
  if (/<(!doctype|html|head|body|div)/i.test(out)) return "网页内容";
  return "文本内容";
}

/** 只要结论词的场景（接口清单汇总）走这里 */
function verdictOf(status: string, output?: string, isRequest = true): TestVerdict {
  return analyzeOutput(status, output, { isRequest }).verdict;
}

/* ------------------------------- 规范化描述 ------------------------------- */

function methodPath(req: RequestInfo): string {
  const parts = [req.method?.toUpperCase(), req.path].filter(Boolean) as string[];
  return parts.join(" ");
}

export function describeTest(
  dir: DirectionId,
  req: RequestInfo,
  title: string,
  input: string,
  kind?: string,
): string {
  const target = req.path || (req.host ? `//${req.host}` : "");
  const withMethod = (p: string) => (req.method ? `${req.method.toUpperCase()} ${p}` : p);
  const paramText = req.params.length ? req.params.join(" / ") : "";
  const first = headline(input, 60);
  const isExec = kind === "execute" || /^(run_terminal_command|run_command|terminal|shell|bash|powershell)\b/i.test(title);

  switch (dir) {
    case "unauth":
      return target ? `不带会话直取 ${target}${req.method ? `（${req.method.toUpperCase()}）` : ""}` : "不带会话直调业务接口";
    case "idor":
      return `用自己会话换对象 ID 取 ${target || "业务对象"}${paramText ? `（参数 ${paramText}）` : ""}`;
    case "auth":
      return `打认证接口 ${target || "登录 / 重置 / 改绑口"}${paramText ? `（参数 ${paramText}）` : ""}`;
    case "injection":
      return `${paramText ? `在 ${paramText} ` : ""}投 ${req.probe || "注入探针"}${target ? `（${withMethod(target)}）` : ""}`;
    case "ssrf":
      return `${paramText ? `在 ${paramText} ` : ""}投 ${req.probe || "内网回连地址"}${target ? `（${target}）` : ""}`;
    case "xss":
      return `${paramText ? `在 ${paramText} ` : ""}投 ${req.probe || "脚本标签"}${target ? `（${target}）` : ""}`;
    case "upload":
      return `打上传 / 下载口 ${target || "文件接口"}${paramText ? `（参数 ${paramText}）` : ""}`;
    case "rce":
      if (!req.isRequest) return `查命令执行入口 ${first || title}`;
      return `试执行入口 ${target || "命令 / 模板口"}${paramText ? `（参数 ${paramText}）` : ""}`;
    case "logic":
      return paramText
        ? `改 ${paramText} 走 ${target || "业务写口"}`
        : `试业务逻辑 ${target || "业务写口"}`;
    case "recon":
      if (req.isRequest) {
        if (isStaticFetch(req)) return `取站点资源 ${withMethod(target)}`;
        return `摸接口 ${withMethod(target)}${paramText ? `（参数 ${paramText}）` : ""}`;
      }
      if (isExec) return `跑资产发现命令 ${first || title}`;
      if (kind && READ_KINDS.has(kind)) return `读目标文件 ${first || title}`;
      return `收集 ${target || req.host || first || title}`;
    case "report":
      return `落盘 ${first || "报告与资产"}`;
    default:
      if (isExec) return `执行本地命令 ${first || title}`;
      if (kind && READ_KINDS.has(kind)) return `读取 ${first || title}`;
      if (kind && FILE_KINDS.has(kind)) return `写文件 ${first || title}`;
      return `${clipText(title, 28) || "工具动作"}：${first || "见证据"}`;
  }
}

/** 把一次测试归到一类规范动作，方向总览里按类计数 */
const ACTION_LABEL: Array<[RegExp, string]> = [
  [/^不带会话/, "匿名直取"],
  [/^用自己会话换/, "换对象 ID"],
  [/^打认证接口/, "打认证口"],
  [/^打上传 \/ 下载口/, "打文件口"],
  [/^查命令执行入口|^试执行入口/, "查执行入口"],
  [/^改 |^试业务逻辑/, "试业务逻辑"],
  [/^取站点资源/, "取站点资源"],
  [/^摸接口/, "摸接口"],
  [/^跑资产发现命令/, "跑资产发现"],
  [/^读目标文件/, "读前端文件"],
  [/^收集 /, "收集线索"],
  [/^落盘 /, "落盘报告"],
  [/^执行本地命令/, "本地命令"],
  [/^读取 /, "读本地文件"],
  [/^写文件 /, "写文件"],
];

function actionLabel(test: AttackTest): string {
  if (/^在 .*投 |^投 /.test(test.description)) {
    if (test.direction === "ssrf") return "投 SSRF 探针";
    if (test.direction === "xss") return "投 XSS 探针";
    return "投注入探针";
  }
  for (const [re, label] of ACTION_LABEL) {
    if (re.test(test.description)) return label;
  }
  return "其它动作";
}

/** 一条方向的规范描述：总次数 + 做过的测试按动作归类，取前三类 */
export function summarizeTests(tests: AttackTest[]): string {
  if (tests.length === 0) return "还没开打";
  const counts = new Map<string, number>();
  for (const test of tests) {
    const label = actionLabel(test);
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const parts = [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 3)
    .map(([label, n]) => `${label} ${n} 次`)
    .join(" · ");
  return `${tests.length} 次测试：${parts}`;
}

/* ------------------------------- 建图 ------------------------------- */

const MAX_TESTS_PER_DIRECTION = 60;
const MAX_CONCLUSIONS = 24;
const MAX_NEXT = 6;

const FINDING_RE = /严重|高危|中危|低危|漏洞|可利用|已确认|已打通|发现|未授权|越权|注入|接管|泄露|绕过|命中/i;

function isFindingText(text: string): boolean {
  const t = text.trim();
  if (t.length < 24) return false;
  if (/^(我|先|现在|接下来|下面|好)/.test(t) && t.length < 60) return false;
  return FINDING_RE.test(t);
}

function findingTitle(text: string): string {
  const line =
    text
      .split("\n")
      .map((l) => l.replace(/^[#>*\-\s]+/, "").trim())
      .find((l) => l.length > 0) ?? "";
  return clipText(line, 90);
}

function emptyVerdicts(): Record<TestVerdict, number> {
  return { hit: 0, blocked: 0, clean: 0, missed: 0, unclear: 0, failed: 0, running: 0 };
}

export function emptyAttackGraph(): AttackGraphData {
  return {
    directions: [],
    tests: [],
    hosts: [],
    conclusions: [],
    next: [],
    endpoints: [],
    gains: [],
    blackboard: {
      live: false,
      stats: { gains: 0, endpoints: 0, discovered: 0, hosts: 0, tests: 0, rounds: 0 },
    },
    counts: { directions: 0, tests: 0, hit: 0, running: 0, planned: 0, gains: 0, endpoints: 0 },
    busy: false,
    trimmed: 0,
  };
}

const STATUS_RANK: Record<DirectionStatus, number> = {
  running: 0,
  hit: 1,
  unclear: 2,
  planned: 3,
  excluded: 4,
};

function statusOf(tests: AttackTest[]): DirectionStatus {
  if (tests.length === 0) return "planned";
  if (tests.some((t) => t.verdict === "running")) return "running";
  if (tests.some((t) => t.verdict === "hit")) return "hit";
  // 只有真的判不出来（没状态码、没业务字段）才留待确认；测过没出数的算已排除
  if (tests.every((t) => t.verdict === "unclear")) return "unclear";
  return "excluded";
}

export function buildAttackGraph(state?: SessionState): AttackGraphData {
  const graph = emptyAttackGraph();
  if (!state) return graph;

  const tests: AttackTest[] = [];
  const conclusions: Conclusion[] = [];
  let round = 0;
  let lastPlan: PlanEntry[] = [];
  let assistantTail = "";
  /** 说这段话时正在跑的方向，用来把模型的结论挂到树上 */
  let lastDir: DirectionId | undefined;

  for (const item of state.timeline as TimelineItem[]) {
    if (item.type === "user") {
      const text = (item.text ?? "").trim();
      if (!text || text.startsWith("<system-reminder")) continue;
      round += 1;
      continue;
    }
    if (item.type === "plan") {
      lastPlan = item.entries ?? [];
      continue;
    }
    if (item.type === "assistant") {
      if (item.text && isFindingText(item.text)) {
        conclusions.push({
          id: item.id,
          at: item.at,
          title: findingTitle(item.text),
          text: clipText(item.text, 4000),
          streaming: Boolean(item.streaming),
          direction: lastDir,
        });
      }
      if (item.text && item.text.trim()) assistantTail = item.text;
      continue;
    }
    if (item.type !== "tool") continue;

    const call = item.call;
    const title = call.title || `${call.kind ?? "工具"}调用`;
    const input = summarizeInput(call.input);
    const direction = classifyDirection(title, input, call.kind);
    lastDir = direction;
    const req = readRequest(title, input, call.kind);
    const hosts = extractHosts(`${title}\n${input}`, 6);
    const at = call.startedAt || item.at;
    const analysis = analyzeOutput(call.status, call.output, { isRequest: req.isRequest });

    tests.push({
      id: call.id || item.id,
      direction,
      at,
      round: Math.max(round, 1),
      host: hosts[0],
      hosts,
      title,
      description: describeTest(direction, req, title, input, call.kind),
      method: req.method?.toUpperCase(),
      path: req.path,
      params: req.params,
      probe: req.probe,
      verdict: analysis.verdict,
      result: analysis.result,
      code: analysis.code,
      kind: call.kind,
      status: call.status,
      isRequest: req.isRequest,
      input: input || undefined,
      output: call.output ? clipText(call.output, 2000) : undefined,
      ms: call.endedAt ? Math.max(0, call.endedAt - at) : undefined,
    });
  }

  // 按方向收拢
  const byDirection = new Map<DirectionId, AttackTest[]>();
  for (const test of tests) {
    const list = byDirection.get(test.direction) ?? [];
    list.push(test);
    byDirection.set(test.direction, list);
  }

  const planEntries = (state.plan?.length ? state.plan : lastPlan) ?? [];
  const plannedDirs = new Set<DirectionId>();
  for (const entry of planEntries) {
    if (entry.status === "completed") continue;
    const dir = classifyIntent(entry.content);
    if (dir && !byDirection.has(dir)) plannedDirs.add(dir);
  }

  const directions: AttackDirection[] = [];
  let trimmed = 0;
  const hostMap = new Map<string, { host: string; count: number; lastAt: number }>();
  const endpointMap = new Map<string, EndpointInfo>();

  for (const def of DIRECTION_DEFS) {
    const all = byDirection.get(def.id) ?? [];
    const planned = all.length === 0 && plannedDirs.has(def.id);
    const kept = all.slice(-MAX_TESTS_PER_DIRECTION);

    // 成果与接口先攒出来：没动作但出过结论/成果的方向也留在树上
    const gainList: Gain[] = [];
    const dirEndpoints = new Map<string, EndpointInfo>();
    for (const test of kept) {
      scanTestEndpoints(test, dirEndpoints, endpointMap);
      const gain = gainOfTest(test);
      if (gain) gainList.push(gain);
    }
    for (const conc of conclusions) {
      if ((conc.direction ?? "other") !== def.id) continue;
      gainList.push({
        id: `gain-${conc.id}`,
        kind: "finding",
        direction: def.id,
        at: conc.at,
        title: conc.title,
        detail: clipText(conc.text, 240),
      });
    }
    gainList.sort((a, b) => a.at - b.at);

    if (all.length === 0 && !planned && gainList.length === 0) continue;

    const cut = all.length - kept.length;
    trimmed += cut;
    const verdicts = emptyVerdicts();
    const hosts: string[] = [];
    const rounds: number[] = [];
    let firstAt = 0;
    let lastAt = 0;
    for (const test of kept) {
      verdicts[test.verdict] += 1;
      if (test.host && !hosts.includes(test.host)) hosts.push(test.host);
      if (!rounds.includes(test.round)) rounds.push(test.round);
      firstAt = firstAt ? Math.min(firstAt, test.at) : test.at;
      lastAt = Math.max(lastAt, test.at);
      for (const host of test.hosts) {
        const entry = hostMap.get(host) ?? { host, count: 0, lastAt: 0 };
        entry.count += 1;
        entry.lastAt = Math.max(entry.lastAt, test.at);
        hostMap.set(host, entry);
      }
    }
    const focus =
      [...kept].reverse().find((t) => t.verdict === "running") ?? kept[kept.length - 1];
    directions.push({
      id: def.id,
      def,
      tests: kept,
      hosts,
      firstAt,
      lastAt,
      rounds,
      verdicts,
      status: statusOf(kept),
      summary: summarizeTests(kept),
      trimmed: cut,
      doing: focus,
      gains: gainList.slice(-GAIN_MAX_PER_DIRECTION),
      endpoints: sortEndpoints([...dirEndpoints.values()]).slice(0, ENDPOINT_MAX_PER_DIRECTION),
    });
  }

  // 渗透方向排在前面，报告整理次之，本地杂事垫底
  const groupRank = (dir: AttackDirection) => (dir.id === "other" ? 2 : dir.id === "report" ? 1 : 0);
  directions.sort(
    (a, b) =>
      groupRank(a) - groupRank(b) ||
      STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
      b.lastAt - a.lastAt,
  );

  // 正在测试：优先真实渗透方向里 running 的测试，其次最近动过的真实方向
  let activeDir: AttackDirection | undefined;
  let activeTest: AttackTest | undefined;
  const isReal = (dir: AttackDirection) => dir.id !== "other" && dir.id !== "report";
  for (const pass of [true, false]) {
    for (const dir of directions) {
      if (pass && !isReal(dir)) continue;
      const running = [...dir.tests].reverse().find((t) => t.verdict === "running");
      if (running) {
        activeDir = dir;
        activeTest = running;
        break;
      }
    }
    if (activeDir) break;
  }
  if (!activeDir) {
    const withTests = directions.filter((d) => d.tests.length > 0);
    const real = withTests.filter(isReal);
    const pool = real.length ? real : withTests;
    pool.sort((a, b) => b.lastAt - a.lastAt);
    activeDir = pool[0];
    activeTest = activeDir ? activeDir.tests[activeDir.tests.length - 1] : undefined;
  }

  // 下一步：计划条目 → 模型最后一段话 → 方向缺口
  const next: NextAction[] = [];
  const pushNext = (text: string, source: NextAction["source"], direction?: DirectionId) => {
    const clean = clipText(text.replace(/^[-*\d.、)\s]+/, ""), 110);
    if (!clean || clean.length < 4) return;
    if (next.some((n) => n.text === clean)) return;
    if (next.length >= MAX_NEXT) return;
    next.push({ id: `${source}-${next.length}`, text: clean, source, direction });
  };

  const pendingPlan = planEntries.filter((e) => e.status !== "completed");
  for (const entry of pendingPlan.filter((e) => e.status === "in_progress")) {
    pushNext(entry.content, "plan", classifyIntent(entry.content));
  }
  for (const entry of pendingPlan.filter((e) => e.status !== "in_progress")) {
    pushNext(entry.content, "plan", classifyIntent(entry.content));
  }
  if (assistantTail) {
    const parts = assistantTail
      .split(/\n+/)
      .flatMap((line) => line.split(/[。；;]/))
      .map((s) => s.trim())
      .filter((s) => s.length >= 10 && s.length <= 160)
      .filter((s) => /下一步|接下来|下一步该|接着|建议|还需|需要先|待确认|还没测|未测|补测|先补|继续/i.test(s));
    for (const part of parts.slice(0, 3)) pushNext(part, "assistant");
  }
  // 方向缺口：每个方向最多一条，先说在跑的，再说有回显的
  const gapLine = (dir: AttackDirection): string | undefined => {
    const where = dir.hosts[0] ? ` · ${dir.hosts[0]}` : "";
    const last = dir.tests[dir.tests.length - 1];
    if (dir.status === "running") {
      return `等「${dir.def.label}」这条出结果：${last?.description ?? dir.def.goal}${where}`;
    }
    if (dir.status === "hit") {
      return `「${dir.def.label}」已经有回显${where}，下一步整理成报告，再顺着同一个对象打写接口和跨用户`;
    }
    if (dir.status === "unclear" && dir.tests.length >= 2) {
      return `「${dir.def.label}」${where} 只看到动作没看到回显，下一步换参数或换接口再确认一次`;
    }
    if (dir.status === "planned") {
      return `「${dir.def.label}」还没开打，按计划补上${where}`;
    }
    return undefined;
  };
  let gaps = 0;
  for (const dir of directions) {
    if (gaps >= 2) break;
    if (dir.id === "other" || dir.id === "report") continue;
    const line = gapLine(dir);
    if (!line) continue;
    pushNext(line, "gap", dir.id);
    gaps += 1;
  }

  graph.directions = directions;
  graph.tests = directions.flatMap((d) => d.tests);
  graph.hosts = [...hostMap.values()].sort((a, b) => b.count - a.count || b.lastAt - a.lastAt).slice(0, 60);
  graph.conclusions = conclusions.slice(-MAX_CONCLUSIONS);
  graph.next = next;
  graph.active = activeDir ? { direction: activeDir, test: activeTest } : undefined;
  graph.gains = directions
    .flatMap((d) => d.gains)
    .sort((a, b) => a.at - b.at)
    .slice(-GAIN_MAX_PER_DIRECTION * 4);
  graph.endpoints = sortEndpoints([...endpointMap.values()]).slice(0, ENDPOINT_MAX);
  graph.counts = {
    directions: directions.length,
    tests: graph.tests.length,
    hit: directions.filter((d) => d.status === "hit").length,
    running: directions.filter((d) => d.status === "running").length,
    planned: directions.filter((d) => d.status === "planned").length,
    gains: graph.gains.length,
    endpoints: graph.endpoints.length,
  };
  graph.trimmed = trimmed;
  graph.busy = state.busy || graph.tests.some((t) => t.verdict === "running");
  const ats = graph.tests.map((t) => t.at);
  graph.startedAt = ats.length ? Math.min(...ats) : undefined;
  graph.lastAt = ats.length ? Math.max(...ats) : undefined;

  const seen = graph.endpoints.filter((e) => e.status === "seen").length;
  graph.blackboard = {
    live: graph.busy,
    startedAt: graph.startedAt,
    lastAt: graph.lastAt,
    doing:
      activeDir && activeTest
        ? {
            direction: activeDir.id,
            label: activeDir.def.label,
            cls: activeDir.def.cls,
            text: activeTest.description,
            at: activeTest.at,
            verdict: activeTest.verdict,
          }
        : activeDir
          ? {
              direction: activeDir.id,
              label: activeDir.def.label,
              cls: activeDir.def.cls,
              text: activeDir.def.goal,
              at: activeDir.lastAt,
            }
          : undefined,
    next: next[0]?.text,
    stats: {
      gains: graph.gains.length,
      endpoints: graph.endpoints.length,
      discovered: seen,
      hosts: graph.hosts.length,
      tests: graph.tests.length,
      rounds: Math.max(0, round),
    },
  };
  return graph;
}
