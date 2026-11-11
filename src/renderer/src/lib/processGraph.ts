import type { SessionState, TimelineItem } from "@shared/types";

/**
 * 渗透过程图谱：把会话时间线里的工具调用、授权、结论按「轮次 + 阶段」摊开。
 * 纯前端推导，只读 SessionState，不改引擎、不加请求、不影响挖洞流程。
 */
export type ProcessPhase = "recon" | "probe" | "exploit" | "file" | "auth" | "finding";

export interface PhaseDef {
  id: ProcessPhase;
  label: string;
  hint: string;
}

export const PHASE_DEFS: PhaseDef[] = [
  { id: "recon", label: "侦察", hint: "访问页面、搜索、读文件、抓前端" },
  { id: "probe", label: "探测", hint: "扫描器、批量请求、接口探测" },
  { id: "exploit", label: "利用", hint: "注入、上传、命令、越权验证" },
  { id: "file", label: "文件", hint: "读写文件、写报告、改脚本、整理资产" },
  { id: "auth", label: "授权", hint: "权限确认与放行" },
  { id: "finding", label: "发现", hint: "模型写下的结论与漏洞" },
];

export type ProcessStatus = "running" | "done" | "failed" | "cancelled";

export interface ProcessStep {
  id: string;
  at: number;
  phase: ProcessPhase;
  title: string;
  status: ProcessStatus;
  kind?: string;
  input?: string;
  output?: string;
  /** 卡片上那一行命令/参数摘要 */
  cmd?: string;
  hosts: string[];
  ms?: number;
}

export interface ProcessHost {
  host: string;
  count: number;
  lastAt: number;
  phases: ProcessPhase[];
}

export interface ProcessRound {
  id: string;
  index: number;
  prompt: string;
  at: number;
  busy: boolean;
  steps: ProcessStep[];
  hosts: string[];
  trimmed: number;
}

/** 一轮里按阶段收拢的步骤，树形图里当中间节点用 */
export interface PhaseGroup {
  phase: ProcessPhase;
  steps: ProcessStep[];
}

/** 按阶段分组，组的顺序按该阶段第一次出现的时间排，组内保持时间顺序 */
export function groupByPhase(steps: ProcessStep[]): PhaseGroup[] {
  const groups: PhaseGroup[] = [];
  for (const step of steps) {
    let group = groups.find((g) => g.phase === step.phase);
    if (!group) {
      group = { phase: step.phase, steps: [] };
      groups.push(group);
    }
    group.steps.push(step);
  }
  return groups;
}

export interface ProcessGraphData {
  rounds: ProcessRound[];
  steps: ProcessStep[];
  hosts: ProcessHost[];
  counts: Record<ProcessPhase, number>;
  findings: ProcessStep[];
  startedAt?: number;
  lastAt?: number;
  busy: boolean;
  totalSteps: number;
  totalRounds: number;
}

const MAX_STEPS_PER_ROUND = 80;
const MAX_ROUNDS = 24;
const MAX_HOSTS = 120;

export function emptyProcessGraph(): ProcessGraphData {
  return {
    rounds: [],
    steps: [],
    hosts: [],
    counts: { recon: 0, probe: 0, exploit: 0, file: 0, auth: 0, finding: 0 },
    findings: [],
    busy: false,
    totalSteps: 0,
    totalRounds: 0,
  };
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

// 不带协议的裸域名很容易和代码里的 obj.prop 撞车（ev.data / msg.id / b.click），
// 所以裸词只认这批后缀；URL 里的主机另外放宽。
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
  // 两字母国家域：留 SRC 常碰的，避开 id/se/fr 这种最容易当属性名的
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
  // 形如 1.2.3 / v1.2.3 的版本号别当主机
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

/** 从命令、参数、输出里抠出主机/IPv4；同一段文本最多返回 max 个 */
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

/* ------------------------------- 阶段判定 ------------------------------- */

const FILE_KINDS = new Set(["write", "edit", "create", "delete", "move"]);
const READ_KINDS = new Set(["read", "list", "search", "fetch"]);

const EXPLOIT_RE =
  /--os-shell|--os-pwn|--sql-shell|--file-write|union[\s+]+select|<\s*script|javascript:|\bon(error|load|click|mouseover|focus)\s*=|\bon\w+\s*=\s*["']?[a-z]+\s*\(|\.\.\/\.\.\/|\/etc\/passwd|xp_cmdshell|webshell|反序列化|\bRCE\b|命令执行|代码执行|任意文件(读取|写入|下载|删除)|越权|未授权|upload|上传/i;

const PROBE_RE =
  /\b(nuclei|ffuf|dirsearch|gobuster|feroxbuster|wfuzz|dirb|nmap|masscan|fscan|xray|nikto|whatweb|wpscan|hydra|sqlmap|httpx|katana|arjun|dalfox|fingerprint)\b|扫描|爆破|目录枚举|探测|payload|注入测试/i;

// 终端/HTTP 类工具本身就是在打目标，算「探测」，别全堆到侦察里
const COMMAND_TOOL_RE =
  /^(run_terminal_command|run_command|execute|execute_command|shell|shell_command|terminal|bash|powershell|cmd|console)\b|terminal_command|run_shell/i;

const HTTP_TOOL_RE = /^(fetch|fetch_url|http|http_request|request|requests|urllib|curl|wget|http_get|http_post)\b|urllib|requests\.|httpx|wget|curl\s/i;

const RECON_RE =
  /\b(curl|wget|dig|nslookup|whois|subfinder|amass|fofa|shodan|zoomeye|robots\.txt|swagger|actuator|heapdump|sitemap\.xml|\.well-known|crt\.sh)\b|\.js\b|查看|浏览|访问|读取|搜索|抓包|抽\s*JS/i;

function classify(title: string, inputText: string, kind?: string): ProcessPhase {
  const hay = `${title}\n${inputText}`;
  if (kind && FILE_KINDS.has(kind)) return "file";
  if (EXPLOIT_RE.test(hay)) return "exploit";
  if (PROBE_RE.test(hay)) return "probe";
  if (COMMAND_TOOL_RE.test(title) || HTTP_TOOL_RE.test(title)) return "probe";
  if (kind && READ_KINDS.has(kind)) return extractHosts(hay, 1).length > 0 ? "recon" : kind === "read" || kind === "list" ? "file" : "recon";
  if (RECON_RE.test(hay)) return "recon";
  if (kind === "execute") return "probe";
  return "recon";
}

/* ------------------------------- 文本摘要 ------------------------------- */

function clipText(text: string, max: number): string {
  const clean = text.replace(/\r/g, "").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

const INPUT_KEYS = [
  "command", "cmd", "script", "url", "target", "endpoint", "query", "pattern", "path",
  "file_path", "target_file", "description", "prompt", "content", "text", "body", "data",
];

/** 工具参数压成一段可读文本，侧栏看细节用 */
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

/** 第一行有内容的文本，当卡片上那一行命令/参数摘要 */
function headline(text: string, max = 110): string {
  const line =
    text
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.length > 0) ?? "";
  return clipText(line, max);
}

const FINDING_RE = /严重|高危|中危|低危|漏洞|可利用|已确认|已打通|发现|未授权|越权|注入|接管|泄露|绕过/i;

function findingTitle(text: string): string {
  const line = text
    .split("\n")
    .map((l) => l.replace(/^[#>*\-\s]+/, "").trim())
    .find((l) => l.length > 0) ?? "";
  return clipText(line, 90);
}

function isFindingText(text: string): boolean {
  const t = text.trim();
  if (t.length < 24) return false;
  if (/^(我|先|现在|接下来|下面|好)/.test(t) && t.length < 60) return false;
  return FINDING_RE.test(t);
}

/* ------------------------------- 建图 ------------------------------- */

function statusOf(status: string): ProcessStatus {
  if (status === "completed") return "done";
  if (status === "failed") return "failed";
  if (status === "cancelled") return "cancelled";
  return "running";
}

interface DraftRound {
  id: string;
  prompt: string;
  at: number;
  steps: ProcessStep[];
  trimmed: number;
}

export function buildProcessGraph(state?: SessionState): ProcessGraphData {
  const graph = emptyProcessGraph();
  if (!state) return graph;

  const drafts: DraftRound[] = [];
  let current: DraftRound | undefined;
  const openRound = (prompt: string, at: number, id: string) => {
    current = { id, prompt, at, steps: [], trimmed: 0 };
    drafts.push(current);
  };

  const addStep = (step: ProcessStep) => {
    if (!current) openRound("", step.at, `round-0`);
    const round = current as DraftRound;
    round.steps.push(step);
    if (round.steps.length > MAX_STEPS_PER_ROUND) {
      round.steps.shift();
      round.trimmed += 1;
    }
  };

  for (const item of state.timeline as TimelineItem[]) {
    if (item.type === "user") {
      // 系统注入的提醒（后台任务完成等）不是一轮指令，别单独占一轮
      const text = (item.text ?? "").trim();
      if (!text || text.startsWith("<system-reminder")) continue;
      openRound(clipText(text, 160), item.at, item.id);
      continue;
    }
    if (item.type === "tool") {
      const call = item.call;
      const inputText = summarizeInput(call.input);
      const hosts = extractHosts(`${call.title ?? ""}\n${inputText}`, 8);
      const phase = classify(call.title ?? "", inputText, call.kind);
      addStep({
        id: call.id || item.id,
        at: call.startedAt || item.at,
        phase,
        title: call.title || `${call.kind ?? "工具"}调用`,
        status: statusOf(call.status),
        kind: call.kind,
        input: inputText,
        cmd: headline(inputText),
        output: call.output ? clipText(call.output, 1600) : undefined,
        hosts,
        ms: call.endedAt ? Math.max(0, call.endedAt - (call.startedAt || item.at)) : undefined,
      });
      continue;
    }
    if (item.type === "permission") {
      addStep({
        id: `perm-${item.id}`,
        at: item.at,
        phase: "auth",
        title: item.title || "等待授权",
        status: item.resolvedOptionId ? "done" : "running",
        input: item.detail ? clipText(item.detail, 900) : undefined,
        cmd: headline(item.detail ?? ""),
        hosts: extractHosts(`${item.title}\n${item.detail ?? ""}`, 4),
      });
      continue;
    }
    if (item.type === "assistant") {
      if (!item.text || !isFindingText(item.text)) continue;
      addStep({
        id: `say-${item.id}`,
        at: item.at,
        phase: "finding",
        title: findingTitle(item.text),
        status: item.streaming ? "running" : "done",
        output: clipText(item.text, 1600),
        hosts: extractHosts(item.text, 4),
      });
    }
  }

  const kept = drafts.slice(-MAX_ROUNDS);
  const hostMap = new Map<string, ProcessHost>();

  const rounds: ProcessRound[] = kept.map((draft, index) => {
    const hosts: string[] = [];
    for (const step of draft.steps) {
      for (const host of step.hosts) {
        if (!hosts.includes(host)) hosts.push(host);
        let entry = hostMap.get(host);
        if (!entry) {
          entry = { host, count: 0, lastAt: 0, phases: [] };
          hostMap.set(host, entry);
        }
        entry.count += 1;
        entry.lastAt = Math.max(entry.lastAt, step.at);
        if (!entry.phases.includes(step.phase)) entry.phases.push(step.phase);
      }
      graph.counts[step.phase] += 1;
      graph.steps.push(step);
      if (step.phase === "finding") graph.findings.push(step);
    }
    const running = draft.steps.some((s) => s.status === "running");
    return {
      id: draft.id,
      index: index + 1,
      prompt: draft.prompt,
      at: draft.at,
      busy: running,
      steps: draft.steps,
      hosts: hosts.slice(0, MAX_HOSTS),
      trimmed: draft.trimmed,
    };
  });

  graph.rounds = rounds;
  graph.hosts = [...hostMap.values()]
    .sort((a, b) => b.count - a.count || b.lastAt - a.lastAt)
    .slice(0, MAX_HOSTS);
  graph.totalSteps = graph.steps.length;
  graph.totalRounds = drafts.length;
  graph.busy = state.busy || graph.steps.some((s) => s.status === "running");
  graph.startedAt = rounds[0]?.at;
  graph.lastAt = graph.steps.length ? graph.steps[graph.steps.length - 1].at : rounds[rounds.length - 1]?.at;
  return graph;
}
