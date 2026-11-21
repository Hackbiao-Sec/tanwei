import fsp from "node:fs/promises";
import path from "node:path";
import type { ModelConfig, ModelConfigInput, ModelsConfig } from "../shared/types";

/**
 * 只按块编辑 ~/.grok/config.toml 里的 [model.<key>] 与 [models] default，
 * 其余表、注释与未知字段原样保留。grok 读配置不需要重启整个 CLI，但当前
 * agent 进程只在启动时加载模型目录，所以保存后由调用方重启引擎。
 */

const FIELD_ORDER = [
  "model",
  "name",
  "description",
  "base_url",
  "api_key",
  "env_key",
  "api_backend",
  "context_window",
  "temperature",
  "top_p",
  "max_completion_tokens",
  "reasoning_summary",
] as const;

type Field = (typeof FIELD_ORDER)[number];
const FIELD_SET = new Set<string>(FIELD_ORDER);

const BACKENDS = ["chat_completions", "responses", "messages"];

export function configFile(grokHome: string): string {
  return path.join(grokHome, "config.toml");
}

// ------------------------------------------------------------------ 解析

export interface Block {
  table: string[] | null;
  start: number;
  end: number;
}

export interface Assign {
  key: string;
  start: number;
  end: number;
  valueRaw: string;
}

interface ParsedConfig {
  models: (ModelConfig & { extra: string })[];
  defaultKey?: string;
  lines: string[];
  eol: string;
}

export function splitLines(text: string): { lines: string[]; eol: string } {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  return { lines: text.split(/\r?\n/), eol };
}

function splitTablePath(raw: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      cur += ch;
      if (ch === "\\" && quote === '"') {
        cur += raw[++i] ?? "";
        continue;
      }
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
    } else if (ch === ".") {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out.map((seg) => unquoteSegment(seg.trim()));
}

function unquoteSegment(seg: string): string {
  if (seg.length >= 2 && seg.startsWith('"') && seg.endsWith('"')) {
    return unescapeBasic(seg.slice(1, -1));
  }
  if (seg.length >= 2 && seg.startsWith("'") && seg.endsWith("'")) {
    return seg.slice(1, -1);
  }
  return seg;
}

function unescapeBasic(s: string): string {
  return s.replace(/\\(u[0-9a-fA-F]{4}|.)/g, (_m, esc: string) => {
    if (esc.length === 5 && esc[0] === "u") return String.fromCharCode(parseInt(esc.slice(1), 16));
    switch (esc) {
      case "n":
        return "\n";
      case "t":
        return "\t";
      case "r":
        return "\r";
      case "b":
        return "\b";
      case "f":
        return "\f";
      case '"':
        return '"';
      case "\\":
        return "\\";
      default:
        return esc;
    }
  });
}

export function scanBlocks(lines: string[]): Block[] {
  const blocks: Block[] = [];
  let cur: Block = { table: null, start: 0, end: lines.length };
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*\[\[?([^\]]*)\]\]?\s*$/.exec(lines[i]);
    if (!m) continue;
    cur.end = i;
    blocks.push(cur);
    cur = { table: splitTablePath(m[1]), start: i, end: lines.length };
  }
  blocks.push(cur);
  return blocks;
}

export function stripComment(raw: string): string {
  let quote: string | null = null;
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      out += ch;
      if (ch === "\\" && quote === '"') {
        out += raw[++i] ?? "";
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === "#") break;
    out += ch;
  }
  return out;
}

function valueComplete(raw: string): boolean {
  const s = stripComment(raw);
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === "\\" && quote === '"') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "[" || ch === "{") depth++;
    else if (ch === "]" || ch === "}") depth--;
  }
  return depth <= 0 && !quote;
}

export function parseAssignments(lines: string[], block: Block): Assign[] {
  const out: Assign[] = [];
  let i = block.start + 1;
  while (i < block.end) {
    const m = /^\s*([A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*")\s*=\s*(.*)$/.exec(lines[i]);
    if (!m) {
      i++;
      continue;
    }
    const key = unquoteSegment(m[1]);
    let raw = m[2];
    let end = i;
    while (end + 1 < block.end && !valueComplete(raw)) {
      end++;
      raw += "\n" + lines[end];
    }
    out.push({ key, start: i, end: end + 1, valueRaw: raw });
    i = end + 1;
  }
  return out;
}

export function parseStringValue(raw: string): string | undefined {
  const s = stripComment(raw).trim();
  if (!s) return undefined;
  if (s.startsWith('"') && s.endsWith('"')) return unescapeBasic(s.slice(1, -1));
  if (s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1);
  return undefined;
}

function parseStringList(raw: string): string[] | undefined {
  const s = stripComment(raw).trim();
  if (!s) return undefined;
  if (!s.startsWith("[")) {
    const one = parseStringValue(s);
    return one === undefined ? undefined : [one];
  }
  const body = s.replace(/^\[/, "").replace(/\]$/, "");
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) out.push(m[1] !== undefined ? unescapeBasic(m[1]) : m[2]);
  return out;
}

function parseNumber(raw: string): number | undefined {
  const s = stripComment(raw).trim();
  if (!/^-?\d+(\.\d+)?$/.test(s)) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

function parseModelBlock(lines: string[], block: Block, key: string): ModelConfig & { extra: string } {
  const assigns = parseAssignments(lines, block);
  const managed = new Map<string, Assign>();
  const consumed = new Set<number>();
  for (const a of assigns) {
    if (!FIELD_SET.has(a.key)) continue;
    if (!managed.has(a.key)) managed.set(a.key, a);
    for (let i = a.start; i < a.end; i++) consumed.add(i);
  }

  const extra: string[] = [];
  for (let i = block.start + 1; i < block.end; i++) {
    if (!consumed.has(i)) extra.push(lines[i]);
  }
  while (extra.length && extra[0].trim() === "") extra.shift();
  while (extra.length && extra[extra.length - 1].trim() === "") extra.pop();

  const str = (field: Field): string | undefined => {
    const a = managed.get(field);
    return a ? parseStringValue(a.valueRaw) : undefined;
  };
  const num = (field: Field): number | undefined => {
    const a = managed.get(field);
    return a ? parseNumber(a.valueRaw) : undefined;
  };

  const envKey = managed.get("env_key");
  const envNames = envKey ? parseStringList(envKey.valueRaw) : undefined;

  return {
    key,
    model: str("model") ?? "",
    name: str("name"),
    description: str("description"),
    baseUrl: str("base_url"),
    apiKey: str("api_key"),
    envKey: envNames && envNames.length ? envNames.join(", ") : undefined,
    apiBackend: str("api_backend"),
    contextWindow: num("context_window"),
    temperature: num("temperature"),
    topP: num("top_p"),
    maxCompletionTokens: num("max_completion_tokens"),
    reasoningSummary: str("reasoning_summary"),
    extra: extra.join("\n"),
  };
}

function parseConfigText(text: string): ParsedConfig {
  const { lines, eol } = splitLines(text);
  const blocks = scanBlocks(lines);
  const models: (ModelConfig & { extra: string })[] = [];
  let defaultKey: string | undefined;

  for (const block of blocks) {
    if (!block.table) continue;
    if (block.table[0] === "models" && block.table.length === 1) {
      for (const a of parseAssignments(lines, block)) {
        if (a.key === "default") defaultKey = parseStringValue(a.valueRaw);
      }
      continue;
    }
    if (block.table[0] === "model" && block.table.length === 2) {
      models.push(parseModelBlock(lines, block, block.table[1]));
    }
  }

  return { models, defaultKey, lines, eol };
}

function blockOf(lines: string[], key: string): Block | undefined {
  return scanBlocks(lines).find(
    (b) => b.table && b.table.length === 2 && b.table[0] === "model" && b.table[1] === key,
  );
}

// ------------------------------------------------------------------ 写值

export function tomlString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code === 0x7f) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return out + '"';
}

export function formatKey(key: string): string {
  return /^[A-Za-z0-9_-]+$/.test(key) ? key : tomlString(key);
}

function fieldLine(field: Field, input: ModelConfigInput): string | undefined {
  const text = (v?: string): string | undefined => {
    const t = v?.trim();
    return t ? t : undefined;
  };
  const num = (v?: number): string | undefined => {
    if (v === undefined || v === null) return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? String(n) : undefined;
  };

  switch (field) {
    case "model": {
      const t = text(input.model);
      return t ? `model = ${tomlString(t)}` : undefined;
    }
    case "name": {
      const t = text(input.name);
      return t ? `name = ${tomlString(t)}` : undefined;
    }
    case "description": {
      const t = text(input.description);
      return t ? `description = ${tomlString(t)}` : undefined;
    }
    case "base_url": {
      const t = text(input.baseUrl);
      return t ? `base_url = ${tomlString(t.replace(/\/+$/, ""))}` : undefined;
    }
    case "api_key": {
      const t = text(input.apiKey);
      return t ? `api_key = ${tomlString(t)}` : undefined;
    }
    case "env_key": {
      const names = (input.envKey ?? "")
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (!names.length) return undefined;
      return names.length === 1
        ? `env_key = ${tomlString(names[0])}`
        : `env_key = [${names.map(tomlString).join(", ")}]`;
    }
    case "api_backend": {
      const t = text(input.apiBackend);
      return t ? `api_backend = ${tomlString(t)}` : undefined;
    }
    case "context_window": {
      const n = num(input.contextWindow);
      return n ? `context_window = ${n}` : undefined;
    }
    case "temperature": {
      const n = num(input.temperature);
      return n !== undefined ? `temperature = ${n}` : undefined;
    }
    case "top_p": {
      const n = num(input.topP);
      return n !== undefined ? `top_p = ${n}` : undefined;
    }
    case "max_completion_tokens": {
      const n = num(input.maxCompletionTokens);
      return n ? `max_completion_tokens = ${n}` : undefined;
    }
    case "reasoning_summary": {
      const t = text(input.reasoningSummary);
      return t ? `reasoning_summary = ${tomlString(t)}` : undefined;
    }
    default:
      return undefined;
  }
}

function extraLines(extra?: string): string[] {
  if (!extra) return [];
  const raw = extra.replace(/\r\n/g, "\n").split("\n");
  const out: string[] = [];
  for (const line of raw) {
    // 受管字段以表单为准，避免同一键写两遍
    const m = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
    if (m && FIELD_SET.has(m[1])) continue;
    out.push(line);
  }
  while (out.length && out[0].trim() === "") out.shift();
  while (out.length && out[out.length - 1].trim() === "") out.pop();
  return out;
}

function renderModelBlock(input: ModelConfigInput, extra?: string): string[] {
  const lines = [`[model.${formatKey(input.key.trim())}]`];
  for (const field of FIELD_ORDER) {
    const line = fieldLine(field, input);
    if (line) lines.push(line);
  }
  const tail = extraLines(extra);
  if (tail.length) {
    lines.push("");
    lines.push(...tail);
  }
  return lines;
}

function setDefault(lines: string[], key: string): string[] {
  const next = [...lines];
  const block = scanBlocks(next).find((b) => b.table && b.table[0] === "models" && b.table.length === 1);
  const line = `default = ${tomlString(key)}`;

  if (!block) {
    while (next.length && next[next.length - 1].trim() === "") next.pop();
    if (next.length) next.push("");
    next.push("[models]", line, "");
    return next;
  }

  const assigns = parseAssignments(next, block);
  const existing = assigns.find((a) => a.key === "default");
  if (existing) {
    next.splice(existing.start, existing.end - existing.start, line);
  } else {
    next.splice(block.start + 1, 0, line);
  }
  return next;
}

function removeDefault(lines: string[]): string[] {
  const next = [...lines];
  const block = scanBlocks(next).find((b) => b.table && b.table[0] === "models" && b.table.length === 1);
  if (!block) return next;
  const existing = parseAssignments(next, block).find((a) => a.key === "default");
  if (existing) next.splice(existing.start, existing.end - existing.start);
  return next;
}

function collapseBlanks(lines: string[]): string[] {
  const out: string[] = [];
  for (const line of lines) {
    if (line.trim() === "" && out.length && out[out.length - 1].trim() === "") continue;
    out.push(line);
  }
  while (out.length > 1 && out[out.length - 1].trim() === "" && out[out.length - 2].trim() === "") out.pop();
  return out;
}

/** 收尾：去掉尾部空行，保留一个换行结尾，和手写的 TOML 一致 */
export function finalize(lines: string[], eol: string): string {
  const out = collapseBlanks(lines);
  while (out.length && out[out.length - 1].trim() === "") out.pop();
  return out.length ? out.join(eol) + eol : "";
}

// ------------------------------------------------------------------ 读写

async function readText(file: string): Promise<string> {
  try {
    return await fsp.readFile(file, "utf8");
  } catch {
    return "";
  }
}

async function writeText(file: string, text: string): Promise<void> {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const previous = await readText(file);
  if (previous) {
    await fsp.writeFile(`${file}.tanwei.bak`, previous, "utf8");
  }
  await fsp.writeFile(file, text, "utf8");
}

/** [session] auto_compact_threshold_percent：引擎到这条线就会自动压缩一次 */
export async function readAutoCompactPercent(grokHome: string): Promise<number | undefined> {
  const text = await readText(configFile(grokHome));
  const { lines } = splitLines(text);
  const block = scanBlocks(lines).find(
    (b) => b.table != null && b.table.length === 1 && b.table[0] === "session",
  );
  if (!block) return undefined;
  const a = parseAssignments(lines, block).find((x) => x.key === "auto_compact_threshold_percent");
  if (!a) return undefined;
  const n = parseNumber(a.valueRaw);
  return n !== undefined && n > 0 && n <= 100 ? n : undefined;
}

export async function readModelsConfig(grokHome: string): Promise<ModelsConfig> {
  const file = configFile(grokHome);
  const parsed = parseConfigText(await readText(file));
  return {
    path: file,
    defaultKey: parsed.defaultKey,
    models: parsed.models.map((m) => ({ ...m, isDefault: m.key === parsed.defaultKey })),
  };
}

function validate(input: ModelConfigInput): void {
  const key = input.key?.trim() ?? "";
  if (!key) throw new Error("配置名不能为空");
  if (key.length > 64) throw new Error("配置名过长（最多 64 字符）");
  if (/["\\[\]]/.test(key) || /[\r\n]/.test(key)) {
    throw new Error("配置名不能包含引号、反斜杠或方括号");
  }
  const url = input.baseUrl?.trim();
  if (url && !/^https?:\/\/[^\s]+$/i.test(url)) {
    throw new Error("Base URL 需以 http:// 或 https:// 开头");
  }
  const backend = input.apiBackend?.trim();
  if (backend && !BACKENDS.includes(backend)) {
    throw new Error(`api_backend 只能是 ${BACKENDS.join(" / ")}`);
  }
  for (const [label, value] of [
    ["context_window", input.contextWindow],
    ["temperature", input.temperature],
    ["top_p", input.topP],
    ["max_completion_tokens", input.maxCompletionTokens],
  ] as const) {
    if (value === undefined || value === null) continue;
    const n = Number(value);
    if (!Number.isFinite(n) || n < 0) throw new Error(`${label} 需为非负数字`);
  }
  if (input.apiKey && /[\r\n]/.test(input.apiKey)) throw new Error("API Key 不能包含换行");
  for (const name of (input.envKey ?? "").split(/[,\s]+/).filter(Boolean)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`环境变量名不合法：${name}`);
  }
}

export async function saveModelConfig(grokHome: string, input: ModelConfigInput): Promise<void> {
  validate(input);
  const file = configFile(grokHome);
  const text = await readText(file);
  const parsed = parseConfigText(text);
  const key = input.key.trim();
  const renaming = Boolean(input.originalKey?.trim());
  const oldKey = input.originalKey?.trim() || key;
  const existing = parsed.models.find((m) => m.key === oldKey);

  if (renaming) {
    if (parsed.models.some((m) => m.key === key && m.key !== oldKey)) {
      throw new Error(`配置名 ${key} 已存在，请换一个名字`);
    }
  } else if (existing) {
    throw new Error(`配置名 ${key} 已存在，请换一个名字，或点该模型的「编辑」`);
  }
  const extra = input.extra !== undefined ? input.extra : existing?.extra;
  const blockLines = renderModelBlock(input, extra);

  let lines = [...parsed.lines];
  const block = existing ? blockOf(lines, oldKey) : undefined;
  if (block) {
    const after = lines.slice(block.end);
    const replacement = [...blockLines];
    if (after.some((l) => l.trim() !== "")) replacement.push("");
    lines = [...lines.slice(0, block.start), ...replacement, ...after];
  } else {
    while (lines.length && lines[lines.length - 1].trim() === "") lines.pop();
    if (lines.length) lines.push("");
    lines = [...lines, ...blockLines, ""];
  }

  if (input.makeDefault) lines = setDefault(lines, key);
  else if (parsed.defaultKey === oldKey && oldKey !== key) lines = setDefault(lines, key);

  await writeText(file, finalize(lines, parsed.eol));
}

export async function deleteModelConfig(grokHome: string, key: string): Promise<void> {
  const file = configFile(grokHome);
  const parsed = parseConfigText(await readText(file));
  let lines = [...parsed.lines];
  const block = blockOf(lines, key);
  if (!block) throw new Error(`没有找到模型配置：${key}`);

  lines = [...lines.slice(0, block.start), ...lines.slice(block.end)];
  const remaining = parseConfigText(lines.join(parsed.eol)).models;
  if (parsed.defaultKey === key) {
    lines = remaining.length ? setDefault(lines, remaining[0].key) : removeDefault(lines);
  }

  await writeText(file, finalize(lines, parsed.eol));
}

export async function setDefaultModel(grokHome: string, key: string): Promise<void> {
  const file = configFile(grokHome);
  const parsed = parseConfigText(await readText(file));
  if (!parsed.models.some((m) => m.key === key)) throw new Error(`没有找到模型配置：${key}`);
  const lines = setDefault(parsed.lines, key);
  await writeText(file, finalize(lines, parsed.eol));
}

// ------------------------------------------------------------------ 技能开关

function findSkillsBlock(lines: string[]): { start: number; end: number } | undefined {
  const start = lines.findIndex((l) => /^\s*\[skills\]\s*(#.*)?$/.test(l));
  if (start < 0) return undefined;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return { start, end };
}

function findDisabledSpan(
  lines: string[],
  block: { start: number; end: number },
): { start: number; end: number } | undefined {
  for (let i = block.start + 1; i < block.end; i++) {
    if (!/^\s*disabled\s*=/.test(lines[i])) continue;
    let j = i;
    while (j < block.end && !lines[j].includes("]")) j++;
    if (j >= block.end) j = i;
    return { start: i, end: j + 1 };
  }
  return undefined;
}

function parseSkillNames(text: string): string[] {
  const arr = /\[([\s\S]*?)\]/.exec(text)?.[1] ?? "";
  return [...arr.matchAll(/"((?:\\.|[^"\\])*)"|'([^']*)'/g)].map((m) =>
    m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2],
  );
}

/** 原来写成多行数组就继续写多行，别把用户的排版压扁。 */
function renderDisabled(names: string[], indent: string, multiline: boolean): string[] {
  if (!multiline) return [`${indent}disabled = [${names.map(tomlString).join(", ")}]`];
  const items = names.map((n) => `${indent}    ${tomlString(n)},`);
  return [`${indent}disabled = [`, ...items, `${indent}]`];
}

/**
 * 启用/禁用一个技能：写 `[skills] disabled = [...]`。
 * aliases 传技能目录名——grok 按名称或目录名匹配，两种写法都清掉才能真生效。
 */
export async function setSkillDisabled(
  grokHome: string,
  name: string,
  aliases: string[],
  disabled: boolean,
): Promise<void> {
  const primary = name.trim();
  if (!primary) throw new Error("技能名为空，无法切换");
  const keys = [...new Set([primary, ...aliases.map((a) => a.trim()).filter(Boolean)])];

  const file = configFile(grokHome);
  const { lines, eol } = splitLines(await readText(file));
  const block = findSkillsBlock(lines);
  const span = block ? findDisabledSpan(lines, block) : undefined;
  const current = span ? parseSkillNames(lines.slice(span.start, span.end).join("\n")) : [];

  const indent = span ? /^\s*/.exec(lines[span.start])![0] : "";
  const multiline = span ? span.end - span.start > 1 : false;
  let next: string[];
  if (disabled) {
    const merged = [...new Set([...current, ...keys])];
    const rendered = renderDisabled(merged, indent, multiline);
    if (span) {
      next = [...lines.slice(0, span.start), ...rendered, ...lines.slice(span.end)];
    } else if (block) {
      next = [...lines.slice(0, block.start + 1), ...rendered, ...lines.slice(block.start + 1)];
    } else {
      next = [...lines];
      while (next.length && next[next.length - 1].trim() === "") next.pop();
      if (next.length) next.push("");
      next.push("[skills]", ...rendered);
    }
  } else {
    const kept = current.filter((n) => !keys.includes(n));
    if (kept.length === current.length || !span) return;
    const rendered = renderDisabled(kept, indent, multiline);
    next = [...lines.slice(0, span.start), ...rendered, ...lines.slice(span.end)];
  }

  await writeText(file, finalize(next, eol));
}
