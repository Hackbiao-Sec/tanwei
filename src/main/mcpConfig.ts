import fsp from "node:fs/promises";
import path from "node:path";
import type { McpServerConfig, McpServerConfigInput, McpServersConfig } from "../shared/types";
import {
  configFile,
  finalize,
  formatKey,
  parseAssignments,
  parseStringValue,
  scanBlocks,
  splitLines,
  stripComment,
  tomlString,
  type Assign,
  type Block,
} from "./config";

/**
 * 按块编辑 ~/.grok/config.toml 的 [mcp_servers.<name>] / [mcp_servers.<name>.env]，
 * 其它表、注释、未受管字段（startup_timeout_sec 之类）原样保留。
 * 引擎只在启动时连 MCP，保存后要重启引擎才生效。
 */

const MANAGED = new Set(["command", "args", "cwd", "enabled"]);

async function readText(file: string): Promise<string> {
  try {
    return await fsp.readFile(file, "utf8");
  } catch {
    return "";
  }
}

function unquoteOrRaw(raw: string): string {
  const s = stripComment(raw).trim();
  const quoted = parseStringValue(s);
  if (quoted !== undefined) return quoted;
  if (s.startsWith("[") || s.startsWith("{")) return s;
  return s;
}

function parseStringArray(raw: string): string[] {
  const s = stripComment(raw).trim();
  if (!s.startsWith("[")) {
    const one = parseStringValue(s);
    return one === undefined ? [] : [one];
  }
  const body = s.slice(1, s.lastIndexOf("]"));
  const out: string[] = [];
  for (const m of body.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)) {
    out.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2]);
  }
  return out;
}

function parseBool(raw: string): boolean | undefined {
  const s = stripComment(raw).trim();
  if (s === "true") return true;
  if (s === "false") return false;
  return undefined;
}

function envOf(lines: string[], block: Block): Record<string, string> {
  const env: Record<string, string> = {};
  for (const a of parseAssignments(lines, block)) env[a.key] = unquoteOrRaw(a.valueRaw);
  return env;
}

function serverBlock(lines: string[], blocks: Block[], name: string): { base?: Block; env?: Block; ranges: Block[] } {
  const own = blocks.filter((b) => b.table && b.table[0] === "mcp_servers" && b.table[1] === name);
  return {
    base: own.find((b) => b.table!.length === 2),
    env: own.find((b) => b.table!.length === 3 && b.table![2] === "env"),
    ranges: own,
  };
}

export async function readMcpConfig(grokHome: string): Promise<McpServersConfig> {
  const file = configFile(grokHome);
  const { lines } = splitLines(await readText(file));
  const blocks = scanBlocks(lines);

  const names = new Set<string>();
  for (const b of blocks) {
    if (b.table && b.table[0] === "mcp_servers" && b.table[1]) names.add(b.table[1]);
  }

  const servers: McpServerConfig[] = [];
  for (const name of names) {
    const { base, env } = serverBlock(lines, blocks, name);
    if (!base) continue;
    const assigns = parseAssignments(lines, base);
    const byKey = new Map<string, Assign>();
    for (const a of assigns) if (!byKey.has(a.key)) byKey.set(a.key, a);

    const consumed = new Set<number>();
    for (const a of assigns) {
      if (!MANAGED.has(a.key)) continue;
      for (let i = a.start; i < a.end; i++) consumed.add(i);
    }
    const extra: string[] = [];
    for (let i = base.start + 1; i < base.end; i++) {
      if (!consumed.has(i)) extra.push(lines[i]);
    }
    while (extra.length && extra[0].trim() === "") extra.shift();
    while (extra.length && extra[extra.length - 1].trim() === "") extra.pop();

    const commandAssign = byKey.get("command");
    const argsAssign = byKey.get("args");
    const enabledAssign = byKey.get("enabled");
    const cwdAssign = byKey.get("cwd");

    servers.push({
      name,
      command: commandAssign ? (parseStringValue(commandAssign.valueRaw) ?? "") : "",
      args: argsAssign ? parseStringArray(argsAssign.valueRaw) : [],
      cwd: cwdAssign ? parseStringValue(cwdAssign.valueRaw) : undefined,
      enabled: enabledAssign ? parseBool(enabledAssign.valueRaw) : undefined,
      env: env ? envOf(lines, env) : {},
      extra: extra.join("\n"),
    });
  }

  servers.sort((a, b) => a.name.localeCompare(b.name));
  return { path: file, servers };
}

function validate(input: McpServerConfigInput): void {
  const name = input.name?.trim() ?? "";
  if (!name) throw new Error("服务名不能为空");
  if (name.length > 64) throw new Error("服务名过长（最多 64 字符）");
  if (/["'\\[\]]/.test(name) || /[\r\n.]/.test(name)) {
    throw new Error("服务名不能包含引号、反斜杠、方括号或点");
  }
  const command = input.command?.trim() ?? "";
  if (!command) throw new Error("启动命令不能为空");
  for (const [label, value] of [
    ["启动命令", command],
    ["工作目录", input.cwd ?? ""],
    ...input.args.map((a, i) => [`参数 ${i + 1}`, a] as const),
    ...Object.entries(input.env ?? {}).map(([k, v]) => [`环境变量 ${k}`, v] as const),
  ] as const) {
    if (/[\r\n]/.test(String(value))) throw new Error(`${label} 里不能有换行`);
  }
  for (const key of Object.keys(input.env ?? {})) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error(`环境变量名不合法：${key}`);
  }
}

function renderBlock(input: McpServerConfigInput): string[] {
  const name = formatKey(input.name.trim());
  const lines: string[] = [`[mcp_servers.${name}]`];
  lines.push(`command = ${tomlString(input.command.trim())}`);

  const args = input.args.map((a) => a.trim()).filter((a) => a.length > 0);
  const flat = `args = [${args.map(tomlString).join(", ")}]`;
  if (flat.length <= 100) lines.push(flat);
  else lines.push("args = [", ...args.map((a) => `    ${tomlString(a)},`), "]");

  const cwd = input.cwd?.trim();
  if (cwd) lines.push(`cwd = ${tomlString(cwd)}`);
  if (input.enabled !== undefined) lines.push(`enabled = ${input.enabled}`);

  const extra = (input.extra ?? "")
    .replace(/\r\n/g, "\n")
    .split("\n")
    .filter((line) => {
      const m = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
      return !(m && MANAGED.has(m[1]));
    });
  while (extra.length && extra[0].trim() === "") extra.shift();
  while (extra.length && extra[extra.length - 1].trim() === "") extra.pop();
  if (extra.length) {
    lines.push("");
    lines.push(...extra);
  }

  const envEntries = Object.entries(input.env ?? {}).filter(([k]) => k.trim());
  if (envEntries.length) {
    lines.push("", `[mcp_servers.${name}.env]`);
    for (const [k, v] of envEntries) lines.push(`${formatKey(k)} = ${tomlString(v ?? "")}`);
  }
  return lines;
}

export async function saveMcpServer(grokHome: string, input: McpServerConfigInput): Promise<void> {
  validate(input);
  const file = configFile(grokHome);
  const text = await readText(file);
  const { lines, eol } = splitLines(text);
  const parsed = { lines, eol };
  const name = input.name.trim();
  const oldName = input.originalName?.trim() || name;
  const blocks = scanBlocks(lines);

  if (oldName !== name && blocks.some((b) => b.table && b.table[0] === "mcp_servers" && b.table[1] === name)) {
    throw new Error(`服务名 ${name} 已存在，请换一个名字`);
  }

  const existing = serverBlock(lines, blocks, oldName);
  if (!existing.base && blocks.some((b) => b.table && b.table[0] === "mcp_servers" && b.table[1] === name)) {
    throw new Error(`服务名 ${name} 已存在，请换一个名字，或点该服务的「编辑」`);
  }
  const rendered = renderBlock({ ...input, name });
  let next: string[];

  if (existing.base) {
    const first = existing.ranges[0];
    const lastEnd = existing.ranges[existing.ranges.length - 1].end;
    // 中间若有别的表，说明这几个块不连续，逐个删再插到第一个位置
    const contiguous = existing.ranges.every((b, i) => i === 0 || b.start === existing.ranges[i - 1].end);
    if (contiguous) {
      const after = lines.slice(lastEnd);
      const replacement = [...rendered];
      if (after.some((l) => l.trim() !== "")) replacement.push("");
      next = [...lines.slice(0, first.start), ...replacement, ...after];
    } else {
      const keep: string[] = [];
      for (let i = 0; i < lines.length; ) {
        const hit = existing.ranges.find((b) => b.start === i);
        if (hit) {
          i = hit.end;
          continue;
        }
        keep.push(lines[i]);
        i++;
      }
      const insertAt = Math.min(first.start, keep.length);
      next = [...keep.slice(0, insertAt), ...rendered, "", ...keep.slice(insertAt)];
    }
  } else {
    next = [...lines];
    while (next.length && next[next.length - 1].trim() === "") next.pop();
    if (next.length) next.push("");
    next = [...next, ...rendered, ""];
  }

  await fsp.mkdir(require("node:path").dirname(file), { recursive: true });
  if (text) await fsp.writeFile(`${file}.tanwei.bak`, text, "utf8");
  await fsp.writeFile(file, finalize(next, parsed.eol), "utf8");
}

export async function deleteMcpServer(grokHome: string, name: string): Promise<void> {
  const file = configFile(grokHome);
  const text = await readText(file);
  const { lines, eol } = splitLines(text);
  const blocks = scanBlocks(lines);
  const { ranges } = serverBlock(lines, blocks, name.trim());
  if (!ranges.length) throw new Error(`没有找到 MCP 服务：${name}`);

  const next: string[] = [];
  for (let i = 0; i < lines.length; ) {
    const hit = ranges.find((b) => b.start === i);
    if (hit) {
      i = hit.end;
      continue;
    }
    next.push(lines[i]);
    i++;
  }

  if (text) await fsp.writeFile(`${file}.tanwei.bak`, text, "utf8");
  await fsp.writeFile(file, finalize(next, eol), "utf8");
}
