import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { TimelineItem, ToolCallView } from "../shared/types";
import { tasksFromToolCall } from "./sessionScope";

function sessionStoreRoot(): string {
  return path.join(process.env.GROK_HOME || path.join(os.homedir(), ".grok"), "sessions");
}

/** 会话里动过哪些任务夹：只看工具调用真实写/执行过的路径，读到或总结里提到的不算 */
export async function sessionTaskNames(sessionId: string, known: string[]): Promise<string[]> {
  const dir = await findSessionDir(sessionId);
  if (!dir) return [];
  const found = new Set<string>();
  const HEAD = 8_000_000;
  const TAIL = 2_000_000;
  let text = "";
  try {
    const buf = await fsp.readFile(path.join(dir, "chat_history.jsonl"));
    // 任务夹常在会话开头那段上下文里出现，尾部也可能有；两头都要看
    const head = buf.subarray(0, Math.min(buf.length, HEAD)).toString("utf8");
    const tail = buf.length > HEAD ? buf.subarray(Math.max(0, buf.length - TAIL)).toString("utf8") : "";
    text = head + "\n" + tail;
  } catch {
    return [];
  }
  for (const line of text.split("\n")) {
    if (!line.includes("_SRC挖洞")) continue;
    let row: any;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    // 新格式把工具调用放 tool_calls，旧格式是 content 里的 tool_use 块
    const calls: any[] = Array.isArray(row?.tool_calls)
      ? row.tool_calls
      : Array.isArray(row?.content)
        ? row.content.filter((c: any) => c && (c.type === "tool_use" || c.type === "tool_call"))
        : [];
    for (const call of calls) {
      const name = String(call?.name ?? call?.tool ?? "");
      const args = call?.arguments ?? call?.input ?? {};
      for (const task of tasksFromToolCall(name, args)) found.add(task);
    }
  }
  return [...found].filter((t) => known.includes(t));
}

export async function findSessionDir(sessionId: string): Promise<string | undefined> {
  const root = sessionStoreRoot();
  let dirs: fs.Dirent[] = [];
  try {
    dirs = await fsp.readdir(root, { withFileTypes: true });
  } catch {
    return undefined;
  }
  for (const d of dirs) {
    if (!d.isDirectory()) continue;
    const candidate = path.join(root, d.name, sessionId);
    try {
      const st = await fsp.stat(candidate);
      if (st.isDirectory()) return candidate;
    } catch {
      /* not here */
    }
  }
  return undefined;
}

/** 删掉磁盘上的会话目录；只允许删 sessions 根下面的那一层，找不到就当已删 */
export async function deleteSessionDir(sessionId: string): Promise<boolean> {
  const id = sessionId.trim();
  if (!id || /[\\/]/.test(id) || id === "." || id === "..") throw new Error("会话 id 不合法");
  const dir = await findSessionDir(id);
  if (!dir) return false;
  const root = sessionStoreRoot();
  const resolved = path.resolve(dir);
  if (!resolved.startsWith(path.resolve(root) + path.sep)) throw new Error("会话目录不在 sessions 根下，拒绝删除");
  // 引擎刚关闭会话时句柄可能还没完全释放，退避重试几次
  let lastErr: unknown;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      await fsp.rm(resolved, { recursive: true, force: true });
      return true;
    } catch (err) {
      lastErr = err;
      if ((err as NodeJS.ErrnoException)?.code !== "EPERM" && (err as NodeJS.ErrnoException)?.code !== "EBUSY") throw err;
      await new Promise((r) => setTimeout(r, 120 * (attempt + 1)));
    }
  }
  const code = (lastErr as NodeJS.ErrnoException)?.code;
  throw new Error(
    code === "EPERM" || code === "EBUSY"
      ? "会话文件正被其他进程占用（可能正在别处使用这个会话），请关闭后重试"
      : `删除会话目录失败：${(lastErr as Error)?.message ?? String(lastErr)}`,
  );
}

function userText(content: any): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b?.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("\n");
}

function cleanUserText(raw: string): string {
  const query = /<user_query>([\s\S]*?)<\/user_query>/.exec(raw);
  if (query) return query[1].trim();
  if (/<system-reminder>|<user_info>|<rules>/.test(raw) && !/<user_query>/.test(raw)) return "";
  return raw.trim();
}

/** Reads the small summary.json next to a session's history for its real title / model. */
export async function readSessionSummary(
  sessionId: string,
): Promise<{ title?: string; model?: string; updatedAt?: number } | null> {
  const dir = await findSessionDir(sessionId);
  if (!dir) return null;
  try {
    const raw = await fsp.readFile(path.join(dir, "summary.json"), "utf8");
    const data = JSON.parse(raw);
    const title = String(data?.generated_title || data?.session_summary || "").trim();
    const model = data?.current_model_id ? String(data.current_model_id) : undefined;
    const updatedAt = data?.updated_at ? Date.parse(data.updated_at) : undefined;
    return { title: title || undefined, model, updatedAt };
  } catch {
    return null;
  }
}

/**
 * Rebuilds a readable timeline from Grok's chat_history.jsonl.
 * Used as a fallback when session/load cannot replay (missing folder, old format).
 */
export async function readSessionHistory(sessionId: string): Promise<{
  timeline: TimelineItem[];
  title?: string;
  model?: string;
} | null> {
  const dir = await findSessionDir(sessionId);
  if (!dir) return null;
  const file = path.join(dir, "chat_history.jsonl");
  let raw = "";
  try {
    raw = await fsp.readFile(file, "utf8");
  } catch {
    return null;
  }
  const lines = raw.split(/\r?\n/).filter(Boolean).slice(-600);
  const timeline: TimelineItem[] = [];
  const toolItems = new Map<string, ToolCallView>();
  let seq = 0;
  let model: string | undefined;
  let title: string | undefined;

  for (const line of lines) {
    let row: any;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    const at = Date.now();
    if (row.type === "user") {
      const text = cleanUserText(userText(row.content));
      if (!text || text.length < 1) continue;
      timeline.push({
        type: "user",
        id: `h-user-${seq++}`,
        text: text.length > 12_000 ? text.slice(0, 12_000) + "\n…" : text,
        at,
      });
      if (!title) title = text.replace(/\s+/g, " ").slice(0, 60);
    } else if (row.type === "assistant") {
      if (row.model_id) model = row.model_id;
      const text = typeof row.content === "string" ? row.content.trim() : "";
      if (text) {
        timeline.push({
          type: "assistant",
          id: `h-asst-${seq++}`,
          text,
          at,
          model: row.model_id,
        });
      }
      const calls = Array.isArray(row.tool_calls) ? row.tool_calls : [];
      for (const call of calls) {
        let input: unknown = call.arguments;
        try {
          input = typeof call.arguments === "string" ? JSON.parse(call.arguments) : call.arguments;
        } catch {
          /* keep raw string */
        }
        const view: ToolCallView = {
          id: String(call.id ?? `${seq++}`),
          title: String(call.name ?? "tool"),
          kind: undefined,
          status: "completed",
          input,
          startedAt: at,
          endedAt: at,
        };
        toolItems.set(view.id, view);
        timeline.push({ type: "tool", id: `h-tool-${view.id}`, call: view, at });
      }
    } else if (row.type === "reasoning") {
      const summary = Array.isArray(row.summary)
        ? row.summary.map((s: any) => s?.text ?? "").join("\n\n")
        : "";
      if (summary.trim()) {
        timeline.push({
          type: "thought",
          id: `h-th-${seq++}`,
          text: summary.trim().slice(0, 20_000),
          at,
        });
      }
    } else if (row.type === "tool_result") {
      const call = toolItems.get(String(row.tool_call_id ?? ""));
      if (!call) continue;
      const out =
        typeof row.content === "string"
          ? row.content
          : Array.isArray(row.content)
            ? row.content.map((c: any) => c?.text ?? "").join("\n")
            : JSON.stringify(row.content);
      call.output = out.slice(0, 30_000);
    }
  }

  return { timeline, title, model };
}
