import type { SessionState } from "@shared/types";

/** 任务根目录的固定后缀；只认正常名字，避免把规则里的 `{任务}_SRC挖洞`、`[^/]+_SRC挖洞` 当成任务 */
const TASK_RE = /([A-Za-z0-9\u4e00-\u9fa5._-]{1,64}_SRC挖洞)/g;

/** 从一段文本（路径、命令、JSON 参数）里抠出任务名 */
export function collectTasks(text: string, into = new Set<string>()): Set<string> {
  if (!text) return into;
  for (const m of text.matchAll(TASK_RE)) into.add(m[1]);
  return into;
}

/**
 * 这个会话碰过哪些任务夹：先看 cwd，再看每次工具调用的标题 / 参数 / 命中文件。
 * 用来把「发现」「图谱」按会话隔离，同时保留「全部」总览。
 */
export function sessionTasks(state?: SessionState): string[] {
  const out = new Set<string>();
  if (!state) return [];
  collectTasks(state.cwd ?? "", out);
  for (const item of state.timeline) {
    if (item.type === "tool") {
      collectTasks(item.call.title ?? "", out);
      collectTasks(JSON.stringify(item.call.input ?? ""), out);
      for (const loc of item.call.locations ?? []) collectTasks(loc.path, out);
      collectTasks(item.call.output ?? "", out);
    }
  }
  return [...out];
}
