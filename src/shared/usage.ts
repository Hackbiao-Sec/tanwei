import type { UsageStats } from "./types";

/**
 * 占窗口的用量：这一轮发出去的提示（输入 + 缓存读写）再加输出。
 * 引擎的 totalTokens 只算输入侧，缓存命中的部分不计，所以和分项之和对不上，取大者两边显示才一致。
 */
export function usedTokens(usage?: UsageStats): number {
  if (!usage) return 0;
  const prompt =
    (usage.inputTokens ?? 0) + (usage.cacheReadTokens ?? 0) + (usage.cacheWriteTokens ?? 0);
  return Math.max(usage.totalTokens ?? 0, prompt + (usage.outputTokens ?? 0));
}
