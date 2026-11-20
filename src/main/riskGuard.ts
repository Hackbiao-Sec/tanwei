/**
 * 风控 / 封禁特征识别。
 *
 * 只认「工具输出里真实出现的拦截形态」，不做裸数字匹配：
 * 单看一个 429 很可能是在读源码或日志，所以要求带 HTTP 状态行或明确的
 * 频控 / 验证 / 封禁文案。拿不准的一律不报，宁可漏一条也不刷屏。
 */

import type { RiskCategory, RiskSignal } from "../shared/types";

export type { RiskCategory, RiskSignal };

export interface RiskHit {
  category: RiskCategory;
  /** 命中的原文片段，已压成单行并截断 */
  evidence: string;
  /** 只用于日志与排序，不对外展示 */
  offset: number;
}

interface Rule {
  category: RiskCategory;
  re: RegExp;
}

/** 顺序即优先级：封禁 > 人机验证 > 限流 > WAF 拦截 */
const RULES: Rule[] = [
  {
    category: "封禁",
    re: /(?:IP|ip|IP\s*地址)\s*(?:已|被|已被)\s*(?:封禁|封停|拉黑|限制访问)|(?:账号|账户|account)\s*(?:已|被|已被)\s*(?:封禁|冻结|锁定)|your\s+(?:ip|account|access)\s+has\s+been\s+(?:blocked|banned|suspended|limited)|ip\s+(?:address\s+)?(?:has\s+been\s+)?banned/i,
  },
  {
    category: "人机验证",
    // 「安全验证」单独出现太常见（写报告、读文档都会提到），要么跟在「请…验证」里，要么带失败/页面字样
    re: /(?:人机验证|人机校验|行为验证|请(?:先)?(?:通过|完成|进行)?\s*(?:人机|安全)?验证|拖动滑块|滑动验证|滑块验证|安全验证(?:失败|未通过|超时|页|弹窗|组件)|initgeetest|static\.geetest\.com|gt\.js|g-recaptcha|recaptcha\.net|hcaptcha\.com|h-captcha|cf-turnstile|challenge-platform|cf-chl-)/i,
  },
  {
    category: "限流",
    re: /(?:HTTP\/[12](?:\.\d)?["'\s]+429\b|status(?:_?code)?["'\s:=]+429\b|429\s+too\s+many\s+requests|too\s+many\s+requests|请求(?:过于|太)频繁|访问(?:过于|太)频繁|操作(?:过于|太)频繁|请求频率(?:过高|超限)|访问频率(?:过高|超限)|rate[\s_-]?limit\s*(?:exceeded|reached))/i,
  },
  {
    category: "WAF 拦截",
    // 只认拦截页/拦截日志的形态，光出现 modsecurity、雷池 这类产品名多半是在读配置或文档
    re: /(?:您的?请求|该请求|本次请求|您的?访问|访问)\s*(?:已被?|被)\s*(?:安全策略)?\s*(?:拦截|阻断|拒绝)|(?:安全策略|Web\s*应用防火墙|网站防火墙)\s*(?:已)?\s*拦截|access\s+denied[\s\S]{0,200}reference\s*#|cf-error-details|modsecurity:\s*access\s+denied|naxsi[\s\S]{0,60}?blocked|(?:阿里云|腾讯|创宇|长信|长亭|安全狗|雷池|云锁|安恒|绿盟)[\s\S]{0,6}?(?:WAF|防火墙|盾)[\s\S]{0,6}?(?:拦截|阻断)/i,
  },
];

/** WAF 页面常见的「403 + 拦截关键词」，比裸 403 稳，又不至于把登录墙当封禁 */
const WAF_PAGE = /HTTP\/[12](?:\.\d)?["'\s]+403\b[\s\S]{0,600}?(?:拦截|禁止访问|access\s+denied|you\s+have\s+been\s+blocked)/i;

function flatten(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function snippet(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 80);
  const end = Math.min(text.length, index + length + 80);
  const cut = flatten(text.slice(start, end));
  return cut.length > 200 ? `${cut.slice(0, 200)}…` : cut;
}

/** 从一段工具输出里找拦截证据；没有就返回 undefined */
export function detectRisk(text: string): RiskHit | undefined {
  if (!text || text.length < 8) return undefined;
  const sample = text.length > 60_000 ? text.slice(-60_000) : text;
  for (const rule of RULES) {
    const m = rule.re.exec(sample);
    if (m) {
      return { category: rule.category, evidence: snippet(sample, m.index, m[0].length), offset: m.index };
    }
  }
  const waf = WAF_PAGE.exec(sample);
  if (waf) {
    return { category: "WAF 拦截", evidence: snippet(sample, waf.index, waf[0].length), offset: waf.index };
  }
  return undefined;
}

/** 从工具入参里捞一个像目标的地址，用于告警文案 */
export function targetFromInput(input: unknown): string | undefined {
  if (!input) return undefined;
  let text = "";
  try {
    text = typeof input === "string" ? input : JSON.stringify(input);
  } catch {
    return undefined;
  }
  if (!text) return undefined;
  const url = /https?:\/\/[^\s"'<>)\\]{4,200}/i.exec(text);
  if (url) return url[0].replace(/[),.;]+$/, "");
  const host = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{2,5})?\b/i.exec(text);
  return host ? host[0] : undefined;
}
