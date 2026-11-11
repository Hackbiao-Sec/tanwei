import { net, session } from "electron";
import fs from "node:fs";
import type { ProxyAiResult, ProxyImportStats, ProxyLocalPort } from "../shared/types";
import { readModelsConfig } from "./config";
import { grokHome } from "./system";
import { networkStatus } from "./proxy";
import { emptyStats, importProxyTokens, normalizeProxyUrl, type ParsedToken } from "./proxyPool";

/**
 * 陌生格式的兜底解析：本地解析器认不出来的代理配置，整份丢给已经配好的模型，
 * 让它只干一件事——把能当代理用的出口抽成 JSON。模型自己不能拨代理，
 * 所以这里只拿它的阅读理解，入库仍走 proxyPool 那套归一化和去重。
 */

const PARTITION = "tanwei-proxy-ai";
const NO_PROXY = "localhost,127.0.0.1,::1";
const TIMEOUT_MS = 120_000;
/** 太长的配置截断，留够节点区就行 */
const MAX_PROMPT_CHARS = 120_000;

const SYSTEM_PROMPT = [
  "你在帮一个安全测试工作台解析代理配置文件。",
  "文件可能是任何格式：Clash/mihomo YAML、sing-box JSON、base64 订阅、供应商自定义文本、CSV，甚至是表格粘贴。",
  "你只做一件事：把里面每一条能当代理出口用的地址找出来。",
  "",
  "只输出严格 JSON，不要 markdown 代码块，不要解释：",
  '{"proxies":[{"url":"scheme://[user:pass@]host:port","label":"节点名"}],',
  '"unsupported":[{"type":"ss","name":"节点名"}],',
  '"localPorts":[{"port":7890,"scheme":"http","key":"mixed-port"}],',
  '"note":"一句话说明你读到了什么、哪些用不了"}',
  "",
  "规则：",
  "1. scheme 只能是 http、https、socks4、socks5、socks5h。",
  "2. 只有真的带 host 和 port 的才写进 proxies；不要编造，不要写示例或占位地址。",
  "3. ss、vmess、vless、trojan、hysteria、hysteria2、tuic、snell、wireguard 这类要靠客户端转发的节点写进 unsupported，type 用节点类型名。",
  "4. 文件里声明的本机监听端口（mixed-port、socks-port、port、inbound listen）写进 localPorts。",
  "5. 一条可用出口都没有时 proxies 就给空数组。",
].join("\n");

interface Endpoint {
  base: string;
  key: string;
  model: string;
  label: string;
}

function trimBase(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, "");
}

function resolveKey(apiKey?: string, envKey?: string): string {
  const direct = apiKey?.trim();
  if (direct) return direct;
  for (const name of (envKey ?? "").split(/[,\s]+/).filter(Boolean)) {
    const value = process.env[name]?.trim();
    if (value) return value;
  }
  return "";
}

/** 用「模型」面板里那套配置，默认模型优先 */
async function pickEndpoint(): Promise<Endpoint> {
  const cfg = await readModelsConfig(grokHome());
  const usable = cfg.models.filter((m) => trimBase(m.baseUrl ?? "") && (m.model ?? "").trim());
  const picked = usable.find((m) => m.isDefault) ?? usable.find((m) => m.key === cfg.defaultKey) ?? usable[0];
  if (!picked) throw new Error("还没有可用的模型：先到「模型」里填 Base URL、模型 ID 和 API Key，AI 解析要用它");
  const key = resolveKey(picked.apiKey, picked.envKey);
  if (!key) throw new Error(`模型 ${picked.model} 没有读到 API Key，先在「模型」里补上`);
  return { base: trimBase(picked.baseUrl ?? ""), key, model: picked.model, label: picked.name ?? picked.key };
}

interface HttpResult {
  status: number;
  body: string;
  error?: string;
}

async function request(url: string, init: { method?: string; headers?: Record<string, string>; body?: string }): Promise<HttpResult> {
  const { effective } = await networkStatus();
  const ses = session.fromPartition(PARTITION);
  await ses
    .setProxy(effective ? { proxyRules: effective, proxyBypassRules: NO_PROXY } : { mode: "direct" })
    .catch(() => undefined);

  return new Promise<HttpResult>((resolve) => {
    let settled = false;
    const finish = (value: HttpResult) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    try {
      const req = net.request({ url, method: init.method ?? "GET", session: ses, useSessionCookies: false });
      for (const [key, value] of Object.entries(init.headers ?? {})) req.setHeader(key, value);
      req.on("response", (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        res.on("end", () => finish({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", (err: Error) => finish({ status: res.statusCode, body: "", error: err.message }));
      });
      req.on("error", (err: Error) => finish({ status: 0, body: "", error: err.message }));
      const timer = setTimeout(() => {
        req.abort();
        finish({ status: 0, body: "", error: `超时（${TIMEOUT_MS / 1000} 秒）` });
      }, TIMEOUT_MS);
      req.on("close", () => clearTimeout(timer));
      if (init.body) req.write(init.body);
      req.end();
    } catch (err) {
      finish({ status: 0, body: "", error: err instanceof Error ? err.message : String(err) });
    }
  });
}

/** 从模型回复里挖出 JSON：可能带代码块、前后废话 */
function extractJson(raw: string): Record<string, unknown> | undefined {
  const cleaned = raw
    .replace(/^```(?:json)?/gim, "")
    .replace(/```$/gim, "")
    .trim();
  const candidates = [cleaned];
  const first = cleaned.indexOf("{");
  const last = cleaned.lastIndexOf("}");
  if (first >= 0 && last > first) candidates.push(cleaned.slice(first, last + 1));
  for (const text of candidates) {
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      /* 换下一个候选 */
    }
  }
  return undefined;
}

function asList(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((v): v is Record<string, unknown> => !!v && typeof v === "object") : [];
}

function toStats(payload: Record<string, unknown>, note: string): { stats: ProxyImportStats; unsupported: number } {
  const stats = emptyStats("ai");
  const seen = new Set<string>();
  for (const item of asList(payload.proxies)) {
    const url = normalizeProxyUrl(String(item.url ?? ""));
    if (!url || seen.has(url)) continue;
    seen.add(url);
    const scheme = url.slice(0, url.indexOf("://"));
    stats.usable[scheme] = (stats.usable[scheme] ?? 0) + 1;
  }
  let unsupported = 0;
  for (const item of asList(payload.unsupported)) {
    const key = String(item.type ?? "unknown").trim().toLowerCase() || "unknown";
    stats.nodes[key] = (stats.nodes[key] ?? 0) + 1;
    unsupported += 1;
  }
  for (const item of asList(payload.localPorts)) {
    const port = Number(item.port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) continue;
    const scheme = String(item.scheme ?? "http").toLowerCase() === "socks5" ? "socks5" : "http";
    const key = String(item.key ?? "mixed-port");
    const entry: ProxyLocalPort = { port, scheme, key };
    if (!stats.localPorts.some((p) => p.port === port && p.scheme === scheme)) stats.localPorts.push(entry);
  }
  if (note) stats.notes.push(note);
  const dialable = Object.values(stats.usable).reduce((sum, n) => sum + n, 0);
  if (dialable) stats.notes.push(`${dialable} 个 HTTP/SOCKS 代理可以直接拨`);
  if (unsupported) {
    stats.notes.push(`${unsupported} 个 ${Object.keys(stats.nodes).join("/")} 节点需要本机客户端转发`);
  }
  return { stats, unsupported };
}

export interface AiParseInput {
  /** 文件绝对路径；和 text 二选一 */
  file?: string;
  text?: string;
}

export async function aiParseProxy(input: AiParseInput): Promise<ProxyAiResult> {
  const origin = input.file?.trim() || "";
  let body = input.text ?? "";
  if (origin) {
    const stat = fs.statSync(origin);
    if (stat.size > 8 * 1024 * 1024) throw new Error("配置文件超过 8 MB，AI 解析先裁一下再喂");
    body = fs.readFileSync(origin, "utf8");
  }
  body = body.replace(/^\uFEFF/, "");
  if (!body.trim()) throw new Error("内容为空，没有可解析的东西");
  const truncated = body.length > MAX_PROMPT_CHARS ? `${body.slice(0, MAX_PROMPT_CHARS)}\n…（后文截断）` : body;

  const endpoint = await pickEndpoint();
  const url = `${endpoint.base}/chat/completions`;
  const payload = {
    model: endpoint.model,
    temperature: 0,
    stream: false,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `配置文件内容如下（${origin || "粘贴"}）：\n\n${truncated}` },
    ],
  };

  const res = await request(url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${endpoint.key}`,
    },
    body: JSON.stringify(payload),
  });

  if (res.error) throw new Error(`调 ${endpoint.label} 失败：${res.error}`);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`${endpoint.label} 返回 ${res.status}：${res.body.slice(0, 240)}`);
  }

  let content = "";
  try {
    const parsed = JSON.parse(res.body) as { choices?: { message?: { content?: string } }[] };
    content = parsed.choices?.[0]?.message?.content ?? "";
  } catch {
    throw new Error(`${endpoint.label} 的回复不是 JSON：${res.body.slice(0, 200)}`);
  }
  if (!content.trim()) throw new Error(`${endpoint.label} 没有给出内容`);

  const json = extractJson(content);
  if (!json) {
    throw new Error(`模型没有按格式给 JSON，原始回复：${content.slice(0, 300)}`);
  }

  const { stats } = toStats(json, String(json.note ?? "").trim());
  const tokens: ParsedToken[] = [];
  const seen = new Set<string>();
  for (const item of asList(json.proxies)) {
    const normalized = normalizeProxyUrl(String(item.url ?? ""));
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    const label = String(item.label ?? item.name ?? "").trim();
    tokens.push({ url: normalized, label: label || undefined });
  }

  const result = importProxyTokens(tokens, origin || "paste", stats);
  return {
    ...result,
    model: endpoint.model,
    note: String(json.note ?? "").trim(),
  };
}
