import { net, session } from "electron";
import type { ModelProbeInput, ModelProbeResult } from "../shared/types";
import { networkStatus } from "./proxy";

/**
 * 模型连通性探测：
 * - 默认 GET {baseUrl}/models，拿回该 key 能看到的模型列表（顺带给表单下拉用）
 * - chat=true 时再发一条最小对话（max_tokens=1），验证这个 model 真能出词
 * 走 Electron 的 net 和「设置 → 网络代理」里那套代理，机器需要 Clash 时也能通。
 */

const PARTITION = "tanwei-model-probe";
const NO_PROXY = "localhost,127.0.0.1,::1";
const TIMEOUT_MS = 20_000;

function trimBase(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, "");
}

function resolveKey(input: ModelProbeInput): string {
  const direct = input.apiKey?.trim();
  if (direct) return direct;
  const names = (input.envKey ?? "")
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (value) return value;
  }
  return "";
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

export async function probeModel(input: ModelProbeInput): Promise<ModelProbeResult> {
  const base = trimBase(input.baseUrl ?? "");
  if (!base) {
    return { ok: false, url: "", latencyMs: 0, error: "Base URL 为空，先把地址填上" };
  }
  const key = resolveKey(input);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (key) headers.Authorization = `Bearer ${key}`;

  const modelsUrl = `${base}/models`;
  const started = Date.now();
  const res = await request(modelsUrl, { headers });

  if (res.error) {
    return { ok: false, url: modelsUrl, latencyMs: Date.now() - started, error: res.error };
  }
  if (res.status < 200 || res.status >= 300) {
    return {
      ok: false,
      url: modelsUrl,
      status: res.status,
      latencyMs: Date.now() - started,
      error: `${res.status}: ${res.body.slice(0, 200)}`,
    };
  }

  let models: string[] | undefined;
  try {
    const parsed = JSON.parse(res.body) as { data?: { id?: string }[]; models?: { name?: string }[] };
    if (Array.isArray(parsed.data)) models = parsed.data.map((m) => String(m.id ?? "")).filter(Boolean);
    else if (Array.isArray(parsed.models)) models = parsed.models.map((m) => String(m.name ?? "")).filter(Boolean);
  } catch {
    return {
      ok: false,
      url: modelsUrl,
      status: res.status,
      latencyMs: Date.now() - started,
      error: `/models 返回的不是 JSON：${res.body.slice(0, 160)}`,
    };
  }

  if (!input.chat) {
    return { ok: true, url: modelsUrl, status: res.status, latencyMs: Date.now() - started, models };
  }

  const model = (input.model ?? "").trim();
  if (!model) {
    return {
      ok: false,
      url: modelsUrl,
      status: res.status,
      latencyMs: Date.now() - started,
      models,
      error: "没有填模型 ID，没法发对话请求",
    };
  }

  const chatUrl = `${base}/chat/completions`;
  const chatStarted = Date.now();
  const chat = await request(chatUrl, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "ping" }],
      max_tokens: 1,
      stream: false,
    }),
  });
  const elapsed = Date.now() - chatStarted;

  if (chat.error) {
    return { ok: false, url: chatUrl, latencyMs: elapsed, models, error: chat.error };
  }
  if (chat.status < 200 || chat.status >= 300) {
    return {
      ok: false,
      url: chatUrl,
      status: chat.status,
      latencyMs: elapsed,
      models,
      error: `${chat.status}: ${chat.body.slice(0, 240)}`,
    };
  }

  let reply = "";
  try {
    const parsed = JSON.parse(chat.body) as { choices?: { message?: { content?: string } }[] };
    reply = parsed.choices?.[0]?.message?.content ?? "";
  } catch {
    reply = chat.body.slice(0, 120);
  }
  return { ok: true, url: chatUrl, status: chat.status, latencyMs: elapsed, models, reply };
}
