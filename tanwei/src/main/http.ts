import type { HttpRequestInput, HttpResponseView } from "../shared/types";

const MAX_BODY = 300_000;

function parseHeaders(text?: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of (text ?? "").split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    if (!name) continue;
    headers[name] = line.slice(idx + 1).trim();
  }
  return headers;
}

function errorView(started: number, message: string): HttpResponseView {
  return {
    ok: false,
    status: 0,
    statusText: "",
    headers: {},
    body: "",
    bodyBytes: 0,
    truncated: false,
    ms: Date.now() - started,
    finalUrl: "",
    error: message,
  };
}

/** 请求重放：给渗透工作台的 HTTP 面板用，输出原始状态/头/正文 */
export async function sendHttpRequest(input: HttpRequestInput): Promise<HttpResponseView> {
  const started = Date.now();
  const method = (input.method || "GET").toUpperCase();
  if (!/^https?:\/\//i.test(input.url || "")) {
    return errorView(started, "URL 需要以 http:// 或 https:// 开头");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(input.timeoutMs ?? 20_000, 120_000));
  try {
    const res = await fetch(input.url, {
      method,
      headers: parseHeaders(input.headers),
      body: method === "GET" || method === "HEAD" ? undefined : input.body || undefined,
      redirect: input.followRedirects === false ? "manual" : "follow",
      signal: controller.signal,
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = buf.toString("utf8");
    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      headers: Object.fromEntries(res.headers.entries()),
      body: text.slice(0, MAX_BODY),
      bodyBytes: buf.length,
      truncated: text.length > MAX_BODY,
      ms: Date.now() - started,
      finalUrl: res.url,
    };
  } catch (err) {
    const message =
      err instanceof Error
        ? err.name === "AbortError"
          ? "请求超时"
          : err.message
        : String(err);
    return errorView(started, message);
  } finally {
    clearTimeout(timer);
  }
}
