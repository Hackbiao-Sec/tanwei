import net from "node:net";
import tls from "node:tls";
import http2 from "node:http2";
import zlib from "node:zlib";
import { TextDecoder } from "node:util";
import type { RawHeaderPair, RawHttpInput, RawHttpResult, RawTlsInfo } from "../shared/types";
import { networkStatus } from "./proxy";

/**
 * 按 Yakit 数据包重放的用法发原始报文：
 * - 头顺序 / 重复头 / 大小写原样保留（fetch 会吃掉这些，所以不能用 fetch）
 * - 支持 HTTP/1.1 与 HTTP/2（ALPN h2）
 * - 支持跳过证书校验、上游 HTTP / SOCKS5 代理、跟随重定向
 * - 响应按原始字节收，做 chunked 解包、gzip/br/deflate 解压、charset 解码
 */

const MAX_BODY_BYTES = 1_500_000;
const MAX_REDIRECTS = 6;
const DEFAULT_TIMEOUT = 30_000;
const MAX_HEAD_BYTES = 256 * 1024;

type ParsedRequest = {
  method: string;
  target: string;
  version: string;
  headers: RawHeaderPair[];
  body: string;
};

function splitMessage(text: string): { head: string; body: string } {
  const normalized = text.replace(/\r\n/g, "\n");
  const idx = normalized.indexOf("\n\n");
  if (idx < 0) return { head: normalized, body: "" };
  return { head: normalized.slice(0, idx), body: normalized.slice(idx + 2) };
}

function parseHeaderLine(line: string): RawHeaderPair | undefined {
  const trimmed = line.replace(/\n$/, "");
  if (!trimmed.trim()) return undefined;
  // HTTP/2 伪头（:method 之类）名字本身带冒号
  const start = trimmed.startsWith(":") ? 1 : 0;
  const idx = trimmed.indexOf(":", start);
  if (idx <= 0) return undefined;
  const name = trimmed.slice(0, idx).trim();
  if (!name || /\s/.test(name)) return undefined;
  return { name, value: trimmed.slice(idx + 1).trim() };
}

export function parseRawRequest(text: string): ParsedRequest | undefined {
  const { head, body } = splitMessage(text);
  const lines = head.split("\n");
  const first = (lines.shift() ?? "").trim();
  if (!first) return undefined;
  const match = /^([A-Za-z!#$%&'*+.^_`|~-]+)\s+(\S+?)(?:\s+(HTTP\/[\d.]+))?$/.exec(first);
  if (!match) return undefined;
  const headers: RawHeaderPair[] = [];
  for (const line of lines) {
    const pair = parseHeaderLine(line);
    if (pair) headers.push(pair);
  }
  return {
    method: match[1].toUpperCase(),
    target: match[2],
    version: match[3] ?? "HTTP/1.1",
    headers,
    body,
  };
}

function headerValue(headers: RawHeaderPair[], name: string): string | undefined {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value).pop();
}

function headerIndex(headers: RawHeaderPair[], name: string): number {
  const lower = name.toLowerCase();
  return headers.findIndex((h) => h.name.toLowerCase() === lower);
}

function withoutHeader(headers: RawHeaderPair[], names: string[]): RawHeaderPair[] {
  const drop = new Set(names.map((n) => n.toLowerCase()));
  return headers.filter((h) => !drop.has(h.name.toLowerCase()));
}

function hasHeader(headers: RawHeaderPair[], name: string): boolean {
  return headerIndex(headers, name) >= 0;
}

function resolveUrl(parsed: ParsedRequest, fallbackUrl?: string): URL | undefined {
  if (/^https?:\/\//i.test(parsed.target)) {
    try {
      return new URL(parsed.target);
    } catch {
      return undefined;
    }
  }
  if (fallbackUrl && /^https?:\/\//i.test(fallbackUrl)) {
    try {
      return new URL(parsed.target, fallbackUrl);
    } catch {
      return undefined;
    }
  }
  const host = headerValue(parsed.headers, "host");
  if (host) {
    const scheme = parsed.target.startsWith("//") ? "https" : "http";
    try {
      return new URL(`${scheme}://${host}${parsed.target.startsWith("/") ? "" : "/"}${parsed.target}`);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function originForm(url: URL): string {
  return `${url.pathname || "/"}${url.search}`;
}

/** 组装真正写进 socket 的字节；缺 Host / Content-Length 时补上，其余一律照抄 */
function buildHttp1(
  parsed: ParsedRequest,
  url: URL,
  forward?: { absolute?: boolean; proxyAuth?: string },
): { text: string; buf: Buffer } {
  const bodyBytes = Buffer.byteLength(parsed.body, "utf8");
  let headers = parsed.headers.filter((h) => !h.name.startsWith(":"));
  const hostName = url.host;
  if (!hasHeader(headers, "host")) {
    headers = [{ name: "Host", value: hostName }, ...headers];
  }
  const isPlain = parsed.method === "GET" || parsed.method === "HEAD";
  if (bodyBytes > 0 && !hasHeader(headers, "content-length") && !hasHeader(headers, "transfer-encoding")) {
    headers = [...headers, { name: "Content-Length", value: String(bodyBytes) }];
  }
  if (bodyBytes === 0 && !isPlain && !hasHeader(headers, "content-length") && !hasHeader(headers, "transfer-encoding")) {
    // POST 空体也按 Yakit 的行为补 0，免得服务端读不到边界
    headers = [...headers, { name: "Content-Length", value: "0" }];
  }
  if (forward?.proxyAuth && !hasHeader(headers, "proxy-authorization")) {
    headers = [...headers, { name: "Proxy-Authorization", value: forward.proxyAuth }];
  }
  // 明文 HTTP 走上游 HTTP 代理时用绝对形式，和 Yakit（Go 传输层）发出去的一致
  const target = forward?.absolute ? url.toString() : originForm(url);
  const headLines = [`${parsed.method} ${target} HTTP/1.1`];
  for (const h of headers) headLines.push(`${h.name}: ${h.value}`);
  const text = `${headLines.join("\r\n")}\r\n\r\n${parsed.body}`;
  return { text, buf: Buffer.from(text, "utf8") };
}

const H2_FORBIDDEN = [
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
  "http2-settings",
  "host",
  "expect",
];

function buildH2Headers(parsed: ParsedRequest, url: URL): RawHeaderPair[] {
  const authority = headerValue(parsed.headers, "host") || url.host;
  const headers: RawHeaderPair[] = [
    { name: ":method", value: parsed.method },
    { name: ":scheme", value: url.protocol.replace(":", "") },
    { name: ":authority", value: authority },
    { name: ":path", value: originForm(url) },
  ];
  let rest = parsed.headers.filter((h) => !h.name.startsWith(":"));
  rest = withoutHeader(rest, H2_FORBIDDEN);
  const bodyBytes = Buffer.byteLength(parsed.body, "utf8");
  if (bodyBytes > 0 && !hasHeader(rest, "content-length")) {
    rest = [...rest, { name: "content-length", value: String(bodyBytes) }];
  }
  const te = headerValue(rest, "te");
  if (te && te.toLowerCase() !== "trailers") rest = withoutHeader(rest, ["te"]);
  return [...headers, ...rest];
}

function rebuildResponseRaw(version: string, status: number, statusText: string, headers: RawHeaderPair[], body: Buffer): string {
  const lines = [version === "2" ? `HTTP/2 ${status}${statusText ? ` ${statusText}` : ""}` : `HTTP/1.1 ${status} ${statusText}`];
  for (const h of headers) lines.push(`${h.name}: ${h.value}`);
  return `${lines.join("\r\n")}\r\n\r\n${body.toString("utf8")}`;
}

type SocketOptions = {
  skipTlsVerify: boolean;
  proxy?: string;
  timeoutMs: number;
};

type OpenedSocket = {
  socket: net.Socket;
  tlsInfo?: RawTlsInfo;
  remote?: string;
  proxy?: string;
  /** 明文 HTTP 经 HTTP 代理转发：请求行用绝对 URI */
  absolute?: boolean;
  proxyAuth?: string;
};

function parseProxyUrl(proxyUrl: string): URL | undefined {
  try {
    return new URL(proxyUrl);
  } catch {
    return undefined;
  }
}

function proxyAuthOf(proxy: URL): string | undefined {
  if (!proxy.username) return undefined;
  const raw = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
  return `Basic ${Buffer.from(raw, "utf8").toString("base64")}`;
}

/** 明文 HTTP + HTTP 代理 → 绝对形式；HTTPS 目标仍走 CONNECT 隧道 */
function forwardAbsolute(url: URL, proxyUrl?: string): boolean {
  if (url.protocol !== "http:" || !proxyUrl) return false;
  return parseProxyUrl(proxyUrl)?.protocol === "http:";
}

function connectTcp(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`连接 ${host}:${port} 超时`));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.setNoDelay(true);
      resolve(socket);
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function readUntilHead(socket: net.Socket, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const done = (fn: () => void) => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new Error("代理握手超时"))), timeoutMs);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > MAX_HEAD_BYTES) done(() => reject(new Error("代理握手响应过大")));
      else if (buf.includes("\r\n\r\n")) done(() => resolve(buf));
    };
    const onError = (err: Error) => done(() => reject(err));
    const onClose = () => done(() => reject(new Error("代理提前断开连接")));
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
    socket.resume();
  });
}

async function socks5Connect(socket: net.Socket, host: string, port: number, proxy: URL, timeoutMs: number): Promise<void> {
  const user = decodeURIComponent(proxy.username || "");
  const pass = decodeURIComponent(proxy.password || "");
  const methods = user || pass ? [0x00, 0x02] : [0x00];
  socket.write(Buffer.from([0x05, methods.length, ...methods]));
  const hello = await readExact(socket, 2, timeoutMs);
  if (hello[0] !== 0x05 || hello[1] === 0xff) throw new Error("SOCKS5 代理拒绝匿名连接");
  if (hello[1] === 0x02) {
    const u = Buffer.from(user, "utf8");
    const p = Buffer.from(pass, "utf8");
    socket.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
    const auth = await readExact(socket, 2, timeoutMs);
    if (auth[1] !== 0x00) throw new Error("SOCKS5 用户名密码被拒绝");
  }
  const hostBuf = Buffer.from(host, "utf8");
  socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]), hostBuf, Buffer.from([port >> 8, port & 0xff])]));
  const reply = await readExact(socket, 4, timeoutMs);
  if (reply[1] !== 0x00) throw new Error(`SOCKS5 连接被拒（code ${reply[1]}）`);
  const atyp = reply[3];
  if (atyp === 0x01) {
    await readExact(socket, 6, timeoutMs);
  } else if (atyp === 0x04) {
    await readExact(socket, 18, timeoutMs);
  } else {
    const len = (await readExact(socket, 1, timeoutMs))[0];
    await readExact(socket, len + 2, timeoutMs);
  }
}

/**
 * 读取定长字节。用 readable + read() 的暂停模式：flushing 模式下两次读取之间
 * 同包剩余字节会被丢弃，SOCKS5 握手会因此超时。
 */
function readExact(socket: net.Socket, size: number, timeoutMs = 15_000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf: Buffer = Buffer.alloc(0);
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener("readable", onReadable);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      fn();
    };
    const timer = setTimeout(() => finish(() => reject(new Error("SOCKS5 响应超时"))), timeoutMs);
    const onError = (err: Error) => finish(() => reject(err));
    const onClose = () => finish(() => reject(new Error("SOCKS5 连接提前断开")));
    const onReadable = () => {
      for (;;) {
        const chunk = socket.read() as Buffer | null;
        if (!chunk) break;
        buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
        if (buf.length >= size) {
          const head = buf.subarray(0, size);
          const rest = buf.subarray(size);
          finish(() => {
            if (rest.length) {
              socket.pause();
              socket.unshift(rest);
            }
            resolve(Buffer.from(head));
          });
          return;
        }
      }
    };
    socket.on("readable", onReadable);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

async function connectViaProxy(proxyUrl: string, host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  let proxy: URL;
  try {
    proxy = new URL(proxyUrl);
  } catch {
    throw new Error(`代理地址不可用：${proxyUrl}`);
  }
  const proxyHost = proxy.hostname;
  const proxyPort = Number(proxy.port) || (proxy.protocol === "https:" ? 443 : 1080);
  const socket = await connectTcp(proxyHost, proxyPort, timeoutMs);
  if (proxy.protocol.startsWith("socks")) {
    await socks5Connect(socket, host, port, proxy, timeoutMs);
    return socket;
  }
  const auth = proxy.username
    ? `Proxy-Authorization: Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}\r\n`
    : "";
  socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}Proxy-Connection: keep-alive\r\n\r\n`);
  const head = await readUntilHead(socket, timeoutMs);
  const line = head.toString("latin1").split("\r\n")[0] ?? "";
  const code = Number(/^HTTP\/\d\.\d\s+(\d{3})/.exec(line)?.[1] ?? 0);
  if (code !== 200) {
    socket.destroy();
    throw new Error(`代理 CONNECT 失败：${line || "无响应"}`);
  }
  return socket;
}

function firstText(value: string | string[] | undefined): string | undefined {
  const text = Array.isArray(value) ? value[0] : value;
  return text ? String(text) : undefined;
}

function tlsInfoOf(socket: tls.TLSSocket): RawTlsInfo {
  const info: RawTlsInfo = {
    protocol: socket.getProtocol() ?? undefined,
    cipher: socket.getCipher()?.name,
    alpn: socket.alpnProtocol || undefined,
    authorized: socket.authorized,
  };
  try {
    const cert = socket.getPeerCertificate(false);
    if (cert && Object.keys(cert).length) {
      info.subject = firstText(cert.subject?.CN) || firstText(cert.subjectaltname);
      info.issuer = firstText(cert.issuer?.CN) || firstText(cert.issuer?.O);
      info.validTo = cert.valid_to;
    }
  } catch {
    /* 自签证书拿不到详情就算了 */
  }
  return info;
}

async function openSocket(url: URL, opts: SocketOptions, alpn: string[], tunnelOnly = false): Promise<OpenedSocket> {
  const port = Number(url.port) || (url.protocol === "https:" ? 443 : 80);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  let base: net.Socket;
  let via: string | undefined;
  const absolute = !tunnelOnly && forwardAbsolute(url, opts.proxy);
  let proxyAuth: string | undefined;
  if (opts.proxy && absolute) {
    // 明文 HTTP 经 HTTP 代理：直接连代理，用绝对形式转发（和 Yakit / Go 传输层一致）
    const proxy = parseProxyUrl(opts.proxy) as URL;
    base = await connectTcp(proxy.hostname, Number(proxy.port) || 80, opts.timeoutMs);
    via = opts.proxy;
    proxyAuth = proxyAuthOf(proxy);
  } else if (opts.proxy) {
    base = await connectViaProxy(opts.proxy, host, port, opts.timeoutMs);
    via = opts.proxy;
  } else {
    base = await connectTcp(host, port, opts.timeoutMs);
  }
  const opened: OpenedSocket = {
    socket: base,
    remote: `${base.remoteAddress ?? host}:${base.remotePort ?? port}`,
    proxy: via,
    absolute,
    proxyAuth,
  };
  if (url.protocol === "https:") {
    const secured = await new Promise<tls.TLSSocket>((resolve, reject) => {
      const socket = tls.connect({
        socket: base,
        servername: net.isIP(host) ? undefined : host,
        ALPNProtocols: alpn,
        rejectUnauthorized: !opts.skipTlsVerify,
      });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error("TLS 握手超时"));
      }, opts.timeoutMs);
      socket.once("secureConnect", () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    opened.socket = secured;
    opened.tlsInfo = tlsInfoOf(secured);
  }
  return opened;
}

function decodeChunked(buf: Buffer): { done: boolean; body: Buffer } {
  const parts: Buffer[] = [];
  let pos = 0;
  for (;;) {
    const lineEnd = buf.indexOf("\r\n", pos);
    if (lineEnd < 0) return { done: false, body: Buffer.alloc(0) };
    const size = parseInt(buf.subarray(pos, lineEnd).toString("latin1").split(";")[0] || "0", 16);
    if (!Number.isFinite(size)) return { done: false, body: Buffer.alloc(0) };
    if (size === 0) {
      const trailerEnd = buf.indexOf("\r\n\r\n", lineEnd);
      // 0\r\n\r\n 里只剩一个 CRLF 时也算结束
      if (trailerEnd < 0 && buf.length < lineEnd + 4) return { done: false, body: Buffer.alloc(0) };
      return { done: true, body: Buffer.concat(parts) };
    }
    const start = lineEnd + 2;
    if (buf.length < start + size + 2) return { done: false, body: Buffer.alloc(0) };
    parts.push(buf.subarray(start, start + size));
    pos = start + size + 2;
  }
}

type Http1Raw = {
  status: number;
  statusText: string;
  headers: RawHeaderPair[];
  body: Buffer;
  chunked: boolean;
  headEnd: number;
};

function tryParseHttp1(buf: Buffer, method: string): { needMore: boolean; message?: Http1Raw; skip?: number } {
  const headEnd = buf.indexOf("\r\n\r\n");
  if (headEnd < 0) {
    if (buf.length > MAX_HEAD_BYTES) throw new Error("响应头过大");
    return { needMore: true };
  }
  const headText = buf.subarray(0, headEnd).toString("latin1");
  const lines = headText.split("\r\n");
  const statusLine = lines.shift() ?? "";
  const match = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$/.exec(statusLine);
  if (!match) throw new Error(`响应不是合法 HTTP 报文：${statusLine.slice(0, 80)}`);
  const status = Number(match[2]);
  const statusText = match[3] ?? "";
  const headers: RawHeaderPair[] = [];
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx > 0) headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
  }
  const headBytes = headEnd + 4;
  if (status >= 100 && status < 200 && status !== 101) {
    return { needMore: false, skip: headBytes };
  }
  const chunked = (headerValue(headers, "transfer-encoding") ?? "").toLowerCase().includes("chunked");
  if (method === "HEAD" || status === 204 || status === 304) {
    return {
      needMore: false,
      message: { status, statusText, headers, body: Buffer.alloc(0), chunked, headEnd },
    };
  }
  if (chunked) {
    const decoded = decodeChunked(buf.subarray(headBytes));
    if (!decoded.done) return { needMore: true };
    return {
      needMore: false,
      message: { status, statusText, headers, body: decoded.body, chunked, headEnd },
    };
  }
  const lengthHeader = headerValue(headers, "content-length");
  if (lengthHeader !== undefined) {
    const length = Number(lengthHeader);
    if (Number.isFinite(length)) {
      if (buf.length < headBytes + length) return { needMore: true };
      return {
        needMore: false,
        message: {
          status,
          statusText,
          headers,
          body: buf.subarray(headBytes, headBytes + length),
          chunked,
          headEnd,
        },
      };
    }
  }
  return {
    needMore: false,
    message: { status, statusText, headers, body: buf.subarray(headBytes), chunked, headEnd },
  };
}

function readHttp1(socket: net.Socket, method: string, timeoutMs: number): Promise<Http1Raw> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("end", onEnd);
      socket.removeListener("close", onClose);
      socket.removeListener("error", onError);
    };
    const finish = (err?: Error, value?: Http1Raw) => {
      cleanup();
      if (err) reject(err);
      else if (value) resolve(value);
    };
    const timer = setTimeout(() => finish(new Error("读取响应超时")), timeoutMs);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      try {
        let cursor = 0;
        for (;;) {
          const parsed = tryParseHttp1(buf.subarray(cursor), method);
          if (parsed.needMore) return;
          if (parsed.skip) {
            cursor += parsed.skip;
            continue;
          }
          if (parsed.message) {
            finish(undefined, parsed.message);
            return;
          }
          return;
        }
      } catch (err) {
        finish(err as Error);
      }
    };
    const onEnd = () => {
      try {
        const parsed = tryParseHttp1(buf, method);
        if (parsed.message) finish(undefined, parsed.message);
        else finish(new Error("连接已关闭，响应不完整"));
      } catch (err) {
        finish(err as Error);
      }
    };
    const onClose = () => {
      if (buf.length === 0) finish(new Error("连接被远端关闭，没有响应"));
    };
    const onError = (err: Error) => finish(err);
    socket.on("data", onData);
    socket.on("end", onEnd);
    socket.on("close", onClose);
    socket.on("error", onError);
    socket.resume();
  });
}

function decompress(body: Buffer, encoding: string): { body: Buffer; decompressed: boolean } {
  const value = encoding.toLowerCase();
  if (!value || value === "identity") return { body, decompressed: false };
  try {
    if (value.includes("br")) return { body: zlib.brotliDecompressSync(body), decompressed: true };
    if (value.includes("gzip")) return { body: zlib.gunzipSync(body), decompressed: true };
    if (value.includes("deflate")) return { body: zlib.inflateSync(body), decompressed: true };
  } catch {
    try {
      return { body: zlib.inflateRawSync(body), decompressed: true };
    } catch {
      return { body, decompressed: false };
    }
  }
  return { body, decompressed: false };
}

function isBinaryType(contentType: string): boolean {
  const type = contentType.toLowerCase();
  return (
    /^(image|audio|video|font)\//.test(type) ||
    /octet-stream|application\/(zip|pdf|gzip|x-|vnd\.|protobuf|wasm)/.test(type)
  );
}

function charsetOf(contentType: string): string {
  const match = /charset=["']?([\w-]+)/i.exec(contentType);
  return (match?.[1] ?? "utf-8").toLowerCase();
}

function decodeText(body: Buffer, contentType: string): { text: string; binary: boolean } {
  if (!body.length) return { text: "", binary: false };
  const binary = isBinaryType(contentType);
  try {
    const decoder = new TextDecoder(charsetOf(contentType), { fatal: false });
    return { text: decoder.decode(body), binary };
  } catch {
    return { text: body.toString("utf8"), binary };
  }
}

function errorResult(started: number, message: string, extra?: Partial<RawHttpResult>): RawHttpResult {
  return {
    ok: false,
    status: 0,
    statusText: "",
    httpVersion: "",
    headers: [],
    body: "",
    bodyBase64: "",
    bodyBytes: 0,
    wireBytes: 0,
    truncated: false,
    decompressed: false,
    binary: false,
    ms: Date.now() - started,
    finalUrl: extra?.finalUrl ?? "",
    requestRaw: extra?.requestRaw ?? "",
    responseRaw: "",
    tls: extra?.tls,
    remote: extra?.remote,
    proxy: extra?.proxy,
    redirects: extra?.redirects ?? [],
    error: message,
  };
}

async function sendHttp1(
  parsed: ParsedRequest,
  url: URL,
  opts: SocketOptions,
): Promise<RawHttpResult> {
  const started = Date.now();
  const opened = await openSocket(url, opts, ["http/1.1"]);
  const { text, buf } = buildHttp1(parsed, url, {
    absolute: opened.absolute,
    proxyAuth: opened.proxyAuth,
  });
  try {
    opened.socket.write(buf);
    const raw = await readHttp1(opened.socket, parsed.method, opts.timeoutMs);
    const wire = raw.body;
    const decoded = decompress(wire, headerValue(raw.headers, "content-encoding") ?? "");
    const contentType = headerValue(raw.headers, "content-type") ?? "";
    const { text: bodyText, binary } = decodeText(decoded.body, contentType);
    const truncated = decoded.body.length > MAX_BODY_BYTES;
    const kept = truncated ? decoded.body.subarray(0, MAX_BODY_BYTES) : decoded.body;
    const keptText = truncated ? decodeText(kept, contentType).text : bodyText;
    return {
      ok: raw.status >= 200 && raw.status < 400,
      status: raw.status,
      statusText: raw.statusText,
      httpVersion: "1.1",
      headers: raw.headers,
      body: keptText,
      bodyBase64: kept.toString("base64"),
      bodyBytes: decoded.body.length,
      wireBytes: wire.length,
      truncated,
      decompressed: decoded.decompressed,
      binary,
      ms: Date.now() - started,
      finalUrl: url.toString(),
      requestRaw: text,
      responseRaw: rebuildResponseRaw("1.1", raw.status, raw.statusText, raw.headers, decoded.body),
      tls: opened.tlsInfo,
      remote: opened.remote,
      proxy: opened.proxy,
      redirects: [],
    };
  } finally {
    opened.socket.destroy();
  }
}

async function sendHttp2(parsed: ParsedRequest, url: URL, opts: SocketOptions): Promise<RawHttpResult> {
  const started = Date.now();
  const headers = buildH2Headers(parsed, url);
  const origin = `${url.protocol}//${url.host}`;
  let client: http2.ClientHttp2Session | undefined;
  let opened: OpenedSocket | undefined;
  try {
    // 一律自己建连接：http2 不允许直接摸 session.socket，且这样才能拿到 TLS / 远端详情
    opened = await openSocket(url, opts, ["h2"], true);
    client = http2.connect(origin, {
      createConnection: () => opened?.socket as unknown as net.Socket,
    });
    const session = client;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("HTTP/2 连接超时")), opts.timeoutMs);
      session.once("connect", () => {
        clearTimeout(timer);
        resolve();
      });
      session.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    const h2Headers: http2.OutgoingHttpHeaders = {};
    for (const h of headers) {
      if (h.name.startsWith(":")) continue;
      const key = h.name.toLowerCase();
      const current = h2Headers[key];
      if (current === undefined) h2Headers[key] = h.value;
      else if (Array.isArray(current)) current.push(h.value);
      else h2Headers[key] = [String(current), h.value];
    }
    const request = session.request(h2Headers, { endStream: !parsed.body });
    if (parsed.body) request.end(Buffer.from(parsed.body, "utf8"));
    let responseHeaders: RawHeaderPair[] = [];
    let status = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk));
    });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("读取 HTTP/2 响应超时")), opts.timeoutMs);
      request.once("response", (incoming) => {
        // HTTP/2 头名按规范为小写；重复头（set-cookie 等）会以数组形式给出，拆回多条
        const obj = incoming as Record<string, unknown>;
        status = Number(obj[":status"] ?? 0);
        const pairs: RawHeaderPair[] = [];
        for (const [name, value] of Object.entries(obj)) {
          if (name.startsWith(":") || value === undefined) continue;
          if (Array.isArray(value)) for (const item of value) pairs.push({ name, value: String(item) });
          else pairs.push({ name, value: String(value) });
        }
        responseHeaders = pairs;
      });
      request.once("end", () => {
        clearTimeout(timer);
        resolve();
      });
      request.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    const h2Body = Buffer.concat(chunks);
    const decoded = decompress(h2Body, headerValue(responseHeaders, "content-encoding") ?? "");
    const contentType = headerValue(responseHeaders, "content-type") ?? "";
    const { text: bodyText, binary } = decodeText(decoded.body, contentType);
    const truncated = decoded.body.length > MAX_BODY_BYTES;
    const kept = truncated ? decoded.body.subarray(0, MAX_BODY_BYTES) : decoded.body;
    const keptText = truncated ? decodeText(kept, contentType).text : bodyText;
    const requestText = [...headers].map((h) => `${h.name}: ${h.value}`).join("\r\n");
    return {
      ok: status >= 200 && status < 400,
      status,
      statusText: "",
      httpVersion: "2",
      headers: responseHeaders,
      body: keptText,
      bodyBase64: kept.toString("base64"),
      bodyBytes: decoded.body.length,
      wireBytes: h2Body.length,
      truncated,
      decompressed: decoded.decompressed,
      binary,
      ms: Date.now() - started,
      finalUrl: url.toString(),
      requestRaw: `${requestText}\r\n\r\n${parsed.body}`,
      responseRaw: rebuildResponseRaw("2", status, "", responseHeaders, decoded.body),
      tls: opened?.tlsInfo,
      remote: opened?.remote,
      proxy: opened?.proxy,
      redirects: [],
    };
  } finally {
    try {
      client?.close();
    } catch {
      /* 会话已断 */
    }
    try {
      opened?.socket.destroy();
    } catch {
      /* socket 已释放 */
    }
  }
}

/** 入口：按输入发一条原始报文，必要时跟随重定向 */
export async function sendRawHttp(input: RawHttpInput): Promise<RawHttpResult> {
  const started = Date.now();
  const timeoutMs = Math.min(Math.max(input.timeoutMs ?? DEFAULT_TIMEOUT, 1_000), 120_000);
  const rawText = input.raw ?? "";
  // 只把整体是否为空白用来判空，报文首尾的空行属于报文本身，不能裁掉
  const raw = rawText.trim() ? rawText.replace(/\r\n/g, "\n") : "";
  const composed =
    raw ||
    [
      `${(input.method ?? "GET").toUpperCase()} / HTTP/1.1`,
      ...((input.headers ?? "").replace(/\r\n/g, "\n").split("\n").filter((l) => l.trim() && l.includes(":"))),
      "",
      input.body ?? "",
    ].join("\r\n");
  const parsed = parseRawRequest(composed);
  if (!parsed) return errorResult(started, "报文解析失败：第一行需要形如 GET /api/x HTTP/1.1");
  let url = resolveUrl(parsed, input.url);
  if (!url) return errorResult(started, "先给出完整 URL 或带 Host 头的报文，才知道往哪里发");
  if (!/^https?:$/.test(url.protocol)) return errorResult(started, "只支持 http:// 与 https://");

  let proxy = "";
  if (input.useProxy) {
    proxy = input.proxyUrl?.trim() || (await networkStatus()).effective;
  }
  const opts: SocketOptions = {
    skipTlsVerify: input.skipTlsVerify !== false,
    proxy: proxy || undefined,
    timeoutMs,
  };
  const version = input.version === "2" ? "2" : "1.1";
  const redirects: { status: number; location: string }[] = [];
  let current = parsed;

  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const result = version === "2" ? await sendHttp2(current, url, opts) : await sendHttp1(current, url, opts);
      const location = headerValue(result.headers, "location");
      const shouldFollow =
        input.followRedirects !== false &&
        Boolean(location) &&
        [301, 302, 303, 307, 308].includes(result.status) &&
        hop < MAX_REDIRECTS;
      if (!shouldFollow) {
        result.redirects = redirects;
        result.ms = Date.now() - started;
        return result;
      }
      redirects.push({ status: result.status, location: location as string });
      let nextUrl: URL;
      try {
        nextUrl = new URL(location as string, url);
      } catch {
        result.redirects = redirects;
        return result;
      }
      url = nextUrl;
      if (result.status === 303 || ((result.status === 301 || result.status === 302) && current.method === "POST")) {
        current = {
          ...current,
          method: "GET",
          body: "",
          headers: withoutHeader(current.headers, ["content-length", "content-type", "transfer-encoding"]),
        };
      }
    }
    return errorResult(started, `重定向超过 ${MAX_REDIRECTS} 次`);
  } catch (err) {
    return errorResult(started, err instanceof Error ? err.message : String(err), {
      finalUrl: url.toString(),
      proxy: opts.proxy,
    });
  }
}
