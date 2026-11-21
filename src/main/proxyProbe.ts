import net from "node:net";
import tls from "node:tls";

/**
 * 带账号密码的代理 Chromium 不给用：规则里塞 userinfo 会被判成无效规则，
 * 而 Electron 的 app「login」事件在 net.request 上并不触发，凭据递不上去。
 * 所以这些代理自己走 socket 拨：HTTP 代理用 absolute-form 带 Proxy-Authorization，
 * SOCKS4/5 走各自的握手（含 RFC 1929 账号密码）。
 */

export interface ProxyProbeOutcome {
  ok: boolean;
  ms: number;
  status?: number;
  error?: string;
}

const TIMEOUT_MS = 7_000;

/** 明文 HTTP 的 204 端点，走代理不涉及 TLS，探针只关心这条路通不通 */
const TARGETS = [
  { host: "www.gstatic.com", port: 80, path: "/generate_204" },
  { host: "cp.cloudflare.com", port: 80, path: "/generate_204" },
];

interface ParsedProxy {
  scheme: string;
  host: string;
  port: number;
  username: string;
  password: string;
}

function parseProxy(url: string): ParsedProxy | null {
  const m = url.match(/^([a-z0-9]+):\/\/(?:([^/@]*)@)?(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?\/?$/i);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  let username = "";
  let password = "";
  if (m[2] !== undefined) {
    const colon = m[2].indexOf(":");
    username = decodeURIComponent(colon >= 0 ? m[2].slice(0, colon) : m[2]);
    password = colon >= 0 ? decodeURIComponent(m[2].slice(colon + 1)) : "";
  }
  const fallback = scheme.startsWith("socks") ? 1080 : scheme === "https" ? 443 : 8080;
  return { scheme, host: m[3].replace(/^\[|\]$/g, ""), port: m[4] ? Number(m[4]) : fallback, username, password };
}

/** 一行一条地喂字节，够数/够标记再交给上层 */
class Reader {
  private buf = Buffer.alloc(0);
  private notify: (() => void) | null = null;
  private failure: Error | null = null;

  constructor(private readonly sock: net.Socket, private readonly deadline: number) {
    sock.on("data", (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.notify?.();
    });
    sock.on("error", (err) => {
      this.failure = err;
      this.notify?.();
    });
    sock.on("close", () => {
      this.failure = this.failure ?? new Error("代理提前断开");
      this.notify?.();
    });
  }

  private pause(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, ms);
      this.notify = () => {
        clearTimeout(timer);
        this.notify = null;
        resolve();
      };
    });
  }

  private async waitFor(ready: () => boolean): Promise<void> {
    for (;;) {
      if (ready()) return;
      if (this.failure) throw this.failure;
      const left = this.deadline - Date.now();
      if (left <= 0) throw new Error("超时");
      await this.pause(Math.min(left, 200));
    }
  }

  async exact(n: number): Promise<Buffer> {
    await this.waitFor(() => this.buf.length >= n);
    const out = Buffer.from(this.buf.subarray(0, n));
    this.buf = this.buf.subarray(n);
    return out;
  }

  async until(marker: string): Promise<string> {
    const needle = Buffer.from(marker, "latin1");
    await this.waitFor(() => this.buf.indexOf(needle) >= 0);
    const idx = this.buf.indexOf(needle);
    const out = this.buf.subarray(0, idx).toString("latin1");
    this.buf = this.buf.subarray(idx + needle.length);
    return out;
  }
}

function connect(proxy: ParsedProxy, deadline: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock =
      proxy.scheme === "https"
        ? tls.connect({ host: proxy.host, port: proxy.port, servername: proxy.host, rejectUnauthorized: false })
        : net.connect({ host: proxy.host, port: proxy.port });
    sock.setNoDelay(true);
    const left = Math.max(deadline - Date.now(), 1);
    sock.setTimeout(left, () => {
      sock.destroy();
      reject(new Error("超时"));
    });
    sock.once("error", (err) => reject(err));
    const ready = proxy.scheme === "https" ? "secureConnect" : "connect";
    sock.once(ready, () => resolve(sock));
  });
}

function statusOf(head: string): number {
  const m = head.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  return m ? Number(m[1]) : 0;
}

async function socks5(sock: net.Socket, reader: Reader, proxy: ParsedProxy, target: { host: string; port: number }): Promise<void> {
  const wantsAuth = Boolean(proxy.username || proxy.password);
  sock.write(Buffer.from(wantsAuth ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00]));
  const [ver, method] = [...(await reader.exact(2))];
  if (ver !== 0x05) throw new Error("不是 SOCKS5 代理");
  if (method === 0xff) throw new Error("SOCKS5 不接受它的认证方式");
  if (method === 0x02) {
    const user = Buffer.from(proxy.username, "utf8");
    const pass = Buffer.from(proxy.password, "utf8");
    sock.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]));
    const [, status] = [...(await reader.exact(2))];
    if (status !== 0x00) throw new Error("SOCKS5 账号密码被拒");
  }
  const host = Buffer.from(target.host, "utf8");
  sock.write(
    Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
      host,
      Buffer.from([target.port >> 8, target.port & 0xff]),
    ]),
  );
  const head = await reader.exact(4);
  const rep = head[1];
  if (rep !== 0x00) throw new Error(`SOCKS5 连接目标失败（code ${rep}）`);
  const atyp = head[3];
  if (atyp === 0x01) await reader.exact(4);
  else if (atyp === 0x04) await reader.exact(16);
  else if (atyp === 0x03) await reader.exact((await reader.exact(1))[0]);
  await reader.exact(2);
}

async function socks4(sock: net.Socket, reader: Reader, proxy: ParsedProxy, target: { host: string; port: number }): Promise<void> {
  const user = Buffer.from(proxy.username, "utf8");
  sock.write(
    Buffer.concat([
      Buffer.from([0x04, 0x01, target.port >> 8, target.port & 0xff, 0, 0, 0, 0x01]),
      user,
      Buffer.from([0x00]),
      Buffer.from(target.host, "utf8"),
      Buffer.from([0x00]),
    ]),
  );
  const reply = await reader.exact(8);
  if (reply[1] !== 0x5a) throw new Error(`SOCKS4 连接目标失败（code ${reply[1]}）`);
}

/** 一个目标试一发；返回 0 表示连状态行都没读到 */
async function attempt(proxy: ParsedProxy, target: { host: string; port: number; path: string }, deadline: number): Promise<number> {
  const sock = await connect(proxy, deadline);
  try {
    sock.setTimeout(Math.max(deadline - Date.now(), 1));
    const reader = new Reader(sock, deadline);
    if (proxy.scheme.startsWith("socks")) {
      if (proxy.scheme.startsWith("socks5") || proxy.scheme === "socks") await socks5(sock, reader, proxy, target);
      else await socks4(sock, reader, proxy, target);
      sock.write(
        `GET ${target.path} HTTP/1.1\r\nHost: ${target.host}\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      );
    } else {
      const auth = proxy.username || proxy.password
        ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}\r\n`
        : "";
      sock.write(
        `GET http://${target.host}:${target.port}${target.path} HTTP/1.1\r\nHost: ${target.host}\r\nAccept: */*\r\n${auth}Proxy-Connection: close\r\nConnection: close\r\n\r\n`,
      );
    }
    return statusOf(await reader.until("\r\n"));
  } finally {
    sock.destroy();
  }
}

export async function probeCredentialedProxy(url: string): Promise<ProxyProbeOutcome> {
  const started = Date.now();
  const proxy = parseProxy(url);
  if (!proxy) return { ok: false, ms: 0, error: "代理地址解析不了" };
  let last: ProxyProbeOutcome = { ok: false, ms: 0, error: "无响应" };
  for (const target of TARGETS) {
    const deadline = Date.now() + TIMEOUT_MS;
    try {
      const status = await attempt(proxy, target, deadline);
      last = { ok: status > 0 && status < 400, ms: Date.now() - started, status };
      if (last.ok) return last;
      // 代理自己通了、只是上游那一段挂了才换地址再试；账号密码错（407）重试也没用
      if (status === 0 || status === 407 || status === 401) return last;
    } catch (err) {
      last = { ok: false, ms: Date.now() - started, error: (err as Error).message };
      if (/超时/.test(last.error ?? "")) return last;
    }
  }
  return last;
}
