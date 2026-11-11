import { net, session } from "electron";
import type { EndpointProbe, NetworkStatus } from "../shared/types";
import { readSettings } from "./appSettings";
import { poolProxy } from "./proxyPool";

/** 探测专用分区：改动代理不会影响主窗口自己的网络 */
const PROBE_PARTITION = "tanwei-probe";
const NO_PROXY = "localhost,127.0.0.1,::1";
const PROBE_TIMEOUT_MS = 8_000;

/** Chromium 的代理规则（PROXY host:port / SOCKS5 host:port）→ 引擎能用的 URL */
function ruleToUrl(rule: string): string {
  const [kind, addr] = rule.trim().split(/\s+/);
  if (!addr) return "";
  const upper = (kind || "").toUpperCase();
  if (upper === "DIRECT") return "";
  if (upper.startsWith("SOCKS")) return `socks5://${addr}`;
  return `http://${addr}`;
}

/** 读 Windows 系统代理（Chromium 会解析注册表 / PAC）；没有则返回空串 */
export async function resolveSystemProxy(): Promise<string> {
  try {
    const rules = await session.defaultSession.resolveProxy("https://api.deepseek.com");
    for (const raw of rules.split(";")) {
      const url = ruleToUrl(raw);
      if (url) return url;
    }
  } catch {
    /* 解析失败按直连处理 */
  }
  return "";
}

export function normalizeProxy(raw: string): string {
  const value = raw.trim();
  if (!value) return "";
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`;
}

/** 当前设置 + 实际生效的代理地址 */
export async function networkStatus(): Promise<NetworkStatus> {
  const { network } = readSettings();
  const systemProxy = await resolveSystemProxy();
  const poolActive = network.proxyMode === "pool" ? poolProxy() : "";
  const effective =
    network.proxyMode === "off"
      ? ""
      : network.proxyMode === "manual"
        ? normalizeProxy(network.proxyUrl)
        : network.proxyMode === "pool"
          ? poolActive
          : systemProxy;
  return { ...network, effective, systemProxy, poolActive };
}

/** 传给 grok agent 子进程的代理环境变量；空地址表示强制直连 */
export function proxyEnv(proxy: string): NodeJS.ProcessEnv {
  if (!proxy) {
    return {
      HTTP_PROXY: "",
      HTTPS_PROXY: "",
      ALL_PROXY: "",
      http_proxy: "",
      https_proxy: "",
      all_proxy: "",
    };
  }
  return {
    HTTP_PROXY: proxy,
    HTTPS_PROXY: proxy,
    ALL_PROXY: proxy,
    http_proxy: proxy,
    https_proxy: proxy,
    all_proxy: proxy,
    NO_PROXY: NO_PROXY,
    no_proxy: NO_PROXY,
  };
}

/** 走指定代理请求一次，拿到任意 HTTP 状态码就算网络通 */
export function probeEndpoint(url: string, proxy: string): Promise<EndpointProbe> {
  const started = Date.now();
  const ses = session.fromPartition(PROBE_PARTITION);

  return ses
    .setProxy(proxy ? { proxyRules: proxy, proxyBypassRules: NO_PROXY } : { mode: "direct" })
    .catch(() => undefined)
    .then(
      () =>
        new Promise<EndpointProbe>((resolve) => {
          let settled = false;
          const finish = (value: EndpointProbe) => {
            if (settled) return;
            settled = true;
            resolve(value);
          };
          const timer = setTimeout(
            () =>
              finish({
                url,
                proxy,
                ms: Date.now() - started,
                reachable: false,
                error: `超时（${PROBE_TIMEOUT_MS / 1000} 秒内没响应）`,
              }),
            PROBE_TIMEOUT_MS,
          );

          try {
            const req = net.request({ url, method: "GET", session: ses, useSessionCookies: false });
            req.on("response", (res) => {
              clearTimeout(timer);
              finish({
                url,
                proxy,
                ms: Date.now() - started,
                reachable: true,
                status: res.statusCode,
              });
              res.on("data", () => undefined);
              res.on("end", () => undefined);
              res.on("error", () => undefined);
            });
            req.on("error", (err) => {
              clearTimeout(timer);
              finish({ url, proxy, ms: Date.now() - started, reachable: false, error: err.message });
            });
            req.end();
          } catch (err) {
            clearTimeout(timer);
            finish({
              url,
              proxy,
              ms: Date.now() - started,
              reachable: false,
              error: (err as Error).message,
            });
          }
        }),
    );
}
