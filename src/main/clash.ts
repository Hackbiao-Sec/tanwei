import http from "node:http";
import type { ClashProfile, ClashStatus, ProxyPool } from "../shared/types";
import { healClashController, readPool, setClashProfile } from "./proxyPool";

/**
 * 本机 Clash / mihomo 的 external-controller 客户端。
 *
 * 订阅配置里的 vmess / ss / trojan 节点 Electron 拨不了，但本机客户端能拨。
 * 只要它能切换，出口 IP 就真的换了，而代理地址始终是 mixed-port，引擎不用重启。
 */

const REQUEST_TIMEOUT_MS = 4_000;
const DELAY_TIMEOUT_MS = 3_500;
const DELAY_URL = "http://www.gstatic.com/generate_204";
const MAX_DELAY_PROBES = 24;

interface ParsedController {
  host: string;
  port: number;
  base: string;
}

function parseController(profile?: ClashProfile): ParsedController | undefined {
  const raw = (profile?.controller ?? "").trim();
  if (!raw) return undefined;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    const url = new URL(withScheme);
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    if (!url.hostname || !Number.isInteger(port) || port <= 0) return undefined;
    return { host: url.hostname, port, base: `${url.protocol}//${url.hostname}:${port}` };
  } catch {
    return undefined;
  }
}

/** 控制口只在本机，直连不走系统代理，免得自己被代理转一圈 */
function request<T>(
  target: ParsedController,
  method: string,
  pathname: string,
  body?: unknown,
  secret?: string,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = { Accept: "application/json" };
    if (secret) headers.Authorization = `Bearer ${secret}`;
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(Buffer.byteLength(payload));
    }
    const req = http.request(
      { host: target.host, port: target.port, method, path: pathname, headers, timeout: REQUEST_TIMEOUT_MS },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            reject(new Error(`控制口返回 ${status}${text ? `：${text.slice(0, 120)}` : ""}`));
            return;
          }
          if (!text.trim()) {
            resolve(undefined as T);
            return;
          }
          try {
            resolve(JSON.parse(text) as T);
          } catch {
            reject(new Error("控制口返回的不是 JSON，检查 external-controller 是否指向 Clash/mihomo"));
          }
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error("控制口超时，Clash/mihomo 没开或端口不对"));
    });
    req.on("error", (err) => reject(err));
    if (payload) req.write(payload);
    req.end();
  });
}

interface ClashProxy {
  name: string;
  type: string;
  now?: string;
  all?: string[];
  alive?: boolean;
  history?: { delay: number; time: string }[];
}

const GROUP_TYPES = new Set(["selector", "urltest", "fallback", "loadbalance"]);
const SELECTOR_TYPES = new Set(["selector"]);
/** 组名里出现这些词，多半就是用户平时点的那个出口组 */
const GROUP_HINT = /(选择|节点|代理|出口|select|proxy|auto|🚀|🔰|♻️|🇭🇰|🇯🇵)/i;

function isGroup(proxy: ClashProxy): boolean {
  return GROUP_TYPES.has(String(proxy?.type ?? "").toLowerCase()) && Array.isArray(proxy.all);
}

function isSelector(proxy: ClashProxy): boolean {
  return SELECTOR_TYPES.has(String(proxy?.type ?? "").toLowerCase()) && Array.isArray(proxy.all);
}

/** 不能当出口的成员：直连/拒绝/内置策略 */
const NON_EXIT_TYPES = new Set(["direct", "reject", "rejectdrop", "pass", "dns", "compatible"]);
/** 订阅里塞进来的提示行（流量、到期、官网）也占着组员位置，切过去等于没代理 */
const NOTICE_NAME = /(剩余流量|套餐|到期|官网|教程|版本|客服|群组|订阅|重置|升级)/;

/**
 * 组里真正能拨出去的成员。
 * 电话卡订阅常在组里塞 DIRECT / REJECT / 「剩余流量」这类行，按延迟排序它们永远最快，
 * 一旦选中出口就成了直连，所以统一在这里剔掉。
 */
function exitNames(all: string[] | undefined, proxies: Record<string, ClashProxy>): string[] {
  return (all ?? []).filter((name) => {
    const node = proxies[name];
    if (!node) return false;
    if (isGroup(node)) return false;
    if (NON_EXIT_TYPES.has(String(node.type ?? "").toLowerCase())) return false;
    return !NOTICE_NAME.test(name);
  });
}

/** 读 /configs 的运行模式：global 时真实出口只由 GLOBAL 组决定，切别的组等于没换 */
async function fetchMode(target: ParsedController, secret?: string): Promise<string | undefined> {
  try {
    const res = await request<{ mode?: string }>(target, "GET", "/configs", undefined, secret);
    const mode = typeof res?.mode === "string" ? res.mode.toLowerCase() : "";
    return mode || undefined;
  } catch {
    return undefined;
  }
}

/** 选一个「切了真换出口」的组：优先用户指定的，其次带选择语义、节点最多的 Selector */
function pickGroup(
  proxies: Record<string, ClashProxy>,
  profile: ClashProfile,
  preferNow?: string,
  mode?: string,
): { name: string; group?: ClashProxy } {
  const globalProxy = proxies.GLOBAL;
  // 全局模式下别的组切了不改变出口，必须切 GLOBAL
  if (mode === "global" && globalProxy && isGroup(globalProxy)) {
    return { name: "GLOBAL", group: globalProxy };
  }
  if (profile.group && profile.group !== "GLOBAL" && proxies[profile.group] && isGroup(proxies[profile.group])) {
    return { name: profile.group, group: proxies[profile.group] };
  }
  const selectors = Object.values(proxies).filter(
    (p) => isSelector(p) && (p.all?.length ?? 0) > 1 && p.name !== "GLOBAL",
  );
  const scored = selectors
    .map((p) => {
      let score = (p.all?.length ?? 0) / 100;
      if (GROUP_HINT.test(p.name)) score += 10;
      if (preferNow && p.now === preferNow) score += 1;
      if (profile.selected && p.all?.includes(profile.selected)) score += 3;
      if (/GLOBAL/i.test(p.name)) score -= 5;
      return { p, score };
    })
    .sort((a, b) => b.score - a.score);
  if (scored.length) return { name: scored[0].p.name, group: scored[0].p };
  const global = proxies.GLOBAL;
  if (global && Array.isArray(global.all)) return { name: "GLOBAL", group: global };
  return { name: "" };
}

function delayOf(proxy: ClashProxy | undefined): number | undefined {
  const last = proxy?.history?.[proxy.history.length - 1];
  return last && last.delay > 0 ? last.delay : undefined;
}

async function fetchProxiesWithAuth(profile: ClashProfile, target: ParsedController): Promise<Record<string, ClashProxy>> {
  const res = await request<any>(target, "GET", "/proxies", undefined, profile.secret);
  const map = res?.proxies && typeof res.proxies === "object" ? res.proxies : res;
  if (!map || typeof map !== "object") throw new Error("控制口没有返回节点表");
  return map as Record<string, ClashProxy>;
}
/** 读实时状态：连得上控制口才有；节点清单以客户端为准，不是配置文件 */
export async function clashStatus(input?: ClashProfile): Promise<ClashStatus> {
  const profile = await ensureProfile(input);
  const target = parseController(profile);
  if (!proxyConfigured(profile) || !target) {
    return {
      connected: false,
      controller: profile?.controller,
      groups: [],
      nodes: [],
      error: profile?.controller ? "控制口地址不对，形如 127.0.0.1:9090" : "还没登记 Clash 控制口",
    };
  }
  try {
    const [proxies, mode] = await Promise.all([
      fetchProxiesWithAuth(profile!, target),
      fetchMode(target, profile!.secret),
    ]);
    const picked = pickGroup(proxies, profile!, undefined, mode);
    const group = picked.group;
    const groups = Object.values(proxies)
      .filter((p) => isGroup(p))
      .map((p) => ({ name: p.name, now: p.now, nodes: p.all?.length ?? 0 }))
      .sort((a, b) => b.nodes - a.nodes);
    const nodes = exitNames(group?.all, proxies);
    return {
      connected: true,
      controller: profile!.controller,
      group: picked.name || undefined,
      selected: group?.now,
      mode,
      groups,
      nodes,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setClashProfile({ error: message });
    return {
      connected: false,
      controller: profile?.controller,
      mode: undefined,
      groups: [],
      nodes: profile?.nodes.map((n) => n.name) ?? [],
      error: message,
    };
  }
}

function proxyConfigured(profile?: ClashProfile): boolean {
  return Boolean(profile && (profile.controller || profile.nodes?.length));
}

/** 控制口还活着吗；顺手确认 secret 对不对 */
async function alive(profile: ClashProfile): Promise<boolean> {
  const target = parseController(profile);
  if (!target) return false;
  try {
    await request(target, "GET", "/version", undefined, profile.secret);
    return true;
  } catch {
    return false;
  }
}

/**
 * 动手前先确认控制口能连。订阅文件里写的地址常是模板默认值（死端口），
 * 连不上就去本机客户端的运行配置里换一个能连的地址，并记进池里。
 */
async function ensureProfile(input?: ClashProfile): Promise<ClashProfile | undefined> {
  const profile = input ?? readPool().clash;
  if (!proxyConfigured(profile)) return profile;
  const target = parseController(profile);
  if (target && (await alive(profile!))) return profile;
  const healed = await healClashController();
  return healed.pool.clash ?? profile;
}

/** 切到指定节点；出口立刻变，引擎不用重启 */
export async function clashSelect(
  name: string,
  options: { group?: string; profile?: ClashProfile } = {},
): Promise<{ pool: ProxyPool; status: ClashStatus; from?: string; to: string; group?: string }> {
  const pool = readPool();
  const profile = await ensureProfile(options.profile);
  if (!profile) throw new Error("先导入 Clash 配置，才有节点可切");
  const target = parseController(profile);
  if (!target) throw new Error("没有 external-controller，先导入 Clash 配置或手填控制口");
  const proxies = await fetchProxiesWithAuth(profile, target);
  const mode = await fetchMode(target, profile.secret);
  const picked = options.group
    ? { name: options.group, group: proxies[options.group] }
    : pickGroup(proxies, profile, undefined, mode);
  if (!picked.name || !picked.group) throw new Error("没找到可切换的节点组，先在 Clash 里建一个 select 组");
  if (picked.group.now === name) {
    const next = writeClash(pool, picked.name, name);
    return { pool: next.pool, status: await clashStatus(next.pool.clash), from: picked.group.now, to: name, group: picked.name };
  }
  await request(target, "PUT", `/proxies/${encodeURIComponent(picked.name)}`, { name }, profile.secret);
  const written = writeClash(pool, picked.name, name);
  return {
    pool: written.pool,
    status: await clashStatus(written.pool.clash),
    from: written.from,
    to: name,
    group: picked.name,
  };
}

function writeClash(pool: ProxyPool, group: string, selected: string): { pool: ProxyPool; from?: string } {
  const from = pool.clash?.selected;
  const next = setClashProfile({ group, selected, switchedAt: Date.now(), error: undefined });
  return { pool: next, from };
}

/**
 * 轮换：按当前组里的顺序换下一个，跳过刚用过的那一个。
 * reason 只影响日志，行为都是「换一个真正不同的出口」。
 */
export async function clashRotate(reason = "manual"): Promise<{ pool: ProxyPool; status: ClashStatus; to?: string; error?: string }> {
  const pool = readPool();
  const profile = await ensureProfile();
  if (!profile) return { pool, status: await clashStatus(undefined), error: "还没有 Clash 节点池" };
  const target = parseController(profile);
  if (!target) return { pool, status: await clashStatus(profile), error: "没有 external-controller" };
  try {
    const proxies = await fetchProxiesWithAuth(profile, target);
    const mode = await fetchMode(target, profile.secret);
    const picked = pickGroup(proxies, profile, undefined, mode);
    if (!picked.group) throw new Error("没找到可切换的节点组");
    const names = exitNames(picked.group.all, proxies);
    if (!names.length) throw new Error("这个组里没有节点");
    const current = picked.group.now ?? profile.selected;
    const idx = current ? names.indexOf(current) : -1;
    let next = names[(idx + 1) % names.length];
    if (next === current && names.length > 1) next = names[(idx + 2) % names.length];
    if (!next || next === current) return { pool, status: await clashStatus(profile), to: current, error: "组里只有一个节点，换不了出口" };
    await request(target, "PUT", `/proxies/${encodeURIComponent(picked.name)}`, { name: next }, profile.secret);
    const written = writeClash(pool, picked.name, next);
    void reason;
    return { pool: written.pool, status: await clashStatus(written.pool.clash), to: next };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const next = setClashProfile({ error: message });
    return { pool: next, status: await clashStatus(next.clash), error: message };
  }
}

/** 测一批节点的延迟，挑最快的切过去；只测前 24 个，别把控制口打满 */
export async function clashFastest(): Promise<{ pool: ProxyPool; status: ClashStatus; to?: string; delays: Record<string, number>; error?: string }> {
  const pool = readPool();
  const profile = await ensureProfile();
  const target = parseController(profile);
  if (!profile || !target) {
    return { pool, status: await clashStatus(profile), delays: {}, error: "没有 Clash 控制口" };
  }
  try {
    const proxies = await fetchProxiesWithAuth(profile, target);
    const mode = await fetchMode(target, profile.secret);
    const picked = pickGroup(proxies, profile, undefined, mode);
    if (!picked.group) throw new Error("没找到可切换的节点组");
    const names = exitNames(picked.group.all, proxies).slice(0, MAX_DELAY_PROBES);
    const delays: Record<string, number> = {};
    const concurrency = 6;
    for (let i = 0; i < names.length; i += concurrency) {
      const batch = names.slice(i, i + concurrency);
      await Promise.all(
        batch.map(async (name) => {
          const query = `?timeout=${DELAY_TIMEOUT_MS}&url=${encodeURIComponent(DELAY_URL)}`;
          try {
            const res = await request<{ delay?: number }>(
              target,
              "GET",
              `/proxies/${encodeURIComponent(name)}/delay${query}`,
              undefined,
              profile.secret,
            );
            if (res && typeof res.delay === "number" && res.delay > 0) delays[name] = res.delay;
          } catch {
            /* 单个节点超时不记，继续测下一个 */
          }
        }),
      );
    }
    const fastest = Object.entries(delays).sort((a, b) => a[1] - b[1])[0];
    if (!fastest) {
      const next = setClashProfile({ error: "这批节点都测不通，检查订阅是否过期" });
      return { pool: next, status: await clashStatus(next.clash), delays, error: "这批节点都测不通" };
    }
    const switched = await clashSelect(fastest[0], { group: picked.name, profile });
    return { pool: switched.pool, status: switched.status, to: fastest[0], delays };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const next = setClashProfile({ error: message });
    return { pool: next, status: await clashStatus(next.clash), delays: {}, error: message };
  }
}

/** 用户手填控制口 / 组名 */
export function setClashController(patch: { controller?: string; secret?: string; group?: string }): ProxyPool {
  const clean = {
    ...patch,
    controller: patch.controller?.trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "") || undefined,
  };
  return setClashProfile(clean);
}
