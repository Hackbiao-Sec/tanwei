import { app } from "electron";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type {
  FindingSeverity,
  NotifyChannel,
  NotifyConfig,
  NotifyDrillResult,
  NotifyEvent,
  NotifyKind,
  NotifyRecent,
  NotifyTestResult,
} from "../shared/types";

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  严重: 4,
  高危: 3,
  中危: 2,
  低危: 1,
  未知: 0,
};

const DEFAULT_CONFIG: NotifyConfig = {
  channels: [],
  onFinding: true,
  onBan: true,
  onProxy: false,
  minSeverity: "中危",
};

function configPath(): string {
  return path.join(app.getPath("userData"), "notify.json");
}

function makeId(seed: string): string {
  const hash = crypto.createHash("sha1").update(`${seed}:${Date.now()}`).digest("hex");
  return `nt_${hash.slice(0, 10)}`;
}

function normalizeKind(raw: unknown): NotifyKind {
  if (raw === "feishu" || raw === "webhook") return raw;
  return "dingtalk";
}

function normalizeChannel(raw: any): NotifyChannel | undefined {
  const url = String(raw?.url ?? "").trim();
  if (!url) return undefined;
  const events: NotifyEvent[] = Array.isArray(raw?.events)
    ? raw.events.filter((e: unknown): e is NotifyEvent => e === "finding" || e === "ban" || e === "proxy" || e === "session")
    : ["finding", "ban"];
  return {
    id: typeof raw?.id === "string" && raw.id ? raw.id : makeId(url),
    kind: normalizeKind(raw?.kind),
    name: String(raw?.name ?? "").trim() || (raw?.kind === "feishu" ? "飞书机器人" : raw?.kind === "webhook" ? "自定义 Webhook" : "钉钉机器人"),
    url,
    secret: String(raw?.secret ?? "").trim() || undefined,
    enabled: raw?.enabled !== false,
    events: events.length ? events : ["finding", "ban"],
    lastTestAt: typeof raw?.lastTestAt === "number" ? raw.lastTestAt : undefined,
    lastTestOk: typeof raw?.lastTestOk === "boolean" ? raw.lastTestOk : undefined,
    lastError: typeof raw?.lastError === "string" ? raw.lastError : undefined,
    sent: typeof raw?.sent === "number" ? raw.sent : 0,
    failed: typeof raw?.failed === "number" ? raw.failed : undefined,
  };
}

export function readNotifyConfig(): NotifyConfig {
  try {
    const raw = JSON.parse(fs.readFileSync(configPath(), "utf8"));
    const channels = Array.isArray(raw?.channels)
      ? raw.channels.map(normalizeChannel).filter((c: NotifyChannel | undefined): c is NotifyChannel => !!c)
      : [];
    return {
      channels,
      onFinding: raw?.onFinding !== false,
      onBan: raw?.onBan !== false,
      onProxy: raw?.onProxy === true,
      minSeverity: (raw?.minSeverity as FindingSeverity) ?? "中危",
      recent: Array.isArray(raw?.recent)
        ? raw.recent
            .filter((r: any) => r && typeof r.at === "number")
            .slice(0, 20)
            .map((r: any) => ({
              at: Number(r.at),
              event: (r.event as NotifyEvent) ?? "finding",
              title: String(r.title ?? ""),
              ok: r.ok === true,
              channels: Number(r.channels ?? 0),
              error: typeof r.error === "string" ? r.error : undefined,
            }))
        : [],
      updatedAt: typeof raw?.updatedAt === "number" ? raw.updatedAt : undefined,
    };
  } catch {
    return { ...DEFAULT_CONFIG, channels: [] };
  }
}

function writeNotifyConfig(cfg: NotifyConfig): NotifyConfig {
  const next: NotifyConfig = { ...DEFAULT_CONFIG, ...cfg, channels: cfg.channels, updatedAt: Date.now() };
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), `${JSON.stringify(next, null, 2)}\n`, "utf8");
  return next;
}

export function saveNotifyChannel(input: Partial<NotifyChannel> & { url: string }): NotifyConfig {
  const cfg = readNotifyConfig();
  const channel = normalizeChannel(input);
  if (!channel) throw new Error("Webhook 地址不能为空");
  const idx = cfg.channels.findIndex((c) => c.id === channel.id);
  if (idx >= 0) cfg.channels[idx] = { ...cfg.channels[idx], ...channel, id: cfg.channels[idx].id };
  else cfg.channels.push(channel);
  return writeNotifyConfig(cfg);
}

export function removeNotifyChannel(id: string): NotifyConfig {
  const cfg = readNotifyConfig();
  return writeNotifyConfig({ ...cfg, channels: cfg.channels.filter((c) => c.id !== id) });
}

export function setNotifyOptions(patch: Partial<NotifyConfig>): NotifyConfig {
  const cfg = readNotifyConfig();
  return writeNotifyConfig({ ...cfg, ...patch, channels: cfg.channels });
}

function dingSign(secret: string): { timestamp: string; sign: string } {
  const timestamp = String(Date.now());
  const sign = crypto.createHmac("sha256", secret).update(`${timestamp}\n${secret}`).digest("base64");
  return { timestamp, sign };
}

function feishuSign(secret: string): { timestamp: string; sign: string } {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const key = `${timestamp}\n${secret}`;
  const sign = crypto.createHmac("sha256", key).update("").digest("base64");
  return { timestamp, sign };
}

interface Payload {
  url: string;
  body: unknown;
}

function buildPayload(channel: NotifyChannel, text: string): Payload {
  if (channel.kind === "feishu") {
    const body: Record<string, unknown> = {
      msg_type: "text",
      content: { text },
    };
    if (channel.secret) {
      const { timestamp, sign } = feishuSign(channel.secret);
      body.timestamp = timestamp;
      body.sign = sign;
    }
    return { url: channel.url, body };
  }
  if (channel.kind === "webhook") {
    return {
      url: channel.url,
      body: { text, title: "天鉴·探微", event: "notify", at: new Date().toISOString() },
    };
  }
  let url = channel.url;
  if (channel.secret) {
    const { timestamp, sign } = dingSign(channel.secret);
    const sep = url.includes("?") ? "&" : "?";
    url = `${url}${sep}timestamp=${encodeURIComponent(timestamp)}&sign=${encodeURIComponent(sign)}`;
  }
  return {
    url,
    body: { msgtype: "text", text: { content: text } },
  };
}

/** 钉钉 / 飞书 失败时也返回 HTTP 200，要自己看 errcode */
function statusFromBody(kind: NotifyKind, body: string): { ok: boolean; reason?: string } {
  try {
    const json = JSON.parse(body);
    if (kind === "dingtalk") {
      const code = Number(json?.errcode ?? 0);
      if (code !== 0) return { ok: false, reason: `errcode ${code}: ${json?.errmsg ?? ""}` };
    }
    if (kind === "feishu") {
      const code = Number(json?.code ?? json?.StatusCode ?? 0);
      if (code !== 0) return { ok: false, reason: `code ${code}: ${json?.msg ?? json?.StatusMessage ?? ""}` };
    }
  } catch {
    /* 自定义 webhook 可能不回 JSON */
  }
  return { ok: true };
}

async function deliver(channel: NotifyChannel, text: string): Promise<NotifyTestResult> {
  const started = Date.now();
  const startedName = channel.name;
  try {
    const { url, body } = buildPayload(channel, text);
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(12_000),
    });
    const raw = await res.text();
    const verdict = res.ok ? statusFromBody(channel.kind, raw) : { ok: false, reason: `HTTP ${res.status}` };
    const out: NotifyTestResult = {
      ok: verdict.ok,
      channel: startedName,
      ms: Date.now() - started,
      status: res.status,
      error: verdict.ok ? undefined : (verdict.reason ?? raw.slice(0, 200)),
    };
    return out;
  } catch (err) {
    return {
      ok: false,
      channel: startedName,
      ms: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function stampTest(channelId: string, result: NotifyTestResult): void {
  const cfg = readNotifyConfig();
  const next = cfg.channels.map((c) =>
    c.id === channelId
      ? { ...c, lastTestAt: Date.now(), lastTestOk: result.ok, lastError: result.error }
      : c,
  );
  writeNotifyConfig({ ...cfg, channels: next });
}

/** 通知测试：可传已有渠道 id，也可直接传一份还没保存的配置 */
export async function testNotify(input: {
  id?: string;
  kind?: NotifyKind;
  url?: string;
  secret?: string;
  text?: string;
}): Promise<NotifyTestResult> {
  const cfg = readNotifyConfig();
  let channel: NotifyChannel | undefined;
  if (input?.id) channel = cfg.channels.find((c) => c.id === input.id);
  if (!channel && input?.url) {
    channel = normalizeChannel({
      kind: input.kind,
      url: input.url,
      secret: input.secret,
      name: input.kind === "feishu" ? "飞书机器人（未保存）" : input.kind === "webhook" ? "Webhook（未保存）" : "钉钉机器人（未保存）",
    });
  }
  if (!channel) throw new Error("没找到要测试的通知渠道");
  const text =
    input?.text?.trim() ||
    `天鉴·探微 通知测试\n渠道：${channel.name}\n时间：${new Date().toLocaleString("zh-CN")}\n收到这条说明 webhook 配置可用。`;
  const result = await deliver(channel, text);
  if (input?.id) stampTest(input.id, result);
  return result;
}

export interface NotifyMessage {
  event: NotifyEvent;
  title: string;
  lines?: string[];
  severity?: FindingSeverity;
}

function formatMessage(msg: NotifyMessage): string {
  const head = `【天鉴·探微】${msg.title}`;
  const body = (msg.lines ?? []).filter(Boolean).join("\n");
  return body ? `${head}\n${body}` : head;
}

const EVENT_LABEL: Record<NotifyEvent, string> = {
  finding: "新报告落盘",
  ban: "被目标封禁 / 风控",
  proxy: "代理自动轮换",
  session: "会话结束",
};

/** 按开关与订阅挑渠道；挑不到时把原因带回去，界面要能回答「为什么没收到」 */
function routeChannels(
  cfg: NotifyConfig,
  msg: NotifyMessage,
): { targets: NotifyChannel[]; reason?: string } {
  const eventOn =
    (msg.event === "finding" && cfg.onFinding) ||
    (msg.event === "ban" && cfg.onBan) ||
    (msg.event === "proxy" && cfg.onProxy) ||
    msg.event === "session";
  if (!eventOn) return { targets: [], reason: `「${EVENT_LABEL[msg.event]}」总开关是关的` };
  if (msg.event === "finding" && msg.severity) {
    const floor = SEVERITY_RANK[cfg.minSeverity ?? "中危"] ?? 2;
    if ((SEVERITY_RANK[msg.severity] ?? 0) < floor) {
      return { targets: [], reason: `${msg.severity} 低于推送门槛 ${cfg.minSeverity ?? "中危"}` };
    }
  }
  const targets = cfg.channels.filter(
    (c) => c.enabled && (c.events.length === 0 || c.events.includes(msg.event)),
  );
  if (targets.length) return { targets };
  if (!cfg.channels.length) return { targets: [], reason: "还没添加任何通知渠道" };
  if (!cfg.channels.some((c) => c.enabled)) return { targets: [], reason: "所有渠道都被停用了" };
  return { targets: [], reason: `没有渠道订阅「${EVENT_LABEL[msg.event]}」` };
}

function withRecent(cfg: NotifyConfig, row: NotifyRecent): NotifyConfig {
  return { ...cfg, recent: [row, ...(cfg.recent ?? [])].slice(0, 20) };
}

/** 广播：按事件开关 + 严重度门槛挑渠道，失败不抛，同时记一条投递结果 */
export async function broadcastNotify(msg: NotifyMessage): Promise<NotifyTestResult[]> {
  const cfg = readNotifyConfig();
  const route = routeChannels(cfg, msg);
  if (!route.targets.length) {
    writeNotifyConfig(
      withRecent(cfg, {
        at: Date.now(),
        event: msg.event,
        title: msg.title,
        ok: false,
        channels: 0,
        error: route.reason,
      }),
    );
    return [];
  }
  const text = formatMessage(msg);
  const results = await Promise.all(route.targets.map((c) => deliver(c, text)));
  const byId = new Map<string, NotifyTestResult>();
  route.targets.forEach((c, i) => byId.set(c.id, results[i]));
  const errors = results.filter((r) => !r.ok).map((r) => `${r.channel}：${r.error ?? "发送失败"}`);
  const stamp = readNotifyConfig();
  writeNotifyConfig(
    withRecent(
      {
        ...stamp,
        channels: stamp.channels.map((c) => {
          const r = byId.get(c.id);
          if (!r) return c;
          return r.ok
            ? { ...c, sent: (c.sent ?? 0) + 1, lastError: undefined }
            : { ...c, failed: (c.failed ?? 0) + 1, lastError: r.error ?? "发送失败" };
        }),
      },
      {
        at: Date.now(),
        event: msg.event,
        title: msg.title,
        ok: errors.length === 0,
        channels: results.length,
        error: errors.length ? errors.join("；") : undefined,
      },
    ),
  );
  return results;
}

/**
 * 演练：走真实事件的完整过滤链路（总开关 → 事件订阅 → 严重度），
 * 用来区分「勾选没生效」和「webhook 发不出去」。
 */
export async function drillNotify(event: NotifyEvent = "ban"): Promise<NotifyDrillResult> {
  const cfg = readNotifyConfig();
  const msg: NotifyMessage = {
    event,
    severity: event === "finding" ? "中危" : undefined,
    title: `告警演练 · ${EVENT_LABEL[event]}`,
    lines: [
      `时间：${new Date().toLocaleString("zh-CN")}`,
      `这条是按你勾选的「${EVENT_LABEL[event]}」开关和渠道订阅发出来的。`,
      "收到说明这条告警链路是通的；没收到就看下面给的原因。",
    ],
  };
  const route = routeChannels(cfg, msg);
  if (!route.targets.length) {
    writeNotifyConfig(
      withRecent(cfg, {
        at: Date.now(),
        event: msg.event,
        title: msg.title,
        ok: false,
        channels: 0,
        error: `演练未发出：${route.reason ?? "没有可用渠道"}`,
      }),
    );
    return { passed: false, reason: route.reason, results: [] };
  }
  const results = await broadcastNotify(msg);
  return { passed: results.some((r) => r.ok), results };
}

export { configPath as notifyConfigPath };
