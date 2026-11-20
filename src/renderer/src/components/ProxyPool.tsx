import React, { useEffect, useMemo, useState } from "react";
import type {
  ClashStatus,
  ProxyEntry,
  ProxyImportResult,
  ProxyImportStats,
  ProxyPool as Pool,
  ProxyRotationMode,
  ProxySource,
} from "@shared/types";
import { Icon } from "./Icons";

const HEALTH_LABEL: Record<string, string> = { ok: "可用", bad: "不通", unknown: "未测" };
const SOURCE_LABEL: Record<ProxySource, string> = { config: "付费配置", free: "免费节点", manual: "手填" };
const SOURCE_TONE: Record<ProxySource, string> = { config: "s-config", free: "s-free", manual: "s-manual" };
const KIND_LABEL: Record<string, string> = {
  clash: "Clash / mihomo",
  json: "JSON",
  list: "地址列表",
  base64: "base64 订阅",
  ai: "AI 解析",
  unknown: "未知格式",
};

const MODE_LABEL: Record<ProxyRotationMode, string> = {
  interval: "按时间换",
  fastest: "只用最快的",
  smart: "智能选路",
};

const MODE_HINT: Record<ProxyRotationMode, string> = {
  interval: "到点就在可用节点里顺手换一条，避免同一个出口打太久",
  fastest: "每次换都挑刚测出来速度最好的那条",
  smart: "综合可用性、速度、延迟、失败次数打分挑一条，被封的自动压到最后",
};

const INTERVALS = [60, 180, 300, 600, 900, 1800, 3600];

const MAX_FILE = 8 * 1024 * 1024;

function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

function maskUrl(url: string): string {
  return url.replace(/\/\/[^@/]+@/, "//***@");
}

function schemeCount(record: Record<string, number>): string[] {
  return Object.entries(record).map(([key, n]) => `${key} ×${n}`);
}

function fileName(file: string): string {
  return file.split(/[\\/]/).pop() || file;
}

function fmtSpeed(kbps?: number): string {
  if (kbps == null) return "—";
  if (kbps >= 1024) return `${(kbps / 1024).toFixed(1)} MB/s`;
  return `${Math.round(kbps)} KB/s`;
}

function fmtAgo(t?: number): string {
  if (!t) return "还没换过";
  const diff = Date.now() - t;
  if (diff < 60_000) return "刚刚换过";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前换过`;
  return `${Math.floor(diff / 3_600_000)} 小时前换过`;
}

/** 订阅里会塞「剩余流量 / 套餐到期 / 请升级客户端」这类占位节点，不能进可选出口 */
const NOTICE_NODE = /(剩余流量|套餐|到期|官网|教程|版本|客服|群组|订阅|重置|升级)/;

interface ParsedView {
  stats: ProxyImportStats;
  how: string;
  model?: string;
  note?: string;
}

export function ProxyPool() {
  const [pool, setPool] = useState<Pool | undefined>();
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const [dropped, setDropped] = useState("");
  const [parsed, setParsed] = useState<ParsedView | undefined>();
  const [lastIds, setLastIds] = useState<string[]>([]);
  const [onlyOk, setOnlyOk] = useState(false);
  const [clearArmed, setClearArmed] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [source, setSource] = useState<ProxySource | "all">("all");
  const [query, setQuery] = useState("");
  const [speed, setSpeed] = useState<{ done: number; total: number } | undefined>();
  const [poolPath, setPoolPath] = useState("");
  const [clash, setClash] = useState<ClashStatus | undefined>();
  const [clashNode, setClashNode] = useState("");
  const [clashDelays, setClashDelays] = useState<Record<string, number>>({});
  const [controller, setController] = useState("");
  const [secret, setSecret] = useState("");

  /** 可选出口：剔掉订阅里的占位节点，没有连上控制口时下拉框整体不显示 */
  const liveNodes = (clash?.nodes ?? []).filter((n) => !NOTICE_NODE.test(n));

  useEffect(() => {
    let alive = true;
    void window.tanwei
      .pool()
      .then((next) => {
        if (!alive) return;
        setPool(next);
        setController(next.clash?.controller ?? "");
        setSecret(next.clash?.secret ?? "");
        setClashNode(next.clash?.selected ?? "");
      })
      .catch((err) => {
        if (alive) setError(errText(err));
      });
    void window.tanwei
      .clashStatus()
      .then((st) => {
        if (!alive) return;
        setClash(st);
        if (st?.selected) setClashNode(st.selected);
      })
      .catch(() => undefined);
    void window.tanwei
      .poolPath()
      .then((p) => {
        if (alive) setPoolPath(p);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  // 后台轮换 / 测速进度都从主进程推过来，界面跟着走，不用手动刷新
  useEffect(() => {
    const off = window.tanwei.onPoolEvent((ev) => {
      if (ev.kind === "rotated") {
        void window.tanwei.pool().then(setPool).catch(() => undefined);
        setNotice(`已换出口（${ev.reason === "ban" ? "被封禁" : ev.reason === "fastest" ? "按最快挑" : "按策略挑"}）`);
      }
      if (ev.kind === "speed") {
        setSpeed(ev.done >= ev.total ? undefined : { done: ev.done, total: ev.total });
        if (ev.done >= ev.total) {
          void window.tanwei.pool().then(setPool).catch(() => undefined);
        }
      }
      if (ev.kind === "clash") {
        void window.tanwei.pool().then(setPool).catch(() => undefined);
        void window.tanwei.clashStatus().then(setClash).catch(() => undefined);
        if (ev.selected) setClashNode(ev.selected);
        setNotice(`已切 Clash 节点${ev.selected ? `：${ev.selected}` : ""}`);
      }
    });
    return off;
  }, []);

  async function run<T>(key: string, fn: () => Promise<T>): Promise<T | undefined> {
    setBusy(key);
    setError("");
    try {
      return await fn();
    } catch (err) {
      setError(errText(err));
      return undefined;
    } finally {
      setBusy("");
    }
  }

  function apply(res: ProxyImportResult, how: string, extra?: { model?: string; note?: string }) {
    setPool(res.pool);
    setParsed({ stats: res.stats, how, model: extra?.model, note: extra?.note });
    setLastIds(res.addedIds);
    const bits = [`新增 ${res.added} 条`];
    if (res.skipped) bits.push(`跳过 ${res.skipped} 行`);
    if (!res.added && res.pool.entries.length) bits.push(`池里已有 ${res.pool.entries.length} 条`);
    setNotice(bits.join(" · "));
  }

  async function parseLocally(input: { file?: string; text?: string }, label: string) {
    await run("parse", async () => {
      try {
        const res = await window.tanwei.importPoolPath(input);
        apply(res, `本地解析 · ${label}`);
      } catch (err) {
        const reason = errText(err);
        setNotice("本地没认出这份格式，改让 AI 抽代理地址…");
        try {
          const ai = await window.tanwei.aiParseProxy(input);
          apply(ai, `AI 解析 · ${ai.model}`, { model: ai.model, note: ai.note });
        } catch (err2) {
          setError(`本地解析：${reason}\nAI 解析：${errText(err2)}`);
        }
      }
    });
  }

  async function pickFile() {
    if (busy) return;
    const file = await run("pick", () => window.tanwei.pickPoolFile());
    if (!file) return;
    setPath(file);
    await parseLocally({ file }, fileName(file));
  }

  async function importPath() {
    const file = path.trim() || dropped.trim();
    if (!file) {
      setError("先填配置文件路径，或者把文件拖进来");
      return;
    }
    setPath(file);
    await parseLocally({ file }, fileName(file));
  }

  async function aiParse() {
    const file = path.trim() || dropped.trim();
    const body = text.trim();
    if (!file && !body) {
      setError("先选一份配置文件，或者把内容粘到下面的框里");
      return;
    }
    await run("ai", async () => {
      const res = await window.tanwei.aiParseProxy(file ? { file } : { text: body });
      apply(res, `AI 解析 · ${res.model}`, { model: res.model, note: res.note });
    });
  }

  async function pasteImport() {
    const body = text.trim();
    if (!body) {
      setError("先把配置内容粘到上面的框里");
      return;
    }
    await parseLocally({ text: body }, "粘贴内容");
  }

  async function dropFile(file: File) {
    setDragging(false);
    if (file.size > MAX_FILE) {
      setError("文件太大（上限 8 MB），从 Clash 里只导出 proxies 那一段也行");
      return;
    }
    const content = await file.text();
    setDropped(file.name);
    const maybe = (file as File & { path?: string }).path;
    await parseLocally(maybe ? { file: maybe } : { text: content }, file.name);
  }

  async function testPool() {
    const next = await run("test", () => window.tanwei.testProxies());
    if (next) setPool(next);
  }

  async function testNew() {
    const ids = lastIds.length ? lastIds.slice(0, 20) : (pool?.entries ?? []).slice(0, 20).map((e) => e.id);
    if (!ids.length) {
      setError("池里还没有条目");
      return;
    }
    const next = await run("test-new", () => window.tanwei.testProxies(ids));
    if (next) setPool(next);
  }

  async function fetchFree() {
    const res = await run("free", () => window.tanwei.fetchFreeProxies(80));
    if (!res) return;
    setPool(res.pool);
    setLastIds(res.addedIds);
    const bits = [`抓到 ${res.fetched} 条`, `新进池 ${res.added} 条`];
    if (res.errors.length) bits.push(`${res.errors.length} 个源没取到`);
    setNotice(bits.join(" · "));
  }

  async function entryTask(key: string, fn: () => Promise<Pool>) {
    const next = await run(`entry-${key}`, fn);
    if (next) setPool(next);
  }

  async function toggleEntry(id: string, enabled: boolean) {
    await entryTask(id, () => window.tanwei.enableProxy(id, enabled));
  }

  async function pickEntry(id: string) {
    await entryTask(id, () => window.tanwei.setPoolActive(id));
  }

  async function dropEntry(id: string) {
    await entryTask(id, () => window.tanwei.removeProxies([id]));
  }

  async function toggleRotate() {
    const next = pool?.rotate ?? false;
    await entryTask("rotate", () => window.tanwei.setPoolRotate(!next));
  }

  async function patchRotation(patch: Parameters<typeof window.tanwei.setPoolRotation>[0]) {
    const next = await run("rotation", () => window.tanwei.setPoolRotation(patch));
    if (next) setPool(next);
  }

  async function rotateNow(reason: "manual" | "fastest" = "manual") {
    const res = await run("rotate-now", () => window.tanwei.rotateNow({ reason }));
    if (!res) return;
    setPool(res.pool);
    if (res.via === "clash") {
      setClashNode(res.selected ?? "");
      void window.tanwei.clashStatus().then(setClash).catch(() => undefined);
      setNotice(`已切 Clash 节点：${res.selected ?? "已切换"}（出口立刻变，引擎不用重启）`);
    } else if (res.via === "pool") {
      setNotice(`出口已切到 ${res.label ?? "池里下一条"}`);
    } else {
      setNotice("没有可换的出口：池里没有启用的条目，Clash 也没连上");
    }
  }

  async function refreshClash() {
    const st = await run("clash-status", () => window.tanwei.clashStatus());
    if (st) setClash(st);
    // 下拉框优先用 clashNode，重连后必须跟一次真实选中节点，
    // 否则面板上「当前节点」会一直停在池文件里存的旧值。
    if (st?.selected) setClashNode(st.selected);
  }

  async function saveController() {
    const res = await run("clash-ctl", () => window.tanwei.setClashController({ controller, secret }));
    if (!res) return;
    setPool(res.pool);
    setClash(res.status);
    // 连上控制口这一刻就把下拉框对到真实出口，不然它停在上一个控制口的节点上
    if (res.status.selected) setClashNode(res.status.selected);
    setNotice(
      res.status.connected
        ? `已连上控制口：${res.status.group ?? "未找到选择组"}，当前 ${res.status.selected ?? "未知"}`
        : `控制口没连上：${res.status.error ?? "检查 Clash 是否在跑"}`,
    );
  }

  async function switchGroup(group: string) {
    if (!clash?.nodes.length) return;
    const target = clash.selected && clash.nodes.includes(clash.selected) ? clash.selected : clash.nodes[0];
    const res = await run("clash-group", () => window.tanwei.setClashController({ group }));
    if (!res) return;
    setPool(res.pool);
    const st = await window.tanwei.clashStatus().catch(() => undefined);
    if (st) setClash(st);
    if (st?.selected) setClashNode(st.selected);
    setNotice(`切换组：${group}${target ? `（当前 ${target}）` : ""}`);
  }

  async function selectClashNode(name: string) {
    if (!name) return;
    const res = await run("clash-select", () => window.tanwei.clashSelect({ name }));
    if (!res) return;
    setPool(res.pool);
    setClash(res.status);
    setClashNode(res.to ?? res.status.selected ?? name);
    setNotice(`已切到 ${res.to}${res.group ? `（组 ${res.group}）` : ""}`);
  }

  async function rotateClash() {
    const res = await run("clash-rotate", () => window.tanwei.clashRotate("manual"));
    if (!res) return;
    setPool(res.pool);
    setClash(res.status);
    if (res.error) {
      setError(res.error);
      return;
    }
    setClashNode(res.to ?? "");
    setNotice(`Clash 换到下一个节点：${res.to ?? "已切换"}`);
  }

  async function fastestClash() {
    const res = await run("clash-fastest", () => window.tanwei.clashFastest());
    if (!res) return;
    setPool(res.pool);
    setClash(res.status);
    setClashDelays(res.delays);
    if (res.error) {
      setError(res.error);
      return;
    }
    setClashNode(res.to ?? "");
    const ms = res.to ? res.delays[res.to] : undefined;
    setNotice(`测速完成，切到最快节点 ${res.to ?? "-"}${ms ? ` · ${ms} ms` : ""}`);
  }

  async function testSpeed(ids?: string[]) {
    const res = await run(ids ? `speed-${ids[0]}` : "speed", () => window.tanwei.testSpeeds(ids));
    if (!res) return;
    setPool(res.pool);
    setSpeed(undefined);
    setNotice(`测速完成：${res.ok} 条出数，${res.failed} 条没测到`);
  }

  async function markFail(entry: ProxyEntry) {
    const next = await run(`fail-${entry.id}`, () => window.tanwei.markProxyFail(entry.id, "手动标记"));
    if (next) {
      setPool(next);
      setNotice("已记一次失败；开了「被封禁时自动切」会顺手换走");
    }
  }

  async function clearPool() {
    if (!pool?.entries.length) return;
    if (!clearArmed) {
      setClearArmed(true);
      setNotice("再点一次「确认清空」就真的清掉整池");
      return;
    }
    setClearArmed(false);
    const next = await run("clear", () => window.tanwei.clearPool());
    if (next) {
      setPool(next);
      setParsed(undefined);
      setLastIds([]);
      setNotice("池已清空");
    }
  }

  const all = pool?.entries ?? [];
  const okCount = all.filter((e) => e.health === "ok").length;
  const enabledCount = all.filter((e) => e.enabled).length;
  const paidCount = all.filter((e) => e.source === "config").length;
  const freeCount = all.filter((e) => e.source === "free").length;
  const manualCount = all.filter((e) => e.source === "manual").length;
  const rotation = pool?.rotation;
  const active = all.find((e) => e.id === pool?.activeId);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = all;
    if (source !== "all") list = list.filter((e) => e.source === source);
    if (onlyOk) list = list.filter((e) => e.health === "ok");
    if (q) {
      list = list.filter(
        (e) =>
          e.url.toLowerCase().includes(q) ||
          (e.label ?? "").toLowerCase().includes(q) ||
          (e.provider ?? "").toLowerCase().includes(q),
      );
    }
    return { shown: list.slice(0, 400), total: list.length, all: all.length };
  }, [all, source, onlyOk, query]);

  const usableTags = parsed ? schemeCount(parsed.stats.usable) : [];
  const nodeTags = parsed ? schemeCount(parsed.stats.nodes) : [];
  const extraNotes = parsed ? parsed.stats.notes.filter((n) => n !== parsed.note) : [];

  return (
    <div className="proxy-page">
      <div className="metric-row metric-row-sm">
        <div className="metric">
          <div className="metric-label">池里节点</div>
          <div className="metric-value">{all.length}</div>
          <div className="metric-foot">启用 {enabledCount} 条</div>
        </div>
        <div className="metric">
          <div className="metric-label">测活可用</div>
          <div className="metric-value">{okCount}</div>
          <div className="metric-foot">本机直连测，不走池</div>
        </div>
        <div className="metric">
          <div className="metric-label">付费配置</div>
          <div className="metric-value">{paidCount}</div>
          <div className="metric-foot">你导入的订阅</div>
        </div>
        <div className="metric">
          <div className="metric-label">免费 / 手填</div>
          <div className="metric-value">
            {freeCount} / {manualCount}
          </div>
          <div className="metric-foot">自动抓的公开节点</div>
        </div>
        <div className="metric">
          <div className="metric-label">当前出口</div>
          <div className="metric-value mono proxy-exit">
            {active ? maskUrl(active.url) : "未选"}
          </div>
          <div className="metric-foot">{fmtAgo(rotation?.lastRotatedAt)}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-top">
          <span className="card-title">自动换代理</span>
          <span className={`chip ${rotation?.enabled ? "chip-on" : "chip-ghost"} mono`}>
            {rotation?.enabled ? `${MODE_LABEL[rotation.mode]} · ${rotation.intervalSec}s` : "已关闭"}
          </span>
        </div>
        <div className="card-note">
          被封的时候自动换（比如目标回 403 / 429 / 验证页），也可以按时间自己换。轮换只改本程序拉起的那条引擎子进程，
          不动系统代理；换了之后引擎需要重启才吃新出口，勾上「换完重启引擎」就不用管。
        </div>

        <div className="rotate-grid">
          <label className="notify-switch">
            <input
              type="checkbox"
              checked={!!rotation?.enabled}
              disabled={!!busy}
              onChange={(e) => void patchRotation({ enabled: e.target.checked })}
            />
            <span>定时自动换</span>
          </label>
          <label className="notify-switch">
            <span>间隔</span>
            <select
              className="select sm"
              value={rotation?.intervalSec ?? 600}
              disabled={!!busy}
              onChange={(e) => void patchRotation({ intervalSec: Number(e.target.value) })}
            >
              {INTERVALS.map((s) => (
                <option key={s} value={s}>
                  {s >= 3600 ? `${s / 3600} 小时` : s >= 60 ? `${s / 60} 分钟` : `${s} 秒`}
                </option>
              ))}
            </select>
          </label>
          <div className="seg">
            {(Object.keys(MODE_LABEL) as ProxyRotationMode[]).map((m) => (
              <button
                key={m}
                className={`seg-btn ${rotation?.mode === m ? "on" : ""}`}
                onClick={() => void patchRotation({ mode: m })}
                disabled={!!busy}
                title={MODE_HINT[m]}
              >
                {MODE_LABEL[m]}
              </button>
            ))}
          </div>
          <label className="notify-switch">
            <input
              type="checkbox"
              checked={rotation?.onBan ?? true}
              disabled={!!busy}
              onChange={(e) => void patchRotation({ onBan: e.target.checked })}
            />
            <span>被封禁时自动切</span>
          </label>
          <label className="notify-switch">
            <input
              type="checkbox"
              checked={rotation?.restartEngine ?? true}
              disabled={!!busy}
              onChange={(e) => void patchRotation({ restartEngine: e.target.checked })}
            />
            <span>换完重启引擎</span>
          </label>
          <label className="pool-rotate">
            <input type="checkbox" checked={!!pool?.rotate} onChange={toggleRotate} disabled={!!busy} />
            <span>冷启动也随机挑一条</span>
          </label>
          <button className="btn sm primary" onClick={() => void rotateNow("manual")} disabled={!!busy || !all.length}>
            <Icon name="refresh" size={12} />
            <span>{busy === "rotate-now" ? "换路中…" : "立刻换一条"}</span>
          </button>
        </div>
        <div className="rotate-hint">{MODE_HINT[rotation?.mode ?? "smart"]}</div>
        <div className="proxy-tags">
          <span className="proxy-tag">付费配置 {paidCount}</span>
          <span className="proxy-tag">免费 {freeCount}</span>
          <span className="proxy-tag">手填 {manualCount}</span>
          {poolPath ? <span className="subtle mono">池文件：{poolPath}</span> : null}
        </div>
      </div>

      <div className="card">
        <div className="card-top">
          <span className="card-title">本机 Clash / mihomo 节点</span>
          <span className={`chip ${clash?.connected ? "chip-on" : "chip-ghost"} mono`}>
            {clash?.connected ? `已连 ${clash.controller ?? ""}` : "未连上控制口"}
          </span>
          <button className="btn sm" onClick={() => void refreshClash()} disabled={!!busy}>
            <Icon name="refresh" size={12} />
            <span>{busy === "clash-status" ? "连接中…" : "重新连接"}</span>
          </button>
        </div>
        <div className="card-note">
          订阅里的 vmess / ss / trojan 本程序拨不了，本机客户端能拨。这里直接切它的节点：出口 IP 立刻变，代理地址还是 mixed-port，引擎不用重启。风控触发「被封禁时自动切」也先走这里。
        </div>

        <div className="rotate-grid">
          <label className="notify-switch">
            <span>控制口</span>
            <input
              className="input mono"
              value={controller}
              placeholder="127.0.0.1:9090"
              onChange={(e) => setController(e.target.value)}
            />
          </label>
          <label className="notify-switch">
            <span>secret</span>
            <input
              className="input mono"
              type="password"
              value={secret}
              placeholder="没有就留空"
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
          <button className="btn sm" onClick={() => void saveController()} disabled={!!busy}>
            <Icon name="plug" size={12} />
            <span>{busy === "clash-ctl" ? "连接中…" : "连接控制口"}</span>
          </button>
          {clash?.groups?.length ? (
            <label className="notify-switch">
              <span>节点组</span>
              <select
                className="select sm"
                value={clash.group ?? ""}
                disabled={!!busy}
                onChange={(e) => void switchGroup(e.target.value)}
              >
                {clash.groups.slice(0, 40).map((g) => (
                  <option key={g.name} value={g.name}>
                    {g.name}（{g.nodes}）
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>

        {clash?.connected && liveNodes.length ? (
          <>
            <div className="rotate-grid">
              <label className="notify-switch pool-clash-pick">
                <span>当前节点</span>
                <select
                  className="select"
                  value={liveNodes.includes(clashNode) ? clashNode : liveNodes[0]}
                  disabled={!!busy}
                  onChange={(e) => void selectClashNode(e.target.value)}
                >
                  {liveNodes.map((n) => (
                    <option key={n} value={n}>
                      {n}
                      {clashDelays[n] ? ` · ${clashDelays[n]} ms` : ""}
                    </option>
                  ))}
                </select>
              </label>
              <button className="btn sm" onClick={() => void rotateClash()} disabled={!!busy}>
                <Icon name="refresh" size={12} />
                <span>{busy === "clash-rotate" ? "切换中…" : "切下一个"}</span>
              </button>
              <button className="btn sm primary" onClick={() => void fastestClash()} disabled={!!busy}>
                <Icon name="bolt" size={12} />
                <span>{busy === "clash-fastest" ? "测速中…" : "测速选最快"}</span>
              </button>
            </div>
            <div className="rotate-hint">
              组里共 {liveNodes.length} 个节点，当前 {clash.selected ?? "未知"}
              {clash.mode === "global" ? " · 客户端是全局模式，实际出口跟 GLOBAL 组走，已自动切 GLOBAL" : ""}
              {pool?.clash?.from ? ` · 控制口来自 ${fileName(pool.clash.from)}` : ""}
              {pool?.clash?.switchedAt ? ` · 上次切于 ${fmtAgo(pool.clash.switchedAt)}` : ""}
            </div>
          </>
        ) : (
          <div className="rotate-hint">
            {pool?.clash?.nodes?.length
              ? `配置里读到 ${pool.clash.nodes.length} 个节点，但还没连上控制口：在 Clash 里打开 external-controller（或把那份 config.yaml 里的地址填到上面）`
              : "导入带 proxies: 的 Clash / mihomo 配置后，这里会列出订阅里的全部节点，不用再手动填 7890"}
          </div>
        )}
        {clash?.error ? <div className="pool-stats pool-error">{clash.error}</div> : null}
      </div>

      <div className="card">
        <div className="card-top">
          <span className="card-title">导入代理配置</span>
          <span className="chip chip-ghost mono">{pool ? `${all.length} 条` : "读取中"}</span>
        </div>
        <div className="card-note">
          你给的付费订阅（Clash / mihomo 的 yaml、yml）拖进来就算「付费配置」；「自动找免费代理」抓来的算「免费节点」，两类分开看、分开测，
          互不覆盖。认不出的格式会交给 AI 抽地址。
        </div>

        <div
          className={`proxy-drop${dragging ? " is-over" : ""}${busy === "parse" ? " is-busy" : ""}`}
          onClick={pickFile}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            const file = e.dataTransfer.files?.[0];
            if (file) void dropFile(file);
            else setDragging(false);
          }}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              void pickFile();
            }
          }}
        >
          <Icon name="upload" size={20} />
          <div className="proxy-drop-title">{busy === "parse" ? "解析中…" : "把代理配置文件拖到这里"}</div>
          <div className="proxy-drop-sub">点这里也能选文件；付费订阅的 yml、txt、json 都行</div>
        </div>

        <div className="proxy-path">
          <input
            className="input mono"
            value={path}
            placeholder="C:\Users\你\.config\clash\profiles\xxxx.yml"
            onChange={(e) => setPath(e.target.value)}
            spellCheck={false}
          />
          <button className="btn sm" onClick={importPath} disabled={!!busy}>
            <Icon name="file" size={12} />
            <span>本地解析</span>
          </button>
          <button className="btn sm ghost" onClick={aiParse} disabled={!!busy}>
            <Icon name="bolt" size={12} />
            <span>{busy === "ai" ? "AI 解析中…" : "AI 解析"}</span>
          </button>
        </div>

        <textarea
          className="pool-text"
          value={text}
          placeholder={"也可以直接粘内容：\nmixed-port: 7890\nproxies:\n  - { name: 香港01, type: trojan, server: 1.2.3.4, port: 443, password: … }\n或者 base64 订阅串、一行一个 http://…"}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
        />

        <div className="pool-actions">
          <button className="btn sm" onClick={pasteImport} disabled={!!busy || !text.trim()}>
            <Icon name="plus" size={12} />
            <span>导入粘贴内容</span>
          </button>
          <button className="btn sm ghost" onClick={() => setText("")} disabled={!!busy || !text}>
            <Icon name="close" size={12} />
            <span>清掉内容</span>
          </button>
          <button className="btn sm ghost" onClick={fetchFree} disabled={!!busy}>
            <Icon name="radar" size={12} />
            <span>{busy === "free" ? "抓取中…" : "自动找免费代理"}</span>
          </button>
        </div>

        {notice ? <div className="pool-stats">{notice}</div> : null}
        {error ? <div className="pool-stats pool-error">{error}</div> : null}

        {parsed ? (
          <div className="proxy-parsed">
            <div className="proxy-parsed-head">
              <span className="chip chip-ghost">{KIND_LABEL[parsed.stats.kind] ?? parsed.stats.kind}</span>
              <span className="proxy-parsed-how">{parsed.how}</span>
            </div>
            <div className="proxy-parsed-row">
              <span className="kv-k">能直接拨</span>
              <span className="proxy-tags">
                {usableTags.length ? (
                  usableTags.map((t) => (
                    <span className="proxy-tag" key={t}>
                      {t}
                    </span>
                  ))
                ) : (
                  <span className="subtle">没有</span>
                )}
              </span>
            </div>
            <div className="proxy-parsed-row">
              <span className="kv-k">要客户端转发</span>
              <span className="proxy-tags">
                {nodeTags.length ? (
                  nodeTags.map((t) => (
                    <span className="proxy-tag" key={t}>
                      {t}
                    </span>
                  ))
                ) : (
                  <span className="subtle">没有</span>
                )}
              </span>
            </div>
            {parsed.stats.localPorts.length ? (
              <div className="proxy-parsed-row">
                <span className="kv-k">配置里的本机端口</span>
                <span className="proxy-tags">
                  {parsed.stats.localPorts.map((p) => (
                    <span className="proxy-tag" key={`${p.key}-${p.port}`}>
                      {p.key} {p.port} · {p.scheme}
                    </span>
                  ))}
                </span>
              </div>
            ) : null}
            {parsed.note ? (
              <div className="proxy-parsed-row">
                <span className="kv-k">AI 说明</span>
                <span className="proxy-note-text">{parsed.note}</span>
              </div>
            ) : null}
            {extraNotes.length ? (
              <ul className="proxy-notes">
                {extraNotes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
      </div>

      <div className="card">
        <div className="card-top">
          <span className="card-title">节点</span>
          <span className={`chip ${okCount ? "chip-on" : "chip-ghost"} mono`}>
            {okCount} 可用 / {all.length} 条
          </span>
        </div>

        <div className="proxy-toolbar">
          <div className="search find-search">
            <Icon name="search" size={13} />
            <input
              value={query}
              placeholder="搜地址 / 备注 / 来源"
              onChange={(e) => setQuery(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="seg">
            <button className={`seg-btn ${source === "all" ? "on" : ""}`} onClick={() => setSource("all")}>
              全部 · {all.length}
            </button>
            <button
              className={`seg-btn ${source === "config" ? "on" : ""}`}
              onClick={() => setSource("config")}
              title="你导入的付费订阅"
            >
              付费 · {paidCount}
            </button>
            <button className={`seg-btn ${source === "free" ? "on" : ""}`} onClick={() => setSource("free")} title="自动抓取的公开节点">
              免费 · {freeCount}
            </button>
            <button className={`seg-btn ${source === "manual" ? "on" : ""}`} onClick={() => setSource("manual")}>
              手填 · {manualCount}
            </button>
          </div>
          <button className="btn sm" onClick={testPool} disabled={!!busy || !all.length}>
            <Icon name="gauge" size={12} />
            <span>{busy === "test" ? "测活中…" : "全部测活"}</span>
          </button>
          <button className="btn sm" onClick={() => void testSpeed()} disabled={!!busy || !all.length}>
            <Icon name="bolt" size={12} />
            <span>{busy === "speed" ? `测速中 ${speed ? `${speed.done}/${speed.total}` : ""}` : "全部测速"}</span>
          </button>
          <button className="btn sm ghost" onClick={testNew} disabled={!!busy || !all.length}>
            <Icon name="cpu" size={12} />
            <span>{busy === "test-new" ? "测活中…" : "测最后导入的 20 条"}</span>
          </button>
          <label className="pool-rotate">
            <input type="checkbox" checked={onlyOk} onChange={(e) => setOnlyOk(e.target.checked)} />
            <span>只看可用</span>
          </label>
          <button className={`btn sm ${clearArmed ? "danger" : "ghost"}`} onClick={clearPool} disabled={!!busy || !all.length}>
            {clearArmed ? "确认清空" : "清空"}
          </button>
        </div>

        {!rows.all ? (
          <div className="card-note">池是空的。上面拖一份付费配置进来，或者点「自动找免费代理」。</div>
        ) : null}
        {rows.all && !rows.total ? (
          <div className="card-note">这个筛选下没有条目。去掉「只看可用」或换一档来源再看。</div>
        ) : null}

        <div className="pool-list">
          {rows.shown.map((e) => (
            <div key={e.id} className={`pool-row${e.enabled ? "" : " is-off"}${pool?.activeId === e.id ? " is-active" : ""}`}>
              <span className={`pool-health h-${e.health}`}>{HEALTH_LABEL[e.health] ?? e.health}</span>
              <span className="pool-url mono" title={maskUrl(e.url)}>
                {maskUrl(e.url)}
              </span>
              {e.label ? (
                <span className="pool-label" title={e.label}>
                  {e.label}
                </span>
              ) : null}
              <span className={`pool-src ${SOURCE_TONE[e.source]}`} title={e.provider ?? SOURCE_LABEL[e.source]}>
                {SOURCE_LABEL[e.source] ?? e.source}
                {e.provider ? ` · ${e.provider}` : ""}
              </span>
              {e.latencyMs != null ? <span className="pool-ms">{e.latencyMs} ms</span> : null}
              <span className="pool-speed mono" title="下载测速，只有代理能收到业务回包时才有数">
                {fmtSpeed(e.speedKbps)}
              </span>
              {e.failCount ? <span className="pool-fail mono" title="失败次数，智能选路会避开">失败 {e.failCount}</span> : null}
              {pool?.activeId === e.id ? <span className="chip chip-on">当前</span> : null}
              <span className="pool-row-actions">
                <button className="pool-mini" onClick={() => void testSpeed([e.id])} disabled={!!busy}>
                  {busy === `speed-${e.id}` ? "测速中" : "测速"}
                </button>
                <button className="pool-mini" onClick={() => void toggleEntry(e.id, !e.enabled)} disabled={!!busy}>
                  {e.enabled ? "停用" : "启用"}
                </button>
                <button className="pool-mini" onClick={() => void pickEntry(e.id)} disabled={!!busy || pool?.activeId === e.id}>
                  选它
                </button>
                <button className="pool-mini" onClick={() => void markFail(e)} disabled={!!busy} title="记一次失败，触发自动换">
                  记失败
                </button>
                <button className="pool-mini danger" onClick={() => void dropEntry(e.id)} disabled={!!busy}>
                  删除
                </button>
              </span>
            </div>
          ))}
        </div>

        {rows.total > rows.shown.length ? (
          <div className="card-note">
            只显示了前 {rows.shown.length} 条，共 {rows.total} 条。
          </div>
        ) : null}
      </div>
    </div>
  );
}
