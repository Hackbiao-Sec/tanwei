import React, { useEffect, useMemo, useState } from "react";
import type { ProxyImportResult, ProxyImportStats, ProxyPool as Pool } from "@shared/types";
import { Icon } from "./Icons";

const HEALTH_LABEL: Record<string, string> = { ok: "可用", bad: "不通", unknown: "未测" };
const SOURCE_LABEL: Record<string, string> = { config: "导入", free: "免费", manual: "手填" };
const KIND_LABEL: Record<string, string> = {
  clash: "Clash / mihomo",
  json: "JSON",
  list: "地址列表",
  base64: "base64 订阅",
  ai: "AI 解析",
  unknown: "未知格式",
};

const MAX_FILE = 8 * 1024 * 1024;

/** Electron 会把主进程抛的错包成 "Error invoking remote method 'x': Error: ..."，这里剥掉壳 */
function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

/** 地址里带的账密在界面上打码，完整值放 title */
function maskUrl(url: string): string {
  return url.replace(/\/\/[^@/]+@/, "//***@");
}

function schemeCount(record: Record<string, number>): string[] {
  return Object.entries(record).map(([key, n]) => `${key} ×${n}`);
}

function fileName(file: string): string {
  return file.split(/[\\/]/).pop() || file;
}

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

  useEffect(() => {
    let alive = true;
    window.tanwei
      .pool()
      .then((next) => {
        if (alive) setPool(next);
      })
      .catch((err) => {
        if (alive) setError(errText(err));
      });
    return () => {
      alive = false;
    };
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

  /** 先本地认格式；认不出来就把同一份内容交给 AI 再抽一遍 */
  async function parseLocally(input: { file?: string; text?: string }, label: string) {
    await run("parse", async () => {
      try {
        const res = await window.tanwei.importPoolPath(input);
        apply(res, `本地解析 · ${label}`);
      } catch (err) {
        const reason = errText(err);
        setNotice(`本地没认出这份格式，改让 AI 抽代理地址…`);
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
    // 新版 Electron 拿不到 File.path，有路径就走主进程读原文件，没有就传文本
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

  const rows = useMemo(() => {
    const list = onlyOk ? all.filter((e) => e.health === "ok") : all;
    return { shown: list.slice(0, 300), total: list.length, all: all.length };
  }, [pool, onlyOk]);

  const usableTags = parsed ? schemeCount(parsed.stats.usable) : [];
  const nodeTags = parsed ? schemeCount(parsed.stats.nodes) : [];
  // AI 的说明已经在上面单独一行，笔记列表里同一句不再重复显示
  const extraNotes = parsed ? parsed.stats.notes.filter((n) => n !== parsed.note) : [];

  return (
    <div className="proxy-page">
      <div className="card">
        <div className="card-top">
          <span className="card-title">导入代理配置</span>
          <span className="chip chip-ghost mono">{pool ? `${all.length} 条` : "读取中"}</span>
        </div>
        <div className="card-note">
          认 Clash / mihomo 的 yaml、yml，也认 JSON、地址列表、base64 订阅。以后碰到没见过的格式，本地认不出会自动交给 AI
          抽代理地址。
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
          <span className="pool-stats">
            池里 {all.length} 条 · 可用 {okCount} · 启用 {enabledCount}
          </span>
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
          <span className="card-title">代理池</span>
          <span className={`chip ${okCount ? "chip-on" : "chip-ghost"} mono`}>
            {pool ? `${okCount} 可用 / ${all.length} 条` : "读取中"}
          </span>
        </div>
        <div className="card-note">
          测活走本机直连，不经过池里的代理。选「选它」之后，配置页把代理模式设成「代理池」，引擎冷启动就会取这一条。
        </div>

        <div className="pool-actions">
          <button className="btn sm" onClick={testPool} disabled={!!busy || !all.length}>
            <Icon name="refresh" size={12} />
            <span>{busy === "test" ? "测活中…" : "全部测活"}</span>
          </button>
          <button className="btn sm ghost" onClick={testNew} disabled={!!busy || !all.length}>
            <Icon name="cpu" size={12} />
            <span>{busy === "test-new" ? "测活中…" : "测最后导入的 20 条"}</span>
          </button>
          <button className="btn sm ghost" onClick={fetchFree} disabled={!!busy}>
            <Icon name="radar" size={12} />
            <span>{busy === "free" ? "抓取中…" : "自动找免费代理"}</span>
          </button>
          <label className="pool-rotate">
            <input type="checkbox" checked={!!pool?.rotate} onChange={toggleRotate} disabled={!!busy} />
            <span>冷启动时轮换</span>
          </label>
          <label className="pool-rotate">
            <input type="checkbox" checked={onlyOk} onChange={(e) => setOnlyOk(e.target.checked)} />
            <span>只看可用</span>
          </label>
          <button
            className={`btn sm ${clearArmed ? "danger" : "ghost"}`}
            onClick={clearPool}
            disabled={!!busy || !all.length}
          >
            {clearArmed ? "确认清空" : "清空"}
          </button>
        </div>

        {!rows.all ? (
          <div className="card-note">池是空的。上面拖一份配置进来，或者点「自动找免费代理」。</div>
        ) : null}
        {rows.all && !rows.total ? (
          <div className="card-note">没有可用条目。去掉「只看可用」再看一遍，或者点「全部测活」。</div>
        ) : null}

        <div className="pool-list">
          {rows.shown.map((e) => (
            <div key={e.id} className={`pool-row${e.enabled ? "" : " is-off"}`}>
              <span className={`pool-health h-${e.health}`}>{HEALTH_LABEL[e.health] ?? e.health}</span>
              <span className="pool-url mono" title={maskUrl(e.url)}>
                {maskUrl(e.url)}
              </span>
              {e.label ? (
                <span className="pool-label" title={e.label}>
                  {e.label}
                </span>
              ) : null}
              <span className="pool-src">{SOURCE_LABEL[e.source] ?? e.source}</span>
              {e.latencyMs != null ? <span className="pool-ms">{e.latencyMs} ms</span> : null}
              {pool?.activeId === e.id ? <span className="chip chip-on">当前</span> : null}
              <span className="pool-row-actions">
                <button
                  className="pool-mini"
                  onClick={() => void toggleEntry(e.id, !e.enabled)}
                  disabled={!!busy}
                >
                  {e.enabled ? "停用" : "启用"}
                </button>
                <button
                  className="pool-mini"
                  onClick={() => void pickEntry(e.id)}
                  disabled={!!busy || pool?.activeId === e.id}
                >
                  选它
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
