import React, { useEffect, useMemo, useRef, useState } from "react";
import type { HttpResponseView, SessionState } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const STORAGE_PREFIX = "tanwei.traffic.v2:";
const MAX_ITEMS = 40;
const MAX_BODY = 120_000;

type TrafficItem = {
  id: string;
  sessionId: string;
  method: string;
  url: string;
  headers: string;
  body: string;
  follow: boolean;
  status: number;
  statusText: string;
  ms: number;
  at: number;
  bytes: number;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  finalUrl?: string;
  error?: string;
};

function storeKey(sessionId: string): string {
  return `${STORAGE_PREFIX}${sessionId}`;
}

function readItems(sessionId: string): TrafficItem[] {
  try {
    const raw = window.localStorage.getItem(storeKey(sessionId));
    if (!raw) return [];
    const list = JSON.parse(raw);
    return Array.isArray(list) ? (list as TrafficItem[]) : [];
  } catch {
    return [];
  }
}

function writeItems(sessionId: string, items: TrafficItem[]): void {
  try {
    window.localStorage.setItem(storeKey(sessionId), JSON.stringify(items.slice(0, MAX_ITEMS)));
  } catch {
    // 存储满了就只留内存，界面照样能用
  }
}

/** 总览：把每个会话各自的记录捞出来，带上会话名 */
function readAllItems(): TrafficItem[] {
  const out: TrafficItem[] = [];
  try {
    for (let i = 0; i < window.localStorage.length; i++) {
      const key = window.localStorage.key(i);
      if (!key || !key.startsWith(STORAGE_PREFIX)) continue;
      const sid = key.slice(STORAGE_PREFIX.length);
      for (const item of readItems(sid)) out.push({ ...item, sessionId: sid });
    }
  } catch {
    /* 读不到就按空处理 */
  }
  return out.sort((a, b) => b.at - a.at).slice(0, 200);
}

function statusClass(status: number): string {
  if (status === 0) return "st-err";
  if (status < 300) return "st-ok";
  if (status < 400) return "st-redir";
  if (status < 500) return "st-warn";
  return "st-err";
}

function fmtBytes(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function clock(t: number): string {
  return new Date(t).toLocaleTimeString("zh-CN", { hour12: false });
}

function shortPath(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}${u.search}`;
  } catch {
    return url;
  }
}

function headerText(map?: Record<string, string>): string {
  if (!map) return "";
  return Object.entries(map)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

type Range = "全部" | "2xx" | "3xx" | "4xx" | "5xx" | "失败";

function inRange(item: TrafficItem, range: Range): boolean {
  if (range === "全部") return true;
  if (range === "失败") return item.status === 0 || Boolean(item.error);
  if (item.status === 0) return false;
  return `${Math.floor(item.status / 100)}xx` === range;
}

export function Traffic({ activeId, live = [] }: { activeId?: string; live?: SessionState[] }) {
  const sessionId = activeId ?? "local";
  const [items, setItems] = useState<TrafficItem[]>([]);
  const [allItems, setAllItems] = useState<TrafficItem[]>([]);
  const [scope, setScope] = useState<"session" | "all">("session");
  const [range, setRange] = useState<Range>("全部");
  const [query, setQuery] = useState("");
  const [active, setActive] = useState<string>();
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("https://");
  const [headers, setHeaders] = useState("User-Agent: Mozilla/5.0\nAccept: */*");
  const [body, setBody] = useState("");
  const [follow, setFollow] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string>();
  const [reqTab, setReqTab] = useState<"headers" | "body" | "curl">("headers");
  const [resTab, setResTab] = useState<"body" | "headers" | "raw">("body");
  const [copied, setCopied] = useState("");
  const inited = useRef(false);

  // 切会话立刻换成那个会话自己的记录
  useEffect(() => {
    const own = readItems(sessionId);
    setItems(own);
    setActive(own[0]?.id);
    setAllItems(scope === "all" ? readAllItems() : []);
    inited.current = true;
    if (own[0]) {
      setMethod(own[0].method);
      setUrl(own[0].url);
      setHeaders(own[0].headers);
      setBody(own[0].body);
      setFollow(own[0].follow);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  useEffect(() => {
    if (scope === "all") setAllItems(readAllItems());
  }, [scope, items]);

  const titleOf = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of live) map.set(s.id, s.title || s.id.slice(0, 8));
    return map;
  }, [live]);

  const rows = useMemo(() => {
    const source = scope === "session" ? items : allItems;
    const q = query.trim().toLowerCase();
    return source.filter((item) => {
      if (!inRange(item, range)) return false;
      if (!q) return true;
      return (
        item.url.toLowerCase().includes(q) ||
        item.method.toLowerCase().includes(q) ||
        String(item.status).includes(q)
      );
    });
  }, [scope, items, allItems, range, query]);

  const current = useMemo(() => {
    const pool = scope === "session" ? items : allItems;
    return pool.find((i) => i.id === active) ?? rows[0];
  }, [scope, items, allItems, active, rows]);

  const curl = useMemo(() => {
    const parts = [`curl -i -X ${method} '${url}'`];
    for (const line of headers.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const idx = line.indexOf(":");
      if (idx <= 0) continue;
      parts.push(`-H '${line.slice(0, idx).trim()}: ${line.slice(idx + 1).trim()}'`);
    }
    if (body && method !== "GET" && method !== "HEAD") parts.push(`--data '${body.replace(/'/g, "'\\''")}'`);
    if (!follow) parts.push("--max-redirs 0");
    return parts.join(" \\\n  ");
  }, [method, url, headers, body, follow]);

  const flash = (tag: string) => {
    setCopied(tag);
    window.setTimeout(() => setCopied(""), 1200);
  };

  const send = async () => {
    if (sending) return;
    if (!/^https?:\/\//i.test(url.trim())) {
      setError("URL 要以 http:// 或 https:// 开头");
      return;
    }
    setSending(true);
    setError(undefined);
    try {
      const res: HttpResponseView = await window.tanwei.sendRequest({
        method,
        url: url.trim(),
        headers,
        body,
        followRedirects: follow,
      });
      const item: TrafficItem = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        sessionId,
        method,
        url: url.trim(),
        headers,
        body,
        follow,
        status: res.status || 0,
        statusText: res.statusText,
        ms: res.ms,
        at: Date.now(),
        bytes: res.bodyBytes,
        finalUrl: res.finalUrl,
        responseHeaders: res.headers,
        responseBody: (res.body ?? "").slice(0, MAX_BODY),
        error: res.error,
      };
      const next = [item, ...items].slice(0, MAX_ITEMS);
      setItems(next);
      writeItems(sessionId, next);
      if (scope === "all") setAllItems(readAllItems());
      setActive(item.id);
      if (res.error) setError(res.error);
      else setError(undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSending(false);
    }
  };

  const loadItem = (item: TrafficItem) => {
    setActive(item.id);
    setMethod(item.method);
    setUrl(item.url);
    setHeaders(item.headers);
    setBody(item.body);
    setFollow(item.follow);
    setError(item.error);
    setResTab("body");
  };

  const clearSession = () => {
    setItems([]);
    writeItems(sessionId, []);
    setActive(undefined);
    if (scope === "all") setAllItems(readAllItems());
  };

  const res = current;
  const rawResponse = res
    ? `HTTP/1.1 ${res.status} ${res.statusText}\n${headerText(res.responseHeaders)}\n\n${res.responseBody ?? ""}`
    : "";

  return (
    <div className="traffic-yk">
      <div className="tr-bar">
        <span className="tr-scope-tag">
          <Icon name="chat" size={12} />
          {scope === "session" ? "只看本会话" : "总览：全部会话"}
        </span>
        <div className="seg">
          <button className={`seg-btn ${scope === "session" ? "on" : ""}`} onClick={() => setScope("session")}>
            本会话 · {items.length}
          </button>
          <button className={`seg-btn ${scope === "all" ? "on" : ""}`} onClick={() => setScope("all")}>
            总览 · {allItems.length}
          </button>
        </div>
        <div className="seg">
          {(["全部", "2xx", "3xx", "4xx", "5xx", "失败"] as Range[]).map((r) => (
            <button key={r} className={`seg-btn ${range === r ? "on" : ""}`} onClick={() => setRange(r)}>
              {r}
            </button>
          ))}
        </div>
        <div className="search tr-search">
          <Icon name="search" size={13} />
          <input value={query} placeholder="搜 URL / 方法 / 状态码" onChange={(e) => setQuery(e.target.value)} />
        </div>
        <span className="tr-count mono">{rows.length} 条</span>
        <button className="panel-link" onClick={() => void copyText(curl).then(() => flash("curl"))}>
          <Icon name={copied === "curl" ? "check" : "copy"} size={12} /> {copied === "curl" ? "已复制 cURL" : "复制 cURL"}
        </button>
        <button className="panel-link" onClick={clearSession} disabled={items.length === 0}>
          <Icon name="close" size={12} /> 清空本会话
        </button>
      </div>

      <div className="tr-split">
        <aside className="tr-hist">
          <div className="tr-hist-head">
            <span>请求历史</span>
            <span className="mono subtle">本会话 {items.length}</span>
          </div>
          <div className="tr-hist-list">
            {rows.length === 0 ? (
              <div className="panel-empty">
                {scope === "session"
                  ? "这个会话还没发过请求。换会话看别的历史点上面「总览」。"
                  : "还没有任何会话的请求记录。"}
              </div>
            ) : (
              rows.map((item) => (
                <button
                  key={item.id}
                  className={`tr-hist-row ${current?.id === item.id ? "on" : ""}`}
                  onClick={() => loadItem(item)}
                >
                  <span className={`status-pill ${statusClass(item.status)}`}>{item.status || "ERR"}</span>
                  <span className="tr-hist-method mono">{item.method}</span>
                  <span className="tr-hist-url mono" title={item.url}>
                    {shortPath(item.url)}
                  </span>
                  <span className="tr-hist-meta mono subtle">
                    {item.ms} ms · {clock(item.at)}
                  </span>
                  {scope === "all" ? (
                    <span className="tr-hist-sess mono">{titleOf.get(item.sessionId) ?? item.sessionId.slice(0, 8)}</span>
                  ) : null}
                </button>
              ))
            )}
          </div>
        </aside>

        <section className="tr-req">
          <header className="tr-pane-head">
            <span>
              <Icon name="send" size={13} />
              请求
            </span>
            <div className="seg seg-sm">
              <button className={`seg-btn ${reqTab === "headers" ? "on" : ""}`} onClick={() => setReqTab("headers")}>
                请求头
              </button>
              <button className={`seg-btn ${reqTab === "body" ? "on" : ""}`} onClick={() => setReqTab("body")}>
                请求体
              </button>
              <button className={`seg-btn ${reqTab === "curl" ? "on" : ""}`} onClick={() => setReqTab("curl")}>
                cURL
              </button>
            </div>
            <button className="panel-link" onClick={() => void copyText(curl).then(() => flash("curl2"))}>
              <Icon name={copied === "curl2" ? "check" : "copy"} size={12} /> {copied === "curl2" ? "已复制" : "复制"}
            </button>
          </header>
          <div className="tr-req-line">
            <select value={method} onChange={(e) => setMethod(e.target.value)} className="method-select">
              {METHODS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <input
              className="req-url mono"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) void send();
              }}
              spellCheck={false}
            />
            <button className="btn primary" onClick={() => void send()} disabled={sending}>
              <Icon name="send" size={13} />
              <span>{sending ? "发送中…" : "发送"}</span>
            </button>
          </div>
          <div className="tr-req-body">
            {reqTab === "headers" ? (
              <textarea
                className="input mono tr-area"
                value={headers}
                spellCheck={false}
                placeholder="一行一个 Name: Value"
                onChange={(e) => setHeaders(e.target.value)}
              />
            ) : reqTab === "body" ? (
              <textarea
                className="input mono tr-area"
                value={body}
                spellCheck={false}
                placeholder={method === "GET" || method === "HEAD" ? "GET / HEAD 不带请求体" : '{"key":"value"}'}
                onChange={(e) => setBody(e.target.value)}
              />
            ) : (
              <pre className="tr-raw mono">{curl}</pre>
            )}
          </div>
          <footer className="tr-req-foot">
            <label className="check">
              <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
              <span>跟随重定向</span>
            </label>
            <span className="subtle">Ctrl + Enter 直接发送</span>
            <span className="subtle">历史按会话存盘，各会话互不可见</span>
          </footer>
          {error ? <div className="module-error">{error}</div> : null}
        </section>

        <section className="tr-res">
          <header className="tr-pane-head">
            <span>
              <Icon name="layers" size={13} />
              响应
            </span>
            {res ? (
              <span className="tr-res-meta">
                <span className={`status-pill ${statusClass(res.status)}`}>
                  {res.status || "ERR"} {res.statusText}
                </span>
                <span className="mono subtle">{res.ms} ms</span>
                <span className="mono subtle">{fmtBytes(res.bytes)}</span>
              </span>
            ) : null}
            <div className="seg seg-sm">
              <button className={`seg-btn ${resTab === "body" ? "on" : ""}`} onClick={() => setResTab("body")}>
                正文
              </button>
              <button className={`seg-btn ${resTab === "headers" ? "on" : ""}`} onClick={() => setResTab("headers")}>
                响应头
              </button>
              <button className={`seg-btn ${resTab === "raw" ? "on" : ""}`} onClick={() => setResTab("raw")}>
                原始
              </button>
            </div>
            <button
              className="panel-link"
              disabled={!res}
              onClick={() => void copyText(res?.responseBody ?? "").then(() => flash("body"))}
            >
              <Icon name={copied === "body" ? "check" : "copy"} size={12} /> {copied === "body" ? "已复制" : "复制"}
            </button>
          </header>
          <div className="tr-res-body">
            {!res ? (
              <div className="panel-empty">发一个请求，或者点左边历史里的一条回看结果。</div>
            ) : res.error ? (
              <div className="module-error">{res.error}</div>
            ) : (
              <>
                <div className="tr-res-url mono" title={res.finalUrl || res.url}>
                  {res.finalUrl || res.url}
                </div>
                {resTab === "body" ? (
                  <pre className="tr-raw mono">{res.responseBody || "（空正文）"}</pre>
                ) : resTab === "headers" ? (
                  <pre className="tr-raw mono">{headerText(res.responseHeaders) || "（没有响应头）"}</pre>
                ) : (
                  <pre className="tr-raw mono">{rawResponse}</pre>
                )}
              </>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
