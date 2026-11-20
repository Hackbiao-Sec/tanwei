import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MutableRefObject,
  type PointerEvent as ReactPointerEvent,
} from "react";
import type { NetworkStatus, RawHeaderPair, RawTlsInfo, SessionState } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";

/* ==========================================================================
   流量 · 数据包重放
   报文按字节原样发出：重复头、头序、大小写、手写 Content-Length 都保留。
   发送走主进程 rawHttp（node:net / tls / http2），不经过 fetch。
   ========================================================================== */

const ITEM_PREFIX = "tanwei.traffic.v3:";
const TAB_PREFIX = "tanwei.traffic.tabs.v3:";
const MAX_ITEMS = 30;
const MAX_TABS = 8;
const MAX_SAVED_BODY = 80_000;
const MAX_SAVED_B64 = 32_000;
const MAX_TAB_RAW = 200_000;
const MAX_DIFF_LINES = 700;

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"];

/* 历史条上的方法色块：只按语义分色，认不出的当 other */
function methodTone(method: string): string {
  switch ((method || "").toUpperCase()) {
    case "GET":
    case "HEAD":
      return "get";
    case "POST":
      return "post";
    case "PUT":
    case "PATCH":
      return "put";
    case "DELETE":
      return "del";
    case "OPTIONS":
    case "TRACE":
      return "opt";
    default:
      return "other";
  }
}

/* 工作区形态：历史侧栏宽 + 请求/响应上下分栏比例，按窗口记住 */
const UI_KEY = "tanwei.traffic.ui.v1";
type UiPrefs = { railW: number; split: number };

function readUi(): UiPrefs {
  const fallback: UiPrefs = { railW: 300, split: 52 };
  try {
    const raw = localStorage.getItem(UI_KEY);
    if (!raw) return fallback;
    const v = JSON.parse(raw) as Partial<UiPrefs>;
    const railW = Number(v.railW);
    const split = Number(v.split);
    return {
      railW: Number.isFinite(railW) ? Math.min(Math.max(railW, 220), 640) : fallback.railW,
      split: Number.isFinite(split) ? Math.min(Math.max(split, 20), 82) : fallback.split,
    };
  } catch {
    return fallback;
  }
}

function writeUi(prefs: UiPrefs): void {
  try {
    localStorage.setItem(UI_KEY, JSON.stringify(prefs));
  } catch {
    /* 隐私模式下写不进去，忽略 */
  }
}

const DEFAULT_RAW = [
  "GET / HTTP/1.1",
  "Host: example.com",
  "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Accept: */*",
  "Connection: close",
].join("\n");

type Version = "1.1" | "2";
type Scheme = "auto" | "http" | "https";

type Tab = {
  id: string;
  raw: string;
  version: Version;
  scheme: Scheme;
  follow: boolean;
  skipTls: boolean;
  useProxy: boolean;
  timeoutMs: number;
};

type TrafficItem = {
  id: string;
  sessionId: string;
  raw: string;
  version: Version;
  method: string;
  url: string;
  status: number;
  statusText: string;
  httpVersion: string;
  headers: RawHeaderPair[];
  body: string;
  bodyBase64: string;
  bodyBytes: number;
  wireBytes: number;
  decompressed: boolean;
  binary: boolean;
  truncated: boolean;
  ms: number;
  at: number;
  tls?: RawTlsInfo;
  remote?: string;
  proxy?: string;
  redirects: { status: number; location: string }[];
  error?: string;
};

type Range = "全部" | "2xx" | "3xx" | "4xx" | "5xx" | "失败";
type ReqMode = "raw" | "form";
type ResView = "body" | "render" | "headers" | "raw" | "hex" | "diff";
type TextEnc = "auto" | "utf-8" | "gbk" | "big5" | "shift_jis";

/* ---------------------------- 原始报文编辑器 ---------------------------- */

type RawKind = "req" | "head" | "blank" | "body";

const RAW_REQ = /^([A-Za-z]+)\s+(\S+)(?:\s+(HTTP\/[\d.]+))?\s*$/;
const RAW_HEAD = /^([^:\s]+)(:)([\s\S]*)$/;

/* 每行只定性一次：请求行、头、空行、正文。着色只影响显示，报文本身不改 */
function classifyRaw(text: string): { kind: RawKind; text: string }[] {
  const lines = text.split("\n");
  let inHead = true;
  return lines.map((line, i) => {
    if (!inHead) return { kind: "body" as RawKind, text: line };
    if (line.trim() === "") {
      inHead = false;
      return { kind: "blank" as RawKind, text: line };
    }
    if (i === 0 && RAW_REQ.test(line)) return { kind: "req" as RawKind, text: line };
    if (RAW_HEAD.test(line)) return { kind: "head" as RawKind, text: line };
    return { kind: "body" as RawKind, text: line };
  });
}

function RawLineBody({ kind, text }: { kind: RawKind; text: string }) {
  if (kind === "req") {
    const m = RAW_REQ.exec(text);
    if (m) {
      return (
        <>
          <span className="tk-m">{m[1]}</span>
          <span className="tk-sp"> </span>
          <span className="tk-u">{m[2]}</span>
          {m[3] ? (
            <>
              <span className="tk-sp"> </span>
              <span className="tk-v">{m[3]}</span>
            </>
          ) : null}
        </>
      );
    }
  }
  if (kind === "head") {
    const m = RAW_HEAD.exec(text);
    if (m) {
      return (
        <>
          <span className="tk-k">{m[1]}</span>
          <span className="tk-col">{m[2]}</span>
          <span className="tk-val">{m[3]}</span>
        </>
      );
    }
  }
  const parts = text.split(/("(?:\\.|[^"\\])*")/g);
  return (
    <>
      {parts.map((p, i) =>
        p.startsWith('"') ? (
          <span key={i} className="tk-str">
            {p}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}

/* 着色层与输入层用同一套字号行高叠在一起，文本域透明只留光标，行号槽跟着纵向滚 */
function RawEditor(props: {
  value: string;
  onChange: (v: string) => void;
  onBlur?: () => void;
  onKeyDown?: (e: ReactKeyboardEvent<HTMLTextAreaElement>) => void;
  areaRef: MutableRefObject<HTMLTextAreaElement | null>;
}) {
  const preRef = useRef<HTMLPreElement | null>(null);
  const numsRef = useRef<HTMLDivElement | null>(null);
  const lines = useMemo(() => classifyRaw(props.value), [props.value]);

  const syncScroll = () => {
    const ta = props.areaRef.current;
    if (!ta) return;
    if (preRef.current) {
      preRef.current.scrollTop = ta.scrollTop;
      preRef.current.scrollLeft = ta.scrollLeft;
    }
    if (numsRef.current) numsRef.current.scrollTop = ta.scrollTop;
  };

  return (
    <div className="tr-raw-ed">
      <div className="tr-raw-nums" ref={numsRef} aria-hidden>
        {lines.map((_, i) => (
          <div key={i}>{i + 1}</div>
        ))}
      </div>
      <div className="tr-raw-pane">
        <pre className="tr-raw-mark" ref={preRef} aria-hidden>
          {lines.map((l, i) => (
            <div key={i} className={`tr-raw-line tk-${l.kind}`}>
              <RawLineBody kind={l.kind} text={l.text} />
            </div>
          ))}
        </pre>
        <textarea
          ref={props.areaRef}
          className="tr-area mono tr-raw-input"
          wrap="off"
          spellCheck={false}
          value={props.value}
          onChange={(e) => {
            props.onChange(e.target.value);
            syncScroll();
          }}
          onBlur={props.onBlur}
          onKeyDown={props.onKeyDown}
          onScroll={syncScroll}
        />
      </div>
    </div>
  );
}

/* ------------------------------ 报文工具 ------------------------------ */

function splitRaw(text: string): { head: string; body: string } {
  const norm = text.replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  if (idx < 0) return { head: norm, body: "" };
  return { head: norm.slice(0, idx), body: norm.slice(idx + 2) };
}

function parseDraft(raw: string): {
  method: string;
  target: string;
  version: string;
  headerText: string;
  body: string;
} {
  const { head, body } = splitRaw(raw);
  const lines = head.split("\n");
  const parts = (lines[0] ?? "").trim().split(/\s+/);
  return {
    method: parts[0] ?? "",
    target: parts[1] ?? "",
    version: parts[2] ?? "HTTP/1.1",
    headerText: lines.slice(1).join("\n"),
    body,
  };
}

function headerValueOf(raw: string, name: string): string | undefined {
  const lower = name.toLowerCase();
  const { head } = splitRaw(raw);
  let found: string | undefined;
  for (const line of head.split("\n").slice(1)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    if (line.slice(0, idx).trim().toLowerCase() === lower) found = line.slice(idx + 1).trim();
  }
  return found;
}

/** 从报文推导目标地址：请求行写绝对 URL 就用它，否则用 Host 头 + 协议选择 */
function deriveUrl(raw: string, scheme: Scheme = "auto", version: Version = "1.1"): string {
  const { target } = parseDraft(raw);
  if (/^https?:\/\//i.test(target)) return target;
  const host = headerValueOf(raw, "host");
  if (!host) return "";
  const proto =
    scheme === "http" || scheme === "https"
      ? scheme
      : /:443$/.test(host) || version === "2"
        ? "https"
        : "http";
  const path = target.startsWith("/") ? target : `/${target}`;
  return `${proto}://${host}${path}`;
}

function setTarget(raw: string, url: string): string {
  const { head, body } = splitRaw(raw);
  const lines = head.split("\n");
  const parts = (lines[0] ?? "").trim().split(/\s+/);
  const method = parts[0] || "GET";
  const version = parts[2] || "HTTP/1.1";
  lines[0] = `${method} ${url} ${version}`;
  // 地址栏改成绝对 URL 时同步 Host 头，否则报文里会留着上一个站点的 Host
  const authority = /^https?:\/\/([^/?#]+)/i.exec(url.trim());
  if (authority) {
    const host = authority[1].replace(/:(80|443)$/, "");
    const at = lines.findIndex((line, i) => i > 0 && /^host\s*:/i.test(line));
    if (at > 0) lines[at] = `Host: ${host}`;
    else lines.splice(1, 0, `Host: ${host}`);
  }
  return body ? `${lines.join("\n")}\n\n${body}` : lines.join("\n");
}

function setMethod(raw: string, method: string): string {
  const { head, body } = splitRaw(raw);
  const lines = head.split("\n");
  const parts = (lines[0] ?? "").trim().split(/\s+/);
  const target = parts[1] || "/";
  const version = parts[2] || "HTTP/1.1";
  lines[0] = `${method || "GET"} ${target} ${version}`;
  return body ? `${lines.join("\n")}\n\n${body}` : lines.join("\n");
}

function applyHeaders(raw: string, headerText: string): string {
  const { head, body } = splitRaw(raw);
  const requestLine = head.split("\n")[0] ?? "GET / HTTP/1.1";
  const kept = headerText
    .replace(/\r\n/g, "\n")
    .split("\n")
    .filter((line) => line.trim().length > 0);
  const next = [requestLine, ...kept].join("\n");
  return body ? `${next}\n\n${body}` : next;
}

function applyBody(raw: string, bodyText: string): string {
  const { head } = splitRaw(raw);
  return `${head}\n\n${bodyText}`;
}

function bytesOf(text: string): number {
  return new TextEncoder().encode(text).length;
}

function tabTitle(raw: string): string {
  const { method, target } = parseDraft(raw);
  let path = target || "/";
  if (/^https?:\/\//i.test(path)) {
    try {
      const u = new URL(path);
      path = u.pathname + u.search;
    } catch {
      /* 保持原样 */
    }
  }
  const host = headerValueOf(raw, "host") ?? "";
  const label = `${method || "GET"} ${path}`;
  return host ? `${label} · ${host}` : label;
}

function shortPath(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}${u.search}`;
  } catch {
    return url;
  }
}

function buildCurl(raw: string, follow: boolean, skipTls: boolean, origin: string): string {
  const { method, target, headerText, body } = parseDraft(raw);
  let url = target;
  if (!/^https?:\/\//i.test(url)) {
    try {
      url = new URL(target.startsWith("/") ? target : `/${target}`, origin).toString();
    } catch {
      url = origin || target;
    }
  }
  const parts = ["curl -i", `-X ${method || "GET"}`, `'${url}'`];
  for (const line of headerText.split("\n")) {
    if (!line.trim()) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    if (name.toLowerCase() === "content-length") continue;
    parts.push(`-H '${line.trim().replace(/'/g, "'\\''")}'`);
  }
  if (body) parts.push(`--data-raw '${body.replace(/'/g, "'\\''")}'`);
  if (!follow) parts.push("--max-redirs 0");
  if (skipTls) parts.push("-k");
  return parts.join(" \\\n  ");
}

function base64ToBytes(b64: string): Uint8Array {
  try {
    const bin = window.atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array();
  }
}

function hexDump(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const rows: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.subarray(off, off + 16);
    const hex: string[] = [];
    const ascii: string[] = [];
    for (let i = 0; i < 16; i++) {
      const b = i < slice.length ? slice[i] : undefined;
      hex.push(b === undefined ? "  " : b.toString(16).padStart(2, "0"));
      if (b === undefined) ascii.push(" ");
      else ascii.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".");
    }
    rows.push(`${off.toString(16).padStart(8, "0")}  ${hex.slice(0, 8).join(" ")}  ${hex.slice(8).join(" ")}  |${ascii.join("")}|`);
  }
  return rows.join("\n");
}

function prettyJson(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return text;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return text;
  }
}

type DiffRow = { kind: "same" | "add" | "del"; text: string };

function diffLines(left: string, right: string): DiffRow[] {
  const a = left.replace(/\r\n/g, "\n").split("\n").slice(0, MAX_DIFF_LINES);
  const b = right.replace(/\r\n/g, "\n").split("\n").slice(0, MAX_DIFF_LINES);
  const n = a.length;
  const m = b.length;
  const dp = new Int32Array((n + 1) * (m + 1));
  const at = (i: number, j: number) => i * (m + 1) + j;
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[at(i, j)] =
        a[i] === b[j]
          ? dp[at(i + 1, j + 1)] + 1
          : Math.max(dp[at(i + 1, j)], dp[at(i, j + 1)]);
    }
  }
  const rows: DiffRow[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      rows.push({ kind: "same", text: a[i] });
      i++;
      j++;
    } else if (dp[at(i + 1, j)] >= dp[at(i, j + 1)]) {
      rows.push({ kind: "del", text: a[i] });
      i++;
    } else {
      rows.push({ kind: "add", text: b[j] });
      j++;
    }
  }
  while (i < n) {
    rows.push({ kind: "del", text: a[i] });
    i++;
  }
  while (j < m) {
    rows.push({ kind: "add", text: b[j] });
    j++;
  }
  return rows;
}

/* ------------------------------ 存盘 ------------------------------ */

function makeTab(raw = DEFAULT_RAW): Tab {
  return {
    id: `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    raw,
    version: "1.1",
    scheme: "auto",
    follow: true,
    skipTls: true,
    useProxy: false,
    timeoutMs: 30_000,
  };
}

function storeKey(sessionId: string): string {
  return `${ITEM_PREFIX}${sessionId}`;
}

function toStored(item: TrafficItem): TrafficItem {
  return {
    ...item,
    body: item.body.slice(0, MAX_SAVED_BODY),
    bodyBase64: item.bodyBase64.slice(0, MAX_SAVED_B64),
  };
}

function readItems(sessionId: string): TrafficItem[] {
  try {
    const raw = window.localStorage.getItem(storeKey(sessionId));
    if (!raw) return [];
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return [];
    return list.filter((item) => item && typeof item.id === "string" && typeof item.raw === "string");
  } catch {
    return [];
  }
}

function writeItems(sessionId: string, items: TrafficItem[]): void {
  const payload = items.slice(0, MAX_ITEMS).map(toStored);
  try {
    window.localStorage.setItem(storeKey(sessionId), JSON.stringify(payload));
  } catch {
    try {
      window.localStorage.setItem(storeKey(sessionId), JSON.stringify(payload.slice(0, 8)));
    } catch {
      /* 存储写不进就只留内存 */
    }
  }
}

function readAllItems(): TrafficItem[] {
  const out: TrafficItem[] = [];
  try {
    for (let i = 0; i < window.localStorage.length; i++) {
      const key = window.localStorage.key(i);
      if (!key || !key.startsWith(ITEM_PREFIX)) continue;
      const sid = key.slice(ITEM_PREFIX.length);
      for (const item of readItems(sid)) out.push({ ...item, sessionId: sid });
    }
  } catch {
    /* 读不到按空处理 */
  }
  return out.sort((a, b) => b.at - a.at).slice(0, 200);
}

function readTabs(sessionId: string): Tab[] {
  try {
    const raw = window.localStorage.getItem(`${TAB_PREFIX}${sessionId}`);
    if (!raw) return [];
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return [];
    return list
      .filter((t) => t && typeof t.raw === "string")
      .slice(0, MAX_TABS)
      .map((t) => ({
        id: typeof t.id === "string" ? t.id : makeTab().id,
        raw: String(t.raw),
        version: t.version === "2" ? ("2" as const) : ("1.1" as const),
        scheme: t.scheme === "http" || t.scheme === "https" ? (t.scheme as Scheme) : ("auto" as const),
        follow: t.follow !== false,
        skipTls: t.skipTls !== false,
        useProxy: Boolean(t.useProxy),
        timeoutMs: typeof t.timeoutMs === "number" ? t.timeoutMs : 30_000,
      }));
  } catch {
    return [];
  }
}

function writeTabs(sessionId: string, tabs: Tab[]): void {
  try {
    const payload = tabs.slice(0, MAX_TABS).map((t) => ({ ...t, raw: t.raw.slice(0, MAX_TAB_RAW) }));
    window.localStorage.setItem(`${TAB_PREFIX}${sessionId}`, JSON.stringify(payload));
  } catch {
    /* 存不下就算了，标签还在内存里 */
  }
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

function inRange(item: TrafficItem, range: Range): boolean {
  if (range === "全部") return true;
  if (range === "失败") return item.status === 0 || Boolean(item.error);
  if (item.status === 0) return false;
  return `${Math.floor(item.status / 100)}xx` === range;
}

function tlsLine(tls?: RawTlsInfo): string {
  if (!tls) return "";
  const bits = [tls.protocol, tls.cipher, tls.alpn ? `ALPN ${tls.alpn}` : ""].filter(Boolean);
  const subject = tls.subject ? `CN=${tls.subject}` : "";
  const issuer = tls.issuer ? `签发 ${tls.issuer}` : "";
  const valid = tls.validTo ? `到期 ${tls.validTo}` : "";
  const auth = tls.authorized ? "证书校验通过" : "未校验证书";
  return [...bits, subject, issuer, valid, auth].filter(Boolean).join(" · ");
}

/* ------------------------------ 组件 ------------------------------ */

export function Traffic({ activeId, live = [] }: { activeId?: string; live?: SessionState[] }) {
  const sessionId = activeId ?? "local";
  const [items, setItems] = useState<TrafficItem[]>([]);
  const [allItems, setAllItems] = useState<TrafficItem[]>([]);
  const [tabs, setTabs] = useState<Tab[]>(() => [makeTab()]);
  const [activeTabId, setActiveTabId] = useState<string>("");
  const [activeItemId, setActiveItemId] = useState<string>();
  const [scope, setScope] = useState<"session" | "all">("session");
  const [range, setRange] = useState<Range>("全部");
  const [query, setQuery] = useState("");
  const [reqMode, setReqMode] = useState<ReqMode>("raw");
  const [resView, setResView] = useState<ResView>("body");
  const [formHeaders, setFormHeaders] = useState("");
  const [formBody, setFormBody] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [pretty, setPretty] = useState(true);
  const [enc, setEnc] = useState<TextEnc>("auto");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string>();
  const [copied, setCopied] = useState("");
  const [net, setNet] = useState<NetworkStatus>();
  const rawRef = useRef<HTMLTextAreaElement | null>(null);
  const [railW, setRailW] = useState<number>(() => readUi().railW);
  const [split, setSplit] = useState<number>(() => readUi().split);
  const shellRef = useRef<HTMLDivElement | null>(null);
  const dockRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    writeUi({ railW, split });
  }, [railW, split]);

  /** 拖动历史栏的竖向分割线 */
  const startColDrag = (e: ReactPointerEvent) => {
    e.preventDefault();
    const rect = shellRef.current?.getBoundingClientRect();
    if (!rect) return;
    const move = (ev: PointerEvent) => {
      const next = ev.clientX - rect.left;
      setRailW(Math.round(Math.min(Math.max(next, 220), Math.max(260, rect.width * 0.62))));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      document.body.classList.remove("tr-drag-col");
    };
    document.body.classList.add("tr-drag-col");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  /** 拖动请求/响应之间的横向分割线 */
  const startRowDrag = (e: ReactPointerEvent) => {
    e.preventDefault();
    const rect = dockRef.current?.getBoundingClientRect();
    if (!rect || rect.height <= 0) return;
    const move = (ev: PointerEvent) => {
      const pct = ((ev.clientY - rect.top) / rect.height) * 100;
      setSplit(Math.round(Math.min(Math.max(pct, 20), 82)));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      document.body.classList.remove("tr-drag-row");
    };
    document.body.classList.add("tr-drag-row");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const activeTab = tabs.find((t) => t.id === activeTabId) ?? tabs[0];
  const draft = useMemo(() => parseDraft(activeTab?.raw ?? ""), [activeTab?.raw]);

  /* 切会话：历史、标签、编辑器一起换，不串台 */
  useEffect(() => {
    const own = readItems(sessionId);
    const saved = readTabs(sessionId);
    const nextTabs = saved.length ? saved : [makeTab()];
    setItems(own);
    setAllItems([]);
    setScope("session");
    setRange("全部");
    setQuery("");
    setTabs(nextTabs);
    setActiveTabId(nextTabs[0].id);
    setActiveItemId(own[0]?.id);
    setFormHeaders(parseDraft(nextTabs[0].raw).headerText);
    setFormBody(parseDraft(nextTabs[0].raw).body);
    setUrlInput(deriveUrl(nextTabs[0].raw, nextTabs[0].scheme, nextTabs[0].version));
    setError(undefined);
  }, [sessionId]);

  useEffect(() => {
    writeTabs(sessionId, tabs);
  }, [sessionId, tabs]);

  useEffect(() => {
    if (scope === "all") setAllItems(readAllItems());
  }, [scope, items]);

  useEffect(() => {
    void window.tanwei
      .network()
      .then(setNet)
      .catch(() => setNet(undefined));
  }, []);

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
    return pool.find((i) => i.id === activeItemId) ?? rows[0];
  }, [scope, items, allItems, activeItemId, rows]);

  const baseItem = useMemo(() => {
    if (!current) return undefined;
    const idx = items.findIndex((i) => i.id === current.id);
    return idx >= 0 ? items[idx + 1] : undefined;
  }, [items, current]);

  const displayUrl = current?.url ?? "";

  const patchTab = (id: string, patch: Partial<Tab>) => {
    setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)));
  };

  const patchRaw = (raw: string) => {
    if (!activeTab) return;
    patchTab(activeTab.id, { raw });
    // 报文里的 Host / 请求行一变，地址栏跟着走（写了一半没 Host 时保持原值，别闪）
    const next = deriveUrl(raw, activeTab.scheme, activeTab.version);
    if (next) setUrlInput(next);
  };

  /** 协议 / 版本变了，地址栏预览跟着变（Host 没写端口时靠它决定 http 还是 https） */
  const patchRoute = (patch: { scheme?: Scheme; version?: Version }) => {
    if (!activeTab) return;
    let raw = activeTab.raw;
    if (patch.scheme) {
      const { target } = parseDraft(raw);
      if (/^https?:\/\//i.test(target)) {
        raw = setTarget(raw, target.replace(/^https?:\/\//i, `${patch.scheme}://`));
      }
    }
    patchTab(activeTab.id, { ...patch, raw });
    setUrlInput(deriveUrl(raw, patch.scheme ?? activeTab.scheme, patch.version ?? activeTab.version));
  };

  const syncFormFromRaw = (raw: string, scheme: Scheme = "auto", version: Version = "1.1") => {
    const parsed = parseDraft(raw);
    setFormHeaders(parsed.headerText);
    setFormBody(parsed.body);
    setUrlInput(deriveUrl(raw, scheme, version));
  };

  const selectTab = (id: string) => {
    const next = tabs.find((t) => t.id === id);
    if (!next) return;
    setActiveTabId(id);
    syncFormFromRaw(next.raw, next.scheme, next.version);
  };

  const addTab = () => {
    if (tabs.length >= MAX_TABS) {
      setError(`最多同时开 ${MAX_TABS} 个标签`);
      return;
    }
    const tab = makeTab();
    setTabs((prev) => [...prev, tab]);
    setActiveTabId(tab.id);
    syncFormFromRaw(tab.raw, tab.scheme, tab.version);
    setError(undefined);
  };

  const closeTab = (id: string) => {
    if (tabs.length <= 1) {
      patchTab(id, { raw: DEFAULT_RAW });
      syncFormFromRaw(DEFAULT_RAW);
      return;
    }
    const idx = tabs.findIndex((t) => t.id === id);
    const next = tabs.filter((t) => t.id !== id);
    setTabs(next);
    if (activeTabId === id) {
      const fallback = next[Math.max(0, idx - 1)] ?? next[0];
      setActiveTabId(fallback.id);
      syncFormFromRaw(fallback.raw, fallback.scheme, fallback.version);
    }
  };

  const flash = (tag: string) => {
    setCopied(tag);
    window.setTimeout(() => setCopied(""), 1200);
  };

  const send = async () => {
    if (sending || !activeTab) return;
    const url = deriveUrl(activeTab.raw, activeTab.scheme, activeTab.version);
    if (!url) {
      setError("报文里没有 Host 头，请求行也没写绝对 URL，不知道往哪发");
      return;
    }
    setSending(true);
    setError(undefined);
    try {
      const res = await window.tanwei.sendRawRequest({
        raw: activeTab.raw,
        url,
        version: activeTab.version,
        followRedirects: activeTab.follow,
        skipTlsVerify: activeTab.skipTls,
        useProxy: activeTab.useProxy,
        timeoutMs: activeTab.timeoutMs,
      });
      const item: TrafficItem = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        sessionId,
        raw: activeTab.raw,
        version: activeTab.version,
        method: draft.method || "GET",
        url: res.finalUrl || url,
        status: res.status,
        statusText: res.statusText,
        httpVersion: res.httpVersion,
        headers: res.headers ?? [],
        body: res.body ?? "",
        bodyBase64: res.bodyBase64 ?? "",
        bodyBytes: res.bodyBytes,
        wireBytes: res.wireBytes,
        decompressed: res.decompressed,
        binary: res.binary,
        truncated: res.truncated,
        ms: res.ms,
        at: Date.now(),
        tls: res.tls,
        remote: res.remote,
        proxy: res.proxy,
        redirects: res.redirects ?? [],
        error: res.error,
      };
      setItems((prev) => {
        const next = [item, ...prev].slice(0, MAX_ITEMS);
        writeItems(sessionId, next);
        return next;
      });
      setActiveItemId(item.id);
      setResView("body");
      if (res.error) setError(res.error);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSending(false);
    }
  };

  const loadItem = (item: TrafficItem) => {
    setActiveItemId(item.id);
    setError(item.error);
    setResView("body");
    if (!activeTab) return;
    const scheme: Scheme = item.url.startsWith("https://") ? "https" : item.url.startsWith("http://") ? "http" : "auto";
    patchTab(activeTab.id, { raw: item.raw, version: item.version, scheme });
    syncFormFromRaw(item.raw, scheme, item.version);
  };

  const replayToNewTab = () => {
    if (!current || !activeTab) return;
    if (tabs.length >= MAX_TABS) {
      setError(`最多同时开 ${MAX_TABS} 个标签`);
      return;
    }
    const tab = { ...makeTab(current.raw), scheme: activeTab.scheme, version: activeTab.version };
    setTabs((prev) => [...prev, tab]);
    setActiveTabId(tab.id);
    syncFormFromRaw(tab.raw, tab.scheme, tab.version);
  };

  const clearSession = () => {
    setItems([]);
    writeItems(sessionId, []);
    setActiveItemId(undefined);
    if (scope === "all") setAllItems(readAllItems());
  };

  const bodyText = current?.body ?? "";
  // 响应字节留在 base64 里，换编码时重新解码，和 Yakit 的编码下拉一致
  const respBytes = useMemo(
    () => (current?.bodyBase64 ? base64ToBytes(current.bodyBase64) : null),
    [current],
  );
  const decodedBody = useMemo(() => {
    if (enc === "auto" || !respBytes) return bodyText;
    try {
      return new TextDecoder(enc).decode(respBytes);
    } catch {
      return bodyText;
    }
  }, [enc, respBytes, bodyText]);
  const bodyView = pretty ? prettyJson(decodedBody) : decodedBody;
  const hexText = useMemo(() => {
    if (!current) return "";
    const bytes = current.bodyBase64 ? base64ToBytes(current.bodyBase64) : new TextEncoder().encode(current.body);
    return hexDump(bytes);
  }, [current]);

  const diffRows = useMemo(() => {
    if (!current) return [] as DiffRow[];
    return diffLines(baseItem?.body ?? draft.body ?? "", current.body ?? "");
  }, [current, baseItem, draft.body]);

  const headersText = useMemo(
    () => (current?.headers ?? []).map((h) => `${h.name}: ${h.value}`).join("\n"),
    [current],
  );

  const originalResponse = useMemo(() => {
    if (!current) return "";
    const statusLine = `${current.httpVersion === "2" || current.httpVersion === "2.0" ? "HTTP/2" : `HTTP/${current.httpVersion}`} ${current.status} ${current.statusText}`;
    return `${statusLine}\n${headersText}\n\n${current.body}`;
  }, [current, headersText]);

  const curl = useMemo(() => {
    if (!activeTab) return "";
    const origin = deriveUrl(activeTab.raw, activeTab.scheme, activeTab.version);
    return buildCurl(activeTab.raw, activeTab.follow, activeTab.skipTls, origin);
  }, [activeTab]);

  const proxyHint = net?.effective
    ? `走代理 · ${net.effective}`
    : "走代理 · 未配置，按直连";

  return (
    <div className="tr-shell" ref={shellRef}>
      <div className="tr-top">
        <div className="tr-bar">
          <span className="tr-scope-tag">
            <Icon name="layers" size={12} />
            数据包重放
          </span>
          <div className="seg seg-sm">
            <button className={`seg-btn ${scope === "session" ? "on" : ""}`} onClick={() => setScope("session")}>
              本会话
            </button>
            <button className={`seg-btn ${scope === "all" ? "on" : ""}`} onClick={() => setScope("all")}>
              总览
            </button>
          </div>
          <div className="search tr-search">
            <Icon name="search" size={13} />
            <input value={query} placeholder="搜 URL / 方法 / 状态码" onChange={(e) => setQuery(e.target.value)} />
          </div>
          <span className="tr-count mono">{rows.length} 条</span>
          <button className="panel-link" onClick={clearSession} disabled={items.length === 0}>
            <Icon name="close" size={12} /> 清空
          </button>
        </div>

        <div className="tr-tabs">
          <div className="tr-tab-list">
            {tabs.map((tab) => (
              <div key={tab.id} className={`tr-tab ${tab.id === activeTab?.id ? "on" : ""}`}>
                <button className="tr-tab-name mono" onClick={() => selectTab(tab.id)} title={tab.raw}>
                  {tabTitle(tab.raw)}
                </button>
                <button className="tr-tab-x" onClick={() => closeTab(tab.id)} title="关闭标签">
                  <Icon name="close" size={10} />
                </button>
              </div>
            ))}
            <button className="tr-tab-add" onClick={addTab} title="新建标签">
              <Icon name="plus" size={12} />
            </button>
          </div>
          <span className="tr-tabs-hint">Ctrl + Enter 发送</span>
        </div>
      </div>

      <div className="tr-body">
        <aside className="tr-rail" style={{ width: railW }}>
          <div className="tr-rail-head">
            <span className="tr-rail-title">
              请求历史
              <span className="tr-rail-n mono">{rows.length}</span>
            </span>
            <button className="panel-link" onClick={replayToNewTab} disabled={!current}>
              <Icon name="external" size={11} /> 重放
            </button>
          </div>

          <div className="tr-dist" role="group" aria-label="按状态筛选">
            {([
              ["全部", "all"],
              ["2xx", "ok"],
              ["3xx", "moved"],
              ["4xx", "warn"],
              ["5xx", "bad"],
              ["失败", "err"],
            ] as [Range, string][]).map(([label, tone]) => {
              const pool = scope === "session" ? items : allItems;
              const n = pool.filter((i) => inRange(i, label)).length;
              const width = pool.length ? Math.max((n / pool.length) * 100, n ? 4 : 0) : 0;
              return (
                <button
                  key={label}
                  className={`tr-dist-seg ${tone} ${range === label ? "on" : ""}`}
                  onClick={() => setRange(label)}
                  title={`${label} · ${n} 条`}
                >
                  <span className="tr-dist-bar" style={{ width: `${width}%` }} />
                  <span className="tr-dist-label mono">
                    {label}
                    <em>{n}</em>
                  </span>
                </button>
              );
            })}
          </div>

          <div className="tr-rail-list">
            {rows.length === 0 ? (
              <div className="panel-empty">
                {scope === "session"
                  ? "这个会话还没发过请求。上面切「总览」看别的会话。"
                  : "还没有任何会话的请求记录。"}
              </div>
            ) : (
              rows.map((item) => (
                <button
                  key={item.id}
                  className={`tr-hrow tr-hrow-${statusClass(item.status)} ${current?.id === item.id ? "on" : ""}`}
                  onClick={() => loadItem(item)}
                  title={item.url}
                >
                  <span className="tr-hrow-top">
                    <span className={`tr-mchip m-${methodTone(item.method)}`}>{item.method}</span>
                    <span className="tr-hrow-url mono">{shortPath(item.url)}</span>
                    <span className={`status-pill ${statusClass(item.status)}`}>{item.status || "ERR"}</span>
                  </span>
                  <span className="tr-hrow-sub mono">
                    <span>{item.ms} ms</span>
                    <span className="tr-dot">·</span>
                    <span>{fmtBytes(item.bodyBytes)}</span>
                    <span className="tr-dot">·</span>
                    <span>{clock(item.at)}</span>
                    {item.version === "2" ? <span className="tr-tag">h2</span> : null}
                    {item.proxy ? <span className="tr-tag">代理</span> : null}
                    {scope === "all" ? (
                      <span className="tr-hrow-sess">{titleOf.get(item.sessionId) ?? item.sessionId.slice(0, 8)}</span>
                    ) : null}
                  </span>
                </button>
              ))
            )}
          </div>
        </aside>

        <div
          className="tr-gutter"
          role="separator"
          aria-orientation="vertical"
          title="拖动调整历史栏宽度"
          onPointerDown={startColDrag}
        />

        <div className="tr-dock" ref={dockRef}>
          <section className="tr-req" style={{ flexBasis: `${split}%` }}>
            <header className="tr-pane-head">
              <span className="tr-pane-title">
                <Icon name="send" size={12} />
                请求
              </span>
              <span className="tr-req-badge mono">
                {draft.method || "GET"} · HTTP/{activeTab?.version === "2" ? "2" : "1.1"}
              </span>
              <div className="seg seg-sm">
                <button className={`seg-btn ${reqMode === "raw" ? "on" : ""}`} onClick={() => setReqMode("raw")}>
                  Raw
                </button>
                <button
                  className={`seg-btn ${reqMode === "form" ? "on" : ""}`}
                  onClick={() => {
                    setReqMode("form");
                    if (activeTab) syncFormFromRaw(activeTab.raw);
                  }}
                >
                  表单
                </button>
              </div>
              <div className="tr-pane-tools">
                <button
                  className="panel-link"
                  onClick={() => activeTab && void copyText(activeTab.raw).then(() => flash("raw"))}
                >
                  <Icon name={copied === "raw" ? "check" : "copy"} size={12} />
                  {copied === "raw" ? "已复制" : "报文"}
                </button>
                <button className="panel-link" onClick={() => void copyText(curl).then(() => flash("curl"))}>
                  <Icon name={copied === "curl" ? "check" : "copy"} size={12} />
                  {copied === "curl" ? "已复制" : "cURL"}
                </button>
              </div>
            </header>

            <div className="tr-addr">
              <input
                className="tr-method mono"
                value={draft.method}
                list="tr-methods"
                spellCheck={false}
                onChange={(e) => activeTab && patchTab(activeTab.id, { raw: setMethod(activeTab.raw, e.target.value) })}
              />
              <datalist id="tr-methods">
                {METHODS.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
              <input
                className="req-url mono"
                value={urlInput}
                spellCheck={false}
                placeholder="https://host/path，也可以只在报文里写 Host"
                onChange={(e) => {
                  const value = e.target.value;
                  setUrlInput(value);
                  if (activeTab) patchTab(activeTab.id, { raw: setTarget(activeTab.raw, value) });
                }}
                onBlur={() => activeTab && setUrlInput(deriveUrl(activeTab.raw, activeTab.scheme, activeTab.version))}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) void send();
                }}
              />
              <button className="btn primary tr-send" onClick={() => void send()} disabled={sending}>
                <Icon name="send" size={13} />
                <span>{sending ? "发送中…" : "发送"}</span>
              </button>
            </div>

            <div className="tr-opts">
              <div className="seg seg-sm tr-ver tr-scheme" title="Host 里没写端口时按哪个协议发">
                {(["auto", "http", "https"] as Scheme[]).map((s) => (
                  <button
                    key={s}
                    className={`seg-btn ${(activeTab?.scheme ?? "auto") === s ? "on" : ""}`}
                    onClick={() => patchRoute({ scheme: s })}
                  >
                    {s === "auto" ? "自动" : s}
                  </button>
                ))}
              </div>
              <div className="seg seg-sm tr-ver" title="HTTP 协议版本">
                <button
                  className={`seg-btn ${activeTab?.version === "1.1" ? "on" : ""}`}
                  onClick={() => patchRoute({ version: "1.1" })}
                >
                  1.1
                </button>
                <button
                  className={`seg-btn ${activeTab?.version === "2" ? "on" : ""}`}
                  onClick={() => patchRoute({ version: "2" })}
                >
                  2
                </button>
              </div>
              <label className="check">
                <input
                  type="checkbox"
                  checked={activeTab?.skipTls ?? true}
                  onChange={(e) => activeTab && patchTab(activeTab.id, { skipTls: e.target.checked })}
                />
                <span>跳过证书校验</span>
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={activeTab?.follow ?? true}
                  onChange={(e) => activeTab && patchTab(activeTab.id, { follow: e.target.checked })}
                />
                <span>跟随重定向</span>
              </label>
              <label className="check" title={proxyHint}>
                <input
                  type="checkbox"
                  checked={activeTab?.useProxy ?? false}
                  onChange={(e) => activeTab && patchTab(activeTab.id, { useProxy: e.target.checked })}
                />
                <span>{proxyHint}</span>
              </label>
              <label className="check tr-timeout">
                <span>超时</span>
                <input
                  className="mono"
                  type="number"
                  min={1000}
                  max={120000}
                  step={1000}
                  value={activeTab?.timeoutMs ?? 30_000}
                  onChange={(e) =>
                    activeTab && patchTab(activeTab.id, { timeoutMs: Number(e.target.value) || 30_000 })
                  }
                />
                <span>ms</span>
              </label>
            </div>

            <div className="tr-editor">
              {reqMode === "raw" ? (
                <RawEditor
                  areaRef={rawRef}
                  value={activeTab?.raw ?? ""}
                  onChange={patchRaw}
                  onBlur={() =>
                    activeTab && setUrlInput(deriveUrl(activeTab.raw, activeTab.scheme, activeTab.version))
                  }
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) void send();
                  }}
                />
              ) : (
                <div className="tr-form">
                  <div className="tr-form-col">
                    <div className="tr-form-head">
                      <span>请求头</span>
                      <span className="subtle mono">一行一个 Name: Value</span>
                    </div>
                    <textarea
                      className="tr-area mono"
                      value={formHeaders}
                      spellCheck={false}
                      onChange={(e) => {
                        setFormHeaders(e.target.value);
                        if (activeTab) patchTab(activeTab.id, { raw: applyHeaders(activeTab.raw, e.target.value) });
                      }}
                    />
                  </div>
                  <div className="tr-form-col">
                    <div className="tr-form-head">
                      <span>请求体</span>
                      <span className="subtle mono">{fmtBytes(bytesOf(formBody))}</span>
                    </div>
                    <textarea
                      className="tr-area mono"
                      value={formBody}
                      spellCheck={false}
                      placeholder='{"key":"value"}'
                      onChange={(e) => {
                        setFormBody(e.target.value);
                        if (activeTab) patchTab(activeTab.id, { raw: applyBody(activeTab.raw, e.target.value) });
                      }}
                    />
                  </div>
                </div>
              )}
            </div>
          </section>

          <div
            className="tr-hgutter"
            role="separator"
            aria-orientation="horizontal"
            title="拖动调整请求/响应高度"
            onPointerDown={startRowDrag}
          />

          <section className="tr-res" style={{ flex: 1 }}>
            <header className="tr-pane-head">
              <span className="tr-pane-title">
                <Icon name="layers" size={12} />
                响应
              </span>
              {current ? (
                <span className="tr-res-meta">
                  <span className={`status-pill ${statusClass(current.status)}`}>
                    {current.status || "ERR"} {current.statusText}
                  </span>
                  <span className="mono subtle">{current.httpVersion}</span>
                  <span className="mono subtle">{current.ms} ms</span>
                  <span className="mono subtle">{fmtBytes(current.bodyBytes)}</span>
                  {current.wireBytes ? <span className="mono subtle">线 {fmtBytes(current.wireBytes)}</span> : null}
                </span>
              ) : null}
              <div className="tr-pane-tools">
                <div className="seg seg-sm">
                  <button className={`seg-btn ${resView === "body" ? "on" : ""}`} onClick={() => setResView("body")}>
                    正文
                  </button>
                  <button
                    className={`seg-btn ${resView === "render" ? "on" : ""}`}
                    onClick={() => setResView("render")}
                  >
                    渲染
                  </button>
                  <button
                    className={`seg-btn ${resView === "headers" ? "on" : ""}`}
                    onClick={() => setResView("headers")}
                  >
                    头
                  </button>
                  <button className={`seg-btn ${resView === "raw" ? "on" : ""}`} onClick={() => setResView("raw")}>
                    原始
                  </button>
                  <button className={`seg-btn ${resView === "hex" ? "on" : ""}`} onClick={() => setResView("hex")}>
                    Hex
                  </button>
                  <button className={`seg-btn ${resView === "diff" ? "on" : ""}`} onClick={() => setResView("diff")}>
                    对比
                  </button>
                </div>
                {resView === "body" ? (
                  <label className="check tr-pretty">
                    <input type="checkbox" checked={pretty} onChange={(e) => setPretty(e.target.checked)} />
                    <span>美化 JSON</span>
                  </label>
                ) : null}
                {resView === "body" || resView === "render" ? (
                  <select
                    className="tr-enc mono"
                    value={enc}
                    title="响应正文按这个编码解码"
                    onChange={(e) => setEnc(e.target.value as TextEnc)}
                  >
                    <option value="auto">自动</option>
                    <option value="utf-8">UTF-8</option>
                    <option value="gbk">GBK</option>
                    <option value="big5">Big5</option>
                    <option value="shift_jis">Shift_JIS</option>
                  </select>
                ) : null}
                <button
                  className="panel-link"
                  disabled={!current}
                  onClick={() =>
                    void copyText(
                      resView === "raw" ? originalResponse : resView === "headers" ? headersText : current?.body ?? "",
                    ).then(() => flash("body"))
                  }
                >
                  <Icon name={copied === "body" ? "check" : "copy"} size={12} />
                  {copied === "body" ? "已复制" : "复制"}
                </button>
              </div>
            </header>

            <div className="tr-res-body">
              {!current ? (
                <div className="panel-empty">填报文点发送，或者点左边历史里的一条回看结果。</div>
              ) : current.error ? (
                <div className="module-error">{current.error}</div>
              ) : (
                <>
                  <div className="tr-res-line">
                    <span className="tr-res-url mono" title={displayUrl}>
                      {displayUrl}
                    </span>
                    {current.truncated ? <span className="tr-chip">正文已截断</span> : null}
                    {current.decompressed ? <span className="tr-chip">已解压</span> : null}
                    {current.binary ? <span className="tr-chip">二进制</span> : null}
                    {current.remote ? <span className="tr-chip mono">{current.remote}</span> : null}
                    {current.proxy ? <span className="tr-chip mono">代理 {current.proxy}</span> : null}
                  </div>

                  {current.redirects.length > 0 ? (
                    <div className="tr-redirs mono">
                      {current.redirects.map((hop, i) => (
                        <div key={`${hop.status}-${i}`}>
                          <span className="subtle">{hop.status}</span> → {hop.location}
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {resView === "body" ? (
                    current.binary ? (
                      <div className="panel-empty">二进制响应，切「Hex」看字节。</div>
                    ) : (
                      <pre className="tr-raw mono">{bodyView || "（空正文）"}</pre>
                    )
                  ) : resView === "render" ? (
                    <iframe
                      className="tr-render"
                      title="响应渲染"
                      sandbox=""
                      referrerPolicy="no-referrer"
                      srcDoc={decodedBody || "<!doctype html><meta charset=utf-8><p style='font-family:sans-serif;color:#666'>（空正文）</p>"}
                    />
                  ) : resView === "headers" ? (
                    <pre className="tr-raw mono">{headersText || "（没有响应头）"}</pre>
                  ) : resView === "raw" ? (
                    <pre className="tr-raw mono">{originalResponse}</pre>
                  ) : resView === "hex" ? (
                    <pre className="tr-raw mono">{hexText || "（空正文）"}</pre>
                  ) : (
                    <div className="tr-diff">
                      <div className="tr-diff-head mono">
                        <span className="tr-diff-side">
                          旧：{baseItem ? shortPath(baseItem.url) : "当前请求体"}
                        </span>
                        <span className="tr-diff-side">
                          新：{shortPath(current.url)}
                        </span>
                      </div>
                      <div className="tr-diff-body mono">
                        {diffRows.map((row, i) => (
                          <div key={i} className={`tr-diff-row ${row.kind}`}>
                            <span className="tr-diff-sign">
                              {row.kind === "add" ? "+" : row.kind === "del" ? "-" : " "}
                            </span>
                            <span className="tr-diff-text">{row.text || " "}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {current.tls ? <div className="tr-tls mono">{tlsLine(current.tls)}</div> : null}
                </>
              )}
            </div>
          </section>
        </div>
      </div>

      <div className="tr-statusbar">
        <span className={`tr-st-led ${sending ? "busy" : error || current?.error ? "bad" : current ? "ok" : ""}`} />
        <span className={`tr-st-main mono ${error ? "is-err" : ""}`} title={error || urlInput}>
          {error
            ? error
            : sending
              ? "发送中…"
              : `${(draft.method || "GET").toUpperCase()} ${urlInput || "（还没填地址）"}`}
        </span>
        <span className="tr-st-sep" />
        <span className="tr-st-item mono">
          请求 {fmtBytes(bytesOf(activeTab?.raw ?? ""))} · {(activeTab?.raw ?? "").split("\n").length} 行
        </span>
        <span className="tr-st-item mono">{activeTab?.version === "2" ? "HTTP/2" : "HTTP/1.1"}</span>
        <span className="tr-st-item mono">超时 {Math.round((activeTab?.timeoutMs ?? 30_000) / 1000)}s</span>
        <span className="tr-st-grow" />
        <span className="tr-st-item mono">本会话 {items.length} 条</span>
        {scope === "all" ? <span className="tr-st-item mono">总览 {allItems.length} 条</span> : null}
        <span className="tr-st-item mono">{proxyHint}</span>
      </div>
    </div>
  );
}
