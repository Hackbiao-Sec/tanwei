import React from "react";
import type { MobileHistoryRecord, MobileKind, MobilePentestMode } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";

export const KIND_LABEL: Record<MobileKind, string> = {
  wechat: "小程序源码",
  uniapp: "uni-app",
  taro: "Taro",
  wxapkg: "wxapkg",
  apk: "Android",
  ipa: "iOS",
  unknown: "未知",
};

export const MINI_KINDS: MobileKind[] = ["wechat", "uniapp", "taro", "wxapkg"];
export const APP_KINDS: MobileKind[] = ["apk", "ipa"];

export function isMiniKind(kind: MobileKind): boolean {
  return MINI_KINDS.includes(kind);
}

export function isAppKind(kind: MobileKind): boolean {
  return APP_KINDS.includes(kind);
}

export const MODE_LABEL: Record<MobilePentestMode, string> = {
  static: "静态",
  dynamic: "动态",
  both: "静态 + 动态",
};

export const MODE_HINT: Record<MobilePentestMode, string> = {
  static: "只打拆出来的东西：接口、密钥、组件、路由，不碰真机",
  dynamic: "上真机 / 模拟器：抓包、hook、绕证书锁定、调私有接口",
  both: "先静态摸清入口，再上真机验证；证据最全",
};

/** 小程序没有装包概念，「动态」= 真机 / 开发者工具里抓包核对 */
export const MINI_MODE_LABEL: Record<MobilePentestMode, string> = {
  static: "只拆静态",
  dynamic: "真机抓包",
  both: "静态 + 抓包",
};

export const MINI_MODE_HINT: Record<MobilePentestMode, string> = {
  static: "解包、路由、接口、云开发配置，全靠静态产物",
  dynamic: "真机或微信开发者工具里跑一遍，核对接口与鉴权，凭据现拿现用",
  both: "先静态列接口，再真机对照；默认走这条",
};

export function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

export function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export function shortPath(p: string): string {
  const m = /^(?:[A-Za-z]:[\\/])(.*)$/.exec(p);
  return m ? m[1] : p;
}

/** 两个面板共用的分组卡：标题 + 计数 + 空态 */
export function MobileSection({
  title,
  count,
  empty,
  hint,
  children,
}: {
  title: string;
  count: number;
  empty: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mob-card">
      <div className="mob-card-head">
        <span>{title}</span>
        <span className="mob-card-count">{count}</span>
      </div>
      {hint ? <div className="mob-card-hint">{hint}</div> : null}
      <div className="mob-card-body">
        {count ? children : <div className="mob-line subtle">{empty}</div>}
      </div>
    </div>
  );
}

export type MobileScope = "session" | "all";

/**
 * 面板顶栏：本会话 / 总览 + 搜索 + 工具按钮。
 * 两档都读主进程的历史记录，切会话时只换过滤条件，面板状态不丢。
 */
export function MobileScopeBar({
  scope,
  onScope,
  mine,
  all,
  query,
  onQuery,
  placeholder,
  busy,
  onRefresh,
  children,
}: {
  scope: MobileScope;
  onScope: (next: MobileScope) => void;
  mine: number;
  all: number;
  query: string;
  onQuery: (next: string) => void;
  placeholder: string;
  busy?: boolean;
  onRefresh?: () => void;
  children?: React.ReactNode;
}) {
  return (
    <div className="mob-scope-bar">
      <div className="scope-switch">
        <button
          className={`seg-btn${scope === "session" ? " on" : ""}`}
          onClick={() => onScope("session")}
          title="只看归属当前会话的拆解记录"
        >
          本会话 · {mine}
        </button>
        <button
          className={`seg-btn${scope === "all" ? " on" : ""}`}
          onClick={() => onScope("all")}
          title="所有会话拆过的记录，含未归属的"
        >
          总览 · {all}
        </button>
      </div>
      <input
        className="mob-filter"
        value={query}
        onChange={(e) => onQuery(e.target.value)}
        placeholder={placeholder}
        spellCheck={false}
      />
      {onRefresh ? (
        <button className="btn ghost sm" onClick={onRefresh} disabled={busy} title="重新读历史记录">
          <Icon name="refresh" size={11} />
          <span>{busy ? "读取中…" : "刷新"}</span>
        </button>
      ) : null}
      {children}
    </div>
  );
}

/** 详情页签：一条横向分段条，计数跟在标签后面 */
export function MobileTabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: string; count?: number; warn?: boolean }[];
  value: T;
  onChange: (next: T) => void;
}) {
  return (
    <div className="mob-tabs">
      {tabs.map((t) => (
        <button
          key={t.id}
          className={`mob-tab${value === t.id ? " on" : ""}${t.warn ? " warn" : ""}`}
          onClick={() => onChange(t.id)}
          type="button"
        >
          <span>{t.label}</span>
          {typeof t.count === "number" ? <span className="mob-tab-count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/** 历史记录的时间：今天 / 昨天 用相对说法，更早带月日 */
export function fmtWhen(ts: number): string {
  if (!ts) return "";
  const date = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  const hm = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  const now = new Date();
  if (date.toDateString() === now.toDateString()) return `今天 ${hm}`;
  const yesterday = new Date(now.getTime() - 864e5);
  if (date.toDateString() === yesterday.toDateString()) return `昨天 ${hm}`;
  return `${date.getMonth() + 1}-${pad(date.getDate())} ${hm}`;
}

/** 拆解记录的搜索：空格分词后逐词 AND，名称 / 路径 / AppID / 包名 / 接口 / 密钥 / 页面 都算命中 */
export function matchRecord(record: MobileHistoryRecord, query: string): boolean {
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [
    record.target.name,
    record.target.path,
    record.appId ?? "",
    record.packageName ?? "",
    record.mini?.appId ?? "",
    ...record.pages,
    ...record.endpoints,
    ...record.secrets.map((s) => s.value),
  ]
    .join("\n")
    .toLowerCase();
  return words.every((w) => hay.includes(w));
}

const normPath = (p: string) => p.replace(/[\\/]+/g, "/").replace(/\/+$/, "").toLowerCase();
/** 扫描目标是否已经拆过：扫描取的 id 与拆解取的 id 哈希输入不同，只能按路径对齐 */
export function alreadyAnalyzed(target: { path: string }, history: MobileHistoryRecord[]): boolean {
  const key = normPath(target.path);
  return history.some((r) => normPath(r.target.path) === key);
}

// 框架 / 库的文档、许可证、命名空间地址：拆包里几乎每个 APK 都有，混在接口里只会淹没真实业务域名
const NOISE_HOSTS = [
  "bouncycastle.org",
  "slf4j.org",
  "w3.org",
  "xml.org",
  "xmlpull.org",
  "schemas.android.com",
  "schemas.xmlsoap.org",
  "json-schema.org",
  "www.json.org",
  "apache.org",
  "eclipse.org",
  "sonatype.org",
  "maven.org",
  "gradle.org",
  "kotlinlang.org",
  "docs.oracle.com",
  "developer.android.com",
  "square.github.io",
  "facebook.github.io",
  "reactnative.dev",
  "flutter.dev",
  "npmjs.com",
  "ns.adobe.com",
  "purl.org",
  "ietf.org",
  "opensource.org",
  "creativecommons.org",
  "gnu.org",
  "github.com",
  "googleapis.com",
  "gstatic.com",
  "example.com",
  "schemas.microsoft.com",
];

/** 拆包抽出来的接口里，哪些只是库/框架地址（不是业务入口） */
export function isNoiseEndpoint(url: string): boolean {
  const low = url.toLowerCase();
  return NOISE_HOSTS.some((h) => low.includes(h));
}

/** 一条可复制的证据行：标签 + 文本 + 出处 + 复制按钮 */
export function MobileCopyRow({
  tag,
  text,
  note,
  mono = true,
}: {
  tag?: string;
  text: string;
  note?: string;
  mono?: boolean;
}) {
  const [done, setDone] = React.useState(false);
  async function handle() {
    await copyText(text);
    setDone(true);
    window.setTimeout(() => setDone(false), 1200);
  }
  return (
    <div className="mob-item">
      {tag ? <span className="mob-tag">{tag}</span> : null}
      <span className={`mob-item-text${mono ? " mono" : ""}`} title={text}>
        {text}
      </span>
      {note ? <span className="mob-item-note mono">{note}</span> : null}
      <button className="chip chip-ghost" type="button" onClick={() => void handle()} title="复制这一条">
        <Icon name="copy" size={10} />
        <span>{done ? "已复制" : "复制"}</span>
      </button>
    </div>
  );
}

/** 小标题 + 右侧「复制全部」这类操作 */
export function MobileBlockHead({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children?: React.ReactNode;
}) {
  return (
    <div className="mob-block-head">
      <span className="mob-block-title">{title}</span>
      {typeof count === "number" ? <span className="mob-card-count">{count}</span> : null}
      <div className="mob-spacer" />
      {children}
    </div>
  );
}

