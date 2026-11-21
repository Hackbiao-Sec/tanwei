import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import zlib from "node:zlib";
import { app } from "electron";
import type {
  AppProfile,
  FridaPreset,
  MiniProfile,
  MobileAnalysis,
  MobileAppEntry,
  MobileAppList,
  MobileAutoCheck,
  MobileComponent,
  MobileDevice,
  MobileDynamicAction,
  MobileDynamicInput,
  MobileActionResult,
  MobileEnvInfo,
  MobileEnvTool,
  MobileKind,
  MobilePentestMode,
  MobileScanResult,
  MobileSecret,
  MobileTarget,
} from "../shared/types";
import { decodeConsole, ensureToolPath, execTool, findToolPath, toolReport } from "./mobileTools";
import { listUploads } from "./uploads";

/**
 * 小程序 / APP 渗透的目标发现与静态拆解。
 *
 * 这层只负责「把目标变成引擎能看的文件」：
 *  - 扫目录认出小程序源码工程、*.wxapkg、APK、IPA
 *  - 解 wxapkg、读 APK 的 AndroidManifest、读 IPA 的 Info.plist
 *  - 抽接口、密钥、权限、导出组件，落一份中文简报
 * 反编译后的攻击动作（越权、注入、动态 hook 等）仍交给引擎按打法执行。
 */

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".idea",
  ".vscode",
  "dist",
  "build",
  "out",
  "target",
  "__pycache__",
  ".cache",
  "unpackage",
]);

const MAX_SCAN_ENTRIES = 20_000;
const MAX_SCAN_DEPTH = 7;
const MAX_SCAN_TARGETS = 200;
const MAX_TEXT_BYTES = 1_500_000;
const MAX_ENDPOINTS = 400;
const MAX_SECRETS = 120;
const MAX_TEXTS = 600;

function sha1(input: string): string {
  return crypto.createHash("sha1").update(input).digest("hex").slice(0, 12);
}

function stamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function safeName(name: string): string {
  return name.replace(/[\\/:*?"<>|]/g, "_").slice(0, 80) || "target";
}

export function mobileOutRoot(): string {
  return path.join(app.getPath("userData"), "mobile");
}

async function exists(p: string): Promise<boolean> {
  try {
    await fsp.access(p);
    return true;
  } catch {
    return false;
  }
}

async function isDir(p: string): Promise<boolean> {
  try {
    return (await fsp.stat(p)).isDirectory();
  } catch {
    return false;
  }
}

const APK_EXT = /\.apk$/i;
/** .apks / .xapk 是分包容器，adb 只吃解压出来的 .apk */
const CONTAINER_EXT = /\.(apks|xapk)$/i;

/** 目录第一层的安装包；没有再往下看一层，浏览器下载常落在子目录里 */
async function apksIn(dir: string): Promise<string[]> {
  try {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    const direct = entries.filter((e) => e.isFile() && APK_EXT.test(e.name)).map((e) => path.join(dir, e.name));
    if (direct.length) return direct;
    const nested: string[] = [];
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const sub = await fsp.readdir(path.join(dir, e.name), { withFileTypes: true }).catch(() => []);
      for (const s of sub) if (s.isFile() && APK_EXT.test(s.name)) nested.push(path.join(dir, e.name, s.name));
    }
    return nested;
  } catch {
    return [];
  }
}

/**
 * 把「用户填的路径」落成真实的安装包文件。
 * 空路径退回本会话上传里最新的 .apk：以前 path.resolve("") 会变成 cwd，
 * 便携版的 cwd 恰好是 exe 解压出来的临时目录，adbd 只会回一句「不是 .apk」。
 * 目录里有多份 .apk 时按拆分包处理，走 adb install-multiple。
 */
async function resolveApkFiles(raw: string, sessionId?: string): Promise<{ files?: string[]; error?: string }> {
  const given = String(raw ?? "").trim();
  if (given) {
    const abs = path.resolve(given);
    const stat = await fsp.stat(abs).catch(() => undefined);
    if (!stat) return { error: `路径不存在：${abs}` };
    if (stat.isFile()) {
      if (APK_EXT.test(abs)) return { files: [abs] };
      if (CONTAINER_EXT.test(abs))
        return { error: `这是分包容器（${path.extname(abs)}）：先解压，把里面的 .apk 放进同一个目录，再把目录填进来` };
      return { error: `只认 .apk，当前选的是 ${path.basename(abs)}` };
    }
    if (!stat.isDirectory()) return { error: `不是文件：${abs}` };
    const found = await apksIn(abs);
    if (found.length) return { files: found };
    return { error: `目录里没有 .apk：${abs}` };
  }
  for (const item of listUploads(sessionId)) {
    if (!APK_EXT.test(item.path)) continue;
    if (await exists(item.path)) return { files: [item.path] };
  }
  return { error: "先选一个 .apk 文件，或在对话里上传安装包（安装只对 APK 有效，IPA 得走 iOS 真机 / Xcode）" };
}

async function readJson(file: string): Promise<any | undefined> {
  try {
    const text = await fsp.readFile(file, "utf8");
    return JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch {
    return undefined;
  }
}

/* ---------------- 扫目录 ---------------- */

interface MiniMarkers {
  appId?: string;
  kind: MobileKind;
  note: string;
}

async function miniMarkers(dir: string): Promise<MiniMarkers | undefined> {
  const appJson = path.join(dir, "app.json");
  const pagesJson = path.join(dir, "pages.json");
  const manifestJson = path.join(dir, "manifest.json");
  const hasApp = await exists(appJson);
  const project = await readJson(path.join(dir, "project.config.json"));
  const manifest = await readJson(manifestJson);
  const mpAppId = typeof manifest?.["mp-weixin"]?.appid === "string" ? manifest["mp-weixin"].appid : undefined;
  const appId = (typeof project?.appid === "string" ? project.appid : undefined) ?? mpAppId;
  const pkg = await readJson(path.join(dir, "package.json"));
  const deps = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) } as Record<string, string>;
  const taro =
    !!deps["@tarojs/taro"] || (await exists(path.join(dir, "app.config.ts"))) || (await exists(path.join(dir, "app.config.js")));
  const uni =
    !!deps["@dcloudio/uni-app"] ||
    !!deps["@dcloudio/vite-plugin-uni"] ||
    ((await exists(pagesJson)) && (await exists(manifestJson)));

  // uni-app / Taro 的源码工程没有 app.json，靠 pages.json / manifest.json / app.config.* 认
  if (!hasApp) {
    if (!taro && !uni) return undefined;
    return taro
      ? { kind: "taro", appId, note: "Taro 源码工程（app.config.* 入口）" }
      : { kind: "uniapp", appId, note: "uni-app 源码工程（pages.json + manifest.json）" };
  }
  if (taro) return { kind: "taro", appId, note: "Taro 编译型小程序源码工程" };
  if (uni) return { kind: "uniapp", appId, note: "uni-app 源码工程" };
  return { kind: "wechat", appId, note: appId ? "微信小程序源码工程" : "小程序源码工程（缺 project.config.json 的 appid）" };
}

export async function scanTargets(dir: string): Promise<MobileScanResult> {
  const root = path.resolve(String(dir ?? "").trim());
  if (!root) throw new Error("先填一个目录，或点「选择目录」");
  if (!(await isDir(root))) throw new Error(`目录不存在：${root}`);

  const targets: MobileTarget[] = [];
  const notes: string[] = [];
  const seen = new Set<string>();
  let scanned = 0;
  let truncated = false;

  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (queue.length) {
    const { dir, depth } = queue.shift()!;
    let entries: import("node:fs").Dirent[] = [];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    const markers = await miniMarkers(dir);
    if (markers) {
      const id = sha1(`mini:${dir}`);
      if (!seen.has(id)) {
        seen.add(id);
        let files = 0;
        try {
          const all = await walkFiles(dir);
          files = all.length;
        } catch {
          files = 0;
        }
        targets.push({
          id,
          name: path.basename(dir) || dir,
          kind: markers.kind,
          path: dir,
          size: files,
          files,
          appId: markers.appId,
          note: markers.note,
        });
      }
    }
    for (const entry of entries) {
      if (targets.length >= MAX_SCAN_TARGETS) {
        truncated = true;
        break;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase()) || entry.name.startsWith(".")) continue;
        if (depth + 1 > MAX_SCAN_DEPTH) {
          truncated = true;
          continue;
        }
        if (++scanned > MAX_SCAN_ENTRIES) {
          truncated = true;
          break;
        }
        queue.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      const lower = entry.name.toLowerCase();
      const hit = lower.endsWith(".wxapkg")
        ? "wxapkg"
        : lower.endsWith(".apk")
          ? "apk"
          : lower.endsWith(".ipa")
            ? "ipa"
            : undefined;
      if (!hit) continue;
      const id = sha1(`${hit}:${full}`);
      if (seen.has(id)) continue;
      seen.add(id);
      let size = 0;
      try {
        size = (await fsp.stat(full)).size;
      } catch {
        size = 0;
      }
      targets.push({
        id,
        name: entry.name,
        kind: hit as MobileKind,
        path: full,
        size,
        note:
          hit === "wxapkg"
            ? "微信小程序包，可直接解包"
            : hit === "apk"
              ? "Android 安装包，读清单 + dex"
              : "iOS 安装包，读 Info.plist + 结构",
      });
    }
    if (scanned > MAX_SCAN_ENTRIES || targets.length >= MAX_SCAN_TARGETS) break;
  }

  const order: Record<string, number> = { wechat: 0, uniapp: 1, taro: 2, wxapkg: 3, apk: 4, ipa: 5, unknown: 9 };
  targets.sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || a.name.localeCompare(b.name));

  if (!targets.length) notes.push("这个目录下没认出小程序工程、*.wxapkg、*.apk 或 *.ipa：换一层目录，或直接拖包进来。");
  if (truncated) notes.push(`目录太大，扫到上限就停了（${MAX_SCAN_ENTRIES} 项）。缩小范围再扫更准。`);
  return { dir: root, scanned, targets, truncated, notes };
}

async function walkFiles(root: string, limit = 20_000): Promise<string[]> {
  const out: string[] = [];
  const queue = [root];
  while (queue.length && out.length < limit) {
    const dir = queue.shift()!;
    let entries: import("node:fs").Dirent[] = [];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= limit) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
        queue.push(full);
      } else if (entry.isFile()) {
        out.push(full);
      }
    }
  }
  return out;
}

/* ---------------- 文本提取：接口 / 密钥 ---------------- */

const URL_RE = /https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{4,180}/g;
const PATH_RE = /["'`](\/(?:api|apis|admin|user|users|upload|file|files|login|auth|v1|v2|v3|wx|mp|mini|order|pay|member|system)[A-Za-z0-9_\-/.]{1,90})["'`]/g;
// 文档头 / XML 命名空间这类地址不是业务接口，混进清单会干扰后面选目标
const URL_NOISE_RE =
  /(?:\bw3\.org|apple\.com\/DTDs|xmlsoap\.org|purl\.org|json-schema\.org|schemas\.|xmlns|apache\.org\/licenses|opensource\.org\/licenses|creativecommons\.org)/i;

const SECRET_KEYWORDS =
  "appSecret|app_secret|apiKey|api_key|apiSecret|api_secret|secretKey|secret_key|clientSecret|client_secret|token|accessToken|password|passwd|pwd";

const SECRET_RES: { kind: string; re: RegExp }[] = [
  { kind: "私钥", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{0,4000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  // Info.plist 用的是 <key>X</key><string>Y</string>，不是 key = "value"
  {
    kind: "密钥",
    re: new RegExp(`<key>\\s*(?:${SECRET_KEYWORDS})[^<]{0,20}<\\/key>\\s*<string>([^<]{6,200})<\\/string>`, "gi")
  },
  {
    kind: "AK/SK",
    re: /(?:AKID|AKSK|SecretId|SecretKey|accessKeyId|accessKeySecret|accessKey)\s*[:=]\s*["'`]([A-Za-z0-9/+=_.-]{12,80})["'`]/gi
  },
  // 大小写都要认：小程序 / 客户端里 TOKEN、APP_SECRET 很常见
  {
    kind: "密钥",
    re: new RegExp(
      `(?:${SECRET_KEYWORDS})\\s*[:=]\\s*["'\`]([A-Za-z0-9!@#$%^&*()_+\\-={}[\\]:;,.?/]{6,120})["'\`]`,
      "gi"
    )
  },
  // 没有键名、只有前缀的裸钥（dex 字符串表、编译产物里常见）
  { kind: "密钥", re: /\b(?:ak_live|sk_live|ak_test|sk_test|AKIA|ASIA|AIza|ghp_|gho_|xoxb-|xoxp-|glpat-)[A-Za-z0-9_-]{8,80}/g },
  { kind: "AppID", re: /(?:appId|appid|app_id)\s*[:=]\s*["'`](wx[a-f0-9]{16}|[A-Za-z0-9_]{8,40})["'`]/gi }
];

interface TextHits {
  endpoints: string[];
  secrets: MobileSecret[];
}

function newHits(): TextHits {
  return { endpoints: [], secrets: [] };
}

function normalizeHost(url: string): string {
  return url.replace(/[",'`)\]]+$/, "").slice(0, 200);
}

function collectHits(text: string, source: string, hits: TextHits, appIds = new Set<string>()): void {
  for (const m of text.matchAll(URL_RE)) {
    const url = normalizeHost(m[0]);
    if (!/^https?:\/\/[A-Za-z0-9.-]+/.test(url)) continue;
    if (/\.(png|jpg|jpeg|gif|svg|webp|css|woff2?|ttf|ico)$/i.test(url)) continue;
    if (URL_NOISE_RE.test(url)) continue;
    if (hits.endpoints.length < MAX_ENDPOINTS && !hits.endpoints.includes(url)) hits.endpoints.push(url);
  }
  for (const m of text.matchAll(PATH_RE)) {
    const p = m[1];
    if (hits.endpoints.length < MAX_ENDPOINTS && !hits.endpoints.includes(p)) hits.endpoints.push(p);
  }
  for (const rule of SECRET_RES) {
    for (const m of text.matchAll(rule.re)) {
      if (hits.secrets.length >= MAX_SECRETS) return;
      const value = (m[1] ?? m[0]).trim();
      if (value.length < 6) continue;
      if (rule.kind === "AppID" && !/^wx[a-f0-9]{16}$/i.test(value) && value.length < 12) continue;
      if (rule.kind === "AppID") appIds.add(value);
      if (hits.secrets.some((s) => s.value === value)) continue;
      hits.secrets.push({ kind: rule.kind, value: value.slice(0, 300), source });
    }
  }
}

/* ---------------- 小程序源码 / 解包 ---------------- */

interface MiniResult {
  files: number;
  appId?: string;
  pages: string[];
  endpoints: string[];
  secrets: MobileSecret[];
  notes: string[];
  log: string[];
  profile: MiniProfile;
}

async function analyzeMiniSource(dir: string, log: string[]): Promise<MiniResult> {
  const notes: string[] = [];
  const hits = newHits();
  const appIds = new Set<string>();
  const pages: string[] = [];
  const profile: MiniProfile = {
    source: "unknown",
    pages,
    subPackages: [],
    tabBar: [],
    plugins: [],
    privateInfos: [],
    cloudEnv: [],
    cloudDev: false,
    upload: false,
  };
  let files = 0;

  const appJson = await readJson(path.join(dir, "app.json"));
  if (appJson) {
    profile.source = "wechat";
    const push = (list: unknown) => {
      if (!Array.isArray(list)) return;
      for (const item of list) {
        if (typeof item === "string" && !pages.includes(item)) pages.push(item);
        else if (item && typeof item === "object" && typeof (item as any).root === "string") {
          const sub = (item as any).pages;
          if (Array.isArray(sub)) for (const p of sub) if (typeof p === "string" && !pages.includes(`${(item as any).root}/${p}`)) pages.push(`${(item as any).root}/${p}`);
        }
      }
    };
    push(appJson.pages);
    const subPackages = appJson.subPackages ?? appJson.subpackages;
    push(subPackages);
    if (Array.isArray(subPackages)) {
      for (const sub of subPackages as any[]) {
        if (typeof sub?.root !== "string") continue;
        profile.subPackages.push({
          root: sub.root,
          count: Array.isArray(sub.pages) ? sub.pages.length : 0,
          independent: sub.independent === true,
        });
      }
    }
    if (appJson.tabBar?.list) {
      for (const tab of appJson.tabBar.list) {
        if (typeof tab?.pagePath !== "string") continue;
        if (!profile.tabBar.includes(tab.pagePath)) profile.tabBar.push(tab.pagePath);
        if (!pages.includes(tab.pagePath)) pages.push(tab.pagePath);
      }
    }
    const plugins = appJson.plugins;
    if (plugins && typeof plugins === "object") {
      profile.plugins = Object.keys(plugins);
      notes.push(`声明了插件：${profile.plugins.join("、")}`);
    }
    if (appJson.requiredPrivateInfos) {
      profile.privateInfos = ([].concat(appJson.requiredPrivateInfos) as unknown[])
        .filter((v): v is string => typeof v === "string")
        .slice(0, 24);
      notes.push(`用了隐私接口：${profile.privateInfos.slice(0, 12).join("、")}`);
    }
    const permission = appJson.permission;
    if (permission && typeof permission === "object") {
      profile.scopes = Object.entries(permission)
        .slice(0, 24)
        .map(([scope, value]) => ({
          scope,
          desc: typeof (value as any)?.desc === "string" ? (value as any).desc : "",
        }));
      if (profile.scopes.length) notes.push(`申请了 ${profile.scopes.length} 个授权 scope：${profile.scopes.map((s) => s.scope).slice(0, 8).join("、")}`);
    }
  } else {
    const pagesJson = await readJson(path.join(dir, "pages.json"));
    if (pagesJson) {
      profile.source = "uniapp";
      const push = (list: unknown) => {
        if (!Array.isArray(list)) return;
        for (const item of list) {
          const p = typeof item === "string" ? item : (item as any)?.path;
          if (typeof p === "string" && !pages.includes(p)) pages.push(p);
        }
      };
      push(pagesJson.pages);
      for (const sub of (pagesJson.subPackages ?? pagesJson.subpackages ?? []) as any[]) {
        if (typeof sub?.root !== "string" || !Array.isArray(sub.pages)) continue;
        profile.subPackages.push({ root: sub.root, count: sub.pages.length, independent: sub.independent === true });
        for (const p of sub.pages) if (typeof p === "string" && !pages.includes(`${sub.root}/${p}`)) pages.push(`${sub.root}/${p}`);
      }
      for (const tab of (pagesJson.tabBar?.list ?? []) as any[]) {
        if (typeof tab?.pagePath !== "string") continue;
        if (!profile.tabBar.includes(tab.pagePath)) profile.tabBar.push(tab.pagePath);
        if (!pages.includes(tab.pagePath)) pages.push(tab.pagePath);
      }
      notes.push("这是 uni-app 工程：页面清单取自 pages.json，编译后的产物在 dist/ 或 mp-weixin/ 下另算。");
    } else {
      notes.push("没读到 app.json：可能是分包目录或解包不完整，页面清单要人工看。");
    }
  }

  const manifest = await readJson(path.join(dir, "manifest.json"));
  const mpAppId = typeof manifest?.["mp-weixin"]?.appid === "string" ? manifest["mp-weixin"].appid : undefined;
  if (mpAppId) appIds.add(mpAppId);

  const project = await readJson(path.join(dir, "project.config.json"));
  const appId = typeof project?.appid === "string" ? project.appid : undefined;
  if (appId) appIds.add(appId);

  const cloudEnv: string[] = [];
  const sdkHints = new Set<string>();
  const referenced = new Set<string>();
  const texts = await walkFiles(dir);
  for (const file of texts) {
    const lower = file.toLowerCase();
    if (!/\.(js|ts|json|wxml|wxs|vue|map|env)$/.test(lower)) continue;
    if (files >= MAX_TEXTS) break;
    let stat;
    try {
      stat = await fsp.stat(file);
    } catch {
      continue;
    }
    if (stat.size > MAX_TEXT_BYTES) continue;
    let text = "";
    try {
      text = await fsp.readFile(file, "utf8");
    } catch {
      continue;
    }
    files += 1;
    const rel = path.relative(dir, file);
    collectHits(text, rel, hits, appIds);
    // 认出框架 / SDK：不同运行时决定后面抽代码的方式
    if (/wx\.cloud\./.test(text)) sdkHints.add("微信云开发");
    if (/dcloud|\buni\.(?:request|navigateTo|getSystemInfo)/.test(text)) sdkHints.add("uni-app 运行时");
    if (/vant-weapp|@vant\//.test(text)) sdkHints.add("Vant Weapp");
    if (/taro/i.test(text)) sdkHints.add("Taro");
    if (/echarts/i.test(text)) sdkHints.add("ECharts");
    if (/qqmap|apis\.map\.qq\.com|amap\.com/.test(text)) sdkHints.add("地图 SDK");
    if (/wx\.login|code2Session/.test(text)) sdkHints.add("微信登录");
    if (/getPhoneNumber|decryptData/.test(text)) sdkHints.add("手机号解密");
    // 页面跳转引用了哪些页面，用来找没入口的孤儿页
    for (const m of text.matchAll(/url\s*[:=]\s*["'`]\/?([A-Za-z0-9_\-/]{2,80})/g)) {
      referenced.add(m[1].replace(/^\/+/, "").replace(/[?#].*$/, ""));
    }
    for (const m of text.matchAll(/env\s*:\s*["'`]([A-Za-z0-9_-]{4,40})["'`]/g)) {
      if (!cloudEnv.includes(m[1])) cloudEnv.push(m[1]);
    }
    if (/wx\.cloud\.(init|callFunction|uploadFile|database)|cloudfunctions/.test(text)) {
      profile.cloudDev = true;
      if (!notes.some((n) => n.includes("云开发"))) {
        notes.push("用了微信云开发（wx.cloud / cloudfunctions）：函数名和权限要单独看，云函数鉴权常缺。");
      }
    }
    if (/wx\.uploadFile|uploadFile\s*\(/.test(text)) {
      profile.upload = true;
      if (!notes.some((n) => n.includes("上传接口"))) {
        notes.push("有上传接口（wx.uploadFile）：按上传链打，别停在能传能下。");
      }
    }
  }
  // 体积与完整性：微信主包 2MB / 整包 20MB 的限制直接决定能不能发版
  const sizeMap = new Map<string, number>();
  let packageSize = 0;
  for (const file of texts) {
    let stat;
    try {
      stat = await fsp.stat(file);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;
    packageSize += stat.size;
    sizeMap.set(path.relative(dir, file).replace(/\\/g, "/"), stat.size);
  }
  profile.packageSize = packageSize;
  profile.heaviest = [...sizeMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([rel, size]) => ({ path: rel, size }));

  for (const sub of profile.subPackages) {
    const prefix = `${sub.root.replace(/^\/+/, "").replace(/\/+$/, "")}/`;
    let total = 0;
    for (const [rel, size] of sizeMap) if (rel.startsWith(prefix)) total += size;
    sub.size = total;
  }

  const residue: string[] = [];
  if ([...sizeMap.keys()].some((rel) => rel.endsWith(".map"))) residue.push("存在 sourcemap（.map）：可直接还原源码结构");
  if (sizeMap.has("project.private.config.json")) residue.push("打包带上了 project.private.config.json：本地调试配置外泄");
  const setting = (project?.setting ?? {}) as Record<string, unknown>;
  if (setting.urlCheck === false) residue.push("urlCheck=false：开发时不校验合法域名，接口可能不在白名单");
  if (setting.minified === false) residue.push("代码未压缩（minified=false）");
  if (project?.debug === true) residue.push("project.config.json 开着 debug");
  profile.debugResidue = residue;
  if (residue.length) notes.push(`调试残留：${residue.join("；")}`);

  if (profile.source === "wechat" && pages.length) {
    const missing: { page: string; missing: string[] }[] = [];
    for (const page of pages.slice(0, 120)) {
      const clean = page.replace(/^\/+/, "");
      const lack = ["js", "wxml"].filter((ext) => !sizeMap.has(`${clean}.${ext}`));
      if (lack.length === 2) missing.push({ page, missing: lack });
    }
    profile.missingPages = missing;
    if (missing.length) {
      notes.push(`${missing.length} 个页面在磁盘上没有文件：分包没解全，或声明了没实现。`);
    }
    const tabSet = new Set(profile.tabBar.map((p) => p.replace(/^\/+/, "")));
    profile.orphanPages = pages
      .map((p) => p.replace(/^\/+/, ""))
      .filter((p) => !tabSet.has(p) && !referenced.has(p))
      .slice(0, 30);
    if (profile.orphanPages.length) notes.push(`${profile.orphanPages.length} 个页面没被 tabBar 或跳转引用，可能是隐藏入口。`);
  }

  profile.sdks = [...sdkHints];
  if (profile.sdks.length) notes.push(`运行时与 SDK：${profile.sdks.join("、")}`);

  profile.insecure = hits.endpoints
    .filter(
      (e) =>
        /^http:\/\//i.test(e) ||
        /\/\/(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|localhost\b)/i.test(e),
    )
    .slice(0, 40);
  if (profile.insecure.length) notes.push(`明文 http / 内网地址 ${profile.insecure.length} 个：不能直接打，先确认从公网能不能到。`);

  profile.appId = [...appIds][0];
  profile.cloudEnv = cloudEnv;
  profile.pages = pages;
  if (cloudEnv.length) notes.push(`云开发环境 id：${cloudEnv.slice(0, 6).join("、")}`);
  log.push(`小程序源码：${files} 个文本文件，${pages.length} 个页面，${hits.endpoints.length} 个接口候选`);

  return { files, appId: [...appIds][0], pages, endpoints: hits.endpoints, secrets: hits.secrets, notes, log, profile };
}

interface WxapkgFile {
  name: string;
  offset: number;
  size: number;
}

async function unpackWxapkg(file: string, outDir: string, log: string[]): Promise<number> {
  const buf = await fsp.readFile(file);
  if (buf.length < 20) throw new Error("文件太小，不像 wxapkg");
  if (buf[0] !== 0xbe) {
    const head = buf.subarray(0, 8).toString("latin1");
    if (/^V1MMWX/.test(head)) throw new Error("这是加密的 wxapkg（PC 端老版本），要先解密再分析");
    throw new Error("不是标准 wxapkg：首字节不是 0xBE，可能被改过或不是小程序包");
  }
  const indexLen = buf.readUInt32BE(5);
  const bodyLen = buf.readUInt32BE(9);
  const count = buf.readUInt32BE(14);
  if (count <= 0 || count > 200_000) throw new Error(`包内文件数异常（${count}），包可能损坏`);
  const bodyStart = 14 + indexLen;
  if (bodyStart > buf.length) throw new Error("索引长度超出文件大小，包被截断");

  const files: WxapkgFile[] = [];
  let pos = 18;
  for (let i = 0; i < count; i += 1) {
    if (pos + 4 > buf.length) break;
    const nameLen = buf.readUInt32BE(pos);
    pos += 4;
    if (nameLen <= 0 || nameLen > 1024 || pos + nameLen + 8 > buf.length) break;
    const name = buf.subarray(pos, pos + nameLen).toString("utf8");
    pos += nameLen;
    const offset = buf.readUInt32BE(pos);
    pos += 4;
    const size = buf.readUInt32BE(pos);
    pos += 4;
    if (offset + size > bodyLen + 1) continue;
    files.push({ name, offset, size });
  }
  if (!files.length) throw new Error("索引里没解出文件，包格式不常见");

  await fsp.mkdir(outDir, { recursive: true });
  let written = 0;
  for (const entry of files) {
    const rel = entry.name
      .replace(/\\/g, "/")
      .split("/")
      .filter((seg) => seg && seg !== "." && seg !== "..")
      .join("/");
    if (!rel) continue;
    const target = path.join(outDir, rel);
    if (!target.startsWith(outDir)) continue;
    const data = buf.subarray(bodyStart + entry.offset, bodyStart + entry.offset + entry.size);
    await fsp.mkdir(path.dirname(target), { recursive: true }).catch(() => undefined);
    await fsp.writeFile(target, data).catch(() => undefined);
    written += 1;
  }
  log.push(`wxapkg 解包：${written} 个文件 → ${outDir}`);
  return written;
}

/* ---------------- ZIP（APK / IPA 共用） ---------------- */

interface ZipEntry {
  name: string;
  method: number;
  csize: number;
  size: number;
  offset: number;
}

function readZipEntries(buf: Buffer): ZipEntry[] {
  let eocd = -1;
  const min = Math.max(0, buf.length - 70_000);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("不是有效的 zip/apk/ipa（找不到中央目录）");
  const total = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];
  for (let i = 0; i < total; i += 1) {
    if (offset + 46 > buf.length) break;
    if (buf.readUInt32LE(offset) !== 0x02014b50) break;
    const method = buf.readUInt16LE(offset + 10);
    const csize = buf.readUInt32LE(offset + 20);
    const size = buf.readUInt32LE(offset + 24);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localOffset = buf.readUInt32LE(offset + 42);
    // 少数打包工具（含部分 Windows 脚本）会用反斜杠当分隔符，统一成正斜杠再匹配
    const name = buf.subarray(offset + 46, offset + 46 + nameLen).toString("utf8").replace(/\\/g, "/");
    entries.push({ name, method, csize, size, offset: localOffset });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readZipFile(buf: Buffer, entry: ZipEntry, limit = 8_000_000): Buffer | undefined {
  if (entry.size > limit) return undefined;
  const at = entry.offset;
  if (at + 30 > buf.length || buf.readUInt32LE(at) !== 0x04034b50) return undefined;
  const nameLen = buf.readUInt16LE(at + 26);
  const extraLen = buf.readUInt16LE(at + 28);
  const start = at + 30 + nameLen + extraLen;
  const raw = buf.subarray(start, start + entry.csize);
  if (entry.method === 0) return raw;
  if (entry.method === 8) {
    try {
      return zlib.inflateRawSync(raw);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/* ---------------- AndroidManifest（二进制 AXML） ---------------- */

interface AxmlResult {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: string;
  targetSdk?: string;
  permissions: string[];
  components: MobileComponent[];
  /** provider 的 authorities，用来拼 content:// 直接查 */
  authorities: string[];
  /** intent-filter 里的 scheme / host */
  deepLinks: string[];
  strings: string[];
  /** <application> 上的安全开关 */
  appFlags?: {
    debuggable: boolean;
    allowBackup: boolean;
    cleartext: boolean;
    networkSecurityConfig?: string;
    backupAgent?: string;
    testOnly: boolean;
  };
  /** 带 MAIN + LAUNCHER 的组件名 */
  launcher?: string;
  /** application android:label 的字面量；引用 @string/xxx 时在 labelRef 里 */
  label?: string;
  /** label 指向的 resId（0xPPTTEEEE），由 resources.arsc 还原成真实名称 */
  labelRef?: number;
}

function axmlStringPool(buf: Buffer, start: number): string[] {
  const count = buf.readUInt32LE(start + 8);
  const flags = buf.readUInt32LE(start + 16);
  const stringsStart = buf.readUInt32LE(start + 20);
  const utf8 = (flags & 0x100) !== 0;
  const base = start + stringsStart;
  const out: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const at = start + 28 + i * 4;
    if (at + 4 > buf.length) break;
    let pos = base + buf.readUInt32LE(at);
    if (pos >= buf.length) continue;
    try {
      if (utf8) {
        let len = buf[pos];
        pos += 1;
        if (len & 0x80) {
          len = ((len & 0x7f) << 8) | buf[pos];
          pos += 1;
        }
        // UTF-8 串有一个 UTF-16 字符数前缀，紧跟一个字节长度前缀；截取要按字节长度
        let len2 = buf[pos];
        pos += 1;
        if (len2 & 0x80) {
          len2 = ((len2 & 0x7f) << 8) | buf[pos];
          pos += 1;
        }
        out.push(buf.subarray(pos, pos + len2).toString("utf8"));
      } else {
        let len = buf.readUInt16LE(pos);
        pos += 2;
        if (len & 0x8000) {
          len = ((len & 0x7fff) << 16) | buf.readUInt16LE(pos);
          pos += 2;
        }
        out.push(buf.subarray(pos, pos + len * 2).toString("utf16le"));
      }
    } catch {
      out.push("");
    }
  }
  return out;
}

function parseAxml(buf: Buffer): AxmlResult {
  const res: AxmlResult = { permissions: [], components: [], authorities: [], deepLinks: [], strings: [] };
  if (buf.length < 16) return res;
  let offset = 8;
  let pool: string[] = [];
  let lastComponent: MobileComponent | undefined;
  // 一个 intent-filter 里同时出现 MAIN 与 LAUNCHER 才算桌面入口。
  // 同一组件可能有多个 filter，所以按 filter 单独记，收口时并入组件级结果，不能中途清掉。
  const mainFlags = new Map<string, { main: boolean; launcher: boolean }>();
  let curFilter: { name: string; main: boolean; launcher: boolean } | undefined;
  const mergeFilter = () => {
    if (!curFilter) return;
    const slot = mainFlags.get(curFilter.name) ?? { main: false, launcher: false };
    mainFlags.set(curFilter.name, {
      main: slot.main || curFilter.main,
      launcher: slot.launcher || curFilter.launcher,
    });
    curFilter = undefined;
  };
  while (offset + 8 <= buf.length) {
    const type = buf.readUInt16LE(offset);
    const headerSize = buf.readUInt16LE(offset + 2);
    const size = buf.readUInt32LE(offset + 4);
    if (size <= 0 || offset + size > buf.length) break;
    if (type === 0x0001) {
      pool = axmlStringPool(buf, offset);
      res.strings = pool;
    } else if (type === 0x0102) {
      const nameIdx = buf.readUInt32LE(offset + 20);
      const attrStart = buf.readUInt16LE(offset + 24);
      const attrSize = buf.readUInt16LE(offset + 26) || 20;
      const attrCount = buf.readUInt16LE(offset + 28);
      const tag = pool[nameIdx] ?? "";
      const attrs: Record<string, { str?: string; bool?: boolean; num?: number; ref?: number }> = {};
      for (let i = 0; i < attrCount; i += 1) {
        const at = offset + 16 + attrStart + i * attrSize;
        if (at + 20 > offset + size) break;
        const key = pool[buf.readUInt32LE(at + 4)] ?? "";
        const raw = buf.readUInt32LE(at + 8);
        const dataType = buf[at + 15];
        const data = buf.readUInt32LE(at + 16);
        if (!key) continue;
        if (dataType === 0x03) attrs[key] = { str: pool[data] ?? (raw ? pool[raw] : undefined) };
        else if (dataType === 0x12) attrs[key] = { bool: data !== 0, num: data };
        else if (dataType === 0x10 || dataType === 0x11) attrs[key] = { num: data };
        else if (dataType === 0x01) attrs[key] = { ref: data, str: raw ? pool[raw] : undefined };
      }
      // 属性名带 android: 前缀，按后缀匹配才算得到
      const pick = (key: string) =>
        Object.entries(attrs).find(([k]) => k === key || k.endsWith(`:${key}`))?.[1];
      const strOf = (key: string) => pick(key)?.str;
      if (tag === "manifest") {
        // manifest 上是 package，不是 name
        const pkg = strOf("package");
        if (pkg) res.packageName = pkg;
        const versionName = strOf("versionName");
        if (versionName) res.versionName = versionName;
        const versionCode = pick("versionCode");
        if (versionCode?.num !== undefined) res.versionCode = String(versionCode.num);
        else if (versionCode?.str) res.versionCode = versionCode.str;
      } else if (tag === "uses-sdk") {
        const min = pick("minSdkVersion");
        if (min) res.minSdk = min.num !== undefined ? String(min.num) : min.str;
        const target = pick("targetSdkVersion");
        if (target) res.targetSdk = target.num !== undefined ? String(target.num) : target.str;
      } else if (tag === "application") {
        const boolOf = (key: string) => pick(key)?.bool;
        res.appFlags = {
          debuggable: boolOf("debuggable") === true,
          // allowBackup 默认 true，只有显式写 false 才算关掉
          allowBackup: boolOf("allowBackup") !== false,
          // targetSdk >= 28 默认 false；清单里没写、SDK 又不到 28 就是明文放行
          cleartext: boolOf("usesCleartextTraffic") ?? !(Number(res.targetSdk ?? 0) >= 28),
          networkSecurityConfig: strOf("networkSecurityConfig"),
          backupAgent: strOf("backupAgent"),
          testOnly: boolOf("testOnly") === true,
        };
        // 应用显示名：字面量直接用，@string 引用留给 resources.arsc 还原
        const labelAttr = pick("label");
        if (labelAttr?.str) res.label = labelAttr.str;
        else if (labelAttr?.ref) res.labelRef = labelAttr.ref;
      } else if (tag === "uses-permission" || tag === "uses-permission-sdk-23") {
        const name = strOf("name");
        if (name && !res.permissions.includes(name)) res.permissions.push(name);
      } else if (["activity", "activity-alias", "service", "receiver", "provider"].includes(tag)) {
        mergeFilter();
        const rawName = strOf("name");
        if (rawName) {
          // 以 . 开头的是相对包名，补全后才好直接拿去实测
          const name = rawName.startsWith(".") && res.packageName ? `${res.packageName}${rawName}` : rawName;
          const component: MobileComponent = {
            type: tag,
            name,
            exported: pick("exported")?.bool === true,
            permission: strOf("permission"),
            deepLinks: [],
          };
          res.components.push(component);
          lastComponent = component;
          if (tag === "provider") {
            for (const authority of (strOf("authorities") ?? "").split(";")) {
              const clean = authority.trim();
              if (clean && !res.authorities.includes(clean)) res.authorities.push(clean);
            }
          }
        }
      } else if (tag === "intent-filter") {
        // 同一个组件常有多个 filter，先把上一条收口，再开新的一条
        mergeFilter();
        if (lastComponent) curFilter = { name: lastComponent.name, main: false, launcher: false };
      } else if (tag === "action" || tag === "category") {
        const value = strOf("name") ?? "";
        if (curFilter && curFilter.name === lastComponent?.name) {
          if (value.endsWith("action.MAIN")) curFilter.main = true;
          if (value.endsWith("category.LAUNCHER")) curFilter.launcher = true;
        }
      } else if (tag === "data" && lastComponent) {
        const scheme = strOf("scheme");
        const host = strOf("host");
        if (scheme) {
          const link = host ? `${scheme}://${host}` : `${scheme}://`;
          if (!res.deepLinks.includes(link)) res.deepLinks.push(link);
          const own = lastComponent.deepLinks ?? (lastComponent.deepLinks = []);
          if (!own.includes(link)) own.push(link);
        }
      }
    }
    offset += size;
    if (headerSize > size) break;
  }
  mergeFilter(); // 收口最后一个 filter，否则末尾那条会丢
  for (const [name, flags] of mainFlags) {
    if (!flags.main || !flags.launcher) continue;
    res.launcher = name;
    const comp = res.components.find((c) => c.name === name);
    if (comp) comp.launcher = true;
    break;
  }
  return res;
}

/* ---------------- APK / IPA ---------------- */

const IMPORTANT_PERMISSIONS = /(LOCATION|CAMERA|RECORD_AUDIO|READ_SMS|READ_CONTACTS|READ_CALL_LOG|READ_PHONE_STATE|MANAGE_EXTERNAL_STORAGE|QUERY_ALL_PACKAGES|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|GET_ACCOUNTS|BLUETOOTH|NFC|BODY_SENSORS|READ_MEDIA)/;

/**
 * APK Signing Block 紧贴在中央目录前面：末尾 16 字节是魔数，
 * 里面按 (u64 长度, u32 id, value) 排列，v2 = 0x7109871a，v3 = 0xf05368c0。
 */
function readSigningSchemes(buf: Buffer, cdOffset: number): { v2: boolean; v3: boolean } {
  const out = { v2: false, v3: false };
  if (cdOffset < 32 || cdOffset > buf.length) return out;
  if (buf.subarray(cdOffset - 16, cdOffset).toString("latin1") !== "APK Sig Block 42") return out;
  try {
    const size = Number(buf.readBigUInt64LE(cdOffset - 24));
    const start = cdOffset - 8 - size;
    if (!Number.isFinite(size) || size <= 24 || start < 0) return out;
    let pos = start + 8;
    const end = cdOffset - 24;
    while (pos + 12 <= end) {
      const len = Number(buf.readBigUInt64LE(pos));
      pos += 8;
      if (!Number.isFinite(len) || len < 4 || pos + len > end) break;
      const id = buf.readUInt32LE(pos);
      if (id === 0x7109871a) out.v2 = true;
      else if (id === 0xf05368c0) out.v3 = true;
      pos += len;
    }
  } catch {
    // 块坏了就当没读到，v1 仍然按 META-INF 证书算
  }
  return out;
}

function zipCdOffset(buf: Buffer): number | undefined {
  const min = Math.max(0, buf.length - 70_000);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) !== 0x06054b50) continue;
    const offset = buf.readUInt32LE(i + 16);
    return offset > 0 && offset < buf.length ? offset : undefined;
  }
  return undefined;
}

/** 第三方 SDK 在 dex 里都以包路径出现，按包名认比按类名稳 */
const SDK_MARKERS: { name: string; re: RegExp }[] = [
  { name: "微信开放 SDK", re: /com\/tencent\/mm\/opensdk|com\.tencent\.mm\.opensdk/ },
  { name: "支付宝 SDK", re: /com\/alipay\/sdk|com\.alipay\.sdk/ },
  { name: "极光推送", re: /cn\/jpush|cn\.jpush/ },
  { name: "友盟统计", re: /com\/umeng|com\.umeng/ },
  { name: "腾讯 Bugly", re: /com\/tencent\/bugly|com\.tencent\.bugly/ },
  { name: "高德地图", re: /com\/amap\/api|com\.amap\.api/ },
  { name: "百度地图", re: /com\/baidu\/mapapi|com\.baidu\.mapapi/ },
  { name: "Firebase", re: /com\/google\/firebase|com\.google\.firebase/ },
  { name: "声网 Agora", re: /io\/agora|io\.agora/ },
  { name: "个推", re: /com\/igexin|com\.igexin/ },
  { name: "华为 HMS", re: /com\/huawei\/hms|com\.huawei\.hms/ },
  { name: "穿山甲广告", re: /com\/bytedance\/sdk\/openadsdk|com\.bytedance\.sdk\.openadsdk/ },
  { name: "腾讯 X5 内核", re: /com\/tencent\/smtt|com\.tencent\.smtt/ },
  { name: "腾讯 IM", re: /com\/tencent\/imsdk|com\.tencent\.imsdk/ },
  { name: "融云 IM", re: /io\/rong|io\.rong/ },
  { name: "环信 IM", re: /com\/hyphenate|com\.hyphenate/ },
  { name: "阿里云 OSS", re: /com\/alibaba\/sdk\/android\/oss|com\.alibaba\.sdk\.android\.oss/ },
  { name: "OkHttp", re: /okhttp3\/|okhttp3\./ },
  { name: "Retrofit", re: /retrofit2\/|retrofit2\./ },
  { name: "RxJava", re: /io\/reactivex|io\.reactivex/ },
  { name: "数美风控", re: /com\/ishumei|com\.ishumei/ },
  { name: "网易易盾", re: /com\/netease\/nis|com\.netease\.nis/ },
  { name: "Weex", re: /com\/taobao\/weex|com\.taobao\.weex/ },
  { name: "React Native", re: /com\/facebook\/react|com\.facebook\.react/ },
  { name: "Cordova", re: /org\/apache\/cordova|org\.apache\.cordova/ },
  { name: "uni-app 运行时", re: /io\/dcloud|io\.dcloud/ },
  { name: "腾讯地图 SDK", re: /com\/tencent\/map|com\.tencent\.map/ },
  { name: "快手/字节 埋点", re: /com\/kuaishou|com\.kuaishou/ },
];

/** dex 里的安全线索：JS 桥、动态加载、反调试这类会直接改变打法 */
const RUNTIME_MARKERS: { hint: string; re: RegExp }[] = [
  { hint: "WebView JS 桥（addJavascriptInterface）", re: /addJavascriptInterface/ },
  { hint: "WebView 允许 file:// 跨源（setAllowUniversalAccessFromFileURLs）", re: /setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs/ },
  { hint: "动态加载 dex（DexClassLoader / InMemoryDexClassLoader）", re: /DexClassLoader|InMemoryDexClassLoader|BaseDexClassLoader/ },
  { hint: "运行时加载 native 库（System.load / dlopen）", re: /System\.load\(|dlopen|System\.loadLibrary/ },
  { hint: "反调试（isDebuggerConnected / ptrace）", re: /isDebuggerConnected|android\/os\/Debug|ptrace/ },
  { hint: "root 检测（su / test-keys / superuser）", re: /superuser\.apk|\/system\/bin\/su|test-keys|isRooted/ },
  { hint: "模拟器检测（goldfish / qemu / ro.kernel）", re: /goldfish|ro\.kernel\.qemu|generic_x86|isEmulator/ },
  { hint: "Xposed / Frida 检测", re: /de\/robv\/android\/xposed|XposedBridge|frida|re\.frida/ },
];

const PINNING_MARKERS: { hint: string; re: RegExp }[] = [
  { hint: "OkHttp CertificatePinner", re: /CertificatePinner/ },
  { hint: "公钥 pin（sha256/ 前缀）", re: /sha256\/[A-Za-z0-9+/=]{16,}/ },
  { hint: "自定义 X509TrustManager", re: /X509TrustManager/ },
  { hint: "HostnameVerifier 覆写", re: /setHostnameVerifier|HostnameVerifier/ },
  { hint: "network_security_config", re: /network_security_config|networkSecurityConfig/ },
];

async function analyzeApk(file: string, outDir: string, log: string[]): Promise<Omit<MobileAnalysis, "target" | "outDir" | "briefPath">> {
  const buf = await fsp.readFile(file);
  const entries = readZipEntries(buf);
  const notes: string[] = [];
  const logLines = [...log];
  const hits = newHits();
  const appIds = new Set<string>();

  const dex = entries.filter((e) => /^classes\d*\.dex$/.test(e.name));
  const libs = entries.filter((e) => e.name.startsWith("lib/") && e.name.endsWith(".so"));
  const frameworks = [...new Set(libs.map((e) => e.name.split("/")[1]))];
  const assets = entries.filter((e) => e.name.startsWith("assets/") && !e.name.endsWith("/"));
  const hasSignature = entries.some((e) => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(e.name));
  const hasManifestMf = entries.some((e) => e.name === "META-INF/MANIFEST.MF");
  const cdOffset = zipCdOffset(buf);
  const sigBlock = cdOffset ? readSigningSchemes(buf, cdOffset) : { v2: false, v3: false };
  const nativeLibs = [...new Map(libs.map((e) => [path.basename(e.name), e.size])).entries()]
    .map(([name, size]) => ({ name, size }))
    .sort((a, b) => b.size - a.size)
    .slice(0, 40);

  const manifestEntry = entries.find((e) => e.name === "AndroidManifest.xml");
  let axml: AxmlResult = { permissions: [], components: [], authorities: [], deepLinks: [], strings: [] };
  if (manifestEntry) {
    const data = readZipFile(buf, manifestEntry);
    if (data) {
      try {
        axml = parseAxml(data);
        logLines.push(`AndroidManifest：包名 ${axml.packageName ?? "未读到"}，权限 ${axml.permissions.length} 条，组件 ${axml.components.length} 个`);
      } catch (err) {
        notes.push(`AndroidManifest 解析失败：${err instanceof Error ? err.message : String(err)}`);
      }
    }
  } else {
    notes.push("包里没有 AndroidManifest.xml，可能不是标准 APK。");
  }

  const guardHints = ["libjiagu", "libshell", "libdexhelper", "libmobisec", "StubShell", "libnesec", "libSecShell", "libapp.so"];
  const guard = guardHints.filter((name) => libs.some((e) => e.name.toLowerCase().includes(name.toLowerCase())));
  if (guard.length) notes.push(`疑似加固：${guard.join("、")}（静态读到的字符串会变少，动态要脱壳后再看）`);

  // dex 与 assets 里抽接口 / 密钥；dex 字符串同时留一份给 SDK / 抓包对抗识别
  let dexText = "";
  for (const entry of dex.slice(0, 6)) {
    const data = readZipFile(buf, entry, 40_000_000);
    if (!data) continue;
    const text = data.toString("latin1");
    const strings = dexStrings(text);
    collectHits(strings, `${entry.name}`, hits, appIds);
    if (dexText.length < 12_000_000) dexText += `\n${strings}`;
  }
  for (const entry of assets.slice(0, 60)) {
    if (entry.size > 800_000) continue;
    const data = readZipFile(buf, entry, 1_000_000);
    if (!data) continue;
    const text = data.toString("utf8");
    if (!/[\x20-\x7e]{8}/.test(text)) continue;
    collectHits(text, entry.name, hits, appIds);
  }

  const components = axml.components;
  const exported = components.filter((c) => c.exported);
  if (exported.length) notes.push(`导出组件 ${exported.length} 个：${exported.slice(0, 8).map((c) => `${c.type}/${c.name}`).join("、")}`);

  const appFlags = axml.appFlags ?? {
    debuggable: false,
    allowBackup: true,
    cleartext: !(Number(axml.targetSdk ?? 0) >= 28),
    testOnly: false,
  };

  const assetNames = entries.map((e) => e.name.toLowerCase());
  const sdks = SDK_MARKERS.filter((m) => m.re.test(dexText)).map((m) => m.name);
  let framework = "";
  if (libs.some((e) => e.name.endsWith("libflutter.so")) || assetNames.some((n) => n.startsWith("assets/flutter_assets/"))) {
    framework = "Flutter";
  } else if (assetNames.includes("assets/index.android.bundle")) {
    framework = "React Native";
  } else if (assetNames.some((n) => n.includes("__uni__"))) {
    framework = "uni-app";
  } else if (assetNames.some((n) => n.startsWith("assets/www/")) || sdks.includes("Cordova")) {
    framework = "Cordova / H5 混合";
  } else if (libs.some((e) => e.name.includes("libweex"))) {
    framework = "Weex";
  } else if (assetNames.some((n) => n.endsWith(".html"))) {
    framework = "H5 混合";
  }
  if (framework) sdks.unshift(framework);
  if (framework) {
    notes.push(
      framework === "Flutter"
        ? "框架：Flutter（业务逻辑在 libapp.so，dex 里抽不到接口，要按 so 字符串和流量走）"
        : `框架：${framework}`,
    );
  }

  const pinning = PINNING_MARKERS.filter((m) => m.re.test(dexText)).map((m) => m.hint);
  if (appFlags.networkSecurityConfig) pinning.push(`清单挂了 ${appFlags.networkSecurityConfig}`);
  const runtimeHints = RUNTIME_MARKERS.filter((m) => m.re.test(dexText)).map((m) => m.hint);
  const weakTls = /TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER/.test(dexText);

  if (appFlags.debuggable) notes.push("debuggable=true：可 jdwp 直接附加，比纯静态好打。");
  if (appFlags.networkSecurityConfig) notes.push(`网络配置：${appFlags.networkSecurityConfig}（明文与抓包策略写在这里）`);
  if (pinning.length) notes.push(`抓包对抗：${pinning.join("、")}`);
  if (runtimeHints.length) notes.push(`运行期线索：${runtimeHints.join("、")}`);
  if (sdks.length) notes.push(`SDK：${sdks.join("、")}`);

  const risks: { level: "high" | "mid" | "low"; text: string }[] = [];
  if (appFlags.debuggable) risks.push({ level: "high", text: "可调试（debuggable=true）：可 jdwp 附加进程，读写内存、直调组件" });
  if (exported.length) risks.push({ level: "mid", text: `导出组件 ${exported.length} 个：任意应用可拉起、发广播、查 provider` });
  if (appFlags.allowBackup) risks.push({ level: "mid", text: "允许备份（allowBackup 未关）：adb backup 可导出私有数据" });
  if (appFlags.cleartext) risks.push({ level: "mid", text: "允许明文 HTTP：流量可被中间人读取与篡改" });
  if (weakTls) risks.push({ level: "mid", text: "宽松 TLS 校验（TrustAllCerts / ALLOW_ALL_HOSTNAME_VERIFIER）：中间人可直接解密" });
  if (!sigBlock.v2 && !sigBlock.v3) risks.push({ level: "mid", text: "缺 v2/v3 签名：可被二次打包替换" });
  if (appFlags.testOnly) risks.push({ level: "mid", text: "testOnly=true：这是测试包，不该出现在生产" });
  if (!pinning.length) risks.push({ level: "low", text: "未检出证书固定：可挂代理抓包" });
  if (guard.length) risks.push({ level: "low", text: "已加固：静态字符串不全，要脱壳再看" });

  // 结构清单
  const structureDir = path.join(outDir, "structure");
  await fsp.mkdir(structureDir, { recursive: true });
  await fsp.writeFile(
    path.join(structureDir, "包内清单.txt"),
    [
      `文件：${path.basename(file)}`,
      `条目总数：${entries.length}`,
      `包名：${axml.packageName ?? "未读到"}  版本：${axml.versionName ?? "-"} (${axml.versionCode ?? "-"})`,
      `SDK：min ${axml.minSdk ?? "-"} / target ${axml.targetSdk ?? "-"}`,
      `DEX（${dex.length}）：${dex.map((e) => e.name).join("、") || "无"}`,
      `Native 库（${frameworks.length} 个 ABI 目录）：${frameworks.join("、") || "无"}`,
      `assets 文件：${assets.length}`,
      `签名：v1 ${hasSignature ? "有" : "无"} / v2 ${sigBlock.v2 ? "有" : "无"} / v3 ${sigBlock.v3 ? "有" : "无"}；MANIFEST.MF：${hasManifestMf ? "有" : "无"}`,
      `框架：${framework || "未识别"}  启动入口：${axml.launcher ?? "未读到"}`,
      "",
      "== 安全开关 ==",
      `debuggable：${appFlags.debuggable}`,
      `allowBackup：${appFlags.allowBackup}`,
      `usesCleartextTraffic：${appFlags.cleartext}`,
      `testOnly：${appFlags.testOnly}`,
      `networkSecurityConfig：${appFlags.networkSecurityConfig ?? "无"}`,
      `backupAgent：${appFlags.backupAgent ?? "无"}`,
      "",
      "== 风险基线 ==",
      ...(risks.length ? risks.map((r) => `[${r.level}] ${r.text}`) : ["（没扫到明显风险）"]),
      "",
      "== SDK / 第三方 ==",
      ...(sdks.length ? sdks : ["（未识别）"]),
      "",
      "== 抓包对抗 ==",
      ...(pinning.length ? pinning : ["（未检出）"]),
      "",
      "== 运行期线索 ==",
      ...(runtimeHints.length ? runtimeHints : ["（未检出）"]),
      "",
      "== 权限 ==",
      ...(axml.permissions.length ? axml.permissions : ["（没读到）"]),
      "",
      "== 组件（导出打 *，LAUNCHER 打 ^）==",
      ...(components.length
        ? components.map(
            (c) =>
              `${c.exported ? "*" : " "}${c.launcher ? "^" : " "} ${c.type} ${c.name}${c.permission ? ` [perm ${c.permission}]` : ""}${
                c.deepLinks?.length ? `  ← ${c.deepLinks.join(" ")}` : ""
              }`,
          )
        : ["（没读到）"]),
      "",
      "== 深链 ==",
      ...(axml.deepLinks.length ? axml.deepLinks : ["（没读到）"]),
      "",
      "== Provider authority ==",
      ...(axml.authorities.length ? axml.authorities : ["（没读到）"]),
      "",
      "== Native 库（按体积） ==",
      ...(nativeLibs.length ? nativeLibs.map((l) => `${l.name}\t${l.size}`) : ["（无）"]),
      "",
      "== 库与资源（前 300 条目）==",
      ...entries.slice(0, 300).map((e) => e.name),
    ].join("\r\n"),
    "utf8",
  );

  return {
    files: entries.length,
    extracted: false,
    appId: [...appIds][0],
    packageName: axml.packageName,
    pages: [],
    endpoints: hits.endpoints,
    secrets: hits.secrets,
    permissions: axml.permissions,
    components,
    libraries: nativeLibs.map((l) => l.name),
    notes,
    log: logLines,
    app: {
      packageName: axml.packageName,
      versionName: axml.versionName,
      versionCode: axml.versionCode,
      minSdk: axml.minSdk,
      targetSdk: axml.targetSdk,
      abis: frameworks,
      signedV1: hasSignature,
      signedManifest: hasManifestMf,
      guards: guard,
      providers: axml.authorities,
      deepLinks: axml.deepLinks,
      counts: {
        activity: components.filter((c) => c.type === "activity" || c.type === "activity-alias").length,
        service: components.filter((c) => c.type === "service").length,
        receiver: components.filter((c) => c.type === "receiver").length,
        provider: components.filter((c) => c.type === "provider").length,
      },
      signature: { v1: hasSignature, v2: sigBlock.v2, v3: sigBlock.v3 },
      debugFlags: appFlags,
      launcher: axml.launcher,
      nativeLibs,
      sdks: [...new Set(sdks)],
      pinning,
      runtimeHints,
      dexCount: dex.length,
      risks,
    },
  };
}

/** dex 里按可打印串抽，比全二进制正则稳一些 */
function dexStrings(text: string): string {
  const out: string[] = [];
  let run = "";
  for (let i = 0; i < text.length && out.length < 60_000; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0x20 && code < 0x7f) {
      run += text[i];
    } else {
      if (run.length >= 8) out.push(run);
      run = "";
    }
    if (run.length >= 400) {
      out.push(run);
      run = "";
    }
  }
  if (run.length >= 8) out.push(run);
  return out.join("\n");
}

async function analyzeIpa(file: string, outDir: string, log: string[]): Promise<Omit<MobileAnalysis, "target" | "outDir" | "briefPath">> {
  const buf = await fsp.readFile(file);
  const entries = readZipEntries(buf);
  const notes: string[] = [];
  const logLines = [...log];
  const hits = newHits();
  const appIds = new Set<string>();

  const appDir = entries.find((e) => /^Payload\/[^/]+\.app\//.test(e.name));
  const appName = appDir ? appDir.name.split("/")[1] : undefined;
  if (!appName) notes.push("包里没找到 Payload/*.app，可能不是标准 IPA。");

  const frameworks = [...new Set(entries.map((e) => /^(?:Payload\/[^/]+\.app\/)?Frameworks\/([^/]+)\.framework/.exec(e.name)?.[1]).filter(Boolean) as string[])];
  const plistEntry = entries.find((e) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name));
  let bundleId: string | undefined;
  let displayName: string | undefined;
  let versionName: string | undefined;
  let versionCode: string | undefined;
  let minOs: string | undefined;
  const urlSchemes: string[] = [];
  const usageDescriptions: string[] = [];
  if (plistEntry) {
    const data = readZipFile(buf, plistEntry, 4_000_000);
    if (data) {
      const isBinary = data.subarray(0, 8).toString("latin1") === "bplist00";
      if (!isBinary) {
        const text = data.toString("utf8");
        bundleId = /<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/.exec(text)?.[1];
        displayName = /<key>CFBundleDisplayName<\/key>\s*<string>([^<]+)<\/string>/.exec(text)?.[1];
        versionName = /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/.exec(text)?.[1];
        versionCode = /<key>CFBundleVersion<\/key>\s*<string>([^<]+)<\/string>/.exec(text)?.[1];
        minOs = /<key>MinimumOSVersion<\/key>\s*<string>([^<]+)<\/string>/.exec(text)?.[1];
        collectHits(text, "Info.plist", hits, appIds);
        for (const m of text.matchAll(/<key>(NS[A-Za-z]+UsageDescription)<\/key>\s*<string>([\s\S]*?)<\/string>/g)) {
          const line = `${m[1]}：${m[2].replace(/\s+/g, " ").trim()}`;
          if (!usageDescriptions.includes(line)) usageDescriptions.push(line);
        }
        for (const m of text.matchAll(/<key>CFBundleURLSchemes<\/key>([\s\S]{0,600}?)<\/array>/g)) {
          for (const s of m[1].matchAll(/<string>([^<]+)<\/string>/g)) {
            if (!urlSchemes.includes(s[1])) urlSchemes.push(s[1]);
            notes.push(`URL Scheme：${s[1]}`);
          }
        }
      } else {
        const text = data.toString("latin1");
        const runs = text.match(/[\x20-\x7e]{4,}/g) ?? [];
        const idCandidate = runs.find((r) => /^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z0-9-]+){2,}$/.test(r) && !/^CF|^NS|^UI/.test(r));
        if (idCandidate) bundleId = idCandidate;
        collectHits(runs.join("\n"), "Info.plist（二进制）", hits, appIds);
        notes.push("Info.plist 是二进制 plist，这里只是粗读；要完整键值用 plutil / 在 mac 上看。");
      }
    }
  } else {
    notes.push("包里没有 Info.plist。");
  }

  const binaries = entries.filter((e) => /^Payload\/[^/]+\.app\/[^/]+$/.test(e.name));
  for (const entry of binaries.slice(0, 3)) {
    const data = readZipFile(buf, entry, 2_000_000);
    if (!data || data.length < 8) continue;
    const magic = data.readUInt32BE(0);
    if (magic === 0xcafebabe) notes.push(`主二进制 ${path.basename(entry.name)} 是 fat 包，需要 lipo 拆架构`);
    else if (magic === 0xfeedfacf || magic === 0xfeedface) notes.push(`主二进制 ${path.basename(entry.name)} 是 Mach-O，Frida 直接 attach 就行`);
    // Mach-O 的 __TEXT/__cstring 里 URL 与硬编码钥照样能抽
    collectHits(dexStrings(data.toString("latin1")), `主二进制 ${path.basename(entry.name)}`, hits, appIds);
  }

  // assets / www 下的 js、json、plist 是 H5 包与配置，接口和钥常在这
  for (const entry of entries) {
    if (!/^Payload\/[^/]+\.app\/(?:assets|www)\/.+\.(?:js|json|plist|html?)$/i.test(entry.name)) continue;
    const data = readZipFile(buf, entry, 2_000_000);
    if (!data) continue;
    collectHits(data.toString("utf8"), entry.name, hits, appIds);
  }

  const structureDir = path.join(outDir, "structure");
  await fsp.mkdir(structureDir, { recursive: true });
  await fsp.writeFile(
    path.join(structureDir, "包内清单.txt"),
    [
      `文件：${path.basename(file)}`,
      `条目总数：${entries.length}`,
      `App：${appName ?? "未识别"}`,
      `Bundle ID：${bundleId ?? "未读到"}`,
      `显示名：${displayName ?? "未读到"}`,
      `最低系统：${minOs ?? "未读到"}`,
      `Framework：${frameworks.join("、") || "无"}`,
      "",
      "== 条目（前 300）==",
      ...entries.slice(0, 300).map((e) => e.name),
    ].join("\r\n"),
    "utf8",
  );

  const components: MobileComponent[] = [];
  return {
    files: entries.length,
    extracted: false,
    appId: bundleId ?? [...appIds][0],
    packageName: bundleId,
    pages: [],
    endpoints: hits.endpoints,
    secrets: hits.secrets,
    permissions: usageDescriptions,
    components,
    libraries: frameworks,
    notes,
    log: logLines,
    app: {
      packageName: bundleId,
      versionName,
      versionCode,
      abis: frameworks,
      signedV1: false,
      signedManifest: false,
      guards: [],
      providers: [],
      deepLinks: urlSchemes.map((s) => `${s}://`),
      counts: { activity: 0, service: 0, receiver: 0, provider: 0 },
      iosMinOs: minOs,
    },
  };
}

/* ---------------- 对外：分析入口 ---------------- */

// 记录目标体积：单文件直接 stat，源码工程按文件累加（封顶避免超大工程拖慢）。
async function targetBytes(p: string, fallback: number): Promise<number> {
  try {
    const st = await fsp.stat(p);
    if (!st.isDirectory()) return st.size;
  } catch {
    return fallback;
  }
  let total = 0;
  let seen = 0;
  const walk = async (dir: string) => {
    if (seen > 5000) return;
    let items: { name: string; isDirectory(): boolean }[] = [];
    try {
      items = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const it of items) {
      const full = path.join(dir, it.name);
      if (it.isDirectory()) {
        if (it.name === "node_modules" || it.name === ".git") continue;
        await walk(full);
      } else {
        seen += 1;
        try {
          total += (await fsp.stat(full)).size;
        } catch {
          // 单个文件读不到就跳过，不影响总量估算
        }
      }
    }
  };
  await walk(p);
  return total || fallback;
}

function kindOf(target: { path: string; kind?: MobileKind }): MobileKind {
  if (target.kind && target.kind !== "unknown") return target.kind;
  const lower = target.path.toLowerCase();
  if (lower.endsWith(".wxapkg")) return "wxapkg";
  if (lower.endsWith(".apk")) return "apk";
  if (lower.endsWith(".ipa")) return "ipa";
  return "unknown";
}

export async function analyzeTarget(input: { path: string; kind?: MobileKind; name?: string }): Promise<MobileAnalysis> {
  const targetPath = path.resolve(String(input.path ?? "").trim());
  if (!targetPath) throw new Error("先选一个目标");
  if (!(await exists(targetPath))) throw new Error(`目标不存在：${targetPath}`);
  const dirStat = await isDir(targetPath);
  let kind = kindOf({ path: targetPath, kind: input.kind });
  if (dirStat) {
    const markers = await miniMarkers(targetPath);
    if (!markers) throw new Error("这个目录不像小程序源码工程（缺 app.json）。选工程根目录，或选 .wxapkg / .apk / .ipa。");
    kind = markers.kind;
  }

  const name = input.name ?? path.basename(targetPath);
  const outDir = path.join(mobileOutRoot(), `${safeName(name)}-${stamp()}-${sha1(targetPath).slice(0, 6)}`);
  await fsp.mkdir(outDir, { recursive: true });
  const log: string[] = [`目标：${targetPath}`, `类型：${kind}`];

  let result: Omit<MobileAnalysis, "target" | "outDir" | "briefPath">;
  if (kind === "wxapkg") {
    const unpackDir = path.join(outDir, "unpacked");
    const count = await unpackWxapkg(targetPath, unpackDir, log);
    const mini = await analyzeMiniSource(unpackDir, log);
    result = {
      files: count,
      extracted: true,
      appId: mini.appId,
      pages: mini.pages,
      endpoints: mini.endpoints,
      secrets: mini.secrets,
      permissions: [],
      components: [],
      libraries: [],
      notes: [
        ...mini.notes,
        "wxapkg 只有主包时，分包要单独导入 app 对应的分包 wxapkg 才能看全。",
      ],
      mini: mini.profile,
      log: [...log, ...mini.log],
    };
  } else if (kind === "wechat" || kind === "uniapp" || kind === "taro") {
    const mini = await analyzeMiniSource(targetPath, log);
    result = {
      files: mini.files,
      extracted: false,
      appId: mini.appId,
      pages: mini.pages,
      endpoints: mini.endpoints,
      secrets: mini.secrets,
      permissions: [],
      components: [],
      libraries: [],
      notes: [...mini.notes, "这是源码工程，不用反编译；直接按接口清单打。"],
      mini: mini.profile,
      log: [...log, ...mini.log],
    };
  } else if (kind === "apk") {
    result = await analyzeApk(targetPath, outDir, log);
  } else if (kind === "ipa") {
    result = await analyzeIpa(targetPath, outDir, log);
  } else {
    throw new Error("认不出类型：只支持小程序源码工程、*.wxapkg、*.apk、*.ipa");
  }

  const analysis: MobileAnalysis = {
    target: {
      id: sha1(`${kind}:${targetPath}`),
      name,
      kind,
      path: targetPath,
      size: await targetBytes(targetPath, dirStat ? result.files : 0),
      files: result.files,
      appId: result.appId,
      note: dirStat ? "小程序源码工程" : "移动端安装包",
    },
    outDir,
    briefPath: path.join(outDir, "静态分析简报.md"),
    ...result,
  };
  await fsp.writeFile(analysis.briefPath, renderBrief(analysis), "utf8");
  return analysis;
}

const KIND_LABEL: Record<MobileKind, string> = {
  wechat: "微信小程序源码",
  uniapp: "uni-app 小程序源码",
  taro: "Taro 小程序源码",
  wxapkg: "微信小程序包（wxapkg）",
  apk: "Android APK",
  ipa: "iOS IPA",
  unknown: "未知",
};

function renderBrief(a: MobileAnalysis): string {
  const lines: string[] = [];
  lines.push(`# 静态分析简报 · ${a.target.name}`);
  lines.push("");
  lines.push(`- 类型：${KIND_LABEL[a.target.kind]}`);
  lines.push(`- 来源：${a.target.path}`);
  lines.push(`- 解出目录：${a.outDir}`);
  lines.push(`- 文件数：${a.files}`);
  if (a.appId) lines.push(`- AppID / BundleID：${a.appId}`);
  if (a.packageName && a.packageName !== a.appId) lines.push(`- 包名：${a.packageName}`);
  if (a.pages.length) lines.push(`- 页面数：${a.pages.length}`);
  lines.push("");
  if (a.pages.length) {
    lines.push("## 页面 / 路由");
    for (const p of a.pages.slice(0, 200)) lines.push(`- ${p}`);
    lines.push("");
  }
  lines.push("## 接口候选");
  if (a.endpoints.length) for (const e of a.endpoints) lines.push(`- ${e}`);
  else lines.push("- 没抽到，源码可能被压缩 / 加密，或接口全在云函数里");
  lines.push("");
  lines.push("## 密钥 / 凭据候选");
  if (a.secrets.length) for (const s of a.secrets) lines.push(`- [${s.kind}] ${s.value}  ← ${s.source}`);
  else lines.push("- 没抽到明文密钥");
  lines.push("");
  if (a.permissions.length) {
    lines.push("## 权限（敏感项优先）");
    for (const p of a.permissions) lines.push(`- ${p}${IMPORTANT_PERMISSIONS.test(p) ? "  ← 敏感" : ""}`);
    lines.push("");
  }
  if (a.components.length) {
    lines.push("## 组件（导出优先，LAUNCHER 打 ^）");
    for (const c of a.components) {
      lines.push(
        `- ${c.exported ? "*" : " "}${c.launcher ? "^" : " "}${c.type} ${c.name}${c.permission ? ` [${c.permission}]` : ""}${
          c.deepLinks?.length ? `  ← ${c.deepLinks.join(" ")}` : ""
        }`,
      );
    }
    lines.push("");
  }
  if (a.mini) {
    const m = a.mini;
    lines.push("## 小程序结构");
    lines.push(`- 来源：${m.source === "wechat" ? "微信原生小程序" : m.source === "uniapp" ? "uni-app / Taro 编译工程" : "未识别"}`);
    if (m.appId) lines.push(`- AppID：${m.appId}`);
    lines.push(`- 页面：${m.pages.length} 个`);
    if (m.subPackages.length) lines.push(`- 分包：${m.subPackages.map((s) => `${s.root}(${s.count} 页)`).join("、")}`);
    if (m.tabBar.length) lines.push(`- tabBar：${m.tabBar.join("、")}`);
    if (m.plugins.length) lines.push(`- 插件：${m.plugins.join("、")}`);
    if (m.privateInfos.length) lines.push(`- 隐私接口：${m.privateInfos.join("、")}`);
    if (m.cloudEnv.length) lines.push(`- 云开发环境：${m.cloudEnv.join("、")}`);
    lines.push(`- 云开发：${m.cloudDev ? "有" : "无"}；上传接口：${m.upload ? "有" : "无"}`);
    if (m.packageSize) lines.push(`- 包体积：${m.packageSize} 字节（${(m.packageSize / 1024 / 1024).toFixed(2)} MB）`);
    if (m.subPackages.some((s) => s.size)) {
      lines.push(`- 分包体积：${m.subPackages.map((s) => `${s.root} ${((s.size ?? 0) / 1024).toFixed(0)}KB${s.independent ? "（独立分包）" : ""}`).join("、")}`);
    }
    if (m.scopes?.length) lines.push(`- 授权 scope：${m.scopes.map((s) => s.scope).join("、")}`);
    if (m.sdks?.length) lines.push(`- 运行时 / SDK：${m.sdks.join("、")}`);
    if (m.debugResidue?.length) for (const r of m.debugResidue) lines.push(`- 调试残留：${r}`);
    if (m.missingPages?.length) lines.push(`- 缺文件页面：${m.missingPages.map((p) => p.page).slice(0, 12).join("、")}`);
    if (m.orphanPages?.length) lines.push(`- 没被引用的页面：${m.orphanPages.slice(0, 12).join("、")}`);
    if (m.insecure?.length) lines.push(`- 明文 / 内网地址：${m.insecure.slice(0, 8).join("、")}`);
    lines.push("");
    if (m.heaviest?.length) {
      lines.push("## 体积 Top");
      for (const h of m.heaviest) lines.push(`- ${h.path}  ${(h.size / 1024).toFixed(0)}KB`);
      lines.push("");
    }
  }
  if (a.app) {
    const p = a.app;
    lines.push("## APP 结构");
    if (p.packageName) lines.push(`- 包名 / BundleID：${p.packageName}`);
    if (p.versionName) lines.push(`- 版本：${p.versionName}${p.versionCode ? ` (${p.versionCode})` : ""}`);
    if (p.minSdk || p.targetSdk) lines.push(`- SDK：min ${p.minSdk ?? "-"} / target ${p.targetSdk ?? "-"}`);
    if (p.iosMinOs) lines.push(`- 最低系统：iOS ${p.iosMinOs}`);
    if (p.abis.length) lines.push(`- ABI / Framework：${p.abis.join("、")}`);
    if (p.signature) lines.push(`- 签名：v1 ${p.signature.v1 ? "有" : "无"} / v2 ${p.signature.v2 ? "有" : "无"} / v3 ${p.signature.v3 ? "有" : "无"}`);
    else lines.push(`- 签名：v1 ${p.signedV1 ? "有" : "无"} / v2 ${p.signedManifest ? "有" : "无"}`);
    if (p.launcher) lines.push(`- 启动入口：${p.launcher}`);
    if (p.debugFlags) {
      const f = p.debugFlags;
      lines.push(
        `- 安全开关：debuggable ${f.debuggable ? "开" : "关"} / allowBackup ${f.allowBackup ? "开" : "关"} / 明文流量 ${f.cleartext ? "允许" : "禁止"} / testOnly ${f.testOnly ? "是" : "否"}`,
      );
      if (f.networkSecurityConfig) lines.push(`- 网络安全配置：${f.networkSecurityConfig}`);
    }
    if (p.sdks?.length) lines.push(`- SDK / 框架：${p.sdks.join("、")}`);
    if (p.pinning?.length) lines.push(`- 抓包对抗：${p.pinning.join("、")}`);
    if (p.runtimeHints?.length) lines.push(`- 运行期线索：${p.runtimeHints.join("、")}`);
    if (p.risks?.length) {
      lines.push("");
      lines.push("## 风险基线");
      for (const r of p.risks) lines.push(`- [${r.level}] ${r.text}`);
    }
    if (p.guards.length) lines.push(`- 加固特征：${p.guards.join("、")}`);
    const c = p.counts;
    if (c.activity || c.service || c.receiver || c.provider) {
      lines.push(`- 组件：activity ${c.activity} / service ${c.service} / receiver ${c.receiver} / provider ${c.provider}`);
    }
    if (p.providers.length) lines.push(`- Provider authority：${p.providers.join("、")}`);
    if (p.deepLinks.length) lines.push(`- 深链：${p.deepLinks.join("、")}`);
    lines.push("");
  }
  if (a.libraries.length) {
    lines.push("## Native 库 / Framework");
    for (const lib of a.libraries) lines.push(`- ${lib}`);
    lines.push("");
  }
  if (a.notes.length) {
    lines.push("## 备注");
    for (const n of a.notes) lines.push(`- ${n}`);
    lines.push("");
  }
  if (a.log.length) {
    lines.push("## 处理日志");
    for (const l of a.log) lines.push(`- ${l}`);
    lines.push("");
  }
  return lines.join("\r\n");
}

/* ---------------- 动态环境探测 ---------------- */

/** 绝对路径的 cmd 必须是真实文件：把目录当程序 CreateProcess 只会回 EINVAL，看不出是哪条 */
function unrunnable(cmd: string): string | undefined {
  if (!path.isAbsolute(cmd)) return undefined;
  if (!fs.existsSync(cmd)) return `找不到可执行文件：${cmd}`;
  try {
    if (fs.statSync(cmd).isFile()) return undefined;
  } catch {
    return `路径不可执行：${cmd}`;
  }
  return `这是个目录，不能当程序启动：${cmd}`;
}

function run(cmd: string, args: string[], timeout = 8_000): Promise<{ ok: boolean; out: string }> {
  const blocked = unrunnable(cmd);
  if (blocked) return Promise.resolve({ ok: false, out: blocked });
  return execTool(cmd, args, timeout);
}

async function firstLine(cmd: string, args: string[]): Promise<{ ok: boolean; out: string }> {
  const res = await run(cmd, args);
  return { ok: res.ok, out: res.out.split(/\r?\n/).filter(Boolean)[0] ?? "" };
}

async function findAdb(): Promise<string | undefined> {
  ensureToolPath();
  const own = await findToolPath("adb");
  if (own) return own;
  const candidates = [
    process.env.ANDROID_HOME ? path.join(process.env.ANDROID_HOME, "platform-tools", "adb.exe") : "",
    process.env.ANDROID_SDK_ROOT ? path.join(process.env.ANDROID_SDK_ROOT, "platform-tools", "adb.exe") : "",
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "Android", "Sdk", "platform-tools", "adb.exe") : "",
    process.env.USERPROFILE ? path.join(process.env.USERPROFILE, "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe") : "",
  ].filter(Boolean);
  for (const candidate of candidates) if (await exists(candidate)) return candidate;
  const which = await run("where", ["adb"], 4_000);
  if (which.ok) {
    const line = which.out
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !s.includes("\uFFFD"))
      .find(Boolean);
    if (line) return line;
  }
  return undefined;
}

export async function mobileEnv(): Promise<MobileEnvInfo> {
  const tools: MobileEnvTool[] = [];
  const devices: MobileDevice[] = [];
  ensureToolPath();

  const adb = await findAdb();
  if (adb) {
    const ver = await firstLine(adb, ["version"]);
    tools.push({ name: "adb", ok: true, version: ver.out.replace(/^Android Debug Bridge version\s*/i, ""), path: adb, hint: "设备连接、安装、拉起组件" });
    const list = await run(adb, ["devices", "-l"], 8_000);
    if (list.ok) {
      for (const line of list.out.split(/\r?\n/).slice(1)) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const [serial, state, ...rest] = trimmed.split(/\s+/);
        if (!serial || !state) continue;
        const model = rest.find((r) => r.startsWith("model:"))?.slice(6);
        devices.push({ serial, state, model });
      }
    }
  } else {
    tools.push({ name: "adb", ok: false, hint: "装 Android Platform Tools 并加进 PATH，或设 ANDROID_HOME" });
  }

  // 工具是否可用只认一份检测（和设置页同一个 toolReport），避免两处判定打架：
  // objection 的版本参数是 `version` 不是 `--version`；jadx / apktool 是 .bat
  const report = await toolReport();
  const envHint: Record<string, string> = {
    adb: "设备连接、安装、拉起组件",
    jadx: "dex → Java 反编译",
    apktool: "资源与清单完整反编译",
    frida: "动态 hook：脱壳、绕 SSL Pinning、定位加密参数",
    objection: "免 root 跑常见动态套路",
    java: "jadx / apktool 依赖 JRE",
    python: "frida / 脚本化工具常用运行时",
  };
  for (const item of report.items) {
    if (item.name === "adb") continue; // adb 上面已按设备扫描那套写入
    tools.push({
      name: item.name,
      ok: item.ok,
      version: item.version || undefined,
      path: item.path,
      launchError: item.launchError,
      hint: item.ok
        ? envHint[item.name] ?? item.purpose
        : item.launchError
          ? item.launchError
          : item.path
            ? `找到了 ${item.path} 但启动失败，去工具页重装`
            : envHint[item.name] ?? item.purpose,
    });
  }

  return { tools, devices, checkedAt: Date.now() };
}

/* ---------------- 动态动作：设备上真执行 ---------------- */

const ACTION_TITLE: Record<MobileDynamicAction, string> = {
  auto: "自动检测暴露面",
  devices: "列举设备",
  install: "安装安装包",
  launch: "启动应用",
  component: "拉起组件",
  broadcast: "发送广播",
  provider: "查询 Provider",
  "proxy-on": "开启设备代理",
  "proxy-off": "关闭设备代理",
  storage: "读应用私有目录",
  logcat: "抓日志",
  package: "读系统里的包详情",
  ports: "看设备监听端口",
  backup: "备份应用数据",
  frida: "生成 Frida 脚本",
  shell: "执行 shell 命令",
};

const FRIDA_PRESETS: Record<FridaPreset, { title: string; script: string }> = {
  "ssl-pinning": {
    title: "绕过 SSL Pinning",
    script: `// 天鉴 · 探微 | SSL Pinning 绕过（OkHttp / TrustManager / HostnameVerifier）
Java.perform(function () {
  try {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
      console.log("[pinning] okhttp3 check bypassed: " + arguments[0]);
    };
  } catch (e) { console.log("[pinning] no okhttp3.CertificatePinner"); }
  try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.registerClass({
      name: "com.tanwei.TrustAll",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
      .implementation = function (km, tm, sr) { this.init(km, [TrustManager.$new()], sr); };
    console.log("[pinning] TrustManager hooked");
  } catch (e) { console.log("[pinning] TrustManager hook failed: " + e); }
  try {
    var Hv = Java.use("javax.net.ssl.HostnameVerifier");
    console.log("[pinning] found HostnameVerifier: " + Hv);
  } catch (e) {}
});
`,
  },
  crypto: {
    title: "抓加解密入参出参",
    script: `// 天鉴 · 探微 | 加解密 / 摘要 / 编码 观测
function hex(bytes) {
  var out = [];
  for (var i = 0; i < bytes.length; i++) out.push(("0" + (bytes[i] & 0xff).toString(16)).slice(-2));
  return out.join("");
}
Java.perform(function () {
  try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
      var res = this.doFinal(input);
      console.log("[cipher:" + this.getAlgorithm() + "] in=" + hex(input) + " out=" + hex(res));
      return res;
    };
  } catch (e) { console.log("[crypto] Cipher hook failed: " + e); }
  try {
    var MD = Java.use("java.security.MessageDigest");
    MD.digest.overload("[B").implementation = function (input) {
      var res = this.digest(input);
      console.log("[digest:" + this.getAlgorithm() + "] in=" + hex(input) + " out=" + hex(res));
      return res;
    };
  } catch (e) { console.log("[crypto] MessageDigest hook failed: " + e); }
  try {
    var B64 = Java.use("android.util.Base64");
    B64.encodeToString.overload("[B", "int").implementation = function (data, flags) {
      var res = this.encodeToString(data, flags);
      console.log("[base64] in=" + hex(data) + " out=" + res);
      return res;
    };
  } catch (e) {}
});
`,
  },
  "root-check": {
    title: "root / 模拟器 / 调试检测观测",
    script: `// 天鉴 · 探微 | root / 模拟器 / 调试检测只观测，不主动绕过业务风控
Java.perform(function () {
  var suPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su"];
  try {
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (suPaths.indexOf(p) >= 0) console.log("[root-check] File.exists(" + p + ")");
      return this.exists();
    };
    File.canExecute.implementation = function () {
      var p = this.getAbsolutePath();
      if (suPaths.indexOf(p) >= 0) console.log("[root-check] File.canExecute(" + p + ")");
      return this.canExecute();
    };
  } catch (e) { console.log("[root-check] File hook failed: " + e); }
  try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
      console.log("[root-check] Runtime.exec(" + cmd + ")");
      return this.exec(cmd);
    };
  } catch (e) {}
  try {
    var Build = Java.use("android.os.Build");
    console.log("[root-check] Build.TAGS=" + Build.TAGS.value + " FINGERPRINT=" + Build.FINGERPRINT.value);
  } catch (e) {}
});
`,
  },
  webview: {
    title: "WebView / JS 桥观测",
    script: `// 天鉴 · 探微 | WebView 加载与 JS 桥观测
Java.perform(function () {
  try {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
      console.log("[webview] loadUrl " + url);
      return this.loadUrl(url);
    };
    WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String").implementation = function (obj, name) {
      console.log("[webview] addJavascriptInterface name=" + name + " obj=" + obj);
      return this.addJavascriptInterface(obj, name);
    };
  } catch (e) { console.log("[webview] WebView hook failed: " + e); }
  try {
    var Client = Java.use("android.webkit.WebViewClient");
    Client.shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String").implementation = function (view, url) {
      console.log("[webview] shouldOverrideUrlLoading " + url);
      return this.shouldOverrideUrlLoading(view, url);
    };
  } catch (e) {}
  try {
    var Settings = Java.use("android.webkit.WebSettings");
    Settings.setJavaScriptEnabled.implementation = function (on) {
      console.log("[webview] setJavaScriptEnabled " + on);
      return this.setJavaScriptEnabled(on);
    };
  } catch (e) {}
});
`,
  },
};

function quoteArg(value: string): string {
  return /\s/.test(value) ? `"${value}"` : value;
}

/** 自动检测回显只留前几行像样的证据，整段输出进 out 字段 */
function compactLines(out: string, max = 4): string[] {
  return out
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !/^[-=]{3,}$/.test(l))
    .slice(0, max);
}

const SECRET_HINT =
  /(token|passwd|password|secret|api[_-]?key|authorization|bearer|cookie|sessionid|手机号|身份证|access[_-]?key)/i;

const AUTO_VERDICT_LABEL: Record<MobileAutoCheck["verdict"], string> = {
  hit: "拿到东西",
  open: "能打通",
  deny: "被拦住",
  skip: "没测",
};

async function firstDevice(adb: string): Promise<string | undefined> {
  const list = await run(adb, ["devices"], 8_000);
  if (!list.ok) return undefined;
  for (const line of list.out.split(/\r?\n/).slice(1)) {
    const [serial, state] = line.trim().split(/\s+/);
    if (serial && state === "device") return serial;
  }
  return undefined;
}

export async function mobileDynamic(input: MobileDynamicInput): Promise<MobileActionResult> {
  const action = input.action;
  const at = Date.now();
  const title = ACTION_TITLE[action] ?? action;
  const fail = (hint: string, cmd = ""): MobileActionResult => ({ ok: false, action, title, cmd, out: "", hint, at });

  if (action === "frida") {
    const preset = input.preset ?? "ssl-pinning";
    const tpl = FRIDA_PRESETS[preset] ?? FRIDA_PRESETS["ssl-pinning"];
    const dir = path.join(mobileOutRoot(), "dynamic", `${stamp()}-${preset}`);
    await fsp.mkdir(dir, { recursive: true });
    const scriptPath = path.join(dir, "hook.js");
    await fsp.writeFile(scriptPath, tpl.script, "utf8");
    const pkg = (input.packageName ?? "").trim();
    const cmd = pkg
      ? `frida -U -f ${quoteArg(pkg)} -l ${quoteArg(scriptPath)} --no-pause`
      : `frida -U -l ${quoteArg(scriptPath)}`;
    return {
      ok: true,
      action,
      title: `${title} · ${tpl.title}`,
      cmd,
      out: `脚本已写入：${scriptPath}`,
      scriptPath,
      hint: pkg
        ? "脚本已就绪。把上面这条命令贴到本机终端跑（frida CLI 是交互式会话，这里不代替它常驻）。"
        : "脚本已就绪。填上包名可自动带 -f 启动；不填就用 -U 挂在当前前台应用上。",
      at,
    };
  }

  if (action === "devices") {
    const adb = await findAdb();
    if (!adb) return fail("没找到 adb：装 Android Platform Tools 并加进 PATH，或设 ANDROID_HOME / ANDROID_SDK_ROOT");
    const cmd = `${quoteArg(adb)} devices -l`;
    const res = await run(adb, ["devices", "-l"], 10_000);
    return { ok: res.ok, action, title, cmd, out: res.out, hint: res.ok ? undefined : "adb 调用失败，检查驱动与 USB 调试授权", at };
  }

  const adb = await findAdb();
  if (!adb) return fail("没找到 adb：装 Android Platform Tools 并加进 PATH，或设 ANDROID_HOME / ANDROID_SDK_ROOT");

  const wanted = (input.serial ?? "").trim();
  const serial = wanted || (await firstDevice(adb));
  if (!serial) return fail("没有已连接设备（adb devices 为空）。开 USB 调试或起模拟器后重试。", `${quoteArg(adb)} devices`);

  const pkg = (input.packageName ?? "").trim();
  const base = `${quoteArg(adb)} -s ${serial}`;
  const shell = (args: string[], timeout = 15_000) => run(adb, ["-s", serial, ...args], timeout);
  const cmdOf = (args: string[]) => `${base} ${args.map(quoteArg).join(" ")}`;

  switch (action) {
    case "auto": {
      if (!pkg) return fail("自动检测要包名：先在静态页拆一次包，或在上面的包名格里手填 com.example.app");

      const checks: MobileAutoCheck[] = [];
      const collect = (c: MobileAutoCheck) => {
        if (checks.length < 48) checks.push(c);
      };

      const listArgs = ["shell", "pm", "list", "packages", pkg];
      const listRes = await shell(listArgs, 15_000);
      const installed = listRes.out.split(/\r?\n/).some((l) => l.trim() === `package:${pkg}`);
      if (!installed) {
        return {
          ok: false,
          action,
          title,
          cmd: cmdOf(listArgs),
          out: listRes.out || `设备上没有找到 ${pkg}`,
          hint: `设备上没装 ${pkg}：先点「安装安装包」，或把包名改成设备上真实安装的那个再检测`,
          at,
        };
      }

      const components = (input.components ?? []).map((c) => c.trim()).filter(Boolean).slice(0, 16);
      for (const comp of components) {
        const full = comp.startsWith(".") ? `${pkg}${comp}` : comp;
        const args = ["shell", "am", "start", "-W", "-n", full];
        const res = await shell(args, 25_000);
        const rows = compactLines(res.out, 4);
        const denied = /Permission Denial|SecurityException|not exported|permission denied/i.test(res.out);
        const missing = /Unable to find explicit|does not exist|not found/i.test(res.out);
        const started = /Status:\s*ok|Starting:|Warning: Activity not started/i.test(res.out);
        if (denied) {
          collect({
            target: full,
            kind: "activity",
            verdict: "deny",
            detail: "系统拒绝：组件没导出，或要声明权限才准拉起。这条到此为止，换下一个。",
            cmd: cmdOf(args),
            rows,
          });
        } else if (started) {
          collect({
            target: full,
            kind: "activity",
            verdict: "open",
            detail: "导出了、不登录也能拉起：攻击面成立。进去后有没有别人的数据、能不能直接进后台页，要看回显与截屏。",
            cmd: cmdOf(args),
            rows,
          });
        } else if (missing) {
          collect({
            target: full,
            kind: "activity",
            verdict: "skip",
            detail: "设备上找不到这个组件：包版本和静态拆的不是同一份，重装同一份包再测。",
            cmd: cmdOf(args),
            rows,
          });
        } else {
          collect({
            target: full,
            kind: "activity",
            verdict: "deny",
            detail: "没拉起来：看回显里的 Error 与缺哪个参数（extras / data URI）。",
            cmd: cmdOf(args),
            rows,
          });
        }
      }

      const links = (input.deepLinks ?? []).map((l) => l.trim()).filter(Boolean).slice(0, 8);
      for (const link of links) {
        const args = ["shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", link];
        const res = await shell(args, 25_000);
        const rows = compactLines(res.out, 4);
        const denied = /Permission Denial|SecurityException|permission denied/i.test(res.out);
        const handled = /Status:\s*ok|Starting:|Warning: Activity not started/i.test(res.out);
        collect({
          target: link,
          kind: "deeplink",
          verdict: denied ? "deny" : handled ? "open" : "deny",
          detail: denied
            ? "深链被系统或目标应用拦下。"
            : handled
              ? "深链被应用接住了：用它试任意页面落地与越权参数。"
              : "没接住：应用没注册这个 scheme / host，或要在登录态里才处理。",
          cmd: cmdOf(args),
          rows,
        });
      }

      const authorities = (input.providers ?? []).map((p) => p.trim()).filter(Boolean).slice(0, 10);
      for (const authority of authorities) {
        const target = authority.startsWith("content://") ? authority : `content://${authority}`;
        const args = ["shell", "content", "query", "--uri", target];
        const res = await shell(args, 25_000);
        const rows = compactLines(res.out, 4);
        const denied = /Permission Denial|IllegalArgumentException|Unable to find provider|Error while accessing/i.test(res.out);
        const dataRows = res.out.split(/\r?\n/).filter((l) => /^\s*Row[:.]/i.test(l));
        if (denied) {
          collect({
            target,
            kind: "provider",
            verdict: "deny",
            detail: "Provider 拦住了：没导出或要权限。这条记结论，换下一个 authority。",
            cmd: cmdOf(args),
            rows,
          });
        } else if (dataRows.length) {
          collect({
            target,
            kind: "provider",
            verdict: "hit",
            detail: `查到 ${dataRows.length} 行数据：别的应用能直接读这张表，先把字段抄下来再换路径试越权。`,
            cmd: cmdOf(args),
            rows,
          });
        } else {
          collect({
            target,
            kind: "provider",
            verdict: "open",
            detail: "能访问但根路径没数据：换成 content://authority/表名 或加 where 参数再查。",
            cmd: cmdOf(args),
            rows,
          });
        }
      }

      const storageArgs = ["shell", "run-as", pkg, "ls", `/data/data/${pkg}`];
      const storageRes = await shell(storageArgs, 25_000);
      const notDebuggable = /not debuggable|unknown package|Package .* is not debuggable/i.test(storageRes.out);
      collect({
        target: `/data/data/${pkg}`,
        kind: "storage",
        verdict: notDebuggable ? "deny" : storageRes.out.trim() ? "hit" : "skip",
        detail: notDebuggable
          ? "不是 debuggable 包：run-as 进不去。改走 frida 读文件，或看 sdcard 上的缓存。"
          : storageRes.out.trim()
            ? "run-as 读到了私有目录：shared_prefs / db 里的 token 与会话可以直接抄。"
            : "run-as 能用但目录是空的，先启动应用产生数据再读。",
        cmd: cmdOf(storageArgs),
        rows: compactLines(storageRes.out, 6),
      });

      const logArgs = ["shell", "logcat", "-d", "-t", "300"];
      const logRes = await shell(logArgs, 30_000);
      const secretLines = logRes.out
        .split(/\r?\n/)
        .filter((l) => SECRET_HINT.test(l))
        .slice(0, 6);
      collect({
        target: "logcat · 最近 300 行",
        kind: "logcat",
        verdict: secretLines.length ? "hit" : "skip",
        detail: secretLines.length
          ? `日志里出现 ${secretLines.length} 行凭据类关键字：先确认是不是真 token，再拿去打接口。`
          : "最近 300 行没匹配到 token / 密码 / 手机号一类关键字。多刷几屏再抓一次。",
        cmd: cmdOf(logArgs),
        rows: secretLines,
      });

      const summary = checks
        .map((c) => `[${AUTO_VERDICT_LABEL[c.verdict]}] ${c.target}\n    ${c.detail}`)
        .join("\n");
      const hitCount = checks.filter((c) => c.verdict === "hit").length;
      const openCount = checks.filter((c) => c.verdict === "open").length;
      const denyCount = checks.filter((c) => c.verdict === "deny").length;
      const skipCount = checks.filter((c) => c.verdict === "skip").length;

      return {
        ok: checks.length > 0,
        action,
        title: `${title} · ${checks.length} 项`,
        cmd: cmdOf(["shell", `pm list packages ${pkg}`]),
        out: summary || "没有可测的对象：静态页里没有导出组件 / Provider / 深链，先补包名手测。",
        checks,
        hint: `拿到东西 ${hitCount} · 能打通 ${openCount} · 被拦住 ${denyCount} · 没测 ${skipCount}。能拉起、能查询只说明这扇门对外开着，是攻击面；真正写成漏洞要等它把别人的数据、后台页面或可执行的操作交出来。对着「拿到东西」那几条继续换路径 / 换 id。`,
        at,
      };
    }
    case "install": {
      const picked = await resolveApkFiles(input.apkPath ?? "", input.sessionId);
      const files = picked.files ?? [];
      if (!files.length) return fail(picked.error ?? "先选一个 .apk 文件", cmdOf(["install", "-r", "<本地 apk>"]));
      const args = files.length > 1 ? ["install-multiple", "-r", ...files] : ["install", "-r", files[0]];
      const res = await shell(args, 180_000);
      const ok = res.ok && /Success/i.test(res.out);
      const hint = /signatures do not match|INSTALL_FAILED_UPDATE_INCOMPATIBLE/i.test(res.out)
        ? "签名冲突：覆盖安装要加 -d（先确认这个包该不该换掉现有版本）"
        : /INSTALL_FAILED_VERSION_DOWNGRADE|downgrade/i.test(res.out)
          ? "版本降级：要 -r -d 才覆盖得过去"
          : files.length > 1
            ? "一次装多个包只在拆分包（base + split）时才对；装不上就逐个装，或把单个 .apk 放一个目录再装"
            : "装不上先看输出：签名冲突加 -d，版本降级加 -r -d";
      return { ok, action, title, cmd: cmdOf(args), out: res.out, hint: ok ? undefined : hint, at };
    }
    case "launch": {
      if (!pkg) return fail("填要启动的包名，例如 com.example.app");
      const args = ["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"];
      const res = await shell(args, 30_000);
      return { ok: res.ok && !/No activities found/i.test(res.out), action, title, cmd: cmdOf(args), out: res.out, hint: res.ok ? "已发起启动；看 logcat 确认进程起来" : "No activities found：包名不对或应用没装", at };
    }
    case "component": {
      if (!pkg) return fail("填包名 + 组件类名/全名，例如 com.example.app/.ui.AdminActivity");
      let comp = (input.component ?? "").trim();
      if (!comp) return fail("填要拉起的组件，例如 .ui.AdminActivity 或 com.example.app/.ui.AdminActivity");
      if (comp.startsWith(".")) comp = `${pkg}${comp}`;
      const args = ["shell", "am", "start", "-n", comp];
      const res = await shell(args, 30_000);
      const denied = /Permission Denial|SecurityException|not exported/i.test(res.out);
      return { ok: res.ok && !denied, action, title, cmd: cmdOf(args), out: res.out, hint: denied ? "系统拒绝：该组件没导出或要权限。导出组件才能直接拉起，这也是一条结论。" : undefined, at };
    }
    case "broadcast": {
      const target = (input.component ?? "").trim();
      if (!target) return fail("填广播 action（如 com.example.PUSH）或组件全名");
      const args = target.includes("/") ? ["shell", "am", "broadcast", "-n", target] : ["shell", "am", "broadcast", "-a", target];
      const res = await shell(args, 30_000);
      return { ok: res.ok, action, title, cmd: cmdOf(args), out: res.out, hint: /Broadcast completed/i.test(res.out) ? undefined : "没 Completed：确认 action 名与是否需要 -p 指定包", at };
    }
    case "provider": {
      const uri = (input.uri ?? "").trim();
      if (!uri) return fail("填 content:// URI，例如 content://com.example.provider/users");
      const args = ["shell", "content", "query", "--uri", uri];
      const res = await shell(args, 30_000);
      const denied = /Permission Denial|Error while accessing provider/i.test(res.out);
      return { ok: res.ok && !denied && Boolean(res.out), action, title, cmd: cmdOf(args), out: res.out, hint: denied ? "Provider 拦住了：没导出或要权限，记录结论换下一个 authority" : res.out ? undefined : "空结果：URI 路径不对，先 adb shell content query --uri content://<authority> 探根", at };
    }
    case "proxy-on": {
      const proxy = (input.proxy ?? "127.0.0.1:7890").trim();
      const [host, port] = proxy.split(":");
      const steps: string[] = [];
      if (host === "127.0.0.1" || host === "localhost") {
        const rev = ["reverse", `tcp:${port}`, `tcp:${port}`];
        const revRes = await shell(rev, 20_000);
        steps.push(`adb reverse ${port}: ${revRes.ok ? "ok" : revRes.out.slice(0, 120)}`);
      }
      const put = ["shell", "settings", "put", "global", "http_proxy", proxy];
      const res = await shell(put, 20_000);
      steps.push(res.out || "http_proxy 已写入");
      return {
        ok: res.ok,
        action,
        title,
        cmd: cmdOf(put),
        out: steps.join("\n"),
        hint: "代理已指向本机 Clash。抓包前确认 Clash 混合端口开着，且允许局域网连接（模拟器要用 10.0.2.2）。",
        at,
      };
    }
    case "proxy-off": {
      const put = ["shell", "settings", "put", "global", "http_proxy", ":0"];
      const res = await shell(put, 20_000);
      const rev = ["reverse", "--remove-all"];
      const revRes = await shell(rev, 20_000);
      return { ok: res.ok, action, title, cmd: cmdOf(put), out: `${res.out}\n${revRes.out}`.trim(), hint: "已清空 http_proxy 并移除 reverse，应用恢复直连。", at };
    }
    case "storage": {
      if (!pkg) return fail("填包名，才能定位 /data/data/<包名>");
      const args = ["shell", "run-as", pkg, "ls", "-R", `/data/data/${pkg}`];
      const res = await shell(args, 30_000);
      const denied = /not debuggable|unknown package|Package .* is not debuggable/i.test(res.out);
      return {
        ok: res.ok && !denied,
        action,
        title,
        cmd: cmdOf(args),
        out: res.out,
        hint: denied ? "不是 debuggable 包：run-as 用不了。改走 frida 读文件，或 adb backup（目标要允许备份）。" : undefined,
        at,
      };
    }
    case "logcat": {
      const args = ["shell", "logcat", "-d", "-t", "400"];
      const res = await shell(args, 25_000);
      return { ok: res.ok, action, title, cmd: cmdOf(args), out: res.out, hint: res.ok ? undefined : "logcat 需要设备授权；先 adb devices 确认 state=device", at };
    }
    case "package": {
      if (!pkg) return fail("填包名，才能读这个包在系统里登记的信息");
      const args = ["shell", "dumpsys", "package", pkg];
      const res = await shell(args, 30_000);
      // dumpsys 全量几千行，只留判断要用的：版本、debuggable、allowBackup、组件与权限
      const keep = /versionName|versionCode|targetSdk|debuggable|allowBackup|flags=|exported|permission:|android\.permission/i;
      const lines = res.out.split(/\r?\n/).filter((l) => keep.test(l)).slice(0, 80);
      const flag = /allowBackup=true/i.test(res.out)
        ? "allowBackup=true：没 root 也能用 adb backup 拿私有数据"
        : /debuggable=true/i.test(res.out)
          ? "debuggable=true：run-as 能直接进私有目录"
          : "";
      return {
        ok: res.ok && lines.length > 0,
        action,
        title,
        cmd: cmdOf(args),
        out: lines.join("\n") || res.out.slice(0, 2000),
        hint: flag || "上面是系统登记的组件与权限：标了 exported 的才是外部能直接进的入口。",
        at,
      };
    }
    case "ports": {
      const args = ["shell", "netstat", "-tuln"];
      const res = await shell(args, 20_000);
      if (!res.out.trim() || /not found|inaccessible|Unknown option/i.test(res.out)) {
        const fallback = ["shell", "cat", "/proc/net/tcp", "/proc/net/tcp6"];
        const fb = await shell(fallback, 20_000);
        if (fb.out.trim()) {
          return {
            ok: true,
            action,
            title,
            cmd: cmdOf(fallback),
            out: fb.out,
            hint: "netstat 用不了，这里读的是 /proc/net/tcp：state 0A 就是 LISTEN，本地地址是「小端十六进制 IP:端口」。",
            at,
          };
        }
      }
      const listening = res.out.split(/\r?\n/).filter((l) => /LISTEN/i.test(l)).length;
      return {
        ok: res.ok,
        action,
        title,
        cmd: cmdOf(args),
        out: res.out,
        hint: listening
          ? `${listening} 条监听：这些端口同网段可达，配合 adb forward 就是本地测试入口。`
          : "没看到监听端口：应用可能只做出站请求，转去看抓包。",
        at,
      };
    }
    case "backup": {
      if (!pkg) return fail("填包名，才能只备份这个应用的数据");
      const safe = pkg.replace(/[^\w.]+/g, "_");
      const file = path.join(app.getPath("temp"), `tanwei-backup-${safe}-${at}.ab`);
      const args = ["backup", "-f", file, pkg];
      const res = await shell(args, 180_000);
      const size = fs.existsSync(file) ? fs.statSync(file).size : 0;
      const ok = size > 1024;
      return {
        ok,
        action,
        title,
        cmd: cmdOf(args),
        out: `${res.out}\n备份文件：${file}\n大小：${size} 字节`.trim(),
        hint: ok
          ? "备份落盘了：用 abe（android-backup-extractor）解成 tar，再翻 shared_prefs 与 db。备份能成说明 allowBackup=true，这是没 root 也能拿私有数据的路。"
          : "设备上要点弹窗「备份我的数据」；Android 12 起系统默认忽略 adb backup，目标得 allowBackup=true 且没禁用备份。",
        at,
      };
    }
    case "shell": {
      const command = (input.command ?? "").trim();
      if (!command) return fail("填要在设备上执行的命令，例如 pm list packages | grep example");
      const args = ["shell", command];
      const res = await shell(args, 40_000);
      return { ok: res.ok, action, title, cmd: cmdOf(args), out: res.out, hint: res.ok ? undefined : "命令非零退出；输出就是原因", at };
    }
    default:
      return fail(`不认识的动态动作：${String(action)}`);
  }
}

/* ---------------- 设备应用：包名 / 版本 / 显示名 ---------------- */

interface LabelCache {
  [key: string]: { label: string; at: number };
}

function labelCachePath(): string {
  return path.join(app.getPath("userData"), "mobile-app-labels.json");
}

function readLabelCache(): LabelCache {
  try {
    return JSON.parse(fs.readFileSync(labelCachePath(), "utf8")) as LabelCache;
  } catch {
    return {};
  }
}

function writeLabelCache(cache: LabelCache): void {
  try {
    fs.writeFileSync(labelCachePath(), JSON.stringify(cache));
  } catch {
    // 缓存写不进去不影响本次结果
  }
}

/** 二进制输出用：exec-out 拉回来的 AndroidManifest / resources.arsc 不能按文本解码 */
function execBuf(cmd: string, args: string[], timeout: number): Promise<{ ok: boolean; buf: Buffer; err: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let err = "";
    let done = false;
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(cmd, args, { windowsHide: true });
    } catch (e) {
      resolve({ ok: false, buf: Buffer.alloc(0), err: (e as Error).message });
      return;
    }
    child.stdout?.on("data", (c: Buffer) => chunks.push(c));
    child.stderr?.on("data", (c: Buffer) => {
      err += c.toString("utf8");
    });
    child.on("error", (e) => {
      if (done) return;
      done = true;
      resolve({ ok: false, buf: Buffer.alloc(0), err: e.message });
    });
    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {}
    }, timeout);
    child.on("close", (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ok: code === 0, buf: Buffer.concat(chunks), err });
    });
  });
}

/**
 * resources.arsc 里按 resId（0xPPTTEEEE）取字符串。
 * 只解析到「type 表 → entry → Res_value」这一层：label 就是一条简单值，
 * 遇到 bag/array 直接放弃，交给上层用包名兜底。
 */
function arscStringFor(buf: Buffer, resId: number, depth = 0): string | undefined {
  if (depth > 3 || buf.length < 12) return undefined;
  if (buf.readUInt16LE(0) !== 0x0002) return undefined;
  const tableHeader = buf.readUInt16LE(2);
  const total = buf.readUInt32LE(4) || buf.length;
  const end = Math.min(buf.length, total);
  const pkgId = (resId >>> 24) & 0xff;
  const typeId = (resId >>> 16) & 0xff;
  const entryIdx = resId & 0xffff;
  let strings: string[] = [];
  let off = tableHeader;
  while (off + 8 <= end) {
    const type = buf.readUInt16LE(off);
    const headerSize = buf.readUInt16LE(off + 2);
    const size = buf.readUInt32LE(off + 4);
    if (size < 8 || off + size > buf.length) break;
    if (type === 0x0001) {
      strings = axmlStringPool(buf, off);
    } else if (type === 0x0200 && buf.readUInt32LE(off + 8) === pkgId) {
      const pkgEnd = off + size;
      let sub = off + headerSize;
      while (sub + 8 <= pkgEnd) {
        const sType = buf.readUInt16LE(sub);
        const sHeader = buf.readUInt16LE(sub + 2);
        const sSize = buf.readUInt32LE(sub + 4);
        if (sSize < 8 || sub + sSize > buf.length) break;
        if (sType === 0x0201 && buf[sub + 8] === typeId) {
          const count = buf.readUInt32LE(sub + 12);
          const entriesStart = buf.readUInt32LE(sub + 16);
          const flags = buf[sub + 9];
          const sparse = (flags & 0x01) !== 0;
          const off16 = (flags & 0x02) !== 0;
          let entryOff = -1;
          if (sparse) {
            for (let i = 0; i < count; i += 1) {
              const at = sub + sHeader + i * 4;
              if (at + 4 > sub + sSize) break;
              if (buf.readUInt16LE(at) === entryIdx) {
                entryOff = buf.readUInt16LE(at + 2) * 4;
                break;
              }
            }
          } else if (entryIdx < count) {
            if (off16) {
              const at = sub + sHeader + entryIdx * 2;
              if (at + 2 <= sub + sSize) entryOff = buf.readUInt16LE(at) * 4;
            } else {
              const at = sub + sHeader + entryIdx * 4;
              if (at + 4 <= sub + sSize) {
                const raw = buf.readUInt32LE(at);
                entryOff = raw === 0xffffffff ? -1 : raw;
              }
            }
          }
          if (entryOff < 0) return undefined;
          const pos = sub + entriesStart + entryOff;
          if (pos + 8 > sub + sSize) return undefined;
          const entrySize = buf.readUInt16LE(pos);
          const entryFlags = buf.readUInt16LE(pos + 2);
          if (entryFlags & 0x0001) return undefined; // 复杂项（bag / array）
          const valuePos = pos + entrySize;
          if (valuePos + 8 > sub + sSize) return undefined;
          const dataType = buf[valuePos + 3];
          const data = buf.readUInt32LE(valuePos + 4);
          if (dataType === 0x03) return strings[data] || undefined;
          if (dataType === 0x01) return arscStringFor(buf, data, depth + 1);
          return undefined;
        }
        sub += sSize;
      }
    }
    off += size;
  }
  return undefined;
}

/** 从设备上的 APK 里抠出应用显示名：只取清单与资源表两个条目，不拉整个包 */
async function labelFromDeviceApk(adb: string, serial: string, apkPath: string): Promise<string | undefined> {
  const pick = async (entry: string, limit: number): Promise<Buffer | undefined> => {
    for (const argv of [
      ["-s", serial, "exec-out", "unzip", "-p", apkPath, entry],
      ["-s", serial, "exec-out", "toybox", "unzip", "-p", apkPath, entry],
    ]) {
      const res = await execBuf(adb, argv, limit);
      if (res.ok && res.buf.length > 16) return res.buf;
    }
    return undefined;
  };
  const manifest = await pick("AndroidManifest.xml", 60_000);
  if (!manifest) return undefined;
  const parsed = parseAxml(manifest);
  if (parsed.label) return parsed.label;
  if (!parsed.labelRef) return undefined;
  const arsc = await pick("resources.arsc", 120_000);
  if (!arsc) return undefined;
  return arscStringFor(arsc, parsed.labelRef);
}

function parsePmLine(line: string): { apkPath: string; packageName: string; versionCode?: string } | undefined {
  const m = /^package:(.*?)=([A-Za-z0-9_.]+)(?:\s+versionCode:(\d+))?/.exec(line.trim());
  if (!m) return undefined;
  return { apkPath: m[1], packageName: m[2], versionCode: m[3] };
}

/** 列出已连接设备上装的全部应用（含系统应用），第三方排在前面 */
export async function listDeviceApps(serial?: string): Promise<MobileAppList> {
  const at = Date.now();
  const empty: MobileAppList = { ok: false, serial: serial ?? "", apps: [], total: 0, thirdParty: 0, cmd: "", at };
  const adb = await findAdb();
  if (!adb) return { ...empty, hint: "没找到 adb：装 Android Platform Tools 并加进 PATH，或设 ANDROID_HOME" };
  const s = (serial ?? "").trim() || (await firstDevice(adb));
  if (!s) return { ...empty, hint: "没有已连接设备（adb devices 为空）：开 USB 调试或起模拟器后再列" };

  const argsOf = (flag?: string) => ["-s", s, "shell", "pm", "list", "packages", ...(flag ? [flag] : []), "-f", "--show-versioncode"];
  const third = await run(adb, argsOf("-3"), 90_000);
  const system = await run(adb, argsOf("-s"), 90_000);
  if (!third.ok && !system.ok) {
    return {
      ...empty,
      serial: s,
      cmd: `${quoteArg(adb)} ${argsOf("-3").map(quoteArg).join(" ")}`,
      hint: `读不到应用列表：${(third.out || system.out).slice(0, 200) || "adb shell pm 无输出"}`,
    };
  }

  const map = new Map<string, MobileAppEntry>();
  const absorb = (out: string, system: boolean) => {
    for (const line of out.split(/\r?\n/)) {
      const item = parsePmLine(line);
      if (!item) continue;
      const prev = map.get(item.packageName);
      if (prev) {
        prev.system = prev.system && system;
        continue;
      }
      map.set(item.packageName, {
        packageName: item.packageName,
        versionCode: item.versionCode,
        apkPath: item.apkPath,
        system,
        labelState: "pending",
      });
    }
  };
  absorb(third.out, false);
  absorb(system.out, true);

  const cache = readLabelCache();
  const apps = [...map.values()];
  for (const app of apps) {
    const hit = cache[`${app.packageName}@${app.versionCode ?? ""}`] ?? cache[app.packageName];
    if (hit?.label) {
      app.label = hit.label;
      app.labelState = "done";
    }
  }
  apps.sort((a, b) => {
    if (a.system !== b.system) return a.system ? 1 : -1;
    return (a.label ?? a.packageName).localeCompare(b.label ?? b.packageName, "zh-CN");
  });
  return {
    ok: true,
    serial: s,
    apps,
    total: apps.length,
    thirdParty: apps.filter((a) => !a.system).length,
    cmd: `${quoteArg(adb)} ${argsOf("-3").map(quoteArg).join(" ")}`,
    hint: apps.length ? undefined : "设备上没有应用列表：检查 USB 调试授权",
    at,
  };
}

/** 单个应用的显示名：有打包路径就直接解包，没有就先 pm path 问出来 */
export async function appLabel(input: {
  serial?: string;
  packageName: string;
  apkPath?: string;
  versionCode?: string;
}): Promise<{ ok: boolean; label?: string; apkPath?: string; hint?: string }> {
  const pkg = (input.packageName ?? "").trim();
  if (!pkg) return { ok: false, hint: "要包名才能查显示名" };
  const adb = await findAdb();
  if (!adb) return { ok: false, hint: "没找到 adb：装 Android Platform Tools 并加进 PATH" };
  const serial = (input.serial ?? "").trim() || (await firstDevice(adb));
  if (!serial) return { ok: false, hint: "没有已连接设备" };

  let apkPath = (input.apkPath ?? "").trim();
  if (!apkPath) {
    const res = await run(adb, ["-s", serial, "shell", "pm", "path", pkg], 20_000);
    const line = res.out.split(/\r?\n/).find((l) => l.startsWith("package:"));
    apkPath = line ? line.slice(8).trim() : "";
  }
  if (!apkPath) return { ok: false, hint: `设备上没找到 ${pkg} 的安装路径` };

  const label = await labelFromDeviceApk(adb, serial, apkPath);
  if (!label) {
    return { ok: false, apkPath, hint: "读到了安装包，但解不出 label（可能是加固包或资源表用的是不支持的压缩）" };
  }
  const cache = readLabelCache();
  cache[`${pkg}@${input.versionCode ?? ""}`] = { label, at: Date.now() };
  cache[pkg] = { label, at: Date.now() };
  writeLabelCache(cache);
  return { ok: true, label, apkPath };
}

/** 设备应用 → 本机：把手机上的安装包拉到本机再拆，拆完的静态结果和本机包完全一致 */
export async function pullDeviceApk(input: {
  serial?: string;
  packageName: string;
  apkPath?: string;
}): Promise<{ ok: boolean; path?: string; hint?: string }> {
  const pkg = (input.packageName ?? "").trim();
  if (!pkg) return { ok: false, hint: "要包名才能拉包" };
  const adb = await findAdb();
  if (!adb) return { ok: false, hint: "没找到 adb：装 Android Platform Tools 并加进 PATH" };
  const serial = (input.serial ?? "").trim() || (await firstDevice(adb));
  if (!serial) return { ok: false, hint: "没有已连接设备" };

  let remote = (input.apkPath ?? "").trim();
  if (!remote) {
    const res = await run(adb, ["-s", serial, "shell", "pm", "path", pkg], 20_000);
    remote = res.out
      .split(/\r?\n/)
      .filter((l) => l.startsWith("package:"))
      .map((l) => l.slice(8).trim())[0] ?? "";
  }
  if (!remote) return { ok: false, hint: `设备上没找到 ${pkg} 的安装路径` };

  const dir = path.join(mobileOutRoot(), "_pulls");
  await fsp.mkdir(dir, { recursive: true });
  const safe = `${pkg}`.replace(/[^\w.@-]+/g, "_");
  const local = path.join(dir, `${safe}.apk`);
  const pulled = await run(adb, ["-s", serial, "pull", remote, local], 300_000);
  if (!pulled.ok || !(await exists(local))) {
    return { ok: false, hint: `拉包失败：${(pulled.out || "").slice(0, 200) || "adb pull 无输出"}` };
  }
  return { ok: true, path: local };
}

/* ---------------- 交给引擎的打法 ---------------- */

const MINI_PLAYBOOK = [
  "小程序打法：",
  "1. 先看解包目录里的 app.json / project.config.json：页面、分包、tabBar、插件、云开发 env、appid 全列进清单。",
  "2. 逐页看 JS：request / uploadFile / cloud.callFunction 的 host、path、参数名、签名算法（salt / sign / nonce / timestamp）全抄进接口清单。",
  "3. 匿名面优先：把清单里每个接口的 Cookie/Token 去掉重放，看有没有直接出业务数据；出了就换 id（不限字段名）看有没有别人的。",
  "4. 有差分面的参数按栈打注入 / SSRF / XSS / RCE；空列表、报错、耗时差都算差分面。",
  "5. 云开发：拿到 env 就试数据库 / 存储 / 云函数的越权；云函数常缺鉴权，重点看 openid 是自己传还是上下文取。",
  "6. 上传接口跟到底：能不能传可执行、能不能越目录、返回的 fileID 能不能换别人的。",
  "7. 登录 / 换票 / 绑定手机号这类口按认证链打：空密、跳步、重置改号、code 换票换 uid。",
  "8. 硬编码密钥 / 盐是钥匙，不是结论：用它自己算签名，打「只要 sign 不要 Cookie」的口。",
].join("\n");

const APP_PLAYBOOK = [
  "APP 打法：",
  "1. 静态：包名、权限、导出组件、深链（intent-filter / URL Scheme）、ContentProvider、WebView 配置、硬编码密钥、证书校验、加固识别。",
  "2. 导出组件逐个真实拉起（adb shell am start / am broadcast / content query）：越权读写、未授权页面、Provider 目录穿越。",
  "3. 抓包：把流量打到本机代理（127.0.0.1:7890，走 Clash 出口），看明文接口；有 pinning 就 frida hook 掉再抓。",
  "4. 接口面按 Web 那套打：未授权、换 id、有差分面的注入 / SSRF / XSS，参数从抓包里抄全，别只看一个字段。",
  "5. 加密参数：frida hook 加密函数 / OkHttp / 加解密类，拿到入参出参后自己造请求。",
  "6. 存储：/data/data/<pkg>/ 下的 shared_prefs、db、cache 里找 token、手机号、隐私数据；World 可读的 sdcard 目录也看。",
  "7. WebView：JS 桥（addJavascriptInterface）、file:// 访问、universal link 劫持，能打通到本地文件或越权调用就算链。",
  "8. 动态检测项：root / 模拟器 / 调试检测只记录，不为了绕过而绕过；绕过只用来让上面的测试跑通。",
].join("\n");

export function buildMobilePrompt(analysis: MobileAnalysis, mode: MobilePentestMode, env?: MobileEnvInfo): string {
  const isApp = Boolean(analysis.app) || analysis.target.kind === "apk" || analysis.target.kind === "ipa";
  const lines: string[] = [];
  lines.push(isApp ? "【APP 授权渗透】" : "【小程序授权渗透】");
  lines.push(`目标：${analysis.target.name}（${KIND_LABEL[analysis.target.kind]}）`);
  lines.push(`来源：${analysis.target.path}`);
  lines.push(`解包 / 产物目录：${analysis.outDir}`);
  lines.push(`静态简报（先读这份）：${analysis.briefPath}`);
  if (analysis.appId) lines.push(`AppID / BundleID：${analysis.appId}`);
  if (analysis.packageName && analysis.packageName !== analysis.appId) lines.push(`包名：${analysis.packageName}`);
  if (analysis.mini) {
    const m = analysis.mini;
    lines.push("");
    lines.push(`小程序结构：${m.pages.length} 页${m.subPackages.length ? `，分包 ${m.subPackages.map((s) => `${s.root}(${s.count})`).join("、")}` : ""}`);
    if (m.tabBar.length) lines.push(`tabBar：${m.tabBar.join("、")}`);
    if (m.plugins.length) lines.push(`插件：${m.plugins.join("、")}`);
    if (m.cloudEnv.length) lines.push(`云开发环境：${m.cloudEnv.join("、")}（云函数 / 数据库 / 存储按越权面打）`);
  }
  if (analysis.app) {
    const p = analysis.app;
    lines.push("");
    lines.push(`APP 结构：${p.packageName ?? "-"} ${p.versionName ?? ""}；ABI ${p.abis.join("、") || "无"}；加固 ${p.guards.join("、") || "未识别"}`);
    const c = p.counts;
    lines.push(`组件：activity ${c.activity} / service ${c.service} / receiver ${c.receiver} / provider ${c.provider}`);
    if (p.deepLinks.length) lines.push(`深链：${p.deepLinks.join("、")}`);
    if (p.providers.length) lines.push(`Provider authority：${p.providers.join("、")}`);
  }
  if (analysis.endpoints.length) {
    lines.push("");
    lines.push(`已抽到 ${analysis.endpoints.length} 个接口候选（前 40 个）：`);
    for (const e of analysis.endpoints.slice(0, 40)) lines.push(`- ${e}`);
  }
  if (analysis.secrets.length) {
    lines.push("");
    lines.push(`已抽到 ${analysis.secrets.length} 条密钥 / 凭据候选（前 12 条，实值在简报里）：`);
    for (const s of analysis.secrets.slice(0, 12)) lines.push(`- [${s.kind}] ${s.value.slice(0, 80)} ← ${s.source}`);
  }
  if (analysis.pages.length) {
    lines.push("");
    lines.push(`页面 ${analysis.pages.length} 个（前 30）：${analysis.pages.slice(0, 30).join("、")}`);
  }
  if (analysis.components.length) {
    const exported = analysis.components.filter((c) => c.exported);
    lines.push("");
    lines.push(`组件 ${analysis.components.length} 个，其中导出 ${exported.length} 个：${exported.slice(0, 15).map((c) => c.name).join("、") || "无"}`);
  }
  if (analysis.notes.length) {
    lines.push("");
    lines.push("静态阶段已确认：");
    for (const note of analysis.notes) lines.push(`- ${note}`);
  }
  lines.push("");
  lines.push(`本轮要做的：${mode === "static" ? "只做静态 + 接口验证" : mode === "dynamic" ? "只做动态（设备 / hook / 抓包）" : "静态与动态都做"}`);
  if (mode !== "static") {
    lines.push("");
    lines.push("本机动态环境：");
    if (env?.tools?.length) for (const t of env.tools) lines.push(`- ${t.name}：${t.ok ? t.version || "可用" : `不可用（${t.hint ?? ""}）`}`);
    if (env?.devices?.length) for (const d of env.devices) lines.push(`- 设备 ${d.serial} ${d.state}${d.model ? ` ${d.model}` : ""}`);
    else lines.push("- 还没有已连接设备；没有设备就用静态 + 接口验证推进，并在结论里写清哪一步缺设备");
  }
  lines.push("");
  if (analysis.target.kind === "apk" || analysis.target.kind === "ipa") lines.push(APP_PLAYBOOK);
  else lines.push(MINI_PLAYBOOK);
  if (isApp) {
    lines.push("");
    lines.push("本应用已经能在当前会话里直接跑这些动态动作（面板「动态测试」页）：安装包 / 启动应用 / 拉起导出组件 / 发广播 / content query 查 Provider / 开关设备代理 / run-as 读私有目录 / logcat / frida 脚本生成 / 任意 adb shell。需要设备上的动作就直说要做哪一步，按上面的命令口径给出结论。");
  }
  lines.push("");
  lines.push("纪律：");
  lines.push("- 先把接口 / 组件清单落盘到任务夹，再按有差分面的参数打；不要每个 path 丢一个引号就算测过。");
  lines.push("- 越权换 id 不限字段名；有会话带着会话换，没会话未授权通了再换。");
  lines.push("- 中危先顺着同一对象挖大再换目标；CORS 不挖。");
  lines.push("- 真出洞按报告规范写到 Desktop\\{任务}_SRC挖洞\\报告\\，文件名就是标题；不写空报告、不堆低危。");
  lines.push("- 每轮结束在会话里说清：打成了什么、下一步打哪，不要问「要不要继续」。");
  return lines.join("\n");
}
