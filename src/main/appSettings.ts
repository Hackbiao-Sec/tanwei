import { app } from "electron";
import fs from "node:fs";
import path from "node:path";
import type { BrowserSettings, ChromeMode, NetworkSettings, ProxyMode } from "../shared/types";

/** 应用自己的设置（与 grok 的 config.toml 分开存） */
export interface AppSettings {
  network: NetworkSettings;
  browser: BrowserSettings;
}

const DEFAULTS: AppSettings = {
  network: { proxyMode: "system", proxyUrl: "" },
  // 默认把 MCP 的 Chrome 放屏幕外，免得每次开探微都弹一个浏览器
  browser: { chromeMode: "hidden" },
};

function file(): string {
  return path.join(app.getPath("userData"), "settings.json");
}

function normalizeMode(value: unknown): ProxyMode {
  return value === "manual" || value === "pool" || value === "off" ? value : "system";
}

function normalizeChromeMode(value: unknown): ChromeMode {
  return value === "hidden" || value === "headless" || value === "visible" ? value : "hidden";
}

export function readSettings(): AppSettings {
  try {
    const raw = JSON.parse(fs.readFileSync(file(), "utf8"));
    const net = raw?.network ?? {};
    return {
      network: {
        proxyMode: normalizeMode(net.proxyMode),
        proxyUrl: typeof net.proxyUrl === "string" ? net.proxyUrl.trim() : "",
      },
      browser: {
        chromeMode: normalizeChromeMode(raw?.browser?.chromeMode),
      },
    };
  } catch {
    return {
      network: { ...DEFAULTS.network },
      browser: { ...DEFAULTS.browser },
    };
  }
}

export function writeSettings(input: {
  network?: Partial<NetworkSettings>;
  browser?: Partial<BrowserSettings>;
}): AppSettings {
  const current = readSettings();
  const next: AppSettings = {
    network: {
      proxyMode: normalizeMode(input.network?.proxyMode ?? current.network.proxyMode),
      proxyUrl: (input.network?.proxyUrl ?? current.network.proxyUrl).trim(),
    },
    browser: {
      chromeMode: normalizeChromeMode(input.browser?.chromeMode ?? current.browser.chromeMode),
    },
  };
  fs.mkdirSync(path.dirname(file()), { recursive: true });
  fs.writeFileSync(file(), `${JSON.stringify(next, null, 2)}\n`, "utf8");
  return next;
}

export function settingsPath(): string {
  return file();
}
