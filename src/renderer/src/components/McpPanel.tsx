import React, { useCallback, useEffect, useState } from "react";
import type { McpServerConfig, McpServerInfo, McpServersConfig } from "@shared/types";
import { Icon } from "./Icons";

function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

interface FormState {
  name: string;
  originalName?: string;
  command: string;
  args: string;
  cwd: string;
  env: string;
  enabled: boolean;
  extra: string;
}

const EMPTY_FORM: FormState = {
  name: "",
  command: "",
  args: "",
  cwd: "",
  env: "",
  enabled: true,
  extra: "",
};

function formOf(s: McpServerConfig): FormState {
  return {
    name: s.name,
    originalName: s.name,
    command: s.command,
    args: s.args.join("\n"),
    cwd: s.cwd ?? "",
    env: Object.entries(s.env)
      .map(([k, v]) => `${k}=${v}`)
      .join("\n"),
    enabled: s.enabled !== false,
    extra: s.extra ?? "",
  };
}

const PRESETS: { id: string; label: string; hint: string; patch: Partial<FormState> }[] = [
  {
    id: "playwright",
    label: "Playwright 浏览器",
    hint: "node ~/.grok/bin/playwright-dual-slot.mjs",
    patch: {
      name: "playwright",
      command: "node",
      args: "C:\\Users\\Hackbiao\\.grok\\bin\\playwright-dual-slot.mjs",
      extra: "startup_timeout_sec = 300\ntool_timeout_sec = 180",
    },
  },
  {
    id: "filesystem",
    label: "文件系统",
    hint: "npx -y @modelcontextprotocol/server-filesystem <目录>",
    patch: {
      name: "filesystem",
      command: "npx",
      args: "-y\n@modelcontextprotocol/server-filesystem\nC:\\Users",
    },
  },
  {
    id: "fetch",
    label: "网页抓取",
    hint: "uvx mcp-server-fetch",
    patch: { name: "fetch", command: "uvx", args: "mcp-server-fetch" },
  },
];

interface Props {
  /** 引擎事件里带回的运行时状态，用来标 ready / failed */
  runtime: McpServerInfo[];
  onChanged?: () => void;
  onRestartEngine?: () => Promise<unknown> | void;
  onToast?: (kind: "error" | "info" | "ok", text: string) => void;
}

export function McpPanel({ runtime, onChanged, onRestartEngine, onToast }: Props): React.JSX.Element {
  const [config, setConfig] = useState<McpServersConfig | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | undefined>();
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setConfig(await window.tanwei.mcpConfig());
    } catch (err) {
      setNotice(errText(err));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const statusOf = (name: string): McpServerInfo | undefined =>
    runtime.find((r) => r.name === name);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form) return;
    setBusy(true);
    setNotice(undefined);
    try {
      const env: Record<string, string> = {};
      for (const raw of form.env.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const eq = line.indexOf("=");
        if (eq <= 0) throw new Error(`环境变量要写成 KEY=VALUE：${line}`);
        env[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
      }
      const next = await window.tanwei.saveMcpServer({
        name: form.name.trim(),
        originalName: form.originalName,
        command: form.command.trim(),
        args: form.args.split(/\r?\n/).map((a) => a.trim()).filter(Boolean),
        cwd: form.cwd.trim() || undefined,
        enabled: form.enabled,
        env,
        extra: form.extra,
      });
      setConfig(next);
      setForm(null);
      onToast?.("ok", "MCP 配置已写入 config.toml，重启引擎后生效");
      onChanged?.();
    } catch (err) {
      setNotice(errText(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (name: string) => {
    setBusy(true);
    setNotice(undefined);
    try {
      setConfig(await window.tanwei.deleteMcpServer(name));
      onToast?.("ok", `已删除 ${name}`);
      onChanged?.();
    } catch (err) {
      setNotice(errText(err));
    } finally {
      setBusy(false);
      setPendingDelete(null);
    }
  };

  const servers = config?.servers ?? [];

  return (
    <div className="model-page">
      <div className="model-bar">
        <button
          className="btn primary"
          onClick={() => {
            setNotice(undefined);
            setForm({ ...EMPTY_FORM });
          }}
          disabled={busy}
        >
          <Icon name="plus" size={13} />
          <span>添加 MCP 服务</span>
        </button>
        <button className="btn ghost" onClick={() => void reload()} disabled={busy}>
          <Icon name="refresh" size={13} />
          <span>重新读取</span>
        </button>
        {onRestartEngine ? (
          <button className="btn ghost" onClick={() => void onRestartEngine()} disabled={busy}>
            <Icon name="bolt" size={13} />
            <span>重启引擎</span>
          </button>
        ) : null}
        <div className="model-hint mono">{config?.path ?? "~/.grok/config.toml"}</div>
      </div>

      {notice ? <div className="module-error">{notice}</div> : null}

      {form ? (
        <form className="model-form" onSubmit={submit}>
          <div className="card-top">
            <span className="card-title">{form.originalName ? `编辑 ${form.originalName}` : "新增 MCP 服务"}</span>
            <button type="button" className="btn ghost sm" onClick={() => setForm(null)}>
              取消
            </button>
          </div>

          <div className="preset-row">
            <span className="preset-label">常用模板</span>
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                className="btn ghost sm"
                title={p.hint}
                onClick={() => setForm({ ...form, ...p.patch })}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="field-grid">
            <label className="field">
              <span className="field-label">服务名 *</span>
              <input
                className="input mono"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="fofa"
              />
              <span className="field-tip">写进 config.toml 的 [mcp_servers.&lt;服务名&gt;]</span>
            </label>

            <label className="field">
              <span className="field-label">启动命令 *</span>
              <input
                className="input mono"
                value={form.command}
                onChange={(e) => setForm({ ...form, command: e.target.value })}
                placeholder="node / uv / npx / python"
              />
              <span className="field-tip">可执行文件或 PATH 里的命令，绝对路径最稳</span>
            </label>

            <label className="field">
              <span className="field-label">参数</span>
              <textarea
                className="input mono mcp-textarea"
                rows={4}
                value={form.args}
                onChange={(e) => setForm({ ...form, args: e.target.value })}
                placeholder={"run\n--directory\nC:\\path\\to\\server\npython\nserver.py"}
              />
              <span className="field-tip">一行一个参数，空格和引号不用自己包</span>
            </label>

            <label className="field">
              <span className="field-label">环境变量</span>
              <textarea
                className="input mono mcp-textarea"
                rows={4}
                value={form.env}
                onChange={(e) => setForm({ ...form, env: e.target.value })}
                placeholder={"FOFA_EMAIL=you@example.com\nFOFA_KEY=xxxx"}
              />
              <span className="field-tip">一行一个 KEY=VALUE，写进 [mcp_servers.&lt;服务名&gt;.env]</span>
            </label>

            <label className="field">
              <span className="field-label">工作目录</span>
              <input
                className="input mono"
                value={form.cwd}
                onChange={(e) => setForm({ ...form, cwd: e.target.value })}
                placeholder="留空表示继承探微的工作目录"
              />
            </label>

            <div className="field">
              <span className="field-label">启用</span>
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                />
                <span>enabled = {form.enabled ? "true" : "false"}</span>
              </label>
            </div>

            <label className="field field-wide">
              <span className="field-label">其它字段</span>
              <textarea
                className="input mono mcp-textarea"
                rows={3}
                value={form.extra}
                onChange={(e) => setForm({ ...form, extra: e.target.value })}
                placeholder={"startup_timeout_sec = 300\ntool_timeout_sec = 180"}
              />
              <span className="field-tip">原样保留在表里，适合超时之类的字段</span>
            </label>
          </div>

          <div className="model-form-foot">
            <div className="model-form-actions">
              <button className="btn primary" type="submit" disabled={busy}>
                {busy ? "保存中…" : "保存"}
              </button>
            </div>
          </div>
        </form>
      ) : null}

      {servers.length === 0 ? (
        <div className="module-empty">
          还没有 MCP 服务。点「添加 MCP 服务」直接写进 config.toml，或手工编辑该文件。
        </div>
      ) : (
        <div className="model-grid">
          {servers.map((s) => {
            const rt = statusOf(s.name);
            const status = rt?.status ?? (s.enabled === false ? "disabled" : "configured");
            const chipClass =
              status === "ready" ? "chip-on" : status === "failed" ? "chip-off" : "chip-ghost";
            return (
              <div className="card model-card" key={s.name}>
                <div className="card-top">
                  <span className="card-title mono">{s.name}</span>
                  <span className={`chip ${chipClass}`}>{status}</span>
                </div>
                <div className="kv">
                  <span className="kv-k">命令</span>
                  <span className="kv-v mono">{s.command}</span>
                </div>
                <div className="kv">
                  <span className="kv-k">参数</span>
                  <span className="kv-v mono">{s.args.length ? s.args.join(" ") : "—"}</span>
                </div>
                <div className="kv">
                  <span className="kv-k">环境变量</span>
                  <span className="kv-v mono">
                    {Object.keys(s.env).length ? Object.keys(s.env).join(", ") : "—"}
                  </span>
                </div>
                <div className="kv">
                  <span className="kv-k">工作目录</span>
                  <span className="kv-v mono">{s.cwd || "继承"}</span>
                </div>
                <div className="kv">
                  <span className="kv-k">启用</span>
                  <span className="kv-v">{s.enabled === false ? "否" : "是"}</span>
                </div>
                {typeof rt?.tools === "number" ? (
                  <div className="kv">
                    <span className="kv-k">工具数</span>
                    <span className="kv-v">{rt.tools}</span>
                  </div>
                ) : null}
                {rt?.status === "failed" && rt.reason ? <div className="card-note">{rt.reason}</div> : null}
                {s.extra ? <div className="card-note mono">{s.extra.split("\n")[0]}</div> : null}
                <div className="card-actions">
                  <button
                    className="btn ghost sm"
                    onClick={() => {
                      setNotice(undefined);
                      setForm(formOf(s));
                    }}
                    disabled={busy}
                  >
                    <Icon name="settings" size={12} />
                    <span>编辑</span>
                  </button>
                  {pendingDelete === s.name ? (
                    <>
                      <button className="btn sm danger" onClick={() => void remove(s.name)} disabled={busy}>
                        <span>确认删除</span>
                      </button>
                      <button className="btn ghost sm" onClick={() => setPendingDelete(null)} disabled={busy}>
                        <span>取消</span>
                      </button>
                    </>
                  ) : (
                    <button
                      className="btn ghost sm"
                      onClick={() => setPendingDelete(s.name)}
                      disabled={busy}
                    >
                      <Icon name="close" size={12} />
                      <span>删除</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
