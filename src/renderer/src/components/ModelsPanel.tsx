import React, { useCallback, useEffect, useMemo, useState } from "react";
import type {
  BootstrapInfo,
  ModelConfig,
  ModelConfigInput,
  ModelProbeResult,
  ModelsConfig,
} from "@shared/types";
import { Icon } from "./Icons";

/** Electron 把主进程异常包成 "Error invoking remote method 'x': Error: ..."，这里剥掉外层 */
function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

function maskKey(key?: string): string {
  if (!key) return "";
  if (key.length <= 8) return "•".repeat(key.length);
  return `${key.slice(0, 3)}…${key.slice(-4)}`;
}

interface FormState {
  key: string;
  originalKey?: string;
  model: string;
  name: string;
  description: string;
  baseUrl: string;
  apiKey: string;
  envKey: string;
  apiBackend: string;
  contextWindow: string;
  temperature: string;
  topP: string;
  maxCompletionTokens: string;
  reasoningSummary: string;
  extra: string;
  makeDefault: boolean;
}

const EMPTY_FORM: FormState = {
  key: "",
  model: "",
  name: "",
  description: "",
  baseUrl: "",
  apiKey: "",
  envKey: "",
  apiBackend: "chat_completions",
  contextWindow: "",
  temperature: "",
  topP: "",
  maxCompletionTokens: "",
  reasoningSummary: "",
  extra: "",
  makeDefault: false,
};

function formOf(m: ModelConfig): FormState {
  return {
    key: m.key,
    originalKey: m.key,
    model: m.model,
    name: m.name ?? "",
    description: m.description ?? "",
    baseUrl: m.baseUrl ?? "",
    apiKey: m.apiKey ?? "",
    envKey: m.envKey ?? "",
    apiBackend: m.apiBackend ?? "chat_completions",
    contextWindow: m.contextWindow !== undefined ? String(m.contextWindow) : "",
    temperature: m.temperature !== undefined ? String(m.temperature) : "",
    topP: m.topP !== undefined ? String(m.topP) : "",
    maxCompletionTokens: m.maxCompletionTokens !== undefined ? String(m.maxCompletionTokens) : "",
    reasoningSummary: m.reasoningSummary ?? "",
    extra: m.extra ?? "",
    makeDefault: Boolean(m.isDefault),
  };
}

interface Preset {
  id: string;
  label: string;
  key: string;
  model: string;
  baseUrl: string;
  envKey: string;
  backend: string;
  context: number;
  note?: string;
}

const PRESETS: Preset[] = [
  {
    id: "deepseek",
    label: "DeepSeek",
    key: "deepseek-chat",
    model: "deepseek-chat",
    baseUrl: "https://api.deepseek.com/v1",
    envKey: "DEEPSEEK_API_KEY",
    backend: "chat_completions",
    context: 128000,
  },
  {
    id: "deepseek-r1",
    label: "DeepSeek R1",
    key: "deepseek-reasoner",
    model: "deepseek-reasoner",
    baseUrl: "https://api.deepseek.com/v1",
    envKey: "DEEPSEEK_API_KEY",
    backend: "chat_completions",
    context: 128000,
  },
  {
    id: "openai",
    label: "OpenAI",
    key: "gpt-4o",
    model: "gpt-4o",
    baseUrl: "https://api.openai.com/v1",
    envKey: "OPENAI_API_KEY",
    backend: "chat_completions",
    context: 128000,
  },
  {
    id: "anthropic",
    label: "Claude",
    key: "claude-sonnet",
    model: "claude-sonnet-4-5",
    baseUrl: "https://api.anthropic.com/v1",
    envKey: "ANTHROPIC_API_KEY",
    backend: "messages",
    context: 200000,
    note: "Anthropic 用 x-api-key 认证：把密钥写进额外参数的 extra_headers，别只填 API Key 输入框。",
  },
  {
    id: "ollama",
    label: "Ollama 本地",
    key: "ollama",
    model: "qwen2.5:7b",
    baseUrl: "http://localhost:11434/v1",
    envKey: "",
    backend: "chat_completions",
    context: 32768,
  },
  {
    id: "gateway",
    label: "本地网关",
    key: "local-gateway",
    model: "grok-4.5",
    baseUrl: "http://127.0.0.1:8787/v1",
    envKey: "XAI_API_KEY",
    backend: "chat_completions",
    context: 200000,
  },
];

function numOrUndefined(raw: string): number | undefined {
  const t = raw.trim();
  if (!t) return undefined;
  const n = Number(t);
  return Number.isFinite(n) ? n : Number.NaN;
}

function toInput(form: FormState): ModelConfigInput {
  return {
    key: form.key.trim(),
    originalKey: form.originalKey,
    model: form.model.trim(),
    name: form.name.trim() || undefined,
    description: form.description.trim() || undefined,
    baseUrl: form.baseUrl.trim() || undefined,
    apiKey: form.apiKey.trim() || undefined,
    envKey: form.envKey.trim() || undefined,
    apiBackend: form.apiBackend || undefined,
    contextWindow: numOrUndefined(form.contextWindow),
    temperature: numOrUndefined(form.temperature),
    topP: numOrUndefined(form.topP),
    maxCompletionTokens: numOrUndefined(form.maxCompletionTokens),
    reasoningSummary: form.reasoningSummary.trim() || undefined,
    extra: form.extra,
    makeDefault: form.makeDefault,
  };
}

export function ModelsPanel({
  boot,
  onConfigPath,
}: {
  boot: BootstrapInfo | null;
  onConfigPath?: (path: string) => void;
}) {
  const [cfg, setCfg] = useState<ModelsConfig | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ level: "ok" | "warn" | "error"; text: string } | null>(null);
  const [confirmKey, setConfirmKey] = useState<string>();
  const [revealKey, setRevealKey] = useState(false);
  /** /models 拉回来的可选模型；选一个就填进表单 */
  const [catalog, setCatalog] = useState<string[]>([]);
  const [probeBusy, setProbeBusy] = useState<"" | "models" | "chat">("");
  const [probeResult, setProbeResult] = useState<ModelProbeResult | null>(null);
  const [cardProbe, setCardProbe] = useState<Record<string, string>>({});

  const reload = useCallback(async () => {
    try {
      const next = await window.tanwei.modelsConfig();
      setCfg(next);
      if (next.path && onConfigPath) onConfigPath(next.path);
    } catch (err) {
      setMsg({ level: "error", text: errText(err) });
    }
  }, [onConfigPath]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const models = cfg?.models ?? [];
  const defaultKey = cfg?.defaultKey;
  const presetNote = useMemo(() => PRESETS.find((p) => p.id === "anthropic")?.note, []);

  const applyEngine = async (note: string): Promise<void> => {
    try {
      const runtime = await window.tanwei.restartEngine();
      await reload();
      setMsg({
        level: runtime.status === "ready" ? "ok" : "warn",
        text: `${note}；引擎已重启，当前加载 ${runtime.models.length} 个模型。`,
      });
    } catch (err) {
      setMsg({ level: "error", text: `重启引擎失败：${errText(err)}` });
    } finally {
      setBusy(false);
    }
  };

  const startCreate = () => {
    setConfirmKey(undefined);
    setRevealKey(false);
    setMsg(null);
    setCatalog([]);
    setProbeResult(null);
    setForm({ ...EMPTY_FORM });
  };

  const startEdit = (m: ModelConfig) => {
    setConfirmKey(undefined);
    setRevealKey(false);
    setMsg(null);
    setCatalog([]);
    setProbeResult(null);
    setForm(formOf(m));
  };

  /** 表单里的探测：先拉 /models，成功就把它铺成下拉；chat=true 再发一条最小对话 */
  const probeForm = async (chat: boolean) => {
    if (!form) return;
    setProbeBusy(chat ? "chat" : "models");
    setProbeResult(null);
    try {
      const res = await window.tanwei.probeModel({
        baseUrl: form.baseUrl,
        apiKey: form.apiKey,
        envKey: form.envKey,
        model: form.model,
        chat,
      });
      setProbeResult(res);
      if (res.models?.length) setCatalog(res.models);
      if (!res.ok) setMsg({ level: "error", text: res.error ?? "探测失败" });
    } catch (err) {
      setMsg({ level: "error", text: errText(err) });
    } finally {
      setProbeBusy("");
    }
  };

  /** 卡片上的连通性：用已保存的凭据跑一条最小对话 */
  const probeCard = async (m: ModelConfig) => {
    setCardProbe((prev) => ({ ...prev, [m.key]: "__busy" }));
    try {
      const res = await window.tanwei.probeModel({
        baseUrl: m.baseUrl,
        apiKey: m.apiKey,
        envKey: m.envKey,
        model: m.model,
        chat: true,
      });
      const text = res.ok
        ? `通 · ${res.latencyMs} ms${res.reply ? ` · 回包「${res.reply.slice(0, 16)}」` : ""}`
        : `失败 · ${res.error ?? "未知错误"}`;
      setCardProbe((prev) => ({ ...prev, [m.key]: text }));
    } catch (err) {
      setCardProbe((prev) => ({ ...prev, [m.key]: `失败 · ${errText(err)}` }));
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form || busy) return;
    const input = toInput(form);
    if (!input.key) {
      setMsg({ level: "error", text: "配置名不能为空" });
      return;
    }
    for (const [label, value] of [
      ["上下文窗口", input.contextWindow],
      ["温度", input.temperature],
      ["top_p", input.topP],
      ["最大输出 tokens", input.maxCompletionTokens],
    ] as const) {
      if (Number.isNaN(value)) {
        setMsg({ level: "error", text: `${label} 需要填数字` });
        return;
      }
    }
    setBusy(true);
    setMsg({ level: "ok", text: `正在写入 ${cfg?.path ?? "config.toml"}…` });
    try {
      const next = await window.tanwei.saveModel(input);
      setCfg(next);
      setForm(null);
      await applyEngine(`已保存模型 ${input.key}`);
    } catch (err) {
      setBusy(false);
      setMsg({ level: "error", text: errText(err) });
    }
  };

  const remove = async (key: string) => {
    if (busy) return;
    if (confirmKey !== key) {
      setConfirmKey(key);
      setMsg({ level: "warn", text: `再点一次「确认删除」会删掉 [model.${key}]。` });
      return;
    }
    setBusy(true);
    setConfirmKey(undefined);
    try {
      const next = await window.tanwei.deleteModel(key);
      setCfg(next);
      await applyEngine(`已删除模型 ${key}`);
    } catch (err) {
      setBusy(false);
      setMsg({ level: "error", text: errText(err) });
    }
  };

  const makeDefault = async (key: string) => {
    if (busy) return;
    setConfirmKey(undefined);
    setBusy(true);
    try {
      const next = await window.tanwei.setDefaultModel(key);
      setCfg(next);
      await applyEngine(`已把 ${key} 设为默认模型`);
    } catch (err) {
      setBusy(false);
      setMsg({ level: "error", text: errText(err) });
    }
  };

  const applyPreset = (p: Preset) => {
    setForm((f) =>
      f
        ? {
            ...f,
            key: f.key || p.key,
            name: f.name || p.label,
            model: p.model,
            baseUrl: p.baseUrl,
            envKey: p.envKey,
            apiBackend: p.backend,
            contextWindow: String(p.context),
          }
        : f,
    );
  };

  const currentPreset = PRESETS.find((p) => p.backend === form?.apiBackend && p.baseUrl === form?.baseUrl);

  return (
    <div className="model-page">
      <div className="model-bar">
        <button className="btn primary" onClick={startCreate} disabled={busy}>
          <Icon name="plus" size={13} />
          <span>新增模型</span>
        </button>
        <button className="btn ghost" onClick={() => void reload()} disabled={busy}>
          <Icon name="refresh" size={13} />
          <span>重新读取</span>
        </button>
        <button
          className="btn ghost"
          onClick={() => cfg?.path && void window.tanwei.openPath(cfg.path)}
          disabled={!cfg?.path}
        >
          <Icon name="file" size={13} />
          <span>打开 config.toml</span>
        </button>
        <button
          className="btn ghost"
          onClick={() => void applyEngine("配置未改动")}
          disabled={busy}
          title="重连 agent 进程，让所有配置改动生效"
        >
          <Icon name="refresh" size={13} />
          <span>重启引擎</span>
        </button>
      </div>

      <div className="model-hint mono">
        {cfg?.path ?? boot?.configPath ?? "~/.grok/config.toml"}
        {defaultKey ? `　默认：${defaultKey}` : ""}
      </div>

      {msg ? <div className={`model-note ${msg.level}`}>{msg.text}</div> : null}

      <div className="model-grid">
        {models.map((m) => (
          <div className="card model-card" key={m.key}>
            <div className="card-top">
              <span className="card-title mono">{m.key}</span>
              {m.isDefault ? <span className="chip chip-on">默认</span> : null}
              <span className={`chip ${m.engineLoaded ? "chip-on" : "chip-off"}`}>
                {m.engineLoaded ? "已加载" : "待重启"}
              </span>
            </div>
            <div className="card-path mono">{m.name || m.model || "（沿用同名内置模型）"}</div>
            <div className="kv">
              <span className="kv-k">模型 ID</span>
              <span className="kv-v mono">{m.model || "（未指定）"}</span>
            </div>
            <div className="kv">
              <span className="kv-k">端点</span>
              <span className="kv-v mono">{m.baseUrl || "（继承 [endpoints]）"}</span>
            </div>
            <div className="kv">
              <span className="kv-k">协议</span>
              <span className="kv-v mono">{m.apiBackend || "chat_completions"}</span>
            </div>
            <div className="kv">
              <span className="kv-k">凭证</span>
              <span className="kv-v mono">
                {m.apiKey ? maskKey(m.apiKey) : m.envKey ? `env: ${m.envKey}` : "登录态 / XAI_API_KEY"}
              </span>
            </div>
            {m.contextWindow ? (
              <div className="kv">
                <span className="kv-k">上下文</span>
                <span className="kv-v mono">{m.contextWindow.toLocaleString()} tokens</span>
              </div>
            ) : null}
            {cardProbe[m.key] && cardProbe[m.key] !== "__busy" ? (
              <div className="card-note mono probe-note">{cardProbe[m.key]}</div>
            ) : null}
            <div className="card-actions">
              <button className="btn ghost sm" onClick={() => startEdit(m)} disabled={busy}>
                <Icon name="settings" size={12} />
                <span>编辑</span>
              </button>
              <button
                className="btn ghost sm"
                onClick={() => void probeCard(m)}
                disabled={busy || cardProbe[m.key] === "__busy"}
              >
                <Icon name="bolt" size={12} />
                <span>{cardProbe[m.key] === "__busy" ? "探测中…" : "连通性"}</span>
              </button>
              {!m.isDefault ? (
                <button className="btn ghost sm" onClick={() => void makeDefault(m.key)} disabled={busy}>
                  <Icon name="check" size={12} />
                  <span>设为默认</span>
                </button>
              ) : null}
              <button
                className={`btn ghost sm ${confirmKey === m.key ? "danger" : ""}`}
                onClick={() => void remove(m.key)}
                disabled={busy}
              >
                <Icon name="close" size={12} />
                <span>{confirmKey === m.key ? "确认删除" : "删除"}</span>
              </button>
            </div>
          </div>
        ))}
        {!models.length ? (
          <div className="module-empty">
            还没有 `[model.*]` 配置。点「新增模型」填一个提供商（DeepSeek / OpenAI / 本地网关都能填），保存后引擎会自动重启并出现在会话的模型下拉里。
          </div>
        ) : null}
      </div>

      {form ? (
        <form className="model-form" onSubmit={submit}>
          <div className="card-top">
            <span className="card-title">
              {form.originalKey ? `编辑 ${form.originalKey}` : "新增模型"}
            </span>
            <button
              type="button"
              className="btn ghost sm"
              onClick={() => setForm(null)}
              disabled={busy}
            >
              <Icon name="close" size={12} />
              <span>取消</span>
            </button>
          </div>

          {!form.originalKey ? (
            <div className="preset-row">
              <span className="preset-label">快速填充</span>
              {PRESETS.map((p) => (
                <button
                  type="button"
                  key={p.id}
                  className={`preset ${currentPreset?.id === p.id ? "on" : ""}`}
                  onClick={() => applyPreset(p)}
                  disabled={busy}
                >
                  {p.label}
                </button>
              ))}
            </div>
          ) : null}

          <div className="field-grid">
            <label className="field">
              <span className="field-label">配置名（表键）*</span>
              <input
                className="input mono"
                value={form.key}
                onChange={(e) => setForm({ ...form, key: e.target.value })}
                placeholder="deepseek-chat"
                spellCheck={false}
                disabled={busy}
              />
              <span className="field-tip">写进 config.toml 的 [model.&lt;这个名字&gt;]，也是下拉里显示的值</span>
            </label>

            <label className="field">
              <span className="field-label">实际模型 ID *</span>
              <input
                className="input mono"
                value={form.model}
                onChange={(e) => setForm({ ...form, model: e.target.value })}
                placeholder="deepseek-chat"
                spellCheck={false}
                disabled={busy}
              />
              <span className="field-tip">发给 API 的 model 字段，例如 deepseek-chat / gpt-4o / grok-4.5</span>
            </label>

            <label className="field">
              <span className="field-label">显示名称</span>
              <input
                className="input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="DeepSeek V3"
                disabled={busy}
              />
            </label>

            <label className="field">
              <span className="field-label">描述</span>
              <input
                className="input"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="可选，模型选择器里的说明"
                disabled={busy}
              />
            </label>

            <label className="field field-wide">
              <span className="field-label">Base URL（API 地址）</span>
              <input
                className="input mono"
                value={form.baseUrl}
                onChange={(e) => setForm({ ...form, baseUrl: e.target.value })}
                placeholder="https://api.deepseek.com/v1"
                spellCheck={false}
                disabled={busy}
              />
              <span className="field-tip">留空则继承 [endpoints] models_base_url</span>
            </label>

            <label className="field">
              <span className="field-label">API Key</span>
              <div className="input-row">
                <input
                  className="input mono"
                  type={revealKey ? "text" : "password"}
                  value={form.apiKey}
                  onChange={(e) => setForm({ ...form, apiKey: e.target.value })}
                  placeholder="sk-..."
                  spellCheck={false}
                  autoComplete="off"
                  disabled={busy}
                />
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => setRevealKey((v) => !v)}
                  disabled={busy}
                >
                  {revealKey ? "隐藏" : "显示"}
                </button>
              </div>
              <span className="field-tip">写进配置文件的 api_key；和下面环境变量二选一，api_key 优先</span>
            </label>

            <label className="field">
              <span className="field-label">环境变量名 env_key</span>
              <input
                className="input mono"
                value={form.envKey}
                onChange={(e) => setForm({ ...form, envKey: e.target.value })}
                placeholder="DEEPSEEK_API_KEY"
                spellCheck={false}
                disabled={busy}
              />
              <span className="field-tip">多个用逗号分隔，写成数组；不把密钥落盘时用这个</span>
            </label>

            <div className="field field-wide">
              <span className="field-label">连通性 / 模型列表</span>
              <div className="probe-row">
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => void probeForm(false)}
                  disabled={busy || probeBusy !== ""}
                >
                  <Icon name="bolt" size={12} />
                  <span>{probeBusy === "models" ? "拉取中…" : "拉取模型列表"}</span>
                </button>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => void probeForm(true)}
                  disabled={busy || probeBusy !== "" || !form.model}
                >
                  <Icon name="check" size={12} />
                  <span>{probeBusy === "chat" ? "测试中…" : "测试对话"}</span>
                </button>
                {probeResult ? (
                  <span className={`probe-status ${probeResult.ok ? "ok" : "bad"}`}>
                    {probeResult.ok ? "通" : "失败"} · {probeResult.latencyMs} ms
                    {probeResult.models ? ` · ${probeResult.models.length} 个模型` : ""}
                    {probeResult.error ? ` · ${probeResult.error}` : ""}
                    {probeResult.reply ? ` · 回包「${probeResult.reply.slice(0, 20)}」` : ""}
                  </span>
                ) : null}
              </div>
              {catalog.length ? (
                <select
                  className="input mono"
                  value={form.model}
                  onChange={(e) => {
                    const id = e.target.value;
                    setForm({
                      ...form,
                      model: id,
                      key: form.originalKey ? form.key : id,
                      name: form.name || id,
                    });
                  }}
                  disabled={busy}
                >
                  <option value="">（从接口返回的 {catalog.length} 个模型里选）</option>
                  {catalog.map((id) => (
                    <option key={id} value={id}>
                      {id}
                    </option>
                  ))}
                </select>
              ) : null}
              <span className="field-tip">
                填好 Base URL 和 Key 后点「拉取模型列表」，列表来自该地址的 /models；选中会自动填上面的模型 ID 和配置名
              </span>
            </div>

            <label className="field">
              <span className="field-label">协议 api_backend</span>
              <select
                className="input"
                value={form.apiBackend}
                onChange={(e) => setForm({ ...form, apiBackend: e.target.value })}
                disabled={busy}
              >
                <option value="chat_completions">chat_completions（OpenAI 兼容，默认）</option>
                <option value="responses">responses（OpenAI Responses）</option>
                <option value="messages">messages（Anthropic Messages）</option>
              </select>
            </label>

            <label className="field">
              <span className="field-label">上下文窗口 context_window</span>
              <input
                className="input mono"
                value={form.contextWindow}
                onChange={(e) => setForm({ ...form, contextWindow: e.target.value })}
                placeholder="128000"
                spellCheck={false}
                disabled={busy}
              />
            </label>

            <label className="field">
              <span className="field-label">温度 temperature</span>
              <input
                className="input mono"
                value={form.temperature}
                onChange={(e) => setForm({ ...form, temperature: e.target.value })}
                placeholder="0.7"
                spellCheck={false}
                disabled={busy}
              />
            </label>

            <label className="field">
              <span className="field-label">top_p</span>
              <input
                className="input mono"
                value={form.topP}
                onChange={(e) => setForm({ ...form, topP: e.target.value })}
                placeholder="0.95"
                spellCheck={false}
                disabled={busy}
              />
            </label>

            <label className="field">
              <span className="field-label">最大输出 max_completion_tokens</span>
              <input
                className="input mono"
                value={form.maxCompletionTokens}
                onChange={(e) => setForm({ ...form, maxCompletionTokens: e.target.value })}
                placeholder="8192"
                spellCheck={false}
                disabled={busy}
              />
            </label>

            <label className="field">
              <span className="field-label">推理摘要 reasoning_summary</span>
              <select
                className="input"
                value={form.reasoningSummary}
                onChange={(e) => setForm({ ...form, reasoningSummary: e.target.value })}
                disabled={busy}
              >
                <option value="">（不设置）</option>
                <option value="none">none</option>
                <option value="auto">auto</option>
                <option value="concise">concise</option>
                <option value="detailed">detailed</option>
              </select>
              <span className="field-tip">仅 responses 协议生效</span>
            </label>

            <label className="field field-wide">
              <span className="field-label">高级参数（原样写进块内）</span>
              <textarea
                className="input mono extra"
                value={form.extra}
                onChange={(e) => setForm({ ...form, extra: e.target.value })}
                placeholder={'extra_headers = { "x-api-key" = "sk-ant-...", "anthropic-version" = "2023-06-01" }'}
                spellCheck={false}
                rows={4}
                disabled={busy}
              />
              <span className="field-tip">
                块里未受管的行会原样保留在这里；可写 extra_headers / query_params / env_http_headers / notice / model_provider 等
              </span>
            </label>
          </div>

          <div className="model-form-foot">
            <label className="check">
              <input
                type="checkbox"
                checked={form.makeDefault}
                onChange={(e) => setForm({ ...form, makeDefault: e.target.checked })}
                disabled={busy}
              />
              <span>设为默认模型（[models] default）</span>
            </label>
            {form.apiBackend === "messages" ? <span className="model-hint">{presetNote}</span> : null}
            <span className="model-hint">保存会重启 agent 进程；当前对话句柄失效，历史记录仍在。</span>
            <div className="model-form-actions">
              <button type="button" className="btn ghost" onClick={() => setForm(null)} disabled={busy}>
                取消
              </button>
              <button type="submit" className="btn primary" disabled={busy}>
                <Icon name="check" size={13} />
                <span>{busy ? "保存中…" : "保存并重启引擎"}</span>
              </button>
            </div>
          </div>
        </form>
      ) : null}
    </div>
  );
}
