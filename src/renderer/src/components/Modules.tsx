import React, { useEffect, useState } from "react";
import type {
  BootstrapInfo,
  BrowserSettings,
  ChromeMode,
  CommandInfo,
  EndpointProbe,
  EngineStatus,
  NetworkStatus,
  ProxyEntry,
  ProxyMode,
  ProxyPool,
  McpServerInfo,
  ReportEntry,
  RuleEntry,
  SessionState,
  SessionSummary,
  SkillEntry,
} from "@shared/types";
import type { ModuleId } from "../view";
import { MODULES } from "../view";
import { Icon } from "./Icons";
import { McpPanel } from "./McpPanel";
import { ModelsPanel } from "./ModelsPanel";
import { Dashboard } from "./Dashboard";
import { Findings } from "./Findings";
import { Graph } from "./Graph";
import { Tasks } from "./Tasks";
import { Assets } from "./Assets";
import { Traffic } from "./Traffic";
import { Tools } from "./Tools";
import { Logs } from "./Logs";

function fmtTime(t?: number): string {
  if (!t) return "—";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function Crumbs({ items }: { items: string[] }) {
  return (
    <div className="crumbs">
      {items.map((t, i) => (
        <span key={`${i}-${t}`} className={i === items.length - 1 ? "crumb on" : "crumb"}>
          {t}
        </span>
      ))}
    </div>
  );
}

const SELF_HEADED: ModuleId[] = ["dashboard"];

const PROXY_MODES: { id: ProxyMode; label: string; hint: string }[] = [
  { id: "system", label: "跟随系统", hint: "读 Windows 代理设置" },
  { id: "manual", label: "手动", hint: "填 Clash 等端口" },
  { id: "pool", label: "代理池", hint: "池里自动挑 + 测活" },
  { id: "off", label: "不使用", hint: "全部直连" },
];

const HEALTH_LABEL: Record<string, string> = { ok: "可用", bad: "不通", unknown: "未测" };
const SOURCE_LABEL: Record<string, string> = { config: "导入", free: "免费", manual: "手填" };

const CHROME_MODES: { id: ChromeMode; label: string; hint: string }[] = [
  { id: "hidden", label: "隐藏", hint: "真 Chrome 放屏幕外" },
  { id: "headless", label: "无头", hint: "不建窗口，更省内存" },
  { id: "visible", label: "显示", hint: "像以前那样弹窗" },
];

function poolHealth(entry: ProxyEntry): string {
  return HEALTH_LABEL[entry.health] ?? "未测";
}

export function ModulePage({
  id,
  mcp,
  boot,
  status,
  version,
  live,
  history,
  loadingId,
  onRefreshSessions,
  onOpenSession,
  onCreateSession,
  onAsk,
  onModule,
  commands,
  sessionTasks = [],
  activeId,
}: {
  id: ModuleId;
  mcp: McpServerInfo[];
  boot: BootstrapInfo | null;
  status: EngineStatus;
  version?: string;
  live: SessionState[];
  history: SessionSummary[];
  loadingId?: string;
  onRefreshSessions: () => void;
  onOpenSession: (id: string) => void;
  onCreateSession: () => void;
  onAsk: (prompt: string) => void;
  onModule: (id: ModuleId) => void;
  commands: CommandInfo[];
  /** 当前会话碰过的任务夹，用来做「本会话 / 全部」隔离 */
  sessionTasks?: string[];
  /** 当前打开的会话，渗透过程图谱默认看它 */
  activeId?: string;
}) {
  const def = MODULES.find((m) => m.id === id)!;
  const [reports, setReports] = useState<ReportEntry[]>([]);
  const [skills, setSkills] = useState<SkillEntry[]>([]);
  const [rules, setRules] = useState<RuleEntry[]>([]);
  const [mcpList, setMcpList] = useState<McpServerInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [startup, setStartup] = useState<{ path: string; text: string; safeMode: boolean }>();
  const [busySkill, setBusySkill] = useState<string>();
  const [installOpen, setInstallOpen] = useState(false);
  const [installBusy, setInstallBusy] = useState(false);
  const [notice, setNotice] = useState<string>();
  const [newSkill, setNewSkill] = useState({ name: "", description: "", body: "" });
  const [net, setNet] = useState<NetworkStatus>();
  const [netBusy, setNetBusy] = useState(false);
  const [netNotice, setNetNotice] = useState<string>();
  const [probe, setProbe] = useState<EndpointProbe>();
  const [probeBusy, setProbeBusy] = useState(false);
  const [pool, setPool] = useState<ProxyPool>();
  const [poolBusy, setPoolBusy] = useState<string>();
  const [poolNotice, setPoolNotice] = useState<string>();
  const [poolError, setPoolError] = useState<string>();
  const [poolText, setPoolText] = useState("");
  const [poolOnlyOk, setPoolOnlyOk] = useState(false);
  const [clearArmed, setClearArmed] = useState(false);
  const [browser, setBrowser] = useState<BrowserSettings>();
  const [browserBusy, setBrowserBusy] = useState(false);
  const [browserNotice, setBrowserNotice] = useState<string>();

  const saveNetwork = async (restart: boolean) => {
    if (!net) return;
    setNetBusy(true);
    setError(undefined);
    setNetNotice(undefined);
    try {
      const saved = await window.tanwei.saveNetwork({
        proxyMode: net.proxyMode,
        proxyUrl: net.proxyUrl,
      });
      setNet(saved);
      if (restart) {
        await window.tanwei.restartEngine();
        setNetNotice(`已保存并重启引擎，当前走 ${saved.effective || "直连"}`);
      } else {
        setNetNotice(`已保存，重启引擎后生效（当前走 ${saved.effective || "直连"}）`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setNetBusy(false);
    }
  };

  const saveBrowser = async (chromeMode: ChromeMode) => {
    setBrowserBusy(true);
    setError(undefined);
    setBrowserNotice(undefined);
    try {
      const saved = await window.tanwei.saveBrowserSettings({ chromeMode });
      setBrowser(saved);
      setBrowserNotice(
        `已保存「${CHROME_MODES.find((m) => m.id === saved.chromeMode)?.label ?? saved.chromeMode}」，重启引擎后生效`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBrowserBusy(false);
    }
  };

  const restartForBrowser = async () => {
    setBrowserBusy(true);
    setError(undefined);
    setBrowserNotice(undefined);
    try {
      await window.tanwei.restartEngine();
      setBrowserNotice("引擎已重启，浏览器按当前设置拉起");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBrowserBusy(false);
    }
  };

  const runProbe = async () => {
    setProbeBusy(true);
    setError(undefined);
    try {
      setProbe(await window.tanwei.probeNetwork());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbeBusy(false);
    }
  };

  const poolTask = async (key: string, fn: () => Promise<void>) => {
    setPoolBusy(key);
    setPoolError(undefined);
    setPoolNotice(undefined);
    try {
      await fn();
    } catch (err) {
      setPoolError(err instanceof Error ? err.message : String(err));
    } finally {
      setPoolBusy(undefined);
    }
  };

  const importPoolFile = () =>
    poolTask("import", async () => {
      const res = await window.tanwei.importPoolFile();
      if (!res) return;
      setPool(res.pool);
      setPoolNotice(
        res.added
          ? `从配置文件导入 ${res.added} 条代理${res.skipped ? `，${res.skipped} 行没认出` : ""}`
          : `没有新代理，这份文件里的 ${res.pool.entries.length} 条已经在池里`,
      );
    });

  const importPoolText = () =>
    poolTask("paste", async () => {
      const res = await window.tanwei.importPoolText(poolText);
      setPool(res.pool);
      setPoolText("");
      setPoolNotice(
        res.added
          ? `粘贴导入 ${res.added} 条代理${res.skipped ? `，${res.skipped} 行没认出` : ""}`
          : "这些代理池里已经有了",
      );
    });

  const fetchFree = () =>
    poolTask("free", async () => {
      const res = await window.tanwei.fetchFreeProxies(80);
      setPool(res.pool);
      setPoolNotice(
        res.added
          ? `公开源抓到 ${res.fetched} 条，新入库 ${res.added} 条`
          : `公开源抓到 ${res.fetched} 条，池里都已经有了`,
      );
    });

  const testPool = () =>
    poolTask("test", async () => {
      const next = await window.tanwei.testProxies();
      setPool(next);
      const ok = next.entries.filter((e) => e.health === "ok").length;
      setPoolNotice(`测活完成：${ok} 条可用 / 池里共 ${next.entries.length} 条`);
    });

  const toggleEntry = (entry: ProxyEntry) =>
    poolTask(`entry-${entry.id}`, async () => {
      setPool(await window.tanwei.enableProxy(entry.id, !entry.enabled));
    });

  const pickEntry = (entry: ProxyEntry) =>
    poolTask(`entry-${entry.id}`, async () => {
      setPool(await window.tanwei.setPoolActive(entry.id));
    });

  const dropEntry = (entry: ProxyEntry) =>
    poolTask(`entry-${entry.id}`, async () => {
      setPool(await window.tanwei.removeProxies([entry.id]));
    });

  const toggleRotate = () =>
    poolTask("rotate", async () => {
      setPool(await window.tanwei.setPoolRotate(!pool?.rotate));
    });

  const clearPool = () =>
    poolTask("clear", async () => {
      setPool(await window.tanwei.clearPool());
      setPoolNotice("代理池已清空");
      setClearArmed(false);
    });

  const installFolder = async () => {
    setInstallBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      const res = await window.tanwei.installSkillFolder();
      if (!res.canceled) {
        setSkills(res.skills);
        setNotice(
          `已安装 ${res.installed.length} 个技能：${res.installed
            .map((p) => p.split(/[\\/]/).filter(Boolean).pop())
            .join("、")}`,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setInstallBusy(false);
    }
  };

  const installZip = async () => {
    setInstallBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      const res = await window.tanwei.installSkillZip();
      if (!res.canceled) {
        setSkills(res.skills);
        setNotice(
          `已从压缩包安装 ${res.installed.length} 个技能：${res.installed
            .map((p) => p.split(/[\\/]/).filter(Boolean).pop())
            .join("、")}`,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setInstallBusy(false);
    }
  };

  const createNewSkill = async () => {
    if (!newSkill.name.trim()) return;
    setInstallBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      setSkills(await window.tanwei.createSkill(newSkill));
      setNotice(`已创建技能 ${newSkill.name.trim()}，目录在 ~/.grok/skills 下`);
      setNewSkill({ name: "", description: "", body: "" });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setInstallBusy(false);
    }
  };

  const toggleSkill = async (skill: SkillEntry) => {
    setBusySkill(skill.path);
    setError(undefined);
    try {
      const next = await window.tanwei.setSkillDisabled(skill.name, skill.path, !skill.disabled);
      // 只更新这一行的状态，保持列表位置不动（后端会把禁用项排到最后）
      setSkills((prev) =>
        prev.map((item) => {
          const fresh = next.find((n) => n.path === item.path);
          return fresh ? { ...item, disabled: fresh.disabled } : item;
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusySkill(undefined);
    }
  };

  const load = async (which: ModuleId) => {
    setLoading(true);
    setError(undefined);
    try {
      if (which === "reports") setReports(await window.tanwei.reports());
      if (which === "skills") setSkills(await window.tanwei.skills());
      if (which === "rules") setRules(await window.tanwei.rules());
      if (which === "mcp") setMcpList(await window.tanwei.mcp());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (["reports", "skills", "rules", "mcp"].includes(id)) void load(id);
    if (id === "settings") {
      void window.tanwei.startupLog().then(setStartup).catch(() => undefined);
      void window.tanwei.network().then(setNet).catch(() => undefined);
      void window.tanwei.pool().then(setPool).catch(() => undefined);
      void window.tanwei.browserSettings().then(setBrowser).catch(() => undefined);
    }
  }, [id]);

  const body = () => {
    if (id === "dashboard") {
      return (
        <Dashboard
          boot={boot}
          status={status}
          version={version}
          mcp={mcp}
          live={live}
          history={history}
          onOpenSession={onOpenSession}
          onCreateSession={onCreateSession}
          onModule={onModule}
        />
      );
    }
    return null;
  };

  const poolOk = (pool?.entries ?? []).filter((e) => e.health === "ok").length;
  const poolEnabled = (pool?.entries ?? []).filter((e) => e.enabled).length;
  const poolShown = (pool?.entries ?? []).filter((e) => (poolOnlyOk ? e.health === "ok" : true));
  const poolRows = poolShown.slice(0, 300);

  return (
    <div className="module-page">
      {!SELF_HEADED.includes(id) ? (
        <div className="module-head">
          <div>
            <Crumbs items={["作战台", "模块", def.label]} />
            <h1>
              <Icon name={def.icon} size={18} />
              <span>{def.label}</span>
            </h1>
            <p>{def.desc}</p>
          </div>
          <div className="module-actions">
            {id === "skills" ? (
              <button className="btn" onClick={() => setInstallOpen((v) => !v)}>
                <Icon name="plus" size={13} />
                <span>{installOpen ? "收起安装" : "安装技能"}</span>
              </button>
            ) : null}
            {["reports", "skills", "rules", "mcp"].includes(id) ? (
              <button className="btn ghost" onClick={() => void load(id)}>
                <Icon name="refresh" size={13} />
                <span>{loading ? "读取中…" : "刷新"}</span>
              </button>
            ) : null}
          </div>
        </div>
      ) : null}

      {error ? <div className="module-error">{error}</div> : null}

      {id === "models" ? <ModelsPanel boot={boot} /> : null}
      {body()}
      {id === "findings" ? <Findings onAsk={onAsk} sessionTasks={sessionTasks} activeId={activeId} /> : null}
      {id === "tasks" ? (
        <Tasks
          live={live}
          history={history}
          loadingId={loadingId}
          onOpenSession={onOpenSession}
          onCreateSession={onCreateSession}
        />
      ) : null}
      {id === "assets" ? <Assets onAsk={onAsk} sessionTasks={sessionTasks} activeId={activeId} /> : null}
      {id === "traffic" ? <Traffic activeId={activeId} live={live} /> : null}
      {id === "graph" ? <Graph onAsk={onAsk} live={live} activeId={activeId} /> : null}
      {id === "tools" ? <Tools commands={commands} mcp={mcp} /> : null}
      {id === "logs" ? <Logs /> : null}

      {id === "reports" ? (
        <div className="table">
          <div className="table-head">
            <span>报告标题</span>
            <span>任务</span>
            <span>大小</span>
            <span>更新时间</span>
          </div>
          {reports.length === 0 ? (
            <div className="module-empty">还没有正式报告。</div>
          ) : (
            reports.map((r) => (
              <button className="table-row" key={r.path} onClick={() => void window.tanwei.openPath(r.path)}>
                <span className="table-title">{r.title}</span>
                <span className="chip chip-ghost">{r.task}</span>
                <span className="mono subtle">{fmtSize(r.size)}</span>
                <span className="mono subtle">{fmtTime(r.updatedAt)}</span>
              </button>
            ))
          )}
        </div>
      ) : null}

      {id === "skills" ? (
        <div className="skill-wrap">
          {installOpen ? (
            <div className="skill-install">
              <div className="skill-install-row">
                <button className="skill-install-tile" onClick={() => void installFolder()} disabled={installBusy}>
                  <Icon name="folder" size={15} />
                  <span className="skill-install-title">从文件夹安装</span>
                  <span className="skill-install-sub">选一个含 SKILL.md 的目录</span>
                </button>
                <button className="skill-install-tile" onClick={() => void installZip()} disabled={installBusy}>
                  <Icon name="file" size={15} />
                  <span className="skill-install-title">从 ZIP 安装</span>
                  <span className="skill-install-sub">压缩包里带 SKILL.md 即可</span>
                </button>
                <button
                  className="skill-install-tile"
                  onClick={() => void window.tanwei.openSkillsDir()}
                  disabled={installBusy}
                >
                  <Icon name="external" size={15} />
                  <span className="skill-install-title">打开技能目录</span>
                  <span className="skill-install-sub">~/.grok/skills</span>
                </button>
              </div>
              <div className="skill-new">
                <input
                  className="input"
                  placeholder="新技能名，例如 java-audit"
                  value={newSkill.name}
                  onChange={(e) => setNewSkill((s) => ({ ...s, name: e.target.value }))}
                />
                <input
                  className="input"
                  placeholder="一句话说明（写进 frontmatter 的 description）"
                  value={newSkill.description}
                  onChange={(e) => setNewSkill((s) => ({ ...s, description: e.target.value }))}
                />
                <textarea
                  className="input skill-new-body"
                  placeholder="正文 Markdown，可留空自动生成模板"
                  value={newSkill.body}
                  onChange={(e) => setNewSkill((s) => ({ ...s, body: e.target.value }))}
                />
                <button
                  className="btn"
                  onClick={() => void createNewSkill()}
                  disabled={installBusy || !newSkill.name.trim()}
                >
                  <Icon name="check" size={13} />
                  <span>{installBusy ? "处理中…" : "创建技能"}</span>
                </button>
              </div>
            </div>
          ) : null}

          {notice ? <div className="skill-notice">{notice}</div> : null}

          <div className="table skill-table">
            <div className="table-head">
              <span>技能</span>
              <span>来源</span>
              <span>说明</span>
              <span>状态</span>
            </div>
            {skills.length === 0 ? (
              <div className="module-empty">没有扫描到技能包。</div>
            ) : (
              skills.map((s) => (
                <div className={`table-row skill-row${s.disabled ? " is-off" : ""}`} key={s.path}>
                  <span className="table-title mono">{s.name}</span>
                  <span className="chip chip-ghost">{s.source}</span>
                  <span className="table-desc">{s.description || "—"}</span>
                  <span className="skill-status">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={!s.disabled}
                      aria-label={`${s.disabled ? "启用" : "禁用"}技能 ${s.name}`}
                      className={`switch${s.disabled ? "" : " on"}`}
                      disabled={busySkill === s.path}
                      onClick={() => void toggleSkill(s)}
                    />
                    <span className="skill-state">{s.disabled ? "已禁用" : "已启用"}</span>
                    <button
                      type="button"
                      className="skill-open"
                      onClick={() => void window.tanwei.openPath(s.path)}
                    >
                      打开
                    </button>
                  </span>
                </div>
              ))
            )}
          </div>
          <p className="skill-hint">
            开关直接写入 ~/.grok/config.toml 的 [skills] disabled，改前自动备份为
            config.toml.tanwei.bak；禁用后不进系统提示、不可被调用，文件仍留在磁盘。切换对之后新建的会话生效，
            已在跑的会话如需立刻生效请重启引擎。
          </p>
        </div>
      ) : null}

      {id === "rules" ? (
        <div className="table">
          <div className="table-head">
            <span>规则</span>
            <span>文件</span>
            <span>规模</span>
            <span>操作</span>
          </div>
          {rules.length === 0 ? (
            <div className="module-empty">`~/.grok/rules` 下没有规则文件。</div>
          ) : (
            rules.map((r) => (
              <button className="table-row" key={r.path} onClick={() => void window.tanwei.openPath(r.path)}>
                <span className="table-title">{r.title || r.name}</span>
                <span className="mono subtle">{r.name}</span>
                <span className="mono subtle">{r.tokens ? `${r.tokens} 字` : "—"}</span>
                <span className="chip chip-ghost">打开</span>
              </button>
            ))
          )}
        </div>
      ) : null}

      {id === "mcp" ? (
        <McpPanel
          runtime={mcpList.length ? mcpList : mcp}
          onChanged={() => void load("mcp")}
          onToast={(kind, text) => setNotice(kind === "error" ? text : undefined)}
          onRestartEngine={async () => {
            setNotice(undefined);
            await window.tanwei.restartEngine();
          }}
        />
      ) : null}

      {id === "settings" ? (
        <div className="settings">
          <div className="card">
            <div className="card-top">
              <span className="card-title">引擎</span>
              <span className={`chip ${boot?.engine.status === "ready" ? "chip-on" : "chip-off"}`}>
                {boot?.engine.status ?? "未知"}
              </span>
            </div>
            <div className="kv"><span className="kv-k">grok.exe</span><span className="kv-v mono">{boot?.grokPath ?? "—"}</span></div>
            <div className="kv"><span className="kv-k">版本</span><span className="kv-v mono">{boot?.grokVersion ?? boot?.engine.version ?? "—"}</span></div>
            <div className="kv"><span className="kv-k">GROK_HOME</span><span className="kv-v mono">{boot?.grokHome ?? "—"}</span></div>
            <div className="kv"><span className="kv-k">config.toml</span><span className="kv-v mono">{boot?.configPath ?? "—"}</span></div>
            <div className="kv"><span className="kv-k">默认权限</span><span className="kv-v">{boot?.permissionMode ?? "—"}</span></div>
            <div className="kv"><span className="kv-k">平台</span><span className="kv-v mono">{boot?.platform ?? "—"}</span></div>
            <div className="kv">
              <span className="kv-k">兼容模式</span>
              <span className="kv-v">{startup?.safeMode ? "已开启（硬件加速关闭）" : "未开启"}</span>
            </div>
            <div className="card-actions">
              <button className="btn ghost sm" onClick={() => boot && void window.tanwei.openPath(boot.grokHome)}>
                <Icon name="folder" size={12} /><span>打开 .grok</span>
              </button>
              <button className="btn ghost sm" onClick={() => boot && void window.tanwei.openPath(boot.configPath)}>
                <Icon name="file" size={12} /><span>打开配置</span>
              </button>
              <button className="btn ghost sm" onClick={() => void window.tanwei.launchTui(boot?.cwd)}>
                <Icon name="terminal" size={12} /><span>原生 TUI</span>
              </button>
              <button className="btn ghost sm" onClick={onRefreshSessions}>
                <Icon name="refresh" size={12} /><span>刷新会话</span>
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-top">
              <span className="card-title">网络代理</span>
              <span className={`chip ${net?.effective ? "chip-on" : "chip-ghost"} mono`}>
                {net?.effective || "直连"}
              </span>
            </div>
            <div className="card-note">
              模型接口报 connect timed out 时先看这里。跟随系统会读取 Windows 的代理设置；手动填本机 Clash
              之类的地址，形如 http://127.0.0.1:7897。
            </div>
            {net ? (
              <>
                <div className="proxy-modes">
                  {PROXY_MODES.map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      className={`proxy-mode${net.proxyMode === m.id ? " on" : ""}`}
                      onClick={() => {
                        setNet({ ...net, proxyMode: m.id });
                        setNetNotice(undefined);
                      }}
                    >
                      <span className="proxy-mode-label">{m.label}</span>
                      <span className="proxy-mode-hint">{m.hint}</span>
                    </button>
                  ))}
                </div>
                {net.proxyMode === "manual" ? (
                  <input
                    className="input mono proxy-url"
                    placeholder="http://127.0.0.1:7897"
                    value={net.proxyUrl}
                    onChange={(e) => {
                      setNet({ ...net, proxyUrl: e.target.value });
                      setNetNotice(undefined);
                    }}
                  />
                ) : null}
                <div className="kv">
                  <span className="kv-k">系统代理</span>
                  <span className="kv-v mono">{net.systemProxy || "未检测到"}</span>
                </div>
                {net.proxyMode === "pool" ? (
                  <div className="kv">
                    <span className="kv-k">池里当前用</span>
                    <span className="kv-v mono">{net.poolActive || "池里还没有可用代理"}</span>
                  </div>
                ) : null}
                <div className="card-actions">
                  <button
                    className="btn sm"
                    onClick={() => void saveNetwork(true)}
                    disabled={netBusy}
                  >
                    <Icon name="check" size={12} />
                    <span>{netBusy ? "处理中…" : "保存并重启引擎"}</span>
                  </button>
                  <button className="btn ghost sm" onClick={() => void runProbe()} disabled={probeBusy}>
                    <Icon name="bolt" size={12} />
                    <span>{probeBusy ? "探测中…" : "测试连通性"}</span>
                  </button>
                </div>
                {netNotice ? <div className="card-note">{netNotice}</div> : null}
                {probe ? (
                  <div className={`probe ${probe.reachable ? "is-ok" : "is-bad"}`}>
                    <span className={`chip ${probe.reachable ? "chip-on" : "chip-off"}`}>
                      {probe.reachable ? `通 ${probe.status ?? ""}`.trim() : "不通"}
                    </span>
                    <span className="probe-url mono">{probe.url || "没有可探测的 base_url"}</span>
                    <span className="probe-res">
                      {probe.reachable ? `${probe.ms} ms · 代理 ${probe.proxy || "直连"}` : probe.error}
                    </span>
                  </div>
                ) : null}
              </>
            ) : (
              <div className="card-note">读取中…</div>
            )}
          </div>

          <div className="card">
            <div className="card-top">
              <span className="card-title">浏览器窗口</span>
              <span className="chip chip-ghost mono">
                {CHROME_MODES.find((m) => m.id === browser?.chromeMode)?.label ?? "读取中"}
              </span>
            </div>
            <div className="card-note">
              引擎启动时会按 MCP 配置拉起一个 Chrome 给 Playwright 用。以前它直接弹在桌面上，现在默认放到屏幕外：
              真浏览器、指纹和可见时一致，只是看不见窗口。无头更省内存，个别站点风控更容易识破；要盯着它干活就选显示。
              选好会自动保存，点「重启引擎生效」后按新设置拉起（重启会断开当前会话）。
            </div>
            {browser ? (
              <>
                <div className="browser-modes">
                  {CHROME_MODES.map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      className={`browser-mode${browser.chromeMode === m.id ? " on" : ""}`}
                      disabled={browserBusy}
                      onClick={() => void saveBrowser(m.id)}
                    >
                      <span className="browser-mode-label">{m.label}</span>
                      <span className="browser-mode-hint">{m.hint}</span>
                    </button>
                  ))}
                </div>
                <div className="card-actions">
                  <button className="btn sm" onClick={() => void restartForBrowser()} disabled={browserBusy}>
                    <Icon name="refresh" size={12} />
                    <span>{browserBusy ? "处理中…" : "重启引擎生效"}</span>
                  </button>
                </div>
                {browserNotice ? <div className="card-note browser-notice">{browserNotice}</div> : null}
              </>
            ) : (
              <div className="card-note">读取中…</div>
            )}
          </div>

          <div className="card">
            <div className="card-top">
              <span className="card-title">代理池</span>
              <span className={`chip ${poolOk ? "chip-on" : "chip-ghost"} mono`}>
                {pool ? `${poolOk} 可用 / ${pool.entries.length} 条` : "读取中"}
              </span>
            </div>
            <div className="card-note">
              付费代理配置文件和公开免费源都能进池。上面模式选「代理池」后，引擎冷启动会取池里选中的那条；勾了轮换就换下一条。测活打 http://www.gstatic.com/generate_204，只影响池里的状态。
            </div>
            <div className="pool-actions">
              <button className="btn sm" onClick={() => void importPoolFile()} disabled={!!poolBusy}>
                <Icon name="file" size={12} />
                <span>{poolBusy === "import" ? "导入中…" : "导入配置文件"}</span>
              </button>
              <button className="btn ghost sm" onClick={() => void fetchFree()} disabled={!!poolBusy}>
                <Icon name="bolt" size={12} />
                <span>{poolBusy === "free" ? "抓取中…" : "自动找免费代理"}</span>
              </button>
              <button className="btn ghost sm" onClick={() => void testPool()} disabled={!!poolBusy}>
                <Icon name="refresh" size={12} />
                <span>{poolBusy === "test" ? "测活中…" : "测活"}</span>
              </button>
              <label className="pool-rotate">
                <input
                  type="checkbox"
                  checked={!!pool?.rotate}
                  disabled={!!poolBusy}
                  onChange={() => void toggleRotate()}
                />
                <span>冷启动时轮换</span>
              </label>
            </div>
            <textarea
              className="pool-text mono"
              placeholder={"也能直接粘贴，一行一条：\nhttp://user:pass@1.2.3.4:8080\n1.2.3.4:1080\nsocks5://1.2.3.4:1080:user:pass"}
              value={poolText}
              onChange={(e) => setPoolText(e.target.value)}
              spellCheck={false}
            />
            <div className="pool-actions">
              <button
                className="btn ghost sm"
                onClick={() => void importPoolText()}
                disabled={!!poolBusy || !poolText.trim()}
              >
                <Icon name="plus" size={12} />
                <span>粘贴导入</span>
              </button>
              <label className="pool-rotate">
                <input
                  type="checkbox"
                  checked={poolOnlyOk}
                  onChange={(e) => setPoolOnlyOk(e.target.checked)}
                />
                <span>只看可用</span>
              </label>
              <span className="pool-stats">
                启用 {poolEnabled} 条 · 当前 {pool?.activeId ? "已选中" : "自动挑选"}
              </span>
              {pool?.entries.length ? (
                <button
                  className="btn danger sm"
                  onClick={() => {
                    if (!clearArmed) {
                      setClearArmed(true);
                      return;
                    }
                    void clearPool();
                  }}
                  disabled={!!poolBusy}
                >
                  <Icon name="close" size={12} />
                  <span>{poolBusy === "clear" ? "清空中…" : clearArmed ? "确认清空" : "清空"}</span>
                </button>
              ) : null}
            </div>
            {poolNotice ? <div className="card-note">{poolNotice}</div> : null}
            {poolError ? <div className="card-note pool-error">{poolError}</div> : null}
            {pool && pool.entries.length ? (
              <div className="pool-list">
                {poolRows.map((entry) => (
                  <div className={`pool-row${entry.enabled ? "" : " is-off"}`} key={entry.id}>
                    <span className={`pool-health h-${entry.health}`}>{poolHealth(entry)}</span>
                    <span className="pool-url mono" title={entry.label || entry.url}>
                      {entry.url.replace(/\/\/[^@/]+@/, "//***@")}
                    </span>
                    <span className="pool-src">{SOURCE_LABEL[entry.source] ?? entry.source}</span>
                    {entry.latencyMs ? <span className="pool-ms mono">{entry.latencyMs}ms</span> : null}
                    {pool.activeId === entry.id ? <span className="chip chip-on">当前</span> : null}
                    <span className="pool-row-actions">
                      <button
                        className="pool-mini"
                        onClick={() => void toggleEntry(entry)}
                        disabled={!!poolBusy}
                      >
                        {entry.enabled ? "停用" : "启用"}
                      </button>
                      <button
                        className="pool-mini"
                        onClick={() => void pickEntry(entry)}
                        disabled={!!poolBusy}
                      >
                        选它
                      </button>
                      <button
                        className="pool-mini danger"
                        onClick={() => void dropEntry(entry)}
                        disabled={!!poolBusy}
                      >
                        删除
                      </button>
                    </span>
                  </div>
                ))}
                {poolShown.length > poolRows.length ? (
                  <div className="card-note">只显示前 {poolRows.length} 条，池里还有 {poolShown.length - poolRows.length} 条。</div>
                ) : null}
                {!poolShown.length ? <div className="card-note">没有可用代理，先测活或者换批源。</div> : null}
              </div>
            ) : (
              <div className="card-note">
                池是空的。导入你的付费代理配置文件，或者点「自动找免费代理」抓一批公开源。
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-top">
              <span className="card-title">启动诊断</span>
              <span className="chip chip-ghost mono">tanwei-startup.log</span>
            </div>
            <div className="card-note">
              窗口不出现或启动异常时，先看这里的日志。虚拟机、远程桌面或显卡驱动异常导致窗口不显示时，用兼容模式重启。
            </div>
            <pre className="startup-log mono">{startup?.text?.trim() || "（还没有日志）"}</pre>
            <div className="card-actions">
              <button className="btn ghost sm" onClick={() => startup && void window.tanwei.openPath(startup.path)}>
                <Icon name="file" size={12} /><span>打开日志</span>
              </button>
              <button className="btn ghost sm" onClick={() => void window.tanwei.startupLog().then(setStartup)}>
                <Icon name="refresh" size={12} /><span>刷新日志</span>
              </button>
              <button className="btn primary sm" onClick={() => void window.tanwei.relaunchSafe()}>
                <Icon name="bolt" size={12} /><span>兼容模式重启</span>
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-top">
              <span className="card-title">路径</span>
            </div>
            <div className="kv"><span className="kv-k">工作目录</span><span className="kv-v mono">{boot?.cwd ?? "—"}</span></div>
            <div className="kv"><span className="kv-k">用户目录</span><span className="kv-v mono">{boot?.home ?? "—"}</span></div>
            <div className="card-note">
              该控制台通过 ACP（agent client protocol）驱动 `grok agent --no-leader stdio`，与原生 TUI 共用同一套配置、会话、技能与 MCP。
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
