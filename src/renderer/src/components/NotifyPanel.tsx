import React, { useEffect, useMemo, useState } from "react";
import type {
  FindingSeverity,
  NotifyChannel,
  NotifyConfig,
  NotifyEvent,
  NotifyKind,
  RiskSignal,
} from "@shared/types";
import { Icon } from "./Icons";

const KIND_LABEL: Record<NotifyKind, string> = {
  dingtalk: "钉钉",
  feishu: "飞书",
  webhook: "自定义 Webhook",
};

const KIND_HINT: Record<NotifyKind, string> = {
  dingtalk: "群机器人 webhook，地址里带 access_token；开了加签就把 sec 开头那串密钥填进「签名密钥」",
  feishu: "群自定义机器人 webhook（…/open-apis/bot/v2/hook/…）；开了签名校验就填密钥",
  webhook: "任意 HTTP 接口，按 POST JSON 发 { text, title, event, at }",
};

const EVENT_LABEL: Record<NotifyEvent, string> = {
  finding: "新报告落盘",
  ban: "被目标封禁",
  proxy: "代理自动轮换",
  session: "会话结束",
};

/** 渠道事件里给用户看的叫法（与主进程消息一致） */
const EVENT_HINT: Record<NotifyEvent, string> = {
  finding: "每 45 秒对一次任务夹，新报告按等级推",
  ban: "测试被限流 / 人机验证 / WAF 拦住 / IP 封禁时立刻推",
  proxy: "定时轮换出口时推",
  session: "一轮任务跑完时推",
};

const SEVERITIES: FindingSeverity[] = ["严重", "高危", "中危", "低危"];

const ALL_EVENTS: NotifyEvent[] = ["finding", "ban", "proxy", "session"];

function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, "");
}

function maskUrl(url: string): string {
  if (url.length <= 42) return url;
  return `${url.slice(0, 30)}…${url.slice(-10)}`;
}

function fmtTime(t?: number): string {
  if (!t) return "未测";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

interface Draft {
  id?: string;
  kind: NotifyKind;
  name: string;
  url: string;
  secret: string;
  events: NotifyEvent[];
  enabled: boolean;
}

function blankDraft(kind: NotifyKind = "dingtalk"): Draft {
  return { kind, name: "", url: "", secret: "", events: ["finding", "ban"], enabled: true };
}

function draftOf(channel: NotifyChannel): Draft {
  return {
    id: channel.id,
    kind: channel.kind,
    name: channel.name,
    url: channel.url,
    secret: channel.secret ?? "",
    events: channel.events.length ? channel.events : ["finding"],
    enabled: channel.enabled,
  };
}

/** 告警：钉钉 / 飞书 / 自定义 webhook，配置完能当场发一条测试 */
export function NotifyPanel() {
  const [cfg, setCfg] = useState<NotifyConfig | undefined>();
  const [cfgPath, setCfgPath] = useState("");
  const [draft, setDraft] = useState<Draft | undefined>();
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [tests, setTests] = useState<Record<string, { ok: boolean; text: string }>>({});
  const [drillNote, setDrillNote] = useState<{ ok: boolean; text: string } | undefined>();
  const [risk, setRisk] = useState<RiskSignal | undefined>();

  // 主进程认出风控就把这条推过来，面板上先亮一条，不用等飞书回执
  useEffect(
    () =>
      window.tanwei.onRiskEvent((sig) => {
        setRisk(sig);
        // 投递记录是发完才落盘的，稍等一下再读回来
        window.setTimeout(() => void reload(), 1600);
      }),
    [],
  );

  useEffect(() => {
    let alive = true;
    void window.tanwei
      .notifyConfig()
      .then((next) => {
        if (!alive) return;
        setCfg(next);
        // 一个渠道都没有时直接把新建表单摊开，省得还要先点一下「新增渠道」
        if (next.channels.length === 0) setDraft(blankDraft());
      })
      .catch((err) => {
        if (alive) setError(errText(err));
      });
    void window.tanwei
      .notifyPath()
      .then((p) => {
        if (alive) setCfgPath(p);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  const channels = cfg?.channels ?? [];

  const recent = cfg?.recent ?? [];

  async function reload() {
    const next = await window.tanwei.notifyConfig().catch(() => undefined);
    if (next) setCfg(next);
  }

  const enabledCount = useMemo(() => channels.filter((c) => c.enabled).length, [channels]);

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

  async function saveDraft(thenTest: boolean) {
    if (!draft) return;
    if (!draft.url.trim()) {
      setError("先填 webhook 地址");
      return;
    }
    const saved = await run("save", () =>
      window.tanwei.saveNotifyChannel({
        id: draft.id,
        kind: draft.kind,
        name: draft.name.trim() || undefined,
        url: draft.url.trim(),
        secret: draft.secret.trim() || undefined,
        events: draft.events,
        enabled: draft.enabled,
      }),
    );
    if (!saved) return;
    setCfg(saved);
    const target = saved.channels.find((c) => (draft.id ? c.id === draft.id : c.url === draft.url.trim()));
    setNotice("已保存");
    if (thenTest && target) {
      setDraft(undefined);
      await testChannel(target.id);
      return;
    }
    setDraft(undefined);
  }

  async function testChannel(id: string) {
    const res = await run(`test-${id}`, () => window.tanwei.testNotify({ id }));
    if (!res) return;
    setTests((prev) => ({
      ...prev,
      [id]: { ok: res.ok, text: res.ok ? `通了 · ${res.ms} ms` : `${res.ms} ms · ${res.error ?? "失败"}` },
    }));
    const next = await window.tanwei.notifyConfig().catch(() => undefined);
    if (next) setCfg(next);
  }

  async function testDraft() {
    if (!draft) return;
    if (!draft.url.trim()) {
      setError("先填 webhook 地址");
      return;
    }
    const res = await run("test-draft", () =>
      window.tanwei.testNotify({
        kind: draft.kind,
        url: draft.url.trim(),
        secret: draft.secret.trim() || undefined,
      }),
    );
    if (!res) return;
    setTests((prev) => ({
      ...prev,
      draft: { ok: res.ok, text: res.ok ? `通了 · ${res.ms} ms` : `${res.ms} ms · ${res.error ?? "失败"}` },
    }));
  }

  /** 演练：走跟真实风控告警完全一样的过滤链路，用来分辨「勾选没生效」和「webhook 发不出去」 */
  async function drill() {
    const res = await run("drill", () => window.tanwei.drillNotify("ban"));
    if (!res) return;
    const ok = res.results.filter((r) => r.ok).map((r) => `${r.channel} ${r.ms} ms`);
    const bad = res.results.filter((r) => !r.ok).map((r) => `${r.channel}：${r.error ?? "失败"}`);
    const text = res.passed
      ? `已发出 → ${ok.join("，")}${bad.length ? `（失败：${bad.join("，")}）` : ""}`
      : `没发出去 → ${res.reason ?? (bad.length ? bad.join("；") : "没有可用渠道")}`;
    setDrillNote({ ok: res.passed, text });
    const next = await window.tanwei.notifyConfig().catch(() => undefined);
    if (next) setCfg(next);
  }

  async function remove(id: string) {
    const next = await run(`del-${id}`, () => window.tanwei.removeNotifyChannel(id));
    if (next) {
      setCfg(next);
      setNotice("渠道已删除");
    }
  }

  async function toggleEnabled(channel: NotifyChannel) {
    const next = await run(`en-${channel.id}`, () =>
      window.tanwei.saveNotifyChannel({ ...channel, enabled: !channel.enabled }),
    );
    if (next) setCfg(next);
  }

  async function setOption(patch: Partial<NotifyConfig>) {
    const next = await run("opt", () => window.tanwei.setNotifyOptions(patch));
    if (next) setCfg(next);
  }

  function toggleEvent(id: string, event: NotifyEvent) {
    if (!cfg) return;
    const channel = cfg.channels.find((c) => c.id === id);
    if (!channel) return;
    const events = channel.events.includes(event)
      ? channel.events.filter((e) => e !== event)
      : [...channel.events, event];
    void run(`ev-${id}`, () =>
      window.tanwei.saveNotifyChannel({ ...channel, events: events.length ? events : channel.events }),
    ).then((next) => {
      if (next) setCfg(next);
    });
  }

  return (
    <div className="notify-page">
      <div className="card">
        <div className="card-top">
          <span className="card-title">推什么</span>
          <div className="notify-head-ops">
            <span className={`chip ${enabledCount ? "chip-on" : "chip-ghost"} mono`}>
              {enabledCount} 个渠道在推 / 共 {channels.length}
            </span>
            <button className="btn sm ghost" onClick={() => void drill()} disabled={!!busy}>
              <Icon name="bolt" size={12} />
              <span>{busy === "drill" ? "发送中…" : "演练一条"}</span>
            </button>
          </div>
        </div>
        <div className="card-note">
          报告落盘由后台每 45 秒对一次任务夹，新出现的正式报告按等级推。测试跑起来之后，工具输出或引擎报错里出现限流（429）、人机验证、WAF 拦截、IP / 账号被封禁的迹象，会自动认出来按「封禁 / 风控」推一条，不用你先去代理池点「记失败」。
        </div>

        <div className="notify-switches">
          <label className="notify-switch" title={EVENT_HINT.finding}>
            <input
              type="checkbox"
              checked={cfg?.onFinding ?? true}
              disabled={!cfg || !!busy}
              onChange={(e) => void setOption({ onFinding: e.target.checked })}
            />
            <span>新报告落盘就推</span>
          </label>
          <label className="notify-switch" title={EVENT_HINT.ban}>
            <input
              type="checkbox"
              checked={cfg?.onBan ?? true}
              disabled={!cfg || !!busy}
              onChange={(e) => void setOption({ onBan: e.target.checked })}
            />
            <span>被封禁 / 风控时推</span>
          </label>
          <label className="notify-switch" title={EVENT_HINT.proxy}>
            <input
              type="checkbox"
              checked={cfg?.onProxy ?? false}
              disabled={!cfg || !!busy}
              onChange={(e) => void setOption({ onProxy: e.target.checked })}
            />
            <span>定时轮换也推</span>
          </label>
          <label className="notify-switch">
            <span>只推这档及以上</span>
            <select
              className="select sm"
              value={cfg?.minSeverity ?? "中危"}
              disabled={!cfg || !!busy}
              onChange={(e) => void setOption({ minSeverity: e.target.value as FindingSeverity })}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="notify-path mono" title={cfgPath}>
          {cfgPath ? `配置：${cfgPath}` : "配置：userData/notify.json"}
        </div>

        {drillNote ? (
          <div className={`notify-drill ${drillNote.ok ? "ok" : "bad"}`}>{drillNote.text}</div>
        ) : null}

        {risk ? (
          <div className="notify-risk">
            <Icon name="shield" size={14} />
            <div className="notify-risk-body">
              <div className="notify-risk-head">
                <b>{risk.category}</b>
                <span className="mono">{new Date(risk.at).toLocaleTimeString("zh-CN")}</span>
                {risk.target ? <span className="mono notify-risk-target">{risk.target}</span> : null}
              </div>
              <div className="notify-risk-ev mono">{risk.evidence}</div>
            </div>
            <button className="btn ghost sm" onClick={() => setRisk(undefined)} title="收起">
              <Icon name="close" size={12} />
            </button>
          </div>
        ) : null}

        <div className="notify-recent">
          <div className="notify-recent-head">
            <span className="kv-k">最近告警</span>
            <span className="notify-recent-note">最近 20 次投递，发失败的、被开关或订阅挡掉的都记在这里</span>
          </div>
          {recent.length === 0 ? (
            <div className="notify-recent-empty">还没有记录。点右上「演练一条」，它会按你现在勾的开关走一遍真实链路。</div>
          ) : (
            recent.map((row, i) => (
              <div key={`${row.at}-${i}`} className={`notify-recent-row${row.ok ? "" : " is-bad"}`}>
                <span className="mono notify-recent-time">{fmtTime(row.at)}</span>
                <span className="notify-recent-ev">{EVENT_LABEL[row.event]}</span>
                <span className="notify-recent-title" title={row.title}>
                  {row.title}
                </span>
                <span className={`notify-recent-state ${row.ok ? "ok" : "bad"}`}>
                  {row.ok ? `已发 ${row.channels}` : row.error ?? "未发出"}
                </span>
              </div>
            ))
          )}
        </div>

        {notice ? <div className="pool-stats">{notice}</div> : null}
        {error ? <div className="pool-stats pool-error">{error}</div> : null}
      </div>

      <div className="card">
        <div className="card-top">
          <span className="card-title">通知渠道</span>
          <div className="notify-head-ops">
            <button className="btn sm" onClick={() => setDraft(blankDraft())} disabled={!!busy}>
              <Icon name="plus" size={12} />
              <span>加渠道</span>
            </button>
          </div>
        </div>
        <div className="card-note">
          钉钉和飞书回 HTTP 200 也算失败，这里会读回包里的 errcode / code 判真假，所以「测试」显示通了才是真通。
        </div>

        {draft ? (
          <div className="notify-editor">
            <div className="notify-editor-head">
              <span className="card-title">{draft.id ? "编辑渠道" : "新渠道"}</span>
              <button className="btn ghost sm" onClick={() => setDraft(undefined)}>
                <Icon name="close" size={12} />
                <span>取消</span>
              </button>
            </div>
            <div className="notify-form">
              <div className="notify-form-row">
                <span className="kv-k">类型</span>
                <div className="seg">
                  {(Object.keys(KIND_LABEL) as NotifyKind[]).map((k) => (
                    <button
                      key={k}
                      className={`seg-btn ${draft.kind === k ? "on" : ""}`}
                      onClick={() => setDraft({ ...draft, kind: k })}
                    >
                      {KIND_LABEL[k]}
                    </button>
                  ))}
                </div>
              </div>
              <div className="notify-form-row">
                <span className="kv-k">名字</span>
                <input
                  className="input"
                  value={draft.name}
                  placeholder={KIND_LABEL[draft.kind] + "机器人"}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                  spellCheck={false}
                />
              </div>
              <div className="notify-form-row">
                <span className="kv-k">Webhook</span>
                <input
                  className="input mono"
                  value={draft.url}
                  placeholder={
                    draft.kind === "dingtalk"
                      ? "https://oapi.dingtalk.com/robot/send?access_token=…"
                      : draft.kind === "feishu"
                        ? "https://open.feishu.cn/open-apis/bot/v2/hook/…"
                        : "https://你的接口/notify"
                  }
                  onChange={(e) => setDraft({ ...draft, url: e.target.value })}
                  spellCheck={false}
                />
              </div>
              <div className="notify-form-row">
                <span className="kv-k">签名密钥</span>
                <input
                  className="input mono"
                  value={draft.secret}
                  placeholder={draft.kind === "dingtalk" ? "SEC… （可选，开了加签才要）" : "可选"}
                  onChange={(e) => setDraft({ ...draft, secret: e.target.value })}
                  spellCheck={false}
                />
              </div>
              <div className="notify-form-row">
                <span className="kv-k">推这些</span>
                <div className="notify-events">
                  {ALL_EVENTS.map((ev) => (
                    <label key={ev} className="notify-switch">
                      <input
                        type="checkbox"
                        checked={draft.events.includes(ev)}
                        onChange={(e) =>
                          setDraft({
                            ...draft,
                            events: e.target.checked
                              ? [...draft.events, ev]
                              : draft.events.filter((x) => x !== ev),
                          })
                        }
                      />
                      <span>{EVENT_LABEL[ev]}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div className="notify-form-note">{KIND_HINT[draft.kind]}</div>
              {tests.draft ? (
                <div className={`notify-test ${tests.draft.ok ? "ok" : "bad"}`}>{tests.draft.text}</div>
              ) : null}
              <div className="notify-form-ops">
                <button className="btn sm ghost" onClick={() => void testDraft()} disabled={!!busy}>
                  <Icon name="bell" size={12} />
                  <span>{busy === "test-draft" ? "发送中…" : "测试这条"}</span>
                </button>
                <button className="btn sm" onClick={() => void saveDraft(false)} disabled={!!busy}>
                  <Icon name="check" size={12} />
                  <span>保存</span>
                </button>
                <button className="btn sm primary" onClick={() => void saveDraft(true)} disabled={!!busy}>
                  <Icon name="send" size={12} />
                  <span>{busy === "save" ? "处理中…" : "保存并测试"}</span>
                </button>
              </div>
            </div>
          </div>
        ) : null}

        {channels.length === 0 && !draft ? (
          <div className="module-empty">
            还没有渠道。加一个钉钉群机器人，填 webhook 地址就能收报告提醒；飞书同理，自定义接口按 POST JSON 也能接。
          </div>
        ) : null}

        <div className="notify-list">
          {channels.map((c) => {
            const result = tests[c.id];
            return (
              <div key={c.id} className={`notify-row${c.enabled ? "" : " is-off"}`}>
                <div className="notify-row-main">
                  <span className={`notify-kind k-${c.kind}`}>{KIND_LABEL[c.kind]}</span>
                  <div className="notify-row-text">
                    <div className="notify-row-name">
                      {c.name}
                      {c.lastTestOk === false ? <span className="notify-badge bad">上次失败</span> : null}
                      {c.lastTestOk === true ? <span className="notify-badge ok">可用</span> : null}
                    </div>
                    <div className="notify-row-url mono" title={c.url}>
                      {maskUrl(c.url)}
                    </div>
                  </div>
                  <div className="notify-row-events">
                    {c.events.map((ev) => (
                      <button
                        key={ev}
                        className="notify-ev on"
                        onClick={() => toggleEvent(c.id, ev)}
                        title="点一下取消这个事件"
                      >
                        {EVENT_LABEL[ev]}
                      </button>
                    ))}
                    {ALL_EVENTS.filter((ev) => !c.events.includes(ev)).map((ev) => (
                      <button
                        key={ev}
                        className="notify-ev"
                        onClick={() => toggleEvent(c.id, ev)}
                        title="点一下加上这个事件"
                      >
                        {EVENT_LABEL[ev]}
                      </button>
                    ))}
                  </div>
                  <div className="notify-row-meta mono">
                    {c.sent ? `已发 ${c.sent}` : "未发过"} · 测试 {fmtTime(c.lastTestAt)}
                  </div>
                  {result ? <div className={`notify-test ${result.ok ? "ok" : "bad"}`}>{result.text}</div> : null}
                  {!result && c.lastError ? <div className="notify-test bad">{c.lastError}</div> : null}
                </div>
                <div className="notify-row-ops">
                  <button className="btn sm ghost" onClick={() => void testChannel(c.id)} disabled={!!busy}>
                    <Icon name="bell" size={12} />
                    <span>{busy === `test-${c.id}` ? "发送中…" : "测试"}</span>
                  </button>
                  <button className="btn sm ghost" onClick={() => setDraft(draftOf(c))} disabled={!!busy}>
                    <Icon name="settings" size={12} />
                    <span>编辑</span>
                  </button>
                  <label className="pool-rotate">
                    <input
                      type="checkbox"
                      checked={c.enabled}
                      onChange={() => void toggleEnabled(c)}
                      disabled={!!busy}
                    />
                    <span>启用</span>
                  </label>
                  <button className="btn sm danger" onClick={() => void remove(c.id)} disabled={!!busy}>
                    <Icon name="close" size={12} />
                    <span>删除</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
