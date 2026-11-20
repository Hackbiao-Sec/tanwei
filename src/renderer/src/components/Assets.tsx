import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AssetCatalog, AssetHostGroup, AssetKind, AssetRecord } from "@shared/types";
import { Icon } from "./Icons";
import { FileViewer, type PreviewTarget } from "./FileViewer";
import { ScopeSwitch } from "./ScopeSwitch";
import { copyText } from "../lib/clipboard";
import { useSessionScope } from "../lib/sessionScope";

const KIND_LABEL: Record<AssetKind, string> = {
  endpoint: "接口",
  domain: "域名",
  ip: "IP",
  service: "服务",
};

const KIND_ORDER: AssetKind[] = ["endpoint", "domain", "ip", "service"];

function fmtTime(t: number): string {
  if (!t) return "—";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function totalOf(c: AssetHostGroup["counts"]): number {
  return c.endpoint + c.domain + c.ip + c.service;
}

function recordText(r: AssetRecord): string {
  if (r.kind === "endpoint") return `${r.method ? `${r.method.toUpperCase()} ` : ""}${r.path ?? r.value}`;
  return r.value;
}

/** 四类资产各占一段色带，宽度按条数占比 */
function KindBar({
  counts,
  className,
  only,
}: {
  counts: AssetHostGroup["counts"];
  className: string;
  only?: AssetKind | "all";
}) {
  const kinds = KIND_ORDER.filter((k) => counts[k] > 0 && (!only || only === "all" || only === k));
  if (!kinds.length) return null;
  return (
    <span className={className} aria-hidden="true">
      {kinds.map((k) => (
        <span key={k} className={`k-${k}`} style={{ flexGrow: counts[k] }} />
      ))}
    </span>
  );
}

const EMPTY_CATALOG: AssetCatalog = {
  records: [],
  hosts: [],
  tasks: [],
  totals: { endpoint: 0, domain: 0, ip: 0, service: 0, total: 0, hosts: 0, tasks: 0 },
  files: [],
};

export function Assets({ onAsk }: { onAsk: (prompt: string) => void }) {
  const ctx = useSessionScope();
  const [own, setOwn] = useState<AssetCatalog>(EMPTY_CATALOG);
  const [all, setAll] = useState<AssetCatalog>();
  const [scope, setScope] = useState<"session" | "all">("session");
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<AssetKind | "all">("all");
  const [task, setTask] = useState("全部");
  const [picked, setPicked] = useState<string>();
  const [preview, setPreview] = useState<PreviewTarget | null>(null);
  const [copied, setCopied] = useState("");
  const [allBusy, setAllBusy] = useState(false);
  const [error, setError] = useState<string>();

  const resolvedTasks = ctx.tasks;
  const loading = ctx.loading || allBusy;
  const allSeq = useRef(0);
  const allAt = useRef(0);

  const loadAll = useCallback(
    async (force = false) => {
      if (!force && all && Date.now() - allAt.current < 15_000) return;
      const mine = ++allSeq.current;
      setAllBusy(true);
      try {
        const next = await window.tanwei.assetCatalog();
        if (mine !== allSeq.current) return;
        setAll(next);
        allAt.current = Date.now();
      } catch (err) {
        if (mine === allSeq.current) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (mine === allSeq.current) setAllBusy(false);
      }
    },
    [all],
  );

  // 本会话的资产用会话快照里的任务夹去取；总览另取一份，不互相顶替
  useEffect(() => {
    let alive = true;
    if (!resolvedTasks.length) {
      setOwn(EMPTY_CATALOG);
      return;
    }
    void window.tanwei
      .assetCatalog(resolvedTasks)
      .then((next) => {
        if (alive) setOwn(next ?? EMPTY_CATALOG);
      })
      .catch((err) => {
        if (alive) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      alive = false;
    };
  }, [resolvedTasks.join("|")]);

  useEffect(() => {
    // 总览是整桌面的资产表（上万条），本会话档位不读它；只有切到总览才扫
    if (scope !== "all") return;
    if (all && Date.now() - allAt.current < 15_000) return;
    void loadAll();
  }, [scope, all, loadAll, ctx.version]);

  const load = () => {
    ctx.refresh();
    void loadAll(true);
  };

  const catalog = scope === "session" ? own : all;
  const hosts = catalog?.hosts ?? [];
  const totals = catalog?.totals;

  const taskNames = useMemo(() => catalog?.tasks ?? [], [catalog]);

  useEffect(() => {
    if (task !== "全部" && !taskNames.includes(task)) setTask("全部");
  }, [taskNames, task]);

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    return hosts
      .filter((h) => {
        if (task !== "全部" && h.task !== task) return false;
        if (kind !== "all" && h.counts[kind] === 0) return false;
        if (!q) return true;
        if (h.host.toLowerCase().includes(q)) return true;
        return h.records.some((r) => r.value.toLowerCase().includes(q) || (r.path ?? "").toLowerCase().includes(q));
      })
      .sort((a, b) => totalOf(b.counts) - totalOf(a.counts) || a.host.localeCompare(b.host));
  }, [hosts, query, kind, task]);

  const current = groups.find((g) => g.host === picked) ?? groups[0];

  useEffect(() => {
    if (groups.length && !groups.some((g) => g.host === picked)) setPicked(groups[0].host);
  }, [groups, picked]);

  /** 任务胶囊上挂的主机数，点一下按任务收窄 */
  const taskPills = useMemo(
    () =>
      taskNames
        .map((name) => ({ name, count: hosts.filter((h) => h.task === name).length }))
        .filter((t) => t.count > 0)
        .sort((a, b) => b.count - a.count),
    [taskNames, hosts],
  );

  /** 当前筛选下真正落在右侧的条数 */
  const shownRecords = useMemo(
    () =>
      groups.reduce(
        (n, g) =>
          n +
          (kind === "all"
            ? totalOf(g.counts)
            : g.records.filter((r) => r.kind === kind).length),
        0,
      ),
    [groups, kind],
  );

  const fileOf = (record: AssetRecord) => catalog?.files.find((f) => f.path === record.file);

  const askHost = (group: AssetHostGroup) => {
    const lines = KIND_ORDER.map((k) => {
      const items = group.records.filter((r) => r.kind === k).slice(0, 30).map(recordText);
      return items.length ? `${KIND_LABEL[k]}：\n${items.join("\n")}` : "";
    }).filter(Boolean);
    onAsk(
      [
        `以这台主机为范围继续挖：${group.host}`,
        `任务夹：${group.task}`,
        lines.join("\n\n"),
        "先建接口清单再打：未登录面、换 id、注入 / SSRF / XSS / RCE 有入口就跟到执行，打到就落报告。",
      ].join("\n\n"),
    );
  };

  const askRecord = (record: AssetRecord) => {
    const target = record.kind === "endpoint"
      ? `${record.method ? `${record.method.toUpperCase()} ` : ""}${record.host}${record.path ?? ""}`
      : record.value;
    onAsk(
      [
        `从资产清单里挑这一条继续打：${target}`,
        `出处：${record.file}:${record.line}（任务 ${record.task}）`,
        "先摸清返回结构再做基线，然后过未授权、换 id 和四件套，别停在能看。",
      ].join("\n\n"),
    );
  };

  return (
    <div className="assets-page">
      <div className="asset-filter">
        <div className="asset-filter-row">
          <div className="search find-search">
            <Icon name="search" size={13} />
            <input
              value={query}
              placeholder="搜主机 / 域名 / 接口路径"
              onChange={(e) => setQuery(e.target.value)}
            />
            {query ? (
              <button className="icon-btn tiny" onClick={() => setQuery("")} title="清空搜索">
                <Icon name="close" size={11} />
              </button>
            ) : null}
          </div>
          <ScopeSwitch
            tasks={resolvedTasks}
            scope={scope}
            onScope={setScope}
            total={all ? (all.totals.hosts ?? 0) + (all.totals.endpoint ?? 0) : undefined}
            scoped={(own?.totals.hosts ?? 0) + (own?.totals.endpoint ?? 0)}
          />
          <button className="btn ghost sm" onClick={load}>
            <Icon name="refresh" size={12} />
            <span>{loading ? "读取中…" : "刷新"}</span>
          </button>
        </div>

        <div className="asset-filter-row asset-kinds-row">
          <div className="asset-kinds">
            <button
              className={`asset-kind k-all ${kind === "all" ? "on" : ""}`}
              onClick={() => setKind("all")}
            >
              <span className="ak-dot" />
              <span className="ak-label">全部</span>
              <span className="ak-count">{totals?.total ?? 0}</span>
            </button>
            {KIND_ORDER.map((k) => (
              <button
                key={k}
                className={`asset-kind k-${k} ${kind === k ? "on" : ""}`}
                onClick={() => setKind(kind === k ? "all" : k)}
                title={`只看${KIND_LABEL[k]}（再点一次取消）`}
              >
                <span className="ak-dot" />
                <span className="ak-label">{KIND_LABEL[k]}</span>
                <span className="ak-count">{totals?.[k] ?? 0}</span>
              </button>
            ))}
          </div>
          <div className="asset-result">
            筛出 <b>{groups.length}</b> 台主机 · <b>{shownRecords}</b> 条记录
          </div>
        </div>

        {taskPills.length > 1 ? (
          <div className="asset-tasks">
            <span className="asset-tasks-label">任务</span>
            <button className={`asset-task ${task === "全部" ? "on" : ""}`} onClick={() => setTask("全部")}>
              <span className="at-name">全部</span>
              <span className="at-count">{hosts.length}</span>
            </button>
            {taskPills.map((t) => (
              <button
                key={t.name}
                className={`asset-task ${task === t.name ? "on" : ""}`}
                onClick={() => setTask(task === t.name ? "全部" : t.name)}
                title={t.name}
              >
                <span className="at-name">{t.name}</span>
                <span className="at-count">{t.count}</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>

      {error ? <div className="module-error">{error}</div> : null}

      {groups.length === 0 ? (
        <div className="module-empty">
          {loading
            ? "正在扫任务夹里的资产（域名 / IP / 接口），任务夹多时要等两三秒…"
            : scope === "session"
              ? resolvedTasks.length === 0
                ? "这个会话还没认领任务夹。点上面「归属」把任务夹勾给它；看全桌面点「总览」。"
                : "本会话任务里还没扫出资产。资产清单落在任务夹的 `资产/` 里，写进去就会出现在这。"
              : "桌面还没有 `*_SRC挖洞` 任务夹，或任务夹的 `资产/` 里没有能认的域名 / IP / 接口。"}
        </div>
      ) : (
        <div className="asset-split">
          <div className="asset-hosts">
            <div className="asset-hosts-head">
              <span>主机</span>
              <span className="subtle">
                {groups.length} 台{kind === "all" ? "" : ` · 只看${KIND_LABEL[kind]}`}
              </span>
            </div>
            {groups.slice(0, 400).map((g) => (
              <button
                key={g.host}
                className={`asset-host${current?.host === g.host ? " on" : ""}`}
                onClick={() => setPicked(g.host)}
                title={`${g.task} · ${totalOf(g.counts)} 条`}
              >
                <span className="asset-host-main">
                  <span className="asset-host-name mono">{g.host}</span>
                  <KindBar counts={g.counts} className="asset-host-bar" only={kind} />
                  <span className="asset-host-sub">
                    {KIND_ORDER.filter((k) => g.counts[k] && (kind === "all" || kind === k))
                      .map((k) => `${KIND_LABEL[k]} ${g.counts[k]}`)
                      .join(" · ")}
                  </span>
                </span>
                <span className="asset-host-count">
                  {kind === "all" ? g.counts.endpoint || totalOf(g.counts) : g.counts[kind]}
                </span>
              </button>
            ))}
            {groups.length > 400 ? (
              <div className="asset-hosts-more">只列前 400 台，用搜索收窄。</div>
            ) : null}
          </div>

          {current ? (
            <div className="asset-detail">
              <div className="asset-detail-head">
                <div className="asset-detail-lead">
                  <div className="asset-detail-host mono">{current.host}</div>
                  <KindBar counts={current.counts} className="asset-breakdown" />
                  <div className="asset-detail-sub">
                    <span className="chip chip-ghost">{current.task}</span>
                    {KIND_ORDER.filter((k) => current.counts[k]).map((k) => (
                      <button
                        key={k}
                        className={`chip chip-ghost k-${k} ${kind === k ? "on" : ""}`}
                        onClick={() => setKind(kind === k ? "all" : k)}
                        title={`只看${KIND_LABEL[k]}`}
                      >
                        <span className="chip-dot" />
                        {KIND_LABEL[k]} {current.counts[k]}
                      </button>
                    ))}
                    <span className="subtle">更新 {fmtTime(current.updatedAt)}</span>
                  </div>
                </div>
                <div className="asset-detail-ops">
                  <button className="btn primary sm" onClick={() => askHost(current)}>
                    <Icon name="bolt" size={12} />
                    <span>以这台继续挖</span>
                  </button>
                </div>
              </div>

              {KIND_ORDER.filter((k) => current.counts[k] && (kind === "all" || kind === k)).map((k) => {
                const rows = current.records.filter((r) => r.kind === k);
                return (
                  <div className={`asset-group k-${k}`} key={k}>
                    <div className="asset-group-head">
                      <span className="ag-dot" />
                      <span className="ag-label">{KIND_LABEL[k]}</span>
                      <span className="subtle">{rows.length}</span>
                    </div>
                    {rows.slice(0, 300).map((r) => (
                      <div className="asset-item" key={r.id}>
                        <span className="asset-item-text mono" title={r.value}>
                          {recordText(r)}
                        </span>
                        <span className="asset-item-src">
                          {fileOf(r) ? (
                            <button
                              className="asset-link"
                              onClick={() =>
                                setPreview({
                                  path: r.file,
                                  name: fileOf(r)?.name,
                                })
                              }
                              title={`预览 ${r.file}`}
                            >
                              {fileOf(r)?.name} :{r.line}
                            </button>
                          ) : (
                            <span className="subtle">
                              {r.file.split(/[\\/]/).pop()}:{r.line}
                            </span>
                          )}
                        </span>
                        <span className="asset-item-ops">
                          <button
                            className="mini-btn"
                            title="复制"
                            onClick={() => {
                              void copyText(recordText(r));
                              setCopied(r.id);
                              window.setTimeout(() => setCopied(""), 1400);
                            }}
                          >
                            <Icon name={copied === r.id ? "check" : "copy"} size={11} />
                          </button>
                          <button className="mini-btn" title="让 AI 打这一条" onClick={() => askRecord(r)}>
                            <Icon name="bolt" size={11} />
                          </button>
                        </span>
                      </div>
                    ))}
                  </div>
                );
              })}

              <div className="asset-files">
                <div className="asset-group-head">
                  <span>来源清单</span>
                  <span className="subtle">{catalog?.files.length ?? 0} 份文件</span>
                </div>
                {(catalog?.files ?? [])
                  .filter((f) => current.records.some((r) => r.file === f.path))
                  .map((f) => (
                    <button
                      className="asset-file"
                      key={f.path}
                      onClick={() => setPreview({ path: f.path, name: f.name })}
                      title={f.path}
                    >
                      <Icon name="file" size={12} />
                      <span className="mono">{f.name}</span>
                      <span className="subtle">{f.entries} 条</span>
                    </button>
                  ))}
              </div>
            </div>
          ) : null}
        </div>
      )}

      <FileViewer file={preview} onClose={() => setPreview(null)} />
    </div>
  );
}
