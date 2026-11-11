import React, { useEffect, useRef, useState } from "react";
import type { SessionState } from "@shared/types";
import { Icon } from "./Icons";
import {
  buildProcessGraph,
  groupByPhase,
  PHASE_DEFS,
  type ProcessPhase,
  type ProcessStep,
} from "../lib/processGraph";

const PHASE_CLASS: Record<ProcessPhase, string> = {
  recon: "pg-ph-recon",
  probe: "pg-ph-probe",
  exploit: "pg-ph-exploit",
  file: "pg-ph-file",
  auth: "pg-ph-auth",
  finding: "pg-ph-finding",
};

const PHASE_LABEL: Record<ProcessPhase, string> = PHASE_DEFS.reduce(
  (acc, def) => ({ ...acc, [def.id]: def.label }),
  {} as Record<ProcessPhase, string>,
);

const STATUS_LABEL: Record<ProcessStep["status"], string> = {
  running: "进行中",
  done: "完成",
  failed: "失败",
  cancelled: "中止",
};

function clip(text: string, max: number): string {
  const clean = (text ?? "").replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function clock(at?: number): string {
  if (!at) return "";
  const d = new Date(at);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function duration(ms?: number): string {
  if (ms == null || ms < 1) return "";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const m = Math.floor(ms / 60_000);
  return `${m}m ${Math.round((ms % 60_000) / 1000)}s`;
}

/** 折叠集合的增删，保持不可变，React 才认得出变化 */
function toggled(set: Set<string>, key: string): Set<string> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}

export function ProcessGraph({
  live,
  activeId,
  onAsk,
}: {
  live: SessionState[];
  activeId?: string;
  onAsk: (prompt: string) => void;
}) {
  const [pinned, setPinned] = useState<string>();
  const [selected, setSelected] = useState<string>();
  const [query, setQuery] = useState("");
  const [phases, setPhases] = useState<ProcessPhase[]>([]);
  const [grouped, setGrouped] = useState(true);
  const [follow, setFollow] = useState(true);
  const [rootOpen, setRootOpen] = useState(true);
  const [openRounds, setOpenRounds] = useState<Set<string>>(() => new Set());
  const [closedGroups, setClosedGroups] = useState<Set<string>>(() => new Set());
  const [openSteps, setOpenSteps] = useState<Set<string>>(() => new Set());
  const seenRounds = useRef<Set<string>>(new Set());
  const canvasRef = useRef<HTMLDivElement>(null);

  const sid =
    pinned && live.some((s) => s.id === pinned)
      ? pinned
      : activeId && live.some((s) => s.id === activeId)
        ? activeId
        : live[0]?.id;
  const state = live.find((s) => s.id === sid);

  // 时间线是就地改写的，这里每次重渲染直接推导，避免缓存住旧步骤
  const graph = buildProcessGraph(state);
  const selectedStep = graph.steps.find((s) => s.id === selected);

  const filtering = query.trim().length > 0 || phases.length > 0;

  // 换会话时树的展开状态归零：轮次 id 是位置序号，跨会话会撞号
  useEffect(() => {
    seenRounds.current = new Set();
    setOpenRounds(new Set());
    setClosedGroups(new Set());
    setOpenSteps(new Set());
    setSelected(undefined);
    setRootOpen(true);
  }, [sid]);

  // 内容长出来时只展开最新一轮；流式加载的历史轮次自动收起，树始终只铺开当前这一轮
  useEffect(() => {
    if (graph.rounds.length === 0) return;
    const fresh = graph.rounds.filter((r) => !seenRounds.current.has(r.id));
    if (fresh.length === 0) return;
    for (const round of graph.rounds) seenRounds.current.add(round.id);
    const latest = graph.rounds[graph.rounds.length - 1];
    setOpenRounds(new Set([latest.id]));
  }, [graph.rounds]);

  useEffect(() => {
    if (!follow || !graph.busy) return;
    const el = canvasRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  });

  if (!state) {
    return (
      <div className="module-empty">
        还没有打开的会话。左边新建一个会话后，探微每调一次工具，这里就实时长出一步。
      </div>
    );
  }

  const q = query.trim().toLowerCase();
  const matchStep = (step: ProcessStep): boolean => {
    if (phases.length > 0 && !phases.includes(step.phase)) return false;
    if (!q) return true;
    const hay = [step.title, step.cmd, step.input, step.output, step.kind, step.hosts.join(" ")]
      .filter(Boolean)
      .join("\n")
      .toLowerCase();
    return hay.includes(q);
  };

  const viewRounds = graph.rounds
    .map((round) => {
      const steps = round.steps.filter(matchStep);
      return { round, steps, groups: groupByPhase(steps) };
    })
    .filter((entry) => (filtering ? entry.steps.length > 0 : true));

  const askHost = (host: string) => {
    onAsk(
      [
        `继续挖这个主机的攻击面：${host}`,
        `先看已有报告和这次会话的结论，再补没测的接口、写操作、跨用户读、认证接管和可执行链。`,
      ].join("\n"),
    );
  };

  const togglePhase = (phase: ProcessPhase) => {
    setPhases((prev) => (prev.includes(phase) ? prev.filter((p) => p !== phase) : [...prev, phase]));
  };

  // 从侧栏「最新结论」跳回树上：清掉筛选、展开所在轮次与阶段，再滚到那一步
  const revealStep = (stepId: string) => {
    const round = graph.rounds.find((r) => r.steps.some((s) => s.id === stepId));
    const step = round?.steps.find((s) => s.id === stepId);
    setSelected(stepId);
    if (!round || !step) return;
    setQuery("");
    setPhases([]);
    setRootOpen(true);
    setOpenRounds((prev) => new Set(prev).add(round.id));
    setClosedGroups((prev) => {
      const next = new Set(prev);
      next.delete(`${round.id}:${step.phase}`);
      return next;
    });
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        document
          .querySelector(`[data-step="${stepId}"]`)
          ?.scrollIntoView({ block: "center", behavior: "smooth" });
      }),
    );
  };

  const expandAll = () => {
    setRootOpen(true);
    setOpenRounds(new Set(graph.rounds.map((r) => r.id)));
    setClosedGroups(new Set());
    setOpenSteps(new Set(graph.steps.map((s) => s.id)));
  };

  const collapseAll = () => {
    setOpenRounds(new Set());
    setClosedGroups(new Set(graph.rounds.flatMap((r) => groupByPhase(r.steps).map((g) => `${r.id}:${g.phase}`))));
    setOpenSteps(new Set());
  };

  const renderStep = (step: ProcessStep) => {
    const hasDetail = Boolean(step.input || step.output || step.hosts.length || step.kind);
    const open = openSteps.has(step.id);
    const cmd = step.cmd && step.cmd !== step.title ? step.cmd : "";
    return (
      <div className="pgt-item" key={step.id}>
        <div
          className={`pgt-row pgt-step-row ${PHASE_CLASS[step.phase]} ${step.status}${selected === step.id ? " on" : ""}`}
          data-step={step.id}
        >
          <button
            type="button"
            className={`pgt-caret${open ? "" : " collapsed"}${hasDetail ? "" : " is-none"}`}
            onClick={() => {
              if (hasDetail) setOpenSteps((prev) => toggled(prev, step.id));
            }}
            aria-label={hasDetail ? (open ? "收起这一步" : "展开这一步") : undefined}
            tabIndex={hasDetail ? 0 : -1}
          >
            {hasDetail ? <Icon name="chevron" size={12} /> : <span className="pgt-dot-sm" />}
          </button>
          <button
            type="button"
            className="pgt-step-main"
            onClick={() => setSelected(selected === step.id ? undefined : step.id)}
            title={[step.title, step.cmd].filter(Boolean).join("\n")}
          >
            <span className="pgt-label">{clip(step.title, 96)}</span>
            {cmd ? <span className="pgt-sub mono">{clip(cmd, 110)}</span> : null}
          </button>
          <span className={`pgt-status ${step.status}`}>{STATUS_LABEL[step.status]}</span>
          <span className="pgt-meta">
            {clock(step.at)}
            {duration(step.ms) ? ` · ${duration(step.ms)}` : ""}
          </span>
          {step.hosts[0] ? (
            <button
              type="button"
              className="pgt-host mono"
              onClick={() => askHost(step.hosts[0])}
              title={`让探微接着打 ${step.hosts[0]}`}
            >
              {step.hosts[0]}
            </button>
          ) : null}
        </div>
        {open ? (
          <div className="pgt-children pgt-detail">
            {step.hosts.length ? (
              <div className="pgt-detail-row">
                <span className="pgt-detail-label">主机</span>
                <span className="pgt-host-row">
                  {step.hosts.map((host) => (
                    <button
                      type="button"
                      key={host}
                      className="pgt-host mono"
                      onClick={() => askHost(host)}
                      title="让探微接着打这个主机"
                    >
                      {host}
                    </button>
                  ))}
                </span>
              </div>
            ) : null}
            {step.kind ? (
              <div className="pgt-detail-row">
                <span className="pgt-detail-label">工具</span>
                <span className="pgt-sub mono">{step.kind}</span>
              </div>
            ) : null}
            {step.input ? (
              <div className="pgt-detail-row is-block">
                <span className="pgt-detail-label">参数</span>
                <pre className="pgt-pre mono">{step.input}</pre>
              </div>
            ) : null}
            {step.output ? (
              <div className="pgt-detail-row is-block">
                <span className="pgt-detail-label">回包 / 结论</span>
                <pre className="pgt-pre mono">{step.output}</pre>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    );
  };

  return (
    <div className="pg-page">
      <div className="graph-toolbar">
        <label className="pg-session">
          <Icon name="chat" size={13} />
          <select value={sid} onChange={(e) => setPinned(e.target.value)}>
            {live.map((s) => (
              <option key={s.id} value={s.id}>
                {clip(s.title || s.id, 40)}
              </option>
            ))}
          </select>
        </label>
        <label className="search graph-search pg-search">
          <Icon name="search" size={13} />
          <input
            value={query}
            placeholder="搜步骤 / 命令 / 主机"
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <div className="segmented">
          <button
            type="button"
            className={`seg${grouped ? " on" : ""}`}
            onClick={() => setGrouped(true)}
            title="轮次下面先按阶段分组"
          >
            按阶段
          </button>
          <button
            type="button"
            className={`seg${grouped ? "" : " on"}`}
            onClick={() => setGrouped(false)}
            title="轮次下面直接按时间顺序铺开"
          >
            按时间
          </button>
        </div>
        <div className="segmented">
          <button type="button" className="seg" onClick={expandAll} title="展开所有轮次与步骤">
            全展开
          </button>
          <button type="button" className="seg" onClick={collapseAll} title="只留轮次这一层">
            全折叠
          </button>
        </div>
        <div className="segmented">
          <button type="button" className={`seg${follow ? " on" : ""}`} onClick={() => setFollow(true)}>
            跟随最新
          </button>
          <button type="button" className={`seg${follow ? "" : " on"}`} onClick={() => setFollow(false)}>
            固定位置
          </button>
        </div>
        <div className="pg-phases">
          {PHASE_DEFS.map((def) => {
            const on = phases.includes(def.id);
            return (
              <button
                type="button"
                key={def.id}
                className={`pg-chip ${PHASE_CLASS[def.id]} is-btn${on ? " on" : ""}${graph.counts[def.id] ? "" : " is-zero"}`}
                title={`${def.hint}｜点一下只看这一类`}
                onClick={() => togglePhase(def.id)}
              >
                {def.label}
                <b>{graph.counts[def.id]}</b>
              </button>
            );
          })}
        </div>
        <div className="graph-counts">
          <span>
            <b>{graph.totalRounds}</b> 轮
          </span>
          <span>
            <b>{graph.totalSteps}</b> 步
          </span>
          <span>
            <b>{graph.hosts.length}</b> 主机
          </span>
          <span className={`pg-live ${graph.busy ? "on" : ""}`}>{graph.busy ? "进行中" : "空闲"}</span>
        </div>
      </div>

      <div className="pg-note">
        树形只做展示：会话 → 轮次 → 阶段 → 步骤 → 参数/回包/主机，读的是会话时间线里的工具调用与授权记录，不额外发请求，也不改挖洞流程。
      </div>

      {graph.rounds.length === 0 ? (
        <div className="module-empty">
          这个会话还没有工具调用。让探微开始跑，侦察、探测、利用、文件、发现会按轮次长成这棵树。
        </div>
      ) : (
        <div className="pg-split">
          <div className="pg-canvas pgt-canvas" ref={canvasRef}>
            <div className="pgt-tree">
              <div className="pgt-item">
                <button
                  type="button"
                  className="pgt-row pgt-root-row"
                  onClick={() => setRootOpen(rootOpen ? false : true)}
                >
                  <span className={`pgt-caret${rootOpen ? "" : " collapsed"}`}>
                    <Icon name="chevron" size={12} />
                  </span>
                  <Icon name="layers" size={12} />
                  <span className="pgt-label">{clip(state.title || "当前会话", 52)}</span>
                  <span className="pgt-meta">
                    {graph.totalRounds} 轮 · {graph.totalSteps} 步 · {graph.hosts.length} 主机
                  </span>
                  {graph.busy ? <span className="pgt-dot-live" /> : null}
                </button>

                {rootOpen ? (
                  <div className="pgt-children">
                    {viewRounds.length === 0 ? (
                      <div className="pgt-empty">没有匹配的步骤，清掉搜索或阶段筛选再看。</div>
                    ) : null}
                    {viewRounds.map(({ round, steps, groups }) => {
                      const roundOpen = filtering || openRounds.has(round.id);
                      const dist = PHASE_DEFS.map((def) => ({
                        def,
                        n: round.steps.filter((s) => s.phase === def.id).length,
                      })).filter((d) => d.n > 0);
                      return (
                        <div className="pgt-item" key={round.id}>
                          <button
                            type="button"
                            className="pgt-row pgt-round-row"
                            onClick={() => {
                              if (!filtering) setOpenRounds((prev) => toggled(prev, round.id));
                            }}
                          >
                            <span className={`pgt-caret${roundOpen ? "" : " collapsed"}`}>
                              <Icon name="chevron" size={12} />
                            </span>
                            <span className="pgt-tag">R{round.index}</span>
                            <span className="pgt-label" title={round.prompt}>
                              {clip(round.prompt || "（未记录指令）", 120)}
                            </span>
                            {dist.length ? (
                              <span
                                className="pgt-mini"
                                title={dist.map((d) => `${d.def.label} ${d.n}`).join(" · ")}
                              >
                                {dist.map((d) => (
                                  <i
                                    key={d.def.id}
                                    className={PHASE_CLASS[d.def.id]}
                                    style={{ flexGrow: d.n }}
                                  />
                                ))}
                              </span>
                            ) : null}
                            <span className="pgt-meta">
                              {round.steps.length} 步
                              {round.hosts.length ? ` · ${round.hosts.length} 主机` : ""} · {clock(round.at)}
                            </span>
                            {round.busy ? <span className="pgt-dot-live" /> : null}
                          </button>

                          {roundOpen ? (
                            <div className="pgt-children">
                              {round.steps.length === 0 ? (
                                <div className="pgt-empty">等待探微动手…</div>
                              ) : grouped ? (
                                groups.map((group) => {
                                  const key = `${round.id}:${group.phase}`;
                                  const groupOpen = filtering || !closedGroups.has(key);
                                  return (
                                    <div className="pgt-item" key={key}>
                                      <button
                                        type="button"
                                        className={`pgt-row pgt-group-row ${PHASE_CLASS[group.phase]}`}
                                        onClick={() => {
                                          if (!filtering) setClosedGroups((prev) => toggled(prev, key));
                                        }}
                                        title={PHASE_DEFS.find((d) => d.id === group.phase)?.hint}
                                      >
                                        <span className={`pgt-caret${groupOpen ? "" : " collapsed"}`}>
                                          <Icon name="chevron" size={12} />
                                        </span>
                                        <span className="pgt-phase-dot" />
                                        <span className="pgt-label">{PHASE_LABEL[group.phase]}</span>
                                        <span className="pgt-count">{group.steps.length}</span>
                                        <span className="pgt-meta">
                                          {clock(group.steps[0]?.at)} → {clock(group.steps[group.steps.length - 1]?.at)}
                                        </span>
                                      </button>
                                      {groupOpen ? (
                                        <div className="pgt-children">{group.steps.map(renderStep)}</div>
                                      ) : null}
                                    </div>
                                  );
                                })
                              ) : (
                                steps.map(renderStep)
                              )}
                              {round.trimmed > 0 ? (
                                <div className="pgt-empty">前面还有 {round.trimmed} 步已折叠</div>
                              ) : null}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          <aside className="pg-side">
            {selectedStep ? (
              <>
                <div className="pg-side-head">
                  <span className={`pg-chip ${PHASE_CLASS[selectedStep.phase]}`}>
                    {PHASE_LABEL[selectedStep.phase]}
                  </span>
                  <span className={`pg-step-status ${selectedStep.status}`}>
                    {STATUS_LABEL[selectedStep.status]}
                  </span>
                </div>
                <div className="pg-side-title">{selectedStep.title}</div>
                <div className="pg-side-sub">
                  {clock(selectedStep.at)}
                  {duration(selectedStep.ms) ? ` · ${duration(selectedStep.ms)}` : ""}
                  {selectedStep.kind ? ` · ${selectedStep.kind}` : ""}
                </div>
                {selectedStep.hosts.length ? (
                  <div className="pg-host-row">
                    {selectedStep.hosts.map((host) => (
                      <button
                        type="button"
                        key={host}
                        className="pg-host"
                        onClick={() => askHost(host)}
                        title="让探微接着打这个主机"
                      >
                        <Icon name="bolt" size={11} />
                        <span className="mono">{host}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
                {selectedStep.input ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">输入</span>
                    <pre className="pg-pre mono">{selectedStep.input}</pre>
                  </div>
                ) : null}
                {selectedStep.output ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">回包 / 结论</span>
                    <pre className="pg-pre mono">{selectedStep.output}</pre>
                  </div>
                ) : null}
                <button className="btn ghost sm" onClick={() => setSelected(undefined)}>
                  <Icon name="close" size={12} />
                  <span>回到概览</span>
                </button>
              </>
            ) : (
              <>
                <div className="pg-side-head">
                  <div>
                    <div className="pg-side-title">这次渗透的路线</div>
                    <div className="pg-side-sub">
                      {clock(graph.startedAt)} → {clock(graph.lastAt)} · {graph.totalSteps} 步
                    </div>
                  </div>
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">碰过的主机</span>
                  {graph.hosts.length === 0 ? (
                    <div className="pg-side-sub">还没有从工具参数里认出主机。</div>
                  ) : (
                    <div className="pg-host-list">
                      {graph.hosts.slice(0, 40).map((host) => (
                        <button
                          type="button"
                          key={host.host}
                          className="pg-host"
                          onClick={() => askHost(host.host)}
                        >
                          <span className="mono">{host.host}</span>
                          <b>{host.count}</b>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">最新结论</span>
                  {graph.findings.length === 0 ? (
                    <div className="pg-side-sub">还没有写下的结论。</div>
                  ) : (
                    <div className="pg-host-list">
                      {graph.findings
                        .slice(-8)
                        .reverse()
                        .map((step) => (
                          <button
                            type="button"
                            key={step.id}
                            className="pg-conclusion"
                            onClick={() => revealStep(step.id)}
                          >
                            <span>{clip(step.title, 64)}</span>
                            <span className="pg-side-sub">{clock(step.at)}</span>
                          </button>
                        ))}
                    </div>
                  )}
                </div>
                <div className="pg-side-label">点树里任意一步看参数与回包，小箭头展开详情。</div>
              </>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}
