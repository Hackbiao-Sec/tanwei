import React, { useEffect, useRef, useState } from "react";
import type { SessionState } from "@shared/types";
import { Icon } from "./Icons";
import {
  BOARD_GROUPS,
  buildAttackGraph,
  GAIN_LABEL,
  STATUS_LABEL,
  VERDICT_LABEL,
  type AttackDirection,
  type AttackTest,
  type BoardGroupId,
  type DirectionId,
  type DirectionStatus,
  type EndpointInfo,
  type Gain,
  type TestVerdict,
} from "../lib/attackPlan";

const VERDICT_ORDER: TestVerdict[] = ["hit", "running", "blocked", "missed", "clean", "unclear", "failed"];

const STATUS_ORDER: DirectionStatus[] = ["running", "hit", "unclear", "planned", "excluded"];

const SOURCE_LABEL: Record<string, string> = {
  plan: "计划",
  assistant: "模型",
  gap: "自检",
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

function ago(at?: number): string {
  if (!at) return "";
  const diff = Date.now() - at;
  if (diff < 3000) return "刚刚";
  if (diff < 60_000) return `${Math.max(1, Math.round(diff / 1000))} 秒前`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)} 分钟前`;
  return `${Math.round(diff / 3_600_000)} 小时前`;
}

function duration(ms?: number): string {
  if (ms == null || ms < 1) return "";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const m = Math.floor(ms / 60_000);
  return `${m}m ${Math.round((ms % 60_000) / 1000)}s`;
}

/** 折叠集合的增删，保持不可变，React 才认得出变化 */
function toggled<T>(set: Set<T>, key: T): Set<T> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}

/** 相对时间单独走一个秒级计时器，别让整棵树每秒重算一次 */
function LiveLag({ at, live }: { at?: number; live: boolean }) {
  const [, force] = useState(0);
  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => force((n) => n + 1), 1000);
    return () => window.clearInterval(timer);
  }, [live]);
  if (!at) return null;
  return (
    <span className={`pdt-lag${live ? " on" : ""}`} title={clock(at)}>
      {live ? "更新于 " : "最近 "}
      {ago(at)}
    </span>
  );
}

export function AttackPlan({
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
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>();
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<DirectionStatus[]>([]);
  const [openDirs, setOpenDirs] = useState<Set<DirectionId>>(() => new Set());
  const [closedGroups, setClosedGroups] = useState<Set<string>>(() => new Set());
  const [openTests, setOpenTests] = useState<Set<string>>(() => new Set());
  const [openGains, setOpenGains] = useState<Set<string>>(() => new Set());
  const [rootOpen, setRootOpen] = useState(true);
  const [follow, setFollow] = useState(true);
  const canvasRef = useRef<HTMLDivElement>(null);

  const sid =
    pinned && live.some((s) => s.id === pinned)
      ? pinned
      : activeId && live.some((s) => s.id === activeId)
        ? activeId
        : live[0]?.id;
  const state = live.find((s) => s.id === sid);

  // 时间线是就地改写的，每次重渲染直接推导，避免缓存住旧动作
  const graph = buildAttackGraph(state);
  const selectedTest = graph.tests.find((t) => t.id === selected);
  const selectedDir = selectedTest
    ? graph.directions.find((d) => d.id === selectedTest.direction)
    : undefined;
  const endpoint =
    (selectedEndpoint
      ? graph.endpoints.find((e) => e.key === selectedEndpoint) ??
        graph.directions.flatMap((d) => d.endpoints).find((e) => e.key === selectedEndpoint)
      : undefined) ?? undefined;

  const filtering = query.trim().length > 0 || filters.length > 0;
  const q = query.trim().toLowerCase();
  const hit = (text?: string) => !q || (text ?? "").toLowerCase().includes(q);

  // 换会话时树的展开与选中状态归零
  useEffect(() => {
    setOpenDirs(new Set());
    setClosedGroups(new Set());
    setOpenTests(new Set());
    setOpenGains(new Set());
    setSelected(undefined);
    setSelectedEndpoint(undefined);
    setRootOpen(true);
  }, [sid]);

  // 正在测试的方向和最近出过成果的方向默认展开：一进来既看得到在验什么，也看得到拿到了什么
  const activeDirection = graph.active?.direction.id;
  const gainDirs = graph.directions
    .filter((d) => d.gains.length > 0)
    .sort((a, b) => (b.gains[b.gains.length - 1]?.at ?? 0) - (a.gains[a.gains.length - 1]?.at ?? 0))
    .slice(0, 2)
    .map((d) => d.id)
    .join(",");
  useEffect(() => {
    const ids = [activeDirection, ...gainDirs.split(",")].filter(Boolean) as DirectionId[];
    if (ids.length === 0) return;
    setOpenDirs((prev) => {
      const next = new Set(prev);
      let changed = false;
      for (const id of ids) {
        if (!next.has(id)) {
          next.add(id);
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [activeDirection, gainDirs]);

  useEffect(() => {
    if (!follow || !graph.busy) return;
    const el = canvasRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  });

  if (!state) {
    return (
      <div className="module-empty">
        还没有打开的会话。左边新建一个会话后，探微每走一步，黑板就把正在做、成果、发现和试过的动作长出来。
      </div>
    );
  }

  const matchTest = (test: AttackTest, dir: AttackDirection): boolean => {
    if (filters.length > 0 && !filters.includes(dir.status)) return false;
    if (!q) return true;
    return [
      test.description,
      test.title,
      test.host,
      test.path,
      test.params.join(" "),
      test.probe,
      test.kind,
      dir.def.label,
      dir.def.goal,
      test.output,
    ]
      .filter(Boolean)
      .join("\n")
      .toLowerCase()
      .includes(q);
  };

  const viewDirs = graph.directions
    .map((dir) => {
      const statusOk = filters.length === 0 || filters.includes(dir.status);
      const tests = dir.tests.filter((test) => matchTest(test, dir));
      const gains = statusOk ? dir.gains.filter((g) => hit(g.title) || hit(g.detail)) : [];
      const endpoints = statusOk
        ? dir.endpoints.filter((e) => hit(e.path) || hit(e.host) || hit(e.source))
        : [];
      const keep = filtering
        ? tests.length > 0 || gains.length > 0 || endpoints.length > 0 || (dir.tests.length === 0 && statusOk)
        : true;
      return { dir, tests, gains, endpoints, keep };
    })
    .filter((entry) => entry.keep);

  const askHost = (host: string) => {
    onAsk(
      [
        `漏洞复测：${host}`,
        `先看已有报告和这次会话的结论，把还没测的口补上，再把测过的口回归一遍：未授权、换 ID、注入、写操作、认证接管、可执行链。`,
      ].join("\n"),
    );
  };

  const askEndpoint = (ep: EndpointInfo) => {
    onAsk(
      [
        `漏洞复测：${ep.method ? `${ep.method} ` : ""}${ep.path}`,
        ep.host ? `主机 ${ep.host}。` : "",
        `它是我从${ep.source}里认出来的。把这条接口复测一遍：未授权、换 ID、注入面，再顺着同一个对象找写接口，测完把结果写清楚。`,
      ].join(""),
    );
  };

  const toggleFilter = (status: DirectionStatus) => {
    setFilters((prev) => (prev.includes(status) ? prev.filter((s) => s !== status) : [...prev, status]));
  };

  const revealTest = (testId: string, direction: DirectionId) => {
    setQuery("");
    setFilters([]);
    setRootOpen(true);
    setOpenDirs((prev) => new Set(prev).add(direction));
    setClosedGroups((prev) => {
      const next = new Set(prev);
      next.delete(`${direction}:tried`);
      return next;
    });
    setOpenTests((prev) => new Set(prev).add(testId));
    setSelectedEndpoint(undefined);
    setSelected(testId);
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        document.querySelector(`[data-test="${testId}"]`)?.scrollIntoView({ block: "center", behavior: "smooth" });
      }),
    );
  };

  const groupKey = (dir: DirectionId, group: BoardGroupId) => `${dir}:${group}`;
  const groupOpen = (dir: DirectionId, group: BoardGroupId) =>
    filtering || !closedGroups.has(groupKey(dir, group));
  const toggleGroup = (dir: DirectionId, group: BoardGroupId, open: boolean) => {
    if (filtering) return;
    setClosedGroups((prev) => {
      const key = groupKey(dir, group);
      const next = new Set(prev);
      if (open) next.add(key);
      else next.delete(key);
      return next;
    });
  };

  const expandAll = () => {
    setRootOpen(true);
    setOpenDirs(new Set(graph.directions.map((d) => d.id)));
    setOpenTests(new Set(graph.tests.map((t) => t.id)));
    setOpenGains(new Set(graph.gains.map((g) => g.id)));
    setClosedGroups(new Set());
  };

  const collapseAll = () => {
    setOpenDirs(new Set());
    setOpenTests(new Set());
    setOpenGains(new Set());
    setClosedGroups(
      new Set(
        graph.directions.flatMap((d) => BOARD_GROUPS.map((g) => groupKey(d.id, g.id))),
      ),
    );
  };

  const renderTest = (test: AttackTest, dir: AttackDirection, focus = false) => {
    const hasDetail = Boolean(
      test.input || test.output || test.result || test.hosts.length || test.kind || test.probe,
    );
    const open = openTests.has(test.id);
    const sub = test.path ? `${test.method ? `${test.method} ` : ""}${test.path}` : test.host ?? "";
    return (
      <div className="pgt-item" key={test.id}>
        <div
          className={`pgt-row pgt-step-row pdt-test-row ${dir.def.cls} ${test.verdict}${selected === test.id ? " on" : ""}${focus ? " is-focus" : ""}`}
          data-test={test.id}
        >
          <button
            type="button"
            className={`pgt-caret${open ? "" : " collapsed"}${hasDetail ? "" : " is-none"}`}
            onClick={() => {
              if (hasDetail) setOpenTests((prev) => toggled(prev, test.id));
            }}
            aria-label={hasDetail ? (open ? "收起这次测试" : "展开这次测试") : undefined}
            tabIndex={hasDetail ? 0 : -1}
          >
            {hasDetail ? <Icon name="chevron" size={12} /> : <span className="pgt-dot-sm" />}
          </button>
          <button
            type="button"
            className="pgt-step-main"
            onClick={() => {
              setSelectedEndpoint(undefined);
              setSelected(selected === test.id ? undefined : test.id);
            }}
            title={[test.description, test.title].filter(Boolean).join("\n")}
          >
            <span className="pgt-label">{clip(test.description, 108)}</span>
            {sub ? <span className="pgt-sub mono">{clip(sub, 96)}</span> : null}
            {test.result ? <span className={`pgt-result ${test.verdict}`}>{clip(test.result, 130)}</span> : null}
          </button>
          <span className={`pdt-verdict ${test.verdict}`}>{VERDICT_LABEL[test.verdict]}</span>
          <span className="pgt-meta">
            R{test.round}
            {duration(test.ms) ? ` · ${duration(test.ms)}` : ` · ${clock(test.at)}`}
          </span>
        </div>
        {open ? (
          <div className="pgt-children pgt-detail">
            <div className="pgt-detail-row">
              <span className="pgt-detail-label">规范描述</span>
              <span>{test.description}</span>
            </div>
            <div className="pgt-detail-row">
              <span className="pgt-detail-label">判定</span>
              <span className={`pdt-verdict ${test.verdict}`}>{VERDICT_LABEL[test.verdict]}</span>
              {test.code ? <span className="pgt-detail-code mono">HTTP {test.code}</span> : null}
            </div>
            <div className="pgt-detail-row">
              <span className="pgt-detail-label">结果</span>
              <span className={`pgt-detail-result ${test.verdict}`}>{test.result || "还没拿到回包"}</span>
            </div>
            {test.hosts.length ? (
              <div className="pgt-detail-row">
                <span className="pgt-detail-label">主机</span>
                <span className="pgt-host-row">
                  {test.hosts.map((host) => (
                    <button
                      type="button"
                      key={host}
                      className="pgt-host mono"
                      onClick={() => askHost(host)}
                      title={`漏洞复测 ${host}`}
                    >
                      {host}
                    </button>
                  ))}
                </span>
              </div>
            ) : null}
            {test.kind || test.probe ? (
              <div className="pgt-detail-row">
                <span className="pgt-detail-label">动作</span>
                <span className="pgt-sub mono">
                  {[test.kind, test.probe, test.params.length ? `参数 ${test.params.join(" / ")}` : ""]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
              </div>
            ) : null}
            {test.input ? (
              <div className="pgt-detail-row is-block">
                <span className="pgt-detail-label">参数</span>
                <pre className="pgt-pre mono">{test.input}</pre>
              </div>
            ) : null}
            {test.output ? (
              <div className="pgt-detail-row is-block">
                <span className="pgt-detail-label">回包 / 证据</span>
                <pre className="pgt-pre mono">{test.output}</pre>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    );
  };

  const renderGain = (gain: Gain, dir: AttackDirection) => {
    const open = openGains.has(gain.id);
    return (
      <div className="pgt-item" key={gain.id}>
        <div className={`pgt-row pdt-gain ${dir.def.cls}`}>
          <button
            type="button"
            className={`pgt-caret${open ? "" : " collapsed"}${gain.detail ? "" : " is-none"}`}
            onClick={() => {
              if (gain.detail) setOpenGains((prev) => toggled(prev, gain.id));
            }}
            tabIndex={gain.detail ? 0 : -1}
            aria-label={gain.detail ? (open ? "收起这条成果" : "展开这条成果") : undefined}
          >
            {gain.detail ? <Icon name="chevron" size={12} /> : <span className="pgt-dot-sm" />}
          </button>
          <span className={`pdt-gain-kind ${gain.kind}`}>{GAIN_LABEL[gain.kind]}</span>
          <button
            type="button"
            className="pgt-step-main"
            onClick={() => {
              if (gain.testId) revealTest(gain.testId, dir.id);
              else setOpenGains((prev) => toggled(prev, gain.id));
            }}
          >
            <span className="pgt-label">{clip(gain.title, 108)}</span>
            {gain.detail ? <span className="pgt-sub">{clip(gain.detail, 100)}</span> : null}
          </button>
          {gain.host ? (
            <button
              type="button"
              className="pgt-host mono"
              onClick={() => askHost(gain.host as string)}
              title={`漏洞复测 ${gain.host}`}
            >
              {gain.host}
            </button>
          ) : null}
          <span className="pgt-meta">{clock(gain.at)}</span>
        </div>
        {open && gain.detail ? (
          <div className="pgt-children pgt-detail">
            <div className="pgt-detail-row is-block">
              <span className="pgt-detail-label">原文</span>
              <pre className="pgt-pre mono">{gain.detail}</pre>
            </div>
          </div>
        ) : null}
      </div>
    );
  };

  const renderEndpoint = (ep: EndpointInfo, dir: AttackDirection, index: number) => (
    <div className="pgt-item" key={`${ep.key}-${index}`}>
      <div className={`pgt-row pdt-ep-row ${dir.def.cls}${endpoint?.key === ep.key ? " on" : ""}`}>
        <span className="pgt-dot-sm" />
        <span className={`pdt-ep-method ${(ep.method ?? "").toLowerCase()}`}>{ep.method ?? "PATH"}</span>
        <button
          type="button"
          className="pgt-step-main"
          onClick={() => {
            setSelected(undefined);
            setSelectedEndpoint(endpoint?.key === ep.key ? undefined : ep.key);
          }}
          title={`${ep.source} · ${clock(ep.firstAt)} 首次看到`}
        >
          <span className="pgt-label mono">{clip(ep.path, 92)}</span>
          <span className="pgt-sub">{ep.host ? ep.host : `来源 ${ep.source}`}</span>
          {ep.status === "called" && ep.result ? (
            <span className={`pgt-result ${ep.verdict}`}>{clip(ep.result, 118)}</span>
          ) : null}
        </button>
        <span className={`pdt-ep-status ${ep.status}`}>{ep.status === "called" ? "打过" : "待打"}</span>
        {ep.status === "called" ? (
          <span className={`pdt-verdict ${ep.verdict}`}>{VERDICT_LABEL[ep.verdict]}</span>
        ) : null}
        <span className="pgt-meta">{ep.count > 1 ? `×${ep.count} · ` : ""}{clock(ep.lastAt)}</span>
      </div>
    </div>
  );

  const renderGroup = (
    dir: AttackDirection,
    group: (typeof BOARD_GROUPS)[number],
    tests: AttackTest[],
    gains: Gain[],
    endpoints: EndpointInfo[],
  ) => {
    const open = groupOpen(dir.id, group.id);
    // 正在做的那步只在「正在做」段出现一次，试过段展示其余动作，避免同一条动作重复两遍
    const doing = dir.doing && (!filtering || matchTest(dir.doing, dir)) ? dir.doing : undefined;
    const tried = doing ? tests.filter((test) => test.id !== doing.id) : tests;
    const count =
      group.id === "doing"
        ? doing
          ? 1
          : 0
        : group.id === "gains"
          ? gains.length
          : group.id === "assets"
            ? endpoints.length
            : tried.length;
    return (
      <div className={`pdt-group g-${group.id}`} key={group.id}>
        <div className="pgt-row pdt-group-row">
          <button
            type="button"
            className={`pgt-caret${open ? "" : " collapsed"}`}
            onClick={() => toggleGroup(dir.id, group.id, open)}
            aria-label={open ? `收起「${group.label}」` : `展开「${group.label}」`}
          >
            <Icon name="chevron" size={12} />
          </button>
          <span className="pdt-group-name">{group.label}</span>
          <span className="pdt-group-hint">{group.hint}</span>
          <span className="pgt-count">{count}</span>
        </div>
        {open ? (
          <div className="pgt-children">
            {group.id === "doing" ? (
              doing ? (
                renderTest(doing, dir, true)
              ) : (
                <div className="pgt-empty">这个方向还没开打，下一步里有它的位置。</div>
              )
            ) : null}
            {group.id === "gains" ? (
              gains.length ? (
                gains
                  .slice(-8)
                  .reverse()
                  .map((gain) => renderGain(gain, dir))
              ) : (
                <div className="pgt-empty">还没有出成果。有回显、模型写下结论、报告落盘时会记到这里。</div>
              )
            ) : null}
            {group.id === "assets" ? (
              endpoints.length ? (
                <>
                  {endpoints.slice(0, 12).map((ep, i) => renderEndpoint(ep, dir, i))}
                  {endpoints.length > 12 ? (
                    <div className="pgt-empty">还有 {endpoints.length - 12} 个接口，右侧「发现接口」里看全。</div>
                  ) : null}
                </>
              ) : (
                <div className="pgt-empty">这条方向还没摸到接口。</div>
              )
            ) : null}
            {group.id === "tried" ? (
              tried.length ? (
                <>
                  {tried.map((test) => renderTest(test, dir))}
                  {dir.trimmed > 0 ? (
                    <div className="pgt-empty">前面还有 {dir.trimmed} 次测试已折叠</div>
                  ) : null}
                </>
              ) : (
                <div className="pgt-empty">
                  {dir.tests.length === 0
                    ? "这个方向还没排到。"
                    : filtering
                      ? "筛选下没有匹配的测试。"
                      : "这个方向只有上面这一步。"}
                </div>
              )
            ) : null}
          </div>
        ) : null}
      </div>
    );
  };

  const nextList = graph.next.slice(0, 4);

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
            placeholder="搜方向 / 动作 / 接口 / 主机"
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <div className="segmented">
          <button type="button" className="seg" onClick={expandAll} title="展开所有方向、成果、发现和试过的动作">
            全展开
          </button>
          <button type="button" className="seg" onClick={collapseAll} title="只留方向这一层">
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
          {STATUS_ORDER.map((status) => {
            const on = filters.includes(status);
            const n = graph.directions.filter((d) => d.status === status).length;
            return (
              <button
                type="button"
                key={status}
                className={`pg-chip pdt-st-${status} is-btn${on ? " on" : ""}${n ? "" : " is-zero"}`}
                title={`点一下只看「${STATUS_LABEL[status]}」的方向`}
                onClick={() => toggleFilter(status)}
              >
                {STATUS_LABEL[status]}
                <b>{n}</b>
              </button>
            );
          })}
        </div>
        <div className="graph-counts">
          <span>
            <b>{graph.counts.directions}</b> 方向
          </span>
          <span>
            <b>{graph.counts.gains}</b> 成果
          </span>
          <span>
            <b>{graph.counts.endpoints}</b> 接口
          </span>
          <span>
            <b>{graph.hosts.length}</b> 主机
          </span>
          <span className={`pg-live ${graph.busy ? "on" : ""}`}>{graph.busy ? "进行中" : "空闲"}</span>
        </div>
      </div>

      <div className="pdt-brief">
        <div className="pdt-brief-col pdt-brief-now">
          <span className="pdt-brief-label">{graph.busy ? "正在做" : "最近做"}</span>
          {graph.blackboard.doing ? (
            <>
              <div className="pdt-brief-head">
                <span className={`pg-chip ${graph.blackboard.doing.cls}`}>
                  {graph.blackboard.doing.label}
                </span>
                {graph.blackboard.doing.verdict ? (
                  <span className={`pdt-verdict ${graph.blackboard.doing.verdict}`}>
                    {VERDICT_LABEL[graph.blackboard.doing.verdict]}
                  </span>
                ) : null}
                <LiveLag at={graph.blackboard.doing.at ?? graph.lastAt} live={graph.busy} />
              </div>
              <div className="pdt-brief-main">{graph.blackboard.doing.text}</div>
              {graph.active?.direction ? (
                <div className="pdt-brief-sub">{graph.active.direction.def.goal}</div>
              ) : null}
            </>
          ) : (
            <div className="pdt-brief-main">还没开始测。让探微跑起来，黑板会实时记下每一步在验什么。</div>
          )}
        </div>
        <div className="pdt-brief-col pdt-brief-next">
          <span className="pdt-brief-label">下一步</span>
          {nextList.length === 0 ? (
            <div className="pdt-brief-sub">暂时没有待办，跟着模型继续推进就行。</div>
          ) : (
            <ol className="pdt-next-list">
              {nextList.map((item) => (
                <li key={item.id}>
                  <span className={`pdt-src ${item.source}`}>{SOURCE_LABEL[item.source] ?? item.source}</span>
                  <span className="pdt-next-text">{item.text}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>

      <div className="pg-note">
        黑板按方向铺开，每个方向固定四段：正在做 → 成果 → 发现 → 试过。只读会话时间线在本地推导，不额外发请求；工具只当证据，看的是方向和拿到的东西。
      </div>

      {graph.directions.length === 0 ? (
        <div className="module-empty">
          这个会话还没有动作。让探微开始跑，正在做、成果、发现会跟着测试一起长出来。
        </div>
      ) : (
        <div className="pg-split">
          <div className="pg-canvas pgt-canvas" ref={canvasRef}>
            <div className="pgt-tree">
              <div className="pgt-item">
                <button
                  type="button"
                  className="pgt-row pgt-root-row"
                  onClick={() => setRootOpen(!rootOpen)}
                >
                  <span className={`pgt-caret${rootOpen ? "" : " collapsed"}`}>
                    <Icon name="chevron" size={12} />
                  </span>
                  <Icon name="radar" size={12} />
                  <span className="pgt-label">{clip(state.title || "当前会话", 52)}</span>
                  <span className="pgt-meta">
                    {graph.counts.directions} 方向 · {graph.counts.gains} 成果 · {graph.counts.endpoints} 接口
                  </span>
                  {graph.busy ? <span className="pgt-dot-live" /> : null}
                </button>

                {rootOpen ? (
                  <div className="pgt-children">
                    {viewDirs.length === 0 ? (
                      <div className="pgt-empty">没有匹配的方向、动作或接口，清掉搜索和状态筛选再看。</div>
                    ) : null}
                    {viewDirs.map(({ dir, tests, gains, endpoints }) => {
                      const dirOpen = filtering || openDirs.has(dir.id);
                      const dist = VERDICT_ORDER.map((v) => ({ v, n: dir.verdicts[v] })).filter((d) => d.n > 0);
                      return (
                        <div className="pgt-item" key={dir.id}>
                          <button
                            type="button"
                            className={`pgt-row pdt-dir-row ${dir.def.cls}${dir.id === activeDirection ? " current" : ""}`}
                            onClick={() => {
                              if (!filtering) setOpenDirs((prev) => toggled(prev, dir.id));
                            }}
                            title={`${dir.def.goal}｜${dir.summary}`}
                          >
                            <span className={`pgt-caret${dirOpen ? "" : " collapsed"}`}>
                              <Icon name="chevron" size={12} />
                            </span>
                            <span className="pgt-phase-dot" />
                            <span className="pgt-label">{dir.def.label}</span>
                            {dir.id === activeDirection ? (
                              <span className={`pdt-cur${graph.busy ? " now" : ""}`}>
                                {graph.busy ? "正在做" : "最近"}
                              </span>
                            ) : null}
                            <span className={`pdt-status ${dir.status}`}>{STATUS_LABEL[dir.status]}</span>
                            {dist.length ? (
                              <span
                                className="pgt-mini"
                                title={dist.map((d) => `${VERDICT_LABEL[d.v]} ${d.n}`).join(" · ")}
                              >
                                {dist.map((d) => (
                                  <i key={d.v} className={`pdt-v-${d.v}`} style={{ flexGrow: d.n }} />
                                ))}
                              </span>
                            ) : null}
                            <span className="pgt-count">{dir.gains.length ? `${dir.gains.length} 成果 · ` : ""}{tests.length}</span>
                            <span className="pgt-meta">
                              {dir.endpoints.length ? `${dir.endpoints.length} 接口 · ` : ""}
                              {clock(dir.lastAt)}
                            </span>
                          </button>

                          {dirOpen ? (
                            <div className="pgt-children pdt-board">
                              <div className="pdt-goal">{dir.def.goal}</div>
                              <div className="pdt-summary">
                                <span className="pdt-summary-label">规范描述</span>
                                <span className="pdt-summary-text">{dir.summary}</span>
                              </div>
                              {BOARD_GROUPS.map((group) =>
                                renderGroup(dir, group, tests, gains, endpoints),
                              )}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                    {graph.trimmed > 0 ? (
                      <div className="pgt-empty">整块黑板还有 {graph.trimmed} 次较早的动作未展示</div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          <aside className="pg-side">
            {endpoint ? (
              <>
                <div className="pg-side-head">
                  <span className={`pdt-ep-status ${endpoint.status}`}>
                    {endpoint.status === "called" ? "打过" : "待打"}
                  </span>
                  <span className={`pdt-verdict ${endpoint.verdict}`}>{VERDICT_LABEL[endpoint.verdict]}</span>
                </div>
                <div className="pg-side-title mono">{endpoint.path}</div>
                <div className="pg-side-sub">
                  {endpoint.source} · {clock(endpoint.firstAt)}
                  {endpoint.count > 1 ? ` · 遇到 ${endpoint.count} 次` : ""}
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">结果</span>
                  <div className={`pg-side-result ${endpoint.verdict}`}>
                    {endpoint.result || (endpoint.status === "called" ? "打过，没留下结论" : "还没打过这条接口")}
                  </div>
                </div>
                {endpoint.method || endpoint.host ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">接口</span>
                    <div className="pg-side-sub mono">
                      {[endpoint.method, endpoint.host].filter(Boolean).join(" · ")}
                    </div>
                  </div>
                ) : null}
                <div className="pg-side-block">
                  <button type="button" className="btn ghost sm" onClick={() => askEndpoint(endpoint)}>
                    <Icon name="bolt" size={12} />
                    <span>漏洞复测</span>
                  </button>
                </div>
                {endpoint.sample ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">回包 / 证据</span>
                    <pre className="pg-pre mono">{endpoint.sample}</pre>
                  </div>
                ) : null}
                <button className="btn ghost sm" onClick={() => setSelectedEndpoint(undefined)}>
                  <Icon name="close" size={12} />
                  <span>回到概览</span>
                </button>
              </>
            ) : selectedTest && selectedDir ? (
              <>
                <div className="pg-side-head">
                  <span className={`pg-chip ${selectedDir.def.cls}`}>{selectedDir.def.label}</span>
                  <span className={`pdt-verdict ${selectedTest.verdict}`}>
                    {VERDICT_LABEL[selectedTest.verdict]}
                  </span>
                </div>
                <div className="pg-side-title">{selectedTest.description}</div>
                <div className="pg-side-sub">
                  {clock(selectedTest.at)}
                  {duration(selectedTest.ms) ? ` · ${duration(selectedTest.ms)}` : ""}
                  {` · 第 ${selectedTest.round} 轮`}
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">结果</span>
                  <div className={`pg-side-result ${selectedTest.verdict}`}>
                    {selectedTest.result || "还没拿到回包"}
                  </div>
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">动作 / 线索</span>
                  <div className="pg-side-sub mono">
                    {[selectedTest.kind, selectedTest.probe, selectedTest.params.length ? `参数 ${selectedTest.params.join(" / ")}` : ""]
                      .filter(Boolean)
                      .join(" · ") || selectedTest.title}
                  </div>
                </div>
                {selectedTest.hosts.length ? (
                  <div className="pg-host-row">
                    {selectedTest.hosts.map((host) => (
                      <button
                        type="button"
                        key={host}
                        className="pg-host"
                        onClick={() => askHost(host)}
                        title={`漏洞复测 ${host}`}
                      >
                        <Icon name="bolt" size={11} />
                        <span className="mono">{host}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
                {selectedTest.input ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">参数</span>
                    <pre className="pg-pre mono">{selectedTest.input}</pre>
                  </div>
                ) : null}
                {selectedTest.output ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">回包 / 证据</span>
                    <pre className="pg-pre mono">{selectedTest.output}</pre>
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
                    <div className="pg-side-title">黑板总览</div>
                    <div className="pg-side-sub">
                      {clock(graph.startedAt)} → {clock(graph.lastAt)} · {graph.counts.tests} 次动作 ·{" "}
                      {graph.counts.gains} 项成果
                    </div>
                  </div>
                </div>
                {graph.blackboard.doing ? (
                  <div className="pg-side-block">
                    <span className="pg-side-label">当前方向</span>
                    <div className="pdt-side-dirs">
                      <div className={`pdt-side-dir ${graph.blackboard.doing.cls} is-current`}>
                        <span className="pgt-phase-dot" />
                        <span className="pdt-side-dir-name">{graph.blackboard.doing.label}</span>
                        <LiveLag at={graph.blackboard.doing.at} live={graph.busy} />
                      </div>
                    </div>
                    <div className="pg-side-sub">{graph.blackboard.doing.text}</div>
                  </div>
                ) : null}
                <div className="pg-side-block">
                  <span className="pg-side-label">最新成果</span>
                  {graph.gains.length === 0 ? (
                    <div className="pg-side-sub">还没有出成果。有回显或写下结论会记到这里。</div>
                  ) : (
                    <div className="pg-host-list">
                      {graph.gains
                        .slice(-6)
                        .reverse()
                        .map((gain) => (
                          <div className={`pdt-gain-side ${gain.kind}`} key={gain.id}>
                            <span className={`pdt-gain-kind ${gain.kind}`}>{GAIN_LABEL[gain.kind]}</span>
                            <div>
                              <div className="pdt-gain-side-title">{clip(gain.title, 78)}</div>
                              <div className="pg-side-sub">
                                {clock(gain.at)}
                                {gain.host ? ` · ${gain.host}` : ""}
                              </div>
                            </div>
                          </div>
                        ))}
                    </div>
                  )}
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">发现接口</span>
                  {graph.endpoints.length === 0 ? (
                    <div className="pg-side-sub">还没从前端文件和回包里认出接口。</div>
                  ) : (
                    <div className="pg-host-list">
                      {graph.endpoints.slice(0, 16).map((ep) => (
                        <button
                          type="button"
                          key={ep.key}
                          className="pdt-ep-side"
                          onClick={() => {
                            setSelected(undefined);
                            setSelectedEndpoint(ep.key);
                          }}
                          title={ep.source}
                        >
                          <span className={`pdt-ep-status ${ep.status}`}>
                            {ep.status === "called" ? "打过" : "待打"}
                          </span>
                          <span className="mono">{clip(ep.path, 42)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <div className="pg-side-block">
                  <span className="pg-side-label">碰过的主机</span>
                  {graph.hosts.length === 0 ? (
                    <div className="pg-side-sub">还没有从参数里认出主机。</div>
                  ) : (
                    <div className="pg-host-list">
                      {graph.hosts.slice(0, 12).map((host) => (
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
                <div className="pg-side-label">点方向看四段分支，点成果看原文，点接口看来源和回包。</div>
              </>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}
