import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Finding, SessionState } from "@shared/types";
import { Icon } from "./Icons";
import { AttackPlan } from "./AttackPlan";
import { FileViewer, type PreviewTarget } from "./FileViewer";
import { ScopeSwitch } from "./ScopeSwitch";
import { buildAttackGraph } from "../lib/attackPlan";
import { useSessionScope } from "../lib/sessionScope";
import {
  BB_KIND_LABEL,
  buildBlackboard,
  collectFoldable,
  defaultOpen,
  findNode,
  type BBNode,
} from "../lib/blackboard";

const KIND_ICON: Record<BBNode["kind"], "node" | "globe" | "plug" | "radar" | "bolt" | "shield" | "file" | "chat" | "send"> = {
  session: "chat",
  host: "globe",
  endpoint: "plug",
  intent: "radar",
  test: "bolt",
  gain: "shield",
  finding: "file",
  conclusion: "chat",
  next: "send",
};

/** 一个节点一行：左边连接线、中间是什么事、右边判定 */
function NodeRow({
  node,
  depth,
  open,
  selected,
  onToggle,
  onSelect,
}: {
  node: BBNode;
  depth: number;
  open: Record<string, boolean>;
  selected?: string;
  onToggle: (id: string) => void;
  onSelect: (node: BBNode) => void;
}) {
  const kids = node.children.length > 0;
  const isOpen = !!open[node.id];
  return (
    <>
      <div
        className={`bb-row k-${node.kind}${selected === node.id ? " on" : ""}`}
        style={{ paddingLeft: 12 + depth * 18 }}
        onClick={() => onSelect(node)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect(node);
          }
        }}
      >
        <span
          className={`bb-twisty${kids ? " has" : ""}${isOpen ? " open" : ""}`}
          onClick={(e) => {
            e.stopPropagation();
            if (kids) onToggle(node.id);
          }}
        >
          {kids ? <Icon name="chevron" size={11} /> : null}
        </span>
        <Icon name={KIND_ICON[node.kind]} size={12} className="bb-icon" />
        <span className="bb-kind">{BB_KIND_LABEL[node.kind]}</span>
        <span className="bb-title">{node.title}</span>
        {node.meta ? <span className="bb-meta">{node.meta}</span> : null}
        {node.badge ? <span className={`bb-badge t-${node.tone ?? "idle"}`}>{node.badge}</span> : null}
      </div>
      {kids && isOpen ? (
        <div className="bb-kids">
          {node.children.map((child) => (
            <NodeRow
              key={child.id}
              node={child}
              depth={depth + 1}
              open={open}
              selected={selected}
              onToggle={onToggle}
              onSelect={onSelect}
            />
          ))}
        </div>
      ) : null}
    </>
  );
}

export function Graph({
  onAsk,
  live = [],
  activeId,
}: {
  onAsk: (prompt: string) => void;
  live?: SessionState[];
  activeId?: string;
}) {
  const [tab, setTab] = useState<"board" | "plan">("board");
  const [selected, setSelected] = useState<string>();
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [preview, setPreview] = useState<PreviewTarget | null>(null);
  const [scope, setScope] = useState<"session" | "all">("session");
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [allLoaded, setAllLoaded] = useState(false);
  const allSeq = useRef(0);
  const allAt = useRef(0);
  // 黑板上的「发现」默认只挂本会话认领的任务夹，跟发现模块同源；切到总览才吃全桌面
  const ctx = useSessionScope();

  // 总览要读整桌面的报告正文，切到总览才拉，15 秒内复用
  useEffect(() => {
    if (scope !== "all") return;
    if (allLoaded && Date.now() - allAt.current < 15_000) return;
    const mine = ++allSeq.current;
    void window.tanwei
      .findings()
      .then((all) => {
        if (mine !== allSeq.current) return;
        setAllFindings(all);
        setAllLoaded(true);
        allAt.current = Date.now();
      })
      .catch(() => undefined);
  }, [scope, allLoaded, ctx.version]);

  const findings = !activeId ? [] : scope === "session" ? ctx.findings : allFindings;

  const state = live.find((s) => s.id === activeId);
  const graph = useMemo(() => buildAttackGraph(state), [state]);
  const view = useMemo(() => buildBlackboard(graph, findings), [graph, findings]);

  // 节点集合一变（新一步、新发现）就保留用户已经手动收起的，只补默认展开
  useEffect(() => {
    setOpen((prev) => ({ ...defaultOpen(view.sections), ...prev }));
  }, [view.sections]);

  const toggle = useCallback((id: string) => {
    setOpen((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const expandAll = () => {
    const next: Record<string, boolean> = {};
    for (const id of collectFoldable(view.sections)) next[id] = true;
    setOpen(next);
  };

  const collapseAll = () => setOpen({});

  const node = selected ? findNode(view.sections, selected) : undefined;

  const total = view.sections.reduce((n, s) => n + s.children.length, 0);

  return (
    <div className="bb-page">
      <div className="bb-top">
        <div className="bb-top-left">
          <span className="bb-session">
            <Icon name="chat" size={12} />
            <b>{state?.title || "未命名会话"}</b>
          </span>
          {state?.busy ? <span className="bb-live">跑着</span> : <span className="bb-idle">待命</span>}
        </div>
        <div className="bb-top-stats">
          <span>
            <b>{view.stats.hosts}</b> 主机
          </span>
          <span>
            <b>{view.stats.endpoints}</b> 接口
          </span>
          <span>
            <b>{view.stats.tests}</b> 步测试
          </span>
          <span className="c-hit">
            <b>{view.stats.hit}</b> 打穿
          </span>
          <span className="c-find">
            <b>{view.stats.findings}</b> 发现
          </span>
        </div>
        <div className="bb-top-ops">
          <button className="btn ghost sm" onClick={expandAll} disabled={!total}>
            展开全部
          </button>
          <button className="btn ghost sm" onClick={collapseAll} disabled={!total}>
            收起全部
          </button>
        </div>
      </div>

      <div className="bb-bar">
        <div className="bb-tabs">
          <button className={`bb-tab${tab === "board" ? " on" : ""}`} onClick={() => setTab("board")}>
            <Icon name="node" size={13} />
            <span>黑板节点</span>
          </button>
          <button className={`bb-tab${tab === "plan" ? " on" : ""}`} onClick={() => setTab("plan")}>
            <Icon name="layers" size={13} />
            <span>方向看板</span>
          </button>
        </div>
        <ScopeSwitch
          tasks={ctx.tasks}
          scope={scope}
          onScope={setScope}
          total={allLoaded ? allFindings.length : undefined}
          scoped={ctx.findings.length}
        />
      </div>

      {tab === "plan" ? (
        <AttackPlan live={live} activeId={activeId} onAsk={onAsk} />
      ) : !state ? (
        <div className="module-empty">先在左边选一个会话。黑板只记当前会话自己走过的路，不混别的会话。</div>
      ) : (
        <>
          {view.doing || view.next ? (
            <div className="bb-now">
              {view.doing ? (
                <div className="bb-now-row">
                  <span className="bb-now-tag live">正在做</span>
                  <span className="bb-now-text">{view.doing}</span>
                </div>
              ) : null}
              {view.next ? (
                <div className="bb-now-row">
                  <span className="bb-now-tag">下一步</span>
                  <span className="bb-now-text">{view.next}</span>
                </div>
              ) : null}
            </div>
          ) : null}

          <div className="bb-split">
            <div className="bb-tree">
              {view.sections.length === 0 ? (
                <div className="module-empty">
                  还没记上东西。会话每发一次请求、每读一份文件、每写一条结论，都会在这里落一个节点。
                </div>
              ) : (
                view.sections.map((section) => (
                  <div className="bb-section" key={section.id}>
                    <div
                      className={`bb-row bb-sec${open[section.id] ? " open" : ""}${selected === section.id ? " on" : ""}`}
                      onClick={() => {
                        setSelected(section.id);
                        toggle(section.id);
                      }}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          toggle(section.id);
                        }
                      }}
                    >
                      <span className={`bb-twisty has${open[section.id] ? " open" : ""}`}>
                        <Icon name="chevron" size={11} />
                      </span>
                      <span className="bb-sec-title">{section.title}</span>
                      <span className="bb-meta">{section.meta}</span>
                      <span className="bb-sec-count">{section.children.length}</span>
                    </div>
                    {open[section.id] ? (
                      <div className="bb-kids">
                        {section.children.map((child) => (
                          <NodeRow
                            key={child.id}
                            node={child}
                            depth={0}
                            open={open}
                            selected={selected}
                            onToggle={toggle}
                            onSelect={(n) => setSelected(n.id)}
                          />
                        ))}
                      </div>
                    ) : null}
                  </div>
                ))
              )}
            </div>

            <aside className="bb-side">
              {node ? (
                <>
                  <div className="bb-side-head">
                    <span className="bb-side-kind">{BB_KIND_LABEL[node.kind]}</span>
                    {node.badge ? <span className={`bb-badge t-${node.tone ?? "idle"}`}>{node.badge}</span> : null}
                  </div>
                  <div className="bb-side-title">{node.title}</div>
                  {node.meta ? <div className="bb-side-meta">{node.meta}</div> : null}
                  {node.detail ? <div className="bb-side-detail">{node.detail}</div> : null}

                  {node.rows?.length ? (
                    <div className="bb-kv">
                      {node.rows.map((r) => (
                        <div className="bb-kv-row" key={`${r.label}:${r.value}`}>
                          <span className="bb-kv-k">{r.label}</span>
                          <span className="bb-kv-v mono">{r.value}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {node.codes?.map((c) => (
                    <div className="bb-code" key={c.label}>
                      <span className="bb-code-label">{c.label}</span>
                      <pre className="bb-pre mono">{c.text}</pre>
                    </div>
                  ))}

                  <div className="bb-side-ops">
                    {node.prompt ? (
                      <button className="btn primary sm" onClick={() => onAsk(node.prompt!)}>
                        <Icon name="bolt" size={12} />
                        <span>{node.kind === "test" ? "漏洞复测" : "让 AI 接着打"}</span>
                      </button>
                    ) : null}
                    {node.filePath ? (
                      <>
                        <button
                          className="btn ghost sm"
                          onClick={() =>
                            setPreview({
                              path: node.filePath!,
                              name: node.filePath!.split(/[\\/]/).pop(),
                            })
                          }
                        >
                          <Icon name="file" size={12} />
                          <span>在线预览</span>
                        </button>
                        <button className="btn ghost sm" onClick={() => void window.tanwei.reveal(node.filePath!)}>
                          <Icon name="folder" size={12} />
                          <span>定位</span>
                        </button>
                      </>
                    ) : null}
                  </div>
                </>
              ) : (
                <>
                  <div className="bb-side-head">
                    <span className="bb-side-kind">怎么读</span>
                  </div>
                  <div className="bb-side-title">一个节点一件事</div>
                  <div className="bb-side-detail">
                    从上往下就是这次渗透走过的路。分区是「资产 / 测试方向 / 发现 / 结论 / 下一步」，点开任意节点看它到底做了什么、拿到了什么。
                    这里只记录，不改变 AI 的打法。
                  </div>
                  <div className="bb-kv">
                    <div className="bb-kv-row">
                      <span className="bb-kv-k">资产</span>
                      <span className="bb-kv-v">主机拆到接口，接口上标打过还是只认出来</span>
                    </div>
                    <div className="bb-kv-row">
                      <span className="bb-kv-k">方向</span>
                      <span className="bb-kv-v">未授权 / 换 ID / 注入 / SSRF / XSS / 上传 / 执行 / 逻辑</span>
                    </div>
                    <div className="bb-kv-row">
                      <span className="bb-kv-k">判定</span>
                      <span className="bb-kv-v">打穿 · 被拦 · 无异常 · 未命中 · 待判 · 失败</span>
                    </div>
                  </div>
                  <div className="bb-side-detail">
                    点节点右边会出现「漏洞复测 / 让 AI 接着打」，把这一条的上下文带回会话，不用自己重述。
                  </div>
                </>
              )}
            </aside>
          </div>
        </>
      )}

      <FileViewer file={preview} onClose={() => setPreview(null)} />
    </div>
  );
}
