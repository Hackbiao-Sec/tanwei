import React, { useState } from "react";
import type { SessionState } from "@shared/types";
import { Icon } from "./Icons";
import { AttackPlan } from "./AttackPlan";
import {
  buildAttackGraph,
  STATUS_LABEL,
  VERDICT_LABEL,
  type AttackDirection,
  type AttackTest,
  type TestVerdict,
} from "../lib/attackPlan";

const LANE_W = 296;
const LANE_GAP = 16;
const PAD = 14;
const HEAD_H = 50;
const NODE_H = 78;
const NODE_GAP = 20;
const MAX_PER_LANE = 14;

const STATUS_RANK: Record<string, number> = { running: 0, hit: 1, unclear: 2, planned: 3, excluded: 4 };

/** 中文字宽按两个单位算，用来把节点里的长句裁到框内 */
function units(text: string): number {
  let n = 0;
  for (const ch of text) n += /[\u2e80-\uffff]/.test(ch) ? 2 : 1;
  return n;
}

function fitText(text: string, maxUnits: number): string {
  const clean = (text ?? "").replace(/\s+/g, " ").trim();
  if (!clean) return "";
  if (units(clean) <= maxUnits) return clean;
  let out = "";
  let used = 0;
  for (const ch of clean) {
    const w = /[\u2e80-\uffff]/.test(ch) ? 2 : 1;
    if (used + w > maxUnits - 1) break;
    out += ch;
    used += w;
  }
  return `${out}…`;
}

function lineText(test: AttackTest): string {
  const target = test.path ?? test.host ?? "";
  const head = `#${test.round}`;
  const verb = test.method ? `${test.method} ` : "";
  return `${head}  ${verb}${target}`.trim();
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
  const [tab, setTab] = useState<"surface" | "plan">("surface");
  const [selected, setSelected] = useState<string>();

  // 时间线是就地改写的，每次重渲染直接推导，攻击面只认当前这一个会话
  const state = live.find((s) => s.id === activeId);
  const graph = buildAttackGraph(state);
  const selectedTest = graph.tests.find((t) => t.id === selected);

  const lanes = graph.directions
    .filter((dir) => dir.tests.length > 0)
    .slice()
    .sort((a, b) => {
      const rank = (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9);
      return rank !== 0 ? rank : b.lastAt - a.lastAt;
    });

  const maxNodes = lanes.reduce((n, dir) => Math.max(n, Math.min(dir.tests.length, MAX_PER_LANE) + (dir.tests.length > MAX_PER_LANE ? 1 : 0)), 0);
  const width = Math.max(360, PAD * 2 + Math.max(lanes.length, 1) * (LANE_W + LANE_GAP) - LANE_GAP);
  const height = PAD * 2 + HEAD_H + Math.max(maxNodes, 1) * (NODE_H + NODE_GAP);

  const counts = graph.counts;
  const blocked = graph.tests.filter((t) => t.verdict === "blocked").length;

  const askTest = (test: AttackTest) => {
    const target = test.path ?? test.host ?? "";
    onAsk(
      [
        `漏洞复测：${test.method ? `${test.method} ` : ""}${target}`.trim(),
        test.result ? `这一步上次的结果是：${test.result}` : "",
        `按上一次的判定换一组参数再复测一遍：没打到就补探针，被拦就换位置和编码，出数就把对象换掉看别人的。`,
      ]
        .filter(Boolean)
        .join("\n"),
    );
  };

  const renderLane = (dir: AttackDirection, index: number) => {
    const x = PAD + index * (LANE_W + LANE_GAP);
    const shown = dir.tests.slice(0, MAX_PER_LANE);
    const rest = dir.tests.length - shown.length;
    const nodes = shown.length + (rest > 0 ? 1 : 0);
    return (
      <g key={dir.id} className={`sv-lane ${dir.def.cls}`}>
        <rect x={x} y={PAD} width={LANE_W} height={HEAD_H - 14} rx={7} className="sv-head" />
        <text x={x + 12} y={PAD + 22} className="sv-head-title">
          {fitText(dir.def.label, 20)}
        </text>
        <text x={x + LANE_W - 12} y={PAD + 22} className="sv-head-meta" textAnchor="end">
          {STATUS_LABEL[dir.status]} · {dir.tests.length} 步
        </text>
        {Array.from({ length: nodes }).map((_, i) => {
          const test = shown[i];
          const y = PAD + HEAD_H + i * (NODE_H + NODE_GAP);
          if (!test) {
            return (
              <g key={`${dir.id}-rest`} className="sv-node is-rest">
                <rect x={x} y={y} width={LANE_W} height={NODE_H} rx={8} />
                <text x={x + 14} y={y + 44} className="sv-title">
                  前面还有 {rest} 步
                </text>
                <text x={x + 14} y={y + 62} className="sv-result">
                  去「渗透方向」看完整黑板
                </text>
              </g>
            );
          }
          const on = test.id === selected;
          return (
            <g
              key={test.id}
              className={`sv-node v-${test.verdict}${on ? " on" : ""}`}
              onClick={() => setSelected(on ? undefined : test.id)}
            >
              <rect x={x} y={y} width={LANE_W} height={NODE_H} rx={8} />
              <rect x={x} y={y} width={3} height={NODE_H} rx={1.5} className="sv-bar" />
              <text x={x + 14} y={y + 22} className="sv-title mono">
                {fitText(lineText(test), 27)}
              </text>
              <text x={x + LANE_W - 12} y={y + 22} className="sv-verdict" textAnchor="end">
                {VERDICT_LABEL[test.verdict]}
              </text>
              <text x={x + 14} y={y + 44} className="sv-desc">
                {fitText(test.description, 30)}
              </text>
              <text x={x + 14} y={y + 64} className="sv-result">
                {fitText(test.result || "还没拿到回包", 44)}
              </text>
            </g>
          );
        })}
        {nodes > 1
          ? Array.from({ length: nodes - 1 }).map((_, i) => {
              const y = PAD + HEAD_H + i * (NODE_H + NODE_GAP) + NODE_H;
              return (
                <line
                  key={`${dir.id}-edge-${i}`}
                  x1={x + LANE_W / 2}
                  y1={y}
                  x2={x + LANE_W / 2}
                  y2={y + NODE_GAP}
                  className="sv-edge"
                />
              );
            })
          : null}
      </g>
    );
  };

  return (
    <div className="graph-page">
      <div className="graph-tabs">
        <button
          type="button"
          className={`graph-tab${tab === "surface" ? " on" : ""}`}
          onClick={() => setTab("surface")}
        >
          <Icon name="radar" size={13} />
          <span>攻击面</span>
        </button>
        <button
          type="button"
          className={`graph-tab${tab === "plan" ? " on" : ""}`}
          onClick={() => setTab("plan")}
        >
          <Icon name="layers" size={13} />
          <span>渗透方向</span>
        </button>
      </div>

      {tab === "plan" ? (
        <AttackPlan live={live} activeId={activeId} onAsk={onAsk} />
      ) : !state ? (
        <div className="module-empty">先在左边选一个会话。攻击面只画当前会话自己的步骤，不汇总别的会话。</div>
      ) : (
        <div className="surface-wrap">
          <div className="surface-bar">
            <span className="surface-session">
              <Icon name="chat" size={12} />
              <b>{state.title || "未命名会话"}</b>
            </span>
            <span className="surface-tag">只看本会话</span>
            <div className="surface-counts">
              <span>
                <b>{counts.tests}</b> 步
              </span>
              <span className="c-hit">
                <b>{counts.hit}</b> 打穿
              </span>
              <span className="c-blocked">
                <b>{blocked}</b> 被拦
              </span>
              <span>
                <b>{counts.endpoints}</b> 接口
              </span>
              {counts.running ? (
                <span className="c-running">
                  <b>{counts.running}</b> 进行中
                </span>
              ) : null}
            </div>
            <span className="surface-hint">
              {graph.busy ? "跑着的时候会自己长出新节点" : "每个节点是一步实际动作，点开看结果和回包"}
            </span>
          </div>

          {graph.tests.length === 0 ? (
            <div className="module-empty">
              这个会话还没有攻击步骤。让探微跑起来，每发一次请求、每读一次文件，都会作为一步节点画到这里。
            </div>
          ) : (
            <div className="surface-split">
              <div className="surface-canvas">
                <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" aria-label="本会话攻击步骤图谱">
                  {lanes.map(renderLane)}
                </svg>
              </div>
              <aside className="surface-side">
                {selectedTest ? (
                  <>
                    <div className="pg-side-head">
                      <span className={`pdt-verdict ${selectedTest.verdict}`}>
                        {VERDICT_LABEL[selectedTest.verdict]}
                      </span>
                      <span className="pgt-meta">第 {selectedTest.round} 轮</span>
                    </div>
                    <div className="pg-side-title">{selectedTest.description}</div>
                    <div className="pg-side-sub">
                      {selectedTest.method ? `${selectedTest.method} ` : ""}
                      {selectedTest.path ?? selectedTest.host ?? selectedTest.title}
                    </div>
                    <div className="pg-side-block">
                      <span className="pg-side-label">结果</span>
                      <div className={`pg-side-result ${selectedTest.verdict}`}>
                        {selectedTest.result || "还没拿到回包"}
                      </div>
                    </div>
                    {selectedTest.probe || selectedTest.params.length ? (
                      <div className="pg-side-block">
                        <span className="pg-side-label">动作 / 线索</span>
                        <div className="pg-side-sub mono">
                          {[
                            selectedTest.kind,
                            selectedTest.probe,
                            selectedTest.params.length ? `参数 ${selectedTest.params.join(" / ")}` : "",
                          ]
                            .filter(Boolean)
                            .join(" · ")}
                        </div>
                      </div>
                    ) : null}
                    {selectedTest.hosts.length ? (
                      <div className="pg-side-block">
                        <span className="pg-side-label">主机</span>
                        <div className="pg-host-row">
                          {selectedTest.hosts.map((host) => (
                            <span className="pg-host" key={host}>
                              <Icon name="plug" size={11} />
                              <span className="mono">{host}</span>
                            </span>
                          ))}
                        </div>
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
                    <div className="pg-side-block" style={{ display: "flex", gap: 8 }}>
                      <button type="button" className="btn primary sm" onClick={() => askTest(selectedTest)}>
                        <Icon name="bolt" size={12} />
                        <span>漏洞复测</span>
                      </button>
                      <button type="button" className="btn ghost sm" onClick={() => setSelected(undefined)}>
                        <Icon name="close" size={12} />
                        <span>收起</span>
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="pg-side-head">
                      <div>
                        <div className="pg-side-title">本会话图谱</div>
                        <div className="pg-side-sub">
                          {counts.tests} 步 · {counts.endpoints} 个接口 · {graph.hosts.length} 个主机
                        </div>
                      </div>
                    </div>
                    <div className="pg-side-block">
                      <span className="pg-side-label">怎么读</span>
                      <div className="pg-side-sub">
                        一列是一个方向，一列里从上往下就是实测顺序。节点上写的是这一步做了什么、拿到了什么，颜色代表判定。
                      </div>
                    </div>
                    <div className="pg-side-block">
                      <span className="pg-side-label">判定统计</span>
                      <div className="surface-legend">
                        {(["hit", "blocked", "clean", "missed", "unclear", "failed", "running"] as TestVerdict[])
                          .map((v) => ({ v, n: graph.tests.filter((t) => t.verdict === v).length }))
                          .filter((d) => d.n > 0)
                          .map((d) => (
                            <span key={d.v} className={`pdt-verdict ${d.v}`}>
                              {VERDICT_LABEL[d.v]} {d.n}
                            </span>
                          ))}
                      </div>
                    </div>
                    {graph.endpoints.length ? (
                      <div className="pg-side-block">
                        <span className="pg-side-label">摸到的接口</span>
                        {graph.endpoints.slice(0, 8).map((ep) => (
                          <div className="surface-ep" key={ep.key}>
                            <span className="mono">{fitText(`${ep.method ?? ""} ${ep.path}`, 34)}</span>
                            <span className={`pdt-verdict ${ep.verdict}`}>{VERDICT_LABEL[ep.verdict]}</span>
                          </div>
                        ))}
                      </div>
                    ) : null}
                    <div className="pg-side-sub">点任意节点看这一步的结果、参数和回包。</div>
                  </>
                )}
              </aside>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
