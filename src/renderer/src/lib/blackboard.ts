import type { Finding } from "@shared/types";
import {
  DIRECTION_MAP,
  GAIN_LABEL,
  STATUS_LABEL,
  VERDICT_LABEL,
  type AttackGraphData,
  type AttackTest,
  type DirectionId,
  type TestVerdict,
} from "./attackPlan";

/**
 * 黑板式节点树：只负责把已经发生的动作记录成可读节点，不参与任何决策。
 * 一个节点 = 一件事（一台主机 / 一个接口 / 一个方向 / 一步测试 / 一条发现）。
 */
export type BBKind =
  | "session"
  | "host"
  | "endpoint"
  | "intent"
  | "test"
  | "gain"
  | "finding"
  | "conclusion"
  | "next";

export type BBTone = TestVerdict | "idle" | "high" | "medium" | "low";

export interface BBRow {
  label: string;
  value: string;
}

export interface BBCode {
  label: string;
  text: string;
}

export interface BBNode {
  id: string;
  kind: BBKind;
  title: string;
  /** 一行补充：目标、轮次、次数 */
  meta?: string;
  /** 右侧小徽标文字 */
  badge?: string;
  tone?: BBTone;
  at?: number;
  detail?: string;
  rows?: BBRow[];
  codes?: BBCode[];
  children: BBNode[];
  direction?: DirectionId;
  host?: string;
  /** 有实体文件时（报告）给在线预览用 */
  filePath?: string;
  /** 点「复测 / 继续这个方向」时交给 AI 的话 */
  prompt?: string;
}

const KIND_TITLE: Record<BBKind, string> = {
  session: "会话",
  host: "主机",
  endpoint: "接口",
  intent: "方向",
  test: "测试",
  gain: "成果",
  finding: "发现",
  conclusion: "结论",
  next: "下一步",
};

export const BB_KIND_LABEL = KIND_TITLE;

function ts(t?: number): string {
  if (!t) return "";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function oneLine(text: string, max = 90): string {
  const clean = (text ?? "").replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

function testNode(test: AttackTest): BBNode {
  const def = DIRECTION_MAP[test.direction];
  const target = test.path ?? test.host ?? "";
  const rows: BBRow[] = [
    { label: "方向", value: def?.label ?? test.direction },
    { label: "目标", value: [test.method, target].filter(Boolean).join(" ") || "—" },
  ];
  if (test.hosts.length) rows.push({ label: "主机", value: test.hosts.join(" / ") });
  if (test.params.length) rows.push({ label: "参数", value: test.params.join(" / ") });
  if (test.probe) rows.push({ label: "探针", value: test.probe });
  if (test.kind) rows.push({ label: "动作", value: test.kind });
  rows.push({ label: "结果", value: test.result || "还没拿到回包" });
  rows.push({ label: "工具", value: test.title });
  if (test.at) rows.push({ label: "时间", value: ts(test.at) });

  const codes: BBCode[] = [];
  if (test.input) codes.push({ label: "请求 / 输入", text: test.input });
  if (test.output) codes.push({ label: "回包 / 证据", text: test.output });

  return {
    id: `test:${test.id}`,
    kind: "test",
    title: test.description || oneLine(test.title),
    meta: `第 ${test.round} 轮${target ? ` · ${oneLine(target, 60)}` : ""}`,
    badge: VERDICT_LABEL[test.verdict],
    tone: test.verdict,
    at: test.at,
    rows,
    codes,
    children: [],
    direction: test.direction,
    prompt: [
      `漏洞复测：${[test.method, target].filter(Boolean).join(" ")}`,
      test.result ? `上一次的结果是：${test.result}` : "",
      "按上一次的判定换一组参数再打一遍：没打通就补探针，被拦就换位置和编码，出数就把对象换掉看别人的。",
    ]
      .filter(Boolean)
      .join("\n"),
  };
}

function hostNode(
  host: string,
  graph: AttackGraphData,
  endpoints: AttackGraphData["endpoints"],
  tests: AttackTest[],
): BBNode {
  const eps = endpoints.filter((ep) => (ep.host ?? "").toLowerCase() === host.toLowerCase());
  const hostTests = tests.filter((t) => t.hosts.some((h) => h.toLowerCase() === host.toLowerCase()));
  const hitCount = hostTests.filter((t) => t.verdict === "hit").length;
  const children = [
    ...eps.map<BBNode>((ep) => ({
      id: `endpoint:${ep.key}`,
      kind: "endpoint",
      title: `${ep.method ? `${ep.method.toUpperCase()} ` : ""}${ep.path}`,
      meta: `${ep.count} 次 · ${ep.status === "called" ? "已打过" : "已认出未打"}${ep.result ? ` · ${oneLine(ep.result, 46)}` : ""}`,
      badge: ep.status === "called" ? VERDICT_LABEL[ep.verdict] : "未打",
      tone: ep.status === "called" ? ep.verdict : "idle",
      at: ep.lastAt,
      host: ep.host ?? host,
      rows: [
        { label: "主机", value: ep.host ?? host },
        { label: "接口", value: `${ep.method ? `${ep.method.toUpperCase()} ` : ""}${ep.path}` },
        { label: "状态", value: ep.status === "called" ? "真打过" : "从前端或回包里认出来，还没打" },
        { label: "次数", value: String(ep.count) },
        { label: "最后结果", value: ep.result || "—" },
        { label: "方向", value: ep.directions.map((d) => DIRECTION_MAP[d]?.label ?? d).join(" / ") || "—" },
        { label: "来源", value: ep.source },
        { label: "最后时间", value: ts(ep.lastAt) },
      ],
      children: [],
      direction: ep.directions[0],
      prompt: [
        `针对这个接口继续测：${ep.method ? `${ep.method.toUpperCase()} ` : ""}${ep.host ? `https://${ep.host}` : ""}${ep.path}`,
        ep.result ? `上次结果：${ep.result}` : "还没打过，先建基线。",
        "按全类型矩阵打：未授权、换 id、注入四件套（按栈选探针）、SSRF/XSS/RCE 有入口就跟到执行。",
      ].join("\n"),
    })),
    ...hostTests.map(testNode),
  ];
  return {
    id: `host:${host}`,
    kind: "host",
    title: host,
    meta: `${eps.length} 个接口 · ${hostTests.length} 步测试${hitCount ? ` · ${hitCount} 打穿` : ""}`,
    badge: hitCount ? "有命中" : eps.length ? "有接口" : "只提到",
    tone: hitCount ? "hit" : "idle",
    host,
    rows: [
      { label: "主机", value: host },
      { label: "接口", value: String(eps.length) },
      { label: "测试", value: String(hostTests.length) },
      { label: "打穿", value: String(hitCount) },
    ],
    prompt: `以 ${host} 这一台为目标继续：先过未登录面，再打换 id、注入、SSRF、XSS、RCE，打成落报告。`,
    children,
  };
}

function directionNode(dir: AttackGraphData["directions"][number]): BBNode {
  const gains = dir.gains.map<BBNode>((g) => ({
    id: `gain:${g.id}`,
    kind: "gain",
    title: g.title,
    meta: [g.host, g.detail ? oneLine(g.detail, 60) : ""].filter(Boolean).join(" · "),
    badge: GAIN_LABEL[g.kind],
    tone: g.kind === "hit" ? "hit" : g.kind === "report" ? "clean" : "unclear",
    at: g.at,
    detail: g.detail,
    children: [],
    direction: g.direction,
  }));
  const tests = dir.tests.map(testNode);
  return {
    id: `intent:${dir.id}`,
    kind: "intent",
    title: dir.def.label,
    meta: dir.summary || `${dir.tests.length} 步`,
    badge: STATUS_LABEL[dir.status],
    tone:
      dir.status === "hit"
        ? "hit"
        : dir.status === "running"
          ? "running"
          : dir.status === "excluded"
            ? "clean"
            : "unclear",
    at: dir.lastAt,
    detail: dir.def.goal,
    direction: dir.id,
    rows: [
      { label: "目标", value: dir.def.goal },
      { label: "状态", value: STATUS_LABEL[dir.status] },
      { label: "步骤", value: `${dir.tests.length} 步${dir.trimmed ? `（另有 ${dir.trimmed} 步已折叠）` : ""}` },
      { label: "主机", value: dir.hosts.join(" / ") || "—" },
      { label: "打穿", value: String(dir.verdicts.hit ?? 0) },
      { label: "最后动作", value: ts(dir.lastAt) },
    ],
    prompt: `继续「${dir.def.label}」这个方向：${dir.def.goal}。别停在列表，往写、跨用户、接管、可执行上打，打成落报告。`,
    children: [...gains, ...tests],
  };
}

function findingNode(f: Finding): BBNode {
  const tone: BBTone =
    f.severity === "严重" || f.severity === "高危" ? "high" : f.severity === "中危" ? "medium" : "low";
  return {
    id: `finding:${f.path}`,
    kind: "finding",
    title: f.title,
    meta: [f.type, f.target].filter(Boolean).join(" · "),
    badge: f.severity,
    tone,
    at: f.updatedAt,
    filePath: f.path,
    rows: [
      { label: "等级", value: f.severity },
      { label: "类型", value: f.type || "—" },
      { label: "目标", value: f.target || "—" },
      { label: "任务", value: f.task },
      { label: "报告", value: f.path },
      { label: "时间", value: ts(f.updatedAt) },
    ],
    children: [],
  };
}

export interface BBStats {
  hosts: number;
  endpoints: number;
  tests: number;
  hit: number;
  gains: number;
  findings: number;
}

export interface BBView {
  sections: BBNode[];
  stats: BBStats;
  doing?: string;
  next?: string;
}

/** 把攻击图谱 + 本会话报告拼成黑板树。findings 已按会话隔离，这里不再自己挑任务。 */
export function buildBlackboard(graph: AttackGraphData, findings: Finding[]): BBView {
  const hosts = graph.hosts
    .map((h) => hostNode(h.host, graph, graph.endpoints, graph.tests))
    .sort((a, b) => b.children.length - a.children.length);

  const intents = graph.directions
    .filter((d) => d.tests.length > 0 || d.gains.length > 0)
    .slice()
    .sort((a, b) => b.lastAt - a.lastAt)
    .map(directionNode);

  const conclusions: BBNode[] = graph.conclusions
    .slice()
    .sort((a, b) => b.at - a.at)
    .slice(0, 40)
    .map((c) => ({
      id: `conclusion:${c.id}`,
      kind: "conclusion",
      title: oneLine(c.title, 110),
      meta: [c.direction ? DIRECTION_MAP[c.direction]?.label : "", ts(c.at)].filter(Boolean).join(" · "),
      badge: c.streaming ? "写下中" : "结论",
      tone: "unclear",
      at: c.at,
      detail: c.text,
      direction: c.direction,
      children: [],
    }));

  const next: BBNode[] = graph.next.slice(0, 12).map((n, i) => ({
    id: `next:${n.id || i}`,
    kind: "next",
    title: oneLine(n.text, 130),
    meta: n.direction ? DIRECTION_MAP[n.direction]?.label : n.source === "plan" ? "计划" : "模型给的下一步",
    badge: "待做",
    tone: "idle",
    direction: n.direction,
    prompt: n.text,
    children: [],
  }));

  const findingNodes = findings
    .slice()
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map(findingNode);

  const section = (id: string, kind: BBKind, title: string, meta: string, children: BBNode[]): BBNode => ({
    id: `section:${id}`,
    kind,
    title,
    meta,
    children,
  });

  const sections = [
    section("hosts", "host", "资产", `${hosts.length} 台主机 · ${graph.endpoints.length} 个接口`, hosts),
    section("intents", "intent", "测试方向", `${intents.length} 个方向 · ${graph.tests.length} 步`, intents),
    section("findings", "finding", "发现", `${findingNodes.length} 篇报告`, findingNodes),
    section("conclusions", "conclusion", "结论", `${conclusions.length} 条`, conclusions),
    section("next", "next", "下一步", `${next.length} 条`, next),
  ].filter((s) => s.children.length > 0);

  const stats: BBStats = {
    hosts: hosts.length,
    endpoints: graph.endpoints.length,
    tests: graph.tests.length,
    hit: graph.tests.filter((t) => t.verdict === "hit").length,
    gains: graph.gains.length,
    findings: findingNodes.length,
  };

  const board = graph.blackboard;
  return {
    sections,
    stats,
    doing: board.doing ? `${board.doing.label}：${board.doing.text}` : undefined,
    next: board.next,
  };
}

/** 展开/收起时按 id 收集全部可折叠节点 */
export function collectFoldable(nodes: BBNode[], out: string[] = []): string[] {
  for (const n of nodes) {
    if (n.children.length) {
      out.push(n.id);
      collectFoldable(n.children, out);
    }
  }
  return out;
}

/** 默认折叠：只展开一级分区，节点多的方向/主机先收起 */
export function defaultOpen(nodes: BBNode[]): Record<string, boolean> {
  const open: Record<string, boolean> = {};
  for (const n of nodes) {
    if (n.id.startsWith("section:")) open[n.id] = true;
    else if (n.children.length && n.children.length <= 4) open[n.id] = true;
  }
  return open;
}

/** 找一条节点（右侧详情要按 id 取回完整节点） */
export function findNode(nodes: BBNode[], id: string): BBNode | undefined {
  for (const n of nodes) {
    if (n.id === id) return n;
    const hit = findNode(n.children, id);
    if (hit) return hit;
  }
  return undefined;
}
