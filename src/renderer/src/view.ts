import type { IconName } from "./components/Icons";

export type ModuleId =
  | "dashboard"
  | "findings"
  | "graph"
  | "tasks"
  | "assets"
  | "traffic"
  | "reports"
  | "skills"
  | "tools"
  | "rules"
  | "mcp"
  | "logs"
  | "models"
  | "settings";

export type View = { kind: "session" } | { kind: "module"; id: ModuleId };

export interface ModuleDef {
  id: ModuleId;
  label: string;
  icon: IconName;
  desc: string;
  group: "作战" | "配置";
}

export const MODULES: ModuleDef[] = [
  { id: "dashboard", label: "总览", icon: "grid", desc: "发现、资产、会话的全局态势", group: "作战" },
  { id: "findings", label: "发现", icon: "shield", desc: "已落盘漏洞，按等级汇总", group: "作战" },
  { id: "graph", label: "图谱", icon: "radar", desc: "任务、主机、漏洞的攻击面关系", group: "作战" },
  { id: "tasks", label: "任务", icon: "bolt", desc: "会话即任务，看状态与用量", group: "作战" },
  { id: "assets", label: "资产", icon: "folder", desc: "任务夹里的可挖面", group: "作战" },
  { id: "traffic", label: "流量", icon: "send", desc: "HTTP 请求重放与响应查看", group: "作战" },
  { id: "reports", label: "报告", icon: "file", desc: "已落盘的正式报告", group: "作战" },
  { id: "skills", label: "技能", icon: "layers", desc: "grok / claude 技能包", group: "配置" },
  { id: "tools", label: "工具", icon: "terminal", desc: "引擎可用命令与工具", group: "配置" },
  { id: "rules", label: "规则", icon: "shield", desc: "永久生效的强制规则", group: "配置" },
  { id: "mcp", label: "MCP", icon: "plug", desc: "服务与工具接入状态", group: "配置" },
  { id: "logs", label: "日志", icon: "file", desc: "引擎、MCP 与启动日志", group: "配置" },
  { id: "models", label: "模型", icon: "cpu", desc: "自定义模型与 API 端点", group: "配置" },
  { id: "settings", label: "设置", icon: "settings", desc: "引擎、路径与原生入口", group: "配置" },
];
