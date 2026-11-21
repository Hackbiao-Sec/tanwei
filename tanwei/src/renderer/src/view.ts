import type { IconName } from "./components/Icons";

export type ModuleId =
  | "dashboard"
  | "findings"
  | "graph"
  | "tasks"
  | "assets"
  | "files"
  | "traffic"
  | "mini"
  | "app"
  | "reports"
  | "skills"
  | "tools"
  | "rules"
  | "mcp"
  | "logs"
  | "models"
  | "proxy"
  | "notify"
  | "settings";

export type View = { kind: "session" } | { kind: "module"; id: ModuleId };

export type ModuleGroupId = "situation" | "fight" | "config";

export interface ModuleGroup {
  id: ModuleGroupId;
  label: string;
  hint: string;
  icon: IconName;
}

/** 二级菜单：先分三大块，再在块里挑页面，避免一级塞 17 个按钮 */
export const MODULE_GROUPS: ModuleGroup[] = [
  { id: "situation", label: "态势", hint: "看结果：发现、资产、文件", icon: "grid" },
  { id: "fight", label: "作战", hint: "看过程：图谱、任务、流量、报告", icon: "radar" },
  { id: "config", label: "配置", hint: "模型、代理、告警、技能与规则", icon: "settings" },
];

export interface ModuleDef {
  id: ModuleId;
  label: string;
  icon: IconName;
  desc: string;
  group: ModuleGroupId;
  /** 二级菜单里的短说明，比 desc 更短，只占一行 */
  short: string;
}

export const MODULES: ModuleDef[] = [
  { id: "dashboard", label: "总览", icon: "grid", desc: "发现、资产、会话的全局态势", group: "situation", short: "全局数字" },
  { id: "findings", label: "发现", icon: "shield", desc: "已落盘漏洞，按等级汇总", group: "situation", short: "漏洞清单" },
  { id: "assets", label: "资产", icon: "folder", desc: "域名 / IP / 接口，按主机归类", group: "situation", short: "资产图谱" },
  { id: "files", label: "文件", icon: "file", desc: "任务夹产物，在线预览", group: "situation", short: "产物文件" },
  { id: "reports", label: "报告", icon: "file", desc: "已落盘的正式报告", group: "situation", short: "正式报告" },
  { id: "graph", label: "图谱", icon: "radar", desc: "黑板式记录：一个节点一件事", group: "fight", short: "黑板节点" },
  { id: "tasks", label: "任务", icon: "bolt", desc: "会话即任务，看状态与用量", group: "fight", short: "会话任务" },
  { id: "traffic", label: "流量", icon: "send", desc: "HTTP 请求重放与响应查看", group: "fight", short: "请求重放" },
  { id: "mini", label: "小程序", icon: "mini", desc: "扫小程序工程与 wxapkg，拆页面、分包、接口与云开发", group: "fight", short: "小程序" },
  { id: "app", label: "APP", icon: "android", desc: "拆 APK / IPA，导出组件真实拉起，动态抓包与 hook", group: "fight", short: "APP" },
  { id: "models", label: "模型", icon: "cpu", desc: "自定义模型与 API 端点", group: "config", short: "模型端点" },
  { id: "proxy", label: "代理", icon: "globe", desc: "付费配置 / 免费节点、测速与自动轮换", group: "config", short: "代理池" },
  { id: "notify", label: "告警", icon: "bell", desc: "钉钉、飞书、Webhook 通知与测试", group: "config", short: "通知渠道" },
  { id: "mcp", label: "MCP", icon: "plug", desc: "服务与工具接入状态", group: "config", short: "服务接入" },
  { id: "skills", label: "技能", icon: "layers", desc: "grok / claude 技能包", group: "config", short: "技能包" },
  { id: "tools", label: "工具", icon: "terminal", desc: "引擎可用命令与工具", group: "config", short: "命令工具" },
  { id: "rules", label: "规则", icon: "shield", desc: "永久生效的强制规则", group: "config", short: "强制规则" },
  { id: "logs", label: "日志", icon: "file", desc: "引擎、MCP 与启动日志", group: "config", short: "运行日志" },
  { id: "settings", label: "设置", icon: "settings", desc: "引擎、路径与原生入口", group: "config", short: "路径引擎" },
];

export const MODULE_MAP = new Map(MODULES.map((m) => [m.id, m]));

export function modulesOf(group: ModuleGroupId): ModuleDef[] {
  return MODULES.filter((m) => m.group === group);
}
