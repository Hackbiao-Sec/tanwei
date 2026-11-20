import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { McpProbeInput, McpProbeResult } from "../shared/types";
import { networkStatus, proxyEnv } from "./proxy";

/**
 * MCP 连接测试：自己拉起服务端进程走一遍 stdio 握手（initialize → initialized → tools/list），
 * 不依赖引擎重启，配置错了能立刻看到原因。
 */

const PROTOCOL_VERSION = "2024-11-05";
const CLIENT_INFO = { name: "tanwei-console", version: "0.1.0" };
const STDERR_LIMIT = 4000;
const TOOL_LIMIT = 200;
const DEFAULT_TIMEOUT = 30_000;

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n));
}

/** 从 extra 的原文里读 startup_timeout_sec，装依赖的慢服务给它更长的握手窗口 */
function timeoutOf(input: McpProbeInput): number {
  if (input.timeoutMs && input.timeoutMs > 0) return clamp(input.timeoutMs, 5_000, 180_000);
  const m = /^\s*startup_timeout_sec\s*=\s*(\d+)\s*$/m.exec(input.extra ?? "");
  if (m) return clamp(Number(m[1]) * 1000, 15_000, 120_000);
  return DEFAULT_TIMEOUT;
}

/** Windows 上 .cmd/.bat 必须经 cmd.exe 才能起，直接 spawn 会 ENOENT */
function needsShell(command: string): boolean {
  return /\.(cmd|bat)$/i.test(command) || !/\.(exe|com)$/i.test(command);
}

function quoteWin(arg: string): string {
  if (arg === "") return '""';
  if (!/[\s"&|<>^()]/.test(arg)) return arg;
  return `"${arg.replace(/"/g, '\\"')}"`;
}

function shellLine(command: string, args: string[]): string {
  return [command, ...args].map(quoteWin).join(" ");
}

type Launched = { child: ChildProcess; viaShell: boolean };

function launch(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): Launched {
  if (process.platform === "win32" && needsShell(command)) {
    const comspec = process.env.ComSpec || "cmd.exe";
    // /s 会剥掉最外层引号，所以整条命令行再包一层，带空格的绝对路径才不会被切坏
    const child = spawn(comspec, ["/d", "/s", "/c", `"${shellLine(command, args)}"`], {
      cwd,
      env,
      windowsHide: true,
      windowsVerbatimArguments: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { child, viaShell: true };
  }
  const child = spawn(command, args, {
    cwd,
    env,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { child, viaShell: false };
}

/** 连同 npx/cmd 拉起的孙子进程一起收掉，避免留下孤儿 */
function killTree(child: ChildProcess): void {
  const pid = child.pid;
  if (!pid) return;
  if (process.platform === "win32") {
    spawn("taskkill", ["/pid", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    return;
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Windows 命令行的报错多是 GBK；按 UTF-8 读出替换符时退回 GBK，免得面板上全是乱码 */
function decodeText(buf: Buffer): string {
  const utf8 = buf.toString("utf8");
  if (!utf8.includes("\uFFFD")) return utf8;
  try {
    return new TextDecoder("gbk").decode(buf);
  } catch {
    return utf8;
  }
}

export async function probeMcpServer(input: McpProbeInput): Promise<McpProbeResult> {
  const started = Date.now();
  const command = (input.command ?? "").trim();
  const args = (input.args ?? []).map((a) => String(a));
  const fail = (error: string, stderr?: string): McpProbeResult => ({
    ok: false,
    latencyMs: Date.now() - started,
    error,
    ...(stderr ? { stderr } : {}),
  });

  if (!command) return fail("启动命令为空：先填 command 再测试");
  const cwd = (input.cwd ?? "").trim() || process.cwd();
  try {
    if (!fs.statSync(cwd).isDirectory()) return fail(`工作目录不是文件夹：${cwd}`);
  } catch {
    return fail(`工作目录不存在：${cwd}`);
  }

  const net = await networkStatus().catch(() => undefined);
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...(net ? proxyEnv(net.effective) : {}),
    GROK_DISABLE_AUTOUPDATER: "1",
    ...(input.env ?? {}),
  };

  const timeoutMs = timeoutOf(input);
  let launched: Launched;
  try {
    launched = launch(command, args, cwd, env);
  } catch (err) {
    return fail(`启动失败：${errText(err)}`);
  }

  const { child } = launched;
  let stderr = "";
  const errChunks: Buffer[] = [];
  child.stderr?.on("data", (chunk: Buffer) => {
    errChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    let total = errChunks.reduce((n, b) => n + b.length, 0);
    while (total > STDERR_LIMIT * 2 && errChunks.length > 1) total -= errChunks.shift()!.length;
    stderr = decodeText(Buffer.concat(errChunks)).slice(-STDERR_LIMIT);
  });

  return await new Promise<McpProbeResult>((resolve) => {
    let settled = false;
    let buffer = "";
    let exitCode: number | null = null;
    let initInfo: { protocolVersion?: string; name?: string; version?: string } = {};
    let tools: string[] = [];
    let toolCount = 0;

    const finish = (result: McpProbeResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout?.removeAllListeners();
      child.stderr?.removeAllListeners();
      child.removeAllListeners();
      try {
        child.stdin?.end();
      } catch {
        /* pipe already closed */
      }
      killTree(child);
      resolve({ ...result, latencyMs: Date.now() - started, ...(stderr ? { stderr } : {}) });
    };

    const timer = setTimeout(() => {
      const detail = exitCode === null ? `握手超时（${Math.round(timeoutMs / 1000)}s）` : `进程已退出（code ${exitCode}）`;
      finish(fail(detail));
    }, timeoutMs);

    const write = (payload: Record<string, unknown>) => {
      if (!child.stdin || child.stdin.destroyed) return false;
      try {
        child.stdin.write(JSON.stringify(payload) + "\n");
        return true;
      } catch {
        return false;
      }
    };

    const sendInitialize = () => {
      write({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
      });
    };

    /** 服务端反过来要能力时先拒掉，不然它会一直等着不应答的客户端 */
    const answerServerRequest = (msg: any) => {
      if (!child.stdin || child.stdin.destroyed) return;
      const id = msg.id;
      let reply: Record<string, unknown>;
      if (msg.method === "ping") reply = { jsonrpc: "2.0", id, result: {} };
      else if (msg.method === "roots/list") reply = { jsonrpc: "2.0", id, result: { roots: [] } };
      else reply = { jsonrpc: "2.0", id, error: { code: -32601, message: `unsupported: ${msg.method}` } };
      write(reply);
    };

    const handle = (msg: any) => {
      if (!msg || typeof msg !== "object") return;
      if (msg.id !== undefined && msg.method) {
        answerServerRequest(msg);
        return;
      }
      if (msg.id === 1) {
        if (msg.error) {
          finish(fail(`initialize 被拒绝：${msg.error.message ?? JSON.stringify(msg.error)}`));
          return;
        }
        const result = msg.result ?? {};
        initInfo = {
          protocolVersion: result.protocolVersion,
          name: result.serverInfo?.name,
          version: result.serverInfo?.version,
        };
        write({ jsonrpc: "2.0", method: "notifications/initialized" });
        write({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
        return;
      }
      if (msg.id === 2) {
        if (msg.error) {
          finish(fail(`tools/list 失败：${msg.error.message ?? JSON.stringify(msg.error)}`));
          return;
        }
        const list = Array.isArray(msg.result?.tools) ? msg.result.tools : [];
        toolCount = list.length;
        tools = list
          .map((t: any) => String(t?.name ?? ""))
          .filter(Boolean)
          .slice(0, TOOL_LIMIT);
        finish({
          ok: true,
          latencyMs: 0,
          protocolVersion: initInfo.protocolVersion,
          serverName: initInfo.name,
          serverVersion: initInfo.version,
          toolNames: tools,
          toolCount,
        });
      }
    };

    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      buffer += chunk;
      let nl = buffer.indexOf("\n");
      while (nl >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        nl = buffer.indexOf("\n");
        if (!line) continue;
        // 服务端会往 stdout 打日志，只认 JSON-RPC 行
        if (!line.startsWith("{")) continue;
        try {
          handle(JSON.parse(line));
        } catch {
          /* 半截 JSON 或普通日志，忽略 */
        }
      }
      if (buffer.length > 2_000_000) buffer = "";
    });

    child.on("error", (err) => {
      const code = (err as NodeJS.ErrnoException).code;
      const hint =
        code === "ENOENT"
          ? `找不到启动命令 ${command}（PATH 里没有，或需要绝对路径）`
          : `启动失败：${errText(err)}`;
      finish(fail(hint));
    });

    child.on("exit", (code, signal) => {
      exitCode = code;
      // 回包可能和 exit 同时到，留一个 tick 让 stdout 收完
      setTimeout(() => {
        if (settled) return;
        const reason = signal ? `信号 ${signal}` : `code ${code}`;
        finish(fail(`服务进程在握手完成前退出（${reason}）`));
      }, 60);
    });

    child.stdin?.on("error", () => {
      /* 服务端提前关 stdin 是常见行为，交给 exit 判定 */
    });

    sendInitialize();
  });
}
