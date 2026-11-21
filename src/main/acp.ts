import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";

export interface AcpRequest {
  id: number;
  method: string;
  params: any;
}

type Pending = {
  resolve: (value: any) => void;
  reject: (err: Error) => void;
  timer?: NodeJS.Timeout;
};

/**
 * Minimal ACP (JSON-RPC 2.0) client for `grok agent stdio`.
 * One process can host many sessions; every session is addressed by id.
 */
export class AcpClient extends EventEmitter {
  private child?: ChildProcessWithoutNullStreams;
  private buffer = "";
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private stopping = false;

  constructor(
    private readonly grokPath: string,
    private readonly cwd: string,
    private readonly extraEnv: NodeJS.ProcessEnv = {},
  ) {
    super();
  }

  get alive(): boolean {
    return !!this.child && !this.child.killed && this.child.exitCode === null;
  }

  async start(timeoutMs = 45_000): Promise<any> {
    if (this.alive) return;
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      GROK_DISABLE_AUTOUPDATER: "1",
      ...this.extraEnv,
    };
    // Keep the agent's own output UTF-8 on Windows consoles.
    env.PYTHONIOENCODING = env.PYTHONIOENCODING ?? "utf-8";

    const child = spawn(this.grokPath, ["agent", "--no-leader", "stdio"], {
      cwd: this.cwd,
      env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.onData(chunk));
    child.stderr.on("data", (chunk: string) => this.emit("stderr", chunk));
    child.on("error", (err) => this.emit("fatal", err));
    child.on("exit", (code, signal) => {
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new Error(`grok agent exited (code=${code}, signal=${signal})`));
      }
      this.pending.clear();
      this.emit("exit", { code, signal, expected: this.stopping });
    });

    const init = await this.request(
      "initialize",
      {
        protocolVersion: 1,
        clientCapabilities: {
          fs: { readTextFile: false, writeTextFile: false },
          terminal: false,
        },
      },
      timeoutMs,
    );
    this.emit("initialized", init);
    return init;
  }

  stop(): void {
    this.stopping = true;
    try {
      this.child?.kill();
    } catch {
      /* already gone */
    }
    this.child = undefined;
  }

  request(method: string, params: any, timeoutMs = 120_000): Promise<any> {
    if (!this.child || !this.child.stdin.writable) {
      return Promise.reject(new Error("grok agent is not running"));
    }
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve, reject) => {
      let timer: NodeJS.Timeout | undefined;
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          this.pending.delete(id);
          reject(new Error(`ACP timeout: ${method} (${Math.round(timeoutMs / 1000)}s)`));
        }, timeoutMs);
      }
      this.pending.set(id, { resolve, reject, timer });
      this.child!.stdin.write(payload + "\n");
      this.emit("outbound", { id, method });
    });
  }

  notify(method: string, params: any): void {
    if (!this.child?.stdin.writable) return;
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
    this.emit("outbound", { method });
  }

  respond(id: number, result: any): void {
    if (!this.child?.stdin.writable) return;
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
    this.emit("outbound", { id, method: "response" });
  }

  respondError(id: number, code: number, message: string): void {
    if (!this.child?.stdin.writable) return;
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, "").trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch {
        // Non-protocol stdout noise is rare; surface it instead of dropping it.
        this.emit("noise", line);
        continue;
      }
      this.dispatch(msg);
    }
  }

  private dispatch(msg: any): void {
    if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) {
        p.reject(new Error(msg.error?.message ?? "ACP error"));
      } else {
        p.resolve(msg.result);
      }
      return;
    }

    if (typeof msg.method === "string") {
      if (msg.id !== undefined) {
        const req: AcpRequest = { id: msg.id, method: msg.method, params: msg.params ?? {} };
        const handled = this.listenerCount("request") > 0;
        if (handled) this.emit("request", req);
        else this.respondError(msg.id, -32601, `unsupported method: ${msg.method}`);
      } else {
        this.emit("notification", { method: msg.method, params: msg.params ?? {} });
      }
    }
  }
}
