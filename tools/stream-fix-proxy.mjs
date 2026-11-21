// 修片代理：某些中转在 SSE 后续分片里回传 "function":{"name":""}, "type":"", "id":""，
// 客户端按「后值覆盖」合并就会把工具名清空，表现成 Tool not found: ""。
// 这里把空字段从分片里去掉，其余原样转发。
//
// 用法: node stream-fix-proxy.mjs [listenPort] [upstreamOrigin] [logFile]
// 例:   node stream-fix-proxy.mjs 8788 https://api.autorouter.top

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import { URL } from "node:url";

const PORT = Number(process.argv[2] ?? 8788);
const UPSTREAM = new URL(process.argv[3] ?? "https://api.autorouter.top");
const LOG = process.argv[4] ?? "";

function log(line) {
  const text = `${new Date().toISOString()} ${line}`;
  if (LOG) {
    try {
      fs.appendFileSync(LOG, `${text}\n`);
    } catch {
      /* 日志写不了就只打 stdout */
    }
  }
  console.log(text);
}

/** 删掉分片里空串的 name/type/id，避免覆盖已收到的真值 */
function fixChunk(payload) {
  let changed = 0;
  const choices = payload?.choices;
  if (Array.isArray(choices)) {
    for (const choice of choices) {
      const calls = choice?.delta?.tool_calls;
      if (!Array.isArray(calls)) continue;
      for (const call of calls) {
        if (call.type === "") {
          delete call.type;
          changed++;
        }
        if (call.id === "") {
          delete call.id;
          changed++;
        }
        const fn = call.function;
        if (fn && typeof fn === "object" && fn.name === "") {
          delete fn.name;
          changed++;
        }
      }
    }
  }
  return changed;
}

/** 逐行处理 SSE，跨网络分片的半行留在 buffer 里 */
function makeSseRewriter() {
  let buffer = "";
  return {
    push(text, out) {
      buffer += text;
      let idx;
      while ((idx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, idx + 1);
        buffer = buffer.slice(idx + 1);
        out(line);
      }
    },
    flush(out) {
      if (buffer) out(buffer);
      buffer = "";
    },
  };
}

function rewriteLine(line) {
  const match = /^data:\s*(\{.*\})\s*$/.exec(line.replace(/\r?\n$/, ""));
  if (!match) return line;
  try {
    const payload = JSON.parse(match[1]);
    const changed = fixChunk(payload);
    if (!changed) return line;
    return `data: ${JSON.stringify(payload)}\n`;
  } catch {
    return line;
  }
}

const server = http.createServer((req, res) => {
  const started = Date.now();
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const target = new URL(req.url ?? "/", UPSTREAM);
    const headers = { ...req.headers };
    delete headers.host;
    delete headers["content-length"];
    headers["accept-encoding"] = "identity";
    if (body.length) headers["content-length"] = String(body.length);

    const upstream = https.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        method: req.method,
        headers,
      },
      (up) => {
        const contentType = String(up.headers["content-type"] ?? "");
        const isSse = contentType.includes("text/event-stream");
        log(
          `${req.method} ${target.pathname} -> ${up.statusCode} ${isSse ? "sse" : "json"} ${Date.now() - started}ms`,
        );

        if (!isSse) {
          res.writeHead(up.statusCode ?? 502, up.headers);
          up.pipe(res);
          return;
        }

        res.writeHead(up.statusCode ?? 502, { ...up.headers, "content-type": contentType });
        const rewriter = makeSseRewriter();
        up.setEncoding("utf8");
        up.on("data", (text) => rewriter.push(text, (line) => res.write(rewriteLine(line))));
        up.on("end", () => {
          rewriter.flush((tail) => res.write(tail));
          res.end();
        });
      },
    );

    upstream.on("error", (err) => {
      log(`upstream error: ${err.message}`);
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: `stream-fix-proxy: ${err.message}` } }));
    });

    if (body.length) upstream.write(body);
    upstream.end();
  });
});

server.listen(PORT, "127.0.0.1", () => log(`listening on http://127.0.0.1:${PORT} -> ${UPSTREAM.origin}`));
