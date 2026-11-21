// 把本机 grok.exe 复制进 resources/grok/，打包时由 electron-builder 一起带进安装包。
// 用法：npm run embed:grok            复制 ~/.grok/bin/grok.exe
//       GROK_EXE=<path> npm run embed:grok
import { copyFileSync, existsSync, mkdirSync, statSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const src = process.env.GROK_EXE || path.join(homedir(), ".grok", "bin", "grok.exe");
const destDir = path.join(process.cwd(), "resources", "grok");
const dest = path.join(destDir, "grok.exe");

if (!existsSync(src)) {
  console.error(`[embed] 找不到 grok.exe：${src}`);
  process.exit(1);
}

mkdirSync(destDir, { recursive: true });

const srcSize = statSync(src).size;
if (existsSync(dest) && statSync(dest).size === srcSize) {
  console.log(`[embed] 已是最新，跳过：${dest} (${(srcSize / 1024 / 1024).toFixed(1)} MB)`);
  process.exit(0);
}

if (existsSync(dest)) unlinkSync(dest);
copyFileSync(src, dest);
console.log(`[embed] 已复制 grok.exe -> ${dest} (${(srcSize / 1024 / 1024).toFixed(1)} MB)`);
console.log("[embed] 打包后主进程优先使用 resources/grok/grok.exe，找不到才回退 ~/.grok/bin。");
