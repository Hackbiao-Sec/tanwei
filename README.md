# 天鉴 | 安全测试平台

**天鉴**是一个安全测试平台项目；**探微（Tanwei Console）** 是其中第一个工具——以本机 `grok.exe` 为内核、参考「天鉴探微」情报作战台风格的桌面控制台。后续工具会按同一套资产、图谱、报告模型继续扩展。

天鉴系列各自成库，本库只放探微。资产侦察那一路在 [天鉴 · 索舆](https://github.com/Hackbiao-Sec/suoyu)。

> **仅限授权使用。** 本项目只用于获得明确授权的安全测试、自有系统测试与教学研究。禁止用于任何未授权访问、攻击或数据获取。完整条款见 [DISCLAIMER.md](DISCLAIMER.md)。
>
> 本项目是独立第三方工具，与 xAI 无隶属、合作或背书关系。Grok 名称、商标与二进制归 xAI 所有；本仓库和发行包都不包含 grok 二进制，需自行通过官方渠道获取并遵守其许可。

探微的界面通过 **ACP（Agent Client Protocol，JSON-RPC over stdio）** 驱动 `grok agent --no-leader stdio`，grok 的工具、命令、MCP、Skill、Workflow、权限审批、计划、用量全部照原样可用；需要纯终端时一键拉原生 TUI。

```
┌ 标题栏：引擎状态 · 当前会话 · MCP 就绪数 · 待授权 · 原生 TUI
├ 会话栏：进行中 / 历史会话（grok sessions list） / 作战模块
├ 主舞台：时间线（用户 · 回答 · 推理 · 工具卡 · 权限卡 · 计划）+ 输入区
└ 右态势：行动方案 · 上下文用量 · 工具流 · MCP · 会话信息
```

## 快速开始

```powershell
cd tanwei
npm install
npm run dev          # 开发模式，热更新
npm run typecheck    # 主进程 + 渲染层类型检查
npm run build        # 产出 out/
npm run embed:grok   # 把 ~/.grok/bin/grok.exe 复制进 resources/grok/
npm run dist         # 打 portable exe（自动先 build）
```

产物：

- `release/TanweiConsole-<version>-setup.exe`：安装版，装一次后从磁盘直接启动（**推荐**，秒开）。
- `release/TanweiConsole-<version>-portable.exe`：免安装单文件，每次启动都要先解压到临时目录，虚拟机/机械盘上明显偏慢。

## 启动诊断 / 打不开时

打包后窗口偶发不显示（虚拟机、远程桌面、显卡驱动）时，程序仍会把整个启动过程写进日志：

```
~/.grok/tanwei-startup.log
```

里面有引擎路径、Electron 版本、兼容模式、`did-finish-load`、窗口 `show` 的实际时间点。窗口现在有三重兜底：`ready-to-show`、`did-finish-load`、3 秒强制显示，任何一个先到都会弹窗，不会再出现「进程在但窗口不出来」。

设置页的「启动诊断」卡片可以直接看日志尾部，并可一键「兼容模式重启」：关闭硬件加速 + 关 GPU 合成，等价于启动参数 `--safe-mode` 或环境变量 `TANWEI_SAFE_MODE=1`（远程桌面会话 `RDP-*` 会自动进入兼容模式）。

## grok.exe 解析顺序

1. 环境变量 `GROK_EXE`
2. 打包后的 `resources/grok/grok.exe`（`npm run embed:grok` 放进去的）
3. `%GROK_HOME%\bin\grok.exe`，默认 `~/.grok/bin/grok.exe`
4. `where.exe grok.exe`

即：本机已装 grok 时可直接开发调试；要「把 grok.exe 镶进 exe」就跑 `embed:grok` 再打包，换机器也能带着走。

## 作战模块

左侧导航分「作战 / 配置」两组，页面直接读任务夹与引擎状态，不改动任何 grok 配置：

| 模块 | 做什么 |
|------|--------|
| 总览 | 活跃会话、确认发现（按严重度拆分）、资产条目、MCP 就绪数、Token 用量、引擎状态；最新发现、最近会话、快捷入口 |
| 发现 | 扫 `Desktop\*_SRC挖洞\报告\*.md`，按严重度过滤/搜索，右侧直接渲染报告正文；「让 AI 接着打」把报告路径与升链要求作为新任务发给 agent；「复制汇总」导出 Markdown 表格 |
| 图谱 | 任务 → 主机 → 漏洞的攻击面关系图（主机点按最严重等级着色），点主机看该面所有发现，可一键让 AI 以该主机为范围继续挖 |
| 任务 | 会话即任务：实时状态、模型、用量、工作目录、更新时间，点开回到会话 |
| 资产 | 扫任务夹 `资产/`：文件名、所属任务、条目数、样例，可让 AI 以这份资产为范围继续 |
| 流量 | 内置 HTTP 请求重放：任意方法、Header、Body、是否跟随重定向、cURL 复制、状态码/耗时/响应头/响应体、本次历史一键回放 |
| 报告 | 已落盘报告的完整列表（标题、任务、大小、更新时间） |
| 工具 | 引擎上报的全部斜杠命令（内置 / 技能 / 工作流），可搜索、复制 |
| 技能 / 规则 / MCP / 模型 / 设置 | 原有扫描与配置页；设置页补了引擎路径、启动日志、兼容模式重启 |

## 模型配置

左侧「模型」页直接读写 `~/.grok/config.toml` 的 `[model.*]` 表与 `[models] default`，其余段落（MCP、ui、endpoints…）原样保留：

- **新增 / 编辑 / 删除**：配置名（TOML 表名，即 `initialize` 里模型下拉的 key）、真实模型 ID、Base URL、API Key 或环境变量名、协议（`chat_completions` / `responses` / `messages`）、上下文窗口、温度、top_p、最大输出、推理摘要，以及「高级参数」里手写任意其他键（`extra_headers`、`query_params` 等）。
- **预设**：DeepSeek、DeepSeek R1、OpenAI、Claude、Ollama 本地、通用网关，选完只填模板，可继续改。
- **设为默认**：改 `[models] default`。
- **生效方式**：引擎只在 `initialize` 读一次模型目录，所以每次保存/删除/设默认后会自动重启引擎（旧会话句柄清空，随后新建一个会话），页面提示「引擎已重启，当前加载 N 个模型」。
- **安全网**：写入前把原文件另存为 `config.toml.tanwei.bak`；未改动的来回编辑与原文件字节一致。已有配置名会被拒绝覆盖，要改就点该模型的「编辑」。

字段含义与 grok 官方一致，见 `~/.grok/docs/user-guide/11-custom-models.md`。

## 技能开关

左侧「技能」页每行右侧是开关，「已启用 / 已禁用」随手切：

- **写入位置**：`~/.grok/config.toml` 的 `[skills] disabled = [...]`，按技能名与目录名同时去重；禁用只把技能从系统提示和调用里摘掉，文件仍留在磁盘。
- **排版保留**：其余表、注释、`paths` / `ignore` 原样不动；原来是多行数组就仍写多行；改前另存 `config.toml.tanwei.bak`，来回切一圈与原文件字节一致。
- **生效时机**：引擎在会话创建时读技能表，切换对之后新建的会话生效；已在跑的会话要立刻生效就重启引擎。
- 「打开」按钮仍在每行右侧，需要看 SKILL.md 正文时点它，不会再把整行变成跳转。

## 安装技能

「技能」页右上角「安装技能」展开三种装法，装完直接落进 `~/.grok/skills/`，列表当场刷新：

- **从文件夹安装**：选一个目录，目录里（最多往下三层）有 `SKILL.md` 就装；一个包里套多套技能会各装一份，只取最外层。已经在 `~/.grok/skills` 里的目录会被拒绝，避免自己复制自己。
- **从 ZIP 安装**：选 `.zip`，用系统 PowerShell `Expand-Archive` 解到临时目录再按上面的规则装，装完自动清临时文件。
- **新建技能**：填名称、一句话说明、正文 Markdown，自动生成带 `name` / `description` frontmatter 的 `SKILL.md`；正文留空会写一份骨架。
- **打开技能目录**：直接跳 `~/.grok/skills`，手工加目录也行。
- 目录名重复时自动加 `-2`、`-3`；名称里的 `\ / : * ? " < > |` 会被替换成 `-`。

## MCP 配置

「MCP」页可以直接增删改 `~/.grok/config.toml` 里的 `[mcp_servers.*]`：

- 卡片列出命令、参数、环境变量名、工作目录、是否启用，以及引擎回报的运行状态和工具数。
- 「添加 MCP 服务」写新表；「编辑」改同一个表（连同 `env` 子表），其余表、注释和 `startup_timeout_sec` 这类未受管字段原样保留。
- 参数一行一个，环境变量一行一个 `KEY=VALUE`，落到 `[mcp_servers.<服务名>.env]`。
- 保存后点「重启引擎」才生效：引擎只在启动时连 MCP。
- 「删除」是两步确认，删掉主表和它的 `env` 子表，不动别的服务。

浏览器槽位脚本现在开 4 个口（9222～9225），同一台机器最多 4 个会话各占一个浏览器；槽位空了看门狗会自动把 Chrome 拉回来。

## 网络代理

「设置」页的「网络代理」卡片管的是 **grok 引擎自己出网**（模型接口）。换机器、换网络后日志里出现
`reason":"request error: error sending request for url (https://api.deepseek.com/v1/chat/completions): client error (Connect): operation timed out`
就是引擎连不上模型接口，grok 会按 15 次退避重试，一轮回答会卡几分钟；它只影响速度，不是程序坏了。

- **跟随系统**（默认）：读 Windows 的代理设置（`session.resolveProxy`），Clash / v2ray 开了「系统代理」就自动带上。
- **手动**：填 `http://127.0.0.1:7897` 这类地址，适用于只开了 TUN 或只想让本程序走代理的情况。
- **不使用**：清掉代理变量强制直连。
- **测试连通性**：拿当前默认模型的 `base_url` 请求一次 `/models`，拿到任意 HTTP 状态码（含 401）就算网络通，探测走的就是保存的这档代理。
- **生效方式**：写给 `grok agent` 子进程的是 `HTTP_PROXY / HTTPS_PROXY / ALL_PROXY`（大写与小写各一份）以及 `NO_PROXY=localhost,127.0.0.1,::1`，保存后点「保存并重启引擎」立即生效，设置存在 `%APPDATA%\tanwei-console\settings.json`。

`auth.json load result ... (os error 2)` 是没缓存 x.ai 登录态时的 info 记录（用 `xai.api_key` 自定义端点本来就没有这个文件），可以忽略。

`model catalog refresh failed` 是引擎去 `base_url/models` 拉模型目录失败后回退到配置里的模型：目录拉不到不影响聊天，但反复刷说明 `base_url` 那一头的 `/models` 有问题，值得顺手看一眼（本地中转的话直接看它的日志）。

### 工具名被冲成空串（上游流式分片的问题）

有些中转在流式 tool_call 的后续分片里把 `id` / `type` / `function.name` 重新发成空串。grok 合并 delta 是「后到覆盖」，工具名被冲成 `""`，于是报 `Failed to parse arguments for tool ``: Tool not found:`，整个会话的工具都用不了。

两条处理路线，优先第一条：

1. **换一个流式分片干净的端点**。DeepSeek 官方 `https://api.deepseek.com/v1`（`deepseek-chat` / `deepseek-reasoner`）实测不重发空字段，配 `env_key = "DEEPSEEK_API_KEY"` 就能直接用工具。
2. **非要那个模型时**，用 `tools/stream-fix-proxy.mjs` 在本地把值为空串的这几个字段删掉再转发。探微只在 `config.toml` 里出现 `127.0.0.1:8787` / `127.0.0.1:8788` 时才拉起它，默认配置直连上游、什么都不起。

自测某个模型是否干净：`grok -p "用 run_terminal_command 执行 echo ok" --model <名> --always-approve`，报 `Tool not found:` 就是它流式分片不干净。

### 模型目录（catalog）

`[endpoints] models_base_url` 只影响“拉模型清单”，推理仍按每个模型自己的 `base_url`。grok 拉清单时**固定用 `XAI_API_KEY`** 做 Bearer，所以这个地址要配能用 `XAI_API_KEY` 通过的端点（当前指 autorouter）；指向 DeepSeek 会因为发的是别人家的 key 而 401，日志里刷 `model catalog refresh failed`。清单拉不到不影响聊天，引擎会回退到 `config.toml` 里的模型。

## 主题

右上角太阳 / 月亮按钮切换深色与浅色，选择存在 `localStorage`（`tanwei.theme`），下次开窗沿用。首帧前就在 `main.tsx` 里写好 `data-theme`，不会先黑后白闪一下；CSS 变量与各面板在 `styles.css` 末尾的 `html[data-theme="light"]` 段里覆盖。窗口按钮（最小化 / 最大化 / 关闭）由渲染层自绘，跟着主题变色；最小化、最大化、关闭走 `window:*` 这组 IPC。

## 目录

```
src/main/acp.ts        ACP 客户端（spawn、JSON-RPC 行协议、超时、事件）
src/main/manager.ts    引擎管理：多会话、时间线、工具、权限、计划、用量、模型/模式
src/main/config.ts     config.toml 的 [model.*] / [models] default 读写（保留其它段落）
src/main/history.ts    从 chat_history.jsonl 还原时间线
src/main/system.ts     路径解析、会话/技能/规则/MCP/资产/报告扫描、原生 TUI
src/main/workspace.ts  任务夹解析：报告 → 发现（等级/目标/类型）、资产条目、统计
src/main/http.ts       请求重放：Header 文本解析、超时、重定向上限、响应截断
src/main/index.ts      Electron 主进程、窗口、启动诊断、IPC
src/preload/index.ts   contextBridge → window.tanwei
src/renderer/          React 界面（时间线、输入区、会话栏、态势栏、模块页）
scripts/embed-grok.mjs 嵌入 grok.exe
scripts/icon/TanweiIcon.cs + scripts/make-icon.ps1  生成 build/icon.ico / icon.png（改图标后重跑 make-icon.ps1 再打包）
electron-builder.yml   打包配置（nsis 安装版 + portable 免安装，extraResources 带 grok）
```

