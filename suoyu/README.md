# 天鉴 · 索舆（ARL-X 资产侦察灯塔 · 增强二次开发版）

天鉴系列之一，系列总览见 [../README.md](../README.md)。仅限授权使用。

基于 **ARL 2.6.2（TophantTechnology/ARL，仓库已下架，基线取 Aabyss-Team/ARL）** 的源码与字典做的
单进程、跨平台（Windows / Linux / macOS）重写增强版，沿用天鉴·索舆前身的**企业主体信息收集思路**，
并把 ARL 原本依赖的 Celery / RabbitMQ / MongoDB / massdns / phantomjs 全部去掉。

## 一、和 ARL 原版的差异

| 维度 | ARL 2.6.2 | ARL-X |
|------|-----------|-------|
| 运行环境 | 仅 Linux / Docker | Windows / Linux / macOS 直跑 |
| 外部依赖 | MongoDB + RabbitMQ + Celery + massdns + phantomjs | 零外部服务（SQLite 单文件） |
| Web 框架 | Flask + flask-restx | FastAPI（异步，SSE 实时日志） |
| DNS | massdns（Linux 二进制） | 自研 UDP 长连接异步 DNS（实测 ≈350 QPS，1.97 万子域 56 秒） |
| 子域来源 | 十几个 | **26 个**（CT 三镜像 / certspotter / myssl / rapiddns / urlscan / anubis / riddler / 搜索引擎 / GitHub / RDAP / ICP 备案 + FOFA/Hunter/Quake/0zone/Shodan/Censys/…） |
| 企业主体 | 无 | **ICP 备案 / 别名 / 新媒体 / AI 扩展**（对齐 suoyu 项目 P1） |
| 深度阶段 | 无 | 代码泄露（Sourcegraph/grep.app/GitHub/Bing）、邮箱、MX/SPF/DMARC、Git 泄露、截图、nuclei |
| 敏感文件 | 固定规则 | 加**软 404 基线剔除**（随机路径取基线，前缀/尾部/长度相似即判废） |
| 调度 | 无内置 | 内置周期任务（小时级）+ 任务模板 |
| 通知 | 有 | webhook / 钉钉 / 飞书 / 企业微信 |
| 数据源密钥 | 配置文件 | Web 页可视化配置 + 打码回显 + 单源连通性测试 |

## 二、目录

```
arl-x/
├── arlx/
│   ├── config.py            配置中心（yaml + 环境变量覆盖 + 热重载）
│   ├── db.py                SQLite（WAL）：tasks/logs/assets/task_assets/users/schedules/templates/audit
│   ├── utils.py             域名工具、CDN 判定、黑名单、指纹引擎、favicon mmh3
│   ├── server.py            FastAPI：登录、任务、资产、统计、导出、测绘、配置、审计、SSE
│   ├── notify.py            webhook / 钉钉 / 飞书 / 企微
│   ├── engine/
│   │   ├── dns_engine.py    UDP 长连接异步 DNS（A/CNAME/PTR/泛解析）
│   │   ├── http_engine.py   探测（证书 DER 解析、title、指纹、favicon hash、CDN）
│   │   ├── portscan.py      端口组（top10/100/1000/自定义）+ banner 识别
│   │   ├── pipeline.py      13 阶段编排 + 任务生命周期
│   │   ├── pipeline_stages.py  P0~P12 各阶段实现
│   │   ├── sources/passive.py  26 个被动源 + FOFA 通用检索
│   │   └── collectors/
│   │       ├── active.py    字典爆破 / dnsgen / altDNS / 站点爬虫 / JS / vhost / C 段 / 证书补全
│   │       ├── enterprise.py ICP 备案 / 企业主体 / 新媒体 / AI 扩展
│   │       └── deep.py      代码泄露 / 邮箱 / 邮件 DNS / 存储桶 / Git / 截图 / nuclei
│   ├── dicts/               ARL 原版字典（domain_2w 19708、file_top_2000、webapp.json 1917 条指纹…）
│   └── web/index.html       单页前端
├── data/                    config.yaml + arlx.db + 日志（自动生成）
└── requirements.txt
```

## 三、安装与启动

```powershell
cd suoyu
pip install -r requirements.txt
python -m arlx
```

浏览器打开 <http://127.0.0.1:5113>，默认账号 `admin / arlpass`（登录后到「配置」改）。

- 端口/监听地址：`config.yaml` 的 `server`
- 数据目录：默认 `./data`，可用环境变量 `ARLX_DATA` 改
- 环境变量覆盖任何配置项，规则：`ARLX_<段>_<键>`，如 `ARLX_SOURCES_FOFA_KEY`

## 四、流水线 13 阶段

| 阶段 | 说明 |
|------|------|
| P0 target_parse | 目标归一：域名 / IP / IP 段 / 企业名分流 |
| P1 enterprise | 企业主体：ICP 备案、别名、子公司、新媒体、AI 扩展关键词 |
| P2 passive | 26 个被动源并发拉子域与记录 |
| P3 brute | 字典爆破（默认 domain_2w.txt）+ dnsgen 变体 + altDNS 拼写变体，自动剔除泛解析 |
| P4 dns | 批量解析 A/CNAME，写 domain / ip 资产 |
| P5 port | 端口扫描（端口组分片并发）+ banner 服务识别 |
| P6 web | 存活探测：title、状态码、长度、Server、指纹、证书 SAN（SAN 回补子域）、favicon hash、CDN |
| P7 crawl | 站点爬虫：内链、JS、API 路径、外链域 |
| P8 leak | 敏感文件探测（软 404 基线剔除） |
| P9 vhost | Host 头碰撞虚拟主机 |
| P10 sibling | PTR 反查、同 C 段旁站（自动跳过 CDN/云 IP）、存储桶（默认关） |
| P11 deep | 代码泄露、邮箱、MX/SPF/DMARC、Git 泄露、截图、nuclei |
| P12 report | 汇总统计、CDN 资产数、耗时、通知 |

任一阶段可在「任务下发」页勾选开关；端口组 / 存活探测上限 / 字典均可按任务覆盖。

## 五、数据源与密钥

免费源（无需 Key）：crtsh（三镜像）、certspotter、ctlogs、myssl、rapiddns、hackertarget、
alienvault、anubis、urlscan、riddler、bing、duckduckgo、github（无 token 限流）、rdap、icp。

需 Key：fofa、hunter、quake、zoomeye、shodan、censys（id+secret）、virustotal、
securitytrails、passivetotal（user+key）、threatbook、chaos、certspotter（有 Key 限速更高）、
deepseek / openai（AI 扩展关键词）。

在「配置」页填写后点「测试」可单源连通性验证；保存时密钥显示为 `***`，不回填不覆盖。

## 六、资产类型（kind）

`domain` `ip` `service` `site` `api` `js` `leak` `leakfile` `git` `email` `mailinfo`
`bucket` `codeleak` `enterprise` `vhost` `sibling` `nuclei` `screenshot`

资产页支持按类型 / 关键字 / 任务过滤、分页、导出 CSV（带 BOM）或 JSON。

## 七、安全与合规注意

- 「配置」里 `server.auth` 默认开启；`api_key` 为空时禁止 Token 头直通。
- 存储桶枚举（`deep.bucket_enum`）默认关闭：它会向 AWS/阿里云/腾讯云推测桶名，属主动探测第三方云。
- `scan_via_proxy` 默认关：目标探测走代理会把目标流量绕到境外，国内目标不建议开。
- 合法授权范围内使用。

## 八、验证记录

- `example.com` 全流程 142 秒完成 13 阶段，产出 11 类资产。
- `qq.com` 大样本：被动 190 子域 → 158 有 IP → 163 活站点 → 2844 接口 → 561 疑似泄露文件（软 404 剔除后）。
- DNS 引擎：并发 800，1.97 万子域 55.7 秒。
- 资产变更（P12）：同一根域连跑两轮，首轮落快照，次轮裁剪快照后重跑，日志 `assetdiff` 记录「新增 N 条」，`/api/diff` 返回 `new_count` 与新增清单，资产页出现 NEW 标记，统计页显示 `+N`，「仅看新增」过滤把 29 条收窄到 10 条。
- 计划任务暂停 / 启用：`PATCH /api/schedules/{id}` 把 `enabled` 在 0 / 1 之间切换，前端按钮同步变成「启用」。

## 九、桌面端（天鉴·索舆 作战台）

与天鉴探微同系列风格（`#060b11` 深色作战台 + 青色高光），Electron 外壳内置本地引擎，单文件运行。

| 项 | 说明 |
|---|---|
| 外壳源码 | `desktop/main.js`、`desktop/electron-builder.yml` |
| 打包命令 | `cd desktop; npx electron-builder --win portable --x64` |
| 前端构建 | `cd web; .\node_modules\.bin\vite.cmd build`（先建前端，再建 exe，最后打外壳） |
| 引擎打包 | `python -m PyInstaller --noconfirm --clean suoyu-server.spec` |
| 产物 | `desktop/release/SuoyuConsole-2.8.0-portable.exe` |
| 端口策略 | 从 5113 起找空闲端口；探活必须命中 `/api/status` 且 `app` 含「索舆」，避免误把本机其它服务当引擎 |
| 数据目录 | `%APPDATA%\suoyu-console\data`（与源码调试库相互独立） |
| 日志 | `%APPDATA%\suoyu-console\logs\shell.log`、`engine.log` |

资产组的根域归约在 `utils.root_domain()` 里做了严格校验：host 先去协议/端口/路径/查询串，后缀必须是真实 TLD 且不在文件名后缀表里。历史上混入的 `index.html`、`${url}`、`item.headimg` 一类假根域，会在 `Store.repair_assets()` 启动时一次性修正（多条归一冲突时保留一条并迁移任务关联）。

