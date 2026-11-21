# 天鉴 | 安全测试平台

**天鉴**是一个安全测试平台项目，按系列组织：每个系列是独立可用的工具，放在自己的子目录里，共用同一套资产、图谱、报告模型与授权条款。所有系列平级放置，互不覆盖。

> **仅限授权使用。** 本项目只用于获得明确授权的安全测试、自有系统测试与教学研究。禁止用于任何未授权访问、攻击或数据获取。完整条款见 [LICENSE](LICENSE) 与 [tanwei/DISCLAIMER.md](tanwei/DISCLAIMER.md)。
>
> 本项目是独立第三方工具，与 xAI 无隶属、合作或背书关系。Grok 名称、商标与二进制归 xAI 所有；本仓库和发行包都不包含 grok 二进制，需自行通过官方渠道获取并遵守其许可。

## 系列

| 系列 | 目录 | 定位 | 形态 |
|------|------|------|------|
| 天鉴 · 探微 | [`tanwei/`](tanwei/) | Tanwei Console，以本机 `grok.exe` 为内核的情报作战台；ACP（Agent Client Protocol）驱动会话、工具、MCP、Skill、Workflow | Electron 桌面应用 |
| 天鉴 · 索舆 | [`suoyu/`](suoyu/) | 资产侦察灯塔（ARL-X 增强版）：企业主体 / 股权 / 26 个被动源 / 子域 / 端口 / 存活 / 爬虫 / 深度泄露，SQLite 单文件、零外部服务 | FastAPI + Web 控制台 |

## 目录

```
tianjian/
├── LICENSE                 天鉴系列授权条款（整库适用）
├── README.md               本文件：系列总览
├── tanwei/                 天鉴 · 探微
│   ├── src/                主进程 / 预加载 / 渲染层
│   ├── scripts/            图标、grok 嵌入
│   ├── docs/               换机清单等
│   └── README.md           探微详细说明
└── suoyu/                  天鉴 · 索舆
    ├── arlx/               后端：引擎、采集器、被动源、字典、单页前端
    ├── web/                前端工程
    ├── desktop/            桌面壳与打包
    ├── scripts/            构建与运维脚本
    ├── docs/               部署与使用文档
    └── README.md           索舆详细说明
```

## 快速开始

### 探微

```powershell
cd tanwei
npm install
npm run dev          # 开发模式，热更新
npm run dist         # 打 portable exe
```

详细说明、启动诊断、grok.exe 解析顺序见 [tanwei/README.md](tanwei/README.md)。

### 索舆

```powershell
cd suoyu
pip install -r requirements.txt
python -m arlx
```

浏览器打开 <http://127.0.0.1:5113>，默认账号 `admin / arlpass`，登录后到「配置」修改。数据目录默认 `./data`，可用 `ARLX_DATA` 改；端口与监听地址在 `config.yaml` 的 `server` 段。数据源密钥在 Web「配置」页填，支持打码回显与单源连通性测试。

详细说明、数据源清单、阶段开关见 [suoyu/README.md](suoyu/README.md)。

## 新增一个系列

1. 在根目录建 `<系列名>/`，把该系列完整代码放进去，自成一套构建流程。
2. 子目录内保留自己的 `README.md` 与 `.gitignore`；根目录只管总览与系统级忽略。
3. 在本文件「系列」表加一行，写清目录、定位、形态。
4. 若来自已有的独立仓库，用保留历史的导入方式并入，保证子目录能单独追溯：

```powershell
git remote add <系列名>-src "<独立仓库路径或 URL>"
git fetch <系列名>-src master
git merge -s ours --no-commit --allow-unrelated-histories <系列名>-src/master
git read-tree --prefix=<系列名>/ -u <系列名>-src/master
git commit -m "feat(<系列名>): 引入天鉴 · <系列名>"
```

后续同步该系列的更新：

```powershell
git subtree pull --prefix=<系列名> "<独立仓库路径或 URL>" master -m "sync(<系列名>): 同步上游更新"
```

## 授权与免责

- 授权条款：[LICENSE](LICENSE)，整库适用。
- 探微的补充条款与第三方声明：[tanwei/DISCLAIMER.md](tanwei/DISCLAIMER.md)。
- 任何系列都只允许在获得明确授权的目标上使用；使用者对自身行为负责。
