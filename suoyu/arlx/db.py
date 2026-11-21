"""SQLite 存储层。

替代 ARL 的 MongoDB：统一为单文件库，跨平台零依赖。
所有资产以「归一化 URL」为唯一键 upsert，来源合并记录在 sources 字段。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from .config import DATA_DIR
from .utils import clean_host, is_ip, is_valid_domain, root_domain

DB_PATH = DATA_DIR / "arlx.db"

# 资产面：Web / 小程序 / 公众号 / APP 各看各的，企业主体、股权、邮箱这类是任务元数据；
# 网段（ASN 归集出来的 CIDR）单独一面，不算站点，避免把 Web 的条数撑大
SURFACE_LABEL = {"web": "Web", "applet": "小程序", "mp": "公众号", "app": "APP",
                 "netblock": "网段", "meta": "主体与邮箱", "icp": "备案"}
# 分支机构、控股企业、对外投资、股东、软著、微博账号与主体/股权同属「主体侧」：
# 没有站点 URL，混进 Web 会把站点条数撑大
_META_KINDS = ("'enterprise','equity','mailinfo','email','branch','weibo',"
               "'holds','invest','partner','copyright','mobileapp','wechatoa',"
               "'job','supplier'")
# 微信公众号资产（昵称 / gh_ / __biz 归到这面，不混进 Web 与 App）
_MP_KIND = "'wxmp'"
# 小程序这一面里还分两档非实体记录：备案号（登记信息，没有包）和只有名字的线索
# （检索到了但没拿到明文 AppID）。它们是小程序的证据，不是小程序本体，但也不该
# 掉进 Web —— 单列出来，面板上才分得清「查到小程序」和「查到备案 / 线索」。
_APPLET_KINDS = "'applet','applet_hint','applet_icp'"


def surface_cond(key: str, alias: str = "") -> str:
    """把资产面换成 SQL 条件；alias 是表别名（如 ``a``）。未知面按 Web 处理。"""
    p = f"{alias}." if alias else ""
    if key == "applet":
        return f"{p}kind IN ({_APPLET_KINDS})"
    if key == "mp":
        return f"{p}kind IN ({_MP_KIND})"
    if key == "app":
        return f"{p}kind='mobile'"
    if key == "meta":
        return f"{p}kind IN ({_META_KINDS})"
    if key == "netblock":
        return f"{p}kind='netblock'"
    if key == "icp":
        return f"{p}kind='icp'"
    return (f"{p}kind NOT IN ({_APPLET_KINDS},'mobile','netblock','icp',{_MP_KIND},{_META_KINDS})")


# 控股比例散在 extra_json 里，工商各源键名不同；SQL 侧取各键最大值，取不到算 0，
# 与导出侧 ``_ratio_of`` 的认键顺序保持一致。
_RATIO_KEYS = ("ratio", "percent", "invest_ratio", "hold_ratio", "share_ratio")
_RATIO_JSON = "CASE WHEN json_valid(extra_json) THEN extra_json ELSE '{}' END"
_RATIO_SQL = "MAX(" + ", ".join(
    f"COALESCE(CAST(REPLACE(json_extract({_RATIO_JSON}, '$.{k}'), '%', '') AS REAL), 0)"
    for k in _RATIO_KEYS) + ")"


# 脆弱资产分桶：命中即从全量里单独拉出来看，键值同时作为前端筛选参数
RISK_RULES: tuple[tuple[str, str, str], ...] = (
    ("leak", "信息泄露", "kind IN ('leak','leakfile','codeleak')"),
    ("git", "代码仓库泄露", "kind='git'"),
    ("takeover", "子域接管", "kind='takeover'"),
    ("bucket", "对象存储暴露", "kind='bucket'"),
    ("middleware", "中间件裸口",
     "port IN (9200,9300,6379,6380,27017,27018,11211,2181,2375,2376,8500,15672,9042,5984,8086,8888,9201)"),
    ("admin", "管理与调试入口",
     "(lower(url) LIKE '%/admin%' OR lower(url) LIKE '%/manage%' OR url LIKE '%/login%'"
     " OR title LIKE '%管理%' OR title LIKE '%后台%' OR title LIKE '%控制台%')"),
    ("api", "敏感接口暴露",
     "(lower(url) LIKE '%swagger%' OR lower(url) LIKE '%api-docs%' OR lower(url) LIKE '%actuator%'"
     " OR lower(url) LIKE '%graphql%' OR lower(url) LIKE '%/druid%' OR lower(url) LIKE '%heapdump%'"
     " OR lower(url) LIKE '%/env%' OR lower(url) LIKE '%nacos%')"),
)


def live_state(row: dict[str, Any]) -> tuple[str, str]:
    """资产存活判定：返回 ``(机器状态, 中文说明)``，给列表/导出共用。

    站点行自己探到了状态码就以码为准；域名行没发过 HTTP，能解析出 IP 就算「解析」；
    端口行按来源分「实测端口开放」和「测绘收录」；其余没探过的老实写「未探测」，
    不拿「有 ip 字段」冒充存活。
    """
    kind = str(row.get("kind") or "")
    code = int(row.get("status_code") or 0)
    if code:
        if code < 400:
            return "alive", f"存活 {code}"
        if code < 500:
            return "auth", f"响应 {code}"
        return "bad", f"异常 {code}"
    src = str(row.get("sources") or "")
    if kind == "domain":
        has_ip = bool(str(row.get("ip") or "").strip() or str(row.get("ips") or "").strip())
        return ("dns", "已解析") if has_ip else ("dead", "不解析")
    if kind in ("ip", "service", "port"):
        # 端口扫描阶段落的行 = 当时真的连上了；测绘引擎来的只是索引里有过
        if any(k in src for k in ("portscan", "masscan", "nmap", "probe")):
            return "open", "端口开放"
        if kind == "ip":
            return "dns", "已解析"
        return "space", "测绘收录"
    return "unknown", "未探测"


def with_liveness(row: dict[str, Any]) -> dict[str, Any]:
    """把 live_state 摊进行里，前端直接读 ``alive`` / ``alive_text``。"""
    state, text = live_state(row)
    row["alive"] = state
    row["alive_text"] = text
    return row


def normalize_asset(item: dict[str, Any]) -> dict[str, Any]:
    """统一 host / root_domain 后再入库。

    采集源给出的 host 常带查询串（``www.a.com?from=x``），root_domain 也可能
    是 JS 里没替换的模板（``${url}``）。这类值会污染资产组聚合，入口处一次治好。
    """
    out = dict(item)
    raw_host = str(out.get("host") or "")
    host = clean_host(raw_host) if raw_host else ""
    if host and host != raw_host:
        out["host"] = host
        url = str(out.get("url") or "")
        # url 只在「主机段就是脏 host」时才跟着改，路径里的 ? 是正常查询串
        if url and (url.startswith(f"{raw_host}?") or url.startswith(f"domain:{raw_host}")):
            out["url"] = "domain:" + host if url.startswith("domain:") else host

    if not is_ip(host) and host and is_valid_domain(host):
        proper = root_domain(host)
        out["root_domain"] = proper
    elif is_ip(host):
        # IP 没有根域可归：备案源给过 "icp: 58.22.2.54" 这类行，旧逻辑把 IP 当根域
        # 留在库里，根域分布图就会冒出「根域 = 一个 IP」的假行。这里统一清空，
        # repair_assets() 启动时会把历史脏数据一并纠正。
        out["root_domain"] = ""
    elif not is_ip(host):
        # 主机名都不成立的（index.html / ${url} / . ），不留假根域
        out["root_domain"] = ""

    # 应用包名 com.xxx.yyy 会被域名规约当成 com.yyy 之类的假根域，别让它进资产组
    if str(out.get("url") or "").startswith("mobile:"):
        out["root_domain"] = ""

    if out.get("root_domain"):
        out["root_domain"] = str(out["root_domain"]).strip().lower()
    return out

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT,
    target TEXT,
    targets_json TEXT,
    options_json TEXT,
    status TEXT,
    progress INTEGER DEFAULT 0,
    message TEXT,
    stats_json TEXT,
    phase TEXT,
    schedule_id TEXT,
    created_at REAL,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    ts REAL,
    level TEXT,
    module TEXT,
    msg TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_task ON logs(task_id, id);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT,                -- domain / ip / site / service / cidr / email / leak / vuln
    url TEXT UNIQUE,          -- 归一化键
    host TEXT,
    ip TEXT,
    port INTEGER,
    scheme TEXT,
    title TEXT,
    status_code INTEGER,
    length INTEGER,
    fingerprint TEXT,
    cdn TEXT,
    server TEXT,
    ips TEXT,                 -- 逗号分隔
    cnames TEXT,
    sources TEXT,             -- 逗号分隔
    root_domain TEXT,
    extra_json TEXT,
    task_id TEXT,
    first_seen REAL,
    last_seen REAL
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host);
CREATE INDEX IF NOT EXISTS idx_assets_root ON assets(root_domain);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);

CREATE TABLE IF NOT EXISTS task_assets (
    task_id TEXT,
    asset_id INTEGER,
    is_new INTEGER DEFAULT 0,
    PRIMARY KEY (task_id, asset_id)
);

-- 阶段时间窗：逐条资产带阶段标记是后来的改动，老任务没记；
-- 有了起止时间，老任务也能按阶段把资产圈出来
CREATE TABLE IF NOT EXISTS task_phases (
    task_id TEXT,
    phase TEXT,
    start_ts REAL,
    end_ts REAL,
    PRIMARY KEY (task_id, phase)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'admin',
    created_at REAL
);

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    name TEXT,
    target TEXT,
    options_json TEXT,
    interval_hours INTEGER,
    enabled INTEGER DEFAULT 1,
    last_run REAL,
    next_run REAL,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS task_templates (
    name TEXT PRIMARY KEY,
    options_json TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    user TEXT,
    action TEXT,
    target TEXT,
    detail TEXT
);

-- 每轮跑完留存某根域的完整资产快照，用于对比出「新上线的资产」
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_domain TEXT,
    task_id TEXT,
    created_at REAL,
    count INTEGER DEFAULT 0,
    new_count INTEGER DEFAULT 0,
    prev_id INTEGER,
    items_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_snap_root ON snapshots(root_domain, created_at DESC);

-- 指纹规则：内置库走 dicts/webapp.json，这里只存用户自定义 / 覆盖的规则
CREATE TABLE IF NOT EXISTS fingerprints (
    name TEXT PRIMARY KEY,
    keyword TEXT,
    favicon TEXT,
    cms TEXT,
    body TEXT,
    header TEXT,
    server TEXT,
    tag TEXT,
    note TEXT,
    enabled INTEGER DEFAULT 1,
    builtin INTEGER DEFAULT 0,
    created_at REAL
);

-- 带外回显命中：DNS / HTTP 回调命中都落这里，token 反查任务
CREATE TABLE IF NOT EXISTS listener_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT,
    task_id TEXT,
    proto TEXT,
    source_ip TEXT,
    host TEXT,
    path TEXT,
    method TEXT,
    headers TEXT,
    body TEXT,
    created_at REAL
);
-- 备案查询结果（含「确实没有」的空结果）。反查接口按 IP 限频，命中过的条目必须复用，
-- 否则第二轮会被频控挡成「无备案」，同一家企业两次跑出两份结论。
CREATE TABLE IF NOT EXISTS miit_cache (
    keyword TEXT NOT NULL,
    kind INTEGER NOT NULL,
    rows_json TEXT,
    total INTEGER DEFAULT 0,
    ts REAL,
    PRIMARY KEY (keyword, kind)
);
CREATE INDEX IF NOT EXISTS idx_hits_token ON listener_hits(token, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hits_task ON listener_hits(task_id, created_at DESC);
-- 渠道健康：任务每次调一个外部数据源就记一行。要能回答「这次用了哪些渠道、
-- 哪些渠道失效了」。同一任务+阶段+渠道只留一条，重复调用累加次数和收取条数。
CREATE TABLE IF NOT EXISTS task_sources (
    task_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT DEFAULT '',
    note TEXT DEFAULT '',
    items INTEGER DEFAULT 0,
    calls INTEGER DEFAULT 0,
    updated_at REAL,
    PRIMARY KEY (task_id, stage, source)
);
"""

# 老库升级：缺列则补
MIGRATIONS = {
    "tasks": {"phase": "TEXT", "schedule_id": "TEXT"},
    "assets": {"is_new": "INTEGER DEFAULT 0"},
    # stage：这条资产是流水线哪个阶段收进来的。任务是按阶段跑出来的，
    # 资产行本身按 url 全局合并，只有关联表能记住「哪个阶段给的」。
    "task_assets": {"is_new": "INTEGER DEFAULT 0", "stage": "TEXT"},
}


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        with self.conn() as c:
            c.executescript(SCHEMA)
            for table, cols in MIGRATIONS.items():
                have = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
                for col, typ in cols.items():
                    if col not in have:
                        c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
            # 阶段明细 / 缺口统计按 (task_id, stage|module) 过滤，建在补列之后
            c.execute("CREATE INDEX IF NOT EXISTS idx_ta_task_stage"
                      " ON task_assets(task_id, stage)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_task_module"
                      " ON logs(task_id, module)")
            c.commit()
        self.repair_assets()
        self.relabel_port_assets()

    def relabel_port_assets(self) -> None:
        """把端口扫描落的历史行从「服务」改成「端口」。

        以前 p5_port 和空间测绘都写 kind=service，资产页只能按「服务」筛，
        看不出哪条是现网真连上的开放端口。url 不变，只改类型，重跑也不会重复。
        """
        with self._write_lock:
            c = self.conn()
            cur = c.execute(
                "UPDATE assets SET kind='port' WHERE kind='service'"
                " AND sources LIKE '%portscan%'"
            )
            if cur.rowcount:
                c.commit()

    def repair_assets(self) -> None:
        """把历史脏 host / 假根域就地修一遍，库升级后资产组立即干净。"""
        with self._write_lock:
            c = self.conn()
            rows = c.execute("SELECT id, url, host, root_domain FROM assets").fetchall()
            fixed = 0
            for row in rows:
                host, root, url = row["host"] or "", row["root_domain"] or "", row["url"] or ""
                new = normalize_asset({"host": host, "root_domain": root, "url": url})
                if new["host"] == host and new["root_domain"] == root and new["url"] == url:
                    continue
                # 多条脏 host 归一后会指向同一 url，唯一键冲突时把任务关联并过去再删陈旧行
                clash = c.execute(
                    "SELECT id FROM assets WHERE url=? AND id<>?", (new["url"], row["id"])
                ).fetchone()
                if clash:
                    c.execute(
                        "INSERT OR IGNORE INTO task_assets (task_id, asset_id, is_new)"
                        " SELECT task_id, ?, is_new FROM task_assets WHERE asset_id=?",
                        (clash["id"], row["id"]),
                    )
                    c.execute("DELETE FROM task_assets WHERE asset_id=?", (row["id"],))
                    c.execute("DELETE FROM assets WHERE id=?", (row["id"],))
                else:
                    c.execute(
                        "UPDATE assets SET host=?, root_domain=?, url=? WHERE id=?",
                        (new["host"] or None, new["root_domain"] or None, new["url"], row["id"]),
                    )
                fixed += 1
            if fixed:
                c.commit()

    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            # 连接一律自动提交，只在 _write_lock 里显式开事务。
            # WAL 下「手动事务 + 其他线程一直写」会让这条读连接卡在旧快照上：实测读循环
            # 连读 12 次都是 0，而库里有 24 条。本项目所有写操作都单独 commit，只要有
            # 一处 INSERT 后抛异常没 rollback（线程池里那条连接还会被下一个调用复用），
            # 这条线程之后读到的就永远是老数据，接口看着像卡死。
            conn.isolation_level = None
            self._local.conn = conn
        return conn

    # ─────── tasks ───────
    def create_task(self, task_id: str, name: str, target: str, targets: list[str], options: dict,
                    schedule_id: str = "") -> None:
        t = time.time()
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO tasks (id,name,target,targets_json,options_json,status,progress,message,stats_json,"
                "schedule_id,created_at,updated_at) VALUES (?,?,?,?,?,'waiting',0,'',?,?,?,?)",
                (task_id, name, target, json.dumps(targets, ensure_ascii=False),
                 json.dumps(options, ensure_ascii=False), json.dumps({}), schedule_id, t, t),
            )
            self.conn().commit()

    def update_task(self, task_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols, vals = [], []
        for k, v in fields.items():
            if k in ("targets", "options", "stats"):
                cols.append(f"{k}_json=?")
                vals.append(json.dumps(v, ensure_ascii=False))
            else:
                cols.append(f"{k}=?")
                vals.append(v)
        cols.append("updated_at=?")
        vals.append(time.time())
        vals.append(task_id)
        with self._write_lock:
            self.conn().execute(f"UPDATE tasks SET {','.join(cols)} WHERE id=?", vals)
            self.conn().commit()

    def delete_task(self, task_id: str) -> bool:
        """删任务行与它的过程数据（日志、阶段窗口、来源、关联），资产本身留在池子里。

        前端任务列表的删除按钮走这条：资产不跟着消失，只是不再挂在这个任务下。
        """
        with self._write_lock:
            c = self.conn()
            row = c.execute("SELECT id FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                return False
            for tbl in ("logs", "task_assets", "task_phases", "task_sources",
                        "snapshots", "listener_hits"):
                try:
                    c.execute(f"DELETE FROM {tbl} WHERE task_id=?", (task_id,))
                except sqlite3.OperationalError:
                    continue
            c.execute("UPDATE assets SET task_id='' WHERE task_id=?", (task_id,))
            c.execute("DELETE FROM tasks WHERE id=?", (task_id,))
            c.commit()
        return True

    def get_task(self, task_id: str) -> dict | None:
        row = self.conn().execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        return self._task_row(row) if row else None

    def list_tasks(self, limit: int = 100) -> list[dict]:
        rows = self.conn().execute(
            "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._task_row(r) for r in rows]

    @staticmethod
    def _task_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        cast = {"targets_json": ("targets", list), "options_json": ("options", dict), "stats_json": ("stats", dict)}
        for src, (dst, default_type) in cast.items():
            raw = d.pop(src, None)
            try:
                d[dst] = json.loads(raw) if raw else default_type()
            except Exception:
                d[dst] = default_type()
        return d

    # ─────── logs ───────
    def add_log(self, task_id: str, module: str, msg: str, level: str = "info") -> None:
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO logs (task_id, ts, level, module, msg) VALUES (?,?,?,?,?)",
                (task_id, time.time(), level, module, msg),
            )
            self.conn().commit()

    def get_logs(self, task_id: str, after_id: int = 0, limit: int = 500) -> list[dict]:
        rows = self.conn().execute(
            "SELECT * FROM logs WHERE task_id=? AND id>? ORDER BY id LIMIT ?",
            (task_id, after_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # ─────── 渠道健康 ───────
    def set_task_source(self, task_id: str, stage: str, source: str, status: str,
                        note: str = "", items: int = 0) -> None:
        """记一条渠道调用。重复调用累加次数与条数，状态以最后一次为准。

        例外：这一路前面已经取到过数据（items>0），最后一次却回「无结果 / 没搜到」，
        状态保持「已取到数据」。否则多根域任务里第二个根域查不到，渠道面板会把
        一个真出过 998 条的源标成「无结果」，看着像整路没生效。
        """
        with self._write_lock:
            prev = self.conn().execute(
                "SELECT items FROM task_sources WHERE task_id=? AND stage=? AND source=?",
                (task_id, stage, source),
            ).fetchone()
            kept = int((prev["items"] if prev else 0) or 0)
            if kept > 0 and (status or "") in ("empty", "not_found"):
                status, note = "ok", ""
            self.conn().execute(
                "INSERT INTO task_sources (task_id,stage,source,status,note,items,calls,updated_at)"
                " VALUES (?,?,?,?,?,?,1,?)"
                " ON CONFLICT(task_id,stage,source) DO UPDATE SET"
                " status=excluded.status,"
                " note=CASE WHEN excluded.note<>'' THEN excluded.note ELSE note END,"
                " items=items+excluded.items, calls=calls+1, updated_at=excluded.updated_at",
                (task_id, stage, source, status, note, items, time.time()),
            )
            self.conn().commit()

    def task_sources(self, task_id: str) -> list[dict]:
        rows = self.conn().execute(
            "SELECT * FROM task_sources WHERE task_id=? ORDER BY stage, source", (task_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ─────── assets ───────
    ASSET_COLS = (
        "kind", "url", "host", "ip", "port", "scheme", "title", "status_code", "length",
        "fingerprint", "cdn", "server", "ips", "cnames", "sources", "root_domain",
        "extra_json", "task_id",
    )

    def upsert_asset(self, item: dict[str, Any]) -> int:
        """按 url 唯一键合并：sources 去重追加，其它字段非空覆盖"""
        now = time.time()
        item = normalize_asset(item)
        url = item.get("url") or item.get("host") or item.get("ip")
        if not url:
            raise ValueError("asset 缺少 url/host/ip")
        key = url
        with self._write_lock:
            row = self.conn().execute("SELECT * FROM assets WHERE url=?", (key,)).fetchone()
            if row is None:
                values = {c: item.get(c) for c in self.ASSET_COLS}
                for list_col in ("ips", "cnames", "sources"):
                    if isinstance(values.get(list_col), (list, tuple, set)):
                        values[list_col] = ",".join(str(x) for x in values[list_col])
                values["url"] = key
                values["extra_json"] = json.dumps(item.get("extra") or {}, ensure_ascii=False)
                values["first_seen"] = now
                values["last_seen"] = now
                cols = list(values.keys())
                cur = self.conn().execute(
                    f"INSERT INTO assets ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                    [values[c] for c in cols],
                )
                self.conn().commit()
                return int(cur.lastrowid)

            merged_sources = row["sources"] or ""
            new_sources = item.get("sources") or ""
            srcs = set(filter(None, [s.strip() for s in (merged_sources + "," + new_sources).split(",")]))
            updates: dict[str, Any] = {"last_seen": now, "sources": ",".join(sorted(srcs))}
            for col in ("title", "fingerprint", "cdn", "server", "cnames", "root_domain", "host"):
                if not row[col] and item.get(col):
                    updates[col] = item[col]
            if not row["ip"] and item.get("ip"):
                updates["ip"] = item["ip"]
            if not row["port"] and item.get("port"):
                updates["port"] = item["port"]
            if item.get("status_code") and not row["status_code"]:
                updates["status_code"] = item["status_code"]
            if item.get("length") and not row["length"]:
                updates["length"] = item["length"]
            if item.get("ips"):
                old = set(filter(None, (row["ips"] or "").split(",")))
                old.update(str(x) for x in item["ips"])
                updates["ips"] = ",".join(sorted(old))
            if item.get("extra"):
                try:
                    old_extra = json.loads(row["extra_json"] or "{}")
                except Exception:
                    old_extra = {}
                old_extra.update(item["extra"])
                updates["extra_json"] = json.dumps(old_extra, ensure_ascii=False)
            self.conn().execute(
                f"UPDATE assets SET {','.join(f'{k}=?' for k in updates)} WHERE id=?",
                [*updates.values(), row["id"]],
            )
            self.conn().commit()
            return int(row["id"])

    def mark_liveness(self, task_id: str, marks: list[dict]) -> int:
        """把存活探测得到的状态码回填到同一主机的其它资产上。

        domain / ip / service / api 这些行是 DNS、端口扫描、爬虫阶段落的，它们自己
        没发过 HTTP，状态码一直是空。web 阶段探完后按 host / ip + 端口回填一份，
        资产表才看得出哪条活着。已经有状态码的行不覆盖（site 自己那条更准）。
        """
        if not task_id or not marks:
            return 0

        def rank(code: int) -> int:
            # 2xx/3xx 说明页面拿到了，4xx/5xx 只说明端口上站着 HTTP 服务
            if 200 <= code < 400:
                return 0
            return 1 if 400 <= code < 500 else 2

        by_host: dict[str, dict[int, int]] = {}
        by_ip: dict[str, dict[int, int]] = {}
        for m in marks:
            code = int(m.get("status") or 0)
            if not code:
                continue
            port = int(m.get("port") or 0)
            pairs = ((str(m.get("host") or "").lower(), by_host),
                     (str(m.get("ip") or "").lower(), by_ip))
            for key, box in pairs:
                if not key:
                    continue
                slot = box.setdefault(key, {})
                old = slot.get(port)
                if old is None or (rank(code), code) < (rank(old), old):
                    slot[port] = code

        if not by_host and not by_ip:
            return 0

        def pick(table: dict[str, dict[int, int]], key: str, port: int) -> int:
            ports = table.get(key)
            if not ports:
                return 0
            if port and port in ports:
                return ports[port]
            # 没记端口（domain 行）或端口对不上：先看 443 / 80，再按码值好坏挑一个
            for p in (443, 80):
                if p in ports:
                    return ports[p]
            return sorted(ports.items(), key=lambda kv: (rank(kv[1]), kv[1]))[0][1]

        updated = 0
        now = time.time()
        with self._write_lock:
            rows = self.conn().execute(
                "SELECT a.id, a.host, a.ip, a.port, a.status_code"
                " FROM assets a JOIN task_assets t ON t.asset_id=a.id WHERE t.task_id=?",
                (task_id,),
            ).fetchall()
            for row in rows:
                if row["status_code"]:
                    continue
                host = str(row["host"] or "").lower()
                ip = str(row["ip"] or "").lower()
                port = int(row["port"] or 0)
                code = pick(by_host, host, port) if host else 0
                if not code and ip:
                    code = pick(by_ip, ip, port)
                if not code:
                    continue
                self.conn().execute(
                    "UPDATE assets SET status_code=?, last_seen=? WHERE id=?",
                    (code, now, row["id"]),
                )
                updated += 1
            if updated:
                self.conn().commit()
        return updated

    def backfill_liveness_from_sites(self, task_id: str) -> int:
        """用本轮已落库的 site 状态码，给同一主机的其它资产补状态码。

        爬虫 / 深挖阶段在 web 探测之后还会新增 api、domain 行，它们没赶上当时那次
        回填；汇总前再来一遍，保证资产表里同一台主机的状态码一致。
        """
        if not task_id:
            return 0
        rows = self.conn().execute(
            "SELECT a.host, a.ip, a.port, a.scheme, a.status_code"
            " FROM assets a JOIN task_assets t ON t.asset_id=a.id"
            " WHERE t.task_id=? AND a.kind='site' AND a.status_code IS NOT NULL",
            (task_id,),
        ).fetchall()
        marks = []
        for r in rows:
            port = int(r["port"] or 0)
            if not port:
                port = 443 if (r["scheme"] or "") == "https" else 80
            marks.append({"host": r["host"], "ip": r["ip"], "port": port,
                          "status": r["status_code"]})
        return self.mark_liveness(task_id, marks)

    def repair_liveness(self, task_id: str = "") -> int:
        """全库补状态码：拿任务里已探到的 site 状态，回填同一主机的其它行。

        ``mark_liveness`` 只在任务正跑 web 阶段时补一次；历史任务、以及 web 之后才
        落库的 api / domain 行一直是空的。这里一次性扫全库补一遍，资产列表才有
        存活状态可看。给 ``task_id`` 就只补那一个任务。
        """
        sql = ("SELECT t.task_id, a.host, a.ip, a.port, a.scheme, a.status_code"
               " FROM assets a JOIN task_assets t ON t.asset_id=a.id"
               " WHERE a.kind='site' AND a.status_code IS NOT NULL AND a.status_code>0")
        vals: list[Any] = []
        if task_id:
            sql += " AND t.task_id=?"
            vals.append(task_id)

        def rank(code: int, port: int) -> tuple:
            # 先挑能拿到页面的码，再挑标准端口，最后挑码小（200 优于 502）
            if 200 <= code < 400:
                tier = 0
            elif 400 <= code < 500:
                tier = 1
            else:
                tier = 2
            return (tier, 0 if port in (443, 80) else 1, code)

        best: dict[tuple[str, str], tuple[tuple, int]] = {}
        for r in self.conn().execute(sql, vals):
            code = int(r["status_code"] or 0)
            port = int(r["port"] or 0)
            if not port:
                port = 443 if (r["scheme"] or "") == "https" else 80
            key_rank = rank(code, port)
            for tag, key in (("h", str(r["host"] or "").lower()),
                             ("i", str(r["ip"] or "").lower())):
                if not key:
                    continue
                slot = (r["task_id"], tag + ":" + key)
                old = best.get(slot)
                if old is None or key_rank < old[0]:
                    best[slot] = (key_rank, code)
        if not best:
            return 0

        sql = ("SELECT a.id, a.host, a.ip, t.task_id FROM assets a"
               " JOIN task_assets t ON t.asset_id=a.id WHERE a.status_code IS NULL")
        vals = []
        if task_id:
            sql += " AND t.task_id=?"
            vals.append(task_id)
        now = time.time()
        marks: list[tuple] = []
        for r in self.conn().execute(sql, vals):
            code = 0
            for tag, key in (("h", str(r["host"] or "").lower()),
                             ("i", str(r["ip"] or "").lower())):
                hit = best.get((r["task_id"], tag + ":" + key)) if key else None
                if hit and (not code or hit[0] < rank(code, 80)):
                    code = hit[1]
            if code:
                marks.append((code, now, r["id"]))
        if not marks:
            return 0
        with self._write_lock:
            self.conn().executemany(
                "UPDATE assets SET status_code=?, last_seen=? WHERE id=?", marks)
            self.conn().commit()
        return len(marks)

    def merge_assets(self, keep_id: int, drop_ids: list[int],
                     extra: dict | None = None) -> int:
        """把重复资产并进保留行：任务关联迁移、sources/ips/extra 合并，再删重复行。

        资产表全局按 url 唯一，但同一个主体/主机换个写法就是另一条 url；
        汇总阶段由 dedupe 层算出重复组，这里只负责无损落库。返回删掉的行数。
        `extra` 给了就用它当合并后的画像（调用方能把 chain/holders 这类列表并起来）。
        """
        keep_id = int(keep_id)
        drops = [int(i) for i in (drop_ids or []) if int(i) != keep_id]
        if not drops:
            return 0
        removed = 0
        with self._write_lock:
            c = self.conn()
            keep = c.execute("SELECT * FROM assets WHERE id=?", (keep_id,)).fetchone()
            if keep is None:
                return 0
            srcs = set(filter(None, [s.strip() for s in (keep["sources"] or "").split(",")]))
            ips = set(filter(None, [x.strip() for x in (keep["ips"] or "").split(",")]))
            if extra is not None:
                extra = dict(extra)
            else:
                try:
                    extra = json.loads(keep["extra_json"] or "{}")
                except Exception:
                    extra = {}
            if not isinstance(extra, dict):
                extra = {}
            for rid in drops:
                row = c.execute("SELECT * FROM assets WHERE id=?", (rid,)).fetchone()
                if row is None:
                    continue
                srcs.update(filter(None, [s.strip() for s in (row["sources"] or "").split(",")]))
                ips.update(filter(None, [x.strip() for x in (row["ips"] or "").split(",")]))
                try:
                    more = json.loads(row["extra_json"] or "{}")
                except Exception:
                    more = {}
                if isinstance(more, dict):
                    for k, v in more.items():
                        if k not in extra or extra[k] in (None, "", [], {}):
                            extra[k] = v
                c.execute(
                    "INSERT INTO task_assets (task_id, asset_id, is_new, stage)"
                    " SELECT task_id, ?, is_new, stage FROM task_assets WHERE asset_id=?"
                    " ON CONFLICT(task_id, asset_id) DO UPDATE SET"
                    " is_new=MAX(task_assets.is_new, excluded.is_new),"
                    " stage=COALESCE(task_assets.stage, excluded.stage)",
                    (keep_id, rid),
                )
                c.execute("DELETE FROM task_assets WHERE asset_id=?", (rid,))
                c.execute("DELETE FROM assets WHERE id=?", (rid,))
                removed += 1
            c.execute("UPDATE assets SET sources=?, ips=?, extra_json=? WHERE id=?",
                      (",".join(sorted(srcs)), ",".join(sorted(ips)),
                       json.dumps(extra, ensure_ascii=False), keep_id))
            c.commit()
        return removed

    def record_phase(self, task_id: str, phase: str, ts: float | None = None) -> None:
        """记阶段起止时间；start 取最早、end 取最晚"""
        if not task_id or not phase:
            return
        now = time.time() if ts is None else float(ts)
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO task_phases (task_id, phase, start_ts, end_ts) VALUES (?,?,?,?)"
                " ON CONFLICT(task_id, phase) DO UPDATE SET"
                " start_ts=MIN(task_phases.start_ts, excluded.start_ts),"
                " end_ts=MAX(COALESCE(task_phases.end_ts, excluded.end_ts), excluded.end_ts)",
                (task_id, phase, now, now),
            )
            self.conn().commit()

    def stage_window(self, task_id: str, stage: str) -> tuple[float, float] | None:
        """某任务某阶段的时间窗：先看阶段表，老任务回落到日志首尾时间"""
        if not task_id or not stage:
            return None
        c = self.conn()
        row = c.execute("SELECT start_ts, end_ts FROM task_phases WHERE task_id=? AND phase=?",
                        (task_id, stage)).fetchone()
        if row and row["start_ts"]:
            return float(row["start_ts"]), float(row["end_ts"] or row["start_ts"])
        row = c.execute("SELECT MIN(ts) lo, MAX(ts) hi FROM logs WHERE task_id=? AND module=?",
                        (task_id, stage)).fetchone()
        if row and row["lo"]:
            return float(row["lo"]), float(row["hi"] or row["lo"])
        return None

    def _stage_cond(self, task_id: str, stage: str) -> tuple[str, list[Any]]:
        """阶段条件：逐条资产记了阶段就按标记，没记的按该阶段时间窗兜底。

        资产行按 url 全局合并，`first_seen` 可能是别的任务留下的；这趟又见到
        （upsert 会刷新 `last_seen`）也算本阶段产出，所以两个时间都看。
        """
        sql = "id IN (SELECT asset_id FROM task_assets WHERE task_id=? AND stage=?)"
        vals: list[Any] = [task_id, stage]
        win = self.stage_window(task_id, stage)
        if win:
            lo, hi = win[0], win[1] + 1
            sql = ("(" + sql + " OR (id IN (SELECT asset_id FROM task_assets"
                   " WHERE task_id=? AND COALESCE(stage,'')='')"
                   " AND (first_seen BETWEEN ? AND ? OR last_seen BETWEEN ? AND ?)))")
            vals += [task_id, lo, hi, lo, hi]
        return sql, vals

    def link_task_asset(self, task_id: str, asset_id: int, stage: str = "") -> None:
        """把资产挂到任务上，阶段只认第一次写进来的那个。

        后面 dns / port / web 会反复关联同一批资产（域名要被解析、站点要被探测），
        若按最后写入者覆盖，被动源收的子域全被改记成 ``dns``、测绘探到的全被改记成
        ``web``，任务详情里「域名收集 / 空间测绘」就永远显示无产出。所以保留首次阶段，
        只补空值。
        """
        with self._write_lock:
            self.conn().execute(
                "INSERT INTO task_assets (task_id, asset_id, stage) VALUES (?,?,?)"
                " ON CONFLICT(task_id, asset_id) DO UPDATE SET"
                " stage=COALESCE(task_assets.stage, excluded.stage)",
                (task_id, asset_id, stage or None),
            )
            self.conn().commit()

    def unlink_task_assets(self, task_id: str, kind: str = "", host: str = "") -> int:
        """把某个主机（或某类资产）从本任务拆掉；资产本身留在库里给别的任务用。"""
        sql = ("DELETE FROM task_assets WHERE task_id=? AND asset_id IN "
               "(SELECT id FROM assets WHERE 1=1")
        vals: list[Any] = [task_id]
        if kind:
            sql += " AND kind=?"
            vals.append(kind)
        if host:
            sql += " AND host=?"
            vals.append(host)
        sql += ")"
        with self._write_lock:
            cur = self.conn().execute(sql, vals)
            self.conn().commit()
            return int(cur.rowcount or 0)

    def _asset_where(self, filters: dict, *, with_new: bool) -> tuple[list[str], list[Any]]:
        """查询条件拼装；指定 task_id 且 with_new 时把该任务的新增标记并进结果"""
        where, vals = [], []
        for k in ("kind", "host", "ip", "root_domain", "cdn", "task_id"):
            if filters.get(k):
                if k == "task_id":
                    where.append("id IN (SELECT asset_id FROM task_assets WHERE task_id=?)")
                else:
                    where.append(f"{k}=?")
                vals.append(filters[k])
        # 分表口径：一张表可能对应多个 kind（APP 同时有本机解包和工商两路来源），
        # 单 kind 的用法保持不变，多 kind 走 kinds。
        kinds = filters.get("kinds")
        if isinstance(kinds, str):
            kinds = [k.strip() for k in kinds.split(",")]
        kinds = [str(k) for k in (kinds or []) if str(k).strip()]
        if kinds:
            where.append("kind IN (" + ",".join("?" * len(kinds)) + ")")
            vals.extend(kinds)
        # 控股比例：工商各源把比例写进 extra_json，键名不统一，取各键里最大的那个比。
        ratio = float(filters.get("min_ratio") or 0)
        if ratio > 0:
            where.append(f"{_RATIO_SQL} >= ?")
            vals.append(ratio)
        # 阶段过滤只在任务内成立：同一个 host 可能是这趟 P4 收进来的、下趟 P6 才探到，
        # 单看 assets 表分不出阶段，必须回到 task_assets.stage。
        stage = str(filters.get("stage") or "")
        task_id = str(filters.get("task_id") or "")
        if stage and task_id:
            cond, cv = self._stage_cond(task_id, stage)
            where.append(cond)
            vals.extend(cv)
        if with_new and filters.get("task_id"):
            if filters.get("is_new"):
                where.append("id IN (SELECT asset_id FROM task_assets WHERE task_id=? AND is_new=1)")
                vals.append(filters["task_id"])
        if filters.get("surface"):
            where.append(surface_cond(str(filters["surface"])))
        risk = str(filters.get("risk") or "")
        if risk:
            cond = next((c for k, _l, c in RISK_RULES if k == risk), "")
            if cond:
                where.append(cond)
        if filters.get("keyword"):
            # 工商画像（备案号、软著登记号、股东、供应商）都装在 extra_json 里，
            # 不带上这一列就搜不到备案号，只能靠眼睛在表里翻
            where.append("(url LIKE ? OR title LIKE ? OR fingerprint LIKE ? OR host LIKE ?"
                         " OR extra_json LIKE ?)")
            kw = f"%{filters['keyword']}%"
            vals.extend([kw, kw, kw, kw, kw])
        return where, vals

    def query_assets(self, **filters: Any) -> list[dict]:
        where, vals = self._asset_where(filters, with_new=True)
        if filters.get("port"):
            where.append("port=?")
            vals.append(int(filters["port"]))
        # 新增标记在 Python 侧按 id 回填：assets.* 自带同名列 is_new，SELECT 里改名会被它盖掉
        sql = "SELECT * FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        order = filters.get("order") or "last_seen DESC"
        sql += f" ORDER BY {order} LIMIT ? OFFSET ?"
        vals = vals + [int(filters.get("limit", 200)), int(filters.get("offset", 0))]
        rows = [dict(r) for r in self.conn().execute(sql, vals).fetchall()]
        if filters.get("task_id") and rows:
            marks = {r[0]: r[1] for r in self.conn().execute(
                "SELECT asset_id, is_new FROM task_assets WHERE task_id=?", (filters["task_id"],))}
            for r in rows:
                r["is_new"] = int(marks.get(r["id"], 0) or 0)
        return rows

    def count_assets(self, **filters: Any) -> int:
        where, vals = self._asset_where(filters, with_new=True)
        sql = "SELECT COUNT(*) FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        return int(self.conn().execute(sql, vals).fetchone()[0])

    def asset_kind_counts(self, **filters: Any) -> dict[str, int]:
        """按资产类型数条数，导出的分表角标用。

        以前每张分表都 ``query_assets(limit=100000)`` 拉一遍全量行只为数长度，
        27 张表就是 27 遍全表扫；这里一条 GROUP BY 出全部类型。
        """
        where, vals = self._asset_where(filters, with_new=True)
        sql = "SELECT COALESCE(kind,'') kind, COUNT(*) n FROM assets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " GROUP BY COALESCE(kind,'')"
        rows = self.conn().execute(sql, vals).fetchall()
        return {str(r["kind"] or ""): int(r["n"] or 0) for r in rows}

    def task_breakdown(self, task_ids: list[str] | None = None,
                       modules: dict[str, dict[str, Any]] | None = None
                       ) -> dict[str, dict[str, Any]]:
        """每个任务真正收了多少条资产，按类型、按阶段、按模块各分一份。

        ``tasks.stats`` 记的是「写入了几次」，同一个 url 被三个阶段各写一次就算 3，
        任务列表上那个数比资产页多得多就是它。这里从 ``task_assets`` 关联表数去重 id。

        ``modules`` 传 ``{"subject": {"stages": [...], "kinds": [...]}}`` 时，
        额外按模块回一份去重数：阶段落在该模块的算它，没记阶段的老资产按类型认。
        """
        ids = [str(t) for t in (task_ids or []) if t]
        task_cond, vals = "", []
        if ids:
            task_cond = "ta.task_id IN (%s)" % ",".join("?" * len(ids))
            vals = ids
        where = (" WHERE " + task_cond) if task_cond else ""
        c = self.conn()
        out: dict[str, dict[str, Any]] = {}

        def slot(tid: str) -> dict[str, Any]:
            return out.setdefault(tid, {"total": 0, "kinds": {}, "stages": {},
                                        "pairs": {}, "modules": {}})

        # 分组计数在 SQL 里算完。
        # 旧写法把 task_assets 明细整表拉回 Python 再按 (阶段, 类型) 建 set 去重：
        # 200 个任务就是十几万行、上千个 set，点任务列表先卡一秒多。
        # 同一个资产在一个任务里只占 task_assets 一行、只属于一个阶段和一个类型，
        # 所以各 (阶段, 类型) 的 COUNT 相加就等于原来的去重总数，结果一致。
        groups: dict[str, dict[tuple[str, str], int]] = {}
        for r in c.execute(
            "SELECT ta.task_id tid, COALESCE(ta.stage,'') stage, COALESCE(a.kind,'') kind,"
            " COUNT(DISTINCT ta.asset_id) n FROM task_assets ta"
            " JOIN assets a ON a.id=ta.asset_id" + where +
            " GROUP BY ta.task_id, stage, kind", vals
        ):
            groups.setdefault(r["tid"], {})[(r["stage"], r["kind"])] = int(r["n"] or 0)

        for tid, pairs in groups.items():
            s = slot(tid)
            stage_n: dict[str, int] = {}
            kind_n: dict[str, int] = {}
            total = 0
            for (stage, kind), n in pairs.items():
                s["pairs"].setdefault(stage, {})[kind] = n
                stage_n[stage] = stage_n.get(stage, 0) + n
                kind_n[kind] = kind_n.get(kind, 0) + n
                total += n
            s["stages"] = stage_n
            s["kinds"] = kind_n
            s["total"] = total

        for key, conf in (modules or {}).items():
            stages = [str(s) for s in (conf.get("stages") or []) if s]
            kinds = [str(k) for k in (conf.get("kinds") or []) if k]
            claimed = [str(s) for s in (conf.get("claimed") or []) if s]
            if not stages and not kinds:
                continue
            want_stage = set(stages)
            want_kind = set(kinds)
            claimed_set = set(claimed)
            for tid, pairs in groups.items():
                matched = 0
                for (stage, kind), n in pairs.items():
                    if stage in want_stage:
                        matched += n
                    elif kind in want_kind and (not stage or stage not in claimed_set):
                        # 阶段压根没记，或者记的是 target_parse 这种不归段的阶段 → 按类型认
                        matched += n
                if matched:
                    slot(tid)["modules"][key] = matched
        return out

    def task_status_counts(self) -> dict[str, int]:
        """按状态数任务，任务列表顶部/左侧角标用；比拉整张任务表轻得多。"""
        rows = self.conn().execute(
            "SELECT status, COUNT(*) n FROM tasks GROUP BY status").fetchall()
        return {str(r["status"] or ""): int(r["n"] or 0) for r in rows}

    def stats(self) -> dict[str, Any]:
        c = self.conn()
        by_kind = {r[0]: r[1] for r in c.execute("SELECT kind, COUNT(*) FROM assets GROUP BY kind")}
        by_fp = [
            {"fingerprint": r[0], "count": r[1]}
            for r in c.execute(
                "SELECT fingerprint, COUNT(*) c FROM assets WHERE fingerprint IS NOT NULL AND fingerprint!='' "
                "GROUP BY fingerprint ORDER BY c DESC LIMIT 30"
            )
        ]
        by_root = [
            {"root_domain": r[0], "count": r[1]}
            for r in c.execute(
                "SELECT root_domain, COUNT(*) c FROM assets WHERE root_domain IS NOT NULL AND root_domain!='' "
                "GROUP BY root_domain ORDER BY c DESC LIMIT 30"
            )
        ]
        ports = [
            {"port": r[0], "count": r[1]}
            for r in c.execute(
                "SELECT port, COUNT(*) c FROM assets WHERE port IS NOT NULL GROUP BY port ORDER BY c DESC LIMIT 30"
            )
        ]
        return {"by_kind": by_kind, "top_fingerprints": by_fp, "top_roots": by_root, "top_ports": ports}

    # ─────── users ───────
    def ensure_admin(self, username: str, password_hash: str) -> None:
        c = self.conn()
        if not c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            c.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)",
                (username, password_hash, "admin", time.time()),
            )
            c.commit()

    def get_user(self, username: str) -> dict | None:
        row = self.conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    # ─────── schedules ───────
    def list_schedules(self) -> list[dict]:
        rows = self.conn().execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["options"] = json.loads(d.pop("options_json") or "{}")
            out.append(d)
        return out

    def save_schedule(self, item: dict) -> None:
        with self._write_lock:
            self.conn().execute(
                "INSERT OR REPLACE INTO schedules (id,name,target,options_json,interval_hours,enabled,last_run,next_run,created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    item["id"], item.get("name", ""), item.get("target", ""),
                    json.dumps(item.get("options") or {}, ensure_ascii=False),
                    int(item.get("interval_hours") or 24), int(item.get("enabled", 1)),
                    item.get("last_run"), item.get("next_run"), item.get("created_at") or time.time(),
                ),
            )
            self.conn().commit()

    def delete_schedule(self, sid: str) -> None:
        with self._write_lock:
            self.conn().execute("DELETE FROM schedules WHERE id=?", (sid,))
            self.conn().commit()

    # ─────── templates ───────
    def list_templates(self) -> list[dict]:
        rows = self.conn().execute("SELECT * FROM task_templates ORDER BY created_at DESC").fetchall()
        return [{"name": r["name"], "options": json.loads(r["options_json"] or "{}"),
                 "created_at": r["created_at"]} for r in rows]

    def save_template(self, name: str, options: dict) -> None:
        with self._write_lock:
            self.conn().execute(
                "INSERT OR REPLACE INTO task_templates (name, options_json, created_at) VALUES (?,?,?)",
                (name, json.dumps(options, ensure_ascii=False), time.time()))
            self.conn().commit()

    def delete_template(self, name: str) -> None:
        with self._write_lock:
            self.conn().execute("DELETE FROM task_templates WHERE name=?", (name,))
            self.conn().commit()

    # ─────── snapshots / 变更 ───────
    def list_snapshots(self, roots: list[str], limit: int = 400) -> list[dict]:
        """按时间倒序返回这些根域的历史快照（每个根域取最新若干条即可）"""
        if not roots:
            return []
        out: list[dict] = []
        c = self.conn()
        for root in roots:
            rows = c.execute(
                "SELECT * FROM snapshots WHERE root_domain=? ORDER BY created_at DESC LIMIT ?",
                (root, limit),
            ).fetchall()
            out.extend(dict(r) for r in rows)
        return out

    def save_snapshot(self, root: str, items: list[str], *, prev_id: int | None = None,
                      new_count: int = 0, task_id: str = "") -> int:
        with self._write_lock:
            cur = self.conn().execute(
                "INSERT INTO snapshots (root_domain, task_id, created_at, count, new_count, prev_id,"
                " items_json) VALUES (?,?,?,?,?,?,?)",
                (root, task_id, time.time(), len(items), int(new_count), prev_id,
                 json.dumps(items, ensure_ascii=False)),
            )
            self.conn().commit()
            return int(cur.lastrowid)

    def clear_new(self, task_id: str) -> None:
        with self._write_lock:
            self.conn().execute("UPDATE task_assets SET is_new=0 WHERE task_id=?", (task_id,))
            self.conn().commit()

    def mark_new(self, task_id: str, url: str) -> None:
        """按任务打新增标记：资产行是全局按 url 合并的，标记必须落在 task_assets 上"""
        with self._write_lock:
            self.conn().execute(
                "UPDATE task_assets SET is_new=1 WHERE task_id=? AND asset_id IN"
                " (SELECT id FROM assets WHERE url=?)",
                (task_id, url),
            )
            self.conn().commit()

    def mark_new_many(self, task_id: str, urls: list[str], chunk: int = 400) -> int:
        """批量打新增标记：一轮资产变更能有上千条，逐条 UPDATE + commit 会把事件循环拖住"""
        if not urls:
            return 0
        done = 0
        with self._write_lock:
            c = self.conn()
            for i in range(0, len(urls), chunk):
                part = urls[i:i + chunk]
                marks = ",".join("?" * len(part))
                cur = c.execute(
                    "UPDATE task_assets SET is_new=1 WHERE task_id=? AND asset_id IN"
                    " (SELECT id FROM assets WHERE url IN (%s))" % marks,
                    [task_id] + list(part),
                )
                done += int(cur.rowcount or 0)
            c.commit()
        return done

    # ─────── 聚合视图（前端仪表盘 / 资产组 / 搜索分面用）───────
    def overview(self) -> dict[str, Any]:
        """一次查询把仪表盘要的统计全算出来，避免前端发一堆小请求"""
        c = self.conn()
        stats = self.stats()
        total = c.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        day = time.time() - 86400
        week = time.time() - 7 * 86400
        new_day = c.execute("SELECT COUNT(*) FROM assets WHERE first_seen>=?", (day,)).fetchone()[0]
        new_week = c.execute("SELECT COUNT(*) FROM assets WHERE first_seen>=?", (week,)).fetchone()[0]
        site = stats["by_kind"].get("site", 0)
        cdn = c.execute("SELECT COUNT(*) FROM assets WHERE cdn IS NOT NULL AND cdn!=''").fetchone()[0]
        tasks = c.execute(
            "SELECT status, COUNT(*) FROM tasks GROUP BY status").fetchall()
        task_stat = {r[0]: r[1] for r in tasks}
        recent_tasks = [dict(r) for r in c.execute(
            "SELECT id,name,target,status,progress,message,phase,stats_json,created_at,updated_at"
            " FROM tasks ORDER BY created_at DESC LIMIT 8").fetchall()]
        last7 = []
        for i in range(6, -1, -1):
            lo = time.time() - (i + 1) * 86400
            hi = time.time() - i * 86400
            n = c.execute("SELECT COUNT(*) FROM assets WHERE first_seen>=? AND first_seen<?",
                          (lo, hi)).fetchone()[0]
            last7.append({"day": time.strftime("%m-%d", time.localtime(hi)), "count": n})
        return {
            "total": total, "by_kind": stats["by_kind"], "site": site, "cdn": cdn,
            "new_day": new_day, "new_week": new_week,
            "tasks": task_stat, "running": len(pipeline_running()),
            "top_fingerprints": stats["top_fingerprints"],
            "top_roots": stats["top_roots"], "top_ports": stats["top_ports"],
            "recent_tasks": recent_tasks, "trend": last7,
        }

    def list_roots(self, keyword: str = "", limit: int = 300) -> list[dict]:
        """资产组：按 root_domain 聚合，带上站点数 / 域名数 / 最近存活"""
        c = self.conn()
        where = " WHERE root_domain IS NOT NULL AND root_domain!=''"
        vals: list[Any] = []
        if keyword:
            where += " AND root_domain LIKE ?"
            vals.append(f"%{keyword}%")
        rows = c.execute(
            "SELECT root_domain, COUNT(*) cnt,"
            " SUM(CASE WHEN kind='site' THEN 1 ELSE 0 END) sites,"
            " SUM(CASE WHEN kind='domain' THEN 1 ELSE 0 END) domains,"
            f" SUM(CASE WHEN {surface_cond('web')} THEN 1 ELSE 0 END) web,"
            f" SUM(CASE WHEN {surface_cond('applet')} THEN 1 ELSE 0 END) applet,"
            f" SUM(CASE WHEN {surface_cond('app')} THEN 1 ELSE 0 END) app,"
            " MAX(last_seen) last_seen, MIN(first_seen) first_seen,"
            " COUNT(DISTINCT CASE WHEN cdn IS NULL OR cdn='' THEN ip END) ips"
            f" FROM assets{where}"
            " GROUP BY root_domain ORDER BY cnt DESC LIMIT ?",
            vals + [int(limit)]).fetchall()
        return [dict(r) for r in rows]

    def list_task_groups(self, keyword: str = "", limit: int = 200) -> list[dict]:
        """资产组按任务聚合：任务自己带走一批资产，各面各多少一眼看清"""
        c = self.conn()
        where, vals = "", []
        if keyword:
            where = " WHERE (t.id LIKE ? OR t.name LIKE ? OR t.target LIKE ?)"
            kw = f"%{keyword}%"
            vals = [kw, kw, kw]
        rows = c.execute(
            "SELECT t.id task_id, t.name, t.target, t.status, t.created_at, t.updated_at,"
            " COUNT(DISTINCT a.id) total,"
            f" COUNT(DISTINCT CASE WHEN {surface_cond('web', 'a')} THEN a.id END) web,"
            f" COUNT(DISTINCT CASE WHEN {surface_cond('applet', 'a')} THEN a.id END) applet,"
            f" COUNT(DISTINCT CASE WHEN {surface_cond('mp', 'a')} THEN a.id END) mp,"
            f" COUNT(DISTINCT CASE WHEN {surface_cond('app', 'a')} THEN a.id END) app,"
            f" COUNT(DISTINCT CASE WHEN {surface_cond('meta', 'a')} THEN a.id END) meta,"
            f" COUNT(DISTINCT CASE WHEN {surface_cond('netblock', 'a')} THEN a.id END) netblock,"
            " MAX(a.last_seen) last_seen"
            " FROM tasks t LEFT JOIN task_assets ta ON ta.task_id=t.id"
            " LEFT JOIN assets a ON a.id=ta.asset_id" + where +
            " GROUP BY t.id ORDER BY total DESC, t.created_at DESC LIMIT ?",
            vals + [int(limit)]).fetchall()
        return [dict(r) for r in rows]

    def _task_scope(self, task_id: str = "", stage: str = "") -> tuple[str, list[Any]]:
        """任务资产范围；再给阶段时缩到该阶段收进来的那批。

        `stage` 只在有 `task_id` 时生效：`task_assets.stage` 是任务内字段。
        """
        if not task_id:
            return "", []
        if stage:
            cond, vals = self._stage_cond(task_id, stage)
            return " WHERE " + cond, vals
        return " WHERE id IN (SELECT asset_id FROM task_assets WHERE task_id=?)", [task_id]

    def surface_counts(self, task_id: str = "", stage: str = "") -> dict[str, int]:
        """各资产面条数：Web / 小程序 / 公众号 / APP / 网段 / 备案 / 主体与邮箱"""
        c = self.conn()
        scope, vals = self._task_scope(task_id, stage)
        out: dict[str, int] = {}
        for key in ("web", "applet", "mp", "app", "netblock", "icp", "meta"):
            sql = (f"SELECT COUNT(*) FROM assets{scope}"
                   f"{' AND ' if scope else ' WHERE '}{surface_cond(key)}")
            out[key] = int(c.execute(sql, vals).fetchone()[0])
        return out

    def risk_overview(self, task_id: str = "", limit: int = 12) -> dict[str, Any]:
        """脆弱资产分桶；给任务 ID 时只看这个任务。total 是去重后的条数。"""
        c = self.conn()
        scope = ""
        vals: list[Any] = []
        if task_id:
            scope = " WHERE id IN (SELECT asset_id FROM task_assets WHERE task_id=?)"
            vals = [task_id]
        lead = " AND " if scope else " WHERE "
        buckets: list[dict[str, Any]] = []
        for key, label, cond in RISK_RULES:
            n = int(c.execute(f"SELECT COUNT(*) FROM assets{scope}{lead}({cond})", vals).fetchone()[0])
            samples: list[dict[str, Any]] = []
            if n:
                samples = [dict(r) for r in c.execute(
                    "SELECT id, kind, url, host, port, title, status_code, fingerprint"
                    f" FROM assets{scope}{lead}({cond}) ORDER BY id DESC LIMIT ?",
                    vals + [int(limit)]).fetchall()]
            buckets.append({"key": key, "label": label, "count": n, "samples": samples})
        union = " OR ".join(f"({cond})" for _k, _l, cond in RISK_RULES)
        total = int(c.execute(
            f"SELECT COUNT(*) FROM assets{scope}{lead}({union})", vals).fetchone()[0])
        return {"total": total, "buckets": buckets}

    def risk_by_task(self, limit: int = 200) -> list[dict[str, Any]]:
        """按任务分隔的脆弱资产计数：一眼看出哪趟侦察打出了脆弱面"""
        c = self.conn()
        cols = ", ".join(
            f"COUNT(DISTINCT CASE WHEN {cond} THEN a.id END) {key}"
            for key, _l, cond in RISK_RULES)
        union = " OR ".join(f"({cond})" for _k, _l, cond in RISK_RULES)
        rows = c.execute(
            "SELECT t.id task_id, t.name, t.target, t.status, t.updated_at,"
            f" {cols},"
            f" COUNT(DISTINCT CASE WHEN {union} THEN a.id END) risky,"
            " COUNT(DISTINCT a.id) total"
            " FROM tasks t JOIN task_assets ta ON ta.task_id=t.id"
            " JOIN assets a ON a.id=ta.asset_id"
            " GROUP BY t.id HAVING risky > 0"
            " ORDER BY risky DESC, t.updated_at DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def facets(self, task_id: str = "", stage: str = "") -> dict[str, Any]:
        """资产搜索左侧分面；给任务 ID 时分面只统计该任务的资产"""
        c = self.conn()
        where, vals = self._task_scope(task_id, stage)

        def grouped(col: str, extra: str = "", limit: int = 40) -> list[dict]:
            sql = (f"SELECT {col}, COUNT(*) c FROM assets{where}")
            if extra:
                sql += (" AND " if where else " WHERE ") + extra
            sql += f" GROUP BY {col} ORDER BY c DESC LIMIT {int(limit)}"
            return [{"value": r[0], "count": r[1]} for r in c.execute(sql, vals)]

        kind = grouped("kind", limit=40)
        port = grouped("port", "port IS NOT NULL AND port>0", 24)
        fp = grouped("fingerprint", "fingerprint IS NOT NULL AND fingerprint!=''", 40)
        root = grouped("root_domain", "root_domain IS NOT NULL AND root_domain!=''", 40)
        cdn = grouped("cdn", "cdn IS NOT NULL AND cdn!=''", 20)
        src = grouped("sources", "sources IS NOT NULL AND sources!=''", 30)
        return {"kind": kind, "port": port, "fingerprint": fp, "root_domain": root,
                "cdn": cdn, "sources": src}

    # ─────── 自定义指纹 ───────
    def list_fingerprints(self) -> list[dict]:
        rows = self.conn().execute("SELECT * FROM fingerprints ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def save_fingerprint(self, item: dict) -> None:
        with self._write_lock:
            self.conn().execute(
                "INSERT OR REPLACE INTO fingerprints (name,keyword,favicon,cms,body,header,server,"
                "tag,note,enabled,builtin,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (item.get("name"), item.get("keyword") or "", item.get("favicon") or "",
                 item.get("cms") or "", item.get("body") or "", item.get("header") or "",
                 item.get("server") or "", item.get("tag") or "", item.get("note") or "",
                 int(item.get("enabled", 1)), int(item.get("builtin", 0)), time.time()))
            self.conn().commit()

    def delete_fingerprint(self, name: str) -> None:
        with self._write_lock:
            self.conn().execute("DELETE FROM fingerprints WHERE name=? AND builtin=0", (name,))
            self.conn().commit()


def pipeline_running() -> dict:
    """延迟导入，避免 db ← pipeline ← db 的循环引用"""
    try:
        from .engine.pipeline import RUNNING

        return RUNNING
    except Exception:
        return {}


store = Store()


def audit(action: str, target: str = "", detail: str = "", user: str = "system") -> None:
    """操作审计（下发任务 / 改配置 / 导出 / 登录 等）"""
    try:
        with store._write_lock:
            c = store.conn()
            c.execute("INSERT INTO audit (ts,user,action,target,detail) VALUES (?,?,?,?,?)",
                      (time.time(), user, action, target, detail))
            c.commit()
    except Exception:
        pass
