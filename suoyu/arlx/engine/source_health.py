"""渠道健康：把任务每次调用外部数据源的结果记下来，回答「这次用了哪些渠道、
哪些渠道失效了」。

设计要点：
- 记录必须便宜且绝不打断采集。写库失败只吞掉，不让一个统计把整条流水线带崩。
- 状态只有几种，前端按状态分组（可用 / 无数据 / 失效 / 未配置），
  新增状态字符串要同步进 STATUS，否则前端显示原始码。
"""

from __future__ import annotations

from typing import Any

# 阶段：资产按阶段收进来，渠道面板也按阶段分组，跑单项时一眼看到是哪一环在用哪些源。
STAGE_LABEL = {
    "enterprise": "企业主体",
    "equity": "股权穿透",
    "icp": "备案查询",
    "mobile": "公众号 / 小程序 / App",
    "applet": "小程序 / App",
    "weibo": "微博",
    "passive": "被动子域",
    "space": "空间测绘",
    "brute": "字典爆破",
    "dns": "DNS 解析",
    "port": "端口扫描",
    "web": "Web 探活",
    "crawl": "爬虫",
    "leak": "泄露检索",
    "vhost": "虚拟主机",
    "takeover": "接管风险",
    "sibling": "关联系列站",
}

# 渠道：键名沿用采集器里的 source 标识，值给人看。
SOURCE_LABEL = {
    # 工商 / 备案。主源是两家工商站：股东、对外投资、分支机构、备案都按
    # 全量分页取；其余工商站在面板上标「辅助」，只在主源缺数据时补位。
    "aiqicha": "工商主源·爱企查",
    "tianyancha": "工商主源·天眼查",
    "qichacha": "企查查",
    "qcc": "企查查",
    "xiaolanben": "小蓝本",
    # 渠道自检面板按「一家一路」列出备用工商源，所以要能在裸键上认出是谁；
    # 采集流程里它们仍以 backup:<名> 的形式落库，两套标签都留着。
    "qcctid": "企查查接口",
    "riskbird": "风险鸟",
    "kuaicha": "快查",
    "qidian": "企典",
    "chinaz": "站长之家",
    "aldzs": "阿拉丁小程序榜",
    "appbk": "应用宝库",
    "backup": "工商辅助源",
    # 企业主体单项跑时会顺带穿一层股权，用来扩子公司。这几路的状态前缀成
    # equity:aiqicha / equity:tianyancha，让面板能和「备案」「搜索」分开看。
    "equity": "股权派生",
    # 备用工商源是一路多家：每家登录态各自独立，面板必须能指到具体一家，
    # 否则「登录态过期」和「没配凭据」又会糊成同一个「备用工商源」。
    # 名字按每家自己的站点写，不写「第一路 / 第二路」：面板上要能直接看出
    # 「该去补哪一家凭据」，序号得回头翻代码才知道是谁。
    "backup:qichacha": "工商辅助源·企查查",
    "backup:qcctid": "工商辅助源·企查查接口",
    "backup:riskbird": "工商辅助源·风险鸟",
    "backup:kuaicha": "工商辅助源·快查",
    "backup:qidian": "工商辅助源·企典",
    "backup:chinaz": "工商辅助源·站长之家",
    "backup:aldzs": "工商辅助源·阿拉丁小程序榜",
    "backup:appbk": "工商辅助源·应用宝库",
    "icp": "备案库",
    "miit": "工信部备案",
    "beian": "备案库",
    "miit_domain": "工信部备案·按域名",
    "miit_reverse": "工信部备案·域名反查主体",
    "aiqicha_icp": "工商接口备案",
    "aizhan": "备案反查页·按主体",
    "aizhan_domain": "备案反查页·按域名",
    "searchengine": "搜索引擎召回",
    # 公众号 / 小程序 / App
    "mp": "公众号检索",
    "mp:homepage": "公众号主页",
    "mp:search": "公众号搜索",
    "applet": "小程序检索",
    # 自设上限 / 总时限把这一轮砍短了：不是渠道坏，是「找得不全」的真实原因，
    # 面板上必须单独一行说明，否则只会看到「可用」却少了一大片资产。
    # 名字说人话：这几个键在界面上和渠道排在一起，写成 cap:xxx 没人看得懂。
    "cap:names": "上限截断·主体数量",
    "cap:subs": "上限截断·并线子公司",
    "cap:deadline": "上限截断·总时长",
    "cap:budget": "上限截断·请求次数",
    "cap:gap": "上限截断·跨源补穿",
    "applet:toutiao": "小程序检索·头条",
    "applet:bing_rss": "小程序检索·必应RSS",
    "applet:sogou": "小程序检索·搜狗",
    "applet:weixin": "小程序检索·搜狗微信",
    "applet:weixin_search": "小程序检索·搜狗微信",
    "applet:local_wechat": "小程序检索·本机微信缓存",
    "applet:miit": "小程序检索·备案库",
    "applet:cdn": "小程序检索·CDN 包资源",
    "local_wechat": "本机微信缓存",
    "app:cdn": "微信 CDN 包资源",
    "cdn": "CDN 包资源",
    "weixin_search": "微信搜索",
    "app": "App 检索",
    "weibo": "微博检索",
    "local_mini": "本机小程序包",
    "local_wechat": "本机微信缓存",
    "tencent_app": "应用市场",
    "qimai": "应用榜单",
    # 证书 / 被动 DNS
    "crtsh": "证书透明日志",
    "certspotter": "证书订阅",
    "ctlogs": "CT 聚合",
    "myssl": "证书查询",
    "rapiddns": "被动 DNS",
    "hackertarget": "被动 DNS",
    "alienvault": "OTX 情报",
    "anubis": "Anubis 情报",
    "urlscan": "URLScan",
    "riddler": "Riddler",
    "wayback": "网页存档",
    "commoncrawl": "CommonCrawl",
    "virustotal": "VirusTotal",
    "securitytrails": "SecurityTrails",
    "passivetotal": "PassiveTotal",
    "chaos": "Chaos",
    "threatbook": "微步情报",
    "github": "代码托管",
    "rdap": "RDAP",
    "ip138": "解析历史",
    "ip138_rev": "IP 反查",
    "subdomain_center": "子域中心",
    "mnemonic": "Mnemonic",
    "robtex": "Robtex",
    "robtex_rev": "Robtex 反查",
    "zero_zone": "ZeroZone",
    "equity": "股权派生",
    # 单次调用没在时限内返回：具体是哪一路都还没交代，只能记一条「这一枪超时」
    "call": "单次查询",
    # 空间测绘（Key 统一叫配置名）
    "fofa": "空间测绘①",
    "hunter": "空间测绘②",
    "quake": "空间测绘③",
    "zoomeye": "空间测绘④",
    "shodan": "空间测绘⑤",
    "censys": "空间测绘⑥",
    "space_search": "空间测绘检索",
    # 搜索引擎
    "bing": "Bing",
    "duckduckgo": "DuckDuckGo",
    "baidu": "百度",
    "google": "Google",
    # 搜索引擎按渠道开关时前缀成 engine:<引擎名>：同一个引擎在被动收集里也会出现，
    # 单列一层才能分清「渠道被我停用了」和「被动那一枪没取到」。
    "engine:bing": "搜索·Bing",
    "engine:bing_rss": "搜索·必应RSS",
    "engine:toutiao": "搜索·头条",
    "engine:baidu": "搜索·百度",
    "engine:baidu_m": "搜索·百度移动",
    "engine:sogou": "搜索·搜狗",
    "engine:sogou_m": "搜索·搜狗移动",
    "engine:so360_m": "搜索·360移动",
    "engine:360": "搜索·360",
    "engine:ddg": "搜索·DuckDuckGo",
    "engine:yyb": "搜索·应用宝",
    # 公众号文章检索（内容平台那一路，与公众号主页 / 公众号搜索分开）
    "weixin": "公众号文章",
    # 基础设施
    "dns": "递归解析",
    "dnsdumpster": "DNSDumpster",
    "port": "端口探测",
    "web": "Web 探活",
    "fingerprint": "指纹识别",
    "handshake": "握手指纹",
    "crawl": "站内爬虫",
    "tools": "本地工具",
}

# 状态 → (人话, 归类)。归类给前端上色和分组：
#   ok 可用有数据 / empty 可用无数据 / dead 失效 / config 未配置 / skip 未启用
STATUS = {
    "ok": ("已取到数据", "ok"),
    "empty": ("连通但无数据", "empty"),
    "not_found": ("未检索到该主体", "empty"),
    "no_credential": ("未配置凭据", "config"),
    "quota": ("额度已用尽", "dead"),
    "blocked": ("被风控 / 登录态失效", "dead"),
    "error": ("请求失败", "dead"),
    "timeout": ("请求超时", "dead"),
    "partial": ("完成了一部分（被上限 / 时限截断）", "partial"),
    # 母渠道汇总行的专有状态：这一族里有的子渠道取到了数据、有的真的坏了。
    # 它既不是「截断」（没被上限砍过），也不能沿用采集器整轮返回值说成「请求失败」。
    "mixed": ("部分渠道失效", "dead"),
    "skip": ("本轮未启用", "skip"),
}

STATE_LABEL = {
    "ok": "可用",
    "empty": "可用·无数据",
    "dead": "失效",
    "config": "未配置",
    "partial": "部分",
    "skip": "未启用",
}


def label_source(key: str) -> str:
    if key in SOURCE_LABEL:
        return SOURCE_LABEL[key]
    head, _, tail = key.partition(":")
    if tail:
        # 子渠道（applet:local_wechat 这类）：母渠道名 + 子渠道标记，面板上不出现裸 key
        base = SOURCE_LABEL.get(head) or head
        return f"{base}·{SOURCE_LABEL.get(tail, tail)}"
    return key


def label_stage(key: str) -> str:
    return STAGE_LABEL.get(key) or key


def state_of(status: str) -> str:
    return (STATUS.get(status) or ("未知", "dead"))[1]


def text_of(status: str) -> str:
    return (STATUS.get(status) or (status or "未知", "dead"))[0]


# 「没检索到这家」先于「无结果」判：一句「公开渠道未检索到「x」的应用」描述的是
# 检索跑通了、库里没有，落到默认的 error 就变成「请求失败」，人会去查一条没坏的渠道。
_NOTFOUND_HINTS = ("未检索到", "未搜到", "查无", "无同名", "不存在该")
_EMPTY_HINTS = ("无结果", "无 A 记录", "无解析", "无反查", "not found", "not_found")
_CONFIG_HINTS = ("未配置", "未填写", "缺少 key", "no key", "需要 key", "未设置")
_BLOCK_HINTS = ("风控", "滑块", "验证码", "频繁", "被拦", "失效", "拒绝", "HTTP 401",
                "HTTP 403", "HTTP 429", "captcha", "forbidden", "unauthorized")
_TIMEOUT_HINTS = ("超时", "timeout", "timed out")
_ERROR_HINTS = ("请求失败", "HTTP ", "error", "ERR", "异常", "不是 JSON", "上游繁忙")


def status_of_error(err: str) -> str:
    """把采集器返回的 error 文本归到一个状态码。

    搜「无结果」并不等于渠道失效：连通了、只是这家没数据，面板上必须和
    被风控、未配置凭据分开，否则每次看到一片红就以为全线挂了。
    """
    e = (err or "").strip()
    if not e:
        return "ok"
    low = e.lower()
    if any(h in low for h in _TIMEOUT_HINTS):
        return "timeout"
    if any(h in e or h in low for h in _CONFIG_HINTS):
        return "no_credential"
    if any(h in e or h in low for h in _BLOCK_HINTS):
        return "blocked"
    if any(h in e or h in low for h in _NOTFOUND_HINTS):
        return "not_found"
    if any(h in e or h in low for h in _EMPTY_HINTS):
        return "empty"
    if any(h in e or h in low for h in _ERROR_HINTS):
        return "error"
    return "error"


def record(store, task_id: str, stage: str, source: str, status: str,
           note: str = "", items: int = 0) -> None:
    """记一条渠道调用。任何异常都吞掉：统计不能影响采集。"""
    if not (store and task_id and source):
        return
    try:
        store.set_task_source(task_id, stage or "misc", source, status or "error",
                              note or "", int(items or 0))
    except Exception:
        pass


def record_many(store, task_id: str, stage: str, status_map: Any,
                notes: Any = None, items: Any = None) -> None:
    """一次记多条。status_map 是 {source: status}，notes/items 同结构的可选补充。"""
    if not isinstance(status_map, dict):
        return
    notes = notes if isinstance(notes, dict) else {}
    items = items if isinstance(items, dict) else {}
    for src, st in status_map.items():
        note, num = notes.get(src, ""), items.get(src, 0)
        if isinstance(st, dict):
            # 部分采集器给的是 {status, note, items} 明细，这里直接摊开，
            # 调用方不用为「带说明的渠道」另写一套。
            note = st.get("note") or note
            num = st.get("items") or num
            st = st.get("status") or "error"
        record(store, task_id, stage, src, st, note, num)


def normalize(status_map: Any, stage: str = "", notes: Any = None,
              items: Any = None) -> list[dict]:
    """采集器自报的 {source: status} 摊成和任务渠道面板一样的一行一条。

    单项执行（`direct:*`）不建任务、没有 task_sources 表可读，但用户跑单项最想
    知道的就是「这一枪调了哪几路、哪路是死的」。这里复用同一套标签和配色，
    前端两处（任务详情 / 功能自检）显示一致。
    """
    if not isinstance(status_map, dict):
        return []
    notes = notes if isinstance(notes, dict) else {}
    items = items if isinstance(items, dict) else {}
    rows = []
    for src, st in status_map.items():
        note, num = notes.get(src, ""), items.get(src, 0)
        if isinstance(st, dict):
            note = st.get("note") or note
            num = st.get("items") or num
            st = st.get("status") or "error"
        status = str(st or "error")
        state = state_of(status)
        rows.append({
            "stage": stage or "misc",
            "stage_label": label_stage(stage) if stage else "",
            "source": str(src),
            "label": label_source(str(src)),
            "status": status,
            "status_text": text_of(status),
            "state": state,
            "state_label": STATE_LABEL.get(state, state),
            "note": note or "",
            "items": int(num or 0),
            "calls": 1,
        })
    order = {"dead": 0, "config": 1, "partial": 2, "ok": 3, "empty": 4, "skip": 5}
    rows.sort(key=lambda x: (order.get(x["state"], 9), x["source"]))
    return rows


def _derived_rows(store, task_id: str) -> list[dict]:
    """没有 task_sources 记录的：从资产的 sources 列反推「哪几路真的出了东西」。

    出现这种情况只有两种：任务还在跑、渠道行还没落；或这轮跑在渠道记录上线之前。
    能交代的只有「这一路产出过多少条资产」。所以状态一律标 ok，说明里写明是反推，
    不冒充「可用」。
    """
    try:
        rows = store.query_assets(task_id=task_id, limit=5000) or []
    except Exception:
        return []
    tally: dict[tuple[str, str], int] = {}
    for a in rows:
        raw = str(a.get("sources") or "")
        kind = str(a.get("kind") or "")
        for src in (x.strip() for x in raw.replace(",", "/").split("/")):
            if src:
                tally[(kind, src)] = tally.get((kind, src), 0) + 1
    return [{"stage": kind or "misc", "source": src, "status": "ok",
             "note": "按资产来源反推（这一轮还没有渠道调用记录：任务可能仍在跑，"
                     "或跑在渠道记录上线之前）",
             "items": n, "calls": 0}
            for (kind, src), n in tally.items()]


# 说明文本 → 它暗示的状态。采集器里 notes 是一串话，不分渠道；要挂到面板上
# 就得先认出这句话在说什么，才能对上「状态相同的那一路」。
_NOTE_SKIP = ("跨来源", "另一路", "已用另一路")
_NOTE_STATUS = (
    ("quota", ("额度", "次数已用", "配额", "超过上限", "quota")),
    ("config", ("未配置", "没有配置", "未设置", "未填", "缺少登录态", "no_credential")),
    ("blocked", ("风控", "验证码", "反爬", "登录态失效", "登录态可能失效", "登录态过期",
                 "已过期", "封禁", "拦截", "挑战", "请重新", "HTTP 301", "HTTP 302",
                 "HTTP 403", "HTTP 405")),
    ("partial", ("内返回", "中途状态")),
    ("timeout", ("超时", "timed out", "timeout")),
    ("error", ("请求失败", "失败：", "异常", "error")),
    ("not_found", ("未检索到", "查无", "无同名", "不存在", "未解析到")),
    ("empty", ("返回空", "无数据", "为空", "没有数据", "暂无", "未解析")),
)
_NOTE_FAMILY = {
    "empty": {"empty", "not_found"},
    "not_found": {"empty", "not_found"},
    "config": {"config", "no_credential", "skip"},
    "blocked": {"blocked"},
    "quota": {"quota"},
    "partial": {"partial"},
    "timeout": {"timeout"},
    "error": {"error"},
}


def _implied_status(text: str) -> str:
    low = str(text or "").lower()
    for st, keys in _NOTE_STATUS:
        if any(k.lower() in low for k in keys):
            return st
    return ""


def _fragments(text) -> list[str]:
    """一句说明里塞了好几路的事：按分号 / 换行拆成单句。

    采集器有时把多路结果拼成一条（``qichacha HTTP 302…；公开工商接口未检索到…``），
    不拆就只能整串丢给某一路，面板上四行字一模一样，看不出该修哪一路。
    """
    out: list[str] = []
    for chunk in str(text or "").replace("；", ";").replace(";", "\n").splitlines():
        one = chunk.strip(" \t，,。")
        if one:
            out.append(one)
    return out


def _note_aliases(status_map: dict) -> list[tuple[str, str]]:
    """「说明里怎么称呼这一路」→ 该挂到哪个渠道键，长的名字排前面。

    说明文本点名渠道有三种写法：内部 key（``qichacha``）、按家拆开后的尾巴
    （``backup:qichacha``）、给人看的名字（``企查查`` / ``备用工商源·企查查``）。
    三种都得认，否则「登录态过期」这句会挂不上任何一行，或者挂错行。
    某一家只有被聚合的母行（``backup``）时，家名也挂回母行 —— 面板上才看得见
    「备用工商源 未配置」背后其实是企查查那条 Cookie 死了。
    """
    keys = [str(k) for k in status_map]
    rows = set(keys)
    alias: dict[str, str] = {}

    def add(name, key: str) -> None:
        words = str(name or "").strip().lower()
        if len(words) < 3 or words in alias:
            return
        alias[words] = key

    for key in keys:
        head, _, tail = key.partition(":")
        add(key, key)
        if tail:
            add(tail, key)
            add(SOURCE_LABEL.get(tail, tail), key)
        add(SOURCE_LABEL.get(key, key), key)
        if tail and head in rows:
            # 这一家自己没有独立行（只剩母行）时，家名仍要能指到母行
            add(SOURCE_LABEL.get(tail, tail), head)
    for key, label in SOURCE_LABEL.items():
        head, _, tail = key.partition(":")
        if head == "backup" and "backup" in rows:
            add(label, "backup")
            if tail:
                add(tail, "backup")
    return sorted(alias.items(), key=lambda kv: -len(kv[0]))


def _owner_of(text: str, aliases) -> str:
    """这句说明在说哪一路；没点名就回空串。"""
    low = str(text or "").lower()
    for words, key in aliases:
        if words in low:
            return key
    return ""


def trim_note(note, key: str, aliases) -> str:
    """一路自己的说明里混进了别路的句子：只留点名自己、或者谁都没点名的那些。

    早期版本把采集器那一整串说明原样写给每一路，面板上四行字完全相同，看不出
    到底哪一路坏了。这里按句拆开：说别路的句子从这一行删掉；整句都在说别路，
    这一行就留空 —— 宁可少一句，也不给人一条指错方向的说明。
    """
    text = str(note or "").strip()
    if not text:
        return text
    if text.startswith("共 ") and " 路：" in text:
        return text
    parts = _fragments(text)
    if len(parts) < 2:
        return text
    mine: list[str] = []
    other = False
    for one in parts:
        owner = _owner_of(one, aliases)
        if owner and owner != key:
            other = True
            continue
        mine.append(one)
    if not other:
        return text
    return "；".join(mine)[:300]


_SHORT_STATE = {
    "ok": "可用", "blocked": "失效", "quota": "额度尽", "error": "请求失败",
    "timeout": "超时", "empty": "无数据", "not_found": "查无此家",
    "no_credential": "未配置", "skip": "未启用", "partial": "部分",
}


def _parent_summary(parent: str, status_map: dict) -> str:
    """一路拆成多家（``backup:qichacha`` 这种）时，给母渠道自己一句汇总。

    母键的状态是按严重度挑出来的代表值，单看只有「失效」两个字；用户真正想知道的
    是这一路几家能用、坏的是哪家。没有子渠道就不编，返回空串。
    """
    kids = {str(k).split(":", 1)[-1]: v for k, v in status_map.items()
            if str(k).startswith(f"{parent}:")}
    if not kids:
        return ""
    buckets: dict[str, list[str]] = {}
    for tail, st in kids.items():
        buckets.setdefault(str(st), []).append(tail)
    parts = []
    for st in _SHORT_STATE:
        names = buckets.pop(st, [])
        if names:
            parts.append(f"{'/'.join(sorted(names))} {_SHORT_STATE[st]}")
    for st, names in sorted(buckets.items()):
        parts.append(f"{'/'.join(sorted(names))} {st}")
    return f"共 {len(kids)} 路：{'；'.join(parts)}"[:300]


def _rollup_status(parent: str, status_map: dict) -> str:
    """汇总行自己的状态，由子渠道推出来；没有子渠道就返回空串。

    采集器返回的是整轮结果：一路取到数据、两路失效、五路无数据，整轮常常返回
    「请求失败」。汇总行照抄这一句，面板上就会出现「小程序检索 请求失败」下面紧跟着
    「站点挖掘 已取到数据」，自相矛盾，也没人知道到底该修哪一路。这里按子渠道重算。
    """
    kids = [str(v or "") for k, v in status_map.items()
            if k != parent and str(k).startswith(f"{parent}:")]
    if not kids:
        return ""
    states = [state_of(s) for s in kids]
    dead = [s for s in kids if state_of(s) == "dead"]
    if dead and any(s != "dead" for s in states):
        # 族里状态不一致（有的取到数据、有的没配、有的坏了）：说「部分渠道失效」，
        # 具体哪一路坏了看说明列，别拿一个整族的状态盖过去。
        return "mixed"
    if dead:
        # 一路都没取到：把最该先修的那个状态带上来，别含糊成「请求失败」
        for want in ("quota", "blocked", "timeout", "error"):
            if want in dead:
                return want
        return "error"
    if "config" in states:
        return "no_credential"
    if "skip" in states:
        return "skip"
    if "partial" in states:
        return "partial"
    if "ok" in states:
        return "ok"
    # 全是无数据 / 查无这家：渠道通着，只是没有这一家的记录
    return next((s for s in kids if s in ("not_found", "empty")), "empty")


def split_notes(notes, status_map: dict) -> dict[str, str]:
    """把一把平铺的说明按渠道拆开。

    采集器里的 ``notes`` 是一串文本、不分渠道，面板上却是一路一行，必须知道哪句是哪路的。
    规则只有两条：句子里点名了哪一路（``qichacha HTTP 302…``）就归那一路；没点名的，
    按「这句话暗示的状态」对上状态相同的普通渠道。对不上就**不挂** —— 宁可这一路少一句
    说明，也不能把「额度已用尽」抄给备案库和备用源，那会让人照着假说明去修错东西。
    """
    out: dict[str, str] = {}
    if not isinstance(status_map, dict) or not status_map:
        return out
    aliases = _note_aliases(status_map)
    # 先给「拆成多家的母渠道」落汇总：这是数出来的事实，比下面按语义猜归属可靠。
    keyed = [str(k) for k in status_map if ":" in str(k)]
    plain = [str(k) for k in status_map if ":" not in str(k)]
    for k in plain:
        summary = _parent_summary(k, status_map)
        if summary:
            out[k] = summary
    texts = [str(n).strip() for n in (notes or []) if str(n).strip()][:12]
    if not texts:
        return out
    for raw in texts:
        if any(s in raw for s in _NOTE_SKIP):
            continue
        for text in _fragments(raw):
            if any(s in text for s in _NOTE_SKIP):
                continue
            owner = _owner_of(text, aliases)
            if owner:
                if not out.get(owner):
                    out[owner] = text[:300]
                continue
            want = _implied_status(text)
            if not want:
                continue
            family = _NOTE_FAMILY.get(want, {want})
            target = next((k for k in plain if str(status_map.get(k) or "") in family), "")
            if not target:
                target = next((k for k in keyed if str(status_map.get(k) or "") in family), "")
            if target and not out.get(target):
                out[target] = text[:300]
    return out


_DEAD_STATUS = ("blocked", "quota", "timeout", "error")


def reconcile_status(status: str, note: str, key: str, aliases) -> str:
    """说明比库里记的状态更准、更严重时按说明报。

    两种真实情况：早先的备用工商源把一条死掉的 Cookie 记成「未配置凭据」，看板上就是
    「去补个凭据就能用」，人照着做还是错的；以及单次调用被时限硬切断，中途状态却写着
    「已取到数据」，看着像这一路跑完了。只在说明确实点名这一路、且比原状态更严重时改，
    其余一律信库里记的状态——不能凭空把一路好渠道说成坏的。
    """
    cur = str(status or "")
    if not note:
        return status
    owner = _owner_of(note, aliases)
    if owner and owner != key:
        return status
    want = _implied_status(note)
    if not want or want == cur:
        return status
    if cur in ("ok", "empty") and want == "partial":
        # 时限切断：拿到的那部分照留，但这一路只跑了一半，不能报「可用」
        return want
    if cur != "no_credential" or owner != key:
        return status
    return want if want in _DEAD_STATUS else status


def snapshot(store, task_id: str) -> dict:
    """渠道面板用：按渠道列一行 + 按状态汇总，另给未启用渠道清单（前端可提「该开没开」）。"""
    rows = []
    derived = False
    try:
        rows = store.task_sources(task_id) or []
    except Exception:
        rows = []
    if not rows:
        rows = _derived_rows(store, task_id)
        derived = bool(rows)
    # 老任务里存着「几路共用一整串说明」的行：每一行只留自己那句，面板上才看得出
    # 该修哪一路，不至于四行字一模一样。
    alias_map = _note_aliases({str(r.get("source") or ""): r.get("status") or "" for r in rows})
    # 先算一遍每行的说明和状态：母渠道的汇总要用子渠道**修正之后**的状态，否则会出现
    # 「汇总说未配置、下面那行说失效」这种自相矛盾。
    prepared = []
    for r in rows:
        source = str(r.get("source") or "")
        note = trim_note(r.get("note"), source, alias_map)
        status = reconcile_status(r.get("status") or "", note, source, alias_map)
        prepared.append((r, source, note, status))
    names = [s for _, s, _, _ in prepared]
    live = {s: st for _, s, _, st in prepared}
    channels = []
    counts = {k: 0 for k in STATE_LABEL}
    by_stage: dict[str, dict] = {}
    for r, source, note, status in prepared:
        # 拆成多家的母渠道（backup 与 backup:qichacha、backup:riskbird…）是一行汇总，
        # 不是又一条渠道。把它和子渠道各算一路，失效数会重复报，人会照着一个并不存在的
        # 渠道去修。汇总行照常列在表里，只是不进计数。
        rollup = any(o != source and o.startswith(f"{source}:") for o in names)
        if rollup:
            summary = _parent_summary(source, live)
            if summary:
                note = summary
            # 状态也不继承采集器整轮的值，改按子渠道重算：否则一路可用、几路失效时，
            # 汇总行会盖成一个「请求失败」，把下面已经取到数据的那一行说成假的。
            status = _rollup_status(source, live) or status
        state = state_of(status)
        stage = r.get("stage") or "misc"
        item = {
            "stage": stage,
            "stage_label": label_stage(stage),
            "source": source,
            "label": label_source(source),
            "status": status,
            "status_text": text_of(status),
            "state": state,
            "state_label": STATE_LABEL.get(state, state),
            "note": note,
            "items": int(r.get("items") or 0),
            "calls": int(r.get("calls") or 0),
            "rollup": rollup,
        }
        channels.append(item)
        bucket = by_stage.setdefault(stage, {"stage": stage, "stage_label": item["stage_label"],
                                             "channels": [], "ok": 0, "dead": 0, "partial": 0,
                                             "config": 0, "skip": 0, "items": 0,
                                             "live": 0})
        bucket["channels"].append(item)
        if rollup:
            continue
        counts[state] = counts.get(state, 0) + 1
        if state != "skip":
            # 本轮启用过的来源才算「动了」，未启用的不进任何健康计数
            bucket["live"] += 1
            bucket["items"] += int(item["items"] or 0)
        if state == "ok":
            bucket["ok"] += 1
        elif state == "partial":
            bucket["partial"] += 1
        elif state == "config":
            bucket["config"] += 1
        elif state == "skip":
            bucket["skip"] += 1
        elif state == "dead":
            bucket["dead"] += 1
    # 有数据 / 失效排前面，未启用的沉底，面板一眼看到重点
    order = {"dead": 0, "config": 1, "partial": 2, "ok": 3, "empty": 4, "skip": 5}
    channels.sort(key=lambda x: (order.get(x["state"], 9), x["stage"], x["source"]))
    stages = sorted(by_stage.values(),
                    key=lambda s: (0 if s["live"] else 1, 0 if s["dead"] else 1,
                                   -len(s["channels"]), s["stage"]))
    return {
        "channels": channels,
        "stages": stages,
        "counts": counts,
        # 汇总行不计入「这趟用了几路」，否则同一路会被数两次
        "total": sum(1 for c in channels if not c.get("rollup")),
        "ok": counts.get("ok", 0),
        # 「失效」只数真的调了、真的坏了的；未配置是「缺凭据」，未启用是「这轮没勾」，
        # 三种混成一个数会让人以为自己没勾的来源在报错。
        "dead": counts.get("dead", 0),
        "config": counts.get("config", 0),
        "partial": counts.get("partial", 0),
        "idle": counts.get("skip", 0),
        "derived": derived,
    }
