"""微博账号采集。

实测（2026-11-09）三条通道，只有带登录态的站内搜索真出账号：

主通道 · 站内搜索（需要登录态）
  `m.weibo.cn/api/container/getIndex?containerid=100103type=3&q=<词>&page_type=searchall`
  一次回用户卡：`cards[].card_group[].user` 里有 id / screen_name / description /
  profile_image_url / followers_count / verified，uid 与昵称一次拿全。
  无 Cookie 时回 `{"ok":-100,"url":"…passport.weibo.com/sso/signin…"}` 或 HTTP 432，
  所以 Cookie 必须由调用方给：配置项 `weibo.cookie`，或本项参数里的「Cookie」，参数优先。
  别指望换 UA / Referer / 换哪个老接口能绕过 —— 432 是账号维度的拒绝，不是请求头的。

兜底 · 搜索引擎发现（不需要登录，命中率低）
  查 `site:weibo.com "<主体名>"` 抽 URL 里的 uid。实测中文 query 下搜索引擎基本不遵守
  `site:`，回的是官网 / 招聘站 / 年报 PDF，所以这条只当兜底，拿到就记「疑似账号」，
  一律标 low，由人确认。

废路 · 无 Cookie 直接取档案
  `getIndex?type=uid&value=<uid>` 无 Cookie 同样是 432，试过就不再当可用通道。
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from ...config import config
from ...utils import is_valid_domain
from ..sources import search as web
from ..sources.passive import _get

#: 用户主页几种写法：/u/1234567890、/profile/123、/n/name，以及 m.weibo.cn 的 /u/
_UID = re.compile(r"(?:weibo\.(?:com|cn)|m\.weibo\.cn)/(?:u/|profile/|n/)?(\d{6,12})")
_UID_Q = re.compile(r"[?&]uid=(\d{6,12})")
_TAG = re.compile(r"<[^>]+>")
# 法人后缀：搜微博时带上「股份有限公司」几乎搜不到东西，昵称也不会这么写
_SUFFIX = re.compile(r"(?:股份)?有限(?:责任)?公司$|集团$|股份有限公司$")
_PAREN = re.compile(r"[（(][^）)]{0,40}[）)]")
API = "https://m.weibo.cn/api/container/getIndex"

_MOBILE_HEAD = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 "
                  "(KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Referer": "https://m.weibo.cn/",
    "MWeibo-Pwa": "1",
    "X-Requested-With": "XMLHttpRequest",
}


@dataclass
class Weibo:
    """一个微博账号。uid 是唯一键，同名号按 uid 分开记。"""

    uid: str = ""
    nick: str = ""
    desc: str = ""
    avatar: str = ""
    followers: int = 0
    verified: bool = False
    url: str = ""
    relation: str = ""          # 从谁身上、几级投资穿下来的（上层填）
    relevance: str = "low"      # high / low：昵称是否对得上目标词
    evidence: str = ""          # 这个 uid 是怎么来的
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "uid": self.uid, "nick": self.nick, "desc": self.desc, "avatar": self.avatar,
            "followers": self.followers, "verified": self.verified,
            "url": self.url or f"https://m.weibo.cn/u/{self.uid}",
            "relation": self.relation, "relevance": self.relevance,
            "evidence": self.evidence, "notes": self.notes,
        }


def _strip(raw: str) -> str:
    return re.sub(r"\s+", " ", _TAG.sub("", raw or "")).strip()


def core_name(target: str) -> str:
    """搜索用的短名：去括注、去法人后缀。括号里多是「集团」「某某分公司」这类补充。"""
    s = _PAREN.sub("", str(target or "")).strip()
    s = _SUFFIX.sub("", s).strip()
    return s or str(target or "").strip()


def tokens(target: str) -> list[str]:
    """回比用的词根：全名、短名、逐段合称。用来判「这号是不是这个主体的」。"""
    full = str(target or "").strip()
    core = core_name(full)
    out = [core]
    if full and full != core:
        out.append(full)
    # 「福建龙溪轴承」这类：短名开头连续 4 字以上也算命中（机关名常带地名）
    if len(core) >= 6:
        out.append(core[:6])
        out.append(core[:4])
    return [t for t in dict.fromkeys(out) if len(t) >= 2]


def _cookie(explicit: str = "") -> str:
    """参数优先，其次配置。空串表示没有登录态。

    设置页统一把来源凭据写在 `sources.<key>` 下，老配置文件则写在 `[weibo]`，
    两条都认，先读新路径。
    """
    if explicit and str(explicit).strip():
        return str(explicit).strip()
    for path in (("sources", "weibo", "cookie"), ("weibo", "cookie")):
        try:
            v = str(config.get(*path, default="") or "").strip()
        except Exception:
            v = ""
        if v:
            return v
    return ""


def _queries(target: str) -> list[str]:
    core = core_name(target)
    full = str(target or "").strip()
    out = [f'site:weibo.com "{core}"', f'site:weibo.cn "{core}"']
    if full and full != core:
        out.append(f'site:weibo.com "{full}"')
    return out


async def _discover(target: str, deadline: float) -> tuple[dict[str, Weibo], list[str]]:
    """搜索引擎发现用户主页。只认 URL 里的 uid，标题当昵称候选。"""
    found: dict[str, Weibo] = {}
    notes: list[str] = []

    async def one(q: str):
        try:
            out = await web.search(q, engines=("bing", "so360", "sogou"),
                                   timeout=18, budget=6.0)
        except Exception as e:
            notes.append(f"检索「{q}」失败：{type(e).__name__}")
            return
        for h in getattr(out, "hits", []) or []:
            url = str(getattr(h, "url", "") or "")
            m = _UID.search(url) or _UID_Q.search(url)
            if not m:
                continue
            uid = m.group(1)
            nick = _strip(getattr(h, "title", "") or "")
            # 标题常是「xxx的微博_微博」这种，削掉尾巴才是昵称
            nick = re.sub(r"[_\-|]+\s*微博.*$", "", nick).strip() or nick
            it = found.get(uid)
            if it is None:
                found[uid] = Weibo(uid=uid, nick=nick, url=url,
                                   evidence=f"检索命中：{q}")
            elif not it.nick and nick:
                it.nick = nick

    try:
        await asyncio.wait_for(asyncio.gather(*(one(q) for q in _queries(target))),
                               timeout=max(6.0, deadline * 0.6))
    except asyncio.TimeoutError:
        notes.append("检索未在时限内完成，只保留已返回的部分")
    return found, notes


async def _api_search(keyword: str, cookie: str, *, pages: int = 1,
                      timeout: float = 16) -> tuple[list[Weibo], list[str]]:
    """站内搜索用户卡。带 Cookie 才有效，一次拿 uid / 昵称 / 简介 / 头像 / 粉丝数。"""
    out: list[Weibo] = []
    notes: list[str] = []
    head = dict(_MOBILE_HEAD)
    if cookie:
        head["Cookie"] = cookie
    for page in range(1, max(1, pages) + 1):
        params = {"containerid": f"100103type=3&q={keyword}", "page_type": "searchall"}
        if page > 1:
            params["page"] = page
        r = await _get(API, params, headers=head, timeout=timeout, proxy="")
        if r is None:
            notes.append(f"站内搜索「{keyword}」无响应")
            return out, notes
        try:
            d = r.json()
        except Exception:
            notes.append(f"站内搜索「{keyword}」回非 JSON（HTTP {r.status_code}）")
            return out, notes
        if d.get("ok") == -100 or "passport" in str(d.get("url") or ""):
            notes.append("站内搜索要求登录（ok:-100）：Cookie 无效或已过期")
            return out, notes
        if r.status_code == 432:
            notes.append("站内搜索被拒（HTTP 432）：多是被判成高频，隔一会儿或用有效 Cookie 再跑")
            return out, notes
        cards = ((d.get("data") or {}).get("cards") or [])
        got = 0
        for cd in cards:
            groups = [cd] + list(cd.get("card_group") or [])
            for g in groups:
                ui = g.get("user") or {}
                uid = str(ui.get("id") or "")
                if not uid:
                    continue
                wb = Weibo(uid=uid,
                           nick=_strip(ui.get("screen_name") or ""),
                           desc=_strip(ui.get("description") or ""),
                           avatar=str(ui.get("profile_image_url") or ""),
                           verified=bool(ui.get("verified")),
                           url=str(ui.get("profile_url") or "") or f"https://m.weibo.cn/u/{uid}",
                           evidence=f"站内搜索「{keyword}」第 {page} 页")
                try:
                    wb.followers = int(ui.get("followers_count") or 0)
                except Exception:
                    wb.followers = 0
                out.append(wb)
                got += 1
        if got == 0:
            break
    return out, notes


async def _profile(wb: Weibo, cookie: str, timeout: float) -> None:
    """补一次档案。拿不到就留着「只有链接」，不猜字段。"""
    head = dict(_MOBILE_HEAD)
    if cookie:
        head["Cookie"] = cookie
    r = await _get(API, {"type": "uid", "value": wb.uid}, headers=head,
                   timeout=timeout, proxy="")
    if r is None:
        wb.notes.append("档案接口无响应")
        return
    if r.status_code == 432:
        wb.notes.append("档案接口 432（登录态被拒），只留主页链接")
        return
    try:
        d = r.json()
    except Exception:
        wb.notes.append(f"档案接口回非 JSON（HTTP {r.status_code}）")
        return
    if d.get("ok") == -100 or "passport" in str(d.get("url") or ""):
        wb.notes.append("档案接口要求登录（ok:-100），Cookie 无效或已过期")
        return
    ui = ((d.get("data") or {}).get("userInfo") or {})
    if not ui:
        wb.notes.append("档案接口无 userInfo")
        return
    wb.nick = _strip(ui.get("screen_name") or "") or wb.nick
    wb.desc = _strip(ui.get("description") or "")
    wb.avatar = str(ui.get("profile_image_url") or "")
    try:
        wb.followers = int(ui.get("followers_count") or 0)
    except Exception:
        wb.followers = 0
    wb.verified = bool(ui.get("verified"))
    if ui.get("profile_url"):
        wb.url = str(ui.get("profile_url"))


async def weibo_search(target: str, *, limit: int = 8, cookie: str = "",
                       deadline: float = 26.0) -> dict:
    """按主体名找微博账号：有登录态走站内搜索，没有就只留检索发现。"""
    target = str(target or "").strip()
    if not target:
        return {"items": [], "status": "empty", "notes": ["目标为空"],
                "cookie_used": False}

    ck = _cookie(cookie)
    toks = tokens(target)
    notes: list[str] = []
    found: dict[str, Weibo] = {}

    if ck:
        # 站内搜索按关键词广度吃结果：短名比法人全名命中多，两个都打，按 uid 合并
        kws = [k for k in dict.fromkeys([core_name(target), target]) if k]
        try:
            got = await asyncio.wait_for(
                asyncio.gather(*(_api_search(k, ck, pages=1, timeout=16) for k in kws)),
                timeout=max(8.0, deadline * 0.7))
        except asyncio.TimeoutError:
            got = []
            notes.append("站内搜索未在时限内完成，只用检索发现的结果")
        for items, ns in got:
            notes.extend(ns)
            for wb in items:
                # 站内搜索一次已经把昵称/简介/头像都带回来了，不需要再逐号补档案
                old = found.get(wb.uid)
                if old is None or (not old.desc and wb.desc):
                    found[wb.uid] = wb

    if not found:
        disc, ns = await _discover(target, deadline)
        notes.extend(ns)
        found.update(disc)
        if ck and disc:
            notes.append("站内搜索没回用户卡，退到检索发现；昵称/简介/头像可能缺")
        if not ck:
            notes.append("未配置微博登录态：只出检索到的账号与链接；"
                         "在配置 weibo.cookie 或本项「Cookie」里填后可用站内搜索拿到"
                         "昵称、简介、头像、粉丝数与认证")

    out = list(found.values())
    for wb in out:
        blob = f"{wb.nick} {wb.desc}"
        wb.relevance = "high" if any(t and t in blob for t in toks) else "low"

    if ck and out:
        # 只给「只有链接、没昵称简介」的号补档案，站内搜索回来的别重复请求
        thin = [w for w in out if not w.nick or not w.desc]
        if thin:
            sem = asyncio.Semaphore(3)
            left = max(1.0, deadline - 6.0)

            async def one(wb: Weibo):
                async with sem:
                    try:
                        await asyncio.wait_for(_profile(wb, ck, 14), timeout=left)
                    except asyncio.TimeoutError:
                        wb.notes.append("档案超时")
                    except Exception as e:
                        wb.notes.append(f"档案失败：{type(e).__name__}")

            try:
                await asyncio.wait_for(asyncio.gather(*(one(w) for w in thin)),
                                       timeout=left + 4)
            except asyncio.TimeoutError:
                notes.append("档案未全部补完，已返回完成的部分")

    if not out:
        notes.append("没有命中微博账号：该主体可能没有官方号，"
                     "或当前检索通道对该主体词不敏感")

    out.sort(key=lambda w: (w.relevance != "high", not w.verified, -w.followers))
    items = [w.as_dict() for w in out[:max(1, int(limit or 8))]]
    if out and all(w.relevance == "low" for w in out):
        notes.append("命中的号昵称都对不上目标词，只列出来供人确认，别当官方号用")
    return {
        "items": items,
        "domains": domains_of(items),
        "status": "ok" if (out and ck) else ("nocookie" if out else "nohit"),
        "cookie_used": bool(ck),
        "notes": list(dict.fromkeys(notes))[:8],
    }


# 同一目标并发只跑一趟：流水线里品牌名与公司全名可能同时打进来
_INFLIGHT: dict[str, asyncio.Task] = {}


async def collect_weibo(target: str, *, limit: int = 8, cookie: str = "",
                        deadline: float = 26.0) -> dict:
    """统一入口，外面套总时限：到点交已完成部分，不把上游阶段顶死。"""
    key = re.sub(r"\s+", "", target or "").lower()
    running = _INFLIGHT.get(key)
    if running is not None:
        return await asyncio.shield(running)
    task = asyncio.create_task(weibo_search(target, limit=limit, cookie=cookie,
                                            deadline=deadline))
    _INFLIGHT[key] = task
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=deadline + 8)
    except asyncio.TimeoutError:
        if task.done() and not task.cancelled() and task.exception() is None:
            return task.result()
        return {"items": [], "status": "timeout", "cookie_used": bool(_cookie(cookie)),
                "notes": [f"采集超时 {deadline:.0f}s"]}
    finally:
        if _INFLIGHT.get(key) is task:
            _INFLIGHT.pop(key, None)


def domains_of(items: list[dict]) -> list[str]:
    """账号简介里出现的域名：和公众号那条一样，业务域比账号本身更值钱。"""
    out: set[str] = set()
    for it in items or []:
        for d in re.findall(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,10})\b",
                            str(it.get("desc") or ""), re.I):
            if is_valid_domain(d) and not d.endswith(("weibo.com", "weibo.cn", "sinaimg.cn",
                                                      "sina.com.cn", "bcebos.com")):
                out.add(d.lower())
    return sorted(out)
