"""主体侧采集结果 → 资产行。

同一次股权穿透 / 备案查询，以前只在流水线阶段里落库：单项直跑（`direct:*`）
只把 JSON 丢回前端，资产页、分面统计和导出都看不到，用户点完「股权穿透」
看到的是「跑完了但一条都没有」。这里把口径收成一份，两条执行路径都调它。

行格式就是 `db.store.upsert_asset()` 吃的字典：`kind / url / title / extra /
sources`，键里带母体名，重跑只更新不翻倍。
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..utils import is_ip, is_valid_domain, root_domain


def _ratio(v: Any) -> float:
    """把 '51.00%' / 51 / 0.51 统一成百分数。

    工商接口有的来源给的是 0~1 的小数，直接拿去比控股线会把 87% 当成 0.87%，
    控股企业就被摊到「对外投资」里，资产页和穿透图的家数对不上。
    """
    if v is None or v == "":
        return 0.0
    if isinstance(v, (int, float)):
        num = float(v)
    else:
        m = re.search(r"-?\d+(?:\.\d+)?", str(v).replace("％", "%"))
        if not m:
            return 0.0
        num = float(m.group(0))
    if "%" not in str(v) and 0 < num <= 1:
        num *= 100.0
    return round(num, 4)


def icp_rows(items: Iterable[dict] | None, owner: str = "") -> list[dict]:
    """备案记录一条一行。

    各家回包的备案号字段名不同：工信部叫 `icp`，股权链路叫 `licence`。只认
    `icp` 时，股权抓到的备案落库后号是空的，分表里就一列空白。
    """
    rows: list[dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        dom = str(it.get("domain") or "").strip().lower()
        if not dom:
            # APP / 小程序 / 快应用备案没有域名，只有「服务名称 + 备案号」。
            # 以前这里直接 continue，移动端备案一条也进不了库，看着像「主体没搜到东西」。
            app = str(it.get("app") or it.get("service_name")
                      or it.get("serviceName") or "").strip()
            if not app:
                continue
            num = str(it.get("icp") or it.get("licence") or it.get("license")
                      or it.get("code") or "").strip()
            unit = str(it.get("unit") or it.get("name")
                       or it.get("company") or "").strip() or owner
            kind = str(it.get("kind") or "").strip()
            key = num or app
            extra = dict(it)
            extra.update({"unit": unit, "name": app, "owner": owner or it.get("owner") or ""})
            if num:
                extra["icp"] = num
            is_mini = kind in ("mapp", "kapp")
            rows.append({
                "kind": "applet" if is_mini else "mobile",
                "url": f"{'applet' if is_mini else 'mobile'}:miit:{key}",
                "host": "", "root_domain": "",
                "title": " | ".join(x for x in (app, num, unit) if x),
                "extra": extra,
                "sources": str(it.get("source") or "miit"),
            })
            continue
        num = str(it.get("icp") or it.get("licence") or it.get("license")
                  or it.get("code") or "").strip()
        unit = str(it.get("unit") or it.get("name") or it.get("company") or "").strip() or owner
        site = str(it.get("site_name") or it.get("webname") or "").strip()
        root = dom
        try:
            if is_valid_domain(dom) and not is_ip(dom):
                root = root_domain(dom) or dom
            elif is_ip(dom):
                # 备案主体给的是 IP（实测 `icp: 58.22.2.54`）时没有根域可归，
                # 记成空串，否则根域分布图里会凭空多出「根域 = 一个 IP」的两行
                root = ""
        except Exception:
            root = dom
        extra = dict(it)
        extra["unit"] = unit
        if site:
            extra["site_name"] = site
        if num:
            extra["icp"] = num
        extra["owner"] = owner or it.get("owner") or ""
        rows.append({
            "kind": "icp", "url": f"icp:{dom}", "host": dom, "root_domain": root,
            "title": " | ".join(x for x in (unit, num) if x),
            "extra": extra,
            "sources": str(it.get("source") or "miit"),
        })
    return rows


def equity_rows(name: str, data: dict[str, Any] | None, ratio: float = 100.0) -> list[dict]:
    """一次股权穿透摊成六类资产：链路本体 / 分支机构 / 备案 / 控股 / 投资 / 股东 / 软著。

    `data` 用 `eq.as_dict()` 的形状，流水线和单项直跑拿到的都是同一份。
    `ratio` 是控股门槛：链路里累计持股低于它的主体不算「控股企业」。
    """
    name = str(name or "").strip()
    data = data or {}
    if not name:
        return []
    rows: list[dict] = [{
        "kind": "equity", "url": f"equity:{name}", "host": "",
        "title": f"{name} 股权链路", "extra": data, "sources": "equity",
    }]

    # 分支机构单列一类资产：导出有独立分表，挂在链路 extra 里查不了、也进不了分面统计
    for br in data.get("branches") or []:
        bnm = str(br.get("name") or "").strip()
        if not bnm:
            continue
        rows.append({
            "kind": "branch", "url": f"branch:{name}:{bnm}", "host": "", "title": bnm,
            "extra": {"name": bnm, "parent": name, "relation": f"{name} 的分支机构",
                      "legal": br.get("legal") or "",
                      "status": br.get("status") or "",
                      "pid": br.get("pid") or "",
                      "capital": br.get("capital") or "",
                      "established": br.get("established") or "",
                      "address": br.get("address") or ""},
            "sources": "equity",
        })

    rows.extend(icp_rows(data.get("icps"), name))

    # 控股企业：链路里累计持股达到门槛的主体
    for c in data.get("chain") or []:
        cnm = str(c.get("name") or "").strip()
        if not cnm or cnm == name:
            continue
        acc = _ratio(c.get("acc_ratio", c.get("ratio", 0)))
        if acc < float(ratio or 0):
            # 累计持股没过控股门槛的链路节点照样落一条：它们不是「控股企业」，
            # 但是穿透挖到的真实关联主体，直接丢掉会让链路看着比实际短。
            rows.append({
                "kind": "invest", "url": f"invest:{name}:{cnm}", "host": "", "title": cnm,
                "extra": {"name": cnm, "parent": c.get("parent") or name,
                          "level": c.get("depth") or 1, "ratio": acc,
                          "pid": c.get("pid") or "",
                          "status": c.get("status") or "",
                          "relation": f"{c.get('parent') or name} 持股 {acc:g}%（未过控股门槛）"},
                "sources": "equity",
            })
            continue
        rows.append({
            "kind": "holds", "url": f"holds:{name}:{cnm}", "host": "", "title": cnm,
            "extra": {"name": cnm, "parent": name, "level": c.get("depth") or 1,
                      "ratio": acc, "pid": c.get("pid") or "",
                      "capital": c.get("capital") or "",
                      "status": c.get("status") or "",
                      "relation": f"{name} 持股 {acc:g}%"},
            "sources": "equity",
        })

    for iv in data.get("invests") or []:
        inm = str(iv.get("name") or "").strip()
        if not inm or inm == name:
            continue
        iratio = _ratio(iv.get("total_ratio", iv.get("ratio", 0)))
        rows.append({
            "kind": "invest", "url": f"invest:{name}:{inm}", "host": "", "title": inm,
            "extra": {"name": inm, "parent": name, "ratio": iratio,
                      "pid": iv.get("pid") or iv.get("id") or "",
                      "status": iv.get("status") or "",
                      "relation": f"{name} 对外投资"},
            "sources": "equity",
        })

    for hd in data.get("holders") or []:
        hnm = str(hd.get("name") or "").strip()
        if not hnm:
            continue
        hratio = _ratio(hd.get("ratio", 0))
        rows.append({
            "kind": "partner", "url": f"partner:{name}:{hnm}", "host": "", "title": hnm,
            "extra": {"name": hnm, "parent": name, "ratio": hratio,
                      "capital": hd.get("capital") or "",
                      "pid": hd.get("pid") or "",
                      "type": hd.get("type") or "",
                      "relation": f"{name} 的股东"},
            "sources": "equity",
        })

    for cp in data.get("copyrights") or []:
        cpnm = str(cp.get("name") or cp.get("softwareName") or "").strip()
        if not cpnm:
            continue
        item = dict(cp)
        item["name"] = cpnm
        item["parent"] = name
        item["relation"] = f"{name} 的软件著作权"
        rows.append({
            "kind": "copyright", "url": f"copyright:{name}:{cpnm}", "host": "",
            "title": cpnm, "extra": item, "sources": "equity",
        })

    # 五个附加画像：移动应用 / 公众号 / 微博 / 招聘 / 供应商。
    # 都挂在主体侧，不进 Web 面，避免把站点条数撑大。
    for ap in data.get("apps") or []:
        anm = str(ap.get("name") or "").strip()
        if not anm:
            continue
        item = dict(ap)
        item["name"] = anm
        item["parent"] = name
        rows.append({
            "kind": "mobileapp", "url": f"mobileapp:{name}:{anm}", "host": "",
            "title": " | ".join(x for x in (ap.get("classify") or "",
                                            ap.get("version") or "") if x),
            "extra": item, "sources": "equity",
        })

    for wc in data.get("wechats") or []:
        wnm = str(wc.get("name") or "").strip()
        if not wnm:
            continue
        item = dict(wc)
        item["name"] = wnm
        item["parent"] = name
        rows.append({
            "kind": "wechatoa", "url": f"wechatoa:{name}:{wnm}", "host": "",
            "title": wc.get("account") or "", "extra": item, "sources": "equity",
        })

    for wb in data.get("weibos") or []:
        wnm = str(wb.get("name") or "").strip()
        if not wnm:
            continue
        item = dict(wb)
        item["name"] = wnm
        item["parent"] = name
        rows.append({
            "kind": "weibo", "url": f"weibo:{wnm}", "host": "",
            "title": wb.get("brief") or "", "extra": item, "sources": "equity",
        })

    for jb in data.get("jobs") or []:
        jnm = str(jb.get("name") or "").strip()
        if not jnm:
            continue
        item = dict(jb)
        item["name"] = jnm
        item["parent"] = name
        rows.append({
            "kind": "job", "url": f"job:{name}:{jnm}", "host": "",
            "title": " | ".join(x for x in (jb.get("location") or "",
                                            jb.get("education") or "") if x),
            "extra": item, "sources": "equity",
        })

    for sp in data.get("suppliers") or []:
        snm = str(sp.get("name") or "").strip()
        if not snm:
            continue
        item = dict(sp)
        item["name"] = snm
        item["parent"] = name
        rows.append({
            "kind": "supplier", "url": f"supplier:{name}:{snm}", "host": "",
            "title": " | ".join(x for x in (sp.get("source") or "",
                                            sp.get("cooperated") or "") if x),
            "extra": item, "sources": "equity",
        })

    return rows

def applet_rows(apps: Iterable[dict] | None, out_root: str = "") -> list[dict]:
    """本机小程序解包结果 → 资产行（小程序档案 + 接口 + 密钥命中）。

    一个包解出来的东西分三类：小程序本体（AppID、包内标题、主体、版本、文件数、
    解包目录）、后端接口、包里扫出来的账号/Key/连接串。三类都进资产表，
    资产页和导出才看得到「这个小程序调了什么」。
    """
    try:
        from .collectors.wxscan import RULES
        rule_names = {r["id"]: r["name"] for r in RULES}
    except Exception:
        rule_names = {}
    rows: list[dict] = []
    for app in apps or []:
        if not isinstance(app, dict):
            continue
        appid = str(app.get("appid") or "").strip()
        name = str(app.get("name") or "").strip()
        subject = str(app.get("subject") or "").strip()
        if not appid:
            # 没有 AppID 就不是能打开的小程序，但不等于没线索：备案库给的是登记信息，
            # 公开检索只给名字。以前这里整条跳过，单项跑小程序明明查到了东西，
            # 资产页和导出却是 0 条 —— 看着像「全打偏」。分开成两种面单列出来。
            lic = str(app.get("license") or "").strip()
            doms = [str(x) for x in (app.get("domains") or []) if x]
            notes = [str(x) for x in (app.get("notes") or []) if x]
            if lic:
                label = name or f"小程序备案 {lic}"
                rows.append({
                    "kind": "applet_icp", "url": f"applet-icp:{lic}",
                    "host": "", "title": label, "sources": "miit",
                    "extra": {"license": lic, "name": name, "subject": subject,
                              "domains": doms[:20], "notes": notes[:8],
                              "note": "备案库只登记单位名与备案号，不公开小程序名与 AppID"},
                })
            elif name:
                key = f"{subject}:{name}" if subject else name
                rows.append({
                    "kind": "applet_hint", "url": f"applet-hint:{key}",
                    "host": "", "title": f"小程序线索 {name}",
                    "sources": "applet",
                    "extra": {"name": name, "subject": subject,
                              "domains": doms[:20], "notes": notes[:8],
                              "note": "只有名字、没有明文 AppID：打不开包，需要 AppID 才能取实体"},
                })
            continue
        label = name or appid
        apis = [str(x) for x in (app.get("apis") or []) if x]
        doms = [str(x) for x in (app.get("domains") or []) if x]
        hits = app.get("hits") if isinstance(app.get("hits"), dict) else {}
        files = int(app.get("files") or 0)
        title = f"小程序 {label}"
        if subject and subject not in (label, appid):
            title += f"（{subject}）"
        if files:
            title += f" · {files} 文件"
        rows.append({
            "kind": "applet", "url": f"applet:{appid}", "host": appid,
            "root_domain": appid, "title": title, "sources": "applet-local",
            "extra": {"appid": appid, "name": name, "subject": subject,
                      "gh_ids": app.get("gh_ids") or [],
                      "titles": app.get("titles") or [],
                      "entry": app.get("entry") or "",
                      "version": app.get("version") or "",
                      "encrypted": app.get("encrypted"),
                      "packages": app.get("packages"), "files": files,
                      "bytes": app.get("bytes"),
                      "unpacked": app.get("unpacked"), "pretty": app.get("pretty"),
                      "unpack_dir": app.get("unpack_dir") or "",
                      "pretty_dir": app.get("pretty_dir") or "",
                      "out_root": out_root,
                      "buckets": app.get("buckets") or [],
                      "counts": app.get("counts") or {},
                      "apis": apis[:40], "domains": doms[:40],
                      "notes": app.get("notes") or []},
        })
        for url in apis[:300]:
            dom = ""
            try:
                dom = url.split("://", 1)[1].split("/")[0].split(":")[0]
            except Exception:
                dom = ""
            rows.append({
                "kind": "api", "url": url, "host": dom,
                "title": f"小程序接口 {label}", "sources": f"applet-local:{appid}",
                "extra": {"appid": appid, "applet": label},
            })
        for rid, vals in hits.items():
            for val in (vals or [])[:40]:
                rows.append({
                    "kind": "leak", "url": f"applet:{appid}:{rid}:{str(val)[:60]}",
                    "host": appid,
                    "title": f"{rule_names.get(rid, rid)}（小程序包）",
                    "sources": f"applet-local:{appid}",
                    "extra": {"appid": appid, "rule": rid, "value": val,
                              "applet": label},
                })
    return rows
