"""第三方域判定：托管服务 / 公共 CDN / 大厂开放平台。

站点大量嵌着邮箱服务商、微信登录、验证码、统计这类外部 JS。这些域里的接口、
密钥、域名都是别人的，收进自家资产表会把结果搅成一锅（厦门某院那轮就是这么被
腾讯企业邮的登录页灌进上百条 `qqmail.com` 接口的）。判定放在一处，抓取、JS 深
度分析、敏感提取都按同一套口径过滤。
"""
from __future__ import annotations

# 服务平台整域：出现即属第三方，不做「同根域例外」
FOREIGN_ROOTS: tuple[str, ...] = (
    # 社交通讯 / 开放平台 / 邮件
    "qq.com", "qcloud.com", "gtimg.com", "qpic.cn", "url.cn", "weixin.com",
    "weixin.qq.com", "weixinbridge.com", "wx.qq.com", "tencent.com", "tencentcloud.com",
    "tencent-cloud.com", "myqcloud.com", "dnspod.cn", "qlogo.cn",
    "google-analytics.com", "googletagmanager.com", "google.com", "gstatic.com",
    "googleapis.com", "doubleclick.net", "facebook.com", "facebook.net", "twitter.com",
    "baidu.com", "bdstatic.com", "bdimg.com", "bdurl.net", "cnzz.com", "51.la", "umeng.com",
    "umengcloud.com", "tongji.baidu.com", "hm.baidu.com", "sentry.io", "sentry-cdn.com",
    "jpush.cn", "getui.com", "getui.net", "igexin.com", "bugly.qq.com", "bugly.qq.com",
    "leancloud.cn", "leancloud.app", "mi.com", "xiaomi.com", "miui.com",
    "alibaba.com", "alicdn.com", "aliyun.com", "aliyuncs.com", "taobao.com", "tmall.com",
    "taobao.net", "alipay.com", "alipayobjects.com", "dingtalk.com", "dingtalkapps.com",
    "bytedance.com", "byteimg.com", "pstatp.com", "snssdk.com", "toutiao.com",
    "wangyi.com", "126.net", "127.net", "163.com", "netease.com",
    "qhimg.com", "qihucdn.com", "huawei.com", "hicloud.com", "dbankcdn.com",
    # 公共 CDN / 字体 / 前端库
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "bootstrapcdn.com",
    "bootcdn.net", "staticfile.org", "staticfile.net", "jquery.com", "fontawesome.com",
    "w3.org", "schema.org", "googleusercontent.com", "gstatic.com", "jqueryui.com",
    # 网络基础设施
    "akamai.net", "akamaized.net", "akamaiedge.net", "cloudflare.net", "cloudflare.com",
    "fastly.net", "awsdns.org", "azureedge.net", "azurewebsites.net",
)

# 搜索引擎与公开数据站：结果页、反查页里挖出来的域是它们自己的
SEARCH_ROOTS: tuple[str, ...] = (
    "bing.com", "baidu.com", "sogou.com", "so.com", "360.cn", "so.com", "google.com",
    "duckduckgo.com", "yandex.com", "yandex.ru", "toutiao.com", "mia.com", "te.gov.cn",
    "miit.gov.cn", "beian.miit.gov.cn", "chinaz.com", "aizhan.com", "icp.chinaz.com",
    "whois.com", "net.cn", "cnnic.cn", "crt.sh", "certspotter.com", "rapiddns.io",
    "hackertarget.com", "alienvault.com", "otx.alienvault.com", "anubisdb.com",
    "urlscan.io", "riddler.io", "threatbook.cn", "myssl.com", "ssllabs.com",
    "censys.io", "shodan.io", "fofa.info", "hunter.qianxin.com", "quake.360.net",
    "zoomeye.org", "virustotal.com", "securitytrails.com", "passivetotal.com",
    "chaos.projectdiscovery.io", "github.com", "githubapp.com", "githubusercontent.com",
    "qqmail.com", "exmail.qq.com", "w3.org",
)

# 静态资源尾巴：域名正则会把文件名、CSS 选择器、JS 变量误当域名（`favicon.ico`、
# `document.write`、`Math.random`、`p.desc`）。只挡明确的非域名形态。
_NON_DOMAIN_TLDS: frozenset[str] = frozenset({
    "ico", "png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "css", "scss", "less",
    "js", "mjs", "map", "json", "xml", "html", "htm", "woff", "woff2", "ttf", "eot",
    "otf", "mp4", "webm", "mp3", "wav", "txt", "md", "yml", "yaml", "zip", "gz", "rar",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "swf", "apk", "ipa",
    # JS 内置对象 / DOM 上的方法链后缀
    "write", "writeln", "length", "substr", "substring", "slice", "split", "replace",
    "indexof", "tofixed", "tostring", "valueof", "call", "apply", "bind", "push",
    "pop", "shift", "unshift", "splice", "join", "map", "filter", "reduce", "foreach",
    "then", "catch", "finally", "resolve", "reject", "random", "floor", "ceil", "round",
    "max", "min", "abs", "now", "parse", "stringify", "assign", "keys", "values",
    "entries", "hostname", "host", "href", "origin", "protocol", "pathname", "search",
    "hash", "port", "text", "desc", "contentul", "top", "center", "end", "js",
    "min", "bundle", "chunk", "compiled", "default", "esm", "prod", "dev", "cjs",
    "amd", "umd", "iife", "prototype", "constructor", "caller", "callee",
})

def _norm(domain: str) -> str:
    return (domain or "").strip().lower().strip(".")


def _hit(domain: str, roots: tuple[str, ...] | list[str]) -> bool:
    return any(domain == x or domain.endswith("." + x) for x in roots)


def is_foreign(domain: str, own_roots: set[str] | frozenset[str] | None = None) -> bool:
    """第三方域（托管服务 / 公共 CDN / 大厂平台 / 搜索引擎）。

    `own_roots` 里的根域是本次任务的自家根，命中的话即使撞上大厂表也放行——例如
    自家根就叫 `xxx.google.com` 的极少，但 `github.io` 这类托管根下的自家站要保。
    """
    d = _norm(domain)
    if not d or "." not in d:
        return True
    if own_roots and _hit(d, sorted(own_roots)):
        return False
    return _hit(d, FOREIGN_ROOTS) or _hit(d, SEARCH_ROOTS)


def is_non_domain(token: str) -> bool:
    """文件名 / 方法链 / 选择器误当域名。"""
    d = _norm(token)
    if not d or "." not in d:
        return True
    if " " in d or "@" in d or "/" in d:
        return True
    tld = d.rsplit(".", 1)[-1]
    if tld in _NON_DOMAIN_TLDS or any(ch.isdigit() for ch in tld):
        return True
    # 首段必须像域名标签；`window.gUin`、`asFile.substr` 这类大小写混杂的写法
    parts = d.split(".")
    for p in parts:
        if not p or not p.replace("-", "").isalnum():
            return True
        if any(ch.isupper() for ch in p[1:]):
            return True      # 大写字母出现在第二位及以后：`gUin`、`D27CDB6E` 这类变量/类 ID
    return False


def in_scope(host: str, own_roots: set[str] | frozenset[str] | None = None) -> bool:
    """这个主机是否落在自家根域下面（含裸 IP）。

    页面里嵌的第三方 JS、CDN 上的包、旁站 IP 都带着自己的主机名，抽出来的接口和密钥
    属于别人。只有 own_roots 下的主机和裸 IP 才允许往自家资产表里写。
    """
    from ...utils import is_ip, root_domain

    h = _norm(host)
    if not h:
        return False
    if is_ip(h):
        return True
    r = _norm(root_domain(h) or h)
    if not own_roots:
        return True
    return _hit(r, sorted(_norm(x) for x in own_roots))


def clean_domain(token: str) -> str:
    """可入库的第三个（及以上）方域名；废的返回空串。IP 不在此判定。"""
    d = _norm(token)
    return "" if is_non_domain(d) else d


def same_root(a: str, b: str) -> bool:
    return _norm(a) == _norm(b) or _norm(a).endswith("." + _norm(b)) or _norm(b).endswith(
        "." + _norm(a))
