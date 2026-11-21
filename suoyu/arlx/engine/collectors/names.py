"""主体名归一：把登记名拆成「区划前缀 + 核心字号」，供工商检索与备案比对共用。

工商检索和备案反查对简称的回包经常是登记全称：输入「漳州九龙江集团」，结果第一行是
「漳州市九龙江集团有限公司」——两者互相都不是对方的子串（差一个「市」和「有限公司」），
只按子串比对会当成没搜到，整条股权链和备案反查全部落空。

只剥组织形态词和开头几段区划，不做相似度：字号真正不同的主体（「跳动字节科技（北京）
有限公司」字号是「跳动字节科技」，「北京字节跳动科技」是「字节跳动科技」）压完仍然不相等，
不会把别人的母子公司算进来。
"""

from __future__ import annotations

import re

# 组织形态词：和主体是谁无关，只在检索结果里反复出现
CORE_FORM = ("有限责任公司", "股份有限公司", "有限公司", "控股集团", "集团公司",
             "总公司", "分公司", "集团", "控股", "股份", "公司", "有限", "责任")

# 行政区前缀：省 / 市 / 区 / 县 / 州 这类结尾才当区划剥，剥完至少还要剩两个字
_PLACE_RE = re.compile(r"^[\u4e00-\u9fa5]{1,3}(?:自治区|自治州|地区|省|市|县|区|州|盟|旗|镇|乡)")


def _norm(s) -> str:
    """去高亮标签、去空白、全角括号折半角。"""
    t = re.sub(r"<[^>]+>", "", str(s or ""))
    t = t.replace("（", "(").replace("）", ")").replace("　", "")
    return re.sub(r"\s+", "", t)


def core_parts(s) -> tuple[str, str]:
    """返回 ``(区划前缀, 核心字号)``。

    「漳州九龙江集团」→ ``('漳州', '九龙江')``；
    「漳州市九龙江集团有限公司」→ ``('漳州市', '九龙江')``。
    """
    t = _norm(s)
    if not t:
        return ("", "")
    t = re.sub(r"\([^)]*\)", "", t)
    for w in CORE_FORM:
        t = t.replace(w, "")
    place = ""
    for _ in range(3):
        m = _PLACE_RE.match(t)
        if not m or len(t) - len(m.group(0)) < 2:
            break
        place += m.group(0)
        t = t[len(m.group(0)):]
    return (place, t)


def core_same(a, b) -> bool:
    """两个主体名是否是同一个字号：核心字号相等，且区划不冲突。

    区划不冲突 = 两边一样、或有一边没写（「九龙江集团」对「漳州市九龙江集团」）、
    或一边的写法包含另一边（「漳州」对「漳州市」、「漳州市」对「福建省漳州市」）。
    「杭州银行」和「苏州银行」字号都压成「银行」，靠这一层区分开。
    """
    pa, ba = core_parts(a)
    pb, bb = core_parts(b)
    if len(ba) < 2 or ba != bb:
        return False
    if not pa or not pb or pa == pb:
        return True
    return pa in pb or pb in pa
