"""主体名归一与匹配（内部通用工具）。

企业主体名在不同数据源里写法不同：
  * 全称 / 简称（腾讯科技（深圳）有限公司 / 腾讯）
  * 半角括号 / 全角括号（(深圳) / （深圳））
  * 中间带空格、顿号、书名号
  * 历史名与现名同时存在

备案库、工商聚合、应用商店、搜索引擎的返回都要拿它跟用户输入对齐，
否则「名字差一个括号」就会被判成不匹配，最后表现为"查无结果"。
"""

from __future__ import annotations

import re

# 名称里不参与比对的字符：空白、全角空格、各种括号与常见分隔符
_NOISE = re.compile(r"[\s\u3000()（）\[\]【】{}<>《》·・,，.。、;；:：'\"“”‘’/\\|\-_+*#@&~]")

# 主体名后缀：比对时剥掉，避免「XX科技有限公司」与「XX科技」因后缀不同被判不等
_SUFFIX = re.compile(
    r"(股份有限公司|有限责任公司|有限公司|集团有限公司|company\s*limited|co\.?[,.]?\s*ltd\.?|"
    r"incorporated|inc\.?|ltd\.?|limited|corp\.?|corporation)$", re.I)

# 常见行政区划前缀：简称里常常省略，比对时当作可省片段
_REGION = ("北京", "上海", "天津", "重庆", "广东", "深圳", "广州", "杭州", "浙江", "江苏", "南京",
           "苏州", "四川", "成都", "湖北", "武汉", "湖南", "长沙", "福建", "厦门", "山东", "青岛",
           "陕西", "西安", "河南", "郑州", "安徽", "合肥", "江西", "南昌", "辽宁", "沈阳", "大连",
           "吉林", "黑龙江", "哈尔滨", "河北", "石家庄", "山西", "太原", "内蒙古", "云南", "昆明",
           "贵州", "贵阳", "广西", "南宁", "海南", "海口", "甘肃", "兰州", "青海", "西宁",
           "宁夏", "银川", "新疆", "乌鲁木齐", "西藏", "拉萨", "香港", "澳门", "中国")


def norm_name(name: str) -> str:
    """去掉不参与比对的字符并转小写：用于"是不是同一个主体"的粗比对。"""
    return _NOISE.sub("", (name or "").lower())


def core_name(name: str) -> str:
    """再剥掉公司组织形式后缀，留下「主体核心名」。"""
    s = norm_name(name)
    for _ in range(2):                      # 「集团有限公司」这类叠两层
        s2 = _SUFFIX.sub("", s)
        if s2 == s:
            break
        s = s2
    return s


def strip_region(name: str) -> str:
    """去掉开头的行政区划，得到可以作为品牌简称用的核心词。"""
    s = core_name(name)
    for r in sorted(_REGION, key=len, reverse=True):
        if s.startswith(r) and len(s) > len(r) + 1:
            return s[len(r):]
    return s


def same_subject(a: str, b: str) -> bool:
    """两个名字是否指向同一主体。

    判据是「归一后互相包含」：全称包含简称、分支机构的括号后缀、历史名多几字都算同一个。
    只做包含不做模糊相似度：备案库里的近似名往往是同名不同公司，宁可漏认也不要错并。
    """
    ka, kb = core_name(a), core_name(b)
    if not ka or not kb:
        return False
    if ka == kb:
        return True
    short, long = (ka, kb) if len(ka) <= len(kb) else (kb, ka)
    if len(short) < 2:
        return False
    return short in long


def brand_of(name: str) -> str:
    """取最像品牌的那一段：优先「去行政区划后的核心名」，退回落原始去噪名。"""
    s = strip_region(name)
    if len(s) >= 2:
        return s
    return core_name(name) or norm_name(name)


def ratio_of(text: str) -> float | None:
    """从「持股比例 51%」「51.0000%」这类文本里取数值；没有则 None。"""
    m = re.search(r"(\d+(?:\.\d+)?)\s*%", text or "")
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None
