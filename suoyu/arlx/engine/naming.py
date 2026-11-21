"""主体名形态判断：一个输入算「机构 / 企业」还是「产品 / 小程序名」。

这批后缀表以前在 collectors/applet.py、collectors/mp.py、collectors/mobile.py、
collectors/enterprise.py 和 pipeline_stages.py 里各写一份，结果
「厦门市特种设备检验检测院」这类以「院」结尾的事业单位在一处被判成主体、
在另一处又被当成小程序名去检索，整批结果跑偏（检索词是机构全名，
平台搜回来的都是无关小程序）。判断统一放这里，以后只改一处。
"""

import re

#: 出现就一定算机构 / 企业：这些尾巴产品名基本不会用。
ORG_TAIL = re.compile(
    r"(?:股份有限公司|有限责任公司|有限公司|公司|集团|分公司|子公司|企业|工厂|厂|"
    r"中心|学院|大学|学校|幼儿园|中学|小学|研究院|设计院|检测院|检验院|科学院|"
    r"研究所|事务所|银行|基金会|协会|委员会|工作室|合伙企业|合伙|控股|投资|"
    r"医院|银行)$"
)

#: 只有一个字的机关 / 事业单位尾巴。单字容易和产品名撞（「抽奖助手」「招聘会」），
#: 所以还要同时满足「名字够长」和「带行政区或事业味前缀」才认。
ORG_TAIL_WEAK = re.compile(r"(?:院|所|局|厅|委|办|署|站|馆|队|部|社)$")

#: 行政区 / 事业味前缀：和单字尾巴一起出现时，基本可以确定是机关事业单位。
ORG_MARK = re.compile(
    r"(?:省|市|县|旗|区|镇|乡|街道|自治区|自治州|监督|检验|检测|研究|技术|"
    r"人民|政府|事业|学院|大学|医院|中心|总台|广播|管理|服务)"
)

#: 法人 / 机构后缀，剥商标名时用（比工商全称后缀宽一点）。
STRIP_TAIL = re.compile(
    r"(?:股份有限公司|有限责任公司|有限公司|集团|公司|股份|"
    r"设计院|检测院|检验院|研究院|科学院|研究所|事务所|基金会|委员会|工作室|"
    r"学院|大学|医院|协会|中心)$"
)


def is_org_name(text: str) -> bool:
    """True = 输入看着是机构 / 企业全称，不能当产品名去检索。"""
    t = (text or "").strip()
    if len(t) < 4:
        return False
    if ORG_TAIL.search(t):
        return True
    return bool(len(t) >= 6 and ORG_TAIL_WEAK.search(t) and ORG_MARK.search(t))


def short_name(text: str) -> str:
    """剥掉法人后缀，留品牌 / 机构主名（「XX 检验检测院」→「XX」）。"""
    t = (text or "").strip()
    m = STRIP_TAIL.search(t)
    if m and len(t) - len(m.group(0)) >= 2:
        return t[:m.start()].strip()
    return t
