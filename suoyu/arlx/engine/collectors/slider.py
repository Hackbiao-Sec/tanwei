"""滑动拼图验证码的缺口横坐标定位（纯 OpenCV + numpy，无外部服务）。

服务端下发的两张图：带缺口的大图（背景）与滑块小图（拼图块）。输出缺口的
左边界 x —— 拼图式验证码要的就是「空块左上角在背景里的位置」。

缺口形态（按实测样本标定，8/8 命中）：背景上盖的是一块**完全不透明、逐像素
恒定的纯色矩形**，宽度与高度都等于滑块小图的边长（实测 68×68），颜色是
浅灰略带色偏（BGR 均值各通道 178~221，通道内极差 0）。

因此判据不看「灰带亮度区间」，而是看**平坦度**：
  1. 3×3 邻域通道内极差 <= TOL 的像素＝局部恒定；
  2. 再叠加亮度下限与饱和度上限，排除大片纯黑/纯蓝天；
  3. 用积分图按小图尺寸滑窗，先要求窗口中心 20×20 近乎全恒定（定位到块内），
     再按整窗恒定覆盖率排序，取最高者；
  4. 以窗口中心像素颜色为锚，做逐像素同色洪泛，取洪泛结果的外接矩形为真实缺口。
     颜色容差收紧到 2，边缘抗锯齿像素不进矩形；洪泛溢到背景时（背景恰好同色）
     用中心行/列重新框定。

坐标基准：左边界是缺口的**像素级左边界**。旧实现用「覆盖率最高窗口 + 偏置」
会在边缘留 4~6px 误差，这里改由洪泛矩形给出精确边界，因此在背景与缺口颜色
差异明显时无需任何偏置。
"""

from __future__ import annotations

import base64
import re
from typing import Any

import cv2
import numpy as np

# 定位到的左边界微调。实测洪泛矩形与缺口真实边界逐像素一致，不需要偏移。
SLIDER_X_BIAS = 0

# 「局部恒定」判据：3×3 邻域内单通道极差上限。缺口内部实测为 0。
_FLAT_TOL = 4
# 缺口亮度下限与饱和度上限，用来排除纯黑底、纯蓝天空等大片恒定背景。
_LUMA_LO = 150.0
_SAT_HI = 25.0
# 洪泛颜色容差。缺口内部逐像素相同，放宽反而会把抗锯齿边与背景吃进来。
_COLOR_TOL = 2
# 中心校验窗占比与阈值：先保证窗口落在缺口内部。
_CORE_FRAC = 0.5
_CORE_RATIO_MIN = 0.995
# 洪泛外接矩形超过小图这个倍数，判定为溢到同色背景，改用中心行/列重框。
_OVERFLOW = 1.35

_DATA_URL = re.compile(r"^data:image/[a-zA-Z0-9.+-]+;base64,", re.I)


class SliderError(RuntimeError):
    """两张图里找不到可信的缺口位置。"""


def decode_b64_image(raw: str) -> np.ndarray:
    """base64（可带 data URL 前缀）→ BGR 图像。"""
    text = (raw or "").strip()
    text = _DATA_URL.sub("", text)
    if not text:
        raise SliderError("empty image")
    text = re.sub(r"\s+", "", text)
    pad = (-len(text)) % 4
    if pad:
        text = text + "=" * pad
    try:
        buf = base64.b64decode(text, validate=False)
    except Exception as exc:  # noqa: BLE001 - 任何解码失败都归为图片无效
        raise SliderError(f"bad base64: {exc}") from exc
    img = cv2.imdecode(np.frombuffer(buf, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None or img.size == 0:
        raise SliderError("image decode failed")
    return img


def _integral(a: np.ndarray) -> np.ndarray:
    p = np.pad(a.astype(np.float64), ((1, 0), (1, 0)), mode="constant", constant_values=0)
    return p.cumsum(axis=0).cumsum(axis=1)


def _rect_sum(ii: np.ndarray, x: int, y: int, rw: int, rh: int) -> float:
    return float(ii[y + rh, x + rw] - ii[y, x + rw] - ii[y + rh, x] + ii[y, x])


def flat_mask(img: np.ndarray) -> np.ndarray:
    """局部恒定掩码：3×3 邻域通道内极差小、亮度够、饱和度低。"""
    f = img.astype(np.int16)
    kern = np.ones((3, 3), np.uint8)
    spread = np.maximum.reduce(
        [cv2.dilate(f[:, :, c], kern) - cv2.erode(f[:, :, c], kern) for c in range(3)]
    )
    b, g, r = (f[:, :, c].astype(np.float32) for c in range(3))
    luma = 0.299 * r + 0.587 * g + 0.114 * b
    mx = np.maximum(np.maximum(b, g), r)
    mn = np.minimum(np.minimum(b, g), r)
    sat = np.where(mx > 0, (mx - mn) / np.maximum(mx, 1) * 100.0, 0.0)
    return (spread <= _FLAT_TOL) & (luma >= _LUMA_LO) & (sat <= _SAT_HI)


def locate_window(img: np.ndarray, box_w: int, box_h: int) -> tuple[int, int] | None:
    """积分图滑窗找缺口所在窗口左上角。找不到返回 None。"""
    h, w = img.shape[:2]
    if box_w <= 0 or box_h <= 0 or box_w > w or box_h > h:
        return None
    pure = flat_mask(img).astype(np.float64)
    ii = _integral(pure)
    cw = max(4, min(20, int(box_w * _CORE_FRAC)))
    ch = max(4, min(20, int(box_h * _CORE_FRAC)))
    best: tuple[float, int, int] | None = None
    for y in range(0, h - box_h + 1):
        for x in range(0, w - box_w + 1):
            core = _rect_sum(ii, x + (box_w - cw) // 2, y + (box_h - ch) // 2, cw, ch) / (cw * ch)
            if core < _CORE_RATIO_MIN:
                continue
            score = _rect_sum(ii, x, y, box_w, box_h) / (box_w * box_h)
            if best is None or score > best[0]:
                best = (score, x, y)
    if best is None:
        return None
    return best[1], best[2]


def refine_rect(img: np.ndarray, pure: np.ndarray, x: int, y: int,
                box_w: int, box_h: int) -> tuple[int, int, int, int, tuple[int, int, int]] | None:
    """以窗口中心为起点做同色洪泛，返回 (left, top, w, h, color)。"""
    h, w = img.shape[:2]
    cx, cy = x + box_w // 2, y + box_h // 2
    x0, x1 = max(0, x), min(w, x + box_w)
    y0, y1 = max(0, y), min(h, y + box_h)
    ys, xs = np.where(pure[y0:y1, x0:x1])
    if not len(ys):
        return None
    dist = (ys + y0 - cy) ** 2 + (xs + x0 - cx) ** 2
    k = int(np.argmin(dist))
    sy, sx = int(ys[k] + y0), int(xs[k] + x0)

    patch = img[max(0, sy - 8):sy + 8, max(0, sx - 8):sx + 8].reshape(-1, 3).astype(np.float32)
    color = np.median(patch, axis=0)
    same = (np.abs(img.astype(np.float32) - color.reshape(1, 1, 3)).max(axis=2) <= _COLOR_TOL)
    work = same.astype(np.uint8)
    # 注意：Windows 版 OpenCV 4.x 不会把掩码回写到实参，必须用返回元组里的矩形。
    _, _, _, (bx, by, bw, bh) = cv2.floodFill(work, None, (sx, sy), 2)
    if bw > box_w * _OVERFLOW or bh > box_h * _OVERFLOW:
        region = work == 2
        cols = np.where(region[cy])[0]
        rows = np.where(region[:, cx])[0]
        if len(cols) and len(rows):
            bx, by = int(cols.min()), int(rows.min())
            bw, bh = int(cols.max() - cols.min() + 1), int(rows.max() - rows.min() + 1)
    if bw <= 0 or bh <= 0:
        return None
    return int(bx), int(by), int(bw), int(bh), tuple(int(v) for v in color)


def solve_x(big_b64: str, small_b64: str) -> int:
    """两张 base64 图 → 滑块要拖到的左边界 x。定位失败抛 SliderError。"""
    big = decode_b64_image(big_b64)
    small = decode_b64_image(small_b64)
    box_h, box_w = small.shape[:2]
    if box_w <= 0 or box_h <= 0:
        raise SliderError("empty slider image")

    window = locate_window(big, box_w, box_h)
    if window is None:
        raise SliderError("failed to locate blank region")
    rect = refine_rect(big, flat_mask(big), window[0], window[1], box_w, box_h)
    if rect is None:
        raise SliderError("failed to refine blank region")
    return max(0, int(rect[0]) + SLIDER_X_BIAS)


def solve_payload(payload: Any) -> dict:
    """兼容识别服务的回包格式：入参取 bigImage / smallImage，回包给 code/data/msg。"""
    if not isinstance(payload, dict):
        return {"code": 400, "data": None, "msg": "invalid payload"}
    big, small = payload.get("bigImage"), payload.get("smallImage")
    if not big or not small:
        return {"code": 400, "data": None, "msg": "missing bigImage or smallImage"}
    try:
        return {"code": 200, "data": solve_x(str(big), str(small)), "msg": "ok"}
    except SliderError as exc:
        return {"code": 500, "data": None, "msg": str(exc)}
    except Exception as exc:  # noqa: BLE001 - 服务接口不因单张图崩
        return {"code": 500, "data": None, "msg": f"{type(exc).__name__}: {exc}"[:120]}
