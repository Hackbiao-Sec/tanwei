import React, { useState } from "react";
import { Icon } from "./Icons";

type Theme = "dark" | "light";

function readTheme(): Theme {
  return localStorage.getItem("tanwei.theme") === "dark" ? "dark" : "light";
}

/**
 * 主题切换自成一个组件：只重渲染这一个按钮，
 * 不再让整棵会话树（时间线几百条）跟着重渲染，切主题就不卡了。
 */
export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);

  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    const root = document.documentElement;
    // 切换瞬间关掉过渡，避免上百个元素同时做 transition
    root.classList.add("theme-switching");
    root.dataset.theme = next;
    try {
      localStorage.setItem("tanwei.theme", next);
    } catch {
      /* 隐私模式等场景忽略 */
    }
    requestAnimationFrame(() => {
      requestAnimationFrame(() => root.classList.remove("theme-switching"));
    });
    void window.tanwei.setWindowTheme(next);
  };

  return (
    <button
      className="tb-btn icon-only"
      onClick={toggle}
      title={theme === "dark" ? "切换浅色主题" : "切换深色主题"}
    >
      <Icon name={theme === "dark" ? "sun" : "moon"} size={14} />
    </button>
  );
}
