import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// 首帧前定主题，避免先黑后白闪一下。默认浅色：便携版换了 asar 路径就是全新 origin，localStorage 是空的
const stored = localStorage.getItem("tanwei.theme");
document.documentElement.dataset.theme = stored === "dark" ? "dark" : "light";

const el = document.getElementById("root");
if (!el) throw new Error("#root not found");

createRoot(el).render(<App />);
