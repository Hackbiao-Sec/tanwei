import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// 首帧前定主题，避免先黑后白闪一下
const stored = localStorage.getItem("tanwei.theme");
document.documentElement.dataset.theme = stored === "light" ? "light" : "dark";

const el = document.getElementById("root");
if (!el) throw new Error("#root not found");

createRoot(el).render(<App />);
