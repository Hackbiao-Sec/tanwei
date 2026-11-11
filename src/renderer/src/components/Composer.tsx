import React, { useEffect, useMemo, useRef, useState } from "react";
import type { CommandInfo, ModelInfo, PermissionMode } from "@shared/types";
import { Icon } from "./Icons";
import { MODE_LABEL } from "./Timeline";

const MODES: PermissionMode[] = ["ask", "auto", "plan", "always-approve"];
const MODE_HINT: Record<PermissionMode, string> = {
  ask: "每个工具调用都先问我",
  auto: "低风险自动过，高风险再问",
  plan: "先出计划，不动手",
  "always-approve": "工具全部放行",
};

export function Composer({
  disabled,
  busy,
  mode,
  model,
  models,
  commands,
  cwd,
  onSend,
  onCancel,
  onMode,
  onModel,
  onPickFolder,
}: {
  disabled: boolean;
  busy: boolean;
  mode: PermissionMode;
  model?: string;
  models: ModelInfo[];
  commands: CommandInfo[];
  cwd: string;
  onSend: (text: string) => void;
  onCancel: () => void;
  onMode: (mode: PermissionMode) => void;
  onModel: (id: string) => void;
  onPickFolder: () => void;
}) {
  const [value, setValue] = useState("");
  const [paletteIndex, setPaletteIndex] = useState(0);
  const areaRef = useRef<HTMLTextAreaElement>(null);

  const palette = useMemo(() => {
    const m = /^\/([^\s]*)$/.exec(value);
    if (!m) return null;
    const q = m[1].toLowerCase();
    const rows = commands.filter(
      (c) => !q || c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q),
    );
    return rows.slice(0, 40);
  }, [value, commands]);

  useEffect(() => {
    setPaletteIndex(0);
  }, [palette?.length, value.startsWith("/")]);

  useEffect(() => {
    const el = areaRef.current;
    if (!el) return;
    el.style.height = "0px";
    el.style.height = `${Math.min(el.scrollHeight, 220)}px`;
  }, [value]);

  useEffect(() => {
    areaRef.current?.focus();
  }, [disabled]);

  const send = () => {
    const text = value.trim();
    if (!text || disabled) return;
    onSend(text);
    setValue("");
  };

  const applyCommand = (c: CommandInfo) => {
    setValue(`/${c.name} `);
    requestAnimationFrame(() => areaRef.current?.focus());
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (palette && palette.length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setPaletteIndex((i) => (i + 1) % palette.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setPaletteIndex((i) => (i - 1 + palette.length) % palette.length);
        return;
      }
      if (e.key === "Tab" || (e.key === "Enter" && !e.shiftKey)) {
        e.preventDefault();
        applyCommand(palette[paletteIndex]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setValue("");
        return;
      }
    }
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="composer">
      {palette && palette.length > 0 ? (
        <div className="palette">
          <div className="palette-head">
            <Icon name="bolt" size={12} />
            <span>命令 · {palette.length}</span>
            <span className="palette-tip">↑↓ 选择 · Tab 补全 · Esc 关闭</span>
          </div>
          <div className="palette-list">
            {palette.map((c, i) => (
              <button
                key={c.name}
                className={`palette-row ${i === paletteIndex ? "active" : ""}`}
                onMouseEnter={() => setPaletteIndex(i)}
                onClick={() => applyCommand(c)}
              >
                <span className="palette-name">/{c.name}</span>
                <span className="palette-desc">{c.description}</span>
                {c.hint ? <span className="palette-hint">{c.hint}</span> : null}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <div className={`composer-box ${disabled ? "off" : ""}`}>
        <textarea
          ref={areaRef}
          className="composer-input"
          placeholder={
            disabled
              ? "先新建或打开一个会话…"
              : "说目标，或输入 / 唤出命令。Enter 发送 · Shift+Enter 换行"
          }
          value={value}
          rows={1}
          disabled={disabled}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <div className="composer-bar">
          <div className="composer-left">
            <button className="cwd-chip" onClick={onPickFolder} title="切换工作目录">
              <Icon name="folder" size={12} />
              <span className="cwd-text">{cwd || "选择目录"}</span>
            </button>
            <div className="segmented">
              {MODES.map((m) => (
                <button
                  key={m}
                  className={`seg ${mode === m ? "on" : ""}`}
                  title={MODE_HINT[m]}
                  disabled={disabled}
                  onClick={() => onMode(m)}
                >
                  {MODE_LABEL[m]}
                </button>
              ))}
            </div>
            {models.length > 0 ? (
              <label className="model-pick" title="切换模型">
                <Icon name="cpu" size={12} />
                <select
                  value={model ?? ""}
                  disabled={disabled}
                  onChange={(e) => onModel(e.target.value)}
                >
                  {!model ? <option value="">默认模型</option> : null}
                  {models.map((m) => (
                    <option key={m.modelId} value={m.modelId}>
                      {m.name}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
          </div>
          <div className="composer-right">
            <span className="composer-hint">{value.length > 0 ? `${value.length} 字` : "/ 命令"}</span>
            {busy ? (
              <button className="btn stop-btn" onClick={onCancel} title="中止本回合">
                <Icon name="stop" size={13} />
                <span>停止</span>
              </button>
            ) : (
              <button className="btn send-btn" onClick={send} disabled={disabled || !value.trim()}>
                <Icon name="send" size={13} />
                <span>发送</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
