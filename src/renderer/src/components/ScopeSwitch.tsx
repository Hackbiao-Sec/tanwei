import React from "react";

/**
 * 「本会话 / 总览」切换：本会话只认这个会话碰过的任务夹，总览才是全桌面。
 * 两个档位都点得开；本会话没任务夹时就展示空态，避免看起来像自动切到了全局。
 */
export function ScopeSwitch({
  tasks,
  scope,
  onScope,
  totalLabel,
  sessionLabel,
  total,
  scoped,
}: {
  tasks: string[];
  scope: "session" | "all";
  onScope: (scope: "session" | "all") => void;
  totalLabel?: string;
  sessionLabel?: string;
  total?: number;
  scoped?: number;
}) {
  const hasTasks = tasks.length > 0;
  return (
    <div className="scope-switch" title={hasTasks ? tasks.join("、") : "本会话还没落到任何任务夹"}>
      <div className="seg">
        <button className={`seg-btn ${scope === "session" ? "on" : ""}`} onClick={() => onScope("session")}>
          {sessionLabel ?? "本会话"}
          {scope === "session" && typeof scoped === "number" ? ` · ${scoped}` : ""}
        </button>
        <button className={`seg-btn ${scope === "all" ? "on" : ""}`} onClick={() => onScope("all")}>
          {totalLabel ?? "总览"}
          {scope === "all" && typeof total === "number" ? ` · ${total}` : ""}
        </button>
      </div>
      <span className="scope-tasks mono">{hasTasks ? tasks.join(" / ") : "本会话暂无任务夹"}</span>
    </div>
  );
}
