import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { SessionScopeSnapshot } from "@shared/types";

/**
 * 会话级产物归属：一个会话只认自己碰过的任务夹，界面里所有「本会话」档位都吃这一份数据。
 * 归属由主进程维护（事件文本 + 会话落盘记录 + 桌面新夹监听 + 手动绑定），渲染层只读不猜。
 */
const EMPTY: SessionScopeSnapshot = {
  tasks: [],
  findings: [],
  assets: [],
  files: [],
  reports: [],
  available: [],
  owners: {},
  orphans: [],
};

export interface SessionScopeValue extends SessionScopeSnapshot {
  sessionId?: string;
  loading: boolean;
  error?: string;
  /** 每成功重拉一次就 +1，给面板当「总览也该刷新了」的触发信号 */
  version: number;
  refresh: () => void;
  bind: (task: string) => Promise<void>;
  unbind: (task: string) => Promise<void>;
}

const FALLBACK: SessionScopeValue = {
  ...EMPTY,
  loading: false,
  version: 0,
  refresh: () => undefined,
  bind: async () => undefined,
  unbind: async () => undefined,
};

const SessionScopeContext = createContext<SessionScopeValue>(FALLBACK);

export function useSessionScope(): SessionScopeValue {
  return useContext(SessionScopeContext);
}

export function SessionScopeProvider({
  sessionId,
  revision,
  busy,
  children,
}: {
  sessionId?: string;
  /** 会话状态版本号（updatedAt）：回合推进时触发重拉 */
  revision?: number;
  /** 当前会话是否正在跑回合；跑着的时候轮询勤一点，文件是边跑边落的 */
  busy?: boolean;
  children: React.ReactNode;
}) {
  const [snap, setSnap] = useState<SessionScopeSnapshot>(EMPTY);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [version, setVersion] = useState(0);
  const seq = useRef(0);

  const load = useCallback(async () => {
    const mine = ++seq.current;
    setLoading(true);
    try {
      const next = await window.tanwei.sessionScope(sessionId);
      if (mine !== seq.current) return;
      setSnap(next);
      setError(undefined);
      setVersion((v) => v + 1);
    } catch (err) {
      if (mine !== seq.current) return;
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (mine === seq.current) setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void load();
  }, [load, revision]);

  // 归属一变（绑定 / 解绑 / 桌面新建任务夹）主进程就广播，界面立刻重拉
  useEffect(() => window.tanwei.onScopeChanged(() => void load()), [load]);

  // 跑回合时产物随时落盘，4 秒一次足够；空闲时只靠事件和手动刷新，别空扫桌面
  useEffect(() => {
    if (!busy) return;
    const timer = window.setInterval(() => void load(), 4000);
    return () => window.clearInterval(timer);
  }, [busy, load]);

  const bind = useCallback(
    async (task: string) => {
      if (!sessionId || !task) return;
      await window.tanwei.sessionBind(sessionId, task);
      await load();
    },
    [sessionId, load],
  );

  const unbind = useCallback(
    async (task: string) => {
      if (!sessionId || !task) return;
      await window.tanwei.sessionUnbind(sessionId, task);
      await load();
    },
    [sessionId, load],
  );

  const value = useMemo<SessionScopeValue>(
    () => ({ ...snap, sessionId, loading, error, version, refresh: () => void load(), bind, unbind }),
    [snap, sessionId, loading, error, version, load, bind, unbind],
  );

  return <SessionScopeContext.Provider value={value}>{children}</SessionScopeContext.Provider>;
}
