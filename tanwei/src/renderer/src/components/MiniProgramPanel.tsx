import React, { useCallback, useEffect, useMemo, useState } from "react";
import type { MiniDirHint, MobileHistoryRecord, MobilePentestMode, MobileTarget } from "@shared/types";
import { Icon } from "./Icons";
import { copyText } from "../lib/clipboard";
import { useSessionScope } from "../lib/sessionScope";
import {
  KIND_LABEL,
  MINI_MODE_HINT,
  MINI_MODE_LABEL,
  MobileBlockHead,
  MobileCopyRow,
  MobileScopeBar,
  MobileSection,
  MobileTabs,
  alreadyAnalyzed,
  errText,
  fmtSize,
  fmtWhen,
  isMiniKind,
  isNoiseEndpoint,
  matchRecord,
  shortPath,
  type MobileScope,
} from "./MobileShared";

type MiniTab = "overview" | "pages" | "endpoints" | "secrets" | "risk" | "artifacts";

/**
 * 小程序渗透：拆解记录落在主进程，按会话归属。
 * 「本会话」只看当前会话拆过的，「总览」看所有会话（含没归属的）。
 * 面板按小程序结构分页签：概览 / 页面路由 / 接口 / 密钥与配置 / 产物与说明。
 */
export function MiniProgramPanel({
  onAsk,
  onStage,
}: {
  onAsk: (prompt: string) => void;
  /** 把写好的渗透需求放进当前会话输入框，等用户自己点发送 */
  onStage: (prompt: string) => void;
}) {
  const scopeCtx = useSessionScope();
  const sessionId = scopeCtx.sessionId;

  const [scope, setScope] = useState<MobileScope>("session");
  const [query, setQuery] = useState("");
  const [itemQuery, setItemQuery] = useState("");
  const [tab, setTab] = useState<MiniTab>("overview");

  const [history, setHistory] = useState<MobileHistoryRecord[]>([]);
  const [histBusy, setHistBusy] = useState(false);
  const [activeId, setActiveId] = useState<string>();

  const [dir, setDir] = useState("");
  const [targets, setTargets] = useState<MobileTarget[]>([]);
  const [notes, setNotes] = useState<string[]>([]);
  const [scanned, setScanned] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [busyId, setBusyId] = useState<string>();
  const [mode, setMode] = useState<MobilePentestMode>("both");
  const [showNoise, setShowNoise] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [sending, setSending] = useState(false);
  const [deleteArm, setDeleteArm] = useState<string>();
  const [wxDirs, setWxDirs] = useState<MiniDirHint[]>([]);
  const [dirsOpen, setDirsOpen] = useState(false);

  const loadHistory = useCallback(async () => {
    setHistBusy(true);
    try {
      const list = await window.tanwei.mobileHistory();
      setHistory(list.filter((r) => isMiniKind(r.target.kind)));
    } catch (err) {
      setError(errText(err));
    } finally {
      setHistBusy(false);
    }
  }, []);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const loadWxDirs = useCallback(async () => {
    try {
      setWxDirs(await window.tanwei.wechatDirs());
    } catch {
      setWxDirs([]);
    }
  }, []);

  useEffect(() => {
    void loadWxDirs();
  }, [loadWxDirs]);

  const wxHit = wxDirs.filter((d) => d.exists && d.wxapkg > 0);
  const wxAny = wxDirs.filter((d) => d.exists);

  // 两档的集合都来自全量历史，搜索只影响行、不影响计数
  const scopeList = useMemo(
    () => history.filter((r) => (scope === "all" ? true : Boolean(sessionId) && r.sessionId === sessionId)),
    [history, scope, sessionId],
  );
  const mineCount = useMemo(
    () => (sessionId ? history.filter((r) => r.sessionId === sessionId).length : 0),
    [history, sessionId],
  );
  const visible = useMemo(() => scopeList.filter((r) => matchRecord(r, query)), [scopeList, query]);
  const active = useMemo(
    () => visible.find((r) => r.id === activeId) ?? visible[0],
    [visible, activeId],
  );

  const totals = useMemo(
    () => ({
      records: scopeList.length,
      pages: scopeList.reduce((n, a) => n + (a.mini?.pages.length ?? a.pages.length), 0),
      sub: scopeList.reduce((n, a) => n + (a.mini?.subPackages.length ?? 0), 0),
      endpoints: scopeList.reduce((n, a) => n + a.endpoints.length, 0),
      secrets: scopeList.reduce((n, a) => n + a.secrets.length, 0),
    }),
    [scopeList],
  );

  const runScan = useCallback(async (target: string) => {
    if (!target) return;
    setScanning(true);
    setError("");
    setNotice("");
    try {
      const res = await window.tanwei.mobileScan(target);
      const list = res.targets.filter((t) => isMiniKind(t.kind));
      setDir(res.dir);
      setTargets(list);
      setNotes(res.notes);
      setScanned(res.scanned);
      setNotice(
        list.length
          ? `扫了 ${res.scanned} 个文件，认出 ${list.length} 个小程序目标`
          : `扫了 ${res.scanned} 个文件，没认出小程序工程或 wxapkg`,
      );
    } catch (err) {
      setError(errText(err));
    } finally {
      setScanning(false);
    }
  }, []);

  const pickDir = useCallback(async () => {
    const picked = await window.tanwei.mobilePickDir();
    if (!picked) return;
    await runScan(picked);
  }, [runScan]);

  const analyze = useCallback(
    async (target: MobileTarget, silent = false) => {
      setBusyId(target.id);
      setError("");
      if (!silent) setNotice("");
      try {
        const res = await window.tanwei.mobileAnalyze({
          path: target.path,
          kind: target.kind,
          name: target.name,
          sessionId: sessionId || undefined,
        });
        await loadHistory();
        setActiveId(res.target.id);
        setTab("overview");
        setNotice(
          `${res.target.name} 拆完了：页面 ${res.mini?.pages.length ?? res.pages.length} 个，分包 ${
            res.mini?.subPackages.length ?? 0
          } 个，接口 ${res.endpoints.length} 条，密钥 ${res.secrets.length} 个`,
        );
      } catch (err) {
        setError(errText(err));
      } finally {
        setBusyId(undefined);
      }
    },
    [loadHistory, sessionId],
  );

  const importPackage = useCallback(async () => {
    const files = await window.tanwei.mobilePickApp();
    if (!files.length) return;
    setScanning(true);
    setError("");
    setNotice("");
    try {
      let miniCount = 0;
      let otherCount = 0;
      let last: string | undefined;
      for (const file of files) {
        const res = await window.tanwei.mobileAnalyze({ path: file, sessionId: sessionId || undefined });
        if (!isMiniKind(res.target.kind)) {
          otherCount += 1;
          continue;
        }
        miniCount += 1;
        last = res.target.id;
        setTargets((prev) => {
          const map = new Map(prev.map((t) => [t.id, t]));
          map.set(res.target.id, res.target);
          return Array.from(map.values());
        });
      }
      await loadHistory();
      if (last) setActiveId(last);
      setNotice(
        otherCount
          ? `导入 ${miniCount} 个小程序包；另外 ${otherCount} 个是 apk / ipa，去 APP 面板拆`
          : `导入 ${miniCount} 个小程序包并拆完`,
      );
    } catch (err) {
      setError(errText(err));
    } finally {
      setScanning(false);
    }
  }, [loadHistory, sessionId]);

  const claim = useCallback(async () => {
    if (!active || !sessionId) return;
    try {
      await window.tanwei.mobileHistoryClaim(active.id, sessionId);
      await loadHistory();
      setScope("session");
      setNotice(`已把 ${active.target.name} 归到本会话`);
    } catch (err) {
      setError(errText(err));
    }
  }, [active, loadHistory, sessionId]);

  const forget = useCallback(
    async (id: string) => {
      try {
        await window.tanwei.mobileHistoryForget(id);
        setDeleteArm(undefined);
        setActiveId(undefined);
        await loadHistory();
        setNotice("已删掉这条拆解记录（产物文件还在，可以按路径重拆）");
      } catch (err) {
        setError(errText(err));
      }
    },
    [loadHistory],
  );

  const handToEngine = useCallback(async () => {
    if (!active) return;
    setSending(true);
    setError("");
    try {
      const prompt = await window.tanwei.mobilePrompt({ analysis: { ...active, log: [] }, mode });
      onAsk(prompt);
      setNotice(`已按「${MINI_MODE_LABEL[mode]}」把 ${active.target.name} 交给引擎，新会话已开`);
    } catch (err) {
      setError(errText(err));
    } finally {
      setSending(false);
    }
  }, [active, mode, onAsk]);

  /** 同一份渗透需求写进当前会话输入框：用户自己看着改、自己点发送 */
  const stageToChat = useCallback(async () => {
    if (!active) return;
    setSending(true);
    setError("");
    try {
      const prompt = await window.tanwei.mobilePrompt({ analysis: { ...active, log: [] }, mode });
      onStage(prompt);
      setNotice("渗透需求已写进当前会话输入框，确认后点发送");
    } catch (err) {
      setError(errText(err));
    } finally {
      setSending(false);
    }
  }, [active, mode, onStage]);

  async function copyAll(text: string, tag: string) {
    await copyText(text);
    setNotice(`已复制${tag}（${text.split("\n").filter(Boolean).length} 条）`);
  }

  const pending = targets.filter((t) => !alreadyAnalyzed(t, history));
  const mini = active?.mini;
  const pageTotal = mini?.pages.length ?? active?.pages.length ?? 0;
  const subTotal = mini?.subPackages.length ?? 0;
  const stage = active ? (active.extracted ? 2 : 1) : 0;

  // 概览与安全基线共用的几个计数，避免每处各算一遍
  const debugResidue = mini?.debugResidue ?? [];
  const insecure = mini?.insecure ?? [];
  const missingPages = mini?.missingPages ?? [];
  const orphanPages = mini?.orphanPages ?? [];
  const heaviest = mini?.heaviest ?? [];
  const scopes = mini?.scopes ?? [];
  const sdks = mini?.sdks ?? [];
  const independentSubs = (mini?.subPackages ?? []).filter((s) => s.independent);
  const heaviestMax = heaviest.reduce((n, f) => Math.max(n, f.size), 0) || 1;
  const riskCount = debugResidue.length + insecure.length + missingPages.length + orphanPages.length;

  const endpointMatched = (active?.endpoints ?? []).filter((e) =>
    itemQuery.trim() ? e.toLowerCase().includes(itemQuery.trim().toLowerCase()) : true,
  );
  const noiseCount = endpointMatched.filter(isNoiseEndpoint).length;
  const endpointRows = showNoise ? endpointMatched : endpointMatched.filter((e) => !isNoiseEndpoint(e));
  const secretRows = (active?.secrets ?? []).filter((s) =>
    itemQuery.trim()
      ? `${s.kind} ${s.value} ${s.source}`.toLowerCase().includes(itemQuery.trim().toLowerCase())
      : true,
  );
  const pageRows = (mini?.pages.length ? mini.pages : (active?.pages ?? [])).filter((p) =>
    itemQuery.trim() ? p.toLowerCase().includes(itemQuery.trim().toLowerCase()) : true,
  );

  return (
    <div className="mob-page">
      <div className="mob-metrics">
        <div className="metric">
          <div className="metric-label">{scope === "session" ? "本会话记录" : "拆解记录"}</div>
          <div className="metric-value">{totals.records}</div>
          <div className="metric-foot">{scope === "session" ? "归属当前会话的小程序" : "所有会话加未归属"}</div>
        </div>
        <div className="metric">
          <div className="metric-label">页面</div>
          <div className="metric-value">{totals.pages}</div>
          <div className="metric-foot">含 {totals.sub} 个分包</div>
        </div>
        <div className="metric">
          <div className="metric-label">接口</div>
          <div className="metric-value">{totals.endpoints}</div>
          <div className="metric-foot">拿去未授权 / 换 id</div>
        </div>
        <div className="metric">
          <div className="metric-label">密钥</div>
          <div className="metric-value">{totals.secrets}</div>
          <div className="metric-foot">仍需认钥验证</div>
        </div>
      </div>

      <MobileScopeBar
        scope={scope}
        onScope={setScope}
        mine={mineCount}
        all={history.length}
        query={query}
        onQuery={setQuery}
        placeholder="搜小程序名 / 路径 / AppID / 接口 / 密钥，空格分词"
        busy={histBusy}
        onRefresh={() => void loadHistory()}
      >
        <button
          className="btn ghost sm"
          onClick={() => void window.tanwei.mobileOutRoot().then((p) => window.tanwei.openPath(p))}
          title="打开所有拆解产物所在目录"
        >
          <Icon name="external" size={11} />
          <span>产物目录</span>
        </button>
      </MobileScopeBar>

      <div className="mob-path-row">
        <input
          className="mob-path"
          value={dir}
          onChange={(e) => setDir(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void runScan(dir);
          }}
          placeholder="粘贴工程目录或 wxapkg 所在目录，回车就扫"
          spellCheck={false}
        />
        <button className="btn ghost sm" onClick={() => void runScan(dir)} disabled={!dir.trim() || scanning}>
          <Icon name="search" size={12} />
          <span>扫描</span>
        </button>
      </div>

      <div className="mob-toolbar">
        <button className="btn ghost sm" onClick={() => void pickDir()} disabled={scanning}>
          <Icon name="folder" size={12} />
          <span>{scanning ? "扫描中…" : "选小程序工程目录"}</span>
        </button>
        <button className="btn ghost sm" onClick={() => void importPackage()} disabled={scanning}>
          <Icon name="upload" size={12} />
          <span>导入 wxapkg</span>
        </button>
        <span className="mob-pill">
          {scope === "session" ? (sessionId ? "本会话" : "未选中会话") : "总览"}
        </span>
        <div className="mob-spacer" />
        {scanned ? <span className="mono subtle">扫了 {scanned} 个文件</span> : null}
      </div>

      {/* 微信不会把小程序放桌面，多数人找不到包在哪；这里直接给出真实目录并允许定位 */}
      <div className="mini-dirs">
        <div className="mini-dirs-head">
          <Icon name="folder" size={12} />
          <span className="mini-dirs-title">微信小程序存在哪</span>
          <span className="mini-dirs-sub">
            {wxHit.length
              ? `已在 ${wxHit.length} 个目录里找到 wxapkg 包`
              : wxAny.length
                ? "找到微信目录，但还没有 wxapkg 包：先用手机打开一次目标小程序"
                : "本机还没找到微信目录，或装在其它盘"}
          </span>
          <div className="mob-spacer" />
          <button className="btn ghost sm" onClick={() => void loadWxDirs()}>
            <Icon name="refresh" size={11} />
            <span>重新检测</span>
          </button>
          <button className="btn ghost sm" onClick={() => setDirsOpen((v) => !v)}>
            <Icon name="chevron" size={11} className={`mini-dirs-caret${dirsOpen ? " open" : ""}`} />
            <span>{dirsOpen ? "收起目录" : "看全部目录"}</span>
          </button>
        </div>

        <div className={`mini-dir-list${dirsOpen ? " open" : ""}`}>
          {(dirsOpen ? wxDirs : wxDirs.filter((d) => d.exists)).slice(0, dirsOpen ? 20 : 3).map((d) => (
            <div className={`mini-dir-row${d.exists ? "" : " miss"}`} key={d.path}>
              <div className="mini-dir-main">
                <span className="mini-dir-label">{d.label}</span>
                <span className="mini-dir-path mono" title={d.path}>
                  {d.path}
                </span>
              </div>
              <span className={`mini-dir-chip${d.wxapkg ? " hit" : ""}`}>
                {d.exists ? (d.wxapkg ? `wxapkg ${d.wxapkg}` : "无包") : "没有该目录"}
              </span>
              <button
                className="btn ghost sm"
                disabled={!d.exists}
                onClick={() => {
                  void window.tanwei.openPath(d.path);
                }}
                title="打开这个目录，从里面选小程序工程目录"
              >
                <Icon name="external" size={11} />
                <span>打开</span>
              </button>
              <button
                className="btn ghost sm"
                disabled={!d.exists}
                onClick={() => void runScan(d.path)}
                title="直接扫这个目录下的 wxapkg"
              >
                <Icon name="search" size={11} />
                <span>扫这里</span>
              </button>
              {d.note ? <div className="mini-dir-note">{d.note}</div> : null}
            </div>
          ))}
          {!wxDirs.length ? <div className="mini-dir-empty">检测中或本机没有微信客户端目录。</div> : null}
        </div>

        <div className="mini-dir-phone">
          <span className="mini-dir-label">手机上的位置</span>
          <span className="mono">/data/data/com.tencent.mm/MicroMsg/&lt;32位hash&gt;/appbrand/pkg/</span>
          <span className="mini-dir-note">
            真机取包需要 root，或用 frida 钩微信的包解密函数；没有 root 就装微信 PC 端打开一次目标小程序，包会落到上面某个目录。
          </span>
        </div>
      </div>

      {error ? <div className="module-error">{error}</div> : null}
      {notice ? <div className="mob-notice">{notice}</div> : null}

      <div className="mob-split">
        <div className="mob-list">
          <div className="mob-list-head">
            <Icon name="mini" size={12} />
            <span>{scope === "session" ? "本会话拆过的小程序" : "所有拆解记录"}</span>
            <span className="mono subtle">{visible.length}</span>
          </div>

          {visible.length ? (
            visible.map((r) => (
              <div
                key={r.id}
                className={`mob-row${active?.id === r.id ? " on" : ""}`}
                role="button"
                tabIndex={0}
                onClick={() => setActiveId(r.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setActiveId(r.id);
                  }
                }}
                title={r.target.path}
              >
                <span className={`mob-kind k-${r.target.kind}`}>{KIND_LABEL[r.target.kind]}</span>
                <span className="mob-row-main">
                  <span className="mob-row-name">{r.target.name}</span>
                  <span className="mob-row-path mono">{shortPath(r.target.path)}</span>
                  <span className="mob-row-meta">
                    接口 {r.endpoints.length} · 密钥 {r.secrets.length} · {fmtWhen(r.updatedAt)}
                    {r.sessionId ? "" : " · 未归属"}
                  </span>
                </span>
                {busyId === r.id ? <span className="mob-done warn">拆解中</span> : null}
              </div>
            ))
          ) : (
            <div className="module-empty">
              {scope === "session"
                ? sessionId
                  ? "当前会话还没拆过小程序。扫出目标后点「拆解」，记录会自动归到这个会话。"
                  : "现在没有选中的会话。上方选一个会话，或者切到「总览」看全部记录。"
                : query.trim()
                  ? "没有匹配的记录，换个关键词或清空搜索。"
                  : "还没拆过任何小程序：选工程目录，或导入解密后的 wxapkg。"}
            </div>
          )}

          {pending.length ? (
            <>
              <div className="mob-list-head">
                <Icon name="layers" size={12} />
                <span>待拆目标</span>
                <span className="mono subtle">{pending.length}</span>
              </div>
              {pending.map((t) => (
                <div key={t.id} className="mob-row" title={t.path}>
                  <span className={`mob-kind k-${t.kind}`}>{KIND_LABEL[t.kind]}</span>
                  <span className="mob-row-main">
                    <span className="mob-row-name">{t.name}</span>
                    <span className="mob-row-path mono">{shortPath(t.path)}</span>
                  </span>
                  <button className="btn ghost sm" onClick={() => void analyze(t)} disabled={busyId === t.id}>
                    {busyId === t.id ? "拆解中…" : "拆解"}
                  </button>
                </div>
              ))}
            </>
          ) : null}

          {notes.length ? (
            <div className="mob-notes">
              {notes.map((n, i) => (
                <div className="mob-note" key={`${i}-${n}`}>
                  {n}
                </div>
              ))}
            </div>
          ) : null}
        </div>

        <div className="mob-detail">
          {active ? (
            <>
              <div className="mob-detail-head">
                <div className="mob-detail-title">
                  <Icon name="mini" size={13} />
                  <span>{active.target.name}</span>
                  <span className={`mob-kind k-${active.target.kind}`}>{KIND_LABEL[active.target.kind]}</span>
                  {mini?.appId ?? active.appId ? (
                    <span className="chip chip-ghost mono">{mini?.appId ?? active.appId}</span>
                  ) : null}
                  {active.sessionId ? null : <span className="mob-pill warn">未归属</span>}
                </div>
                <div className="mob-detail-ops">
                  <button className="btn ghost sm" onClick={() => void window.tanwei.openPath(active.briefPath)}>
                    <Icon name="file" size={12} />
                    <span>简报</span>
                  </button>
                  <button className="btn ghost sm" onClick={() => void window.tanwei.openPath(active.outDir)}>
                    <Icon name="folder" size={12} />
                    <span>产物</span>
                  </button>
                  <button
                    className="btn ghost sm"
                    onClick={() => void analyze(active.target)}
                    disabled={busyId === active.id}
                  >
                    <Icon name="refresh" size={12} />
                    <span>{busyId === active.id ? "重拆中…" : "重拆"}</span>
                  </button>
                  {sessionId && active.sessionId !== sessionId ? (
                    <button className="btn ghost sm" onClick={() => void claim()} title="把这条记录归到当前会话">
                      <Icon name="check" size={12} />
                      <span>归本会话</span>
                    </button>
                  ) : null}
                  <button
                    className={`btn ghost sm${deleteArm === active.id ? " danger" : ""}`}
                    onClick={() => (deleteArm === active.id ? void forget(active.id) : setDeleteArm(active.id))}
                    title="只删历史记录，产物文件保留"
                  >
                    <Icon name="close" size={12} />
                    <span>{deleteArm === active.id ? "确认删除" : "删除记录"}</span>
                  </button>
                </div>
              </div>

              <MobileTabs<MiniTab>
                value={tab}
                onChange={(next) => {
                  setTab(next);
                  setItemQuery("");
                }}
                tabs={[
                  { id: "overview", label: "概览" },
                  { id: "pages", label: "页面路由", count: pageTotal },
                  { id: "endpoints", label: "接口", count: active.endpoints.length },
                  { id: "secrets", label: "密钥与配置", count: active.secrets.length },
                  { id: "risk", label: "安全基线", count: riskCount },
                  { id: "artifacts", label: "产物与说明", count: active.notes.length },
                ]}
              />

              {tab === "overview" ? (
                <>
                  <div className="mini-brief">
                    <div className="mini-brief-item">
                      <span className="mini-brief-label">来源类型</span>
                      <span className="mini-brief-value">
                        {mini?.source === "wechat"
                          ? "微信原生小程序"
                          : mini?.source === "uniapp"
                            ? "uni-app 工程"
                            : KIND_LABEL[active.target.kind]}
                      </span>
                    </div>
                    <div className="mini-brief-item">
                      <span className="mini-brief-label">AppID</span>
                      <span className="mini-brief-value">{mini?.appId ?? active.appId ?? "未读到"}</span>
                    </div>
                    <div className="mini-brief-item">
                      <span className="mini-brief-label">页面 / 分包</span>
                      <span className="mini-brief-value">
                        {pageTotal} / {subTotal}
                        {independentSubs.length ? ` · 独立 ${independentSubs.length}` : ""}
                      </span>
                    </div>
                    <div className="mini-brief-item">
                      <span className="mini-brief-label">包体积</span>
                      <span className="mini-brief-value">
                        {mini?.packageSize ? fmtSize(mini.packageSize) : "未读到"}
                        {heaviest.length ? ` · 最重 ${shortPath(heaviest[0].path)}` : ""}
                      </span>
                    </div>
                    <div className={`mini-brief-item${mini?.cloudDev ? " warn" : ""}`}>
                      <span className="mini-brief-label">云开发</span>
                      <span className={`mini-brief-value${mini?.cloudDev ? " warn" : ""}`}>
                        {mini?.cloudDev ? `在用 · ${mini.cloudEnv.length} 个环境` : "未使用"}
                      </span>
                    </div>
                    <div className={`mini-brief-item${mini?.upload ? " warn" : ""}`}>
                      <span className="mini-brief-label">上传 / 组件</span>
                      <span className={`mini-brief-value${mini?.upload ? " warn" : ""}`}>
                        {mini?.upload ? "有上传接口" : "无上传"}
                        {mini?.plugins.length ? ` · 插件 ${mini.plugins.length}` : ""}
                      </span>
                    </div>
                    <div className="mini-brief-item">
                      <span className="mini-brief-label">运行时 / SDK</span>
                      <span className="mini-brief-value">{sdks.length ? sdks.join(" · ") : "未认出"}</span>
                    </div>
                    <div className={`mini-brief-item${riskCount ? " warn" : ""}`}>
                      <span className="mini-brief-label">安全基线</span>
                      <span className={`mini-brief-value${riskCount ? " warn" : ""}`}>
                        {riskCount
                          ? `调试残留 ${debugResidue.length} · 明文/内网 ${insecure.length} · 缺文件页 ${missingPages.length} · 孤儿页 ${orphanPages.length}`
                          : "没读出基线问题"}
                      </span>
                    </div>
                    <div className="mini-brief-item">
                      <span className="mini-brief-label">文件 / 源码</span>
                      <span className="mini-brief-value">
                        {active.files} · {active.extracted ? "已解出源码" : "仅结构"}
                      </span>
                    </div>
                  </div>

                  <div className="mini-steps">
                    <span className="mini-step on">工程 / wxapkg</span>
                    <span className="mini-step-arrow">→</span>
                    <span className={`mini-step${stage >= 1 ? " on" : ""}`}>解包读结构</span>
                    <span className="mini-step-arrow">→</span>
                    <span className={`mini-step${stage >= 2 ? " on" : ""}`}>路由 / 接口 / 密钥</span>
                    <span className="mini-step-arrow">→</span>
                    <span className="mini-step">真机核对 · 打接口</span>
                  </div>

                  {heaviest.length ? (
                    <div className="mini-weight">
                      <div className="mini-weight-head">
                        <Icon name="layers" size={11} />
                        <span>体积 Top 源码</span>
                        <span className="mono subtle">{heaviest.length}</span>
                      </div>
                      {heaviest.map((f) => (
                        <div className="mini-weight-row" key={f.path}>
                          <span className="mini-weight-path mono">{shortPath(f.path)}</span>
                          <span className="mini-weight-bar">
                            <span style={{ width: `${Math.max(4, Math.round((f.size / heaviestMax) * 100))}%` }} />
                          </span>
                          <span className="mini-weight-size mono">{fmtSize(f.size)}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {riskCount ? (
                    <div className="mini-flags">
                      {debugResidue.length ? (
                        <span className="mini-flag warn">
                          <Icon name="shield" size={10} />
                          调试残留 {debugResidue.length}
                        </span>
                      ) : null}
                      {insecure.length ? (
                        <span className="mini-flag warn">
                          <Icon name="globe" size={10} />
                          明文/内网 {insecure.length}
                        </span>
                      ) : null}
                      {missingPages.length ? (
                        <span className="mini-flag">
                          <Icon name="file" size={10} />
                          缺文件页 {missingPages.length}
                        </span>
                      ) : null}
                      {orphanPages.length ? (
                        <span className="mini-flag">
                          <Icon name="layers" size={10} />
                          孤儿页 {orphanPages.length}
                        </span>
                      ) : null}
                    </div>
                  ) : null}

                  <div className="mob-callout">
                    <span className="mob-callout-title">这摊怎么打</span>
                    <span>
                      {mini?.cloudDev
                        ? `在用云开发（${mini.cloudEnv.join(" / ") || "未读到环境名"}）：先试环境 ID 泄漏、openid 越权与云函数未鉴权；`
                        : "没用云开发，攻击面全在自建接口；"}
                      {active.endpoints.length
                        ? `接口 ${active.endpoints.length} 条，拿去逐条打未授权、换 id 与注入；`
                        : "没抽到接口，走真机抓包；"}
                      {active.secrets.length ? `密钥 ${active.secrets.length} 个，先过认钥闸再写报告；` : ""}
                      {mini?.upload ? "有上传接口，跟到能不能落地执行。" : ""}
                      {debugResidue.length ? `有 ${debugResidue.length} 处调试残留，sourcemap 能还原可读源码；` : ""}
                      {insecure.length ? `${insecure.length} 条明文或内网地址，先试能不能直接出内容；` : ""}
                      {orphanPages.length ? `${orphanPages.length} 个页面没入口，可以按 path 直接打。` : ""}
                    </span>
                  </div>

                  <div className="mob-mode">
                    <div className="seg">
                      {(["static", "dynamic", "both"] as MobilePentestMode[]).map((m) => (
                        <button
                          key={m}
                          className={`seg-btn ${mode === m ? "on" : ""}`}
                          onClick={() => setMode(m)}
                          title={MINI_MODE_HINT[m]}
                        >
                          {MINI_MODE_LABEL[m]}
                        </button>
                      ))}
                    </div>
                    <span className="mob-mode-hint">{MINI_MODE_HINT[mode]}</span>
                    <div className="mob-spacer" />
                    <button
                      className="btn ghost sm"
                      onClick={() => void stageToChat()}
                      disabled={sending}
                      title="把这次拆解结果写成渗透需求，放进当前会话输入框，自己改完再发"
                    >
                      <Icon name="chat" size={12} />
                      <span>发到对话框</span>
                    </button>
                    <button className="btn sm" onClick={() => void handToEngine()} disabled={sending}>
                      <Icon name="send" size={12} />
                      <span>{sending ? "交给引擎…" : "交给引擎开打"}</span>
                    </button>
                  </div>
                </>
              ) : null}

              {tab === "pages" ? (
                <>
                  <MobileBlockHead title="主包页面" count={pageTotal}>
                    <input
                      className="mob-filter"
                      value={itemQuery}
                      onChange={(e) => setItemQuery(e.target.value)}
                      placeholder="筛页面路径"
                      spellCheck={false}
                    />
                    <button
                      className="chip chip-ghost"
                      onClick={() => void copyAll(pageRows.join("\n"), "页面路径")}
                      disabled={!pageRows.length}
                    >
                      <Icon name="copy" size={10} />
                      <span>复制全部</span>
                    </button>
                  </MobileBlockHead>
                  <div className="mob-cards">
                    <MobileSection
                      title="主包页面"
                      count={pageRows.length}
                      empty="没读到 pages：工程可能被压缩或加密，走真机抓包更靠谱。"
                    >
                      {pageRows.map((p) => (
                        <MobileCopyRow key={p} text={p} />
                      ))}
                    </MobileSection>

                    <MobileSection title="分包" count={subTotal} empty="没有分包（单包小程序）。">
                      {(mini?.subPackages ?? []).map((s) => (
                        <div className="mini-subpkg" key={s.root}>
                          <span className="mini-subpkg-root">{s.root}</span>
                          {s.independent ? <span className="mini-chip cloud">独立分包</span> : null}
                          <span className="mini-subpkg-count">
                            {s.count} 页{s.size ? ` · ${fmtSize(s.size)}` : ""}
                          </span>
                        </div>
                      ))}
                    </MobileSection>

                    <MobileSection
                      title="缺文件的页面"
                      count={missingPages.length}
                      empty="页面结构齐全。"
                      hint="app.json 声明了但包里没有 js/wxml，通常是被裁掉或按需下发，真机上要单独抓。"
                    >
                      {missingPages.map((m) => (
                        <div className="mob-line" key={m.page}>
                          <span className="mono">{m.page}</span>
                          <span className="mob-tag warn">{m.missing.join(" / ")}</span>
                        </div>
                      ))}
                    </MobileSection>

                    <MobileSection
                      title="没被引用的页面"
                      count={orphanPages.length}
                      empty="页面都有入口引用。"
                      hint="没进 tabBar 也没被跳转引用：可能是历史页、内部测试页，或靠扫码 / 分享直达的页。"
                    >
                      <div className="mini-chips">
                        {orphanPages.map((p) => (
                          <span className="mini-chip" key={p}>
                            {p}
                          </span>
                        ))}
                      </div>
                    </MobileSection>

                    <MobileSection
                      title="tabBar"
                      count={mini?.tabBar.length ?? 0}
                      empty="没有 tabBar（单页或纯跳转型小程序）。"
                      hint="tabBar 的页面通常是核心业务，先从这几页的接口打起。"
                    >
                      <div className="mini-chips">
                        {(mini?.tabBar ?? []).map((t) => (
                          <span className="mini-chip" key={t}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </MobileSection>
                  </div>
                </>
              ) : null}

              {tab === "endpoints" ? (
                <>
                  <MobileBlockHead title="接口候选" count={endpointRows.length}>
                    <input
                      className="mob-filter"
                      value={itemQuery}
                      onChange={(e) => setItemQuery(e.target.value)}
                      placeholder="筛域名 / 路径"
                      spellCheck={false}
                    />
                    <button
                      className="chip chip-ghost"
                      onClick={() => void copyAll(endpointRows.join("\n"), "接口")}
                      disabled={!endpointRows.length}
                    >
                      <Icon name="copy" size={10} />
                      <span>复制全部</span>
                    </button>
                    {noiseCount ? (
                      <button
                        className={`chip chip-ghost${showNoise ? " on" : ""}`}
                        onClick={() => setShowNoise((v) => !v)}
                        title="库 / 框架的文档与命名空间地址默认收起"
                      >
                        <Icon name="layers" size={10} />
                        <span>{showNoise ? "收起框架地址" : `含框架地址 ${noiseCount}`}</span>
                      </button>
                    ) : null}
                  </MobileBlockHead>
                  <div className="mob-cards">
                    <MobileSection
                      title="接口候选"
                      count={endpointRows.length}
                      empty="没抽到接口：走真机抓包，或确认 wxapkg 是否已解密。"
                      hint="抽出来的只是入口，逐条打未授权、换 id、注入，才算打过。"
                    >
                      {endpointRows.map((e) => (
                        <MobileCopyRow key={e} text={e} />
                      ))}
                    </MobileSection>
                  </div>
                </>
              ) : null}

              {tab === "secrets" ? (
                <>
                  <MobileBlockHead title="密钥 / 凭据" count={secretRows.length}>
                    <input
                      className="mob-filter"
                      value={itemQuery}
                      onChange={(e) => setItemQuery(e.target.value)}
                      placeholder="筛类型 / 值 / 出处"
                      spellCheck={false}
                    />
                    <button
                      className="chip chip-ghost"
                      onClick={() =>
                        void copyAll(secretRows.map((s) => `${s.kind}\t${s.value}\t${s.source}`).join("\n"), "密钥")
                      }
                      disabled={!secretRows.length}
                    >
                      <Icon name="copy" size={10} />
                      <span>复制全部</span>
                    </button>
                  </MobileBlockHead>
                  <div className="mob-cards">
                    <MobileSection
                      title="密钥 / 凭据"
                      count={secretRows.length}
                      empty="没抽到明文密钥。"
                      hint="抄到不算洞：先拿假值对照证明生产认它，再用它拉一次身份或列表。"
                    >
                      {secretRows.map((s) => (
                        <MobileCopyRow key={`${s.kind}-${s.value}`} tag={s.kind} text={s.value} note={s.source} />
                      ))}
                    </MobileSection>

                    <MobileSection
                      title="云开发环境"
                      count={mini?.cloudEnv.length ?? 0}
                      empty="没用云开发。"
                    >
                      <div className="mini-chips">
                        {(mini?.cloudEnv ?? []).map((t) => (
                          <span className="mini-chip cloud" key={t}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </MobileSection>

                    <MobileSection
                      title="隐私接口"
                      count={mini?.privateInfos.length ?? 0}
                      empty="没声明隐私接口。"
                      hint="声明了哪些隐私能力，就说明业务真的在取哪些数据。"
                    >
                      <div className="mini-chips">
                        {(mini?.privateInfos ?? []).map((t) => (
                          <span className="mini-chip private" key={t}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </MobileSection>

                    <MobileSection title="引用插件" count={mini?.plugins.length ?? 0} empty="没引用插件。">
                      <div className="mini-chips">
                        {(mini?.plugins ?? []).map((t) => (
                          <span className="mini-chip" key={t}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </MobileSection>

                    <MobileSection
                      title="授权 scope"
                      count={scopes.length}
                      empty="app.json 没声明 permission.scope。"
                      hint="声明了哪些授权，就说明业务在取哪些身份数据；按 scope 反推接口要哪些参数。"
                    >
                      {scopes.map((s) => (
                        <div className="mob-line" key={s.scope}>
                          <span className="mono">{s.scope}</span>
                          <span className="subtle">{s.desc}</span>
                        </div>
                      ))}
                    </MobileSection>
                  </div>
                </>
              ) : null}

              {tab === "risk" ? (
                <div className="mob-cards">
                  <div className="mob-callout">
                    <span className="mob-callout-title">基线怎么用</span>
                    <span>
                      这些是拆包时读出来的配置问题，本身只是线索：调试残留说明还有没删的 sourcemap 与私有配置，
                      明文与内网地址能直接接成 SSRF / 内网探测，孤儿页往往是没走入口的测试页。
                      要按洞交，得先把它们接到具体接口上。
                    </span>
                  </div>

                  <MobileSection
                    title="调试残留"
                    count={debugResidue.length}
                    empty="没发现 sourcemap 或私有配置残留。"
                    hint="有 .map 就能还原可读源码；project.private.config.json 常带真 appid 与本地调试开关。"
                  >
                    {debugResidue.map((d) => (
                      <div className="mob-line" key={d}>
                        <span className="mob-tag warn">残留</span>
                        <span className="mono">{d}</span>
                      </div>
                    ))}
                  </MobileSection>

                  <MobileSection
                    title="明文 / 内网地址"
                    count={insecure.length}
                    empty="没读到 http 明文或内网地址。"
                    hint="逐条试能不能出内容：内网地址出响应就是 SSRF 面，明文的鉴权包可被直接抓改。"
                  >
                    <div className="mob-line">
                      <button className="chip chip-ghost" onClick={() => void copyAll(insecure.join("\n"), "地址")}>
                        <Icon name="copy" size={10} />
                        <span>复制全部 {insecure.length} 条</span>
                      </button>
                    </div>
                    {insecure.map((u) => (
                      <MobileCopyRow key={u} text={u} />
                    ))}
                  </MobileSection>

                  <MobileSection
                    title="运行时 / SDK"
                    count={sdks.length}
                    empty="没认出框架或 SDK。"
                    hint="认到运行时决定下面怎么抽代码：云开发走环境与云函数，uni-app 走编译产物，地图 / 登录 SDK 各有固定接口。"
                  >
                    <div className="mini-chips">
                      {sdks.map((s) => (
                        <span className="mini-chip cloud" key={s}>
                          {s}
                        </span>
                      ))}
                    </div>
                  </MobileSection>
                </div>
              ) : null}

              {tab === "artifacts" ? (
                <div className="mob-cards">
                  <MobileSection title="产物位置" count={2} empty="">
                    <MobileCopyRow tag="产物" text={active.outDir} />
                    <MobileCopyRow tag="简报" text={active.briefPath} />
                    <div className="mob-item">
                      <span className="mob-item-text">打开简报 · 打开产物目录</span>
                      <div className="mob-spacer" />
                      <button className="chip chip-ghost" onClick={() => void window.tanwei.openPath(active.briefPath)}>
                        <Icon name="file" size={10} />
                        <span>简报</span>
                      </button>
                      <button className="chip chip-ghost" onClick={() => void window.tanwei.openPath(active.outDir)}>
                        <Icon name="folder" size={10} />
                        <span>目录</span>
                      </button>
                    </div>
                  </MobileSection>

                  <MobileSection
                    title="拆解备注"
                    count={active.notes.length}
                    empty="没有备注。"
                    hint="这里记的是拆解过程中认到的结构与坑，不是漏洞结论。"
                  >
                    {active.notes.map((n) => (
                      <div className="mob-line" key={n}>
                        {n}
                      </div>
                    ))}
                  </MobileSection>

                  <MobileSection
                    title="交付说明"
                    count={3}
                    empty=""
                  >
                    <div className="mob-line">
                      1、接口与密钥只算线索：接口逐条打未授权 / 换 id / 注入，密钥先过认钥闸。
                    </div>
                    <div className="mob-line">
                      2、拆解记录归本会话，报告落任务夹；两边不互相替代。
                    </div>
                    <div className="mob-line">
                      3、「交给引擎开打」会带着这摊的接口、密钥、路由开会话，接着由引擎落报告。
                    </div>
                  </MobileSection>
                </div>
              ) : null}
            </>
          ) : (
            <div className="module-empty">
              左边挑一条拆过的记录看结果；没记录就先扫目录或导入 wxapkg。
              会读 app.json 的 pages / subPackages / tabBar / plugins / 隐私接口，解 wxapkg 取业务代码，再抽接口、密钥与云开发环境。
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
