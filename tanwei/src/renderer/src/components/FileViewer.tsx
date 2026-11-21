import React, { useEffect, useState } from "react";
import { Icon } from "./Icons";
import { Markdown } from "./Markdown";
import { copyText } from "../lib/clipboard";

function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export interface PreviewTarget {
  path: string;
  name?: string;
  size?: number;
}

/** 任务目录内的任意文件在线预览：.md 渲染，其余按原文等宽显示 */
export function FileViewer({ file, onClose }: { file: PreviewTarget | null; onClose: () => void }) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!file) return;
    let cancelled = false;
    setLoading(true);
    setError(undefined);
    setText("");
    void window.tanwei
      .readTaskFile(file.path)
      .then((content) => {
        if (!cancelled) setText(content);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [file]);

  useEffect(() => {
    if (!file) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [file, onClose]);

  if (!file) return null;

  const name = file.name ?? file.path.split(/[\\/]/).pop() ?? file.path;
  const isMarkdown = /\.md$/i.test(name);

  return (
    <div className="viewer-mask" onClick={onClose}>
      <div className="viewer" onClick={(e) => e.stopPropagation()}>
        <div className="viewer-head">
          <div className="viewer-title">
            <Icon name="file" size={13} />
            <span className="mono">{name}</span>
            {file.size ? <span className="viewer-size">{fmtSize(file.size)}</span> : null}
          </div>
          <div className="viewer-ops">
            <button
              className="btn ghost sm"
              onClick={() => {
                void copyText(file.path);
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1600);
              }}
            >
              <Icon name="check" size={12} />
              <span>{copied ? "已复制" : "复制路径"}</span>
            </button>
            <button className="btn ghost sm" onClick={() => void window.tanwei.reveal(file.path)}>
              <Icon name="folder" size={12} />
              <span>定位</span>
            </button>
            <button className="btn ghost sm" onClick={() => void window.tanwei.openPath(file.path)}>
              <Icon name="send" size={12} />
              <span>外部打开</span>
            </button>
            <button className="btn ghost sm" onClick={onClose}>
              <Icon name="close" size={12} />
              <span>关闭</span>
            </button>
          </div>
        </div>
        <div className="viewer-path mono">{file.path}</div>
        <div className="viewer-body">
          {loading ? <div className="panel-empty">读取中…</div> : null}
          {error ? <div className="module-error">{error}</div> : null}
          {!loading && !error ? (
            isMarkdown ? (
              <Markdown text={text} />
            ) : (
              <pre className="viewer-pre">{text || "（空文件）"}</pre>
            )
          ) : null}
        </div>
      </div>
    </div>
  );
}
