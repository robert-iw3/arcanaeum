'use client';

import { useState } from 'react';
import type { CapturedRequest } from '@/lib/types';
import { statusColor, prettyJson, copyToClipboard } from '@/lib/api';

const METHOD_COLORS: Record<string, string> = {
  GET: 'var(--green)',
  POST: 'var(--accent)',
  PUT: 'var(--yellow)',
  PATCH: 'var(--yellow)',
  DELETE: 'var(--red)',
};

// ── CodeBlock ──────────────────────────────────────────────────────────────────

interface CodeBlockProps {
  title: string;
  content: string | null | undefined;
  lang?: string;
}

function CodeBlock({ title, content, lang }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  if (!content) return null;
  const pretty = lang === 'json' ? (prettyJson(content) ?? content) : content;
  return (
    <div style={{ marginBottom: 16 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 6,
        }}
      >
        <span
          style={{
            fontSize: 11,
            color: 'var(--muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
          }}
        >
          {title}
        </span>
        <button
          style={{ padding: '2px 7px', fontSize: 10 }}
          onClick={() => {
            copyToClipboard(pretty);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre
        style={{
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          padding: '12px 14px',
          fontSize: 12,
          overflowX: 'auto',
          maxHeight: 300,
          overflowY: 'auto',
          color: 'var(--text)',
          lineHeight: 1.6,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
        }}
      >
        {pretty}
      </pre>
    </div>
  );
}

// ── RequestDetail ──────────────────────────────────────────────────────────────

interface RequestDetailProps {
  request: CapturedRequest;
  onClose: () => void;
  replayResult: boolean | null;
}

export function RequestDetail({ request, onClose, replayResult }: RequestDetailProps) {
  const req = request;
  const methodColor = METHOD_COLORS[req.method] ?? 'var(--text)';

  let reqHeaders: string | null = null;
  let reqBody: string | null = null;
  let resHeaders: string | null = null;
  let resBody: string | null = null;

  try {
    const rb = req.request_body ? JSON.parse(req.request_body) : null;
    if (rb && typeof rb === 'object' && 'headers' in rb) {
      reqHeaders = JSON.stringify(rb.headers, null, 2);
      reqBody = typeof rb.body === 'string' ? rb.body : JSON.stringify(rb.body, null, 2);
    } else {
      reqBody = req.request_body;
    }
  } catch { reqBody = req.request_body; }

  try {
    const rb = req.response_body ? JSON.parse(req.response_body) : null;
    if (rb && typeof rb === 'object' && 'headers' in rb) {
      resHeaders = JSON.stringify(rb.headers, null, 2);
      resBody = typeof rb.body === 'string' ? rb.body : JSON.stringify(rb.body, null, 2);
    } else {
      resBody = req.response_body;
    }
  } catch { resBody = req.response_body; }

  return (
    <div
      style={{
        padding: '16px 20px',
        borderTop: '1px solid var(--border)',
        background: 'var(--surface)',
        overflowY: 'auto',
        flex: 1,
      }}
    >
      {/* Title bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: methodColor }}>
          {req.method}
        </span>
        <span
          style={{
            fontFamily: 'var(--mono)',
            color: 'var(--text)',
            flex: 1,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {req.path}
        </span>
        <span style={{ fontFamily: 'var(--mono)', color: statusColor(req.status) }}>
          {req.status}
        </span>
        <span style={{ color: 'var(--muted)', fontSize: 12 }}>{req.duration_ms}ms</span>
        <button onClick={onClose} style={{ marginLeft: 4, padding: '2px 8px' }}>✕</button>
      </div>

      {/* Meta row */}
      <div
        style={{
          display: 'flex',
          gap: 20,
          marginBottom: 16,
          fontSize: 11,
          color: 'var(--muted)',
          fontFamily: 'var(--mono)',
          flexWrap: 'wrap',
        }}
      >
        <span>id: {req.id}</span>
        <span>captured: {new Date(req.captured_at).toLocaleString()}</span>
        <span>req: {req.request_bytes}b</span>
        <span>res: {req.response_bytes}b</span>
      </div>

      {/* Replay result banner */}
      {replayResult && (
        <div
          style={{
            marginBottom: 14,
            padding: '8px 12px',
            background: '#0d2a1a',
            border: '1px solid #1e5e30',
            borderRadius: 'var(--radius)',
            fontSize: 12,
            color: 'var(--green)',
            fontFamily: 'var(--mono)',
          }}
        >
          ↺ Replay queued — tunnel will forward this request again.
        </div>
      )}

      <CodeBlock title="Request Headers" content={reqHeaders} lang="json" />
      <CodeBlock title="Request Body" content={reqBody} lang="json" />
      <CodeBlock title="Response Headers" content={resHeaders} lang="json" />
      <CodeBlock title="Response Body" content={resBody} lang="json" />

      {!reqHeaders && !reqBody && !resHeaders && !resBody && (
        <div style={{ color: 'var(--muted)', fontSize: 12 }}>
          No body captured for this request.
        </div>
      )}
    </div>
  );
}
