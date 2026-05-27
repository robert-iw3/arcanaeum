'use client';

import type { CapturedRequest } from '@/lib/types';
import { statusColor } from '@/lib/api';

const METHOD_COLORS: Record<string, string> = {
  GET: 'var(--green)',
  POST: 'var(--accent)',
  PUT: 'var(--yellow)',
  PATCH: 'var(--yellow)',
  DELETE: 'var(--red)',
  OPTIONS: 'var(--muted)',
};

interface RequestListProps {
  requests: CapturedRequest[];
  selectedId: string | undefined;
  onSelect: (r: CapturedRequest | null) => void;
  onReplay: (r: CapturedRequest) => void;
}

export function RequestList({ requests, selectedId, onSelect, onReplay }: RequestListProps) {
  if (requests.length === 0) {
    return (
      <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--muted)' }}>
        No requests captured yet.
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          fontSize: 12,
          fontFamily: 'var(--mono)',
        }}
      >
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
            {['Time', 'Method', 'Path', 'Status', 'Duration', 'Size', ''].map((h) => (
              <th
                key={h}
                style={{
                  padding: '7px 12px',
                  textAlign: 'left',
                  fontWeight: 500,
                  fontSize: 11,
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  whiteSpace: 'nowrap',
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {requests.map((r) => {
            const isSelected = selectedId === r.id;
            const methodColor = METHOD_COLORS[r.method] ?? 'var(--text)';
            return (
              <tr
                key={r.id}
                onClick={() => onSelect(isSelected ? null : r)}
                style={{
                  borderBottom: '1px solid var(--border)',
                  cursor: 'pointer',
                  background: isSelected ? '#1a2535' : 'transparent',
                  transition: 'background 0.1s',
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) e.currentTarget.style.background = 'var(--surface2)';
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) e.currentTarget.style.background = 'transparent';
                }}
              >
                <td style={{ padding: '8px 12px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                  {new Date(r.captured_at).toLocaleTimeString()}
                </td>
                <td style={{ padding: '8px 12px', color: methodColor, fontWeight: 600 }}>
                  {r.method}
                </td>
                <td
                  style={{
                    padding: '8px 12px',
                    maxWidth: 300,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                  title={r.path}
                >
                  {r.path}
                </td>
                <td style={{ padding: '8px 12px', color: statusColor(r.status) }}>
                  {r.status || '—'}
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                  {r.duration_ms != null ? `${r.duration_ms}ms` : '—'}
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                  {r.response_bytes != null
                    ? r.response_bytes > 1024
                      ? `${(r.response_bytes / 1024).toFixed(1)}k`
                      : `${r.response_bytes}b`
                    : '—'}
                </td>
                <td style={{ padding: '8px 12px' }}>
                  <button
                    style={{ padding: '2px 7px', fontSize: 11 }}
                    onClick={(e) => {
                      e.stopPropagation();
                      onReplay(r);
                    }}
                    title="Replay this request"
                  >
                    ↺ Replay
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
