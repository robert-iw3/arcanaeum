'use client';

interface BadgeProps {
  label: string;
  color?: string;
}

export function Badge({ label, color = 'var(--muted)' }: BadgeProps) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '1px 7px',
        borderRadius: 99,
        fontSize: 11,
        fontFamily: 'var(--mono)',
        background: color + '22',
        color,
        border: `1px solid ${color}44`,
      }}
    >
      {label}
    </span>
  );
}
