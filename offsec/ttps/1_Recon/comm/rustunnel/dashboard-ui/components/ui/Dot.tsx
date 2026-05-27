'use client';

interface DotProps {
  color: string;
  size?: number;
  pulse?: boolean;
}

export function Dot({ color, size = 8, pulse }: DotProps) {
  return (
    <span
      style={{
        display: 'inline-block',
        width: size,
        height: size,
        borderRadius: '50%',
        background: color,
        flexShrink: 0,
        boxShadow: pulse ? `0 0 6px ${color}` : 'none',
        animation: pulse ? 'pulse 2s infinite' : 'none',
      }}
    />
  );
}
