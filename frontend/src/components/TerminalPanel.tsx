import { ReactNode } from 'react';

interface Props {
  title?: string;
  children: ReactNode;
  className?: string;
}

export function TerminalPanel({ title, children, className = '' }: Props) {
  return (
    <div className={`neon-border rounded bg-panel/80 backdrop-blur ${className}`}>
      {title && (
        <div className="border-b border-border px-4 py-2 text-xs text-primary flex items-center gap-2">
          <span className="text-glove">╭─</span>
          <span>{title}</span>
          <span className="ml-auto text-dim">● ● ●</span>
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
