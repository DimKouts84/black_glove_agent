import { ReactNode } from 'react';

interface Props {
  title?: string;
  children: ReactNode;
  className?: string;
  fill?: boolean;
  actions?: ReactNode;
}

export function TerminalPanel({ title, children, className = '', fill = false, actions }: Props) {
  return (
    <div className={`neon-border rounded bg-panel/80 backdrop-blur ${fill ? 'flex flex-col h-full min-h-0' : ''} ${className}`}>
      {title && (
        <div className="border-b border-border px-4 py-2 text-xs text-primary flex items-center gap-2 shrink-0">
          <span className="text-glove">╭─</span>
          <span>{title}</span>
          <span className="ml-auto flex items-center gap-2">
            {actions}
            <span className="text-dim">● ● ●</span>
          </span>
        </div>
      )}
      <div className={fill ? 'p-4 flex flex-col flex-1 min-h-0' : 'p-4'}>{children}</div>
    </div>
  );
}
