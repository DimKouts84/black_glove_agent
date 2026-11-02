import { useState } from 'react';
import { ActivityEvent } from '../hooks/useChatSocket';
import {
  SpecialistCard,
  TraceRow,
  cardSummaryLine,
  groupRun,
  specialistLabel,
} from '../chat/groupRun';

const AGENT_COLORS: Record<string, string> = {
  recon_agent: 'text-accent',
  network_agent: 'text-secondary',
  web_agent: 'text-green-400',
  assessment_agent: 'text-accent',
};

interface Props {
  events: ActivityEvent[];
  acting?: boolean;
}

export function TurnTrace({ events, acting = false }: Props) {
  const grouped = groupRun(events);
  const [overrides, setOverrides] = useState<Record<string, boolean>>({});

  if (grouped.cards.length === 0) {
    if (!acting) return null;
    return (
      <p className="text-primary text-sm animate-pulse">Black Glove is working…</p>
    );
  }

  return (
    <div className="space-y-2 my-2">
      {grouped.cards.map((card) => {
        const open = overrides[card.id] ?? card.status === 'running';
        return (
          <SpecialistCardView
            key={card.id}
            card={card}
            open={open}
            onToggle={() => setOverrides((prev) => ({ ...prev, [card.id]: !open }))}
          />
        );
      })}
    </div>
  );
}

function oneLine(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > 140 ? `${flat.slice(0, 140)}…` : flat;
}

function SpecialistCardView({
  card,
  open,
  onToggle,
}: {
  card: SpecialistCard;
  open: boolean;
  onToggle: () => void;
}) {
  const color = AGENT_COLORS[card.agent] || 'text-primary';
  const counts = cardSummaryLine(card).split(' · ').slice(1).join(' · ');
  return (
    <div className="border border-border rounded bg-black/30">
      <button
        type="button"
        className="w-full text-left px-3 py-2 text-xs flex items-center gap-2 min-w-0"
        aria-expanded={open}
        onClick={onToggle}
      >
        <span className={`font-bold shrink-0 ${color}`}>{specialistLabel(card.agent)}</span>
        <span className="text-dim shrink-0">{counts}</span>
        {card.status === 'running' && (
          <span className="text-primary animate-pulse shrink-0">working</span>
        )}
        {!open && card.summary && (
          <span className="text-dim truncate min-w-0">{oneLine(card.summary)}</span>
        )}
      </button>
      {open && (
        <div className="px-3 pb-2 space-y-1">
          {card.rows.map((row) => (
            <TraceRowView key={row.id} row={row} />
          ))}
          {card.summary && (
            <p className="text-xs text-dim pt-1">{card.summary}</p>
          )}
        </div>
      )}
    </div>
  );
}

function TraceRowView({ row }: { row: TraceRow }) {
  if (row.kind === 'thinking') {
    return <p className="text-[11px] text-dim">{row.content}</p>;
  }
  if (row.kind === 'warning') {
    return <p className="text-[11px] text-yellow-400">Warning: {row.content}</p>;
  }
  if (row.kind === 'notice') {
    return <p className="text-[11px] text-secondary">{row.content}</p>;
  }
  if (row.kind === 'tool' && row.tool) {
    return <ToolRowView row={row} />;
  }
  return null;
}

function ToolRowView({ row }: { row: TraceRow }) {
  const [open, setOpen] = useState(false);
  const tool = row.tool;
  if (!tool) return null;
  const failed = tool.status === 'error' || (tool.result || '').startsWith('Error');
  return (
    <div className="border-l border-primary/30 pl-2">
      <button
        type="button"
        className="w-full text-left text-xs py-0.5"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="text-accent">{tool.name}</span>
        {tool.target && <span className="text-dim"> {tool.target}</span>}
        <span className={failed ? 'text-glove' : 'text-dim'}>
          {' · '}
          {tool.running ? 'running' : (tool.status || 'done')}
        </span>
      </button>
      {open && (
        <div className="max-h-40 overflow-y-auto text-[10px] font-mono whitespace-pre-wrap break-words pb-1">
          {tool.params && Object.keys(tool.params).length > 0 && (
            <pre className="text-dim">{JSON.stringify(tool.params, null, 2)}</pre>
          )}
          {tool.result && (
            <pre className={failed ? 'text-glove' : 'text-gray-300'}>{tool.result}</pre>
          )}
        </div>
      )}
    </div>
  );
}
