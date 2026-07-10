import { ActivityEvent } from '../hooks/useChatSocket';

interface Props {
  events: ActivityEvent[];
  acting?: boolean;
  compact?: boolean;
  newestFirst?: boolean;
}

const TYPE_ICONS: Record<string, string> = {
  thinking: '🤖',
  tool_call: '🛠️',
  tool_result: '✅',
  answer: '📤',
  warning: '⚠️',
  approval_request: '🔒',
  approval_resolved: '🔓',
};

const AGENT_COLORS: Record<string, string> = {
  root_agent: 'text-primary',
  planner_agent: 'text-accent',
  researcher_agent: 'text-secondary',
  analyst_agent: 'text-green-400',
};

function formatParams(params?: Record<string, unknown>): string | null {
  if (!params || Object.keys(params).length === 0) return null;
  const raw = JSON.stringify(params);
  return raw.length > 120 ? `${raw.slice(0, 120)}…` : raw;
}

export function ActivityTimeline({ events, acting = false, compact = false, newestFirst = false }: Props) {
  if (events.length === 0) {
    if (acting) {
      return (
        <p className="text-dim text-xs animate-pulse">
          Orchestrating…
        </p>
      );
    }
    return null;
  }

  const displayEvents = newestFirst ? [...events].reverse() : events;

  return (
    <div className={`space-y-2 ${compact ? 'text-xs' : 'text-xs'}`}>
      {displayEvents.map((ev, i) => {
        const agentClass = AGENT_COLORS[ev.agent || ''] || 'text-secondary';
        const paramsStr = ev.type === 'tool_call' ? formatParams(ev.params) : null;
        const toolLabel = ev.type === 'tool_call' ? (ev.content || ev.tool) : ev.tool;

        return (
          <div key={ev.id ?? `${ev.ts}-${ev.type}-${i}`} className="flex gap-2 items-start border-l-2 border-primary/30 pl-3 py-1">
            <span>{TYPE_ICONS[ev.type] || '•'}</span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-x-1">
                <span className={`font-bold ${agentClass}`}>{ev.agent}</span>
                <span className="text-dim">·</span>
                <span className="text-primary">{ev.type}</span>
                {ev.ts && !compact && (
                  <span className="text-dim ml-auto text-[10px]">{ev.ts.slice(11, 19)}</span>
                )}
              </div>
              {ev.content && ev.type !== 'tool_result' && (
                <p className="text-dim mt-0.5 break-words">{ev.content}</p>
              )}
              {ev.type === 'tool_result' && (
                <div className="mt-0.5 break-words space-y-1">
                  <p className={
                    ev.content?.startsWith('Error:') || ev.status === 'error'
                      ? 'text-glove'
                      : ev.status === 'partial' || ev.status === 'not_applicable'
                        ? 'text-yellow-400'
                        : 'text-dim'
                  }>
                    {ev.content || 'Tool execution completed'}
                  </p>
                  {ev.status && (
                    <p className="text-[10px] text-secondary">status: {ev.status}</p>
                  )}
                  {ev.warnings && ev.warnings.length > 0 && (
                    <p className="text-[10px] text-yellow-400">
                      warnings: {ev.warnings.slice(0, 2).join('; ')}
                    </p>
                  )}
                  {ev.coverage && Object.keys(ev.coverage).length > 0 && (
                    <p className="text-[10px] text-dim font-mono">
                      coverage: {JSON.stringify(ev.coverage)}
                    </p>
                  )}
                  {ev.evidence_paths && ev.evidence_paths.length > 0 && (
                    <p className="text-[10px] text-secondary break-all">
                      evidence: {ev.evidence_paths[0]}
                    </p>
                  )}
                </div>
              )}
              {toolLabel && ev.type === 'tool_call' && (
                <p className="text-accent mt-0.5">tool: {toolLabel}</p>
              )}
              {paramsStr && (
                <p className="text-dim/80 mt-0.5 font-mono text-[10px] break-all">{paramsStr}</p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
