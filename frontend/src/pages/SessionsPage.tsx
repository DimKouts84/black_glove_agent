import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, RunTrace } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';
import { NeonButton } from '../components/NeonButton';
import { ActivityTimeline } from '../components/ActivityTimeline';

const STALE_MS = 5 * 60 * 1000;
const POLL_MS = 2000;

function lastEventTs(runs: RunTrace[]): string | null {
  let latest: string | null = null;
  for (const run of runs) {
    for (const event of run.events) {
      if (!latest || event.ts > latest) {
        latest = event.ts;
      }
    }
    if (!latest && run.started_at) {
      latest = run.started_at;
    }
  }
  return latest;
}

function isStaleRun(runs: RunTrace[]): boolean {
  const hasRunning = runs.some((r) => r.status === 'running');
  if (!hasRunning) return false;
  const last = lastEventTs(runs);
  if (!last) return false;
  const lastMs = Date.parse(last);
  if (Number.isNaN(lastMs)) return false;
  return Date.now() - lastMs > STALE_MS;
}

export function SessionsPage() {
  const { data, refetch } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.listSessions(),
  });

  const handleDelete = async (id: string) => {
    await api.deleteSession(id);
    refetch();
  };

  const handleCreate = async () => {
    await api.createSession('New Assessment');
    refetch();
  };

  return (
    <TerminalPanel title="SESSION HISTORY">
      <div className="mb-4">
        <NeonButton onClick={handleCreate}>+ New Session</NeonButton>
      </div>
      <div className="space-y-3">
        {data?.sessions.map((s) => (
          <SessionRow key={s.id} session={s} onDelete={() => handleDelete(s.id)} />
        ))}
        {(!data?.sessions || data.sessions.length === 0) && (
          <p className="text-dim text-sm">No sessions yet. Start a chat to create one.</p>
        )}
      </div>
    </TerminalPanel>
  );
}

function SessionRow({
  session,
  onDelete,
}: {
  session: { id: string; title: string; created_at: string; last_active: string };
  onDelete: () => void;
}) {
  const { data: trace, refetch: refetchTrace } = useQuery({
    queryKey: ['trace', session.id],
    queryFn: () => api.getTrace(session.id),
    refetchInterval: (query) => {
      const runs = query.state.data?.runs ?? [];
      return runs.some((r) => r.status === 'running') ? POLL_MS : false;
    },
  });

  const runs = trace?.runs ?? [];
  const hasRunning = runs.some((r) => r.status === 'running');
  const stale = isStaleRun(runs);
  const lastEvent = lastEventTs(runs);

  useEffect(() => {
    if (!hasRunning) return;
    const id = setInterval(() => {
      void refetchTrace();
    }, POLL_MS);
    return () => clearInterval(id);
  }, [hasRunning, refetchTrace]);

  return (
    <div className="border border-border rounded p-3 hover:border-primary/50 transition-colors">
      <div className="flex justify-between items-start">
        <div>
          <Link to={`/chat/${session.id}`} className="text-primary hover:underline font-bold">
            {session.title || session.id.slice(0, 8)}
          </Link>
          <p className="text-dim text-xs mt-1">
            Created: {session.created_at} · Last: {session.last_active}
          </p>
        </div>
        <NeonButton variant="ghost" className="text-xs py-1 px-2" onClick={onDelete}>Delete</NeonButton>
      </div>
      {runs.length > 0 && (
        <details className="mt-2 text-xs">
          <summary className="text-accent cursor-pointer">
            {runs.length} run(s) · view trace
            {hasRunning && (
              <span className="text-primary ml-2 animate-pulse">● running</span>
            )}
            {stale && (
              <span className="text-yellow-500 ml-2">⚠ stale (no events recently)</span>
            )}
          </summary>
          {lastEvent && (
            <p className="text-dim mt-1">Last event: {lastEvent}</p>
          )}
          {runs.map((run) => (
            <div key={run.id} className="mt-2 pl-2 border-l border-border">
              <p className="text-dim">Query: {run.query}</p>
              <p className="text-dim">Status: {run.status}</p>
              <ActivityTimeline events={run.events.map((e) => ({
                type: e.type,
                agent: e.agent,
                content: e.content,
                tool: e.params ? String(Object.keys(e.params)[0]) : undefined,
              }))} />
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
