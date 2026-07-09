import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';
import { NeonButton } from '../components/NeonButton';
import { ActivityTimeline } from '../components/ActivityTimeline';

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

function SessionRow({ session, onDelete }: { session: { id: string; title: string; created_at: string; last_active: string }; onDelete: () => void }) {
  const { data: trace } = useQuery({
    queryKey: ['trace', session.id],
    queryFn: () => api.getTrace(session.id),
  });

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
      {trace?.runs && trace.runs.length > 0 && (
        <details className="mt-2 text-xs">
          <summary className="text-accent cursor-pointer">
            {trace.runs.length} run(s) · view trace
          </summary>
          {trace.runs.map((run) => (
            <div key={run.id} className="mt-2 pl-2 border-l border-border">
              <p className="text-dim">Query: {run.query}</p>
              <p className="text-dim">Status: {run.status}</p>
              <ActivityTimeline events={run.events.map((e) => ({
                type: e.type, agent: e.agent, content: e.content, tool: e.params ? String(Object.keys(e.params)[0]) : undefined,
              }))} />
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
