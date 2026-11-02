import { ActivityEvent } from '../hooks/useChatSocket';
import { specialistLabel, workingStatus } from '../chat/groupRun';

interface Props {
  events: ActivityEvent[];
}

export function WorkingPanel({ events }: Props) {
  const status = workingStatus(events);
  const specialist = status.specialist ? specialistLabel(status.specialist) : undefined;
  return (
    <div className="mt-3 flex items-center gap-3 border border-primary/40 rounded px-3 py-2 text-xs" role="status">
      <span
        className="h-4 w-4 shrink-0 rounded-full border-2 border-primary border-t-transparent animate-spin"
        aria-hidden
      />
      <span className="text-primary">Black Glove is working</span>
      {specialist && <span className="text-secondary">{specialist}</span>}
      {status.tool && <span className="text-accent">{status.tool}</span>}
    </div>
  );
}
