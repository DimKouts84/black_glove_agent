import { describe, expect, it } from 'vitest';
import {
  dedupeActivities,
  mergeActivities,
  shouldPollTraceWhileActing,
  ActivityEvent,
} from './useChatSocket';

describe('mergeActivities', () => {
  it('dedupes live and trace events by semantic key', () => {
    const live: ActivityEvent = {
      run_id: 'run-1',
      type: 'tool_result',
      agent: 'researcher_agent',
      content: 'OSINT summary',
    };
    const traced: ActivityEvent = {
      id: 42,
      run_id: 'run-1',
      type: 'tool_result',
      agent: 'researcher_agent',
      content: 'OSINT summary',
      ts: '2026-01-01T10:00:00',
    };
    const merged = mergeActivities([live], [traced]);
    expect(merged).toHaveLength(1);
    expect(merged[0].id).toBe(42);
  });

  it('dedupes tool_result with empty content and fallback text', () => {
    const empty: ActivityEvent = {
      run_id: 'run-1',
      type: 'tool_result',
      agent: 'researcher_agent',
      content: '',
    };
    const fallback: ActivityEvent = {
      id: 7,
      run_id: 'run-1',
      type: 'tool_result',
      agent: 'researcher_agent',
      content: 'Tool execution completed',
      ts: '2026-01-01T10:00:00',
    };
    const merged = mergeActivities([empty], [fallback]);
    expect(merged).toHaveLength(1);
    expect(merged[0].id).toBe(7);
  });

  it('dedupes duplicate trace rows with the same semantic key', () => {
    const events: ActivityEvent[] = [
      {
        id: 1,
        run_id: 'run-1',
        type: 'thinking',
        agent: 'root_agent',
        content: 'Planning scan',
        ts: '2026-01-01T10:00:00',
      },
      {
        id: 2,
        run_id: 'run-1',
        type: 'thinking',
        agent: 'root_agent',
        content: 'Planning scan',
        ts: '2026-01-01T10:00:00',
      },
    ];
    const deduped = dedupeActivities(events);
    expect(deduped).toHaveLength(1);
    expect(deduped[0].id).toBe(1);
  });
});

describe('shouldPollTraceWhileActing', () => {
  it('polls only when acting and disconnected', () => {
    expect(shouldPollTraceWhileActing(true, true, 'session-1')).toBe(false);
    expect(shouldPollTraceWhileActing(true, false, 'session-1')).toBe(true);
    expect(shouldPollTraceWhileActing(false, false, 'session-1')).toBe(false);
    expect(shouldPollTraceWhileActing(true, false, null)).toBe(false);
  });
});
