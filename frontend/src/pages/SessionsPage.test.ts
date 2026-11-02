import { describe, expect, it } from 'vitest';
import {
  POLL_MS,
  sessionsWithoutId,
  tracePollIntervalMs,
} from './SessionsPage';

describe('tracePollIntervalMs', () => {
  it('polls while a run is running and there is no error', () => {
    expect(tracePollIntervalMs(false, [{ status: 'running' }])).toBe(POLL_MS);
    expect(tracePollIntervalMs(false, [{ status: 'completed' }])).toBe(false);
  });

  it('stops polling when the query has an error even if cached runs look running', () => {
    expect(tracePollIntervalMs(true, [{ status: 'running' }])).toBe(false);
  });
});

describe('sessionsWithoutId', () => {
  it('removes the deleted session from the list cache shape', () => {
    const data = {
      sessions: [
        {
          id: 'keep',
          title: 'A',
          created_at: 't0',
          last_active: 't1',
        },
        {
          id: 'gone',
          title: 'B',
          created_at: 't0',
          last_active: 't1',
        },
      ],
    };
    expect(sessionsWithoutId(data, 'gone')?.sessions.map((s) => s.id)).toEqual(['keep']);
    expect(sessionsWithoutId(undefined, 'gone')).toBeUndefined();
  });
});
