import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ActivityTimeline } from './ActivityTimeline';
import { ActivityEvent } from '../hooks/useChatSocket';

const events: ActivityEvent[] = [
  { id: 1, type: 'thinking', agent: 'planner_agent', content: 'First event', ts: '2026-01-01T10:00:00' },
  { id: 2, type: 'tool_call', agent: 'researcher_agent', content: 'Second event', ts: '2026-01-01T10:01:00' },
  { id: 3, type: 'answer', agent: 'root_agent', content: 'Third event', ts: '2026-01-01T10:02:00' },
];

function agentOrder(): string[] {
  return screen.getAllByText(/_agent$/).map((el) => el.textContent ?? '');
}

describe('ActivityTimeline', () => {
  it('renders events oldest-first by default', () => {
    render(<ActivityTimeline events={events} />);
    expect(agentOrder()).toEqual(['planner_agent', 'researcher_agent', 'root_agent']);
  });

  it('renders events newest-first when newestFirst is set', () => {
    render(<ActivityTimeline events={events} newestFirst />);
    expect(agentOrder()).toEqual(['root_agent', 'researcher_agent', 'planner_agent']);
  });

  it('shows tool_result content and error styling', () => {
    render(
      <ActivityTimeline
        events={[
          {
            id: 4,
            type: 'tool_result',
            agent: 'researcher_agent',
            content: 'Error: crt.sh: timeout',
            ts: '2026-01-01T10:03:00',
            status: 'error',
          },
        ]}
      />,
    );
    expect(screen.getByText('Error: crt.sh: timeout').textContent).toBe('Error: crt.sh: timeout');
    expect(screen.getByText('status: error').textContent).toBe('status: error');
  });

  it('shows partial status, warnings, coverage, and evidence metadata', () => {
    render(
      <ActivityTimeline
        events={[
          {
            id: 5,
            type: 'tool_result',
            agent: 'researcher_agent',
            content: 'WHOIS/RDAP lookup returned no registration data.',
            ts: '2026-01-01T10:04:00',
            status: 'partial',
            warnings: ['RDAP HTTP 503', 'Legacy WHOIS failed'],
            coverage: { has_core_fields: false, rdap_used: false },
            evidence_paths: ['evidence/whoisadapter/whois_example_123.txt'],
          },
        ]}
      />,
    );
    expect(screen.getByText(/no registration data/i)).toBeTruthy();
    expect(screen.getByText('status: partial').textContent).toBe('status: partial');
    expect(screen.getByText(/warnings: RDAP HTTP 503/)).toBeTruthy();
    expect(screen.getByText(/coverage:/)).toBeTruthy();
    expect(screen.getByText(/evidence: evidence\/whoisadapter/)).toBeTruthy();
  });
});
