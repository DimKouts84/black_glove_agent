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
});
