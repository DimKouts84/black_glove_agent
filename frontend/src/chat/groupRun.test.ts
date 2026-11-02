import { describe, expect, it } from 'vitest';
import { ActivityEvent } from '../hooks/useChatSocket';
import { cardSummaryLine, groupRun, traceByMessageIndex, workingStatus } from './groupRun';

function event(partial: ActivityEvent): ActivityEvent {
  return partial;
}

describe('groupRun', () => {
  it('nests a scanner call and a warning inside the specialist that ran them', () => {
    const grouped = groupRun([
      event({
        id: 1,
        type: 'thinking',
        agent: 'network_agent',
        content: 'Summoning network_agent',
      }),
      event({
        id: 2,
        type: 'tool_call',
        agent: 'network_agent',
        tool: 'network_agent',
        content: 'network_agent',
        params: { task: 'scan the host' },
      }),
      event({
        id: 3,
        type: 'tool_call',
        agent: 'network_agent',
        tool: 'nmap',
        content: 'nmap',
        params: { target: '10.0.0.5' },
      }),
      event({
        id: 4,
        type: 'warning',
        agent: 'network_agent',
        content: 'Target is outside authorized networks',
      }),
      event({
        id: 5,
        type: 'tool_result',
        agent: 'network_agent',
        tool: 'nmap',
        content: '443 open',
        status: 'success',
      }),
      event({
        id: 6,
        type: 'tool_result',
        agent: 'black_glove',
        tool: 'network_agent',
        content: 'One open HTTPS port',
        status: 'success',
      }),
      event({
        id: 7,
        type: 'answer',
        agent: 'black_glove',
        content: 'The host has HTTPS open.',
      }),
    ]);

    expect(grouped.cards).toHaveLength(1);
    const card = grouped.cards[0];
    expect(card.agent).toBe('network_agent');
    expect(card.status).toBe('done');
    expect(card.task).toBe('scan the host');
    expect(card.summary).toBe('One open HTTPS port');
    expect(card.toolCount).toBe(1);
    expect(card.warningCount).toBe(1);
    expect(card.rows.map((row) => row.kind)).toEqual(['thinking', 'tool', 'warning']);
    expect(card.rows[1].tool).toMatchObject({
      name: 'nmap',
      target: '10.0.0.5',
      result: '443 open',
      running: false,
    });
    expect(grouped.answer).toBe('The host has HTTPS open.');
    expect(card.rows.some((row) => row.content === 'The host has HTTPS open.')).toBe(false);
    expect(cardSummaryLine(card)).toBe('Network Agent · 1 tool · 1 warning');
  });

  it('keeps two specialists in order', () => {
    const grouped = groupRun([
      event({
        id: 1,
        type: 'tool_call',
        agent: 'recon_agent',
        tool: 'recon_agent',
        params: { task: 'whois' },
      }),
      event({
        id: 2,
        type: 'tool_result',
        agent: 'black_glove',
        tool: 'recon_agent',
        content: 'registered',
      }),
      event({
        id: 3,
        type: 'tool_call',
        agent: 'web_agent',
        tool: 'web_agent',
        params: { task: 'directories' },
      }),
      event({
        id: 4,
        type: 'tool_call',
        agent: 'web_agent',
        tool: 'gobuster',
        params: { url: 'https://example.com' },
      }),
      event({
        id: 5,
        type: 'tool_result',
        agent: 'web_agent',
        tool: 'gobuster',
        content: '/admin',
      }),
      event({
        id: 6,
        type: 'tool_result',
        agent: 'black_glove',
        tool: 'web_agent',
        content: 'found /admin',
      }),
    ]);

    expect(grouped.cards.map((card) => card.agent)).toEqual(['recon_agent', 'web_agent']);
    expect(grouped.cards[0].status).toBe('done');
    expect(grouped.cards[1].rows[0].tool?.target).toBe('https://example.com');
    expect(cardSummaryLine(grouped.cards[1])).toBe('Web Agent · 1 tool');
  });

  it('leaves a specialist running when its closing result never arrives', () => {
    const grouped = groupRun([
      event({
        id: 1,
        type: 'tool_call',
        agent: 'assessment_agent',
        tool: 'assessment_agent',
        params: { task: 'report' },
      }),
      event({
        id: 2,
        type: 'tool_call',
        agent: 'assessment_agent',
        tool: 'credential_tester',
        params: { host: '10.0.0.8' },
      }),
    ]);

    expect(grouped.cards).toHaveLength(1);
    expect(grouped.cards[0].status).toBe('running');
    expect(grouped.cards[0].rows[0].tool).toMatchObject({
      name: 'credential_tester',
      target: '10.0.0.8',
      running: true,
    });
  });
});

describe('workingStatus', () => {
  it('is empty before any specialist starts', () => {
    expect(workingStatus([])).toEqual({});
  });

  it('names the running specialist and its latest tool', () => {
    expect(workingStatus([
      event({ id: 1, type: 'tool_call', agent: 'network_agent', tool: 'network_agent' }),
      event({ id: 2, type: 'tool_call', agent: 'network_agent', tool: 'nmap', params: { target: '10.0.0.5' } }),
    ])).toEqual({ specialist: 'network_agent', tool: 'nmap' });
  });

  it('is empty once every specialist has finished', () => {
    expect(workingStatus([
      event({ id: 1, type: 'tool_call', agent: 'recon_agent', tool: 'recon_agent' }),
      event({ id: 2, type: 'tool_result', agent: 'black_glove', tool: 'recon_agent', content: 'done' }),
    ])).toEqual({});
  });
});

describe('traceByMessageIndex', () => {
  const events: ActivityEvent[] = [
    { id: 1, type: 'tool_call', agent: 'recon_agent', tool: 'recon_agent' },
  ];

  it('uses run_id when the message saved one', () => {
    const traces = traceByMessageIndex(
      [
        { role: 'user', content: 'whois example.com' },
        { role: 'assistant', content: 'registered', runId: 'run-9' },
      ],
      [{ id: 'run-9', query: 'different text', events }],
    );
    expect(traces.get(1)).toEqual(events);
  });

  it('pairs an older assistant message with the run that asked the same question', () => {
    const traces = traceByMessageIndex(
      [
        { role: 'user', content: 'whois example.com' },
        { role: 'assistant', content: 'registered' },
      ],
      [{ id: 'run-1', query: 'whois example.com', events }],
    );
    expect(traces.get(1)).toEqual(events);
  });
});
