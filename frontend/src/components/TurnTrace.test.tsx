import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ActivityEvent } from '../hooks/useChatSocket';
import { TurnTrace } from './TurnTrace';

const finished: ActivityEvent[] = [
  {
    id: 1,
    type: 'tool_call',
    agent: 'network_agent',
    tool: 'network_agent',
    params: { task: 'ports' },
  },
  {
    id: 2,
    type: 'tool_call',
    agent: 'network_agent',
    tool: 'nmap',
    params: { target: '10.0.0.5' },
  },
  {
    id: 3,
    type: 'warning',
    agent: 'network_agent',
    content: 'Target is outside authorized networks',
  },
  {
    id: 4,
    type: 'tool_result',
    agent: 'network_agent',
    tool: 'nmap',
    content: '443 open',
    status: 'success',
  },
  {
    id: 5,
    type: 'tool_result',
    agent: 'black_glove',
    tool: 'network_agent',
    content: 'One open HTTPS port',
  },
];

describe('TurnTrace', () => {
  it('collapses a finished specialist and keeps the warning on that line', () => {
    render(<TurnTrace events={finished} />);
    const card = screen.getByRole('button', { name: /Network Agent/ });
    expect(card.getAttribute('aria-expanded')).toBe('false');
    expect(screen.getByText(/1 warning/)).toBeTruthy();
    expect(screen.queryByText('443 open')).toBeNull();
  });

  it('expands a finished card to the tool result', () => {
    render(<TurnTrace events={finished} />);
    fireEvent.click(screen.getByRole('button', { name: /Network Agent/ }));
    const tool = screen.getByRole('button', { name: /nmap/ });
    fireEvent.click(tool);
    expect(screen.getByText('443 open')).toBeTruthy();
    expect(screen.getByText(/"target": "10.0.0.5"/)).toBeTruthy();
  });

  it('keeps the active specialist open', () => {
    render(
      <TurnTrace
        acting
        events={[
          {
            id: 1,
            type: 'tool_call',
            agent: 'web_agent',
            tool: 'web_agent',
            params: { task: 'directories' },
          },
          {
            id: 2,
            type: 'tool_call',
            agent: 'web_agent',
            tool: 'gobuster',
            params: { url: 'https://example.com' },
          },
        ]}
      />,
    );
    expect(screen.getByRole('button', { name: /Web Agent/ }).getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByRole('button', { name: /gobuster/ })).toBeTruthy();
  });

  it('shortens a long specialist summary on the collapsed line', () => {
    const long = 'detail '.repeat(80);
    render(
      <TurnTrace
        events={[
          { id: 1, type: 'tool_call', agent: 'recon_agent', tool: 'recon_agent' },
          { id: 2, type: 'tool_result', agent: 'black_glove', tool: 'recon_agent', content: long },
        ]}
      />,
    );
    const card = screen.getByRole('button', { name: /Recon Agent/ });
    expect(card.textContent && card.textContent.length < 220).toBe(true);
    expect(card.textContent).toContain('…');
  });
});
