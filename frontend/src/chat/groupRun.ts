import { ActivityEvent } from '../hooks/useChatSocket';

export const SPECIALISTS = [
  'recon_agent',
  'network_agent',
  'web_agent',
  'assessment_agent',
] as const;

const SPECIALIST_SET = new Set<string>(SPECIALISTS);
const TARGET_KEYS = ['target', 'url', 'domain', 'host'] as const;

export interface ToolRow {
  name: string;
  target?: string;
  params?: Record<string, unknown>;
  result?: string;
  status?: string;
  running: boolean;
}

export interface TraceRow {
  id: string;
  kind: 'thinking' | 'tool' | 'warning' | 'notice';
  content?: string;
  tool?: ToolRow;
}

export interface SpecialistCard {
  id: string;
  agent: string;
  task?: string;
  status: 'running' | 'done';
  summary?: string;
  toolCount: number;
  warningCount: number;
  rows: TraceRow[];
}

export interface GroupedRun {
  cards: SpecialistCard[];
  answer?: string;
}

export interface RunLike {
  id: string;
  query: string;
  events: ActivityEvent[];
}

export function specialistLabel(agent: string): string {
  const names: Record<string, string> = {
    recon_agent: 'Recon Agent',
    network_agent: 'Network Agent',
    web_agent: 'Web Agent',
    assessment_agent: 'Assessment Agent',
  };
  return names[agent] || agent;
}

export function cardSummaryLine(card: SpecialistCard): string {
  const tools = `${card.toolCount} ${card.toolCount === 1 ? 'tool' : 'tools'}`;
  const parts = [specialistLabel(card.agent), tools];
  if (card.warningCount > 0) {
    parts.push(`${card.warningCount} ${card.warningCount === 1 ? 'warning' : 'warnings'}`);
  }
  return parts.join(' · ');
}

export function targetFromParams(params?: Record<string, unknown>): string | undefined {
  if (!params) return undefined;
  for (const key of TARGET_KEYS) {
    const value = params[key];
    if (typeof value === 'string' && value.trim()) return value;
    if (typeof value === 'number') return String(value);
  }
  return undefined;
}

function toolName(event: ActivityEvent): string | undefined {
  if (event.tool) return event.tool;
  if (event.type === 'tool_call' && event.content) return event.content;
  return undefined;
}

function eventKey(event: ActivityEvent, index: number): string {
  if (event.id != null) return `e${event.id}`;
  return `${event.ts || 't'}-${event.type}-${event.agent || ''}-${index}`;
}

function isSpecialist(name: string | undefined): name is string {
  return !!name && SPECIALIST_SET.has(name);
}

function startCard(agent: string, id: string): SpecialistCard {
  return {
    id,
    agent,
    status: 'running',
    toolCount: 0,
    warningCount: 0,
    rows: [],
  };
}

function addRow(card: SpecialistCard, event: ActivityEvent, index: number): void {
  const id = eventKey(event, index);
  if (event.type === 'thinking') {
    card.rows.push({ id, kind: 'thinking', content: event.content || '' });
    return;
  }
  if (event.type === 'warning') {
    card.warningCount += 1;
    card.rows.push({ id, kind: 'warning', content: event.content || '' });
    return;
  }
  if (event.type === 'approval_resolved') {
    card.rows.push({
      id,
      kind: 'notice',
      content: event.approved ? 'Approved' : 'Rejected',
    });
    return;
  }
  if (event.type === 'tool_call') {
    const name = toolName(event) || 'tool';
    card.toolCount += 1;
    card.rows.push({
      id,
      kind: 'tool',
      tool: {
        name,
        target: targetFromParams(event.params),
        params: event.params,
        running: true,
      },
    });
    return;
  }
  if (event.type === 'tool_result') {
    const name = toolName(event);
    const match = [...card.rows].reverse().find(
      (row) => row.kind === 'tool' && row.tool?.running && (!name || row.tool.name === name),
    );
    if (match?.tool) {
      match.tool.running = false;
      match.tool.result = event.content || '';
      match.tool.status = event.status;
      return;
    }
    card.toolCount += 1;
    card.rows.push({
      id,
      kind: 'tool',
      tool: {
        name: name || 'tool',
        target: targetFromParams(event.params),
        params: event.params,
        result: event.content || '',
        status: event.status,
        running: false,
      },
    });
  }
}

/** Turn one run's activity events into specialist cards. The answer is not a row. */
export function groupRun(events: ActivityEvent[]): GroupedRun {
  const cards: SpecialistCard[] = [];
  let current: SpecialistCard | null = null;
  let answer: string | undefined;

  events.forEach((event, index) => {
    if (event.type === 'answer') {
      if (event.content) answer = event.content;
      return;
    }

    const name = toolName(event);
    const specialistCall = event.type === 'tool_call' && isSpecialist(name);
    const specialistClose = event.type === 'tool_result'
      && isSpecialist(name)
      && (event.agent === 'black_glove' || event.agent === 'root_agent' || !event.agent);

    if (specialistCall && name) {
      if (!current || current.agent !== name || current.status === 'done') {
        current = startCard(name, eventKey(event, index));
        cards.push(current);
      }
      const task = event.params?.task;
      if (typeof task === 'string') current.task = task;
      return;
    }

    if (specialistClose && name && current?.agent === name) {
      current.status = 'done';
      current.summary = event.content || '';
      current = null;
      return;
    }

    if (event.agent && isSpecialist(event.agent)) {
      if (!current || current.agent !== event.agent || current.status === 'done') {
        current = startCard(event.agent, eventKey(event, index));
        cards.push(current);
      }
      addRow(current, event, index);
    }
  });

  return { cards, answer };
}

/**
 * Attach each assistant message to the run that produced it.
 * Messages saved with run_id win. Older messages match the next run whose query equals the user text.
 */
export function traceByMessageIndex(
  messages: { role: string; content: string; runId?: string }[],
  runs: RunLike[],
): Map<number, ActivityEvent[]> {
  const byId = new Map(runs.map((run) => [run.id, run]));
  const used = new Set<string>();
  const assigned = new Map<number, ActivityEvent[]>();
  let cursor = 0;
  let pending: ActivityEvent[] | undefined;

  const takeForQuery = (query: string): ActivityEvent[] | undefined => {
    for (let i = cursor; i < runs.length; i += 1) {
      const run = runs[i];
      if (used.has(run.id) || run.query !== query) continue;
      cursor = i + 1;
      used.add(run.id);
      return run.events;
    }
    return undefined;
  };

  messages.forEach((message, index) => {
    if (message.role === 'user') {
      pending = takeForQuery(message.content);
      return;
    }
    if (message.role !== 'assistant') return;
    if (message.runId && byId.has(message.runId)) {
      used.add(message.runId);
      assigned.set(index, byId.get(message.runId)?.events ?? []);
      pending = undefined;
      return;
    }
    if (pending) {
      assigned.set(index, pending);
      pending = undefined;
    }
  });

  return assigned;
}
