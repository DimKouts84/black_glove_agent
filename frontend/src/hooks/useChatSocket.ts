import { useCallback, useEffect, useRef, useState } from 'react';
import { api, RunTrace, TraceEvent } from '../api/client';

export interface ActivityEvent {
  id?: number;
  type: string;
  agent?: string;
  content?: string;
  params?: Record<string, unknown>;
  tool?: string;
  approved?: boolean;
  approval_id?: string;
  run_id?: string;
  ts?: string;
  status?: string;
  evidence_paths?: string[];
  warnings?: string[];
  coverage?: Record<string, unknown>;
  result_digest?: string;
  error?: string;
  report_path?: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

const TOOL_RESULT_FALLBACK = 'Tool execution completed';

export function normalizeActivityContent(e: ActivityEvent): string {
  if (e.type === 'tool_result' && !e.content) {
    return TOOL_RESULT_FALLBACK;
  }
  return e.content || '';
}

function semanticKey(e: ActivityEvent): string {
  return `${e.run_id || ''}-${e.type}-${e.agent || ''}-${normalizeActivityContent(e)}`;
}

export function shouldPollTraceWhileActing(
  acting: boolean,
  connected: boolean,
  sessionId: string | null,
): boolean {
  return !!(acting && sessionId && !connected);
}

export function traceToActivities(runs: RunTrace[]): ActivityEvent[] {
  const events: ActivityEvent[] = [];
  for (const run of runs) {
    for (const e of run.events) {
      events.push(traceEventToActivity(e, run.id));
    }
  }
  return events.sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));
}

function traceEventToActivity(e: TraceEvent, runId: string): ActivityEvent {
  return {
    id: e.id,
    type: e.type,
    agent: e.agent,
    content: e.content,
    params: e.params,
    ts: e.ts,
    run_id: runId,
    tool: e.tool ?? (e.type === 'tool_call' ? e.content : undefined),
    status: e.status,
    evidence_paths: e.evidence_paths,
    warnings: e.warnings,
    coverage: e.coverage,
    result_digest: e.result_digest,
    error: e.error,
    report_path: e.report_path,
  };
}

export function mergeActivities(existing: ActivityEvent[], incoming: ActivityEvent[]): ActivityEvent[] {
  const bySemantic = new Map<string, ActivityEvent>();

  for (const e of [...existing, ...incoming]) {
    const key = semanticKey(e);
    const prev = bySemantic.get(key);
    if (!prev || (e.id != null && prev.id == null)) {
      bySemantic.set(key, e);
    }
  }

  return [...bySemantic.values()].sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));
}

export function dedupeActivities(events: ActivityEvent[]): ActivityEvent[] {
  return mergeActivities([], events);
}

function filterByRunId(events: ActivityEvent[], runId: string | null): ActivityEvent[] {
  if (!runId) return events;
  return events.filter((e) => !e.run_id || e.run_id === runId);
}

const ORCHESTRATION_TYPES = [
  'thinking',
  'tool_call',
  'tool_result',
  'answer',
  'warning',
  'approval_resolved',
] as const;

export function useChatSocket(sessionId: string | null) {
  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const loadTraceRef = useRef<(() => Promise<void>) | null>(null);
  const connectedRef = useRef(false);
  const activeRunIdRef = useRef<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [acting, setActing] = useState(false);
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ActivityEvent | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const loadTrace = useCallback(async () => {
    if (!sessionId) return;
    try {
      const trace = await api.getTrace(sessionId);
      const runs = trace.runs || [];
      let fromTrace = traceToActivities(runs);
      const runningRun = runs.find((r) => r.status === 'running');
      const hasRunning = !!runningRun;

      if (!activeRunIdRef.current && runningRun) {
        activeRunIdRef.current = runningRun.id;
      }
      fromTrace = filterByRunId(fromTrace, activeRunIdRef.current);

      if (hasRunning) {
        setActing(true);
        if (!connectedRef.current) {
          setActivities((prev) => mergeActivities(prev, fromTrace));
        }
      } else {
        setActing(false);
        activeRunIdRef.current = null;
        setActivities(dedupeActivities(fromTrace));
        const history = await api.getMessages(sessionId);
        setMessages(
          history.messages.map((m) => ({
            role: m.role as 'user' | 'assistant' | 'system',
            content: m.content,
          })),
        );
      }
    } catch {
      // trace may be empty for new sessions
    }
  }, [sessionId]);

  loadTraceRef.current = loadTrace;

  useEffect(() => {
    if (!sessionId) return;
    loadTrace();
  }, [sessionId, loadTrace]);

  useEffect(() => {
    if (!sessionId) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host = window.location.host;
    const ws = new WebSocket(`${proto}://${host}/ws/chat/${sessionId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      connectedRef.current = true;
      setConnected(true);
    };
    ws.onclose = () => {
      connectedRef.current = false;
      setConnected(false);
    };
    ws.onmessage = (ev) => {
      const data = JSON.parse(ev.data) as ActivityEvent & { type: string; content?: string };
      if (data.type === 'status' && data.content === 'acting') {
        activeRunIdRef.current = null;
        setActing(true);
        setActivities([]);
        return;
      }
      if (data.type === 'assistant_message') {
        setActing(false);
        activeRunIdRef.current = null;
        setMessages((prev) => [...prev, { role: 'assistant', content: data.content || '' }]);
        void loadTraceRef.current?.();
        return;
      }
      if (data.type === 'approval_request') {
        setPendingApproval(data);
        return;
      }
      if (data.type === 'error') {
        setActing(false);
        activeRunIdRef.current = null;
        setMessages((prev) => [...prev, { role: 'system', content: `Error: ${data.content}` }]);
        void loadTraceRef.current?.();
        return;
      }
      if (ORCHESTRATION_TYPES.includes(data.type as (typeof ORCHESTRATION_TYPES)[number])) {
        if (data.run_id && !activeRunIdRef.current) {
          activeRunIdRef.current = data.run_id;
        }
        setActivities((prev) => mergeActivities(prev, [data]));
      }
    };
    return () => ws.close();
  }, [sessionId]);

  useEffect(() => {
    if (shouldPollTraceWhileActing(acting, connected, sessionId)) {
      pollRef.current = setInterval(() => {
        void loadTraceRef.current?.();
      }, 2000);
    } else if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [acting, connected, sessionId]);

  const sendMessage = useCallback((content: string) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    setMessages((prev) => [...prev, { role: 'user', content }]);
    wsRef.current.send(JSON.stringify({ type: 'user_message', content }));
  }, []);

  const respondApproval = useCallback((approved: boolean) => {
    if (!pendingApproval || !wsRef.current) return;
    wsRef.current.send(JSON.stringify({
      type: 'approval',
      approval_id: pendingApproval.approval_id,
      approved,
    }));
    setPendingApproval(null);
  }, [pendingApproval]);

  return {
    connected,
    acting,
    activities,
    messages,
    setMessages,
    sendMessage,
    pendingApproval,
    respondApproval,
    loadTrace,
  };
}
