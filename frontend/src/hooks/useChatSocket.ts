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
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

function eventKey(e: ActivityEvent): string {
  return e.id != null
    ? `id:${e.id}`
    : `${e.run_id || ''}-${e.ts || ''}-${e.type}-${e.agent}-${e.content}`;
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
    tool: e.type === 'tool_call' ? e.content : undefined,
  };
}

export function mergeActivities(existing: ActivityEvent[], incoming: ActivityEvent[]): ActivityEvent[] {
  const seen = new Set(existing.map(eventKey));
  const merged = [...existing];
  for (const e of incoming) {
    const key = eventKey(e);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(e);
    }
  }
  return merged.sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));
}

export function useChatSocket(sessionId: string | null) {
  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const loadTraceRef = useRef<(() => Promise<void>) | null>(null);
  const [connected, setConnected] = useState(false);
  const [acting, setActing] = useState(false);
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ActivityEvent | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const loadTrace = useCallback(async () => {
    if (!sessionId) return;
    try {
      const trace = await api.getTrace(sessionId);
      const fromTrace = traceToActivities(trace.runs || []);
      setActivities((prev) => mergeActivities(prev, fromTrace));
      const hasRunning = (trace.runs || []).some((r) => r.status === 'running');
      if (hasRunning) {
        setActing(true);
      } else {
        setActing(false);
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

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (ev) => {
      const data = JSON.parse(ev.data) as ActivityEvent & { type: string; content?: string };
      if (data.type === 'status' && data.content === 'acting') {
        setActing(true);
        setActivities([]);
        return;
      }
      if (data.type === 'assistant_message') {
        setActing(false);
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
        setMessages((prev) => [...prev, { role: 'system', content: `Error: ${data.content}` }]);
        void loadTraceRef.current?.();
        return;
      }
      if (['thinking', 'tool_call', 'tool_result', 'answer', 'warning', 'approval_resolved'].includes(data.type)) {
        setActivities((prev) => mergeActivities(prev, [data]));
      }
    };
    return () => ws.close();
  }, [sessionId]);

  useEffect(() => {
    if (acting && sessionId) {
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
  }, [acting, sessionId]);

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
