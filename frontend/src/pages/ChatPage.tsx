import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { traceByMessageIndex } from '../chat/groupRun';
import { useChatSocket, messageFromApi } from '../hooks/useChatSocket';
import { TerminalPanel } from '../components/TerminalPanel';
import { ActivityTimeline } from '../components/ActivityTimeline';
import { ApprovalModal } from '../components/ApprovalModal';
import { TurnTrace } from '../components/TurnTrace';
import { WorkingPanel } from '../components/WorkingPanel';
import { MarkdownBody } from '../components/MarkdownBody';
import { NeonButton } from '../components/NeonButton';

interface Props {
  sessionId: string;
  onNewSession?: () => void;
}

export function ChatPage({ sessionId, onNewSession }: Props) {
  const { data: history } = useQuery({
    queryKey: ['messages', sessionId],
    queryFn: () => api.getMessages(sessionId),
  });

  const {
    connected, acting, activities, runs, messages, setMessages,
    sendMessage, pendingApproval, respondApproval,
  } = useChatSocket(sessionId);

  const [input, setInput] = useState('');
  const [rawLog, setRawLog] = useState(false);
  const transcriptRef = useRef<HTMLDivElement>(null);
  const traces = traceByMessageIndex(messages, runs);

  useEffect(() => {
    if (history?.messages) {
      setMessages(history.messages.map(messageFromApi));
    }
  }, [history, setMessages]);

  useEffect(() => {
    const el = transcriptRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [messages, activities.length, acting]);

  const handleSend = () => {
    if (!input.trim()) return;
    sendMessage(input.trim());
    setInput('');
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      <TerminalPanel
        fill
        title="CHAT // BLACK GLOVE"
        className="flex-1 min-h-0"
        actions={onNewSession && (
          <NeonButton variant="ghost" className="text-xs py-1 px-2" onClick={onNewSession}>
            New session
          </NeonButton>
        )}
      >
        <div
          ref={transcriptRef}
          className="flex-1 min-h-0 overflow-y-auto space-y-4 mb-4"
        >
          {messages.map((msg, i) => (
            <div key={`${msg.role}-${i}`} className={msg.role === 'user' ? 'text-right' : ''}>
              <span className={`text-xs ${msg.role === 'user' ? 'text-secondary' : 'text-primary'}`}>
                {msg.role === 'user' ? 'YOU' : '🛡️ BLACK GLOVE'}
              </span>
              {msg.role === 'assistant' && (
                <TurnTrace events={traces.get(i) ?? []} />
              )}
              <div className={`mt-1 text-sm max-w-none ${msg.role === 'user' ? 'text-gray-300' : ''}`}>
                <MarkdownBody>{msg.content}</MarkdownBody>
              </div>
            </div>
          ))}
          {acting && (
            <div>
              <span className="text-xs text-primary">🛡️ BLACK GLOVE</span>
              <TurnTrace events={activities} />
              <WorkingPanel events={activities} />
            </div>
          )}
        </div>
        <div className="neon-border rounded flex gap-2 p-2 shrink-0">
          <span className="text-primary px-1">│ &gt;</span>
          <input
            className="flex-1 bg-transparent outline-none text-sm font-mono"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Scan my local network for open ports..."
            disabled={!connected || acting}
          />
          <NeonButton onClick={handleSend} disabled={!connected || acting}>Send</NeonButton>
        </div>
        <div className="text-xs text-dim mt-2 flex justify-between shrink-0">
          <span>{connected ? '● connected' : '○ disconnected'}</span>
          <button
            type="button"
            className="text-accent"
            onClick={() => setRawLog((open) => !open)}
          >
            {rawLog ? 'Hide raw log' : 'Raw log'}
          </button>
        </div>
        {rawLog && (
          <div className="mt-2 max-h-64 overflow-y-auto border-t border-border pt-2 shrink-0">
            <ActivityTimeline events={activities} acting={acting} newestFirst />
            {!acting && activities.length === 0 && (
              <p className="text-dim text-xs">No activity yet.</p>
            )}
          </div>
        )}
      </TerminalPanel>

      {pendingApproval && (
        <ApprovalModal
          tool={pendingApproval.tool}
          content={pendingApproval.content}
          onApprove={() => respondApproval(true)}
          onReject={() => respondApproval(false)}
        />
      )}
    </div>
  );
}
