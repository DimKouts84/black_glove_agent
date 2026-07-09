import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import ReactMarkdown from 'react-markdown';
import { api } from '../api/client';
import { useChatSocket } from '../hooks/useChatSocket';
import { TerminalPanel } from '../components/TerminalPanel';
import { ActivityTimeline } from '../components/ActivityTimeline';
import { ApprovalModal } from '../components/ApprovalModal';
import { NeonButton } from '../components/NeonButton';

interface Props {
  sessionId: string;
}

export function ChatPage({ sessionId }: Props) {
  const { data: history } = useQuery({
    queryKey: ['messages', sessionId],
    queryFn: () => api.getMessages(sessionId),
  });

  const {
    connected, acting, activities, messages, setMessages,
    sendMessage, pendingApproval, respondApproval,
  } = useChatSocket(sessionId);

  const [input, setInput] = useState('');
  const orchestrationRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (history?.messages) {
      setMessages(history.messages.map((m) => ({
        role: m.role as 'user' | 'assistant',
        content: m.content,
      })));
    }
  }, [history, setMessages]);

  useEffect(() => {
    orchestrationRef.current?.scrollTo({
      top: 0,
      behavior: 'smooth',
    });
  }, [activities.length]);

  const handleSend = () => {
    if (!input.trim()) return;
    sendMessage(input.trim());
    setInput('');
  };

  const showOrchestration = acting || activities.length > 0;

  return (
    <div className="flex flex-col lg:flex-row gap-4 h-full">
      <div className="flex-1 flex flex-col min-h-0">
        <TerminalPanel title="CHAT // BLACK GLOVE" className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 overflow-y-auto space-y-4 mb-4 min-h-[400px] max-h-[calc(100vh-280px)]">
            {messages.map((msg, i) => (
              <div key={i} className={msg.role === 'user' ? 'text-right' : ''}>
                <span className={`text-xs ${msg.role === 'user' ? 'text-secondary' : 'text-primary'}`}>
                  {msg.role === 'user' ? 'YOU' : '🛡️ BLACK GLOVE'}
                </span>
                <div className={`mt-1 text-sm prose prose-invert max-w-none ${msg.role === 'user' ? 'text-gray-300' : ''}`}>
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              </div>
            ))}
            {acting && (
              <div className="text-primary text-sm animate-pulse caret-blink">
                Acting...
              </div>
            )}
          </div>
          <div className="neon-border rounded flex gap-2 p-2">
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
          <div className="text-xs text-dim mt-2 flex justify-between">
            <span>{connected ? '● connected' : '○ disconnected'}</span>
            <span>Provider | Model in status bar</span>
          </div>
        </TerminalPanel>
      </div>

      {/* Desktop sidebar */}
      <div className="w-72 shrink-0 hidden lg:block">
        <TerminalPanel title="LIVE ORCHESTRATION" className="h-full flex flex-col min-h-0">
          <div ref={orchestrationRef} className="flex-1 overflow-y-auto min-h-[300px] max-h-[calc(100vh-200px)]">
            <ActivityTimeline events={activities} acting={acting} newestFirst />
            {!showOrchestration && (
              <p className="text-dim text-xs">Sub-agent activity will appear here during scans.</p>
            )}
          </div>
        </TerminalPanel>
      </div>

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
