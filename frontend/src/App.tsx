import { ReactNode, useEffect } from 'react';
import { Routes, Route, NavLink, useNavigate, useParams } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AsciiBanner } from './components/AsciiBanner';
import { ChatPage } from './pages/ChatPage';
import { SessionsPage } from './pages/SessionsPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { AssetsPage } from './pages/AssetsPage';
import { ToolsPage } from './pages/ToolsPage';
import { SettingsPage } from './pages/SettingsPage';
import { useAppStore } from './store/appStore';
import { api, Session } from './api/client';
import { NeonButton } from './components/NeonButton';

const NAV = [
  { to: '/', label: 'Chat' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/findings', label: 'Findings' },
  { to: '/reports', label: 'Reports' },
  { to: '/assets', label: 'Assets' },
  { to: '/tools', label: 'Tools' },
  { to: '/settings', label: 'Settings' },
];

function ScrollPage({ children }: { children: ReactNode }) {
  return <div className="h-full overflow-y-auto">{children}</div>;
}

function ChatRoute() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: sessions } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.listSessions(),
  });

  const { sessionId } = useParams();
  const sessionsLoaded = !!sessions;
  const sessionMissing =
    sessionsLoaded &&
    !!sessionId &&
    !sessions.sessions.some((s) => s.id === sessionId);
  const activeId = sessionMissing
    ? undefined
    : sessionId || sessions?.sessions[0]?.id;

  useEffect(() => {
    if (sessionMissing) {
      const fallback = sessions.sessions[0]?.id;
      navigate(fallback ? `/chat/${fallback}` : '/', { replace: true });
      return;
    }
    if (!sessionId && sessions?.sessions[0]) {
      navigate(`/chat/${sessions.sessions[0].id}`, { replace: true });
    }
  }, [sessionId, sessions, sessionMissing, navigate]);

  const handleNew = async () => {
    const created = await api.createSession('Security Assessment');
    queryClient.setQueryData<{ sessions: Session[] }>(['sessions'], (current) => {
      const known = current?.sessions ?? [];
      if (known.some((session) => session.id === created.id)) return current;
      return { sessions: [created, ...known] };
    });
    navigate(`/chat/${created.id}`);
  };

  if (sessionMissing) {
    return null;
  }

  if (!activeId) {
    return (
      <div className="text-center py-20">
        <p className="text-dim mb-4">No active session.</p>
        <NeonButton onClick={handleNew}>Start New Session</NeonButton>
      </div>
    );
  }

  return (
    <div className="h-full min-h-0 overflow-hidden flex flex-col">
      <ChatPage sessionId={activeId} onNewSession={handleNew} />
    </div>
  );
}

export default function App() {
  const { provider, model, loadConfig } = useAppStore();

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  return (
    <div className="h-dvh overflow-hidden bg-grid flex flex-col">
      <header className="border-b border-border px-4 py-3 shrink-0">
        <AsciiBanner compact />
      </header>
      <div className="flex flex-1 min-h-0">
        <aside className="w-48 border-r border-border p-3 hidden md:block shrink-0">
          <nav className="space-y-1">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `block px-3 py-2 rounded text-sm transition-colors ${
                    isActive ? 'bg-primary/10 text-primary border border-primary/30' : 'text-dim hover:text-primary'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="flex-1 min-h-0 p-4 flex flex-col overflow-hidden">
          <Routes>
            <Route path="/" element={<ChatRoute />} />
            <Route path="/chat/:sessionId" element={<ChatRoute />} />
            <Route path="/sessions" element={<ScrollPage><SessionsPage /></ScrollPage>} />
            <Route path="/findings" element={<ScrollPage><FindingsPage /></ScrollPage>} />
            <Route path="/reports" element={<ScrollPage><ReportsPage /></ScrollPage>} />
            <Route path="/assets" element={<ScrollPage><AssetsPage /></ScrollPage>} />
            <Route path="/tools" element={<ScrollPage><ToolsPage /></ScrollPage>} />
            <Route path="/settings" element={<ScrollPage><SettingsPage /></ScrollPage>} />
          </Routes>
        </main>
      </div>
      <footer className="border-t border-border px-4 py-2 text-xs text-dim flex justify-end shrink-0">
        <span className="text-primary">╰</span>
        <span className="mx-2 text-secondary">
          Provider: {provider} | Model: {model}
        </span>
        <span className="text-primary">╯</span>
      </footer>
    </div>
  );
}
