import { useEffect } from 'react';
import { Routes, Route, NavLink, useNavigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AsciiBanner } from './components/AsciiBanner';
import { ChatPage } from './pages/ChatPage';
import { SessionsPage } from './pages/SessionsPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { AssetsPage } from './pages/AssetsPage';
import { ToolsPage } from './pages/ToolsPage';
import { SettingsPage } from './pages/SettingsPage';
import { useAppStore } from './store/appStore';
import { api } from './api/client';
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

function ChatRoute() {
  const navigate = useNavigate();
  const { data: sessions } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.listSessions(),
  });

  const { sessionId } = useParams();
  const activeId = sessionId || sessions?.sessions[0]?.id;

  useEffect(() => {
    if (!sessionId && sessions?.sessions[0]) {
      navigate(`/chat/${sessions.sessions[0].id}`, { replace: true });
    }
  }, [sessionId, sessions, navigate]);

  const handleNew = async () => {
    const s = await api.createSession('Security Assessment');
    navigate(`/chat/${s.id}`);
  };

  if (!activeId) {
    return (
      <div className="text-center py-20">
        <p className="text-dim mb-4">No active session.</p>
        <NeonButton onClick={handleNew}>Start New Session</NeonButton>
      </div>
    );
  }

  return <ChatPage sessionId={activeId} />;
}

export default function App() {
  const { provider, model, loadConfig } = useAppStore();

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  return (
    <div className="min-h-screen bg-grid flex flex-col">
      <header className="border-b border-border px-4 py-3">
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
        <main className="flex-1 p-4 overflow-y-auto">
          <Routes>
            <Route path="/" element={<ChatRoute />} />
            <Route path="/chat/:sessionId" element={<ChatRoute />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/tools" element={<ToolsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
      <footer className="border-t border-border px-4 py-2 text-xs text-dim flex justify-end">
        <span className="text-primary">╰</span>
        <span className="mx-2 text-secondary">
          Provider: {provider} | Model: {model}
        </span>
        <span className="text-primary">╯</span>
      </footer>
    </div>
  );
}
