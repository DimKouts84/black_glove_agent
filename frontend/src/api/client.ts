const API_BASE = '';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

export const api = {
  health: () => request<{ status: string }>('/api/health'),
  getConfig: () => request<Record<string, unknown>>('/api/config'),
  getConfigSchema: () => request<{ fields: ConfigField[] }>('/api/config/schema'),
  patchConfig: (data: Record<string, unknown>) =>
    request<Record<string, unknown>>('/api/config', { method: 'PATCH', body: JSON.stringify(data) }),
  listSessions: () => request<{ sessions: Session[] }>('/api/sessions'),
  createSession: (title?: string) =>
    request<Session>('/api/sessions', { method: 'POST', body: JSON.stringify({ title }) }),
  getSession: (id: string) => request<Session>(`/api/sessions/${id}`),
  deleteSession: (id: string) => request(`/api/sessions/${id}`, { method: 'DELETE' }),
  getMessages: (id: string) => request<{ messages: Message[] }>(`/api/sessions/${id}/messages`),
  getTrace: (id: string) => request<{ runs: RunTrace[] }>(`/api/sessions/${id}/trace`),
  listFindings: (assetId?: number) =>
    request<{ findings: Finding[] }>(`/api/findings${assetId ? `?asset_id=${assetId}` : ''}`),
  listAssets: () => request<{ assets: Asset[] }>('/api/assets'),
  createAsset: (data: { name: string; type: string; value: string }) =>
    request('/api/assets', { method: 'POST', body: JSON.stringify(data) }),
  deleteAsset: (id: number) => request(`/api/assets/${id}`, { method: 'DELETE' }),
  generateReport: (format: string) =>
    request<{ content: string }>('/api/reports', { method: 'POST', body: JSON.stringify({ format }) }),
  listTools: () => request<{ tools: Tool[]; agents: string[] }>('/api/tools'),
};

export interface ConfigField {
  name: string;
  type: string;
  default: unknown;
  description: string;
  required: boolean;
  secret: boolean;
}

export interface Session {
  id: string;
  title: string;
  created_at: string;
  last_active: string;
}

export interface Message {
  id: number;
  role: string;
  content: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface RunTrace {
  id: string;
  query: string;
  status: string;
  started_at: string;
  finished_at?: string;
  final_answer?: string;
  events: TraceEvent[];
}

export interface TraceEvent {
  id: number;
  agent: string;
  type: string;
  content: string;
  params?: Record<string, unknown>;
  ts: string;
  tool?: string;
  status?: string;
  evidence_paths?: string[];
  warnings?: string[];
  coverage?: Record<string, unknown>;
  result_digest?: string;
  error?: string;
  report_path?: string;
}

export interface Finding {
  id: number;
  asset_id: number;
  title: string;
  severity: string;
  confidence: number;
  evidence_path?: string;
  recommended_fix?: string;
  description?: string;
  created_at: string;
  asset_name: string;
  asset_value: string;
}

export interface Asset {
  id: number;
  name: string;
  type: string;
  value: string;
}

export interface Tool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  category: string;
  safe_mode: boolean;
}
