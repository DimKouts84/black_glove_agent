import { create } from 'zustand';
import { api } from '../api/client';

interface AppState {
  provider: string;
  model: string;
  setStatus: (provider: string, model: string) => void;
  loadConfig: () => Promise<void>;
}

export const useAppStore = create<AppState>((set) => ({
  provider: 'Unknown',
  model: 'Unknown',
  setStatus: (provider, model) => set({ provider, model }),
  loadConfig: async () => {
    const cfg = await api.getConfig();
    set({
      provider: String(cfg.llm_provider || 'Unknown'),
      model: String(cfg.llm_model || 'Unknown'),
    });
  },
}));
