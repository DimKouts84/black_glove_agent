import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';

export function ToolsPage() {
  const { data } = useQuery({
    queryKey: ['tools'],
    queryFn: () => api.listTools(),
  });

  return (
    <TerminalPanel title="AVAILABLE TOOLS // DYNAMIC">
      <p className="text-dim text-xs mb-4">
        Tools are discovered at runtime from adapters. Adding a new adapter requires no UI changes.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {data?.tools.map((tool) => (
          <div key={tool.name} className="border border-border rounded p-3 hover:border-primary/40 transition-colors">
            <div className="flex justify-between items-start">
              <span className="text-primary font-bold">{tool.name}</span>
              {tool.safe_mode && <span className="text-xs text-green-400">safe</span>}
            </div>
            <p className="text-xs text-dim mt-1">{tool.description}</p>
            <span className="text-xs text-accent mt-2 inline-block">{tool.category}</span>
          </div>
        ))}
      </div>
      {data?.agents && (
        <div className="mt-6">
          <h3 className="text-sm text-accent mb-2">Sub-Agents</h3>
          <div className="flex gap-2 flex-wrap">
            {data.agents.map((a) => (
              <span key={a} className="border border-secondary/50 text-secondary px-2 py-1 rounded text-xs">{a}</span>
            ))}
          </div>
        </div>
      )}
    </TerminalPanel>
  );
}
