import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';
import { SeverityBadge } from '../components/SeverityBadge';

export function FindingsPage() {
  const { data } = useQuery({
    queryKey: ['findings'],
    queryFn: () => api.listFindings(),
  });

  const findings = data?.findings || [];
  const grouped = findings.reduce<Record<string, typeof findings>>((acc, f) => {
    const key = f.severity || 'info';
    if (!acc[key]) acc[key] = [];
    acc[key].push(f);
    return acc;
  }, {});

  const order = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <TerminalPanel title="SECURITY FINDINGS">
      {order.map((sev) => {
        const items = grouped[sev];
        if (!items?.length) return null;
        return (
          <div key={sev} className="mb-6">
            <h3 className="text-sm uppercase mb-3 flex items-center gap-2">
              <SeverityBadge severity={sev} /> ({items.length})
            </h3>
            <div className="space-y-2">
              {items.map((f) => (
                <div key={f.id} className="border border-border rounded p-3 text-sm">
                  <div className="flex justify-between">
                    <strong>{f.title}</strong>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <p className="text-dim text-xs mt-1">
                    Asset: {f.asset_name} ({f.asset_value}) · Confidence: {((f.confidence || 0) * 100).toFixed(0)}%
                  </p>
                  {f.description && (
                    <p className="text-xs text-secondary mt-1 whitespace-pre-wrap">{f.description}</p>
                  )}
                  {f.evidence_path && <p className="text-xs text-secondary mt-1">Evidence: {f.evidence_path}</p>}
                  {f.recommended_fix && <p className="text-xs text-primary mt-1">Fix: {f.recommended_fix}</p>}
                </div>
              ))}
            </div>
          </div>
        );
      })}
      {(!data?.findings || data.findings.length === 0) && (
        <p className="text-dim text-sm">No findings recorded yet. Run a scan to discover vulnerabilities.</p>
      )}
    </TerminalPanel>
  );
}
