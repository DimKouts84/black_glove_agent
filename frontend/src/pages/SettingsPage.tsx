import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, ConfigField } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';
import { NeonButton } from '../components/NeonButton';
import { useAppStore } from '../store/appStore';

export function SettingsPage() {
  const qc = useQueryClient();
  const loadStatus = useAppStore((s) => s.loadConfig);
  const { data: config } = useQuery({ queryKey: ['config'], queryFn: () => api.getConfig() });
  const { data: schemaData } = useQuery({ queryKey: ['config-schema'], queryFn: () => api.getConfigSchema() });
  const [form, setForm] = useState<Record<string, unknown>>({});
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (config) setForm(config);
  }, [config]);

  const fields = schemaData?.fields || [];

  const mutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.patchConfig(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] });
      loadStatus();
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    },
  });

  const buildSavePayload = (): Record<string, unknown> => {
    const payload = { ...form };
    if (!config) return payload;
    for (const field of fields) {
      if (!field.secret) continue;
      const formVal = form[field.name];
      const loadedVal = config[field.name];
      if (formVal === loadedVal) {
        delete payload[field.name];
      }
    }
    return payload;
  };

  const handleSave = () => mutation.mutate(buildSavePayload());

  const update = (name: string, value: unknown) => {
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  return (
    <TerminalPanel title="CONFIGURATION // ALL SETTINGS">
      <div className="space-y-6 max-w-2xl">
        {fields.map((field: ConfigField) => (
          <ConfigFieldInput
            key={field.name}
            field={field}
            value={form[field.name]}
            onChange={(v) => update(field.name, v)}
          />
        ))}
        <div className="flex gap-3 items-center">
          <NeonButton onClick={handleSave} disabled={mutation.isPending}>
            {mutation.isPending ? 'Saving...' : 'Save Configuration'}
          </NeonButton>
          {saved && <span className="text-green-400 text-sm">✓ Saved</span>}
          {mutation.isError && (
            <span className="text-glove text-sm">
              Save failed: {mutation.error instanceof Error ? mutation.error.message : 'Unknown error'}
            </span>
          )}
        </div>
      </div>
    </TerminalPanel>
  );
}

function ConfigFieldInput({
  field, value, onChange,
}: {
  field: ConfigField;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const label = (
    <label className="block text-xs text-primary mb-1">
      {field.name}
      {field.secret && <span className="text-accent ml-1">[secret]</span>}
    </label>
  );

  if (field.type.includes('bool')) {
    return (
      <div>
        {label}
        <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} className="accent-primary" />
        <p className="text-dim text-xs mt-1">{field.description}</p>
      </div>
    );
  }

  if (field.secret) {
    return (
      <div>
        {label}
        <input
          type="password"
          className="w-full bg-panel border border-border rounded px-3 py-2 text-sm font-mono"
          value={String(value || '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Leave unchanged to keep existing key"
        />
        <p className="text-dim text-xs mt-1">{field.description}</p>
      </div>
    );
  }

  if (field.type.includes('float') || field.name === 'llm_temperature') {
    return (
      <div>
        {label}
        <input
          type="range" min="0" max="1" step="0.1"
          value={Number(value) || 0}
          onChange={(e) => onChange(parseFloat(e.target.value))}
          className="w-full accent-primary"
        />
        <span className="text-xs text-dim">{String(value)}</span>
        <p className="text-dim text-xs mt-1">{field.description}</p>
      </div>
    );
  }

  return (
    <div>
      {label}
      <input
        className="w-full bg-panel border border-border rounded px-3 py-2 text-sm font-mono"
        value={String(value ?? '')}
        onChange={(e) => {
          const v = e.target.value;
          if (field.type.includes('int')) onChange(parseInt(v, 10) || 0);
          else onChange(v);
        }}
      />
      <p className="text-dim text-xs mt-1">{field.description}</p>
    </div>
  );
}
