import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';
import { NeonButton } from '../components/NeonButton';

export function AssetsPage() {
  const { data, refetch } = useQuery({
    queryKey: ['assets'],
    queryFn: () => api.listAssets(),
  });
  const [name, setName] = useState('');
  const [type, setType] = useState('host');
  const [value, setValue] = useState('');

  const handleAdd = async () => {
    if (!name || !value) return;
    await api.createAsset({ name, type, value });
    setName(''); setValue('');
    refetch();
  };

  const handleDelete = async (id: number) => {
    await api.deleteAsset(id);
    refetch();
  };

  return (
    <TerminalPanel title="TARGET ASSETS">
      <div className="grid grid-cols-1 md:grid-cols-4 gap--2 mb-4">
        <input className="bg-panel border border-border rounded px-3 py-2 text-sm" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <select className="bg-panel border border-border rounded px-3 py-2 text-sm" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="host">host</option>
          <option value="domain">domain</option>
          <option value="vm">vm</option>
        </select>
        <input className="bg-panel border border-border rounded px-3 py-2 text-sm" placeholder="IP / domain" value={value} onChange={(e) => setValue(e.target.value)} />
        <NeonButton onClick={handleAdd}>Add Asset</NeonButton>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-dim text-left border-b border-border">
            <th className="py-2">Name</th><th>Type</th><th>Value</th><th></th>
          </tr>
        </thead>
        <tbody>
          {data?.assets.map((a) => (
            <tr key={a.id} className="border-b border-border/50">
              <td className="py-2 text-primary">{a.name}</td>
              <td>{a.type}</td>
              <td>{a.value}</td>
              <td><NeonButton variant="ghost" className="text-xs py-1" onClick={() => handleDelete(a.id)}>Remove</NeonButton></td>
            </tr>
          ))}
        </tbody>
      </table>
    </TerminalPanel>
  );
}
