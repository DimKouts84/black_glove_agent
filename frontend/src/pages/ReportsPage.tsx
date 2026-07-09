import { useState } from 'react';
import { api } from '../api/client';
import { TerminalPanel } from '../components/TerminalPanel';
import { NeonButton } from '../components/NeonButton';
import ReactMarkdown from 'react-markdown';

export function ReportsPage() {
  const [format, setFormat] = useState('markdown');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);

  const generate = async () => {
    setLoading(true);
    try {
      const result = await api.generateReport(format);
      setContent(result.content);
    } finally {
      setLoading(false);
    }
  };

  const download = () => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `black-glove-report.${format === 'json' ? 'json' : format === 'html' ? 'html' : 'md'}`;
    a.click();
  };

  return (
    <TerminalPanel title="REPORT GENERATOR">
      <div className="flex gap-3 mb-4 items-center">
        <select
          className="bg-panel border border-border rounded px-3 py-2 text-sm"
          value={format}
          onChange={(e) => setFormat(e.target.value)}
        >
          <option value="markdown">Markdown</option>
          <option value="json">JSON</option>
          <option value="html">HTML</option>
          <option value="csv">CSV</option>
        </select>
        <NeonButton onClick={generate} disabled={loading}>
          {loading ? 'Generating...' : 'Generate Report'}
        </NeonButton>
        {content && <NeonButton variant="ghost" onClick={download}>Download</NeonButton>}
      </div>
      {content && (
        <div className="border border-border rounded p-4 max-h-[60vh] overflow-y-auto prose prose-invert prose-sm max-w-none">
          {format === 'markdown' ? <ReactMarkdown>{content}</ReactMarkdown> : (
            <pre className="text-xs whitespace-pre-wrap">{content}</pre>
          )}
        </div>
      )}
    </TerminalPanel>
  );
}
