import { NeonButton } from './NeonButton';
import { TerminalPanel } from './TerminalPanel';

interface Props {
  tool?: string;
  content?: string;
  onApprove: () => void;
  onReject: () => void;
}

export function ApprovalModal({ tool, content, onApprove, onReject }: Props) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <TerminalPanel title="APPROVAL REQUIRED" className="max-w-md w-full">
        <p className="text-sm mb-2">{content}</p>
        {tool && <p className="text-accent text-sm mb-4">Tool: <strong>{tool}</strong></p>}
        <div className="flex gap-3 justify-end">
          <NeonButton variant="danger" onClick={onReject}>Reject</NeonButton>
          <NeonButton onClick={onApprove}>Approve</NeonButton>
        </div>
      </TerminalPanel>
    </div>
  );
}
