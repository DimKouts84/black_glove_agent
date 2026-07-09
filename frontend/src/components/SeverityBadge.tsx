interface Props {
  severity: string;
}

export function SeverityBadge({ severity }: Props) {
  const s = severity.toLowerCase();
  return (
    <span className={`severity-${s} border px-2 py-0.5 rounded text-xs uppercase font-bold`}>
      {severity}
    </span>
  );
}
