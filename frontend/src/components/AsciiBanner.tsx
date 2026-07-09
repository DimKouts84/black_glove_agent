const BANNER_BLACK = `██████╗ ██╗      █████╗  ██████╗██╗  ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
██████╔╝██║     ███████║██║     █████╔╝ 
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ 
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝`;

const BANNER_GLOVE = ` ██████╗  ██╗      ██████╗ ██╗   ██╗███████╗
██╔════╝ ██║     ██╔═══██╗██║   ██║██╔════╝
██║  ███╗██║     ██║   ██║██║   ██║█████╗  
██║   ██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  
╚██████╔╝███████╗╚██████╔╝ ╚████╔╝ ███████╗
 ╚═════╝ ╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝`;

interface Props {
  compact?: boolean;
}

export function AsciiBanner({ compact }: Props) {
  const blackLines = BANNER_BLACK.split('\n');
  const gloveLines = BANNER_GLOVE.split('\n');
  const scale = compact ? 'text-[6px] sm:text-[8px]' : 'text-[8px] sm:text-xs';

  return (
    <pre className={`${scale} leading-tight font-mono text-center boot-animate`}>
      {blackLines.map((b, i) => (
        <div key={i}>
          <span className="text-gray-500 font-bold">{b}</span>
          <span className="text-glove font-bold">{gloveLines[i] || ''}</span>
        </div>
      ))}
    </pre>
  );
}
