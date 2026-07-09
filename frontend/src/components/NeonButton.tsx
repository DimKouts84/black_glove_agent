import { ButtonHTMLAttributes } from 'react';

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'danger' | 'ghost';
}

export function NeonButton({ variant = 'primary', className = '', children, ...props }: Props) {
  const colors = {
    primary: 'border-primary text-primary hover:shadow-neon hover:bg-primary/10',
    danger: 'border-glove text-glove hover:bg-glove/10',
    ghost: 'border-border text-dim hover:border-primary hover:text-primary',
  };
  return (
    <button
      className={`px-4 py-2 border rounded font-mono text-sm transition-all ${colors[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
