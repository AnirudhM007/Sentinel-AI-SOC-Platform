import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md';
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'sm',
  className = '',
}) => {
  const sev = (severity || 'INFORMATIONAL').toUpperCase();

  const getStyle = () => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500 text-white border-black shadow-[2px_2px_0px_0px_#000000] animate-pulse';
      case 'HIGH':
        return 'bg-orange-400 text-black border-black shadow-[2px_2px_0px_0px_#000000]';
      case 'MEDIUM':
        return 'bg-amber-300 text-black border-black shadow-[2px_2px_0px_0px_#000000]';
      case 'LOW':
        return 'bg-lime-400 text-black border-black shadow-[2px_2px_0px_0px_#000000]';
      case 'INFORMATIONAL':
      default:
        return 'bg-cyan-300 text-black border-black shadow-[2px_2px_0px_0px_#000000]';
    }
  };

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span
      className={`
        inline-flex items-center font-mono font-black uppercase tracking-wider
        border-2 ${getStyle()} ${sizeClass} ${className}
      `}
    >
      {sev}
    </span>
  );
};
