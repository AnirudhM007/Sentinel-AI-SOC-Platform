import React from 'react';

interface BrutalBadgeProps {
  children: React.ReactNode;
  color?: 'lime' | 'cyan' | 'amber' | 'coral' | 'purple' | 'slate' | 'white';
  className?: string;
  size?: 'sm' | 'md';
}

export const BrutalBadge: React.FC<BrutalBadgeProps> = ({
  children,
  color = 'lime',
  className = '',
  size = 'sm',
}) => {
  const getColorStyles = () => {
    switch (color) {
      case 'lime':
        return 'bg-lime-400 text-black border-black';
      case 'cyan':
        return 'bg-cyan-400 text-black border-black';
      case 'amber':
        return 'bg-amber-400 text-black border-black';
      case 'coral':
        return 'bg-red-400 text-black border-black';
      case 'purple':
        return 'bg-purple-400 text-black border-black';
      case 'white':
        return 'bg-white text-black border-black';
      case 'slate':
      default:
        return 'bg-zinc-800 text-zinc-200 border-black';
    }
  };

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span
      className={`
        inline-flex items-center font-mono font-bold uppercase tracking-wider
        border-2 shadow-[2px_2px_0px_0px_#000000]
        ${getColorStyles()}
        ${sizeClass}
        ${className}
      `}
    >
      {children}
    </span>
  );
};
