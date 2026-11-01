import React from 'react';

interface BrutalCardProps {
  children: React.ReactNode;
  className?: string;
  headerTitle?: string;
  headerBadge?: string;
  headerColor?: 'lime' | 'cyan' | 'amber' | 'coral' | 'purple' | 'slate' | 'default';
  action?: React.ReactNode;
}

export const BrutalCard: React.FC<BrutalCardProps> = ({
  children,
  className = '',
  headerTitle,
  headerBadge,
  headerColor = 'default',
  action,
}) => {
  const getHeaderBg = () => {
    switch (headerColor) {
      case 'lime':
        return 'bg-lime-400 text-black';
      case 'cyan':
        return 'bg-cyan-400 text-black';
      case 'amber':
        return 'bg-amber-400 text-black';
      case 'coral':
        return 'bg-red-400 text-black';
      case 'purple':
        return 'bg-purple-400 text-black';
      case 'slate':
        return 'bg-zinc-800 text-white';
      default:
        return 'bg-zinc-900 text-white';
    }
  };

  return (
    <div className={`bg-zinc-900 border-2 border-black shadow-[4px_4px_0px_0px_#000000] overflow-hidden ${className}`}>
      {headerTitle && (
        <div className={`px-4 py-2.5 border-b-2 border-black flex items-center justify-between font-bold ${getHeaderBg()}`}>
          <div className="flex items-center space-x-2">
            <span className="font-mono text-sm tracking-wider uppercase">{headerTitle}</span>
            {headerBadge && (
              <span className="px-2 py-0.5 text-xs font-mono font-black border border-black bg-white text-black shadow-[1px_1px_0px_0px_#000000]">
                {headerBadge}
              </span>
            )}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className="p-4 sm:p-5">{children}</div>
    </div>
  );
};
