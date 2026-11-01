import React from 'react';

interface StatBoxProps {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  accentColor?: 'lime' | 'cyan' | 'amber' | 'coral' | 'purple';
  subtext?: string;
}

export const StatBox: React.FC<StatBoxProps> = ({
  label,
  value,
  icon,
  accentColor = 'lime',
  subtext,
}) => {
  const getAccentBg = () => {
    switch (accentColor) {
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
      default:
        return 'bg-white text-black';
    }
  };

  return (
    <div className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] relative overflow-hidden group hover:translate-x-[-1px] hover:translate-y-[-1px] transition-all">
      <div className="flex items-center justify-between mb-2">
        <span className="font-mono text-xs uppercase font-bold text-zinc-400 tracking-wider">
          {label}
        </span>
        {icon && (
          <div className={`p-1.5 border border-black ${getAccentBg()} shadow-[2px_2px_0px_0px_#000000]`}>
            {icon}
          </div>
        )}
      </div>
      <div className="text-3xl font-black font-mono tracking-tight text-white">
        {value}
      </div>
      {subtext && (
        <div className="mt-2 text-xs font-mono text-zinc-400 flex items-center space-x-1">
          <span className="inline-block w-1.5 h-1.5 bg-lime-400 mr-1"></span>
          <span>{subtext}</span>
        </div>
      )}
    </div>
  );
};
