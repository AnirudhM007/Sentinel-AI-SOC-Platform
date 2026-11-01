import React from 'react';

interface BrutalButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'lime' | 'cyan' | 'amber' | 'coral' | 'purple' | 'slate' | 'white';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  icon?: React.ReactNode;
}

export const BrutalButton: React.FC<BrutalButtonProps> = ({
  children,
  variant = 'lime',
  size = 'md',
  loading = false,
  icon,
  className = '',
  disabled,
  ...props
}) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'lime':
        return 'bg-lime-400 text-black hover:bg-lime-300 active:bg-lime-500';
      case 'cyan':
        return 'bg-cyan-400 text-black hover:bg-cyan-300 active:bg-cyan-500';
      case 'amber':
        return 'bg-amber-400 text-black hover:bg-amber-300 active:bg-amber-500';
      case 'coral':
        return 'bg-red-400 text-black hover:bg-red-300 active:bg-red-500';
      case 'purple':
        return 'bg-purple-400 text-black hover:bg-purple-300 active:bg-purple-500';
      case 'white':
        return 'bg-white text-black hover:bg-zinc-100 active:bg-zinc-200';
      case 'slate':
      default:
        return 'bg-zinc-800 text-white hover:bg-zinc-700 active:bg-zinc-900';
    }
  };

  const getSizeStyles = () => {
    switch (size) {
      case 'sm':
        return 'px-3 py-1.5 text-xs';
      case 'lg':
        return 'px-6 py-3 text-base';
      case 'md':
      default:
        return 'px-4 py-2 text-sm';
    }
  };

  return (
    <button
      disabled={disabled || loading}
      className={`
        inline-flex items-center justify-center font-bold font-mono tracking-wide uppercase
        border-2 border-black shadow-[3px_3px_0px_0px_#000000]
        hover:translate-x-[-1px] hover:translate-y-[-1px] hover:shadow-[4px_4px_0px_0px_#000000]
        active:translate-x-[2px] active:translate-y-[2px] active:shadow-none
        disabled:opacity-50 disabled:pointer-events-none disabled:shadow-none
        transition-all duration-75 select-none
        ${getVariantStyles()}
        ${getSizeStyles()}
        ${className}
      `}
      {...props}
    >
      {loading ? (
        <span className="flex items-center space-x-2">
          <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-black" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span>PROCESSING...</span>
        </span>
      ) : (
        <span className="flex items-center space-x-2">
          {icon && <span className="flex-shrink-0">{icon}</span>}
          <span>{children}</span>
        </span>
      )}
    </button>
  );
};
