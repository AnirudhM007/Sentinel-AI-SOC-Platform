import React from 'react';
import { Shield, Terminal, AlertTriangle, FileText, Settings, PlayCircle, Activity } from 'lucide-react';
import { BrutalBadge } from './BrutalBadge';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  mockMode: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, mockMode }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <Activity className="w-4 h-4" /> },
    { id: 'logs', label: 'Log Explorer', icon: <Terminal className="w-4 h-4" /> },
    { id: 'alerts', label: 'Alerts & ML', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'investigation', label: 'LangGraph Agents', icon: <Shield className="w-4 h-4" /> },
    { id: 'scenarios', label: 'Scenarios & Upload', icon: <PlayCircle className="w-4 h-4" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <header className="sticky top-0 z-50 bg-zinc-950 border-b-4 border-black shadow-[0_4px_0_0_#000000]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-10 h-10 bg-lime-400 border-2 border-black flex items-center justify-center shadow-[3px_3px_0px_0px_#000000] rotate-[-2deg]">
              <Shield className="w-6 h-6 text-black stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xl font-black tracking-wider text-white">
                  SENTINEL<span className="text-lime-400">.AI</span>
                </span>
                <span className="bg-cyan-400 text-black px-1.5 py-0.2 text-[10px] font-mono font-black border border-black shadow-[1px_1px_0px_0px_#000000]">
                  v1.0 SOC
                </span>
              </div>
              <p className="text-[10px] font-mono text-zinc-400 tracking-tight hidden sm:block">
                AUTONOMOUS THREAT INVESTIGATION PLATFORM
              </p>
            </div>
          </div>

          {/* Navigation links */}
          <nav className="hidden md:flex items-center space-x-2">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`
                    flex items-center space-x-2 px-3 py-1.5 text-xs font-mono font-bold uppercase tracking-wider
                    border-2 border-black transition-all
                    ${
                      isActive
                        ? 'bg-lime-400 text-black shadow-[3px_3px_0px_0px_#000000] translate-x-[-1px] translate-y-[-1px]'
                        : 'bg-zinc-900 text-zinc-300 hover:bg-zinc-800 hover:text-white hover:border-black shadow-[2px_2px_0px_0px_#000000]'
                    }
                  `}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right status badges */}
          <div className="flex items-center space-x-3">
            <BrutalBadge
              color={mockMode ? 'amber' : 'lime'}
              size="sm"
              className="hidden lg:inline-flex"
            >
              {mockMode ? '⚡ MOCK REASONING ENGINE' : '🟢 LIVE OPENAI API'}
            </BrutalBadge>
            <div className="hidden sm:flex items-center space-x-1.5 px-2 py-1 bg-zinc-900 border border-black text-[11px] font-mono text-zinc-400">
              <span className="w-2 h-2 rounded-full bg-lime-400 animate-ping mr-1"></span>
              <span>ORCHESTRATION: LANGGRAPH</span>
            </div>
          </div>
        </div>

        {/* Mobile Navigation bar */}
        <div className="md:hidden flex overflow-x-auto py-2 space-x-2 border-t border-zinc-800 scrollbar-none">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`
                  flex items-center space-x-1.5 px-2.5 py-1 text-xs font-mono font-bold uppercase whitespace-nowrap
                  border-2 border-black
                  ${
                    isActive
                      ? 'bg-lime-400 text-black shadow-[2px_2px_0px_0px_#000000]'
                      : 'bg-zinc-900 text-zinc-300'
                  }
                `}
              >
                {item.icon}
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
