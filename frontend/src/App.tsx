import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { LogExplorer } from './pages/LogExplorer';
import { AlertsView } from './pages/AlertsView';
import { InvestigationView } from './pages/InvestigationView';
import { ScenariosView } from './pages/ScenariosView';
import { SettingsView } from './pages/SettingsView';
import { apiClient } from './api/client';
import { Alert } from './types';
import { Shield, GitBranch, Cpu, Lock } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [mockMode, setMockMode] = useState<boolean>(true);
  const [investigationContext, setInvestigationContext] = useState<{
    investigation_id?: string;
    alert_id?: string;
    title?: string;
  }>({});

  const refreshSettings = async () => {
    try {
      const data = await apiClient.getSettings();
      setMockMode(data.mock_mode);
    } catch (e) {
      console.warn('Backend server may not be running yet:', e);
    }
  };

  useEffect(() => {
    refreshSettings();
  }, []);

  const handleNavigate = (tab: string, context?: any) => {
    if (context) {
      setInvestigationContext(context);
    }
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleStartAlertInvestigation = (alert: Alert) => {
    setInvestigationContext({
      alert_id: alert.alert_id,
      title: `Investigation: ${alert.title}`
    });
    setActiveTab('investigation');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#0c0e14] text-zinc-100 flex flex-col selection:bg-lime-400 selection:text-black">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => handleNavigate(tab)}
        mockMode={mockMode}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <Dashboard onNavigate={handleNavigate} />
        )}

        {activeTab === 'logs' && (
          <LogExplorer />
        )}

        {activeTab === 'alerts' && (
          <AlertsView onStartInvestigation={handleStartAlertInvestigation} />
        )}

        {activeTab === 'investigation' && (
          <InvestigationView
            initialInvestigationId={investigationContext.investigation_id}
            initialAlertId={investigationContext.alert_id}
            initialTitle={investigationContext.title}
          />
        )}

        {activeTab === 'scenarios' && (
          <ScenariosView onNavigate={handleNavigate} />
        )}

        {activeTab === 'settings' && (
          <SettingsView onSettingsUpdated={refreshSettings} />
        )}
      </main>

      {/* Retro Neubrutalist Footer */}
      <footer className="bg-black border-t-4 border-black py-6 mt-12 font-mono text-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <div className="w-6 h-6 bg-lime-400 border border-black flex items-center justify-center text-black font-black">
              S
            </div>
            <span className="font-bold tracking-wider text-white">
              SENTINEL AI <span className="text-zinc-500">| AUTONOMOUS SOC THREAT INVESTIGATION PLATFORM</span>
            </span>
          </div>

          <div className="flex items-center space-x-4 text-zinc-400 text-[11px]">
            <span className="flex items-center">
              <GitBranch className="w-3.5 h-3.5 mr-1 text-cyan-400" />
              LangGraph Multi-Agent Engine
            </span>
            <span className="flex items-center">
              <Cpu className="w-3.5 h-3.5 mr-1 text-purple-400" />
              Scikit-learn Isolation Forest
            </span>
            <span className="flex items-center">
              <Lock className="w-3.5 h-3.5 mr-1 text-lime-400" />
              MITRE ATT&CK Enterprise
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
