import { useEffect, useState, type FC } from 'react';
import { apiClient } from '../api/client';
import { DashboardSummary } from '../types';
import { StatBox } from '../components/StatBox';
import { BrutalCard } from '../components/BrutalCard';
import { BrutalButton } from '../components/BrutalButton';
import { SeverityBadge } from '../components/SeverityBadge';
import { BrutalBadge } from '../components/BrutalBadge';
import {
  ShieldAlert,
  Flame,
  BrainCircuit,
  Radio,
  Clock,
  ArrowRight,
  Server,
  Play,
  RotateCw
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';

interface DashboardProps {
  onNavigate: (tab: string, context?: any) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#84cc16',
  INFORMATIONAL: '#06b6d4',
};

export const Dashboard: FC<DashboardProps> = ({ onNavigate }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [scenarioLoading, setScenarioLoading] = useState<string | null>(null);

  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  const fetchSummary = async () => {
    try {
      setLoading(true);
      const data = await apiClient.getDashboardSummary();
      setSummary(data);
    } catch (err: any) {
      console.error('Failed to load dashboard summary:', err);
      setNotification({
        type: 'error',
        message: 'Could not connect to backend server. Make sure the backend is running on port 8008!'
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  const handleQuickLoad = async (scenarioId: string) => {
    try {
      setScenarioLoading(scenarioId);
      setNotification({ type: 'info', message: `Injecting scenario "${scenarioId}" into detection engine...` });
      const res = await apiClient.loadScenario(scenarioId);
      await fetchSummary();
      setNotification({
        type: 'success',
        message: `Scenario Loaded Successfully! ${res.result?.events_ingested || 0} events ingested, ${res.result?.alerts_generated || 0} alerts generated.`
      });
      setTimeout(() => {
        onNavigate('alerts');
      }, 700);
    } catch (err: any) {
      console.error('Failed to quick-load scenario:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Failed to load scenario';
      setNotification({
        type: 'error',
        message: `Error injecting scenario: ${errMsg}. Check that backend is running on port 8008.`
      });
    } finally {
      setScenarioLoading(null);
    }
  };

  const pieData = summary
    ? Object.entries(summary.severity_distribution || {})
        .filter(([_, count]) => count > 0)
        .map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="space-y-6">
      {/* Toast Notification Banner */}
      {notification && (
        <div
          className={`border-2 border-black p-3.5 shadow-[4px_4px_0px_0px_#000000] font-mono text-xs font-bold flex items-center justify-between ${
            notification.type === 'error'
              ? 'bg-red-500 text-white'
              : notification.type === 'success'
              ? 'bg-lime-400 text-black'
              : 'bg-cyan-400 text-black'
          }`}
        >
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-black inline-block"></span>
            <span>{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="ml-4 px-2 py-0.5 border border-black bg-black text-white text-[10px] uppercase hover:bg-zinc-800"
          >
            DISMISS
          </button>
        </div>
      )}

      {/* Top Banner / Hero Neubrutalist Card */}
      <div className="bg-lime-400 border-2 border-black p-5 shadow-[5px_5px_0px_0px_#000000] text-black">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="bg-black text-lime-400 font-mono text-xs font-bold px-2 py-0.5 border border-black shadow-[1px_1px_0px_0px_#ffffff]">
                SOC INTELLIGENCE CORE
              </span>
              <span className="font-mono text-xs font-bold text-zinc-900 uppercase">
                ACTIVE MONITORING ONLINE
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black font-mono tracking-tight mt-1 text-black">
              SENTINEL AI OPERATIONS COMMAND
            </h1>
            <p className="text-sm font-bold text-zinc-800 mt-1 max-w-2xl">
              Autonomous multi-agent orchestration investigating real security logs using LangGraph state machines, deterministic rules, and Isolation Forest ML.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <BrutalButton
              variant="white"
              size="sm"
              icon={<RotateCw className="w-3.5 h-3.5" />}
              onClick={fetchSummary}
              loading={loading}
            >
              Refresh Telemetry
            </BrutalButton>
            <BrutalButton
              variant="slate"
              size="sm"
              icon={<Play className="w-3.5 h-3.5 text-lime-400" />}
              onClick={() => handleQuickLoad('scenario_1')}
              loading={scenarioLoading === 'scenario_1'}
            >
              Run SSH Brute Force Demo
            </BrutalButton>
          </div>
        </div>
      </div>

      {/* Primary KPI Metric Boxes */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        <StatBox
          label="Total Events"
          value={(summary?.total_events ?? 0).toLocaleString()}
          accentColor="cyan"
          icon={<Radio className="w-4 h-4" />}
          subtext="Telemetry ingested"
        />
        <StatBox
          label="Active Alerts"
          value={String(summary?.total_alerts ?? 0)}
          accentColor="amber"
          icon={<ShieldAlert className="w-4 h-4" />}
          subtext="Rule detections"
        />
        <StatBox
          label="Critical Cases"
          value={String(summary?.critical_incidents ?? 0)}
          accentColor="coral"
          icon={<Flame className="w-4 h-4" />}
          subtext="Breach probability"
        />
        <StatBox
          label="High Priority"
          value={String(summary?.high_incidents ?? 0)}
          accentColor="amber"
          icon={<ShieldAlert className="w-4 h-4" />}
          subtext="Adversarial activity"
        />
        <StatBox
          label="ML Anomalies"
          value={String(summary?.anomaly_count ?? 0)}
          accentColor="purple"
          icon={<BrainCircuit className="w-4 h-4" />}
          subtext="Isolation Forest"
        />
        <StatBox
          label="Investigations"
          value={String(summary?.total_investigations ?? 0)}
          accentColor="lime"
          icon={<Clock className="w-4 h-4" />}
          subtext="LangGraph runs"
        />
      </div>

      {/* Quick Scenarios Row */}
      <BrutalCard
        headerTitle="PRE-BUILT ATTACK & BENIGN SCENARIOS (1-CLICK EXECUTION)"
        headerColor="slate"
        headerBadge="READY TO RUN"
      >
        <p className="text-xs text-zinc-400 mb-4 font-mono">
          Click any scenario to inject synthetic security logs, trigger the deterministic detection engine, fit ML anomaly boundaries, and prepare events for LangGraph agent investigation:
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
          {[
            { id: 'scenario_1', name: '1. SSH Brute Force', desc: 'Failed SSH bursts + interactive session', tag: 'High Risk' },
            { id: 'scenario_2', name: '2. Windows 4625 Auth', desc: 'Failed logon sequence + 4672 tokens', tag: 'Privilege' },
            { id: 'scenario_3', name: '3. Priv Escalation', desc: 'Sudo curl stage2 + useradd backdoor', tag: 'Persistence' },
            { id: 'scenario_4', name: '4. C2 Outbound Beacon', desc: 'Outbound traffic to malicious IP', tag: 'C2 Network' },
            { id: 'scenario_5', name: '5. Benign Baseline', desc: 'Normal routine user operations', tag: 'Baseline' },
            { id: 'scenario_6', name: '6. C2 PCAP Capture', desc: 'Binary PCAP with DNS exfil & port 4444', tag: 'PCAP DPI' }
          ].map((sc) => (
            <div
              key={sc.id}
              className="bg-black border-2 border-black p-3 hover:border-lime-400 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-xs font-bold text-white">{sc.name}</span>
                  <BrutalBadge color="lime" size="sm">{sc.tag}</BrutalBadge>
                </div>
                <p className="text-[11px] text-zinc-400 font-mono mb-3">{sc.desc}</p>
              </div>
              <BrutalButton
                size="sm"
                variant="white"
                onClick={() => handleQuickLoad(sc.id)}
                loading={scenarioLoading === sc.id}
                className="w-full text-[11px]"
              >
                Inject & Test
              </BrutalButton>
            </div>
          ))}
        </div>
      </BrutalCard>

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Timeline Bar Chart */}
        <div className="lg:col-span-2">
          <BrutalCard
            headerTitle="TELEMETRY ACTIVITY TIMELINE"
            headerColor="cyan"
            headerBadge="EVENTS OVER TIME"
          >
            <div className="h-64 w-full">
              {summary?.event_activity_chart && summary.event_activity_chart.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={summary.event_activity_chart}>
                    <XAxis
                      dataKey="time"
                      stroke="#71717a"
                      fontSize={11}
                      tickLine={false}
                      fontFamily="JetBrains Mono"
                    />
                    <YAxis
                      stroke="#71717a"
                      fontSize={11}
                      tickLine={false}
                      fontFamily="JetBrains Mono"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#000000',
                        border: '2px solid #bef264',
                        fontFamily: 'JetBrains Mono',
                        fontSize: '12px'
                      }}
                    />
                    <Bar dataKey="auth_failures" name="Auth Failures" fill="#ef4444" radius={[2, 2, 0, 0]} />
                    <Bar dataKey="normal" name="Normal Telemetry" fill="#67e8f9" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center font-mono text-xs text-zinc-500">
                  NO TIMELINE DATA AVAILABLE. LOAD A SCENARIO ABOVE.
                </div>
              )}
            </div>
          </BrutalCard>
        </div>

        {/* Severity Distribution Donut */}
        <div>
          <BrutalCard
            headerTitle="INCIDENT SEVERITY SPREAD"
            headerColor="amber"
            headerBadge="DISTRIBUTION"
          >
            <div className="h-64 w-full flex flex-col items-center justify-center">
              {pieData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height="75%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={3}
                      >
                        {pieData.map((entry) => (
                          <Cell
                            key={entry.name}
                            fill={SEVERITY_COLORS[entry.name] || '#71717a'}
                            stroke="#000000"
                            strokeWidth={2}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#000000',
                          border: '2px solid #fde047',
                          fontFamily: 'JetBrains Mono',
                          fontSize: '12px'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex flex-wrap justify-center gap-2 mt-2">
                    {pieData.map((d) => (
                      <span key={d.name} className="flex items-center text-[10px] font-mono text-zinc-300">
                        <span
                          className="w-2.5 h-2.5 border border-black inline-block mr-1"
                          style={{ backgroundColor: SEVERITY_COLORS[d.name] || '#71717a' }}
                        ></span>
                        {d.name}: {d.value}
                      </span>
                    ))}
                  </div>
                </>
              ) : (
                <div className="font-mono text-xs text-zinc-500">NO SEVERITY DATA AVAILABLE.</div>
              )}
            </div>
          </BrutalCard>
        </div>
      </div>

      {/* Two Column Section: Recent Alerts & Investigations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts */}
        <BrutalCard
          headerTitle="ACTIVE DETECTIONS & ANOMALIES"
          headerColor="coral"
          headerBadge="LIVE ALERTS"
          action={
            <button
              onClick={() => onNavigate('alerts')}
              className="text-xs font-mono font-bold hover:underline flex items-center space-x-1"
            >
              <span>View All</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          }
        >
          {summary?.recent_alerts && summary.recent_alerts.length > 0 ? (
            <div className="divide-y-2 divide-zinc-950 font-mono">
              {summary.recent_alerts.map((alt) => (
                <div key={alt.alert_id} className="py-2.5 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center space-x-2">
                      <SeverityBadge severity={alt.severity} size="sm" />
                      <span className="text-white font-bold text-xs truncate">{alt.title}</span>
                    </div>
                    <p className="text-[11px] text-zinc-400 truncate mt-0.5">
                      Type: {alt.detection_type} | Rule: {alt.rule_id}
                    </p>
                  </div>
                  <BrutalButton
                    size="sm"
                    variant="lime"
                    onClick={() => onNavigate('investigation', { alert_id: alt.alert_id, title: alt.title })}
                  >
                    Investigate
                  </BrutalButton>
                </div>
              ))}
            </div>
          ) : (
            <p className="font-mono text-xs text-zinc-500 py-4 text-center">No alerts recorded yet.</p>
          )}
        </BrutalCard>

        {/* Top Affected Hosts & Recent Investigations */}
        <div className="space-y-6">
          <BrutalCard
            headerTitle="TOP AFFECTED ASSETS"
            headerColor="purple"
            headerBadge="HOST ACTIVITY"
          >
            {summary?.top_affected_hosts && summary.top_affected_hosts.length > 0 ? (
              <div className="space-y-2 font-mono">
                {summary.top_affected_hosts.map((h, i) => (
                  <div key={h.hostname} className="flex items-center justify-between p-2 bg-black border border-zinc-800">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-lime-400">#{i + 1}</span>
                      <Server className="w-4 h-4 text-zinc-400" />
                      <span className="text-xs font-bold text-white">{h.hostname}</span>
                    </div>
                    <span className="text-xs font-bold text-zinc-300 bg-zinc-900 px-2 py-0.5 border border-zinc-700">
                      {h.event_count} events
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="font-mono text-xs text-zinc-500 py-4 text-center">No host activity registered.</p>
            )}
          </BrutalCard>

          <BrutalCard
            headerTitle="RECENT INVESTIGATION REPORTS"
            headerColor="slate"
            headerBadge="HISTORY"
            action={
              <button
                onClick={() => onNavigate('investigation')}
                className="text-xs font-mono font-bold hover:underline flex items-center space-x-1"
              >
                <span>Workspace</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            }
          >
            {summary?.recent_investigations && summary.recent_investigations.length > 0 ? (
              <div className="divide-y-2 divide-zinc-950 font-mono">
                {summary.recent_investigations.map((inv) => (
                  <div key={inv.investigation_id} className="py-2 flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={inv.severity} size="sm" />
                        <span className="text-xs font-bold text-white">{inv.investigation_id}</span>
                      </div>
                      <p className="text-[11px] text-zinc-400 truncate max-w-xs">{inv.title}</p>
                    </div>
                    <BrutalButton
                      size="sm"
                      variant="white"
                      onClick={() => onNavigate('investigation', { investigation_id: inv.investigation_id })}
                    >
                      Open Report
                    </BrutalButton>
                  </div>
                ))}
              </div>
            ) : (
              <p className="font-mono text-xs text-zinc-500 py-4 text-center">No investigations completed yet.</p>
            )}
          </BrutalCard>
        </div>
      </div>
    </div>
  );
};
