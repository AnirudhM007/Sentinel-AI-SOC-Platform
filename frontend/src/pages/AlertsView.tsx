import { useEffect, useState, type FC } from 'react';
import { apiClient } from '../api/client';
import { Alert } from '../types';
import { BrutalCard } from '../components/BrutalCard';
import { BrutalButton } from '../components/BrutalButton';
import { SeverityBadge } from '../components/SeverityBadge';
import { BrutalBadge } from '../components/BrutalBadge';
import { ShieldAlert, BrainCircuit, Play, ArrowRight, Info, CheckCircle2 } from 'lucide-react';

interface AlertsViewProps {
  onStartInvestigation: (alert: Alert) => void;
}

export const AlertsView: FC<AlertsViewProps> = ({ onStartInvestigation }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const data = await apiClient.getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const filteredAlerts = alerts.filter((a) => {
    if (filterType === 'RULE') return a.detection_type === 'RULE';
    if (filterType === 'ML') return a.detection_type === 'ML_ANOMALY';
    return true;
  });

  const ruleCount = alerts.filter((a) => a.detection_type === 'RULE').length;
  const mlCount = alerts.filter((a) => a.detection_type === 'ML_ANOMALY').length;

  return (
    <div className="space-y-6">
      {/* Category Toggle Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-zinc-950 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000]">
        <div>
          <h2 className="text-xl font-black font-mono tracking-tight text-white uppercase">
            DETECTIONS & ML ANOMALIES FEED
          </h2>
          <p className="text-xs font-mono text-zinc-400 mt-0.5">
            Deterministic heuristics separated from Isolation Forest statistical telemetry outliers.
          </p>
        </div>

        <div className="flex items-center space-x-2 font-mono text-xs">
          <button
            onClick={() => setFilterType('ALL')}
            className={`px-3 py-1.5 font-bold border-2 border-black transition-all ${
              filterType === 'ALL'
                ? 'bg-lime-400 text-black shadow-[2px_2px_0px_0px_#000000]'
                : 'bg-zinc-900 text-zinc-400 hover:text-white'
            }`}
          >
            ALL ({alerts.length})
          </button>
          <button
            onClick={() => setFilterType('RULE')}
            className={`px-3 py-1.5 font-bold border-2 border-black transition-all ${
              filterType === 'RULE'
                ? 'bg-amber-400 text-black shadow-[2px_2px_0px_0px_#000000]'
                : 'bg-zinc-900 text-zinc-400 hover:text-white'
            }`}
          >
            RULES ({ruleCount})
          </button>
          <button
            onClick={() => setFilterType('ML')}
            className={`px-3 py-1.5 font-bold border-2 border-black transition-all ${
              filterType === 'ML'
                ? 'bg-purple-400 text-black shadow-[2px_2px_0px_0px_#000000]'
                : 'bg-zinc-900 text-zinc-400 hover:text-white'
            }`}
          >
            ML ANOMALIES ({mlCount})
          </button>
        </div>
      </div>

      {/* Alerts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alerts List */}
        <div className="lg:col-span-2 space-y-3">
          {filteredAlerts.length > 0 ? (
            filteredAlerts.map((alt) => {
              const isML = alt.detection_type === 'ML_ANOMALY';
              return (
                <div
                  key={alt.alert_id}
                  className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] hover:translate-x-[-1px] hover:translate-y-[-1px] transition-all"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                      <SeverityBadge severity={alt.severity} size="sm" />
                      <BrutalBadge color={isML ? 'purple' : 'amber'} size="sm">
                        {isML ? 'ISOLATION FOREST' : alt.rule_id}
                      </BrutalBadge>
                      <span className="font-mono text-xs text-zinc-400">{alt.alert_id}</span>
                    </div>
                    <span className="font-mono text-[11px] text-zinc-500">
                      {alt.timestamp ? alt.timestamp.slice(0, 19).replace('T', ' ') : ''}
                    </span>
                  </div>

                  <h3 className="font-mono text-sm font-black text-white mb-1.5">{alt.title}</h3>
                  <p className="font-mono text-xs text-zinc-300 leading-relaxed mb-3">
                    {alt.description}
                  </p>

                  {/* ML Contributing Dimensions Pill if ML */}
                  {isML && Array.isArray(alt.relevant_fields?.top_contributing_features) && alt.relevant_fields.top_contributing_features.length > 0 && (
                    <div className="mb-3 bg-black p-2 border border-zinc-800">
                      <span className="text-[10px] font-mono text-purple-400 font-bold uppercase block mb-1">
                        Top Anomaly Dimensions (Z-Score Deviation):
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {alt.relevant_fields.top_contributing_features.map((feat: any, idx: number) => (
                          <span
                            key={idx}
                            className="bg-zinc-900 text-zinc-200 border border-zinc-700 px-1.5 py-0.5 text-[10px] font-mono"
                          >
                            {feat.feature}: {feat.observed_value} (z: +{feat.deviation_z_score})
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-2 border-t border-zinc-800 font-mono text-xs">
                    <div className="text-zinc-500 text-[11px]">
                      Confidence: <span className="text-white font-bold">{Math.round(alt.confidence * 100)}%</span> |
                      Events: <span className="text-lime-400 font-bold">{alt.triggering_event_ids?.length || 1}</span>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => setSelectedAlert(alt)}
                        className="px-2.5 py-1 text-zinc-300 hover:text-white underline font-bold"
                      >
                        Inspect
                      </button>
                      <BrutalButton
                        size="sm"
                        variant="lime"
                        icon={<Play className="w-3.5 h-3.5" />}
                        onClick={() => onStartInvestigation(alt)}
                      >
                        Investigate
                      </BrutalButton>
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="bg-zinc-900 border-2 border-black p-8 text-center font-mono text-zinc-500 shadow-[4px_4px_0px_0px_#000000]">
              NO ALERTS RECORDED. RUN A SCENARIO FROM THE DASHBOARD OR SCENARIOS TAB.
            </div>
          )}
        </div>

        {/* Info & Side Panel */}
        <div className="space-y-6">
          <BrutalCard
            headerTitle="SOC ARCHITECTURE CONCEPTS"
            headerColor="slate"
            headerBadge="EXPLAINER"
          >
            <div className="space-y-3 font-mono text-xs text-zinc-300 leading-relaxed">
              <div className="p-2.5 bg-black border-l-4 border-amber-400">
                <span className="font-bold text-amber-400 block mb-0.5">1. DETERMINISTIC RULES</span>
                <p className="text-zinc-400 text-[11px]">
                  Configurable threshold checks (SSH failed logon sequences, Windows 4625 logon bursts, privilege token assignments) providing explainable high-certainty alerts.
                </p>
              </div>

              <div className="p-2.5 bg-black border-l-4 border-purple-400">
                <span className="font-bold text-purple-400 block mb-0.5">2. ISOLATION FOREST ML</span>
                <p className="text-zinc-400 text-[11px]">
                  Unsupervised statistical anomaly detection on aggregated host feature vectors (failed logins, unique IPs, off-hours ratio, volume deviation) without requiring pre-labeled training data.
                </p>
              </div>

              <div className="p-2.5 bg-black border-l-4 border-lime-400">
                <span className="font-bold text-lime-400 block mb-0.5">3. LANGGRAPH AGENTS</span>
                <p className="text-zinc-400 text-[11px]">
                  Multi-agent stateful workflow connecting Triage, Timeline Correlation, Threat Intelligence, MITRE mapping, and Evidence Validation to synthesize incident reports.
                </p>
              </div>
            </div>
          </BrutalCard>

          {/* Quick Inspection Card */}
          {selectedAlert && (
            <BrutalCard
              headerTitle={`INSPECT: ${selectedAlert.alert_id}`}
              headerColor="cyan"
              action={
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="text-black font-bold text-xs"
                >
                  ✕
                </button>
              }
            >
              <div className="space-y-2 font-mono text-xs">
                <div>
                  <span className="text-zinc-500 uppercase text-[10px] block">RULE / TYPE:</span>
                  <span className="text-white font-bold">{selectedAlert.rule_id} ({selectedAlert.detection_type})</span>
                </div>
                <div>
                  <span className="text-zinc-500 uppercase text-[10px] block">SEVERITY:</span>
                  <SeverityBadge severity={selectedAlert.severity} size="sm" />
                </div>
                <div>
                  <span className="text-zinc-500 uppercase text-[10px] block">RELEVANT FIELDS:</span>
                  <pre className="bg-black p-2 border border-zinc-800 text-[11px] text-zinc-300 max-h-40 overflow-x-auto">
                    {JSON.stringify(selectedAlert.relevant_fields, null, 2)}
                  </pre>
                </div>
                <div className="pt-2">
                  <BrutalButton
                    size="sm"
                    variant="lime"
                    className="w-full"
                    onClick={() => onStartInvestigation(selectedAlert)}
                  >
                    Start Full Agent Investigation
                  </BrutalButton>
                </div>
              </div>
            </BrutalCard>
          )}
        </div>
      </div>
    </div>
  );
};
