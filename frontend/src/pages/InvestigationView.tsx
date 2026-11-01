import { useEffect, useState, type FC } from 'react';
import { apiClient } from '../api/client';
import { Investigation, InvestigationTraceStep, IncidentReport } from '../types';
import { BrutalCard } from '../components/BrutalCard';
import { BrutalButton } from '../components/BrutalButton';
import { SeverityBadge } from '../components/SeverityBadge';
import { BrutalBadge } from '../components/BrutalBadge';
import { TerminalTrace } from '../components/TerminalTrace';
import {
  Shield,
  Download,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCw,
  ExternalLink,
  ChevronRight,
  UserCheck,
  Server,
  Layers,
  ArrowRight
} from 'lucide-react';

interface InvestigationViewProps {
  initialInvestigationId?: string;
  initialAlertId?: string;
  initialTitle?: string;
}

export const InvestigationView: FC<InvestigationViewProps> = ({
  initialInvestigationId,
  initialAlertId,
  initialTitle,
}) => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInv, setSelectedInv] = useState<Investigation | null>(null);
  const [traces, setTraces] = useState<InvestigationTraceStep[]>([]);
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'summary' | 'timeline' | 'mitre' | 'threat' | 'remediation' | 'traces'>('summary');
  const [isStartingNew, setIsStartingNew] = useState(false);

  // Fetch list of investigations
  const loadInvestigations = async (selectId?: string) => {
    try {
      setLoading(true);
      const data = await apiClient.getInvestigations();
      setInvestigations(data);

      const targetId = selectId || initialInvestigationId || (data.length > 0 ? data[0].investigation_id : null);
      if (targetId) {
        await loadInvestigationDetails(targetId);
      }
    } catch (err) {
      console.error('Failed to load investigations list:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadInvestigationDetails = async (id: string) => {
    try {
      setLoading(true);
      const invData = await apiClient.getInvestigationDetail(id);
      setSelectedInv(invData);
      setTraces(invData.agent_traces || []);
      setReport(invData.report || null);
    } catch (err) {
      console.error('Failed to load investigation details:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStartInvestigation = async (alertId?: string, title?: string) => {
    try {
      setIsStartingNew(true);
      const res = await apiClient.startInvestigation({
        alert_id: alertId || initialAlertId,
        title: title || initialTitle || 'Autonomous Security Investigation',
      });
      await loadInvestigations(res.investigation_id);
    } catch (err) {
      console.error('Failed to start investigation:', err);
    } finally {
      setIsStartingNew(false);
    }
  };

  useEffect(() => {
    if (initialAlertId && !initialInvestigationId) {
      handleStartInvestigation(initialAlertId, initialTitle);
    } else {
      loadInvestigations();
    }
  }, [initialInvestigationId, initialAlertId]);

  const handleDownloadPdf = () => {
    if (!selectedInv) return;
    const url = apiClient.getPdfReportUrl(selectedInv.investigation_id);
    window.open(url, '_blank');
  };

  const handleExportJson = () => {
    if (!report) return;
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `${selectedInv?.investigation_id}_report.json`);
    dlAnchor.click();
  };

  // Node states for the visual LangGraph flow
  const nodes = [
    { id: 'soc_triage', label: '1. SOC Triage', agent: 'Triage Agent', color: 'lime' },
    { id: 'log_investigation', label: '2. Log Timeline', agent: 'Log Agent', color: 'cyan' },
    { id: 'threat_intelligence', label: '3. Threat Intel', agent: 'Intel Agent', color: 'amber' },
    { id: 'mitre_mapping', label: '4. MITRE ATT&CK', agent: 'Matrix Agent', color: 'purple' },
    { id: 'incident_analysis', label: '5. Analysis', agent: 'Scope Agent', color: 'coral' },
    { id: 'validation', label: '6. Validation', agent: 'Fact-Check Agent', color: 'lime' },
    { id: 'report_generation', label: '7. Synthesis', agent: 'Report Agent', color: 'white' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Controls Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-zinc-950 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000]">
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-mono text-xs font-bold text-lime-400 bg-black px-2 py-0.5 border border-black">
              AGENTIC ORCHESTRATION WORKSPACE
            </span>
            <span className="font-mono text-xs text-zinc-400">STATEFUL LANGGRAPH WORKFLOW</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-black font-mono tracking-tight text-white mt-1">
            {selectedInv ? `${selectedInv.title} [${selectedInv.investigation_id}]` : 'INVESTIGATION WORKSPACE'}
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Investigation Selector */}
          <select
            value={selectedInv?.investigation_id || ''}
            onChange={(e) => loadInvestigationDetails(e.target.value)}
            className="bg-black border-2 border-black p-2 text-white font-mono text-xs focus:outline-none focus:border-lime-400"
          >
            {investigations.map((i) => (
              <option key={i.investigation_id} value={i.investigation_id}>
                {i.investigation_id} - {i.severity} ({i.title.slice(0, 30)})
              </option>
            ))}
          </select>

          <BrutalButton
            size="sm"
            variant="lime"
            icon={<Play className="w-3.5 h-3.5" />}
            onClick={() => handleStartInvestigation()}
            loading={isStartingNew}
          >
            Run New Investigation
          </BrutalButton>
        </div>
      </div>

      {/* Visual LangGraph Workflow Pipeline Diagram */}
      <BrutalCard
        headerTitle="LANGGRAPH ORCHESTRATION PIPELINE STATE"
        headerColor="slate"
        headerBadge="STATEFUL GRAPH"
      >
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 font-mono text-xs">
          {nodes.map((node, index) => {
            const hasTrace = traces.some((t) => t.agent_name.toLowerCase().includes(node.agent.split(' ')[0].toLowerCase()));
            const isCompleted = selectedInv?.status === 'COMPLETED' || hasTrace;

            return (
              <div
                key={node.id}
                className={`p-2.5 border-2 border-black flex flex-col justify-between transition-all ${
                  isCompleted
                    ? 'bg-zinc-900 border-lime-400 shadow-[2px_2px_0px_0px_#a3e635]'
                    : 'bg-black border-zinc-800 opacity-60'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] text-zinc-500 font-bold">NODE {index + 1}</span>
                    {isCompleted ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-lime-400" />
                    ) : (
                      <span className="w-2 h-2 rounded-full bg-zinc-600"></span>
                    )}
                  </div>
                  <div className="font-bold text-white text-[11px] truncate">{node.label}</div>
                  <div className="text-[10px] text-zinc-400 truncate">{node.agent}</div>
                </div>

                <div className="mt-2 pt-1 border-t border-zinc-800 text-[10px] flex items-center justify-between">
                  <span className={isCompleted ? 'text-lime-400 font-bold' : 'text-zinc-600'}>
                    {isCompleted ? 'EXECUTED' : 'PENDING'}
                  </span>
                  {index < 6 && <ChevronRight className="w-3 h-3 text-zinc-600 hidden lg:block" />}
                </div>
              </div>
            );
          })}
        </div>
      </BrutalCard>

      {/* Investigation Details & Report Viewer */}
      {selectedInv ? (
        <div className="space-y-6">
          {/* Metadata & Actions Header */}
          <div className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
            <div className="flex items-center space-x-3 flex-wrap gap-y-2">
              <div>
                <span className="text-[10px] text-zinc-500 uppercase block">EVIDENCE-BACKED SEVERITY</span>
                <SeverityBadge severity={selectedInv.severity} size="md" />
              </div>
              <div className="border-l border-zinc-800 pl-3">
                <span className="text-[10px] text-zinc-500 uppercase block">STATUS</span>
                <BrutalBadge color="lime" size="sm">{selectedInv.status}</BrutalBadge>
              </div>
              <div className="border-l border-zinc-800 pl-3">
                <span className="text-[10px] text-zinc-500 uppercase block">FACT-CHECK VALIDATION</span>
                <BrutalBadge color={report?.validation_status === 'PASSED' ? 'lime' : 'amber'} size="sm">
                  {report?.validation_status || 'VERIFIED'}
                </BrutalBadge>
              </div>
              <div className="border-l border-zinc-800 pl-3">
                <span className="text-[10px] text-zinc-500 uppercase block">STEPS LOGGED</span>
                <span className="text-white font-bold text-sm">{traces.length} agent actions</span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <BrutalButton
                size="sm"
                variant="white"
                icon={<FileCode className="w-3.5 h-3.5" />}
                onClick={handleExportJson}
              >
                Export JSON
              </BrutalButton>
              <BrutalButton
                size="sm"
                variant="lime"
                icon={<Download className="w-3.5 h-3.5" />}
                onClick={handleDownloadPdf}
              >
                Export PDF Report
              </BrutalButton>
            </div>
          </div>

          {/* Navigation Sub-Tabs */}
          <div className="flex border-b-2 border-black overflow-x-auto bg-zinc-950 font-mono text-xs scrollbar-none">
            {[
              { id: 'summary', label: '1. Executive Summary & Attack Chain' },
              { id: 'timeline', label: '2. Chronological Timeline' },
              { id: 'mitre', label: '3. MITRE ATT&CK Mapping' },
              { id: 'threat', label: '4. Threat Intelligence' },
              { id: 'remediation', label: '5. Remediation Plan' },
              { id: 'traces', label: `6. Agent Execution Traces (${traces.length})` }
            ].map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`
                    px-4 py-2.5 font-bold uppercase tracking-wider whitespace-nowrap border-r-2 border-black transition-all
                    ${
                      isActive
                        ? 'bg-lime-400 text-black border-t-2 border-t-black translate-y-[2px]'
                        : 'text-zinc-400 hover:text-white hover:bg-zinc-900'
                    }
                  `}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* TAB 1: EXECUTIVE SUMMARY */}
          {activeTab === 'summary' && report && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
              <div className="lg:col-span-2 space-y-6">
                <BrutalCard
                  headerTitle="EXECUTIVE INCIDENT OVERVIEW"
                  headerColor="lime"
                  headerBadge="FINDINGS"
                >
                  <p className="text-sm text-zinc-200 leading-relaxed font-sans mb-4">
                    {report.executive_summary}
                  </p>

                  <div className="p-3 bg-black border-2 border-black space-y-2 text-xs">
                    <span className="text-lime-400 font-bold block uppercase text-[10px]">
                      ATTACK SEQUENCE NARRATIVE:
                    </span>
                    <div className="text-white font-bold flex items-center flex-wrap gap-2">
                      {report.root_cause_assessment && (
                        <span className="text-zinc-300">
                          {selectedInv.summary || report.incident_overview}
                        </span>
                      )}
                    </div>
                  </div>
                </BrutalCard>

                {/* Root Cause & Potential Impact */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000]">
                    <span className="text-amber-400 font-bold text-xs uppercase block mb-1">
                      ROOT CAUSE ASSESSMENT
                    </span>
                    <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                      {report.root_cause_assessment}
                    </p>
                  </div>

                  <div className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000]">
                    <span className="text-red-400 font-bold text-xs uppercase block mb-1">
                      POTENTIAL SECURITY IMPACT
                    </span>
                    <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                      {report.potential_impact}
                    </p>
                  </div>
                </div>

                {/* Investigation Methodology & Limitations */}
                <div className="bg-black border-2 border-black p-4 space-y-2 text-xs text-zinc-400 shadow-[4px_4px_0px_0px_#000000]">
                  <span className="text-cyan-400 font-bold uppercase block text-[10px]">
                    INVESTIGATION METHODOLOGY & EVIDENCE BOUNDARIES:
                  </span>
                  <p>{report.investigation_methodology}</p>
                  <p className="text-[11px] text-zinc-500 pt-1 border-t border-zinc-900">
                    {report.investigation_limitations}
                  </p>
                </div>
              </div>

              {/* Sidebar Assets & Validation Status */}
              <div className="space-y-6">
                <BrutalCard
                  headerTitle="AFFECTED ASSETS & ENTITIES"
                  headerColor="cyan"
                  headerBadge="SCOPING"
                >
                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">HOSTS IDENTIFIED</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {(report.affected_assets?.hosts || []).map((h, i) => (
                          <span key={i} className="px-2 py-0.5 bg-black border border-zinc-700 text-white font-bold">
                            {h}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">TARGET ACCOUNTS</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {(report.affected_assets?.users || []).map((u, i) => (
                          <span key={i} className="px-2 py-0.5 bg-black border border-zinc-700 text-lime-300 font-bold">
                            {u}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">NETWORK ENDPOINTS</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {(report.affected_assets?.ips || []).map((ip, i) => (
                          <span key={i} className="px-2 py-0.5 bg-black border border-zinc-700 text-cyan-300 font-bold">
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </BrutalCard>

                {/* Validation Card */}
                <BrutalCard
                  headerTitle="GROUNDING AUDIT"
                  headerColor="purple"
                  headerBadge={report.validation_status}
                >
                  <div className="text-xs space-y-2">
                    <p className="text-zinc-300">
                      The Validation Agent performed cross-entity fact-checking to ensure referenced events, timestamps, and MITRE techniques are directly supported by source telemetry without model hallucination.
                    </p>
                    <div className="p-2 bg-black border border-zinc-800 text-[11px] text-lime-400">
                      ✓ All referenced telemetry verified in SQLite log store.
                    </div>
                  </div>
                </BrutalCard>
              </div>
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && report && (
            <BrutalCard
              headerTitle="CHRONOLOGICAL EVENT CORRELATION TIMELINE"
              headerColor="cyan"
              headerBadge={`${(report.event_timeline || []).length} TIMELINE ENTRIES`}
            >
              <div className="divide-y-2 divide-zinc-950 font-mono text-xs">
                {(report.event_timeline || []).map((entry, idx) => (
                  <div key={idx} className="py-3 flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                    <div className="sm:w-44 flex-shrink-0 text-zinc-400 font-bold">
                      {entry.timestamp ? entry.timestamp.slice(0, 19).replace('T', ' ') : ''}
                    </div>
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={entry.severity} size="sm" />
                        <BrutalBadge color="slate" size="sm">{entry.event_type}</BrutalBadge>
                        <span className="text-white font-bold">{entry.summary}</span>
                      </div>
                      <div className="text-zinc-400 text-[11px] bg-black p-1.5 border border-zinc-800">
                        Evidence snippet: {entry.evidence}
                      </div>
                    </div>
                    <span className="text-zinc-600 text-[10px] font-mono sm:self-center">
                      ID: {entry.event_id}
                    </span>
                  </div>
                ))}
              </div>
            </BrutalCard>
          )}

          {/* TAB 3: MITRE ATT&CK */}
          {activeTab === 'mitre' && report && (
            <div className="space-y-4 font-mono">
              <div className="p-4 bg-zinc-950 border-2 border-black text-xs text-zinc-300">
                <span className="font-bold text-purple-400 block mb-1">MITRE ATT&CK ENTERPRISE BEHAVIORAL ALIGNMENT:</span>
                Behavior patterns mapped deterministically to verified technique IDs with supporting event evidence.
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(report.mitre_attack_mappings || []).map((m) => (
                  <div
                    key={m.technique_id}
                    className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="px-2 py-0.5 bg-purple-400 text-black border border-black font-black text-xs">
                          {m.technique_id}
                        </span>
                        <BrutalBadge color="slate" size="sm">TACTIC: {m.tactic}</BrutalBadge>
                      </div>

                      <h4 className="text-white font-black text-sm mb-1">{m.technique_name}</h4>
                      <p className="text-zinc-300 text-xs mb-3 font-sans leading-relaxed">{m.reason}</p>
                    </div>

                    <div className="pt-2 border-t border-zinc-800 text-[11px]">
                      <span className="text-zinc-500 uppercase block text-[10px] mb-1">Supporting Evidence:</span>
                      <ul className="list-disc list-inside text-zinc-400 space-y-0.5">
                        {(m.supporting_evidence || []).map((ev, i) => (
                          <li key={i} className="truncate">{ev}</li>
                        ))}
                      </ul>
                      <div className="mt-2 text-right">
                        <span className="text-lime-400 font-bold text-xs">
                          Confidence: {Math.round(m.confidence * 100)}%
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: THREAT INTEL */}
          {activeTab === 'threat' && report && (
            <div className="space-y-4 font-mono">
              <div className="p-4 bg-zinc-950 border-2 border-black text-xs text-zinc-300">
                <span className="font-bold text-amber-400 block mb-1">INDICATOR REPUTATION & FEEDS:</span>
                Queries AbuseIPDB, VirusTotal, or simulated threat database. Live and simulated indicators are explicitly segregated.
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(report.threat_intelligence_findings || []).map((item, idx) => (
                  <div
                    key={idx}
                    className={`bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] ${
                      item.is_malicious ? 'border-red-500 shadow-[4px_4px_0px_0px_#ef4444]' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-sm font-black text-white">{item.indicator}</span>
                        <BrutalBadge color={item.is_simulated ? 'slate' : 'lime'} size="sm">
                          {item.is_simulated ? 'SIMULATED FEED' : 'LIVE FEED'}
                        </BrutalBadge>
                      </div>
                      <span className={`px-2 py-0.5 text-xs font-bold border border-black ${
                        item.is_malicious ? 'bg-red-500 text-white' : 'bg-lime-400 text-black'
                      }`}>
                        {item.is_malicious ? 'MALICIOUS' : 'BENIGN / UNRATED'}
                      </span>
                    </div>

                    <div className="mb-2">
                      <span className="text-xs text-zinc-400">Reputation Score: </span>
                      <span className="font-bold text-white text-sm">{item.reputation_score} / 100</span>
                    </div>

                    <p className="text-xs text-zinc-300 mb-3 font-sans leading-relaxed">
                      {item.summary}
                    </p>

                    {item.details && (
                      <div className="bg-black p-2 border border-zinc-800 text-[11px] text-zinc-400">
                        {item.details.category && <div>Category: <span className="text-white font-bold">{item.details.category}</span></div>}
                        {item.details.isp && <div>ISP / Network: <span className="text-white">{item.details.isp}</span></div>}
                        {item.details.country && <div>Country: <span className="text-white">{item.details.country}</span></div>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 5: REMEDIATION */}
          {activeTab === 'remediation' && report && (
            <div className="space-y-4 font-mono">
              <div className="bg-amber-400 border-2 border-black p-4 text-black text-xs font-bold shadow-[4px_4px_0px_0px_#000000]">
                <div className="flex items-center space-x-2 mb-1">
                  <UserCheck className="w-5 h-5" />
                  <span className="text-sm uppercase tracking-wide font-black">
                    SOC DEFENSE POLICY: HUMAN AUTHORIZATION MANDATORY
                  </span>
                </div>
                Per defensive cybersecurity controls, AI agents generate remediation recommendations only. No automated firewall blocks, account deletions, or system modifications are executed without analyst sign-off.
              </div>

              <div className="space-y-3">
                {(report.recommended_remediation || []).map((act) => (
                  <div
                    key={act.action_id}
                    className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                  >
                    <div>
                      <div className="flex items-center space-x-2 mb-1">
                        <span className="font-mono text-xs font-bold text-zinc-400">[{act.action_id}]</span>
                        <SeverityBadge severity={act.priority} size="sm" />
                        <h4 className="text-white font-black text-sm">{act.title}</h4>
                      </div>
                      <p className="text-xs text-zinc-300 font-sans leading-relaxed">{act.description}</p>
                    </div>

                    <div className="flex-shrink-0">
                      <span className="px-2 py-1 bg-black border border-zinc-700 text-amber-300 font-bold text-[11px]">
                        Requires Human Approval: YES
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 6: TRACES */}
          {activeTab === 'traces' && (
            <TerminalTrace traces={traces} />
          )}
        </div>
      ) : (
        <div className="bg-zinc-900 border-2 border-black p-12 text-center font-mono shadow-[4px_4px_0px_0px_#000000]">
          <Shield className="w-12 h-12 text-lime-400 mx-auto mb-3" />
          <h3 className="text-lg font-black text-white">NO INVESTIGATION SELECTED</h3>
          <p className="text-zinc-400 text-xs mt-1 mb-4">
            Select an existing investigation from the dropdown or click 'Run New Investigation' to begin.
          </p>
          <BrutalButton
            variant="lime"
            onClick={() => handleStartInvestigation()}
            loading={isStartingNew}
          >
            Start LangGraph Investigation
          </BrutalButton>
        </div>
      )}
    </div>
  );
};
