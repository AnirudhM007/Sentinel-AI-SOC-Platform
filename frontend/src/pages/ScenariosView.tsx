import { useEffect, useState, type FC } from 'react';
import { apiClient } from '../api/client';
import { ScenarioMeta } from '../types';
import { BrutalCard } from '../components/BrutalCard';
import { BrutalButton } from '../components/BrutalButton';
import { BrutalBadge } from '../components/BrutalBadge';
import { Upload, Play, CheckCircle2, AlertCircle, FileText, ArrowRight } from 'lucide-react';

interface ScenariosViewProps {
  onNavigate: (tab: string, context?: any) => void;
}

export const ScenariosView: FC<ScenariosViewProps> = ({ onNavigate }) => {
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeScenarioId, setActiveScenarioId] = useState<string | null>(null);
  const [loadResult, setLoadResult] = useState<any | null>(null);

  // File Upload state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<any | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  useEffect(() => {
    const fetchScenarios = async () => {
      try {
        setLoading(true);
        const data = await apiClient.getScenarios();
        setScenarios(data);
      } catch (err) {
        console.error('Failed to load scenarios:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchScenarios();
  }, []);

  const handleLoadScenario = async (scId: string) => {
    try {
      setActiveScenarioId(scId);
      setLoadResult(null);
      const res = await apiClient.loadScenario(scId);
      setLoadResult(res.result);
    } catch (err) {
      console.error('Error loading scenario:', err);
    } finally {
      setActiveScenarioId(null);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setUploadError(null);
      setUploadResult(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    try {
      setUploading(true);
      setUploadError(null);
      const res = await apiClient.uploadLogs(selectedFile);
      setUploadResult(res);
    } catch (err: any) {
      setUploadError(err.response?.data?.detail || err.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6 font-mono">
      {/* Header Banner */}
      <div className="bg-zinc-950 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000]">
        <h2 className="text-xl font-black text-white uppercase tracking-tight">
          SAMPLE SECURITY SCENARIOS & RAW LOG INGESTION
        </h2>
        <p className="text-xs text-zinc-400 mt-1">
          Demonstrate end-to-end multi-agent threat response using pre-canned realistic datasets or upload custom Linux/Windows/JSON/CSV logs.
        </p>
      </div>

      {/* 5 Pre-Built Scenarios Grid */}
      <div>
        <h3 className="text-sm font-black text-lime-400 uppercase tracking-wider mb-3">
          1-CLICK SYNTHETIC SECURITY SCENARIOS (CLEARLY LABELED SIMULATED):
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => (
            <div
              key={sc.id}
              className="bg-zinc-900 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <BrutalBadge color="slate" size="sm">{sc.category}</BrutalBadge>
                  <span className="text-[10px] bg-amber-400 text-black px-1.5 py-0.5 font-bold border border-black">
                    SIMULATED
                  </span>
                </div>
                <h4 className="text-white font-black text-sm mb-1">{sc.title}</h4>
                <p className="text-zinc-300 text-xs mb-2 font-sans">{sc.description}</p>
                <div className="text-[11px] text-zinc-500 mb-4">
                  Source: <span className="text-cyan-400 font-bold">{sc.filename}</span>
                </div>
              </div>

              <div>
                <BrutalButton
                  size="sm"
                  variant="lime"
                  icon={<Play className="w-3.5 h-3.5" />}
                  className="w-full text-xs"
                  onClick={() => handleLoadScenario(sc.id)}
                  loading={activeScenarioId === sc.id}
                >
                  Load & Ingest Scenario
                </BrutalButton>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scenario Ingestion Result Box */}
      {loadResult && (
        <div className="bg-black border-2 border-lime-400 p-4 shadow-[4px_4px_0px_0px_#a3e635]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-lime-400 font-black text-xs uppercase flex items-center">
              <CheckCircle2 className="w-4 h-4 mr-1.5" />
              SCENARIO LOADED: {loadResult.title}
            </span>
            <span className="text-zinc-400 text-xs">
              {loadResult.events_ingested} Events Ingested | {loadResult.alerts_generated} Alerts Triggered
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs mb-3">
            <div className="p-2 bg-zinc-900 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">RULE-BASED ALERTS:</span>
              <span className="text-amber-400 font-bold">{loadResult.rule_alerts_count}</span>
            </div>
            <div className="p-2 bg-zinc-900 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">ISOLATION FOREST ANOMALIES:</span>
              <span className="text-purple-400 font-bold">{loadResult.ml_alerts_count}</span>
            </div>
            <div className="p-2 bg-zinc-900 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">NEXT STEP:</span>
              <span className="text-lime-400 font-bold">Inspect Alerts or Launch Agents</span>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <BrutalButton
              size="sm"
              variant="white"
              onClick={() => onNavigate('logs')}
            >
              View Ingested Logs
            </BrutalButton>
            <BrutalButton
              size="sm"
              variant="lime"
              icon={<ArrowRight className="w-3.5 h-3.5" />}
              onClick={() => onNavigate('alerts')}
            >
              Go to Generated Alerts
            </BrutalButton>
          </div>
        </div>
      )}

      {/* Custom Log Upload Section */}
      <BrutalCard
        headerTitle="CUSTOM SECURITY TELEMETRY INGESTION"
        headerColor="cyan"
        headerBadge="DRAG & DROP LOGS"
      >
        <p className="text-xs text-zinc-300 font-sans leading-relaxed mb-4">
          Upload real enterprise security logs or raw packet captures. SENTINEL AI automatically detects the format (Linux auth/syslog, Windows Event CSV, SIEM JSON, and binary PCAP/PCAPNG with Deep Packet Inspection for DNS queries, TLS SNI, HTTP, and TCP/UDP streams), parses timestamps, normalizes fields into the unified schema, and triggers detection rules and ML anomaly scoring.
        </p>

        <div className="border-2 border-dashed border-zinc-700 bg-black p-6 text-center hover:border-lime-400 transition-colors">
          <Upload className="w-8 h-8 text-zinc-500 mx-auto mb-2" />
          <input
            type="file"
            id="logUploadInput"
            className="hidden"
            accept=".log,.txt,.csv,.json,.pcap,.pcapng,.cap"
            onChange={handleFileChange}
          />
          <label
            htmlFor="logUploadInput"
            className="cursor-pointer font-mono text-xs font-bold text-lime-400 hover:underline"
          >
            {selectedFile ? `SELECTED: ${selectedFile.name} (${Math.round(selectedFile.size / 1024)} KB)` : 'CHOOSE REAL LOGS OR PACKET CAPTURE (.LOG, .CSV, .JSON, .PCAP, .PCAPNG)'}
          </label>
          <p className="text-[11px] text-zinc-500 mt-1">Supports live packet captures & logs up to 10 MB</p>
        </div>

        {selectedFile && (
          <div className="mt-4 flex items-center justify-end space-x-2">
            <BrutalButton
              size="sm"
              variant="slate"
              onClick={() => setSelectedFile(null)}
            >
              Cancel
            </BrutalButton>
            <BrutalButton
              size="sm"
              variant="lime"
              onClick={handleUpload}
              loading={uploading}
            >
              Parse & Ingest Telemetry
            </BrutalButton>
          </div>
        )}

        {/* Upload Result / Error */}
        {uploadError && (
          <div className="mt-4 p-3 bg-red-950/60 border border-red-500 text-red-300 text-xs flex items-center">
            <AlertCircle className="w-4 h-4 mr-2 text-red-400" />
            <span>Upload Error: {uploadError}</span>
          </div>
        )}

        {uploadResult && (
          <div className="mt-4 p-4 bg-zinc-950 border border-lime-400 text-xs space-y-2">
            <div className="text-lime-400 font-bold flex items-center">
              <CheckCircle2 className="w-4 h-4 mr-1.5" />
              File Ingested Successfully: {uploadResult.filename}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-zinc-300">
              <div>Format Detected: <span className="text-white font-bold">{uploadResult.stats?.format_detected}</span></div>
              <div>Parsed Events: <span className="text-white font-bold">{uploadResult.events_ingested}</span></div>
              <div>Duplicates Dropped: <span className="text-white font-bold">{uploadResult.stats?.duplicates_dropped}</span></div>
              <div>Alerts Created: <span className="text-lime-400 font-bold">{uploadResult.alerts_generated}</span></div>
            </div>
          </div>
        )}
      </BrutalCard>
    </div>
  );
};
