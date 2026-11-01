import { useEffect, useState, type FC } from 'react';
import { apiClient } from '../api/client';
import { AppSettings } from '../types';
import { BrutalCard } from '../components/BrutalCard';
import { BrutalButton } from '../components/BrutalButton';
import { BrutalBadge } from '../components/BrutalBadge';
import { Save, CheckCircle2, ShieldCheck, Key, Cpu, Sliders } from 'lucide-react';

interface SettingsViewProps {
  onSettingsUpdated: () => void;
}

export const SettingsView: FC<SettingsViewProps> = ({ onSettingsUpdated }) => {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Form inputs
  const [mockMode, setMockMode] = useState(true);
  const [llmProvider, setLlmProvider] = useState('mock');
  const [openaiModel, setOpenaiModel] = useState('gpt-4o-mini');
  const [openaiApiKey, setOpenaiApiKey] = useState('');
  const [abuseipdbApiKey, setAbuseipdbApiKey] = useState('');
  const [virustotalApiKey, setVirustotalApiKey] = useState('');
  const [bruteForceThreshold, setBruteForceThreshold] = useState(5);
  const [timeWindowMinutes, setTimeWindowMinutes] = useState(15);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      const data = await apiClient.getSettings();
      setSettings(data);
      setMockMode(data.mock_mode);
      setLlmProvider(data.llm_provider);
      setOpenaiModel(data.openai_model);
      setBruteForceThreshold(data.brute_force_threshold);
      setTimeWindowMinutes(data.time_window_minutes);
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSave = async () => {
    try {
      setSaving(true);
      setSavedSuccess(false);
      const updatePayload: Record<string, any> = {
        mock_mode: mockMode,
        llm_provider: llmProvider,
        openai_model: openaiModel,
        brute_force_threshold: Number(bruteForceThreshold),
        time_window_minutes: Number(timeWindowMinutes),
      };
      if (openaiApiKey.trim()) updatePayload.openai_api_key = openaiApiKey.trim();
      if (abuseipdbApiKey.trim()) updatePayload.abuseipdb_api_key = abuseipdbApiKey.trim();
      if (virustotalApiKey.trim()) updatePayload.virustotal_api_key = virustotalApiKey.trim();

      const res = await apiClient.updateSettings(updatePayload);
      setSettings(res.settings);
      setOpenaiApiKey('');
      setAbuseipdbApiKey('');
      setVirustotalApiKey('');
      setSavedSuccess(true);
      onSettingsUpdated();
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to update settings:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="bg-zinc-950 border-2 border-black p-4 shadow-[4px_4px_0px_0px_#000000]">
        <h2 className="text-xl font-black text-white uppercase tracking-tight">
          SOC PLATFORM CONFIGURATION & SECURITY CONTROLS
        </h2>
        <p className="text-xs text-zinc-400 mt-1">
          Configure Agentic AI reasoning provider, threat intelligence API keys, and deterministic rule thresholds.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* LLM & Agent Engine */}
        <BrutalCard
          headerTitle="AI & LANGGRAPH REASONING ENGINE"
          headerColor="lime"
          headerBadge={mockMode ? 'MOCK REASONING' : 'OPENAI'}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-zinc-300 font-bold mb-1.5">
                EXECUTION MODE
              </label>
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => { setMockMode(true); setLlmProvider('mock'); }}
                  className={`px-3 py-2 font-bold border-2 border-black flex-1 text-center transition-all ${
                    mockMode ? 'bg-lime-400 text-black shadow-[2px_2px_0px_0px_#000000]' : 'bg-black text-zinc-400'
                  }`}
                >
                  ⚡ Local Structured Engine (No API Credits Required)
                </button>
                <button
                  type="button"
                  onClick={() => { setMockMode(false); setLlmProvider('openai'); }}
                  className={`px-3 py-2 font-bold border-2 border-black flex-1 text-center transition-all ${
                    !mockMode ? 'bg-cyan-400 text-black shadow-[2px_2px_0px_0px_#000000]' : 'bg-black text-zinc-400'
                  }`}
                >
                  🟢 Live OpenAI Provider
                </button>
              </div>
            </div>

            <div>
              <label className="block text-zinc-300 font-bold mb-1">
                OPENAI MODEL SELECTION
              </label>
              <select
                value={openaiModel}
                onChange={(e) => setOpenaiModel(e.target.value)}
                disabled={mockMode}
                className="w-full bg-black border-2 border-black p-2 text-white focus:outline-none focus:border-lime-400 disabled:opacity-40"
              >
                <option value="gpt-4o-mini">gpt-4o-mini (Recommended for Fast SOC Triaging)</option>
                <option value="gpt-4o">gpt-4o (Deep Multimodal & Correlation)</option>
                <option value="gpt-3.5-turbo">gpt-3.5-turbo</option>
              </select>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-zinc-300 font-bold">
                  OPENAI API KEY
                </label>
                {settings?.has_openai_key ? (
                  <span className="text-lime-400 font-bold">✓ Configured in Environment</span>
                ) : (
                  <span className="text-zinc-500">Not set (Using Mock Mode)</span>
                )}
              </div>
              <input
                type="password"
                placeholder={settings?.has_openai_key ? '••••••••••••••••••••••••' : 'sk-...'}
                value={openaiApiKey}
                onChange={(e) => setOpenaiApiKey(e.target.value)}
                className="w-full bg-black border-2 border-black p-2 text-white placeholder-zinc-600 focus:outline-none focus:border-lime-400 font-mono"
              />
              <p className="text-[10px] text-zinc-500 mt-1">
                Credentials are saved to local runtime environment; never exposed in client bundles.
              </p>
            </div>
          </div>
        </BrutalCard>

        {/* Threat Intelligence API Configuration */}
        <BrutalCard
          headerTitle="THREAT INTELLIGENCE APIS (OPTIONAL)"
          headerColor="amber"
          headerBadge="EXTERNAL FEEDS"
        >
          <div className="space-y-4">
            <p className="text-zinc-400 text-[11px] leading-relaxed">
              When live API keys are provided, the Threat Intelligence Agent queries live endpoints with caching and rate-limiting. When omitted, it seamlessly falls back to the curated offline threat intelligence database.
            </p>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-zinc-300 font-bold">
                  ABUSEIPDB API KEY
                </label>
                {settings?.has_abuseipdb_key ? (
                  <span className="text-lime-400 font-bold">✓ Active</span>
                ) : (
                  <span className="text-amber-400">Offline Mock Feed Active</span>
                )}
              </div>
              <input
                type="password"
                placeholder={settings?.has_abuseipdb_key ? '••••••••••••••••••••••••' : 'Enter AbuseIPDB key...'}
                value={abuseipdbApiKey}
                onChange={(e) => setAbuseipdbApiKey(e.target.value)}
                className="w-full bg-black border-2 border-black p-2 text-white placeholder-zinc-600 focus:outline-none focus:border-amber-400 font-mono"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-zinc-300 font-bold">
                  VIRUSTOTAL API KEY
                </label>
                {settings?.has_virustotal_key ? (
                  <span className="text-lime-400 font-bold">✓ Active</span>
                ) : (
                  <span className="text-amber-400">Offline Mock Feed Active</span>
                )}
              </div>
              <input
                type="password"
                placeholder={settings?.has_virustotal_key ? '••••••••••••••••••••••••' : 'Enter VirusTotal key...'}
                value={virustotalApiKey}
                onChange={(e) => setVirustotalApiKey(e.target.value)}
                className="w-full bg-black border-2 border-black p-2 text-white placeholder-zinc-600 focus:outline-none focus:border-amber-400 font-mono"
              />
            </div>
          </div>
        </BrutalCard>

        {/* Deterministic Rule Thresholds */}
        <BrutalCard
          headerTitle="DETECTION ENGINE RULE THRESHOLDS"
          headerColor="purple"
          headerBadge="HEURISTICS"
        >
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <label className="text-zinc-300 font-bold">FAILED LOGINS THRESHOLD (BURST)</label>
                <span className="text-lime-400 font-bold">{bruteForceThreshold} attempts</span>
              </div>
              <input
                type="range"
                min="2"
                max="20"
                value={bruteForceThreshold}
                onChange={(e) => setBruteForceThreshold(Number(e.target.value))}
                className="w-full accent-lime-400 cursor-pointer"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <label className="text-zinc-300 font-bold">CORRELATION TIME WINDOW (MINUTES)</label>
                <span className="text-cyan-400 font-bold">{timeWindowMinutes} minutes</span>
              </div>
              <input
                type="range"
                min="5"
                max="60"
                value={timeWindowMinutes}
                onChange={(e) => setTimeWindowMinutes(Number(e.target.value))}
                className="w-full accent-cyan-400 cursor-pointer"
              />
            </div>
          </div>
        </BrutalCard>

        {/* Save Bar */}
        <div className="bg-zinc-900 border-2 border-black p-5 shadow-[4px_4px_0px_0px_#000000] flex flex-col justify-between">
          <div>
            <h4 className="font-bold text-white text-sm mb-1 uppercase">PERSIST SETTINGS</h4>
            <p className="text-zinc-400 text-xs leading-relaxed mb-4">
              Changes apply instantly across LangGraph agent workflows, threat intelligence lookups, and detection engine evaluations.
            </p>
            {savedSuccess && (
              <div className="p-2 bg-lime-950 border border-lime-400 text-lime-300 text-xs flex items-center mb-4">
                <CheckCircle2 className="w-4 h-4 mr-1.5" />
                Settings saved successfully!
              </div>
            )}
          </div>

          <BrutalButton
            size="md"
            variant="lime"
            icon={<Save className="w-4 h-4" />}
            onClick={handleSave}
            loading={saving}
          >
            Save All Configurations
          </BrutalButton>
        </div>
      </div>
    </div>
  );
};
