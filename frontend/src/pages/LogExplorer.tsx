import { useEffect, useState, type FC } from 'react';
import { apiClient } from '../api/client';
import { LogEvent } from '../types';
import { BrutalCard } from '../components/BrutalCard';
import { BrutalButton } from '../components/BrutalButton';
import { SeverityBadge } from '../components/SeverityBadge';
import { BrutalBadge } from '../components/BrutalBadge';
import { Search, Filter, Eye, X, RefreshCw } from 'lucide-react';

export const LogExplorer: FC = () => {
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedLog, setSelectedLog] = useState<LogEvent | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [hostname, setHostname] = useState('');
  const [username, setUsername] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [eventType, setEventType] = useState('');

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const params: Record<string, any> = { limit: 100 };
      if (search) params.search = search;
      if (severity) params.severity = severity;
      if (hostname) params.hostname = hostname;
      if (username) params.username = username;
      if (sourceIp) params.source_ip = sourceIp;
      if (eventType) params.event_type = eventType;

      const data = await apiClient.getLogs(params);
      setLogs(data);
    } catch (err) {
      console.error('Failed to query logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [severity, eventType]);

  const handleResetFilters = () => {
    setSearch('');
    setSeverity('');
    setHostname('');
    setUsername('');
    setSourceIp('');
    setEventType('');
    setTimeout(fetchLogs, 50);
  };

  return (
    <div className="space-y-6">
      {/* Filter Toolbar */}
      <BrutalCard
        headerTitle="TELEMETRY SEARCH & FILTRATION ENGINE"
        headerColor="lime"
        headerBadge={`${logs.length} EVENTS FETCHED`}
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 font-mono text-xs">
          {/* Keyword Search */}
          <div className="lg:col-span-2">
            <label className="block text-zinc-400 font-bold mb-1">KEYWORD / MESSAGE</label>
            <div className="relative">
              <input
                type="text"
                placeholder="Search command, raw log..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
                className="w-full bg-black border-2 border-black p-2 text-white placeholder-zinc-600 focus:outline-none focus:border-lime-400"
              />
              <Search className="w-4 h-4 text-zinc-500 absolute right-2.5 top-2.5 pointer-events-none" />
            </div>
          </div>

          {/* Severity */}
          <div>
            <label className="block text-zinc-400 font-bold mb-1">SEVERITY</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full bg-black border-2 border-black p-2 text-white focus:outline-none focus:border-lime-400"
            >
              <option value="">ALL SEVERITIES</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>
          </div>

          {/* Event Type */}
          <div>
            <label className="block text-zinc-400 font-bold mb-1">EVENT TYPE</label>
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full bg-black border-2 border-black p-2 text-white focus:outline-none focus:border-lime-400"
            >
              <option value="">ALL TYPES</option>
              <option value="AUTH_FAILURE">AUTH_FAILURE</option>
              <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
              <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
              <option value="USER_CREATE">USER_CREATE</option>
              <option value="PROCESS_CREATE">PROCESS_CREATE</option>
              <option value="NETWORK_CONNECT">NETWORK_CONNECT</option>
            </select>
          </div>

          {/* Hostname */}
          <div>
            <label className="block text-zinc-400 font-bold mb-1">HOST</label>
            <input
              type="text"
              placeholder="e.g. srv-edge-01"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
              className="w-full bg-black border-2 border-black p-2 text-white placeholder-zinc-600 focus:outline-none focus:border-lime-400"
            />
          </div>

          {/* Source IP */}
          <div>
            <label className="block text-zinc-400 font-bold mb-1">SOURCE IP</label>
            <input
              type="text"
              placeholder="e.g. 198.51.100.45"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
              className="w-full bg-black border-2 border-black p-2 text-white placeholder-zinc-600 focus:outline-none focus:border-lime-400"
            />
          </div>
        </div>

        {/* Buttons */}
        <div className="flex items-center justify-end space-x-2 mt-4 pt-3 border-t border-zinc-800">
          <BrutalButton
            size="sm"
            variant="slate"
            onClick={handleResetFilters}
          >
            Clear Filters
          </BrutalButton>
          <BrutalButton
            size="sm"
            variant="lime"
            icon={<Filter className="w-3.5 h-3.5" />}
            onClick={fetchLogs}
            loading={loading}
          >
            Apply Query
          </BrutalButton>
        </div>
      </BrutalCard>

      {/* Events Table */}
      <div className="bg-zinc-900 border-2 border-black shadow-[4px_4px_0px_0px_#000000] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="bg-zinc-950 border-b-2 border-black text-zinc-400 uppercase font-bold tracking-wider">
                <th className="p-3 border-r border-zinc-800">Timestamp (UTC)</th>
                <th className="p-3 border-r border-zinc-800">Severity</th>
                <th className="p-3 border-r border-zinc-800">Event Type</th>
                <th className="p-3 border-r border-zinc-800">Target User</th>
                <th className="p-3 border-r border-zinc-800">Source Host / IP</th>
                <th className="p-3 border-r border-zinc-800">Command / Payload</th>
                <th className="p-3 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {logs.length > 0 ? (
                logs.map((e) => (
                  <tr
                    key={e.event_id}
                    className="hover:bg-zinc-950/70 transition-colors"
                  >
                    <td className="p-3 whitespace-nowrap text-zinc-300 font-bold border-r border-zinc-800">
                      {e.timestamp ? e.timestamp.slice(0, 19).replace('T', ' ') : 'N/A'}
                    </td>
                    <td className="p-3 whitespace-nowrap border-r border-zinc-800">
                      <SeverityBadge severity={e.severity} size="sm" />
                    </td>
                    <td className="p-3 whitespace-nowrap border-r border-zinc-800">
                      <BrutalBadge color="slate" size="sm">
                        {e.event_type}
                      </BrutalBadge>
                    </td>
                    <td className="p-3 whitespace-nowrap text-white font-bold border-r border-zinc-800">
                      {e.username || '-'}
                    </td>
                    <td className="p-3 whitespace-nowrap text-cyan-300 border-r border-zinc-800">
                      <div>{e.hostname}</div>
                      {e.source_ip && (
                        <div className="text-[10px] text-zinc-400 font-bold">{e.source_ip}</div>
                      )}
                    </td>
                    <td className="p-3 text-zinc-300 max-w-xs truncate border-r border-zinc-800">
                      {e.command_line || e.raw_event}
                    </td>
                    <td className="p-3 text-center whitespace-nowrap">
                      <button
                        onClick={() => setSelectedLog(e)}
                        className="px-2 py-1 bg-zinc-800 text-white border border-black hover:bg-lime-400 hover:text-black transition-colors font-bold text-[10px]"
                      >
                        <Eye className="w-3 h-3 inline mr-1" />
                        Raw
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-zinc-500 font-mono">
                    NO LOGS MATCHING CURRENT SEARCH CRITERIA.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Event Modal / Drawer */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-zinc-900 border-4 border-black shadow-[8px_8px_0px_0px_#000000] w-full max-w-3xl max-h-[85vh] overflow-y-auto">
            <div className="bg-lime-400 px-4 py-3 border-b-2 border-black flex items-center justify-between text-black font-mono font-bold">
              <span className="text-sm uppercase tracking-wider">
                RAW SECURITY EVENT DETAILS: {selectedLog.event_id}
              </span>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-1 hover:bg-black hover:text-white border border-black transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4 font-mono text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-black p-3 border border-zinc-800">
                <div>
                  <span className="text-zinc-500 uppercase block text-[10px]">EVENT TYPE</span>
                  <span className="text-white font-bold">{selectedLog.event_type}</span>
                </div>
                <div>
                  <span className="text-zinc-500 uppercase block text-[10px]">NATIVE ID</span>
                  <span className="text-lime-400 font-bold">{selectedLog.event_id_native || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-zinc-500 uppercase block text-[10px]">STATUS</span>
                  <span className="text-white font-bold">{selectedLog.status}</span>
                </div>
                <div>
                  <span className="text-zinc-500 uppercase block text-[10px]">SEVERITY</span>
                  <SeverityBadge severity={selectedLog.severity} size="sm" />
                </div>
              </div>

              <div>
                <span className="text-zinc-400 uppercase font-bold block mb-1">ORIGINAL RAW LOG STRING:</span>
                <div className="bg-black p-3 border-2 border-black text-lime-300 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                  {selectedLog.raw_event}
                </div>
              </div>

              <div>
                <span className="text-zinc-400 uppercase font-bold block mb-1">FULL NORMALIZED METADATA:</span>
                <pre className="bg-black p-3 border border-zinc-800 text-zinc-300 overflow-x-auto">
                  {JSON.stringify(selectedLog, null, 2)}
                </pre>
              </div>

              <div className="flex justify-end pt-2">
                <BrutalButton
                  size="sm"
                  variant="white"
                  onClick={() => setSelectedLog(null)}
                >
                  Close Inspector
                </BrutalButton>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
