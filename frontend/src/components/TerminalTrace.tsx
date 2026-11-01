import { useState, type FC } from 'react';
import { InvestigationTraceStep } from '../types';
import { BrutalBadge } from './BrutalBadge';
import { ChevronDown, ChevronRight, Terminal, CheckCircle2, AlertCircle, Wrench } from 'lucide-react';

interface TerminalTraceProps {
  traces: InvestigationTraceStep[];
  isStreaming?: boolean;
}

export const TerminalTrace: FC<TerminalTraceProps> = ({ traces, isStreaming }) => {
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({});

  const toggleStep = (stepId: number) => {
    setExpandedSteps((prev) => ({ ...prev, [stepId]: !prev[stepId] }));
  };

  const getAgentColor = (name: string): 'lime' | 'cyan' | 'amber' | 'purple' | 'coral' | 'white' | 'slate' => {
    if (name.includes('Triage')) return 'lime';
    if (name.includes('Log')) return 'cyan';
    if (name.includes('Threat')) return 'amber';
    if (name.includes('MITRE')) return 'purple';
    if (name.includes('Analysis')) return 'coral';
    if (name.includes('Validation')) return 'lime';
    if (name.includes('Report')) return 'white';
    return 'slate';
  };

  if (!traces || traces.length === 0) {
    return (
      <div className="bg-black border-2 border-black p-8 text-center font-mono shadow-[4px_4px_0px_0px_#000000]">
        <Terminal className="w-8 h-8 text-zinc-600 mx-auto mb-2" />
        <p className="text-zinc-400 text-sm">NO ACTIVE AGENT TRACE AVAILABLE.</p>
        <p className="text-zinc-600 text-xs mt-1">Start an investigation to trigger the LangGraph orchestration pipeline.</p>
      </div>
    );
  }

  return (
    <div className="bg-black border-2 border-black shadow-[4px_4px_0px_0px_#000000] overflow-hidden">
      {/* Terminal header */}
      <div className="bg-zinc-950 px-4 py-2 border-b-2 border-black flex items-center justify-between font-mono text-xs">
        <div className="flex items-center space-x-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 border border-black inline-block"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 border border-black inline-block"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-green-500 border border-black inline-block"></span>
          <span className="font-bold text-zinc-400 ml-2 tracking-wider">LANGGRAPH MULTI-AGENT EXECUTION STREAM</span>
        </div>
        <div className="flex items-center space-x-2">
          {isStreaming && (
            <span className="flex items-center text-lime-400 text-[11px] font-bold">
              <span className="w-2 h-2 rounded-full bg-lime-400 animate-ping mr-1.5"></span>
              LIVE SSE STREAMING
            </span>
          )}
          <span className="text-zinc-500 font-bold">STEPS: {traces.length}</span>
        </div>
      </div>

      {/* Steps List */}
      <div className="divide-y-2 divide-zinc-900 font-mono">
        {traces.map((trace, idx) => {
          const isExpanded = expandedSteps[trace.step_id] !== false; // default open
          const agentCol = getAgentColor(trace.agent_name);

          return (
            <div key={idx} className="p-3.5 hover:bg-zinc-950/60 transition-colors">
              <div
                className="flex items-center justify-between cursor-pointer select-none"
                onClick={() => toggleStep(trace.step_id)}
              >
                <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                  <span className="text-zinc-600 text-xs font-bold">#{trace.step_id}</span>
                  <BrutalBadge color={agentCol} size="sm">
                    {trace.agent_name}
                  </BrutalBadge>
                  <span className="text-white text-xs font-bold tracking-wide">
                    {trace.action}
                  </span>
                  {trace.tool_name && (
                    <span className="text-[11px] text-zinc-400 bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 flex items-center">
                      <Wrench className="w-3 h-3 mr-1 text-cyan-400" />
                      tool: {trace.tool_name}
                    </span>
                  )}
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-[10px] text-zinc-500 hidden sm:inline">
                    {trace.timestamp ? trace.timestamp.slice(11, 19) : ''}
                  </span>
                  <span className="text-xs font-bold text-lime-400 flex items-center">
                    {trace.status === 'COMPLETED' ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-lime-400" />
                    ) : (
                      <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                    )}
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-zinc-400" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-zinc-400" />
                  )}
                </div>
              </div>

              {isExpanded && (
                <div className="mt-3 pl-4 border-l-2 border-zinc-800 space-y-2 text-xs">
                  {/* Thought */}
                  {trace.thought && (
                    <div className="bg-zinc-950 p-2.5 border border-zinc-800 text-zinc-300">
                      <span className="text-[10px] text-zinc-500 font-bold uppercase block mb-1">
                        Agent Reasoning / Internal Thought:
                      </span>
                      <p className="leading-relaxed text-zinc-200">{trace.thought}</p>
                    </div>
                  )}

                  {/* Findings Summary */}
                  {trace.findings_summary && (
                    <div className="bg-zinc-900/80 p-2.5 border border-black border-l-4 border-l-lime-400 text-lime-200">
                      <span className="text-[10px] text-lime-400 font-bold uppercase block mb-0.5">
                        Verified Finding:
                      </span>
                      <p className="leading-relaxed">{trace.findings_summary}</p>
                    </div>
                  )}

                  {/* Tool Output if present */}
                  {trace.tool_output && Object.keys(trace.tool_output).length > 0 && (
                    <div className="bg-black p-2 border border-zinc-900 text-[11px]">
                      <span className="text-[10px] text-cyan-400 font-bold uppercase block mb-1">
                        Tool Output Data:
                      </span>
                      <pre className="text-zinc-400 overflow-x-auto p-1 max-h-36">
                        {JSON.stringify(trace.tool_output, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
