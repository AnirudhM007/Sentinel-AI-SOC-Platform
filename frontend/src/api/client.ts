import axios from 'axios';
import {
  DashboardSummary,
  LogEvent,
  Alert,
  Investigation,
  IncidentReport,
  ScenarioMeta,
  AppSettings,
  InvestigationTraceStep
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const apiClient = {
  // Dashboard
  getDashboardSummary: async (): Promise<DashboardSummary> => {
    const res = await api.get('/dashboard/summary');
    return res.data;
  },

  // Logs
  getLogs: async (params?: Record<string, any>): Promise<LogEvent[]> => {
    const res = await api.get('/logs', { params });
    return res.data;
  },

  getLogById: async (eventId: string): Promise<LogEvent> => {
    const res = await api.get(`/logs/${eventId}`);
    return res.data;
  },

  uploadLogs: async (file: File): Promise<any> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/logs/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },

  // Alerts
  getAlerts: async (params?: Record<string, any>): Promise<Alert[]> => {
    const res = await api.get('/alerts', { params });
    return res.data;
  },

  getAlertDetail: async (alertId: string): Promise<Alert> => {
    const res = await api.get(`/alerts/${alertId}`);
    return res.data;
  },

  // Investigations
  startInvestigation: async (data: { alert_id?: string; event_ids?: string[]; title?: string }): Promise<any> => {
    const res = await api.post('/investigations/start', data);
    return res.data;
  },

  getInvestigations: async (): Promise<Investigation[]> => {
    const res = await api.get('/investigations');
    return res.data;
  },

  getInvestigationDetail: async (id: string): Promise<Investigation> => {
    const res = await api.get(`/investigations/${id}`);
    return res.data;
  },

  getInvestigationTrace: async (id: string): Promise<{ investigation_id: string; traces: InvestigationTraceStep[] }> => {
    const res = await api.get(`/investigations/${id}/trace`);
    return res.data;
  },

  getInvestigationReport: async (id: string): Promise<IncidentReport> => {
    const res = await api.get(`/investigations/${id}/report`);
    return res.data;
  },

  getPdfReportUrl: (id: string): string => {
    return `${API_BASE_URL}/investigations/${id}/report/pdf`;
  },

  // Threat Intel
  getThreatIntel: async (indicator: string): Promise<any> => {
    const res = await api.get(`/threat-intelligence/${indicator}`);
    return res.data;
  },

  // Scenarios
  getScenarios: async (): Promise<ScenarioMeta[]> => {
    const res = await api.get('/scenarios');
    return res.data;
  },

  loadScenario: async (scenarioId: string): Promise<any> => {
    const res = await api.post(`/scenarios/load/${scenarioId}`);
    return res.data;
  },

  // Settings
  getSettings: async (): Promise<AppSettings> => {
    const res = await api.get('/settings');
    return res.data;
  },

  updateSettings: async (data: Partial<AppSettings>): Promise<any> => {
    const res = await api.post('/settings', data);
    return res.data;
  },

  // SSE Stream helper
  subscribeToInvestigationStream: (
    investigationId: string,
    onStep: (step: InvestigationTraceStep) => void,
    onComplete: () => void,
    onError: (err: any) => void
  ) => {
    const eventSource = new EventSource(`${API_BASE_URL}/investigations/${investigationId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'AGENT_STEP' && payload.step) {
          onStep(payload.step);
        } else if (payload.type === 'COMPLETE') {
          onComplete();
          eventSource.close();
        }
      } catch (e) {
        console.error('Error parsing SSE event:', e);
      }
    };

    eventSource.onerror = (err) => {
      onError(err);
      eventSource.close();
    };

    return () => eventSource.close();
  }
};
