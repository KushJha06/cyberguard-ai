import type { Agent, Dataset, Health, Incident, IncidentStatus, IngestResponse, Plugin, Preflight, Stats } from './types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const options: RequestInit = { ...init, signal: init?.signal ?? AbortSignal.timeout(60_000) }
  const response = await fetch(path, options)
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try { detail = (await response.json()).detail ?? detail } catch { /* response is not JSON */ }
    throw new Error(detail)
  }
  return response.json() as Promise<T>
}

export const api = {
  health: () => request<Health>('/health'),
  stats: () => request<Stats>('/api/v1/stats'),
  incidents: (limit = 250) => request<Incident[]>(`/api/v1/incidents?limit=${limit}`),
  agents: () => request<Agent[]>('/api/v1/agents'),
  plugins: () => request<Plugin[]>('/api/v1/plugins'),
  datasets: () => request<Dataset[]>('/api/v1/datasets'),
  preflight: () => request<Preflight>('/api/v1/preflight'),
  updateStatus: (id:string, status:IncidentStatus) => request<Incident>(`/api/v1/incidents/${id}/status`, {
    method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({status}),
  }),
  loadDemo: () => request<IngestResponse>('/api/v1/demo/load', { method:'POST' }),
  upload: async (file:File, adapter?:string) => {
    const form = new FormData(); form.append('file', file); if (adapter) form.append('adapter', adapter)
    return request<IngestResponse>('/api/v1/ingest/file', { method:'POST', body:form })
  },
}
