export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'false_positive'

export interface Evidence { event_id?: string; summary: string; details: Record<string, unknown> }
export interface Incident {
  id: string; created_at: string; updated_at: string; title: string; category: string;
  severity: Severity; status: IncidentStatus; confidence: number; summary: string;
  root_cause: string; evidence: Evidence[]; analyst_checks: string[]; remediation: string[];
  validation: string[]; limitations: string[]; mitre_techniques: string[]; rule_ids: string[];
  correlation_key: string; event_count: number;
}
export interface Health { status: string; version: string; rules: number; adapters: string[]; stored_events: number }
export interface Stats { events: number; incidents: number; by_severity: Record<string, number>; by_status: Record<string, number>; generated_at: string }
export interface Agent {
  agent_id: string; hostname: string; platform: string; agent_version: string; last_seen: string;
  state: 'online' | 'stale'; event_count: number; incident_count: number;
  latest_metrics: Record<string, Record<string, number | string>>;
}
export interface Plugin { id: string; kind: 'adapter'|'detection'; distribution: string; version: string; source: string; status: string; detail?: string }
export interface Dataset { id:string; name:string; provider:string; homepage:string; download_url:string; license_url:string; domains:string[]; formats:string[]; size_note:string; license_note:string; recommended_use:string; adapter_status:'direct'|'sample_or_transform'|'transform'|'adapter_needed'; upload_instructions:string; coverage:string[] }
export interface Diagnosis { primary_issue_area:string; input_classification:string; readiness:string; summary:string; likely_causes:string[]; recommended_actions:string[]; indicators:Record<string,number>; sample_evidence:string[]; limitations:string[] }
export interface AnalysisManifest { uploaded_file:string; adapter:string; files_analyzed:string[]; events_evaluated:number; rules_evaluated:number; event_categories:Record<string,number>; event_types:Record<string,number>; sources:Record<string,number>; notes:string[] }
export interface IngestResponse { accepted_events:number; incidents:Incident[]; diagnosis?:Diagnosis; manifest?:AnalysisManifest; processing_ms:number; request_id?:string }
export interface PreflightCheck { name:string; status:'pass'|'warn'|'fail'; detail:string; action?:string }
export interface Preflight { ready:boolean; checks:PreflightCheck[] }
