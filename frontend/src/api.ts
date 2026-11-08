export type UserRole = "admin" | "analyst" | "viewer";
export type Severity = "informational" | "low" | "medium" | "high" | "critical" | "unknown";
export type FindingStatus = "new" | "triaged" | "accepted" | "false_positive" | "resolved";

export interface User {
  id: number;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}
export interface Asset {
  id: number;
  name: string;
  asset_type: string;
  environment: string;
  source_engine: string | null;
  external_id: string | null;
  ip_address: string | null;
  os_name: string | null;
  agent_status: string | null;
  last_seen_at: string | null;
  created_at: string;
}
export interface Finding {
  id: number;
  source_engine: string;
  source_native_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  status: FindingStatus;
  asset_id: number | null;
  evidence_uri: string | null;
  first_seen_at: string;
  last_seen_at: string;
}
export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "closed";
export interface Incident {
  id: number;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  description: string | null;
  assigned_to_user_id: number | null;
  resolution: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}
export interface WazuhHealth {
  integration: string;
  configured: boolean;
  status: "not_configured" | "healthy" | "unhealthy";
}
export interface CrowdSecHealth { integration: string; configured: boolean; status: "not_configured" | "healthy" | "unhealthy"; capability: "read_active_decisions"; }
export interface CrowdSecCollection { integration: string; received: number; inserted: number; updated: number; truncated_possible: boolean; max_results: number; data_scope: "active_decisions_only"; }
export interface WazuhManagerHealth {integration:string;configured:boolean;status:"not_configured"|"healthy"|"unhealthy";capability:"read_agent_inventory";}
export interface WazuhManagerSync {integration:string;received:number;created:number;updated:number;unchanged:number;skipped:number;truncated_possible:boolean;max_agents:number;data_scope:"registered_agents_only";}
export interface WazuhCollection {
  integration: string;
  since: string;
  received: number;
  inserted: number;
  updated: number;
  truncated_possible: boolean;
  max_results: number;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1").replace(/\/$/, "");
const TOKEN_KEY = "opsaegis.access_token";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getAccessToken(): string | null {
  return window.sessionStorage.getItem(TOKEN_KEY);
}
export function saveAccessToken(token: string): void {
  window.sessionStorage.setItem(TOKEN_KEY, token);
}
export function clearAccessToken(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, options: RequestInit = {}, authenticated = true): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (authenticated) {
    const token = getAccessToken();
    if (token) headers.set("Authorization", "Bearer " + token);
  }

  let response: Response;
  try {
    response = await fetch(API_BASE_URL + path, { ...options, headers });
  } catch {
    throw new ApiError("Cannot reach the OpsAegis API. Check that the backend is running and the API URL is correct.", 0);
  }

  if (response.status === 401 && authenticated) clearAccessToken();
  if (!response.ok) {
    let message = "Request failed (" + response.status + ").";
    try {
      const payload = await response.json() as { detail?: unknown };
      if (typeof payload.detail === "string") message = payload.detail;
      else if (Array.isArray(payload.detail)) message = payload.detail.map((item: { msg?: string }) => item.msg || "Invalid request").join("; ");
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function login(email: string, password: string): Promise<{ access_token: string; token_type: string; expires_in: number }> {
  return request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }, false);
}
export function getCurrentUser(): Promise<User> {
  return request("/auth/me");
}
export function getAssets(): Promise<Asset[]> {
  return request("/assets?skip=0&limit=200");
}
export function getFindings(): Promise<Finding[]> {
  return request("/findings?skip=0&limit=200");
}
export function getIncidents(): Promise<Incident[]> {
  return request("/incidents?skip=0&limit=200");
}
export function getWazuhHealth(): Promise<WazuhHealth> {
  return request("/integrations/wazuh/health");
}
export function getWazuhManagerHealth():Promise<WazuhManagerHealth>{return request("/integrations/wazuh-manager/health");}
export function syncWazuhManager():Promise<WazuhManagerSync>{return request("/integrations/wazuh-manager/sync",{method:"POST"});}
export function collectWazuh(): Promise<WazuhCollection> {
  return request("/integrations/wazuh/collect", { method: "POST" });
}

export function getCrowdSecHealth(): Promise<CrowdSecHealth> { return request("/integrations/crowdsec/health"); }
export function collectCrowdSec(): Promise<CrowdSecCollection> { return request("/integrations/crowdsec/collect", { method: "POST" }); }

export interface NucleiHealth { integration: string; configured: boolean; status: "healthy" | "not_configured"; execution_enabled: boolean; profile: "safe"; }
export interface NucleiTarget { id: number; name: string; url: string; authorization_reference: string; asset_id:number|null; enabled: boolean; created_at: string; }
export interface NucleiScan { id: number; target_id: number; status: string; profile: string; started_at: string | null; finished_at: string | null; findings_count: number; error_code: string | null; created_at: string; }
export const getNucleiHealth = (): Promise<NucleiHealth> => request("/integrations/nuclei/health");
export const getNucleiTargets = (): Promise<NucleiTarget[]> => request("/integrations/nuclei/targets");
export const getNucleiScans = (): Promise<NucleiScan[]> => request("/integrations/nuclei/scans");
export const registerNucleiTarget = (payload: {name:string;url:string;authorization_reference:string;asset_id?:number|null}): Promise<NucleiTarget> =>
  request("/integrations/nuclei/targets",{method:"POST",body:JSON.stringify(payload)});
export const startNucleiScan = (id:number): Promise<{scan:NucleiScan;received:number;inserted:number;updated:number}> =>
  request("/integrations/nuclei/targets/"+id+"/scans",{method:"POST",body:JSON.stringify({profile:"safe"})});

export interface ShannonHealth {
  integration: string; configured: boolean;
  status: "not_configured" | "healthy" | "unhealthy";
  execution_enabled: boolean; mode: "external_isolated_runner";
}
export interface ShannonTarget {
  id: number; name: string; target_url: string; source_repository: string;
  authorization_reference: string; enabled: boolean; created_at: string;
}
export interface ShannonScan {
  id: number; target_id: number; runner_job_id: string | null; status: string;
  findings_count: number; started_at: string | null; finished_at: string | null;
  error_code: string | null; created_at: string;
}
export interface ShannonSync { scan: ShannonScan; received: number; inserted: number; updated: number; }
export const getShannonHealth = (): Promise<ShannonHealth> => request("/integrations/shannon/health");
export const getShannonTargets = (): Promise<ShannonTarget[]> => request("/integrations/shannon/targets");
export const getShannonScans = (): Promise<ShannonScan[]> => request("/integrations/shannon/scans");
export const registerShannonTarget = (payload: {
  name: string; target_url: string; source_repository: string; authorization_reference: string;
}): Promise<ShannonTarget> => request("/integrations/shannon/targets", { method: "POST", body: JSON.stringify(payload) });
export const startShannonScan = (id: number): Promise<{ scan: ShannonScan }> =>
  request("/integrations/shannon/targets/" + id + "/scans", { method: "POST" });
export const syncShannonScan = (id: number): Promise<ShannonSync> =>
  request("/integrations/shannon/scans/" + id + "/sync", { method: "POST" });

export function updateFindingStatus(id: number, status: FindingStatus): Promise<Finding> {
  return request("/findings/" + id + "/status", { method: "PATCH", body: JSON.stringify({ status }) });
}
export function updateIncident(id: number, payload: { status?: IncidentStatus; assigned_to_user_id?: number | null; resolution?: string }): Promise<Incident> {
  return request("/incidents/" + id, { method: "PATCH", body: JSON.stringify(payload) });
}

export interface DetectionRule {
  key: string; name: string; description: string; sources: string[];
  default_threshold: number; default_window_minutes: number; severity: string; enabled: boolean;
}
export interface Detection {
  id: number; status: DetectionStatus; acknowledged_at: string | null; resolved_at: string | null; rule_key: string; fingerprint: string; title: string; description: string;
  severity: Severity; finding_ids: number[]; evidence: Record<string, unknown>;
  incident_id: number | null; created_at: string; last_seen_at: string;
}
export interface DetectionEvaluation {
  window_minutes: number; auth_threshold: number; findings_considered: number;
  candidates: number; created: number; refreshed: number; incidents_created: number; detection_ids: number[];
}
export const getDetections = (): Promise<Detection[]> => request("/detections?skip=0&limit=100");
export const getDetectionRules = (): Promise<DetectionRule[]> => request("/detections/rules");
export const evaluateDetections = (): Promise<DetectionEvaluation> => request("/detections/evaluate?window_minutes=15&auth_threshold=3", { method: "POST" });

export type DetectionStatus = "new" | "acknowledged" | "investigating" | "resolved";
export interface DetectionScheduler {
  enabled: boolean; interval_seconds: number; window_minutes: number; auth_threshold: number;
  updated_at: string; next_run_at: string | null; last_scheduled_at: string | null;
  worker_status: "online" | "offline" | "unknown"; redis_status: "connected" | "unavailable" | "unknown";
}
export interface ScheduledDetectionRun {
  id: number; status: "queued" | "running" | "retrying" | "succeeded" | "failed";
  attempts: number; window_minutes: number; auth_threshold: number;
  next_attempt_at: string; started_at: string | null; finished_at: string | null;
  error_code: string | null; created_at: string;
}
export interface DetectionNotification {
  id: number; detection_id: number; severity: Severity; title: string;
  message: string; created_at: string; read_at: string | null;
}
export const getDetectionScheduler = (): Promise<DetectionScheduler> => request("/detections/scheduler");
export const updateDetectionScheduler = (payload: Pick<DetectionScheduler, "enabled" | "interval_seconds" | "window_minutes" | "auth_threshold">): Promise<DetectionScheduler> =>
  request("/detections/scheduler", { method: "PUT", body: JSON.stringify(payload) });
export const getScheduledDetectionRuns = (): Promise<ScheduledDetectionRun[]> => request("/detections/runs?limit=20");
export const getDetectionNotifications = (): Promise<DetectionNotification[]> => request("/detections/notifications?limit=50");
export const markDetectionNotificationRead = (id: number): Promise<DetectionNotification> =>
  request("/detections/notifications/" + id + "/read", { method: "PATCH" });
export const updateDetectionStatus = (id: number, status: DetectionStatus): Promise<Detection> =>
  request("/detections/" + id + "/status", { method: "PATCH", body: JSON.stringify({ status }) });


export type IOCType = "ip" | "domain" | "url" | "hash";
export interface ThreatIntelProviderResult { status:string; verdict:"malicious"|"suspicious"|"clean"|"unknown"; risk_score:number|null; details:Record<string,unknown>; }
export interface ThreatIntelIOC {
 id:number;indicator_type:IOCType;indicator_value:string;verdict:"malicious"|"suspicious"|"clean"|"unknown";
 risk_score:number|null;provider_results:{virustotal:ThreatIntelProviderResult;abuseipdb:ThreatIntelProviderResult};
 enriched_at:string|null;created_at:string;cached?:boolean;
}
export interface ThreatIntelProviders { virustotal:{configured:boolean;status:string};abuseipdb:{configured:boolean;status:string};cache_ttl_seconds:number; }
export const getThreatIntelProviders=():Promise<ThreatIntelProviders>=>request("/threat-intel/providers");
export const getThreatIntelIOCs=():Promise<ThreatIntelIOC[]>=>request("/threat-intel/iocs?skip=0&limit=100");
export const enrichThreatIndicator=(payload:{indicator_type:IOCType;indicator_value:string;force_refresh?:boolean}):Promise<ThreatIntelIOC>=>request("/threat-intel/enrich",{method:"POST",body:JSON.stringify(payload)});


export interface WazuhVulnerabilitySync {integration:string;received:number;total_hits:number;created:number;updated:number;unmapped:number;skipped:number;truncated_possible:boolean;max_results:number;data_scope:string;}
export const syncWazuhVulnerabilities=():Promise<WazuhVulnerabilitySync>=>request("/integrations/wazuh-vulnerabilities/sync",{method:"POST"});
export type VulnerabilityStatus = "open" | "in_progress" | "accepted" | "remediated" | "false_positive";
export interface Vulnerability {
 id:number;cve_id:string;finding_id:number;asset_id:number|null;cvss_score:number|null;cvss_version:string|null;
 cvss_severity:string|null;description:string|null;published_at:string|null;nvd_modified_at:string|null;
 nvd_data_updated_at:string|null;nvd_url:string;status:VulnerabilityStatus;remediation_notes:string|null;
 first_seen_at:string;last_seen_at:string;updated_at:string;cached?:boolean;
}
export const getVulnerabilities=(filters:{severity?:string;status?:VulnerabilityStatus;asset_id?:number;q?:string}={}):Promise<Vulnerability[]>=>{
 const params=new URLSearchParams({skip:"0",limit:"200"});
 Object.entries(filters).forEach(([k,v])=>{if(v!==undefined&&v!=="")params.set(k,String(v));});
 return request("/vulnerabilities?"+params.toString());
};
export const enrichVulnerability=(id:number,force=false):Promise<Vulnerability>=>request("/vulnerabilities/"+id+"/enrich?force="+String(force),{method:"POST"});
export const updateVulnerability=(id:number,payload:{status?:VulnerabilityStatus;remediation_notes?:string|null}):Promise<Vulnerability>=>request("/vulnerabilities/"+id,{method:"PATCH",body:JSON.stringify(payload)});
