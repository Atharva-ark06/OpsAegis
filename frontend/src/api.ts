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
  until?: string;
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
  if (options.body && !(typeof FormData !== "undefined" && options.body instanceof FormData) && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
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
      if (typeof payload.detail === "string") {
        message = payload.detail;
      } else if (Array.isArray(payload.detail)) {
        message = payload.detail.map((item: unknown) => {
          if (typeof item === "string") return item;
          if (item && typeof item === "object" && "msg" in item && typeof item.msg === "string") return item.msg;
          return "Invalid request";
        }).join("; ");
      }
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  try {
    return await response.json() as T;
  } catch {
    throw new ApiError("The OpsAegis API returned an invalid or empty JSON response.", response.status);
  }
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
export function createIncident(payload: {title:string;severity:Severity;description?:string}): Promise<Incident> {
  return request("/incidents", {method:"POST", body:JSON.stringify(payload)});
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
 id:number;cve_id:string;finding_id:number;asset_id:number|null;source_engine?:string|null;agent_id?:string|null;agent_name?:string|null;host_os?:string|null;package_name?:string|null;package_version?:string|null;package_type?:string|null;package_architecture?:string|null;cvss_score:number|null;cvss_version:string|null;
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


export interface CollectionSchedule {
  source: string; description: string; enabled: boolean; interval_seconds: number; lookback_minutes: number;
  next_run_at: string | null; last_run_at: string | null; updated_at: string | null;
}
export interface CollectionRun {
  id: number; source: string; status: "queued" | "running" | "retrying" | "succeeded" | "failed";
  attempts: number; lookback_minutes: number; received: number; created: number; updated: number; skipped: number;
  truncated_possible: boolean; error_code: string | null; next_attempt_at: string;
  started_at: string | null; finished_at: string | null; window_start_at: string | null; window_end_at: string | null;
  duration_ms: number | null; created_at: string;
}
export const getCollectionSchedules = (): Promise<CollectionSchedule[]> => request("/collections/schedules");
export const updateCollectionSchedule = (source: string, payload: Pick<CollectionSchedule, "enabled" | "interval_seconds" | "lookback_minutes">): Promise<CollectionSchedule> =>
  request("/collections/schedules/" + encodeURIComponent(source), { method: "PUT", body: JSON.stringify(payload) });
export const requestCollectionRun = (source: string): Promise<CollectionRun> =>
  request("/collections/" + encodeURIComponent(source) + "/run", { method: "POST" });
export const getCollectionRuns = (): Promise<CollectionRun[]> => request("/collections/runs?limit=50");

export interface IncidentTimelineEvent {
  id: string; type: string; occurred_at: string; actor_user_id: number | null;
  summary: string; details: Record<string, unknown>; provenance: string;
}
export interface IncidentTimeline {
  incident_id: number; generated_at: string; events: IncidentTimelineEvent[];
  limits: Record<string, number>;
}
export const getIncidentTimeline = (id: number): Promise<IncidentTimeline> => request("/incidents/" + id + "/timeline");
export const addIncidentNote = (id: number, note: string): Promise<{id:number;incident_id:number;author_user_id:number;note:string;created_at:string}> =>
  request("/incidents/" + id + "/notes", { method: "POST", body: JSON.stringify({ note }) });
export async function downloadIncidentEvidence(id: number): Promise<void> {
  const payload = await request<Record<string, unknown>>("/incidents/" + id + "/evidence-export");
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "opsaegis-incident-" + id + "-evidence.json";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export interface IncidentEvidenceAttachment {
  id: number; filename: string; media_type: string; size_bytes: number; sha256: string;
  uploaded_by_user_id: number | null; created_at: string; expires_at: string;
}
export const getIncidentAttachments = (id: number): Promise<{incident_id:number;items:IncidentEvidenceAttachment[];limit:number}> =>
  request("/incidents/" + id + "/attachments");
export const uploadIncidentAttachment = (id: number, file: File): Promise<IncidentEvidenceAttachment> => {
  const form = new FormData();
  form.append("file", file);
  return request("/incidents/" + id + "/attachments", { method: "POST", body: form });
};
export async function downloadIncidentAttachment(id: number, attachment: IncidentEvidenceAttachment): Promise<void> {
  const headers = new Headers();
  const token = getAccessToken();
  if (token) headers.set("Authorization", "Bearer " + token);
  let response: Response;
  try {
    response = await fetch(API_BASE_URL + "/incidents/" + id + "/attachments/" + attachment.id, { headers });
  } catch {
    throw new ApiError("Cannot reach the OpsAegis API.", 0);
  }
  if (!response.ok) {
    let message = "Attachment download failed (" + response.status + ").";
    try { const payload = await response.json() as {detail?: string}; if (payload.detail) message = payload.detail; } catch { /* status fallback */ }
    throw new ApiError(message, response.status);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = attachment.filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}


export interface OperationsTrendPoint {
  start: string; collection_runs: number; collection_succeeded: number; collection_failed: number;
  detections: number; incidents: number; resolved_incidents: number;
}
export interface OperationsTrends {
  window: { since: string; until: string; timezone: "UTC" };
  bucket: "day" | "week"; points: OperationsTrendPoint[]; rows_limited: boolean; limitations: string[];
}
export interface OperationalThresholds {
  collection_failure_rate_percent: number; source_stale_after_minutes: number;
  detection_to_incident_minutes: number; incident_resolution_minutes: number; updated_at: string | null; active_alerts?: {code:string;source:string|null;message:string}[]; evaluation_window?: {since:string;until:string;timezone:string};
}
export interface OperationsReport {
  generated_at:string; window:{since:string;until:string;timezone:"UTC"};
  collection:{sources_configured:number;sources_with_successful_runs:number;sources:Array<{
    source:string;description:string;enabled:boolean;runs:number;successful_runs:number;failed_runs:number;
    failure_rate:number|null;received:number;created:number;updated:number;skipped:number;
    truncated_possible_runs:number;latest_success_at:string|null;freshness_age_seconds:number|null;
    freshness:"fresh"|"stale"|"never_succeeded";
  }>;rows_limited:boolean};
  response:{detections_linked_to_incidents:number;mean_detection_to_incident_seconds:number|null;
    incidents_resolved:number;mean_incident_to_resolution_seconds:number|null;resolution_metric_source:string;
    rows_limited:boolean};
  data_quality:{stale_sources:string[];never_succeeded_sources:string[];truncated_collection_runs:number;limitations:string[]};
}
export const getOperationsReport = (since:string,until:string):Promise<OperationsReport> =>
  request("/reports/operations?"+new URLSearchParams({since,until}).toString());
export async function downloadOperationsReport(format:"json"|"csv",since:string,until:string):Promise<void> {
  const headers=new Headers();
  const token=getAccessToken();
  if(token) headers.set("Authorization","Bearer "+token);
  const path="/reports/operations/export?"+new URLSearchParams({format,since,until}).toString();
  let response:Response;
  try { response=await fetch(API_BASE_URL+path,{headers}); }
  catch { throw new ApiError("Cannot reach the OpsAegis API.",0); }
  if(response.status===401) clearAccessToken();
  if(!response.ok) {
    let message="Report export failed ("+response.status+").";
    try {const payload=await response.json() as {detail?:string};if(payload.detail)message=payload.detail;} catch {/* status fallback */}
    throw new ApiError(message,response.status);
  }
  const blob=await response.blob();
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement("a");
  anchor.href=url;
  anchor.download="opsaegis-operations-report-"+since.slice(0,10)+"-to-"+until.slice(0,10)+"."+format;
  document.body.appendChild(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(url);
}
export const getOperationsTrends = (since: string, until: string, bucket: "day" | "week" = "day"): Promise<OperationsTrends> =>
  request("/reports/operations/trends?" + new URLSearchParams({since, until, bucket}).toString());
export const getOperationalThresholds = (): Promise<OperationalThresholds> => request("/reports/operations/thresholds");
export const updateOperationalThresholds = (payload: Omit<OperationalThresholds, "updated_at">): Promise<OperationalThresholds> =>
  request("/reports/operations/thresholds", {method:"PUT", body:JSON.stringify(payload)});


export type PlaybookExecutionStatus = "pending" | "claimed" | "executing" | "succeeded" | "failed" | "outcome_unknown";
export type PlaybookCompensationStatus = "not_requested" | "requested" | "executing" | "succeeded" | "failed" | "outcome_unknown";
export interface PlaybookExecutionRecord {
  id: number;
  approval_id: number;
  action_id: string;
  action_version: string;
  status: PlaybookExecutionStatus;
  compensation_status: PlaybookCompensationStatus;
  created_at: string | null;
  updated_at: string | null;
  started_at: string | null;
  completed_at: string | null;
}
export interface PlaybookExecutionPage {
  items: PlaybookExecutionRecord[];
  count: number;
  limit: number;
  offset: number;
  has_more: boolean;
  execution_enabled: false;
}
export const getPlaybookExecutions = (
  filters: { status?: PlaybookExecutionStatus; limit?: number; offset?: number } = {},
): Promise<PlaybookExecutionPage> => {
  const params = new URLSearchParams({
    limit: String(filters.limit ?? 50),
    offset: String(filters.offset ?? 0),
  });
  if (filters.status) params.set("status", filters.status);
  return request("/playbooks/executions?" + params.toString());
};


export interface PlaybookDefinition {
  id: string; name: string; version: string; description: string;
  required_roles: string[];
  inputs: Record<string, {type:string;minimum?:number;maximum?:number;default?:number;required?:boolean}>;
  preconditions: string[]; execution_mode: "dry_run_only"; external_actions_enabled: false;
}
export interface PlaybookAction {
  action_id: string; version: string; description: string; target_type: string;
  timeout_seconds: number; requires_approval: boolean; requires_independent_approver: boolean;
  idempotency_required: boolean; compensation_action_id: string;
  enabled: boolean; adapter_registered: boolean; execution_available: false; reason: string;
}
export interface PlaybookPreview {
  playbook_id: string; playbook_version: string; status: "preview_only"; executed: false;
  external_actions_enabled: false; generated_at: string;
  inputs: {incident_id:number;lookback_minutes:number};
  preconditions: {incident_exists:boolean;operator_role:string;passed:boolean};
  incident: {id:number;title:string;severity:string;status:string};
  observed_context: {detections_in_window:number;linked_findings:number;affected_asset_ids:number[];window_start:string;window_end:string;possible_truncation:boolean};
  proposed_checklist: string[]; side_effects: string[]; limitations: string[];
}
export type PlaybookApprovalStatus = "pending" | "approved" | "rejected" | "expired";
export interface PlaybookApproval {
  id:number;playbook_id:string;playbook_version:string;incident_id:number;
  requested_by_user_id:number;reviewed_by_user_id:number|null;
  input_parameters:{lookback_minutes:number};request_reason:string;decision_reason:string|null;
  status:PlaybookApprovalStatus;expires_at:string;created_at:string;reviewed_at:string|null;
  execution_enabled:false;
}
export const getPlaybooks = ():Promise<{items:PlaybookDefinition[];count:number}> => request("/playbooks");
export const getPlaybookActions = (id:string):Promise<{playbook_id:string;items:PlaybookAction[];count:number;external_actions_enabled:false}> =>
  request("/playbooks/"+encodeURIComponent(id)+"/actions");
export const previewPlaybook = (id:string,payload:{incident_id:number;lookback_minutes:number}):Promise<PlaybookPreview> =>
  request("/playbooks/"+encodeURIComponent(id)+"/dry-run",{method:"POST",body:JSON.stringify(payload)});
export const createPlaybookApproval = (id:string,payload:{incident_id:number;lookback_minutes:number;reason:string}):Promise<PlaybookApproval> =>
  request("/playbooks/"+encodeURIComponent(id)+"/approval-requests",{method:"POST",body:JSON.stringify(payload)});
export const getPlaybookApprovals = (status:"pending"|"approved"|"rejected"|"expired"|"all"="pending"):Promise<{items:PlaybookApproval[];count:number}> =>
  request("/playbooks/approvals?status_filter="+encodeURIComponent(status));
export const decidePlaybookApproval = (id:number,payload:{decision:"approve"|"reject";reason:string}):Promise<PlaybookApproval> =>
  request("/playbooks/approvals/"+id+"/decision",{method:"POST",body:JSON.stringify(payload)});


export interface AuthSetupStatus { setup_required: boolean; setup_enabled: boolean; }
export interface AdminUser extends User {}
export function getAuthSetupStatus(): Promise<AuthSetupStatus> {
  return request("/auth/setup-status", {}, false);
}
export function bootstrapFirstAdmin(email: string, password: string, setupToken: string): Promise<AdminUser> {
  return request("/auth/bootstrap", { method: "POST", headers: { "X-Setup-Token": setupToken }, body: JSON.stringify({ email, password }) }, false);
}
export function getAdminUsers(): Promise<AdminUser[]> { return request("/auth/users?skip=0&limit=200"); }
export function createAdminUser(payload: { email: string; password: string; role: UserRole }): Promise<AdminUser> {
  return request("/auth/users", { method: "POST", body: JSON.stringify(payload) });
}
export function updateAdminUser(id: number, payload: { role?: UserRole; is_active?: boolean }): Promise<AdminUser> {
  return request("/auth/users/" + id, { method: "PATCH", body: JSON.stringify(payload) });
}
