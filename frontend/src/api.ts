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
export function collectWazuh(): Promise<WazuhCollection> {
  return request("/integrations/wazuh/collect", { method: "POST" });
}

export function getCrowdSecHealth(): Promise<CrowdSecHealth> { return request("/integrations/crowdsec/health"); }
export function collectCrowdSec(): Promise<CrowdSecCollection> { return request("/integrations/crowdsec/collect", { method: "POST" }); }

export interface NucleiHealth { integration: string; configured: boolean; status: "healthy" | "not_configured"; execution_enabled: boolean; profile: "safe"; }
export interface NucleiTarget { id: number; name: string; url: string; authorization_reference: string; enabled: boolean; created_at: string; }
export interface NucleiScan { id: number; target_id: number; status: string; profile: string; started_at: string | null; finished_at: string | null; findings_count: number; error_code: string | null; created_at: string; }
export const getNucleiHealth = (): Promise<NucleiHealth> => request("/integrations/nuclei/health");
export const getNucleiTargets = (): Promise<NucleiTarget[]> => request("/integrations/nuclei/targets");
export const getNucleiScans = (): Promise<NucleiScan[]> => request("/integrations/nuclei/scans");
export const registerNucleiTarget = (payload: {name:string;url:string;authorization_reference:string}): Promise<NucleiTarget> =>
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
