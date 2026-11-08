export type EngineHealthStatus = "healthy" | "unhealthy" | "not_configured";
export type EngineHealthName = "Nuclei" | "Shannon";

export interface EngineHealthSnapshot {
  status: EngineHealthStatus;
  configured: boolean;
  execution_enabled: boolean;
}

export interface EngineHealthPresentation {
  status: EngineHealthStatus | "unknown";
  label: string;
  detail: string;
}

/**
 * Convert the backend health contract into an honest, role-aware SOC card.
 * A reachable adapter is not treated as executable unless the backend says so.
 */
export function describeEngineHealth(
  engine: EngineHealthName,
  health: EngineHealthSnapshot | null,
  canOperate: boolean,
  failed = false,
): EngineHealthPresentation {
  if (!canOperate) {
    return {
      status: "unknown",
      label: "Restricted",
      detail: "Health details are available to administrator and analyst roles.",
    };
  }

  if (failed) {
    return {
      status: "unknown",
      label: "Unknown",
      detail: "The backend health check could not be completed. Refresh to retry.",
    };
  }

  if (!health) {
    return {
      status: "unknown",
      label: "Checking",
      detail: "Checking the backend health endpoint…",
    };
  }

  if (health.status === "unhealthy") {
    return {
      status: "unhealthy",
      label: "Unhealthy",
      detail: engine === "Shannon"
        ? "The external runner is configured but its health check failed."
        : "The configured scanner is not currently healthy.",
    };
  }

  if (health.status === "healthy" && health.execution_enabled) {
    return {
      status: "healthy",
      label: "Healthy",
      detail: engine === "Shannon"
        ? "External isolated runner health check succeeded; dispatch is enabled."
        : "Nuclei binary is available and safe-profile execution is enabled.",
    };
  }

  if (health.configured) {
    return {
      status: "not_configured",
      label: "Execution disabled",
      detail: "The integration is configured, but the backend has not enabled execution.",
    };
  }

  return {
    status: "not_configured",
    label: "Not configured",
    detail: engine === "Shannon"
      ? "Configure the external HTTPS runner URL and token, then enable SHANNON_ENABLED."
      : "Enable NUCLEI_ENABLED and install the configured Nuclei binary in the backend runtime.",
  };
}
