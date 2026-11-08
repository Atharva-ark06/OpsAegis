import { describe, expect, it } from "vitest";
import { describeEngineHealth, EngineHealthSnapshot } from "./engineHealth";

const ready: EngineHealthSnapshot = {
  status: "healthy",
  configured: true,
  execution_enabled: true,
};

describe("engine health presentation", () => {
  it("shows a healthy Nuclei scanner only when execution is enabled", () => {
    expect(describeEngineHealth("Nuclei", ready, true)).toEqual({
      status: "healthy",
      label: "Healthy",
      detail: "Nuclei binary is available and safe-profile execution is enabled.",
    });
  });

  it("shows a healthy external Shannon runner when its health check succeeds", () => {
    expect(describeEngineHealth("Shannon", ready, true).label).toBe("Healthy");
  });

  it("does not confuse a missing Nuclei binary with an unhealthy configured service", () => {
    const missing = { status: "not_configured", configured: false, execution_enabled: false } as const;
    expect(describeEngineHealth("Nuclei", missing, true).label).toBe("Not configured");
  });

  it("reports a configured but disabled integration without claiming it is healthy", () => {
    const disabled = { status: "healthy", configured: true, execution_enabled: false } as const;
    const result = describeEngineHealth("Nuclei", disabled, true);
    expect(result.status).toBe("not_configured");
    expect(result.label).toBe("Execution disabled");
  });

  it("reports a configured Shannon runner health failure", () => {
    const unhealthy = { status: "unhealthy", configured: true, execution_enabled: false } as const;
    expect(describeEngineHealth("Shannon", unhealthy, true).status).toBe("unhealthy");
  });

  it("does not expose health details to viewer roles", () => {
    const result = describeEngineHealth("Shannon", ready, false);
    expect(result.label).toBe("Restricted");
    expect(result.detail).toContain("administrator and analyst");
  });

  it("distinguishes an unavailable health request from an unconfigured engine", () => {
    const result = describeEngineHealth("Shannon", null, true, true);
    expect(result.status).toBe("unknown");
    expect(result.label).toBe("Unknown");
  });

  it("uses a checking state before the health response arrives", () => {
    expect(describeEngineHealth("Nuclei", null, true).label).toBe("Checking");
  });
});
