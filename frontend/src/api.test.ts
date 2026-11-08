import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, clearAccessToken, getAccessToken, getAssets, getNucleiHealth, getShannonHealth, login, saveAccessToken } from "./api";

function mockResponse(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  } as Response;
}

describe("OpsAegis API client", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("sends login credentials without an existing bearer token", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200, {
      access_token: "test-token",
      token_type: "bearer",
      expires_in: 900,
    }));

    const result = await login("analyst@example.com", "correct-password");

    expect(result.access_token).toBe("test-token");
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/auth/login",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
        body: JSON.stringify({ email: "analyst@example.com", password: "correct-password" }),
      }),
    );
    const options = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(new Headers(options.headers).has("Authorization")).toBe(false);
  });

  it("attaches the session token to protected API requests", async () => {
    saveAccessToken("session-token");
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200, []));

    await getAssets();

    const options = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(new Headers(options.headers).get("Authorization")).toBe("Bearer session-token");
  });

  it("clears the session token when the API rejects an expired session", async () => {
    saveAccessToken("expired-token");
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(401, { detail: "Valid bearer token required" }));

    await expect(getAssets()).rejects.toMatchObject({ status: 401 });
    expect(getAccessToken()).toBeNull();
  });

  it("surfaces API validation messages", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(422, { detail: "Invalid query" }));

    await expect(getAssets()).rejects.toEqual(expect.objectContaining({
      name: "ApiError",
      message: "Invalid query",
      status: 422,
    }));
  });

  it("retrieves Nuclei execution state from the backend health endpoint", async () => {
    const health = { integration: "nuclei", configured: true, status: "healthy", execution_enabled: true, profile: "safe" };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200, health));

    await expect(getNucleiHealth()).resolves.toEqual(health);
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/integrations/nuclei/health",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
  });

  it("retrieves Shannon runner health instead of inferring availability from configuration", async () => {
    const health = { integration: "shannon", configured: true, status: "unhealthy", execution_enabled: false, mode: "external_isolated_runner" };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200, health));

    await expect(getShannonHealth()).resolves.toEqual(health);
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/integrations/shannon/health",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
  });

  it("removes the session token on explicit sign out", () => {
    saveAccessToken("session-token");
    clearAccessToken();
    expect(getAccessToken()).toBeNull();
  });

  it("reports a useful error when the API cannot be reached", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError("network down"));

    const request = getAssets();
    await expect(request).rejects.toBeInstanceOf(ApiError);
    await expect(request).rejects.toMatchObject({ status: 0 });
  });
});
