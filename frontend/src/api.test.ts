import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, clearAccessToken, getAccessToken, getAssets, getNucleiHealth, getShannonHealth, getPlaybookExecutions, getPlaybooks, getPlaybookActions, previewPlaybook, createPlaybookApproval, getPlaybookApprovals, decidePlaybookApproval, getOperationsReport, downloadOperationsReport, login, saveAccessToken } from "./api";

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

  it("requests a bounded, filtered read-only playbook execution page with the session token", async () => {
    saveAccessToken("analyst-session");
    const page = {
      items: [{
        id: 7, approval_id: 12, action_id: "wazuh.agent_isolate", action_version: "1.0.0",
        status: "pending", compensation_status: "not_requested",
        created_at: "2026-11-09T10:00:00Z", updated_at: "2026-11-09T10:00:00Z",
        started_at: null, completed_at: null,
      }],
      count: 1, limit: 25, offset: 0, has_more: false, execution_enabled: false,
    };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200, page));

    await expect(getPlaybookExecutions({ status: "pending", limit: 25, offset: 0 })).resolves.toEqual(page);
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/playbooks/executions?limit=25&offset=0&status=pending",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    const options = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(new Headers(options.headers).get("Authorization")).toBe("Bearer analyst-session");
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


  it("formats structured validation errors without assuming every item is an object", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(422, {
      detail: [{ msg: "Email is required" }, "Password is required", null],
    }));

    await expect(getAssets()).rejects.toMatchObject({
      message: "Email is required; Password is required; Invalid request",
      status: 422,
    });
  });

  it("uses a status-based message when an error response is not JSON", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 502,
      json: async () => { throw new SyntaxError("not JSON"); },
    } as unknown as Response);

    await expect(getAssets()).rejects.toMatchObject({
      message: "Request failed (502).",
      status: 502,
    });
  });

  it("accepts successful no-content responses", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 204,
      json: async () => { throw new Error("204 must not parse a body"); },
    } as unknown as Response);

    await expect(getAssets()).resolves.toBeUndefined();
  });

  it("returns a useful API error when a successful response contains invalid JSON", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => { throw new SyntaxError("Unexpected token"); },
    } as unknown as Response);

    await expect(getAssets()).rejects.toMatchObject({
      name: "ApiError",
      message: "The OpsAegis API returned an invalid or empty JSON response.",
      status: 200,
    });
  });

});


  it("loads the playbook catalogue and explicitly disabled action contracts", async () => {
    const catalogue = {items:[{id:"incident-investigation",name:"Incident investigation",version:"1.0.0"}],count:1};
    const actions = {playbook_id:"incident-investigation",items:[{action_id:"wazuh.agent_isolate",enabled:false,adapter_registered:false,execution_available:false}],count:1,external_actions_enabled:false};
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200,catalogue)).mockResolvedValueOnce(mockResponse(200,actions));
    await expect(getPlaybooks()).resolves.toEqual(catalogue);
    await expect(getPlaybookActions("incident-investigation")).resolves.toEqual(actions);
    expect(fetch).toHaveBeenNthCalledWith(1,"http://localhost:8000/api/v1/playbooks",expect.objectContaining({headers:expect.any(Headers)}));
    expect(fetch).toHaveBeenNthCalledWith(2,"http://localhost:8000/api/v1/playbooks/incident-investigation/actions",expect.objectContaining({headers:expect.any(Headers)}));
  });

  it("supports preview-only playbooks and independent approval lifecycle requests", async () => {
    saveAccessToken("operator-session");
    const preview = {status:"preview_only",executed:false,external_actions_enabled:false};
    const approval = {id:4,status:"pending",execution_enabled:false};
    const decided = {id:4,status:"approved",execution_enabled:false};
    vi.mocked(fetch)
      .mockResolvedValueOnce(mockResponse(200,preview))
      .mockResolvedValueOnce(mockResponse(201,approval))
      .mockResolvedValueOnce(mockResponse(200,{items:[approval],count:1}))
      .mockResolvedValueOnce(mockResponse(200,decided));
    await expect(previewPlaybook("incident-investigation",{incident_id:9,lookback_minutes:60})).resolves.toEqual(preview);
    await expect(createPlaybookApproval("incident-investigation",{incident_id:9,lookback_minutes:60,reason:"Independent investigation review requested."})).resolves.toEqual(approval);
    await expect(getPlaybookApprovals("pending")).resolves.toEqual({items:[approval],count:1});
    await expect(decidePlaybookApproval(4,{decision:"approve",reason:"Reviewed the evidence and agree."})).resolves.toEqual(decided);
    expect(fetch).toHaveBeenNthCalledWith(1,"http://localhost:8000/api/v1/playbooks/incident-investigation/dry-run",expect.objectContaining({method:"POST"}));
    expect(fetch).toHaveBeenNthCalledWith(2,"http://localhost:8000/api/v1/playbooks/incident-investigation/approval-requests",expect.objectContaining({method:"POST"}));
    expect(fetch).toHaveBeenNthCalledWith(3,"http://localhost:8000/api/v1/playbooks/approvals?status_filter=pending",expect.objectContaining({headers:expect.any(Headers)}));
    expect(fetch).toHaveBeenNthCalledWith(4,"http://localhost:8000/api/v1/playbooks/approvals/4/decision",expect.objectContaining({method:"POST"}));
  });


  it("loads an authenticated bounded-window operations report", async () => {
    saveAccessToken("report-session");
    const report = {window:{since:"2026-11-01T00:00:00Z",until:"2026-11-10T00:00:00Z",timezone:"UTC"},collection:{sources:[]},response:{},data_quality:{}};
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(200,report));
    await expect(getOperationsReport("2026-11-01T00:00:00Z","2026-11-10T00:00:00Z")).resolves.toEqual(report);
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/reports/operations?since=2026-11-01T00%3A00%3A00Z&until=2026-11-10T00%3A00%3A00Z",
      expect.objectContaining({headers:expect.any(Headers)}),
    );
  });

  it("requests the authenticated CSV export endpoint", async () => {
    saveAccessToken("report-session");
    const createObjectURL=vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:test");
    const revokeObjectURL=vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});
    const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
    vi.mocked(fetch).mockResolvedValueOnce({
      ok:true,status:200,blob:async()=>new Blob(["metric,source,value,unit"]),
    } as Response);
    await downloadOperationsReport("csv","2026-11-01T00:00:00Z","2026-11-10T00:00:00Z");
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/reports/operations/export?format=csv&since=2026-11-01T00%3A00%3A00Z&until=2026-11-10T00%3A00%3A00Z",
      expect.objectContaining({headers:expect.any(Headers)}),
    );
    expect(click).toHaveBeenCalledOnce();
    createObjectURL.mockRestore();revokeObjectURL.mockRestore();click.mockRestore();
  });
