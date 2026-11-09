import { describe, expect, it } from "vitest";
import { getRecoveryGuidance } from "./recovery-guidance";

describe("getRecoveryGuidance", () => {
  it("keeps unknown provider outcomes in a stop-and-reconcile state", () => {
    expect(getRecoveryGuidance("reconcile_provider_state")).toMatchObject({
      tone: "warning",
      title: "Outcome unknown — stop and reconcile",
    });
  });

  it("requires a separate approval before unisolation", () => {
    expect(getRecoveryGuidance("separate_approval_required").detail).toContain("distinct approval");
  });

  it("does not treat a succeeded compensation ledger state as proof of recovery", () => {
    expect(getRecoveryGuidance("verify_unisolated_state").detail).toContain("not proof");
  });

  it("fails safely for an unknown guidance code", () => {
    expect(getRecoveryGuidance("unexpected-provider-state")).toMatchObject({
      tone: "warning",
      title: "Manual recovery required",
    });
  });
});
