import type {} from "./api";

export type RecoveryGuidanceCode =
  | "not_applicable"
  | "separate_approval_required"
  | "verify_provider_state"
  | "reconcile_provider_state"
  | "operator_review_required"
  | "verify_unisolated_state"
  | "manual_recovery_required";

declare module "./api" {
  interface PlaybookExecutionRecord {
    recovery_guidance: RecoveryGuidanceCode;
  }
}

export interface RecoveryGuidance {
  title: string;
  detail: string;
  tone: "neutral" | "caution" | "warning";
}

const GUIDANCE: Record<RecoveryGuidanceCode, RecoveryGuidance> = {
  not_applicable: {
    title: "No recovery step indicated",
    detail: "This ledger state does not indicate a completed provider action. Do not infer that isolation or recovery occurred.",
    tone: "neutral",
  },
  separate_approval_required: {
    title: "Separate approval required",
    detail: "If unisolation is needed, obtain a distinct approval for the exact target and verify provider state independently. No automatic compensation is available.",
    tone: "caution",
  },
  verify_provider_state: {
    title: "Verify provider state",
    detail: "A failed request does not prove that no side effect occurred. Check the authorized provider state before deciding on recovery.",
    tone: "caution",
  },
  reconcile_provider_state: {
    title: "Outcome unknown — stop and reconcile",
    detail: "Do not retry or assume success/failure. Use an authorized read-only provider-state check; keep the outcome unknown if it cannot be confirmed.",
    tone: "warning",
  },
  operator_review_required: {
    title: "Operator review required",
    detail: "The ledger records a compensation state, but this repository has no dispatcher. Do not infer that a provider request was sent or completed.",
    tone: "caution",
  },
  verify_unisolated_state: {
    title: "Independently verify unisolation",
    detail: "A succeeded ledger state is not proof of restored endpoint connectivity. Confirm the provider's unisolated state before closing recovery.",
    tone: "caution",
  },
  manual_recovery_required: {
    title: "Manual recovery required",
    detail: "Stop automatic retries. Reconcile the actual provider state, preserve the audit trail and escalate through the approved operator process.",
    tone: "warning",
  },
};

export function getRecoveryGuidance(code: string): RecoveryGuidance {
  return GUIDANCE[code as RecoveryGuidanceCode] ?? GUIDANCE.manual_recovery_required;
}
