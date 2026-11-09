"""Fail-closed contracts for future human-approved playbook action adapters.

No adapter is registered or executable in this increment. This module defines
stable metadata, idempotency derivation and the timeout/compensation interface
that a future integration must satisfy before it can be enabled.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Protocol


MAX_ACTION_TIMEOUT_SECONDS = 30
MIN_ACTION_TIMEOUT_SECONDS = 1
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    version: str
    description: str
    target_type: str
    timeout_seconds: int
    requires_approval: bool
    requires_independent_approver: bool
    idempotency_required: bool
    compensation_action_id: str
    enabled: bool = False
    adapter_registered: bool = False

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


# Intentionally descriptive only: the provider adapter is not implemented,
# registered, or enabled. A deployment cannot activate it through API input.
ACTION_CATALOG: dict[str, ActionSpec] = {
    "wazuh.agent_isolate": ActionSpec(
        action_id="wazuh.agent_isolate",
        version="1.0.0",
        description="Isolate a registered Wazuh agent from network activity.",
        target_type="registered_wazuh_agent",
        timeout_seconds=15,
        requires_approval=True,
        requires_independent_approver=True,
        idempotency_required=True,
        compensation_action_id="wazuh.agent_unisolate",
    ),
}


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    target_id: str
    parameters: dict[str, Any]
    idempotency_key: str
    approval_id: int


@dataclass(frozen=True)
class ActionResult:
    status: str
    provider_reference: str | None
    safe_summary: str
    compensation_reference: str | None = None


class ActionAdapter(Protocol):
    """Provider adapters must implement bounded execution and compensation."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        """Execute one allowlisted action using the supplied idempotency key."""
        ...

    async def compensate(self, request: ActionRequest, result: ActionResult) -> ActionResult:
        """Attempt the declared compensating action; never silently claim rollback."""
        ...


def derive_idempotency_key(
    approval_id: int,
    action_id: str,
    target_id: str,
    parameters: dict[str, Any],
) -> str:
    """Return a stable SHA-256 key for one approved action request."""
    if approval_id < 1 or not action_id or not target_id:
        raise ValueError("Approval, action and target identifiers are required")
    canonical = json.dumps(
        {
            "approval_id": approval_id,
            "action_id": action_id,
            "target_id": target_id,
            "parameters": parameters,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_action_contract(spec: ActionSpec) -> None:
    """Reject unsafe adapter metadata before a future adapter can be registered."""
    if not MIN_ACTION_TIMEOUT_SECONDS <= spec.timeout_seconds <= MAX_ACTION_TIMEOUT_SECONDS:
        raise ValueError("Action timeout must be between 1 and 30 seconds")
    if not spec.requires_approval or not spec.requires_independent_approver:
        raise ValueError("External actions require independent human approval")
    if not spec.idempotency_required:
        raise ValueError("External actions must require an idempotency key")
    if not spec.compensation_action_id:
        raise ValueError("External actions must declare a compensation action")
    if spec.enabled and not spec.adapter_registered:
        raise ValueError("An action cannot be enabled without a registered adapter")


def validate_idempotency_key(value: str) -> str:
    if not IDEMPOTENCY_KEY_PATTERN.fullmatch(value):
        raise ValueError("Idempotency key must be a SHA-256 hex digest")
    return value



class ActionAdapterTimeout(TimeoutError):
    """Raised when an adapter exceeds its server-enforced execution deadline."""


def _require_executable_adapter(spec: ActionSpec) -> None:
    validate_action_contract(spec)
    if not spec.enabled or not spec.adapter_registered:
        raise RuntimeError("Action adapter is not registered and enabled")


async def execute_with_timeout(
    adapter: ActionAdapter,
    request: ActionRequest,
    spec: ActionSpec,
) -> ActionResult:
    """Execute only a registered adapter and enforce its declared deadline."""
    _require_executable_adapter(spec)
    validate_idempotency_key(request.idempotency_key)
    try:
        return await asyncio.wait_for(adapter.execute(request), timeout=spec.timeout_seconds)
    except asyncio.TimeoutError as exc:
        raise ActionAdapterTimeout("Action adapter exceeded its execution deadline") from exc


async def compensate_with_timeout(
    adapter: ActionAdapter,
    request: ActionRequest,
    result: ActionResult,
    spec: ActionSpec,
) -> ActionResult:
    """Run the declared compensation path with the same bounded deadline."""
    _require_executable_adapter(spec)
    validate_idempotency_key(request.idempotency_key)
    try:
        return await asyncio.wait_for(
            adapter.compensate(request, result),
            timeout=spec.timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        raise ActionAdapterTimeout("Action compensation exceeded its deadline") from exc
