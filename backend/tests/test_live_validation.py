from pathlib import Path
from types import SimpleNamespace

from scripts.validate_integrations import (
    DETECTION_HEARTBEAT,
    NUCLEI_HEARTBEAT,
    detection_worker_check,
    nuclei_worker_check,
    parse_env_file,
    summarize,
)


class FakeRedis:
    def __init__(self, values=None, error=None):
        self.values = values or {}
        self.error = error

    def get(self, key):
        if self.error:
            raise self.error
        return self.values.get(key)


def test_parse_env_file_supports_export_quotes_and_ignores_comments(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        '# comment\nWAZUH_MANAGER_URL=https://manager.example.test\n'
        'export WAZUH_MANAGER_USERNAME="ops reader"\n'
        "WAZUH_MANAGER_PASSWORD='a=b=c'\nINVALID LINE\n",
        encoding="utf-8",
    )
    assert parse_env_file(env_file) == {
        "WAZUH_MANAGER_URL": "https://manager.example.test",
        "WAZUH_MANAGER_USERNAME": "ops reader",
        "WAZUH_MANAGER_PASSWORD": "a=b=c",
    }


def test_parse_env_file_missing_file_is_empty(tmp_path: Path):
    assert parse_env_file(tmp_path / "missing.env") == {}


def test_summary_fails_when_any_configured_check_fails():
    overall, counts = summarize([
        {"name": "wazuh_manager", "status": "passed", "detail": "ok"},
        {"name": "wazuh_indexer", "status": "failed", "detail": "TimeoutException"},
    ])
    assert overall == "failed"
    assert counts == {"passed": 1, "failed": 1}


def test_summary_distinguishes_unconfigured_from_healthy():
    overall, counts = summarize([
        {"name": "wazuh_manager", "status": "skipped", "detail": "Not configured"},
        {"name": "nuclei", "status": "skipped", "detail": "Disabled"},
    ])
    assert overall == "no_configured_integrations"
    assert counts == {"skipped": 2}


def test_summary_reports_partial_when_provider_was_not_probed():
    overall, counts = summarize([
        {"name": "wazuh_indexer", "status": "passed", "detail": "ok"},
        {"name": "virustotal", "status": "not_probed", "detail": "No quota used"},
    ])
    assert overall == "partial"
    assert counts == {"passed": 1, "not_probed": 1}


def test_summary_passes_only_when_all_configured_checks_pass():
    overall, counts = summarize([
        {"name": "wazuh_manager", "status": "passed", "detail": "ok"},
        {"name": "crowdsec_lapi", "status": "skipped", "detail": "Not configured"},
    ])
    assert overall == "passed"
    assert counts == {"passed": 1, "skipped": 1}


def test_nuclei_worker_is_skipped_when_both_execution_flags_are_disabled():
    config = SimpleNamespace(nuclei_enabled=False, nuclei_worker_enabled=False)
    result = nuclei_worker_check(config, FakeRedis())
    assert result["status"] == "skipped"


def test_nuclei_worker_rejects_mismatched_enablement_flags():
    config = SimpleNamespace(nuclei_enabled=True, nuclei_worker_enabled=False)
    result = nuclei_worker_check(config, FakeRedis())
    assert result["status"] == "failed"
    assert "both be true" in result["detail"]


def test_nuclei_worker_requires_a_live_heartbeat_when_enabled():
    config = SimpleNamespace(nuclei_enabled=True, nuclei_worker_enabled=True)
    healthy = nuclei_worker_check(config, FakeRedis({NUCLEI_HEARTBEAT: "2026-11-09T00:00:00+00:00"}))
    missing = nuclei_worker_check(config, FakeRedis())
    assert healthy["status"] == "passed"
    assert missing["status"] == "failed"


def test_detection_worker_is_required_in_production_but_optional_in_development():
    production = SimpleNamespace(environment="production")
    development = SimpleNamespace(environment="development")
    assert detection_worker_check(production, FakeRedis())["status"] == "failed"
    assert detection_worker_check(development, FakeRedis())["status"] == "skipped"
    assert detection_worker_check(
        production, FakeRedis({DETECTION_HEARTBEAT: "2026-11-09T00:00:00+00:00"})
    )["status"] == "passed"


def test_worker_heartbeat_errors_are_sanitized():
    config = SimpleNamespace(nuclei_enabled=True, nuclei_worker_enabled=True)
    result = nuclei_worker_check(config, FakeRedis(error=ConnectionError("private endpoint detail")))
    assert result == {
        "name": "nuclei_worker",
        "status": "failed",
        "detail": "ConnectionError",
    }
