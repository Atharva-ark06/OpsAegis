from pathlib import Path

from scripts.validate_integrations import parse_env_file, summarize


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
