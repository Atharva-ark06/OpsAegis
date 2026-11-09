from pathlib import Path
from types import SimpleNamespace

from scripts.validate_integrations import (
    DETECTION_HEARTBEAT,
    NUCLEI_HEARTBEAT,
    detection_worker_check,
    heartbeat_check,
    nuclei_worker_check,
    parse_env_file,
    summarize,
)


class FakeRedis:
    def __init__(self, values=None, error=None):
        self.values = values or {}
        self.error = error
        self.requested_keys = []

    def get(self, key):
        self.requested_keys.append(key)
        if self.error:
            raise self.error
        return self.values.get(key)


def test_parse_env_file_handles_comments_exports_quotes_and_equals(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# ignored\n"
        "PLAIN=value\n"
        "export QUOTED='two words'\n"
        'TOKEN="left=right"\n'
        "INVALID LINE\n"
        " =missing-key\n",
        encoding="utf-8",
    )

    assert parse_env_file(env_file) == {
        "PLAIN": "value",
        "QUOTED": "two words",
        "TOKEN": "left=right",
    }


def test_parse_missing_env_file_returns_empty_mapping(tmp_path: Path):
    assert parse_env_file(tmp_path / "missing.env") == {}


def test_summarize_distinguishes_no_checks_partial_and_failure():
    assert summarize([{"status": "skipped"}])[0] == "no_configured_integrations"
    assert summarize([{"status": "passed"}, {"status": "skipped"}])[0] == "passed"
    assert summarize([{"status": "passed"}, {"status": "not_probed"}])[0] == "partial"
    assert summarize([{"status": "passed"}, {"status": "failed"}])[0] == "failed"


def test_heartbeat_disabled_does_not_contact_redis():
    redis = FakeRedis()
    result = heartbeat_check("worker", redis, "heartbeat", enabled=False)

    assert result["status"] == "skipped"
    assert redis.requested_keys == []


def test_heartbeat_reports_active_worker():
    redis = FakeRedis({DETECTION_HEARTBEAT: "alive"})
    result = heartbeat_check("detection_worker", redis, DETECTION_HEARTBEAT, enabled=True)

    assert result["status"] == "passed"
    assert redis.requested_keys == [DETECTION_HEARTBEAT]


def test_heartbeat_missing_status_can_be_environment_specific():
    redis = FakeRedis()
    production = heartbeat_check(
        "detection_worker", redis, DETECTION_HEARTBEAT,
        enabled=True, missing_status="failed",
    )
    development = heartbeat_check(
        "detection_worker", redis, DETECTION_HEARTBEAT,
        enabled=True, missing_status="skipped",
    )

    assert production["status"] == "failed"
    assert development["status"] == "skipped"


def test_heartbeat_exception_exposes_only_exception_type():
    class SecretBearingError(RuntimeError):
        pass

    redis = FakeRedis(error=SecretBearingError("do-not-print-this-secret"))
    result = heartbeat_check("worker", redis, "heartbeat", enabled=True)

    assert result == {
        "name": "worker",
        "status": "failed",
        "detail": "SecretBearingError",
    }
    assert "do-not-print-this-secret" not in str(result)


def test_nuclei_disabled_skips_without_redis_access():
    config = SimpleNamespace(nuclei_enabled=False, nuclei_worker_enabled=False)
    redis = FakeRedis()

    result = nuclei_worker_check(config, redis)

    assert result["status"] == "skipped"
    assert redis.requested_keys == []


def test_nuclei_mismatched_enablement_fails_closed():
    config = SimpleNamespace(nuclei_enabled=True, nuclei_worker_enabled=False)
    redis = FakeRedis()

    result = nuclei_worker_check(config, redis)

    assert result["status"] == "failed"
    assert "must both be true" in result["detail"]
    assert redis.requested_keys == []


def test_nuclei_enabled_requires_active_worker_heartbeat():
    config = SimpleNamespace(nuclei_enabled=True, nuclei_worker_enabled=True)
    redis = FakeRedis({NUCLEI_HEARTBEAT: "alive"})

    result = nuclei_worker_check(config, redis)

    assert result["status"] == "passed"
    assert redis.requested_keys == [NUCLEI_HEARTBEAT]


def test_detection_worker_is_required_only_in_production():
    redis = FakeRedis()
    production = SimpleNamespace(environment="production")
    development = SimpleNamespace(environment="development")

    assert detection_worker_check(production, redis)["status"] == "failed"
    assert detection_worker_check(development, redis)["status"] == "skipped"
