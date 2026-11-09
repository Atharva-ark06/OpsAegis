from datetime import datetime, timezone

from app.integrations.contracts import NormalizedFinding
from app.integrations.wazuh_manager import WazuhManagerAdapter
from app.models.entities import (
    Asset,
    AuditLog,
    Finding,
    FindingSeverity,
    FindingStatus,
    Vulnerability,
    VulnerabilityStatus,
)
from app.routers import integrations as integrations_router


def test_crowdsec_collection_is_idempotent_and_preserves_analyst_triage(
    client, db_session, analyst_headers, monkeypatch
):
    observed = datetime(2026, 11, 9, 8, tzinfo=timezone.utc)

    class FakeCrowdSecAdapter:
        is_configured = True

        async def collect_findings(self):
            return [
                NormalizedFinding(
                    source_engine="crowdsec",
                    source_native_id="decision-77",
                    title="CrowdSec ban: Ip 203.0.113.77",
                    description="crowdsecurity/ssh-bf",
                    severity="high",
                    observed_at=observed,
                    asset_reference="203.0.113.77",
                    evidence={"decision_id": "decision-77", "scope": "Ip", "value": "203.0.113.77"},
                )
            ]

    monkeypatch.setattr(integrations_router, "CrowdSecLapiAdapter", FakeCrowdSecAdapter)

    first = client.post("/api/v1/integrations/crowdsec/collect", headers=analyst_headers)
    assert first.status_code == 200
    assert first.json()["inserted"] == 1
    assert first.json()["updated"] == 0

    finding = db_session.query(Finding).filter_by(
        source_engine="crowdsec", source_native_id="decision-77"
    ).one()
    finding.status = FindingStatus.false_positive
    original_first_seen = finding.first_seen_at
    db_session.commit()

    second = client.post("/api/v1/integrations/crowdsec/collect", headers=analyst_headers)
    assert second.status_code == 200
    assert second.json()["inserted"] == 0
    assert second.json()["updated"] == 1

    db_session.refresh(finding)
    assert db_session.query(Finding).filter_by(
        source_engine="crowdsec", source_native_id="decision-77"
    ).count() == 1
    assert finding.status == FindingStatus.false_positive
    assert finding.first_seen_at == original_first_seen
    assert db_session.query(AuditLog).filter_by(
        action="integration.crowdsec.collect"
    ).count() == 2


def test_wazuh_manager_sync_preserves_analyst_managed_asset_fields(
    client, db_session, analyst_headers, monkeypatch
):
    asset = Asset(
        name="web-prod-01",
        asset_type="server",
        environment="production",
        source_engine="wazuh",
        external_id="004",
        ip_address="10.0.0.10",
        os_name="Ubuntu 22.04",
        agent_status="disconnected",
    )
    db_session.add(asset)
    db_session.commit()

    manager_agent = {
        "id": "004",
        "name": "web-prod-01",
        "ip": "10.0.0.44",
        "status": "active",
        "lastKeepAlive": "2026-11-09T08:00:00Z",
        "os": {"name": "Ubuntu", "version": "24.04", "platform": "ubuntu"},
    }

    class FakeWazuhManagerAdapter:
        is_configured = True
        normalize_agent = staticmethod(WazuhManagerAdapter.normalize_agent)

        async def collect_agents(self):
            return [manager_agent]

    monkeypatch.setattr(integrations_router, "WazuhManagerAdapter", FakeWazuhManagerAdapter)

    response = client.post("/api/v1/integrations/wazuh-manager/sync", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["received"] == 1
    assert response.json()["updated"] == 1
    assert response.json()["created"] == 0

    db_session.refresh(asset)
    assert asset.name == "web-prod-01"
    assert asset.asset_type == "server"
    assert asset.environment == "production"
    assert asset.ip_address == "10.0.0.44"
    assert asset.os_name == "Ubuntu 24.04"
    assert asset.agent_status == "active"
    assert db_session.query(AuditLog).filter_by(
        action="integration.wazuh_manager.sync"
    ).count() == 1


def test_wazuh_vulnerability_sync_preserves_remediation_and_nvd_metadata(
    client, db_session, analyst_headers, monkeypatch
):
    asset = Asset(
        name="db-prod-01",
        asset_type="database",
        environment="production",
        source_engine="wazuh",
        external_id="009",
    )
    db_session.add(asset)
    db_session.flush()

    finding = Finding(
        source_engine="wazuh-vulnerability",
        source_native_id="stable-indexer-document",
        title="CVE-2025-12345 affects openssl 3.0.2",
        description="Existing Wazuh vulnerability evidence",
        severity=FindingSeverity.high,
        status=FindingStatus.triaged,
        asset_id=asset.id,
        first_seen_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
        evidence={"agent_id": "009"},
    )
    db_session.add(finding)
    db_session.flush()

    cached_at = datetime(2026, 11, 2, tzinfo=timezone.utc)
    vulnerability = Vulnerability(
        cve_id="CVE-2025-12345",
        finding_id=finding.id,
        asset_id=asset.id,
        cvss_score=8.1,
        cvss_version="3.1",
        cvss_severity="high",
        description="Existing description",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2025-12345",
        status=VulnerabilityStatus.accepted,
        remediation_notes="Exception approved by security team",
        nvd_modified_at=cached_at,
        nvd_data_updated_at=cached_at,
        first_seen_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    db_session.add(vulnerability)
    db_session.commit()

    refreshed_item = {
        "source_native_id": "stable-indexer-document",
        "cve_id": "CVE-2025-12345",
        "agent_id": "009",
        "agent_name": "db-prod-01",
        "package_name": "openssl",
        "package_version": "3.0.2",
        "package_type": "deb",
        "package_architecture": "amd64",
        "package_description": None,
        "os_name": "Ubuntu 24.04",
        "description": "Updated source description",
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_version": "3.1",
        "observed_at": datetime(2026, 11, 9, 8, tzinfo=timezone.utc),
        "published_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "references": "",
        "category": "Packages",
        "scanner_vendor": "Wazuh",
    }

    class FakeWazuhIndexerAdapter:
        is_configured = True

        async def collect_vulnerabilities(self):
            return [refreshed_item], 1, False

    monkeypatch.setattr(integrations_router, "WazuhIndexerAdapter", FakeWazuhIndexerAdapter)

    response = client.post(
        "/api/v1/integrations/wazuh-vulnerabilities/sync", headers=analyst_headers
    )
    assert response.status_code == 200
    assert response.json()["received"] == 1
    assert response.json()["created"] == 0
    assert response.json()["updated"] == 1
    assert response.json()["unmapped"] == 0

    db_session.refresh(finding)
    db_session.refresh(vulnerability)
    assert finding.status == FindingStatus.triaged
    assert vulnerability.status == VulnerabilityStatus.accepted
    assert vulnerability.remediation_notes == "Exception approved by security team"
    # SQLite drops timezone metadata on DateTime round-trips; these test values are UTC.
    assert vulnerability.nvd_modified_at.replace(tzinfo=timezone.utc) == cached_at
    assert vulnerability.nvd_data_updated_at.replace(tzinfo=timezone.utc) == cached_at
    assert vulnerability.cvss_score == 9.1
    assert vulnerability.cvss_severity == "critical"
    assert db_session.query(Finding).filter_by(
        source_engine="wazuh-vulnerability", source_native_id="stable-indexer-document"
    ).count() == 1
    assert db_session.query(Vulnerability).filter_by(
        finding_id=finding.id, cve_id="CVE-2025-12345"
    ).count() == 1
    assert db_session.query(AuditLog).filter_by(
        action="integration.wazuh_vulnerabilities.sync"
    ).count() == 1


def test_viewer_cannot_run_integration_syncs(client, db_session):
    from app.models.entities import User, UserRole
    from app.security import create_access_token, hash_password

    viewer = User(
        email="viewer-integration@example.com",
        password_hash=hash_password("Viewer-Password-2026!"),
        role=UserRole.viewer,
        is_active=True,
    )
    db_session.add(viewer)
    db_session.commit()
    db_session.refresh(viewer)
    headers = {"Authorization": f"Bearer {create_access_token(viewer)}"}

    paths = (
        "/api/v1/integrations/crowdsec/collect",
        "/api/v1/integrations/wazuh-manager/sync",
        "/api/v1/integrations/wazuh-vulnerabilities/sync",
    )
    for path in paths:
        response = client.post(path, headers=headers)
        assert response.status_code == 403, path
