"""Opt-in, deterministic synthetic security dataset for local/staging OpsAegis demos.

Run from backend/: python -m app.seed_demo_data
Reset only this fixture: python -m app.seed_demo_data --reset

This command never creates users, credentials, provider schedules, or successful
external integration runs. All generated records carry an OpsAegis demo marker.
"""
from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.config import settings
from app.database import SessionLocal
from app.models.entities import (
    Asset, AuditLog, CorrelatedDetection, Finding, FindingSeverity,
    FindingStatus, Incident, IncidentNote, ThreatIntelIOC, User,
    Vulnerability, VulnerabilityStatus,
)

PREFIX = "[DEMO]"
SOURCE = "opsaegis-demo"
NOW = datetime.now(timezone.utc)

ASSET_FIXTURES = [
    ("demo-web-01", "Public Web Gateway", "server", "production", "203.0.113.10", "Ubuntu 22.04"),
    ("demo-api-01", "Customer API", "server", "production", "203.0.113.11", "Ubuntu 22.04"),
    ("demo-db-01", "Customer Database", "database", "production", "10.20.0.15", "PostgreSQL 16"),
    ("demo-auth-01", "Identity Service", "server", "production", "10.20.0.20", "Debian 12"),
    ("demo-ci-01", "Build Runner", "endpoint", "development", "10.30.0.25", "Windows Server 2022"),
    ("demo-dev-01", "Developer Workstation", "endpoint", "development", "10.30.0.41", "Windows 11"),
    ("demo-vpn-01", "Remote Access VPN", "network", "production", "198.51.100.8", "Appliance OS"),
    ("demo-s3-01", "Customer File Store", "cloud", "production", None, "Object Storage"),
    ("demo-k8s-01", "Kubernetes Cluster", "cloud", "production", "10.20.1.10", "Kubernetes 1.29"),
    ("demo-mail-01", "Mail Gateway", "server", "production", "10.20.0.30", "Ubuntu 22.04"),
    ("demo-mon-01", "Monitoring Node", "server", "staging", "10.40.0.12", "Debian 12"),
    ("demo-stage-01", "Staging Application", "application", "staging", "192.0.2.55", "Container Linux"),
]

FINDING_FIXTURES = [
    ("Exposed administrative endpoint", "critical", "new", 0, "Internet-facing admin route is reachable from an untrusted network."),
    ("Outdated OpenSSL package", "high", "triaged", 0, "Installed package is behind the vendor security release."),
    ("SSH password authentication enabled", "high", "new", 1, "Production API host permits password-based SSH authentication."),
    ("Database backup encryption not verified", "medium", "triaged", 2, "Backup encryption evidence is missing from the latest review."),
    ("Excessive service account permissions", "high", "new", 3, "Service identity has permissions beyond its documented workload."),
    ("Unsigned build artifact detected", "medium", "new", 4, "A development pipeline artifact is missing signature metadata."),
    ("Endpoint agent disconnected", "low", "triaged", 5, "Endpoint has not reported to its management plane recently."),
    ("VPN login from unusual geography", "high", "new", 6, "Authentication event differs from the account's normal access pattern."),
    ("Public object storage policy", "critical", "new", 7, "Storage policy permits anonymous object listing in the demo scenario."),
    ("Kubernetes API exposure", "high", "triaged", 8, "Cluster API is reachable from a wider network range than intended."),
    ("Mail gateway TLS policy weak", "medium", "accepted", 9, "Legacy TLS compatibility remains enabled."),
    ("Staging debug mode enabled", "low", "resolved", 11, "Debug endpoint was enabled in a staging deployment."),
    ("Missing host security updates", "medium", "new", 10, "Monitoring node is missing routine security updates."),
    ("Suspicious repeated login failures", "critical", "new", 3, "Multiple failed authentication attempts were observed for a privileged identity."),
    ("Unexpected outbound connection", "high", "triaged", 1, "API host generated an unusual outbound connection in the demo telemetry."),
    ("Container image contains vulnerable library", "high", "new", 8, "Container dependency inventory includes a vulnerable library version."),
    ("MFA coverage gap", "medium", "new", 3, "A privileged account is not included in the MFA enforcement group."),
    ("Excessive inbound network exposure", "low", "resolved", 5, "Development endpoint has an unnecessary inbound rule."),
]

VULN_FIXTURES = [
    (1, "CVE-2023-0286", 7.4, "high", "OpenSSL X.509 certificate verification vulnerability."),
    (2, "CVE-2024-3094", 10.0, "critical", "Synthetic association for a known high-impact library supply-chain issue."),
    (3, "CVE-2023-48795", 5.9, "medium", "SSH prefix truncation weakness."),
    (9, "CVE-2024-21626", 8.6, "high", "Container runtime working-directory escape weakness."),
    (15, "CVE-2023-44487", 7.5, "high", "HTTP/2 rapid reset denial-of-service weakness."),
]

IOC_FIXTURES = [
    ("ipv4", "198.51.100.77", "malicious", 92, "Synthetic threat-feed match; TEST-NET address only."),
    ("domain", "login-portal.example.invalid", "suspicious", 68, "Reserved invalid domain used only for demonstration."),
    ("url", "https://updates.example.invalid/payload", "malicious", 95, "Non-resolving reserved domain; synthetic indicator."),
    ("sha256", "a" * 64, "suspicious", 61, "Synthetic file hash; not a real malware sample."),
    ("ipv4", "203.0.113.222", "clean", 2, "Documentation-only TEST-NET address."),
    ("domain", "cdn.example.invalid", "unknown", None, "Synthetic indicator awaiting enrichment."),
]

INCIDENT_FIXTURES = [
    ("Privileged account brute-force investigation", "critical", "investigating", "Repeated failed logins against the identity service. Synthetic scenario; no real account was accessed."),
    ("Public storage exposure review", "high", "open", "Review the demo object-storage policy and confirm access boundaries."),
    ("Suspicious outbound traffic", "high", "contained", "Analyst recorded containment in the synthetic scenario; no network control was changed."),
    ("Build pipeline integrity alert", "medium", "resolved", "Demo artifact signature gap was reviewed and marked resolved."),
    ("Kubernetes workload vulnerability", "high", "open", "Investigate vulnerable dependency evidence associated with the demo cluster."),
]

DETECTION_FIXTURES = [
    ("DEMO-AUTH-001", "Repeated authentication failures", "critical", [13, 16], 0, "Multiple authentication findings for the demo identity service."),
    ("DEMO-NET-002", "Unusual outbound connection", "high", [14], 2, "Outbound connection deviates from the demo baseline."),
    ("DEMO-CLOUD-003", "Public storage policy detected", "critical", [8], 1, "Cloud storage access policy is broader than expected."),
    ("DEMO-ENDPOINT-004", "Endpoint telemetry gap", "low", [6], None, "Endpoint reporting is stale in the synthetic dataset."),
    ("DEMO-K8S-005", "Vulnerable container workload", "high", [15], 4, "Container dependency finding is associated with the demo cluster."),
]


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clear_demo(db) -> None:
    finding_ids = list(db.scalars(select(Finding.id).where(Finding.source_engine == SOURCE)).all())
    incident_ids = list(db.scalars(select(Incident.id).where(Incident.title.like(PREFIX + "%"))).all())
    if finding_ids:
        db.execute(delete(Vulnerability).where(Vulnerability.finding_id.in_(finding_ids)))
    if incident_ids:
        db.execute(delete(IncidentNote).where(IncidentNote.incident_id.in_(incident_ids)))
    db.execute(delete(CorrelatedDetection).where(CorrelatedDetection.rule_key.like("DEMO-%")))
    db.execute(delete(ThreatIntelIOC).where(ThreatIntelIOC.indicator_hash.in_([_hash(f"{kind}:{value}") for kind, value, *_ in IOC_FIXTURES])))
    db.execute(delete(Finding).where(Finding.source_engine == SOURCE))
    db.execute(delete(Incident).where(Incident.title.like(PREFIX + "%")))
    db.execute(delete(Asset).where(Asset.source_engine == SOURCE))
    db.execute(delete(AuditLog).where(AuditLog.target.like("demo:%")))
    db.flush()


def seed_demo(db) -> dict[str, int]:
    admin = db.scalar(select(User).where(User.role == "admin", User.is_active.is_(True)).order_by(User.id).limit(1))
    if admin is None:
        raise RuntimeError("Create the first real administrator before seeding the demo dataset.")
    existing = db.scalar(select(Asset.id).where(Asset.source_engine == SOURCE).limit(1))
    if existing is not None:
        return {"already_seeded": 1}

    assets: list[Asset] = []
    for index, (external_id, name, kind, environment, ip, os_name) in enumerate(ASSET_FIXTURES):
        item = Asset(name=f"{PREFIX} {name}", asset_type=kind, environment=environment,
                     source_engine=SOURCE, external_id=external_id, ip_address=ip,
                     os_name=os_name, agent_status="demo-online" if index % 4 else "demo-stale",
                     last_seen_at=NOW - timedelta(hours=(index * 5) % 72),
                     created_at=NOW - timedelta(days=(index * 3) % 40))
        db.add(item)
        assets.append(item)
    db.flush()

    findings: list[Finding] = []
    for index, (title, severity, status, asset_index, description) in enumerate(FINDING_FIXTURES):
        first_seen = NOW - timedelta(days=(index * 2) % 28, hours=index % 12)
        item = Finding(source_engine=SOURCE, source_native_id=f"demo-finding-{index + 1:03d}",
                       title=f"{PREFIX} {title}", description=description,
                       severity=FindingSeverity(severity), status=FindingStatus(status),
                       asset_id=assets[asset_index].id, first_seen_at=first_seen,
                       last_seen_at=first_seen + timedelta(hours=index % 9),
                       evidence={"synthetic": True, "scenario": "acme-enterprise-lab",
                                 "asset_external_id": ASSET_FIXTURES[asset_index][0],
                                 "note": "Generated fixture. Not observed in a real environment."})
        db.add(item)
        findings.append(item)
    db.flush()

    for finding_index, cve, score, severity, description in VULN_FIXTURES:
        finding = findings[finding_index]
        observed = finding.first_seen_at
        db.add(Vulnerability(cve_id=cve, finding_id=finding.id, asset_id=finding.asset_id,
            cvss_score=score, cvss_version="3.1", cvss_severity=severity,
            description=description, published_at=NOW - timedelta(days=365),
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            status=VulnerabilityStatus.open if score >= 7 else VulnerabilityStatus.in_progress,
            remediation_notes="Synthetic demo record. Validate vendor advisory before any real remediation.",
            first_seen_at=observed, last_seen_at=observed, created_at=observed, updated_at=NOW))

    incidents: list[Incident] = []
    for index, (title, severity, status, description) in enumerate(INCIDENT_FIXTURES):
        created = NOW - timedelta(days=index * 2 + 1)
        item = Incident(title=f"{PREFIX} {title}", severity=FindingSeverity(severity),
                        status=status, description=description,
                        assigned_to_user_id=admin.id, created_at=created, updated_at=NOW,
                        closed_at=NOW - timedelta(hours=4) if status == "resolved" else None,
                        resolution="Synthetic analyst resolution; no external system was modified." if status == "resolved" else None)
        db.add(item)
        incidents.append(item)
    db.flush()

    for index, (rule, title, severity, finding_indexes, incident_index, description) in enumerate(DETECTION_FIXTURES):
        ids = [findings[n].id for n in finding_indexes]
        created = NOW - timedelta(hours=(index + 1) * 7)
        db.add(CorrelatedDetection(rule_key=rule, fingerprint=_hash(rule + ":" + ",".join(map(str, ids))),
            title=f"{PREFIX} {title}", description=description,
            severity=FindingSeverity(severity), finding_ids=ids,
            evidence={"synthetic": True, "scenario": "acme-enterprise-lab",
                      "source": "opsaegis-demo-seed"},
            incident_id=incidents[incident_index].id if incident_index is not None else None,
            status="investigating" if incident_index == 0 else "new",
            created_at=created, last_seen_at=created, updated_at=created))

    for kind, value, verdict, risk, description in IOC_FIXTURES:
        db.add(ThreatIntelIOC(indicator_type=kind, indicator_value=value,
            indicator_hash=_hash(f"{kind}:{value}"), verdict=verdict, risk_score=risk,
            provider_results={"demo": {"status": "synthetic", "description": description},
                              "virustotal": {"status": "not_queried"},
                              "abuseipdb": {"status": "not_queried"},
                              "crowdsec_cti": {"status": "not_queried"}},
            enriched_at=None, created_by_user_id=admin.id, created_at=NOW - timedelta(days=2)))

    for incident in incidents:
        db.add(IncidentNote(incident_id=incident.id, author_user_id=admin.id,
            note="Synthetic demo context: validate evidence and workflow behavior. No real-world action was taken.",
            created_at=incident.created_at + timedelta(minutes=15)))

    db.add(AuditLog(actor_user_id=admin.id, action="demo.dataset.seed",
        target="demo:acme-enterprise-lab",
        detail="synthetic_only:true; external_actions:false; provider_health_unchanged:true"))
    db.flush()
    return {"assets": len(assets), "findings": len(findings), "vulnerabilities": len(VULN_FIXTURES),
            "incidents": len(incidents), "detections": len(DETECTION_FIXTURES), "iocs": len(IOC_FIXTURES)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed or reset the OpsAegis synthetic demo dataset.")
    parser.add_argument("--reset", action="store_true", help="Delete only records created by this demo fixture, then reseed.")
    args = parser.parse_args()
    if settings.environment.lower() == "production":
        raise SystemExit("Refusing to seed synthetic records when OPS_AEGIS_ENV=production.")
    with SessionLocal() as db:
        try:
            if args.reset:
                clear_demo(db)
            result = seed_demo(db)
            db.commit()
            print("OpsAegis synthetic dataset:", result)
            print("All generated records are marked [DEMO]/opsaegis-demo. No providers or external actions were invoked.")
        except Exception:
            db.rollback()
            raise


if __name__ == "__main__":
    main()
