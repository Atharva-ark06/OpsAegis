import { BlurredStagger } from "./blurred-stagger-text";

const SECTION_COPY = {
  assets: { index: "01", eyebrow: "ATTACK SURFACE / INVENTORY", title: "Attack Surface Atlas", description: "Map the systems, endpoints and infrastructure that make up your monitored environment." },
  findings: { index: "02", eyebrow: "RISK / EXPOSURE MANAGEMENT", title: "Risk & Exposure", description: "Prioritize security findings, understand their status and drive remediation forward." },
  vulnerabilities: { index: "03", eyebrow: "VULNERABILITY INTELLIGENCE", title: "Exposure Intelligence", description: "Assess authorized scan results and focus attention on the weaknesses that matter." },
  detections: { index: "04", eyebrow: "THREAT DETECTION / TELEMETRY", title: "Detection Command", description: "Investigate authentication signals, suspicious activity and the evidence behind each alert." },
  incidents: { index: "05", eyebrow: "INCIDENT RESPONSE / CASEWORK", title: "Incident Response", description: "Coordinate investigations, track severity and move security events toward resolution." },
  integrations: { index: "06", eyebrow: "CONNECTED SECURITY ECOSYSTEM", title: "Security Engine Network", description: "Monitor the health and connectivity of the engines feeding your security operations." },
  "threat-intel": { index: "07", eyebrow: "THREAT INTELLIGENCE / IOC ANALYSIS", title: "Threat Intelligence", description: "Enrich indicators, inspect reputation signals and turn external context into actionable insight." },
  playbooks: { index: "08", eyebrow: "AUTOMATION / ORCHESTRATION", title: "Response Automation", description: "Design and govern repeatable security workflows for faster, consistent response." },
  users: { index: "09", eyebrow: "IDENTITY / ACCESS GOVERNANCE", title: "Identity & Access", description: "Manage workspace identities, roles and the permissions that protect critical operations." },
  reports: { index: "10", eyebrow: "SECURITY POSTURE / REPORTING", title: "Security Insights", description: "Turn authenticated operational records into clear evidence and decision-ready reports." },
  settings: { index: "11", eyebrow: "WORKSPACE / CONFIGURATION", title: "Workspace Control", description: "Tune account preferences and review the configuration of your OpsAegis workspace." },
} as const;

type SectionKey = keyof typeof SECTION_COPY;

export function SectionHeading({ section }: { section: SectionKey }) {
  const content = SECTION_COPY[section];
  return (
    <header className="ops-section-heading">
      <div className="ops-section-heading-copy">
        <div className="ops-section-heading-meta">
          <span className="ops-section-heading-index">{content.index}</span>
          <span className="ops-section-heading-eyebrow">{content.eyebrow}</span>
        </div>
        <BlurredStagger text={content.title} className="ops-section-heading-title" />
        <p>{content.description}</p>
      </div>
      <div className="ops-section-heading-mark" aria-hidden="true">
        <span>OPSAEGIS</span>
        <strong>{content.index}</strong>
        <i />
      </div>
    </header>
  );
}
