"use client";

import { useCallback, useEffect, useState, type CSSProperties } from "react";
import WorkflowBlueprint, { type WorkflowApp, type WorkflowGraph } from "./interactive-workflow-blueprint";

const securityInitialGraph: WorkflowGraph = {
  nodes: [
    { id: "alert", type: "blueprint", position: { x: 20, y: 70 }, data: { label: "Detection triggered", detail: "Repeated authentication failures detected by rule SF-AUTH-001.", kind: "trigger", tool: "Detection engine" } },
    { id: "context", type: "blueprint", position: { x: 250, y: 170 }, data: { label: "Enrich event context", detail: "Collect source IP, affected identity, asset context and related findings.", kind: "integration", tool: "OpsAegis · Threat Intel" } },
    { id: "triage", type: "blueprint", position: { x: 480, y: 70 }, data: { label: "Assess severity", detail: "Summarize evidence, confidence and potential impact for analyst review.", kind: "agent", tool: "Triage analysis" } },
    { id: "approval", type: "blueprint", position: { x: 710, y: 170 }, data: { label: "Analyst approval", detail: "Require an independent operator to approve or reject the proposed response.", kind: "review", tool: "Separation of duties" } },
    { id: "record", type: "blueprint", position: { x: 940, y: 70 }, data: { label: "Record response plan", detail: "Store the decision, rationale and evidence references in the audit trail.", kind: "delivery", tool: "OpsAegis · Audit log" } },
  ],
  edges: [
    { id: "alert-context", source: "alert", target: "context" },
    { id: "context-triage", source: "context", target: "triage" },
    { id: "triage-approval", source: "triage", target: "approval" },
    { id: "approval-record", source: "approval", target: "record" },
  ],
};

const securityApps: WorkflowApp[] = [
  { id: "detections", name: "Detection engine", logo: "https://cdn.simpleicons.org/wazuh/00AEEF", actions: [
    { label: "Detection rule matched", detail: "Start when a configured detection rule reports a matching event.", kind: "trigger", tool: "OpsAegis detections" },
    { label: "Incident opened", detail: "Start from an incident already ingested into OpsAegis.", kind: "trigger", tool: "Incident register" },
  ] },
  { id: "intel", name: "Threat intelligence", logo: "https://cdn.simpleicons.org/virustotal/394EFF", actions: [
    { label: "Enrich indicator", detail: "Attach available reputation and indicator context to an event.", kind: "integration", tool: "Threat Intel" },
    { label: "Correlate related findings", detail: "Review related detections, vulnerabilities and linked findings.", kind: "agent", tool: "Correlation context" },
  ] },
  { id: "assets", name: "Assets & identity", logo: "https://cdn.simpleicons.org/okta/007DC1", actions: [
    { label: "Read asset context", detail: "Reference registered asset inventory and known ownership metadata.", kind: "integration", tool: "Asset inventory" },
    { label: "Check identity context", detail: "Add available user, role and access context to the investigation.", kind: "integration", tool: "Identity & access" },
  ] },
  { id: "governance", name: "Governance", logo: "https://cdn.simpleicons.org/letsencrypt/003A70", actions: [
    { label: "Request independent approval", detail: "Create a review step requiring a different operator before response.", kind: "review", tool: "Approval workflow" },
    { label: "Record decision", detail: "Record the human decision, reason and evidence references.", kind: "delivery", tool: "Audit trail" },
  ] },
  { id: "response", name: "Response adapters", logo: "https://cdn.simpleicons.org/shield/64748B", actions: [
    { label: "Prepare isolation request", detail: "Draft a Wazuh isolation proposal for independent review. No provider command is sent.", kind: "review", tool: "Wazuh · adapter disabled" },
    { label: "Prepare notification", detail: "Draft a notification payload for a configured channel. Nothing is dispatched.", kind: "delivery", tool: "Notification template" },
  ] },
];

const draftKey = "opsaegis.workflow-blueprint.v2";
function loadSecurityGraph(): WorkflowGraph {
  try {
    const raw = window.localStorage.getItem(draftKey);
    if (!raw) return securityInitialGraph;
    const value = JSON.parse(raw) as WorkflowGraph;
    if (!value || !Array.isArray(value.nodes) || !Array.isArray(value.edges) || value.nodes.length > 20) return securityInitialGraph;
    const ids = new Set(value.nodes.map(node => node.id));
    if (!value.nodes.every(node => typeof node.id === "string" && typeof node.position?.x === "number" && typeof node.position?.y === "number" && typeof node.data?.label === "string" && typeof node.data?.detail === "string" && ["trigger", "agent", "integration", "review", "delivery"].includes(node.data.kind))) return securityInitialGraph;
    if (!value.edges.every(edge => ids.has(edge.source) && ids.has(edge.target))) return securityInitialGraph;
    return value;
  } catch { return securityInitialGraph; }
}

export function PlaybookWorkflowDesigner() {
  const [graph, setGraph] = useState<WorkflowGraph | null>(null);
  useEffect(() => { setGraph(loadSecurityGraph()); }, []);
  const save = useCallback((next: WorkflowGraph) => {
    try { window.localStorage.setItem(draftKey, JSON.stringify(next)); } catch { /* JSON export remains available if storage is unavailable. */ }
  }, []);
  if (!graph) return <div className="playbook-blueprint-loading" role="status">Loading security workflow canvas…</div>;
  return <div className="playbook-blueprint-page">
    <div className="playbook-blueprint-intro">
      <div><p className="eyebrow">OPSAEGIS · RESPONSE AUTOMATION</p><h3>Security playbook builder</h3><p>Design governed security workflows by connecting detections, intelligence, analyst review and response preparation.</p></div>
      <span className="playbook-blueprint-state"><i/> DESIGN MODE · LOCAL DRAFT</span>
    </div>
    <WorkflowBlueprint key="opsaegis-security-blueprint" title="Security response workflow" initialGraph={graph} apps={securityApps}
      agentTemplate={{ label: "New analysis agent", detail: "Describe the evidence this agent should evaluate.", kind: "agent", tool: "OpsAegis analysis" }}
      onChange={save}
      style={{
        "--color-background": "var(--aegis-bg)",
        "--color-foreground": "var(--aegis-text)",
        "--color-card": "var(--aegis-panel)",
        "--color-muted-foreground": "var(--aegis-muted)",
        "--color-border": "var(--aegis-border)",
        "--color-primary": "var(--aegis-accent)",
        "--color-primary-foreground": "var(--aegis-bg)",
        "--color-chart-2": "#31c5a0",
        "--color-chart-3": "#9b8cff",
      } as CSSProperties} />
    <div className="playbook-blueprint-foot"><strong>Governed by design.</strong> Workflow edits save locally in this browser and can be exported as JSON. The canvas does not execute provider actions. Wazuh isolation, notifications and other external response actions remain disabled until secure adapters and server-side approval gates are implemented.</div>
    <style>{`.playbook-blueprint-page{display:grid;gap:16px;min-width:0}.playbook-blueprint-intro{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;padding:4px 2px 16px;border-bottom:1px solid var(--aegis-border)}.playbook-blueprint-intro h3{margin:4px 0 7px;color:var(--aegis-text);font-size:clamp(25px,3vw,36px);font-weight:900;letter-spacing:-.045em}.playbook-blueprint-intro p:not(.eyebrow){max-width:72ch;margin:0;color:var(--aegis-muted);font-size:13px;line-height:1.65}.playbook-blueprint-state{display:flex;align-items:center;gap:7px;flex:0 0 auto;padding:7px 10px;border:1px solid var(--aegis-border);border-radius:7px;color:var(--aegis-muted);font:9px ui-monospace,monospace;letter-spacing:.08em}.playbook-blueprint-state i{width:7px;height:7px;border-radius:50%;background:#31c5a0;box-shadow:0 0 10px #31c5a088}.playbook-blueprint-foot{padding:13px 15px;border:1px solid var(--aegis-border);border-radius:10px;background:var(--aegis-panel);color:var(--aegis-muted);font-size:11px;line-height:1.65}.playbook-blueprint-foot strong{color:var(--aegis-text)}.playbook-blueprint-loading{padding:30px;border:1px solid var(--aegis-border);border-radius:12px;color:var(--aegis-muted);background:var(--aegis-panel)}@media(max-width:760px){.playbook-blueprint-intro{align-items:flex-start;flex-direction:column}}`}</style>
  </div>;
}
