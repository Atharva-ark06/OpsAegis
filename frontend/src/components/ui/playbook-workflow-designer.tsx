"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Activity, AlertTriangle, ArrowDownToLine, Bot, CheckCircle2, ChevronDown, ClipboardCheck, Database, Link2, Plus, Shield, ShieldCheck, Trash2, Undo2, ZoomIn, ZoomOut } from "lucide-react";

type StepKind = "trigger" | "agent" | "integration" | "review" | "delivery";
type Step = { id: string; label: string; detail: string; kind: StepKind; tool?: string; x: number; y: number };
type Link = { id: string; source: string; target: string };
type Graph = { nodes: Step[]; edges: Link[] };
type Action = Omit<Step, "id" | "x" | "y">;
type ActionGroup = { id: string; name: string; icon: typeof Shield; actions: Action[] };

const initialGraph: Graph = {
  nodes: [
    { id: "trigger", label: "Security event detected", detail: "A detection rule identifies repeated authentication failures.", kind: "trigger", tool: "SF-AUTH-001", x: 40, y: 150 },
    { id: "enrich", label: "Enrich event context", detail: "Collect source IP, affected user, asset and threat-intelligence context.", kind: "integration", tool: "OpsAegis event context", x: 290, y: 150 },
    { id: "assess", label: "Assess severity", detail: "Evaluate event frequency, confidence and affected accounts.", kind: "agent", tool: "Triage analysis", x: 540, y: 150 },
    { id: "approve", label: "Analyst approval", detail: "Require an independent operator to review the proposed response.", kind: "review", tool: "Separation of duties", x: 790, y: 150 },
    { id: "audit", label: "Record response plan", detail: "Write the approved decision and evidence references to the audit trail.", kind: "delivery", tool: "Execution ledger", x: 1040, y: 150 },
  ],
  edges: [
    { id: "e1", source: "trigger", target: "enrich" },
    { id: "e2", source: "enrich", target: "assess" },
    { id: "e3", source: "assess", target: "approve" },
    { id: "e4", source: "approve", target: "audit" },
  ],
};

const groups: ActionGroup[] = [
  { id: "detections", name: "Detections", icon: AlertTriangle, actions: [
    { label: "Detection rule matched", detail: "Start when an enabled detection rule reports a matching event.", kind: "trigger", tool: "Detection engine" },
    { label: "Incident opened", detail: "Start from an incident already recorded in OpsAegis.", kind: "trigger", tool: "Incident register" },
  ]},
  { id: "intelligence", name: "Threat intelligence", icon: Activity, actions: [
    { label: "Enrich indicator", detail: "Attach available reputation and indicator context to the event.", kind: "integration", tool: "Threat Intel" },
    { label: "Correlate findings", detail: "Review related findings and linked detections for this incident.", kind: "agent", tool: "Correlation context" },
  ]},
  { id: "analysis", name: "Analysis agents", icon: Bot, actions: [
    { label: "Assess severity", detail: "Summarize evidence and recommend a severity for analyst review.", kind: "agent", tool: "Triage analysis" },
    { label: "Build investigation checklist", detail: "Prepare a bounded investigation checklist from recorded context.", kind: "agent", tool: "Investigation preview" },
  ]},
  { id: "governance", name: "Governance", icon: ClipboardCheck, actions: [
    { label: "Request approval", detail: "Create an independent review request; approval does not execute actions.", kind: "review", tool: "Approval queue" },
    { label: "Record decision", detail: "Record a human decision and its reason in the governance trail.", kind: "delivery", tool: "Audit log" },
  ]},
  { id: "integrations", name: "Integrations", icon: Database, actions: [
    { label: "Read asset context", detail: "Reference registered asset inventory and known ownership metadata.", kind: "integration", tool: "Asset inventory" },
    { label: "Check provider status", detail: "Read the configured integration health status without dispatching commands.", kind: "integration", tool: "Integration health" },
  ]},
];

const kindLabel: Record<StepKind, string> = { trigger: "TRIGGER", agent: "AI AGENT", integration: "INTEGRATION", review: "REVIEW", delivery: "DELIVERY" };
const kindIcon: Record<StepKind, typeof Shield> = { trigger: AlertTriangle, agent: Bot, integration: Link2, review: ShieldCheck, delivery: CheckCircle2 };
const STORAGE_KEY = "opsaegis.playbook-designer.draft.v1";

function isGraph(value: unknown): value is Graph {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Graph;
  return Array.isArray(candidate.nodes) && Array.isArray(candidate.edges)
    && candidate.nodes.length <= 20
    && candidate.nodes.every((node) => node && typeof node.id === "string" && typeof node.label === "string" && typeof node.detail === "string" && ["trigger", "agent", "integration", "review", "delivery"].includes(node.kind) && Number.isFinite(node.x) && Number.isFinite(node.y))
    && candidate.edges.every((edge) => edge && typeof edge.id === "string" && candidate.nodes.some((node) => node.id === edge.source) && candidate.nodes.some((node) => node.id === edge.target));
}

function canConnect(graph: Graph, source: string, target: string) {
  if (!source || !target || source === target || graph.edges.some((edge) => edge.source === source && edge.target === target)) return false;
  const seen = new Set<string>();
  const reachesSource = (id: string): boolean => {
    if (id === source) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    return graph.edges.filter((edge) => edge.source === id).some((edge) => reachesSource(edge.target));
  };
  return !reachesSource(target);
}

export function PlaybookWorkflowDesigner() {
  const [graph, setGraph] = useState<Graph>(initialGraph);
  const [selected, setSelected] = useState("trigger");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [expanded, setExpanded] = useState("detections");
  const [editing, setEditing] = useState<Step | null>(null);
  const [history, setHistory] = useState<Graph[]>([]);
  const [zoom, setZoom] = useState(1);
  const [message, setMessage] = useState("Select a node, drag it to reposition, or add a security action from the stack.");
  const [saved, setSaved] = useState(false);
  const dragRef = useRef<{ id: string; startX: number; startY: number; originX: number; originY: number } | null>(null);
  const sequence = useRef(0);

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (!stored) return;
      const parsed: unknown = JSON.parse(stored);
      if (isGraph(parsed)) setGraph(parsed);
    } catch {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  const commit = useCallback((next: Graph, notice: string) => {
    setHistory((items) => [...items.slice(-19), graph]);
    setGraph(next);
    setSaved(false);
    setMessage(notice);
  }, [graph]);

  useEffect(() => {
    const onMove = (event: PointerEvent) => {
      const drag = dragRef.current;
      if (!drag) return;
      const dx = (event.clientX - drag.startX) / zoom;
      const dy = (event.clientY - drag.startY) / zoom;
      setGraph((current) => ({ ...current, nodes: current.nodes.map((node) => node.id === drag.id ? { ...node, x: Math.max(0, Math.min(1500, drag.originX + dx)), y: Math.max(0, Math.min(420, drag.originY + dy)) } : node) }));
      setSaved(false);
    };
    const onUp = () => { if (dragRef.current) { dragRef.current = null; setMessage("Node position updated. Save draft to keep this layout on this browser."); } };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => { window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerup", onUp); };
  }, [zoom]);

  const selectedNode = graph.nodes.find((node) => node.id === selected);
  const edges = useMemo(() => graph.edges.map((edge) => {
    const from = graph.nodes.find((node) => node.id === edge.source);
    const to = graph.nodes.find((node) => node.id === edge.target);
    if (!from || !to) return null;
    const sx = from.x + 188, sy = from.y + 76, tx = to.x, ty = to.y + 76;
    const bend = Math.max(55, (tx - sx) * 0.48);
    return <path key={edge.id} className="pwb-edge" d={`M ${sx} ${sy} C ${sx + bend} ${sy}, ${tx - bend} ${ty}, ${tx} ${ty}`} />;
  }), [graph]);

  function add(action: Action) {
    if (graph.nodes.length >= 20) { setMessage("This canvas supports up to 20 nodes. Remove a step before adding another."); return; }
    const anchor = graph.nodes.find((node) => node.id === selectedNode?.id);
    const id = `step-${++sequence.current}`;
    const x = anchor ? anchor.x + 250 : 40;
    const y = anchor ? anchor.y : 80 + graph.nodes.length * 22;
    const node: Step = { ...action, id, x: Math.min(1280, x), y: Math.min(360, y) };
    let nextEdges = graph.edges;
    if (anchor) {
      const outgoing = graph.edges.filter((edge) => edge.source === anchor.id);
      if (outgoing.length === 1) nextEdges = nextEdges.map((edge) => edge.id === outgoing[0].id ? { ...edge, source: id } : edge);
      nextEdges = [...nextEdges, { id: `edge-${++sequence.current}`, source: anchor.id, target: id }];
    }
    commit({ nodes: [...graph.nodes, node], edges: nextEdges }, `${action.label} added to the workflow.`);
    setSelected(id);
  }

  function removeSelected() {
    if (!selectedNode) return;
    const incoming = graph.edges.filter((edge) => edge.target === selected);
    const outgoing = graph.edges.filter((edge) => edge.source === selected);
    const remaining: Graph = { nodes: graph.nodes.filter((node) => node.id !== selected), edges: graph.edges.filter((edge) => edge.source !== selected && edge.target !== selected) };
    if (incoming.length === 1 && outgoing.length === 1 && canConnect(remaining, incoming[0].source, outgoing[0].target)) {
      remaining.edges.push({ id: `edge-${++sequence.current}`, source: incoming[0].source, target: outgoing[0].target });
    }
    commit(remaining, `${selectedNode.label} removed.`);
    setSelected(remaining.nodes[0]?.id ?? "");
    setEditing(null);
  }

  function connectNodes(event: FormEvent) {
    event.preventDefault();
    if (!canConnect(graph, source, target)) { setMessage("Choose two different nodes without an existing link or a cycle."); return; }
    commit({ ...graph, edges: [...graph.edges, { id: `edge-${++sequence.current}`, source, target }] }, "Connection added.");
    setSource(""); setTarget("");
  }

  function saveStep(event: FormEvent) {
    event.preventDefault();
    if (!editing || !editing.label.trim()) return;
    commit({ ...graph, nodes: graph.nodes.map((node) => node.id === editing.id ? { ...node, label: editing.label.trim(), detail: editing.detail.trim(), tool: editing.tool.trim() || undefined, kind: editing.kind } : node) }, "Workflow step updated.");
    setEditing(null);
  }

  function saveDraft() {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(graph));
      setSaved(true);
      setMessage("Draft saved in this browser. It has not been published or executed.");
    } catch {
      setMessage("This browser could not save the draft. Export JSON to keep a copy.");
    }
  }

  function exportGraph() {
    const payload = { schema_version: 1, product: "OpsAegis", execution_enabled: false, graph };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = "opsaegis-security-playbook.json"; anchor.click();
    URL.revokeObjectURL(url);
    setMessage("Playbook exported as JSON. No integrations or response actions were executed.");
  }

  function undo() {
    const previous = history[history.length - 1];
    if (!previous) return;
    setGraph(previous); setHistory((items) => items.slice(0, -1)); setSaved(false); setEditing(null);
    setMessage("Last workflow edit undone.");
  }

  return <section className="panel pwb-shell" aria-label="Interactive security playbook designer">
    <div className="pwb-topline"><div className="pwb-brand"><span><Shield size={18}/></span><div><strong>Security playbook builder</strong><small>INTERACTIVE WORKFLOW BLUEPRINT</small></div></div><div className="pwb-actions"><button type="button" onClick={() => add({ label: "New analysis agent", detail: "Describe what this analysis step should evaluate.", kind: "agent", tool: "OpsAegis" })} disabled={graph.nodes.length >= 20}><Plus size={14}/> Add agent</button><button type="button" onClick={undo} disabled={!history.length}><Undo2 size={14}/> Undo edit</button><button type="button" className="pwb-primary" onClick={exportGraph}><ArrowDownToLine size={14}/> Export JSON</button></div></div>
    <div className="pwb-workspace">
      <div className="pwb-main">
        <div className="pwb-canvas-scroll">
          <div className="pwb-canvas" style={{ transform: `scale(${zoom})` }}>
            <svg className="pwb-links" viewBox="0 0 1500 520" aria-hidden="true">{edges}</svg>
            {graph.nodes.map((node) => {
              const Icon = kindIcon[node.kind];
              return <button type="button" key={node.id} className={`pwb-node ${node.kind} ${selected === node.id ? "selected" : ""}`} style={{ left: node.x, top: node.y }} onClick={() => { setSelected(node.id); setEditing(null); }} onPointerDown={(event) => { if (event.button !== 0) return; dragRef.current = { id: node.id, startX: event.clientX, startY: event.clientY, originX: node.x, originY: node.y }; }} aria-label={`${node.label}, ${kindLabel[node.kind]}`}>
                <span className="pwb-node-icon"><Icon size={18}/></span><span className="pwb-node-copy"><strong>{node.label}</strong><small>{kindLabel[node.kind]}</small></span><span className="pwb-node-description">{node.detail}</span>{node.tool && <span className="pwb-node-tool">{node.tool}</span>}
                <i className="pwb-port left"/><i className="pwb-port right"/>
              </button>;
            })}
            {!graph.nodes.length && <div className="pwb-empty">Add a security action from the connection stack to begin.</div>}
          </div>
          <div className="pwb-zoom"><button type="button" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(.65, value - .1))}><ZoomOut size={14}/></button><button type="button" onClick={() => setZoom(1)}>Fit all</button><button type="button" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(1.25, value + .1))}><ZoomIn size={14}/></button></div>
        </div>
        <div className="pwb-status"><span><i/> {graph.nodes.length} nodes · {graph.edges.length} connections</span><span>LOCAL DRAFT · NO LIVE ACTIONS</span></div>
        <div className="pwb-editor">
          <div className="pwb-edit-row"><label>Selected step<select value={selected} onChange={(event) => setSelected(event.target.value)}><option value="">Choose a step</option>{graph.nodes.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}</select></label><button type="button" onClick={() => selectedNode && setEditing(selectedNode)} disabled={!selectedNode}>Edit step</button><button type="button" onClick={removeSelected} disabled={!selectedNode}><Trash2 size={13}/> Remove selected</button><button type="button" className={saved ? "pwb-saved" : ""} onClick={saveDraft}>{saved ? <CheckCircle2 size={13}/> : <Database size={13}/>} {saved ? "Draft saved" : "Save draft"}</button></div>
          {editing && <form className="pwb-step-form" onSubmit={saveStep}><label>Step name<input required maxLength={60} value={editing.label} onChange={(event) => setEditing({ ...editing, label: event.target.value })}/></label><label>What it does<textarea rows={2} maxLength={180} value={editing.detail} onChange={(event) => setEditing({ ...editing, detail: event.target.value })}/></label><label>Step type<select value={editing.kind} onChange={(event) => setEditing({ ...editing, kind: event.target.value as StepKind })}>{Object.entries(kindLabel).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Tool<input maxLength={60} value={editing.tool ?? ""} onChange={(event) => setEditing({ ...editing, tool: event.target.value })}/></label><div><button className="pwb-primary" type="submit">Save step</button><button type="button" onClick={() => setEditing(null)}>Cancel</button></div></form>}
          <form className="pwb-connect" onSubmit={connectNodes}><label>From<select value={source} onChange={(event) => setSource(event.target.value)}><option value="">Choose source</option>{graph.nodes.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}</select></label><span>→</span><label>To<select value={target} onChange={(event) => setTarget(event.target.value)}><option value="">Choose destination</option>{graph.nodes.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}</select></label><button type="submit" disabled={!source || !target}>Connect nodes</button></form>
          <details className="pwb-help"><summary>Connections and keyboard help <ChevronDown size={13}/></summary><ul>{graph.edges.map((edge) => <li key={edge.id}>{graph.nodes.find((node) => node.id === edge.source)?.label} → {graph.nodes.find((node) => node.id === edge.target)?.label}<button type="button" onClick={() => commit({ ...graph, edges: graph.edges.filter((item) => item.id !== edge.id) }, "Connection removed.")}>Remove</button></li>)}</ul><p>Drag a node to reposition it. Use the source and destination selectors to connect steps. Duplicate links and cycles are rejected.</p></details>
          <p className="pwb-message" role="status" aria-live="polite">{message}</p>
        </div>
      </div>
      <aside className="pwb-stack"><div className="pwb-stack-heading"><h4>Connection stack</h4><span>SECURITY ACTIONS</span></div><p>Pick an action to add it after the selected step.</p>{groups.map((group) => { const Icon = group.icon; return <div className="pwb-group" key={group.id}><button type="button" className="pwb-group-toggle" onClick={() => setExpanded((value) => value === group.id ? "" : group.id)}><Icon size={16}/><strong>{group.name}</strong><small>{group.actions.length}</small><span>{expanded === group.id ? "−" : "+"}</span></button>{expanded === group.id && <div className="pwb-group-actions">{group.actions.map((action) => <button type="button" key={action.label} onClick={() => add(action)} disabled={graph.nodes.length >= 20}><span>{action.label}<small>{kindLabel[action.kind]}</small></span><b>+</b></button>)}</div>}</div>; })}</aside>
    </div>
    <div className="pwb-safety-note"><ShieldCheck size={15}/><span><strong>Governed designer · not an execution console.</strong> Drafts are stored locally in this browser. Exported JSON contains workflow structure only. OpsAegis currently supports read-only investigation previews and approval records; provider actions remain disabled.</span></div>
    <style>{styles}</style>
  </section>;
}

const styles = `
.pwb-shell{padding:0!important;overflow:hidden;border:1px solid var(--aegis-border);background:var(--aegis-panel);color:var(--aegis-text)}
.pwb-topline{display:flex;align-items:center;gap:14px;padding:16px 18px;border-bottom:1px solid var(--aegis-border);background:linear-gradient(110deg,color-mix(in srgb,var(--aegis-accent) 8%,var(--aegis-panel)),var(--aegis-panel) 48%)}
.pwb-brand{display:flex;align-items:center;gap:11px;flex:1;min-width:190px}.pwb-brand>span{display:grid;place-items:center;width:36px;height:36px;border-radius:10px;background:var(--aegis-accent);color:#07131d}.pwb-brand strong{display:block;font-size:14px;font-weight:850}.pwb-brand small{display:block;margin-top:3px;color:var(--aegis-muted);font:9px ui-monospace,monospace;letter-spacing:.13em}
.pwb-actions{display:flex;flex-wrap:wrap;gap:7px}.pwb-shell button,.pwb-shell select,.pwb-shell input,.pwb-shell textarea{font:inherit}.pwb-shell button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:36px;padding:7px 10px;border:1px solid var(--aegis-border);border-radius:8px;background:var(--aegis-panel);color:var(--aegis-text);font-size:11px;font-weight:700;cursor:pointer}.pwb-shell button:hover:enabled{border-color:var(--aegis-accent);background:color-mix(in srgb,var(--aegis-accent) 9%,var(--aegis-panel))}.pwb-shell button:disabled{opacity:.4;cursor:not-allowed}.pwb-shell button:focus-visible,.pwb-shell :is(select,input,textarea):focus-visible{outline:2px solid var(--aegis-accent);outline-offset:2px}.pwb-shell .pwb-primary{background:var(--aegis-accent);border-color:var(--aegis-accent);color:#06131c}.pwb-shell .pwb-saved{color:#36bd8a;border-color:#36bd8a66}
.pwb-workspace{display:grid;grid-template-columns:minmax(0,1fr) 255px;min-width:0}.pwb-main{min-width:0}.pwb-canvas-scroll{position:relative;overflow:auto;height:480px;background-image:radial-gradient(color-mix(in srgb,var(--aegis-muted) 48%,transparent) 1px,transparent 1px),radial-gradient(ellipse at 50% 0%,color-mix(in srgb,var(--aegis-accent) 9%,transparent),transparent 68%);background-size:18px 18px,100% 100%}.pwb-canvas{position:relative;width:1500px;height:520px;transform-origin:top left;transition:transform .16s ease}.pwb-links{position:absolute;inset:0;width:1500px;height:520px;overflow:visible;pointer-events:none}.pwb-edge{fill:none;stroke:var(--aegis-accent);stroke-width:2.4;filter:drop-shadow(0 0 4px color-mix(in srgb,var(--aegis-accent) 35%,transparent));stroke-dasharray:8 7;animation:pwb-flow 7s linear infinite}@keyframes pwb-flow{to{stroke-dashoffset:-120}}
.pwb-node{position:absolute!important;display:grid!important;grid-template-columns:36px minmax(0,1fr);align-content:start;gap:0 10px;width:188px;min-height:152px;text-align:left!important;padding:13px!important;border-radius:16px!important;border-color:color-mix(in srgb,var(--aegis-accent) 55%,var(--aegis-border))!important;background:var(--aegis-panel)!important;box-shadow:0 14px 32px -20px #000b,0 0 25px -22px var(--aegis-accent);touch-action:none;cursor:grab!important}.pwb-node:active{cursor:grabbing!important}.pwb-node.selected{outline:2px solid var(--aegis-accent);outline-offset:3px}.pwb-node.agent{--node-accent:#a78bfa}.pwb-node.integration{--node-accent:#38bdf8}.pwb-node.review{--node-accent:#f0b45b}.pwb-node.delivery{--node-accent:#38c99a}.pwb-node-icon{display:grid;place-items:center;width:34px;height:34px;border:1px solid var(--aegis-border);border-radius:9px;background:color-mix(in srgb,var(--node-accent,var(--aegis-accent)) 13%,var(--aegis-panel));color:var(--node-accent,var(--aegis-accent))}.pwb-node-copy{min-width:0;align-self:center}.pwb-node-copy strong{display:block;color:var(--aegis-text);font-size:12px;font-weight:850;line-height:1.25;overflow-wrap:anywhere}.pwb-node-copy small{display:block;margin-top:5px;color:var(--aegis-muted);font:8px ui-monospace,monospace;letter-spacing:.12em}.pwb-node-description{grid-column:1/-1;margin-top:12px;padding-top:10px;border-top:1px solid var(--aegis-border);color:var(--aegis-muted);font-size:10px;line-height:1.5}.pwb-node-tool{grid-column:1/-1;justify-self:start;margin-top:8px;padding:3px 6px;border:1px solid var(--aegis-border);border-radius:5px;color:var(--aegis-muted);font:8px ui-monospace,monospace;text-transform:uppercase}.pwb-port{position:absolute;top:70px;width:9px;height:9px;border:2px solid var(--aegis-panel);border-radius:50%;background:var(--node-accent,var(--aegis-accent))}.pwb-port.left{left:-5px}.pwb-port.right{right:-5px}.pwb-empty{position:absolute;left:40px;top:210px;width:1380px;text-align:center;color:var(--aegis-muted);font-size:13px}
.pwb-zoom{position:sticky;left:14px;bottom:12px;display:flex;gap:3px;width:max-content;margin:-50px 0 12px 14px;padding:4px;border:1px solid var(--aegis-border);border-radius:10px;background:var(--aegis-panel)}.pwb-zoom button{min-width:34px;border:0}.pwb-status{display:flex;justify-content:space-between;gap:12px;padding:10px 16px;border-top:1px solid var(--aegis-border);color:var(--aegis-muted);font:9px ui-monospace,monospace}.pwb-status span:first-child{color:var(--aegis-text)}.pwb-status i{display:inline-block;width:6px;height:6px;margin-right:6px;border-radius:50%;background:#39c891}
.pwb-editor{padding:16px;border-top:1px solid var(--aegis-border)}.pwb-edit-row{display:flex;align-items:end;gap:8px;flex-wrap:wrap}.pwb-edit-row label,.pwb-connect label,.pwb-step-form label{display:grid;gap:5px;flex:1;min-width:160px;color:var(--aegis-muted);font-size:10px;font-weight:700}.pwb-shell select,.pwb-shell input,.pwb-shell textarea{width:100%;min-width:0;min-height:36px;padding:8px 10px;border:1px solid var(--aegis-border);border-radius:8px;background:var(--aegis-panel);color:var(--aegis-text);font-size:11px}.pwb-step-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px;padding:13px;border:1px solid var(--aegis-border);border-radius:10px;background:color-mix(in srgb,var(--aegis-panel) 88%,var(--aegis-accent))}.pwb-step-form>div{display:flex;gap:8px;align-items:end}.pwb-connect{display:flex;align-items:end;gap:10px;margin-top:14px}.pwb-connect label{flex:1}.pwb-connect>span{padding-bottom:10px;color:var(--aegis-muted)}.pwb-help{margin-top:14px;color:var(--aegis-muted);font-size:10px}.pwb-help summary{display:flex;align-items:center;gap:7px;cursor:pointer}.pwb-help ul{padding:0;list-style:none}.pwb-help li{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-top:1px solid var(--aegis-border);color:var(--aegis-text)}.pwb-help li button{min-height:27px;padding:3px 8px}.pwb-help p,.pwb-message{color:var(--aegis-muted);font-size:10px;line-height:1.6}.pwb-message{min-height:16px;margin:10px 0 0;color:var(--aegis-text)}
.pwb-stack{padding:18px 14px;border-left:1px solid var(--aegis-border);background:color-mix(in srgb,var(--aegis-panel) 94%,var(--aegis-accent));min-width:0}.pwb-stack-heading{display:flex;align-items:center;justify-content:space-between;gap:8px}.pwb-stack-heading h4{margin:0;color:var(--aegis-text);font-size:13px;font-weight:850}.pwb-stack-heading span{color:var(--aegis-muted);font:8px ui-monospace,monospace;letter-spacing:.1em}.pwb-stack>p{margin:7px 0 16px;color:var(--aegis-muted);font-size:10px;line-height:1.5}.pwb-group{margin-top:9px;border:1px solid var(--aegis-border);border-radius:10px;background:var(--aegis-panel);overflow:hidden}.pwb-group-toggle{display:flex!important;width:100%;justify-content:flex-start!important;border:0!important;border-radius:0!important;text-align:left}.pwb-group-toggle strong{flex:1;text-align:left;font-size:11px}.pwb-group-toggle small{color:var(--aegis-muted);font:9px ui-monospace,monospace}.pwb-group-toggle>span{color:var(--aegis-muted)}.pwb-group-actions{padding:5px;border-top:1px solid var(--aegis-border)}.pwb-group-actions button{display:flex;width:100%;justify-content:space-between;gap:8px;border:0;text-align:left;font-size:10px;background:transparent}.pwb-group-actions button>span{flex:1}.pwb-group-actions small{display:block;margin-top:3px;color:var(--aegis-muted);font:8px ui-monospace,monospace;letter-spacing:.08em}.pwb-group-actions b{color:var(--aegis-accent);font-size:16px;font-weight:500}
.pwb-safety-note{display:flex;align-items:flex-start;gap:9px;padding:12px 16px;border-top:1px solid var(--aegis-border);background:color-mix(in srgb,var(--aegis-accent) 5%,var(--aegis-panel));color:var(--aegis-muted);font-size:10px;line-height:1.6}.pwb-safety-note svg{flex:0 0 auto;color:#38c99a}.pwb-safety-note strong{color:var(--aegis-text)}
@media(max-width:1050px){.pwb-workspace{grid-template-columns:1fr}.pwb-stack{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;border-left:0;border-top:1px solid var(--aegis-border)}.pwb-stack-heading,.pwb-stack>p{grid-column:1/-1}.pwb-group{margin:0}}
@media(max-width:680px){.pwb-topline{align-items:flex-start;flex-direction:column}.pwb-actions{width:100%}.pwb-actions button{flex:1}.pwb-canvas-scroll{height:400px}.pwb-status{flex-wrap:wrap}.pwb-edit-row{align-items:stretch;flex-direction:column}.pwb-edit-row label{width:100%}.pwb-step-form{grid-template-columns:1fr}.pwb-connect{flex-wrap:wrap}.pwb-connect label{min-width:calc(50% - 8px)}.pwb-connect>span{display:none}.pwb-connect button{width:100%}.pwb-stack{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){.pwb-edge{animation:none}.pwb-canvas{transition:none}}
`;
