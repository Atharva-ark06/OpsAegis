import { useMemo } from "react";
import type { Asset, Finding, Incident } from "../../api";
type View = "assets"|"findings"|"vulnerabilities"|"detections"|"incidents"|"integrations"|"threat-intel"|"playbooks"|"users"|"reports"|"settings";
type Props = {view:View;assets:Asset[];findings:Finding[];incidents:Incident[]};
const fmt=(n:number)=>n.toLocaleString();
const title=(s:string)=>s.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase());
const colors=["#35d6a0","#8b5cf6","#38a6ff","#ffb020","#ff755f","#8792a2"];
export function SectionInsights({view,assets,findings,incidents}:Props){
 const data=useMemo(()=>{
  const severity=(s:string)=>findings.filter(x=>x.severity===s).length;
  const active=incidents.filter(x=>["open","investigating","contained"].includes(x.status)).length;
  if(view==="assets"){const groups=Object.entries(assets.reduce<Record<string,number>>((a,x)=>{const k=x.environment||"unknown";a[k]=(a[k]||0)+1;return a;},{}));return {eyebrow:"ATTACK SURFACE",heading:"Asset inventory intelligence",desc:"Explore monitored assets, environment coverage and reported agent connectivity.",kpis:[["REGISTERED ASSETS",assets.length],["ONLINE",assets.filter(x=>["active","connected","online"].includes((x.agent_status||"").toLowerCase())).length],["ENVIRONMENTS",groups.length],["SOURCE-MAPPED",assets.filter(x=>!!x.source_engine).length]],groups:groups.sort((a,b)=>b[1]-a[1]),label:"Assets by environment"};}
  if(["findings","vulnerabilities"].includes(view)){const groups=["critical","high","medium","low","informational","unknown"].map(s=>[s,severity(s)] as [string,number]).filter(x=>x[1]);return {eyebrow:"RISK EXPOSURE",heading:view==="findings"?"Finding intelligence":"Vulnerability exposure",desc:"Prioritize verified risk by severity and track records awaiting analyst attention.",kpis:[["TOTAL FINDINGS",findings.length],["CRITICAL",severity("critical")],["HIGH",severity("high")],["NEW / TRIAGED",findings.filter(x=>["new","triaged"].includes(x.status)).length]],groups,label:"Findings by severity"};}
  if(view==="incidents"){const groups=["open","investigating","contained","resolved","closed"].map(s=>[s,incidents.filter(x=>x.status===s).length] as [string,number]).filter(x=>x[1]);return {eyebrow:"INCIDENT RESPONSE",heading:"Response operations",desc:"Monitor incident lifecycle, active workload and resolution state.",kpis:[["TOTAL INCIDENTS",incidents.length],["ACTIVE",active],["CONTAINED",incidents.filter(x=>x.status==="contained").length],["RESOLVED",incidents.filter(x=>["resolved","closed"].includes(x.status)).length]],groups,label:"Incident lifecycle"};}
  const common: [string, number][]=[["ASSET RECORDS",assets.length],["FINDING RECORDS",findings.length],["ACTIVE INCIDENTS",active],["HIGH / CRITICAL",severity("high")+severity("critical")]];
  const names:Record<string,[string,string]>={detections:["DETECTION ENGINE","Detection intelligence"],integrations:["COLLECTION FABRIC","Integration operations"],"threat-intel":["THREAT CONTEXT","Threat intelligence workspace"],playbooks:["RESPONSE AUTOMATION","Playbook governance"],reports:["OPERATIONAL REPORTING","Security operations reporting"],settings:["WORKSPACE CONFIGURATION","Workspace & access settings"],users:["ACCESS GOVERNANCE","Users & roles"]};
  const [eyebrow,heading]=names[view]||names.settings;
  return {eyebrow,heading,desc:"Live workspace context from authenticated OpsAegis records. Detailed controls and records remain below.",kpis:common,groups:[] as [string,number][],label:""};
 },[view,assets,findings,incidents]);
 const max=Math.max(1,...data.groups.map(x=>x[1]));
 return <section className="section-insights"><div className="section-insights-heading"><div><small>{data.eyebrow}</small><h2>{data.heading}</h2><p>{data.desc}</p></div><span><i/> LIVE API CONTEXT</span></div><div className="section-insights-kpis">{data.kpis.map(([label,value],i)=><article key={label}><span>{label}</span><strong>{fmt(value)}</strong><i style={{background:colors[i%colors.length]}}/></article>)}</div>{data.groups.length>0&&<div className="section-insights-distribution"><div><small>DATA DISTRIBUTION</small><h3>{data.label}</h3></div>{data.groups.map(([name,value],i)=><div className="section-insights-bar" key={name}><span>{title(name)}</span><i><b style={{width:(value/max*100)+"%",background:colors[i%colors.length]}}/></i><strong>{fmt(value)}</strong></div>)}</div>}</section>;
}
