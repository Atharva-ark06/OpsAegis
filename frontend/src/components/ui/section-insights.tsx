import { AnalyticsBento } from "./analytics-bento";
import type { Asset, Finding, Incident } from "../../api";

type Props={view:string;assets:Asset[];findings:Finding[];incidents:Incident[]};
const palette=["#7cff5b","#8b3dff","#ffb800","#ff5a1f","#22d3ee","#7b8494"];
const severityOrder=["critical","high","medium","low","informational","unknown"];
const label=(s:string)=>s.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase());
const dayKey=(date:Date)=>date.toISOString().slice(0,10);
const inWindow=(value:string,days:number)=>{const t=new Date(value).getTime();return Number.isFinite(t)&&Date.now()-t<=days*86400000;};
const countByDay=(rows:{date:string}[],days=30)=>Array.from({length:days},(_,i)=>{const d=new Date();d.setUTCHours(0,0,0,0);d.setUTCDate(d.getUTCDate()-(days-1-i));const key=dayKey(d);return {label:d.toLocaleDateString("en-US",{month:"short",day:"numeric",timeZone:"UTC"}),value:rows.filter(r=>dayKey(new Date(r.date))===key).length};});
export function SectionInsights({view,assets,findings,incidents}:Props){
 const now=Date.now();
 const sectionRows=view==="assets"?assets.map(x=>({name:x.name,group:x.environment||"unknown",date:x.created_at})):
  view==="incidents"||view==="playbooks"?incidents.map(x=>({name:x.title,group:x.severity||"unknown",date:x.created_at})):
  view==="integrations"||view==="threat-intel"?findings.map(x=>({name:x.title,group:x.source_engine||"unknown",date:x.first_seen_at})):
  findings.map(x=>({name:x.title,group:x.severity||"unknown",date:x.first_seen_at}));
 const rawGroups=new Map<string,number>();
 sectionRows.forEach(r=>rawGroups.set(r.group,(rawGroups.get(r.group)||0)+1));
 const keys=[...rawGroups.keys()].sort((a,b)=>(rawGroups.get(b)||0)-(rawGroups.get(a)||0)).slice(0,8);
 const groups=keys.map((key,i)=>({id:key,name:label(key),color:palette[i%palette.length],ink:i===0||i===1||i===3?"light" as const:"dark" as const}));
 const records=sectionRows.map(r=>({name:r.name,group:r.group,values:[inWindow(r.date,7)?1:0,inWindow(r.date,30)?1:0,1]}));
 const weekly=sectionRows.filter(r=>inWindow(r.date,7)).length;
 const monthly=sectionRows.filter(r=>inWindow(r.date,30)).length;
 const days=countByDay(sectionRows.map(r=>({date:r.date})));
 const detectionDays=countByDay(findings.map(x=>({date:x.first_seen_at}))).map(x=>x.value);
 const incidentDays=countByDay(incidents.map(x=>({date:x.created_at}))).map(x=>x.value);
 const active=incidents.filter(x=>["open","investigating","contained"].includes(x.status)).length;
 const open=findings.filter(x=>["new","triaged"].includes(x.status)).length;
 const weekday=Array(7).fill(0) as number[];
 findings.forEach(x=>{const d=new Date(x.first_seen_at);if(Number.isFinite(d.getTime())&&now-d.getTime()<=30*86400000)weekday[d.getUTCDay()]++;});
 incidents.forEach(x=>{const d=new Date(x.created_at);if(Number.isFinite(d.getTime())&&now-d.getTime()<=30*86400000)weekday[d.getUTCDay()]++;});
 const heading:Record<string,[string,string,string]>={
 assets:["ATTACK SURFACE","Asset inventory","Registered assets and environment distribution from the asset API."],
 findings:["RISK EXPOSURE","Finding intelligence","Severity, source distribution and first-seen activity from normalized findings."],
 vulnerabilities:["VULNERABILITY EXPOSURE","Vulnerability intelligence","Risk distribution across findings returned by the vulnerability workflow."],
 detections:["DETECTION OPERATIONS","Detection activity","Detection and incident signals aggregated from persisted security records."],
 incidents:["INCIDENT RESPONSE","Incident lifecycle","Incident volume, severity and response status from the incident API."],
 integrations:["COLLECTION FABRIC","Integration coverage","Source coverage and finding activity from connected security engines."],
 "threat-intel":["THREAT CONTEXT","Threat intelligence","Threat-source distribution and security records available to the workspace."],
 playbooks:["RESPONSE AUTOMATION","Response governance","Incident response workload and risk context for playbook operations."],
 reports:["OPERATIONAL REPORTING","Security reporting","Record volumes and trends from authenticated operational datasets."],
 users:["ACCESS GOVERNANCE","Workspace access context","Security workload context alongside the existing administrator-managed user register."],
 settings:["WORKSPACE CONFIGURATION","Workspace health context","Security inventory and response context; account permissions remain server-enforced."]
 };
 const [eyebrow,title,description]=heading[view]||heading.reports;
 const sourceGroups=keys.slice(0,3).map(k=>({label:label(k),value:String(rawGroups.get(k)||0)}));
 const sessionsTotal=detectionDays.reduce((a,b)=>a+b,0)+incidentDays.reduce((a,b)=>a+b,0);
 const eventSeries=days.length>=2?days:[{label:"No data",value:0},{label:"No data",value:0}];
 const dSeries=detectionDays.length>=2?detectionDays:[0,0],iSeries=incidentDays.length>=2?incidentDays:[0,0];
 return <section className="aegis-section-bento">
  <div className="aegis-section-heading"><div><small>{eyebrow}</small><h2>{title}</h2><p>{description}</p></div><span><i/> LIVE API CONTEXT</span></div>
  <AnalyticsBento
   className="mx-auto max-w-[1240px]"
   currency=""
   fontFamily="Inter, ui-sans-serif, system-ui, sans-serif"
   monoFamily="'Geist Mono', ui-monospace, SFMono-Regular, monospace"
   credit={false}
   revenue={{label:view==="assets"?"Registered assets":view==="incidents"?"Incidents":"Records in section",value:sectionRows.length,delta:"API",note:"Current authenticated record set",caption:"First-seen / created activity · 30 days",series:eventSeries}}
   sessions={{label:"Security event streams",value:sessionsTotal,delta:"30D",note:"Persisted findings + incident records",desktop:[dSeries],mobile:[iSeries],labels:{desktop:"Findings",mobile:"Incidents",prior:"",current:"daily activity"}}}
   categories={{title:view==="assets"?"Assets by environment":view==="incidents"?"Incidents by severity":view==="integrations"||view==="threat-intel"?"Findings by source":"Records by classification",groups:groups.length?groups:[{id:"none",name:"No records",color:"#6b7280"}],periods:[{label:"Weekly",total:weekly,delta:"API",compare:"Records created / first seen in 7 days"},{label:"Monthly",total:monthly,delta:"API",compare:"Records created / first seen in 30 days"},{label:"Loaded",total:sectionRows.length,delta:"API",compare:"Current authenticated API response"}],items:records,table:{columns:["Category","Records"],rows:sourceGroups}}}
   seasonality={{title:"Security activity rhythm",axis:["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],years:[{label:"30 days",values:weekday,stats:[{label:"Active incidents",value:active,delta:"LIVE",note:"current incident records"},{label:"Open findings",value:open,delta:"LIVE",note:"new + triaged"}],rows:sourceGroups.map(r=>({label:r.label,value:r.value}))}]}}
   colors={{revenue:["#22d3ee","#3bf08c"],desktop:["#22d3ee","#3c2cff"],mobile:["#ffb800","#ff3da5"],radar:"#3bf08c"}}
  />
 </section>;
}
