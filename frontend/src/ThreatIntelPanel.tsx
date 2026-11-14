import { FormEvent,useEffect,useState } from "react";
import { ApiError,Finding,Incident,IOCType,ThreatIntelIOC,ThreatIntelProviders,enrichThreatIndicator,getFindings,getIncidents,getThreatIntelIOCs,getThreatIntelProviders } from "./api";

function dateLabel(value:string|null):string {
 if(!value)return "Not enriched";
 const date=new Date(value);return Number.isNaN(date.getTime())? "—":date.toLocaleString();
}
function verdictLabel(value:string):string{return value.replace(/_/g," ").toUpperCase();}
function fieldLabel(value:string):string{return value.replace(/_/g," ").replace(/\b\w/g,char=>char.toUpperCase());}
function valueLabel(value:unknown):string {
 if(value===null||value===undefined||value==="")return "—";
 if(typeof value==="boolean")return value?"Yes":"No";
 if(typeof value==="object")return JSON.stringify(value);
 return String(value);
}

function ThreatIntelContext({findings,incidents,iocs,loading,error}:{findings:Finding[];incidents:Incident[];iocs:ThreatIntelIOC[];loading:boolean;error:string}) {
 const now=Date.now();
 const monthStart=now-30*86400000;
 const weekStart=now-7*86400000;
 const records=[
  ...findings.map(item=>({date:item.first_seen_at||item.last_seen_at,source:item.source_engine||"Unknown source"})),
  ...incidents.map(item=>({date:item.created_at,source:"Incident response"})),
 ];
 const validRecords=records.filter(item=>Number.isFinite(new Date(item.date).getTime()));
 const weekly=validRecords.filter(item=>new Date(item.date).getTime()>=weekStart).length;
 const monthly=validRecords.filter(item=>new Date(item.date).getTime()>=monthStart).length;
 const activeIncidents=incidents.filter(item=>["open","investigating","contained"].includes(item.status)).length;
 const openFindings=findings.filter(item=>["new","triaged"].includes(item.status)).length;
 const sources=Object.entries(findings.reduce<Record<string,number>>((counts,item)=>{const key=item.source_engine||"Unknown source";counts[key]=(counts[key]||0)+1;return counts;},{})).sort((a,b)=>b[1]-a[1]);
 const weekdays=Array.from({length:7},()=>0);
 validRecords.filter(item=>new Date(item.date).getTime()>=monthStart).forEach(item=>weekdays[new Date(item.date).getDay()]++);
 const maxWeekday=Math.max(1,...weekdays);
 const maxSource=Math.max(1,...sources.map(([,count])=>count));
 const weekdayLabels=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
 return <section className="ti-context" aria-label="Threat intelligence API context">
  <div className="ti-context-heading"><div><p className="eyebrow">LIVE API CONTEXT</p><h3>Threat intelligence</h3><p>Threat-source distribution and security records available to the workspace.</p></div><span className="ti-context-state"><i/>Authenticated API data</span></div>
  {error&&<p className="ti-context-error" role="status">Some context data could not be loaded: {error}</p>}
  <div className="ti-context-metrics">
   <article><small>RECORDS IN SECTION</small><strong>{loading?"—":validRecords.length.toLocaleString()}</strong><span>Current authenticated record set</span><em>First-seen / created activity · 30 days</em></article>
   <article><small>SECURITY EVENT STREAMS</small><strong>{loading?"—":validRecords.length.toLocaleString()}</strong><span>Persisted findings + incident records</span><em>30-day activity window</em></article>
   <article><small>ACTIVE INCIDENTS</small><strong>{loading?"—":activeIncidents.toLocaleString()}</strong><span>Current incident records</span><em>Live API</em></article>
   <article><small>OPEN FINDINGS</small><strong>{loading?"—":openFindings.toLocaleString()}</strong><span>New + triaged findings</span><em>Live API</em></article>
  </div>
  <div className="ti-context-grid">
   <article className="ti-context-card ti-source-card"><div className="ti-card-heading"><div><h4>Findings by source</h4><p>Distribution from persisted finding records</p></div><span>{findings.length} API</span></div>
    {loading?<p className="ti-context-empty">Loading source records…</p>:sources.length===0?<p className="ti-context-empty">No records</p>:<div className="ti-source-list">{sources.map(([source,count])=><div className="ti-source-row" key={source}><div><span>{source}</span><strong>{count}</strong></div><div className="ti-source-track"><i style={{width:(count/maxSource*100)+"%"}}/></div></div>)}</div>}
   </article>
   <article className="ti-context-card ti-period-card"><div className="ti-card-heading"><div><h4>Record activity</h4><p>Created / first-seen records by time window</p></div><span>API</span></div>
    <div className="ti-period-stats"><div><small>Weekly</small><strong>{loading?"—":weekly.toLocaleString()}</strong><span>Records in 7 days</span></div><div><small>Monthly</small><strong>{loading?"—":monthly.toLocaleString()}</strong><span>Records in 30 days</span></div><div><small>Loaded</small><strong>{loading?"—":validRecords.length.toLocaleString()}</strong><span>Current API response</span></div></div>
   </article>
   <article className="ti-context-card ti-rhythm-card"><div className="ti-card-heading"><div><h4>Security activity rhythm</h4><p>First-seen findings and incident creation by weekday</p></div><span>30 days</span></div>
    {loading?<p className="ti-context-empty">Loading activity…</p>:validRecords.length===0?<p className="ti-context-empty">No records in this period.</p>:<div className="ti-weekday-chart" role="img" aria-label="Security records by weekday for the last 30 days">{weekdays.map((count,index)=><div className="ti-weekday-column" key={weekdayLabels[index]}><strong>{count}</strong><i style={{height:Math.max(4,count/maxWeekday*88)+"px"}}/><small>{weekdayLabels[index]}</small></div>)}</div>}
   </article>
   <article className="ti-context-card ti-ioc-card"><div className="ti-card-heading"><div><h4>IOC intelligence</h4><p>Persisted provider enrichment history</p></div><span>{iocs.length} API</span></div><div className="ti-ioc-summary"><strong>{iocs.length.toLocaleString()}</strong><span>Indicators enriched</span><small>VirusTotal · AbuseIPDB · CrowdSec CTI where configured</small></div></article>
  </div>
 </section>;
}

function ProviderResult({name,result}:{name:string;result:ThreatIntelIOC["provider_results"]["virustotal"]}) {
 const details=result.details||{};
 const analysis=details.analysis as Record<string,unknown>|undefined;
 const flags=Array.isArray(details.detection_flags)?details.detection_flags as Array<Record<string,unknown>>:[];
 const categories=details.categories&&typeof details.categories==="object"?Object.entries(details.categories as Record<string,unknown>):[];
 const tags=Array.isArray(details.tags)?details.tags as unknown[]:[];
 const reports=Array.isArray(details.reports)?details.reports as Array<Record<string,unknown>>:[];
 const excluded=new Set(["analysis","detection_flags","categories","tags","reports"]);
 const metadata=Object.entries(details).filter(([key])=>!excluded.has(key));
 return <article className="ioc-provider-result">
  <div className="panel-heading"><strong>{name}</strong><span className={"ioc-verdict "+result.verdict}>{verdictLabel(result.verdict)}</span></div>
  <p>Status: {fieldLabel(result.status)} · Provider risk score: {result.risk_score===null?"—":result.risk_score+"/100"}</p>
  {analysis&&<section className="ioc-evidence-section"><h4>Analysis breakdown</h4><div className="ioc-analysis-grid">
   {Object.entries(analysis).map(([key,count])=><div className={"ioc-analysis-stat "+key} key={key}><strong>{valueLabel(count)}</strong><small>{fieldLabel(key)}</small></div>)}
  </div></section>}
  {flags.length>0&&<section className="ioc-evidence-section"><h4>Detection flags <span className="ioc-count">{flags.length}</span></h4><div className="ioc-flag-list">
   {flags.map((flag,index)=><div className="ioc-flag-row" key={String(flag.engine||index)}><div><strong>{valueLabel(flag.engine)}</strong><small>{valueLabel(flag.method)}{flag.engine_update? " · Updated "+valueLabel(flag.engine_update):""}</small></div><span className={"ioc-flag-category "+String(flag.category||"")}>{valueLabel(flag.category)}</span><p>{valueLabel(flag.result)}</p></div>)}
  </div></section>}
  {categories.length>0&&<section className="ioc-evidence-section"><h4>Classifications</h4><div className="ioc-chip-list">{categories.map(([source,category])=><span className="ioc-data-chip" key={source}>{source}: {valueLabel(category)}</span>)}</div></section>}
  {tags.length>0&&<section className="ioc-evidence-section"><h4>Threat tags</h4><div className="ioc-chip-list">{tags.map((tag,index)=><span className="ioc-data-chip" key={String(tag)+index}>{valueLabel(tag)}</span>)}</div></section>}
  {metadata.length>0&&<section className="ioc-evidence-section"><h4>Indicator intelligence</h4><dl className="ioc-detail-grid">{metadata.map(([key,value])=><div key={key}><dt>{fieldLabel(key)}</dt><dd>{valueLabel(value)}</dd></div>)}</dl></section>}
  {reports.length>0&&<section className="ioc-evidence-section"><h4>Abuse reports <span className="ioc-count">{reports.length} shown</span></h4><div className="ioc-report-list">
   {reports.map((report,index)=><article className="ioc-report" key={String(report.reported_at||index)}><div className="panel-heading"><strong>{valueLabel(report.reported_at)}</strong><span>{valueLabel(report.reporter_country_code)}</span></div><p>{valueLabel(report.comment)}</p><div className="ioc-chip-list">{(Array.isArray(report.categories)?report.categories as Array<Record<string,unknown>>:[]).map((category,i)=><span className="ioc-data-chip" key={String(category.id||i)}>{valueLabel(category.name)}</span>)}</div></article>)}
  </div></section>}
  {result.status==="ok"&&flags.length===0&&<p className="integration-note">No malicious or suspicious engine flags were returned in this provider response. This is not a guarantee of safety.</p>}
  {result.status!=="ok"&&<p className="integration-note">No evidence details available for this provider status. A failed, rate-limited or unsupported lookup is not a clean result.</p>}
 </article>;
}
export function ThreatIntelPanel({canOperate}:{canOperate:boolean}) {
 const [providers,setProviders]=useState<ThreatIntelProviders|null>(null);
 const [items,setItems]=useState<ThreatIntelIOC[]>([]);\n const [findings,setFindings]=useState<Finding[]>([]);\n const [incidents,setIncidents]=useState<Incident[]>([]);\n const [contextLoading,setContextLoading]=useState(true);\n const [contextError,setContextError]=useState("");
 const [kind,setKind]=useState<IOCType>("ip");
 const [value,setValue]=useState("");
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [message,setMessage]=useState("");
 const [selected,setSelected]=useState<ThreatIntelIOC|null>(null);
 async function refresh(){
  const results=await Promise.allSettled([getThreatIntelProviders(),getThreatIntelIOCs()]);
  if(results[0].status==="fulfilled")setProviders(results[0].value);
  if(results[1].status==="fulfilled")setItems(results[1].value);
  const failed=results.find(result=>result.status==="rejected");
  if(failed?.status==="rejected")setError(failed.reason instanceof Error?failed.reason.message:"Unable to load threat intelligence records.");
 }
 useEffect(()=>{void refresh();},[]);
 async function enrich(event:FormEvent<HTMLFormElement>,indicatorType:IOCType=kind,indicatorValue=value,force=false){
  event.preventDefault();setBusy(true);setError("");setMessage("");
  try{
   const result=await enrichThreatIndicator({indicator_type:indicatorType,indicator_value:indicatorValue.trim(),force_refresh:force});
   setSelected(result);setMessage(result.cached?"Cached provider result returned.":"Combined provider enrichment completed. Review the evidence and source disagreements below.");
   setValue(force?"":value);await refresh();
  }catch(reason){setError(reason instanceof ApiError?reason.message:reason instanceof Error?reason.message:"Enrichment failed.");}
  finally{setBusy(false);}
 }
 const vt=selected?.provider_results.virustotal;
 const abuse=selected?.provider_results.abuseipdb;
 const providerConflict=Boolean(vt?.status==="ok"&&abuse?.status==="ok"&&vt.verdict!==abuse.verdict);
 return <section className="threat-intel-workspace">
  <div className="ti-workspace-intro"><div><p className="eyebrow">INDICATOR REPUTATION & CONTEXT</p><h2>Threat intelligence workspace</h2><p>Investigate indicators, understand source coverage and review authenticated security activity.</p></div></div>\n  <ThreatIntelContext findings={findings} incidents={incidents} iocs={items} loading={contextLoading} error={contextError}/>
  {error&&<div className="error-banner" role="alert">{error}</div>}
  {message&&<div className="success-banner" role="status">{message}</div>}
  <div className="provider-strip">
   <div className="provider-chip"><i className={providers?.virustotal.configured?"configured":""}/><strong>VirusTotal</strong> · {providers?.virustotal.status||"Loading"}</div>
   <div className="provider-chip"><i className={providers?.abuseipdb.configured?"configured":""}/><strong>AbuseIPDB</strong> · {providers?.abuseipdb.status||"Loading"}</div>
   <div className="provider-chip"><i className={providers?.crowdsec_cti?.configured?"configured":""}/><strong>CrowdSec CTI</strong> · {providers?.crowdsec_cti?.status||"Loading"}</div>
   <div className="provider-chip">Cache · {providers?Math.round(providers.cache_ttl_seconds/60)+" min":"—"}</div>
  </div>
  {canOperate&&<form className="threat-intel-form" onSubmit={event=>void enrich(event)}>
   <label>Indicator type<select value={kind} onChange={event=>setKind(event.target.value as IOCType)}><option value="ip">IP address</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">File hash</option></select></label>
   <label>Indicator value<input value={value} onChange={event=>setValue(event.target.value)} required maxLength={2048} placeholder={kind==="ip"?"8.8.8.8":kind==="domain"?"example.com":kind==="url"?"https://example.com/path":"SHA-256 / SHA-1 / MD5 / SHA-512"} /></label>
   <button className="primary-button compact" disabled={busy||!value.trim()||(!providers?.virustotal.configured&&!providers?.abuseipdb.configured&&!providers?.crowdsec_cti.configured)}>{busy?"Checking…":"Generate combined report"}</button>
   <span className="integration-note">Read-only lookup · No file upload or URL visit · AbuseIPDB supports public IPs only</span>
  </form>}
  {selected&&<section className="panel ioc-combined-report">
   <div className="panel-heading"><div><p className="eyebrow">COMBINED THREAT INTELLIGENCE REPORT · IOC-{selected.id}</p><h3>{selected.indicator_value}</h3></div><span className={"ioc-verdict "+selected.verdict}>{verdictLabel(selected.verdict)} · {selected.risk_score===null?"No score":selected.risk_score+"/100"}</span></div>
   <p className="integration-note">Type: {selected.indicator_type.toUpperCase()} · Enriched: {dateLabel(selected.enriched_at)} · {selected.cached?"Cached":"Fresh lookup"} · Combined score uses the highest available provider score; it is not a probability.</p>
   {providerConflict&&<div className="ioc-conflict-banner" role="status"><strong>Provider disagreement detected.</strong> VirusTotal and AbuseIPDB returned different verdicts. Review their separate evidence before making a decision.</div>}
   <div className="ioc-provider-results"><ProviderResult name="VirusTotal" result={selected.provider_results.virustotal}/><ProviderResult name="AbuseIPDB" result={selected.provider_results.abuseipdb}/>{selected.provider_results.crowdsec_cti&&<ProviderResult name="CrowdSec CTI" result={selected.provider_results.crowdsec_cti}/>}</div>
  </section>}
  <section className="panel"><div className="panel-heading"><div><p className="eyebrow">PERSISTED INDICATORS</p><h3>IOC enrichment history</h3></div><button className="secondary-button" onClick={()=>void refresh()}>Refresh history</button></div>
   {items.length===0?<div className="empty-state"><strong>No IOC lookups recorded</strong><p>Enriched indicators will appear here after a provider lookup.</p></div>:
    <div className="ioc-table-wrap"><table className="ioc-table"><thead><tr><th>Indicator</th><th>Verdict</th><th>Score</th><th>Last enriched</th><th>Action</th></tr></thead><tbody>{items.map(item=><tr key={item.id}>
     <td><span className="ioc-value">{item.indicator_value}</span><span className="ioc-sub">{item.indicator_type.toUpperCase()} · IOC-{item.id}</span></td>
     <td><span className={"ioc-verdict "+item.verdict}>{verdictLabel(item.verdict)}</span></td><td>{item.risk_score===null?"—":item.risk_score+"/100"}</td><td>{dateLabel(item.enriched_at)}</td>
     <td><div className="ioc-actions"><button className="text-button" onClick={()=>setSelected(item)}>Details</button>{canOperate&&<button className="text-button" disabled={busy} onClick={event=>void enrich(event as unknown as FormEvent<HTMLFormElement>,item.indicator_type,item.indicator_value,true)}>Recheck</button>}</div></td>
    </tr>)}</tbody></table></div>}
  </section>
  <p className="integration-note">A clean verdict only reflects the available provider data at lookup time. AbuseIPDB and CrowdSec CTI support public IP lookups only. Provider rate limits and account coverage affect returned evidence.</p>
 </section>;
}
