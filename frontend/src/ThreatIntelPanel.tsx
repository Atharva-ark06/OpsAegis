import { FormEvent,useEffect,useState } from "react";
import { ApiError,IOCType,ThreatIntelIOC,ThreatIntelProviders,enrichThreatIndicator,getThreatIntelIOCs,getThreatIntelProviders } from "./api";

function dateLabel(value:string|null):string {
 if(!value)return "Not enriched";
 const date=new Date(value);return Number.isNaN(date.getTime())?"—":date.toLocaleString();
}
function verdictLabel(value:string):string{return value.replace(/_/g," ").toUpperCase();}
function ProviderResult({name,result}:{name:string;result:ThreatIntelIOC["provider_results"]["virustotal"]}) {
 return <div className="ioc-provider-result"><div className="panel-heading"><strong>{name}</strong><span className={"ioc-verdict "+result.verdict}>{verdictLabel(result.verdict)}</span></div>
  <p>Status: {result.status} · Provider risk score: {result.risk_score===null?"—":result.risk_score+"/100"}</p>
  <pre>{JSON.stringify(result.details,null,2)}</pre>
 </div>;
}
export function ThreatIntelPanel({canOperate}:{canOperate:boolean}) {
 const [providers,setProviders]=useState<ThreatIntelProviders|null>(null);
 const [items,setItems]=useState<ThreatIntelIOC[]>([]);
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
   setSelected(result);setMessage(result.cached?"Cached provider result returned.":"Provider enrichment completed; review individual provider statuses.");
   setValue(force?"":value);await refresh();
  }catch(reason){setError(reason instanceof ApiError?reason.message:reason instanceof Error?reason.message:"Enrichment failed.");}
  finally{setBusy(false);}
 }
 return <section className="threat-intel-workspace">
  <div className="list-intro"><div><p className="eyebrow">INDICATOR REPUTATION & CONTEXT</p><h2>Threat intelligence workspace</h2><p>Look up an IOC against configured providers. Results are source-attributed; unavailable provider data is never treated as clean.</p></div></div>
  {error&&<div className="error-banner" role="alert">{error}</div>}
  {message&&<div className="success-banner" role="status">{message}</div>}
  <div className="provider-strip">
   <div className="provider-chip"><i className={providers?.virustotal.configured?"configured":""}/><strong>VirusTotal</strong> · {providers?.virustotal.status||"Loading"}</div>
   <div className="provider-chip"><i className={providers?.abuseipdb.configured?"configured":""}/><strong>AbuseIPDB</strong> · {providers?.abuseipdb.status||"Loading"}</div>
   <div className="provider-chip">Cache · {providers?Math.round(providers.cache_ttl_seconds/60)+" min":"—"}</div>
  </div>
  {canOperate&&<form className="threat-intel-form" onSubmit={event=>void enrich(event)}>
   <label>Indicator type<select value={kind} onChange={event=>setKind(event.target.value as IOCType)}><option value="ip">IP address</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">File hash</option></select></label>
   <label>Indicator value<input value={value} onChange={event=>setValue(event.target.value)} required maxLength={2048} placeholder={kind==="ip"?"8.8.8.8":kind==="domain"?"example.com":kind==="url"?"https://example.com/path":"SHA-256 / SHA-1 / MD5 / SHA-512"} /></label>
   <button className="primary-button compact" disabled={busy||!value.trim()||(!providers?.virustotal.configured&&!providers?.abuseipdb.configured)}>{busy?"Checking…":"Enrich indicator"}</button>
   <span className="integration-note">Read-only lookup · No file or URL submission</span>
  </form>}
  {selected&&<section className="panel"><div className="panel-heading"><div><p className="eyebrow">ENRICHMENT RESULT · IOC-{selected.id}</p><h3>{selected.indicator_value}</h3></div><span className={"ioc-verdict "+selected.verdict}>{verdictLabel(selected.verdict)} · {selected.risk_score===null?"No score":selected.risk_score+"/100"}</span></div>
   <p className="integration-note">Type: {selected.indicator_type} · Enriched: {dateLabel(selected.enriched_at)} · {selected.cached?"Cached":"Fresh lookup"}</p>
   <div className="ioc-provider-results"><ProviderResult name="VirusTotal" result={selected.provider_results.virustotal}/><ProviderResult name="AbuseIPDB" result={selected.provider_results.abuseipdb}/></div>
  </section>}
  <section className="panel"><div className="panel-heading"><div><p className="eyebrow">PERSISTED INDICATORS</p><h3>IOC enrichment history</h3></div><button className="secondary-button" onClick={()=>void refresh()}>Refresh history</button></div>
   {items.length===0?<div className="empty-state"><strong>No IOC lookups recorded</strong><p>Enriched indicators will appear here after a provider lookup.</p></div>:
    <div className="ioc-table-wrap"><table className="ioc-table"><thead><tr><th>Indicator</th><th>Verdict</th><th>Score</th><th>Last enriched</th><th>Action</th></tr></thead><tbody>{items.map(item=><tr key={item.id}>
     <td><span className="ioc-value">{item.indicator_value}</span><span className="ioc-sub">{item.indicator_type.toUpperCase()} · IOC-{item.id}</span></td>
     <td><span className={"ioc-verdict "+item.verdict}>{verdictLabel(item.verdict)}</span></td><td>{item.risk_score===null?"—":item.risk_score+"/100"}</td><td>{dateLabel(item.enriched_at)}</td>
     <td><div className="ioc-actions"><button className="text-button" onClick={()=>setSelected(item)}>Details</button>{canOperate&&<button className="text-button" disabled={busy} onClick={event=>void enrich(event as unknown as FormEvent<HTMLFormElement>,item.indicator_type,item.indicator_value,true)}>Recheck</button>}</div></td>
    </tr>)}</tbody></table></div>}
  </section>
  <p className="integration-note">A clean result means configured sources returned no detections in their available data. It is not proof that an indicator is safe. AbuseIPDB supports IP addresses only; provider coverage and rate limits vary by account.</p>
 </section>;
}
