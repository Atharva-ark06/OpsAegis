from __future__ import annotations
import base64,ipaddress,re
from urllib.parse import urlsplit
import httpx
from app.config import Settings,settings

def normalize_indicator(kind:str,value:str)->tuple[str,str]:
    raw=value.strip()
    if not raw or len(raw)>2048: raise ValueError("Indicator must contain 1–2048 characters")
    if kind=="ip":
        try: address=ipaddress.ip_address(raw)
        except ValueError: raise ValueError("Enter a valid IPv4 or IPv6 address") from None
        if not address.is_global: raise ValueError("Only globally routable IP addresses can be enriched")
        return kind,address.compressed
    if kind=="domain":
        domain=raw.rstrip(".").lower()
        if len(domain)>253 or "." not in domain or any(ch in domain for ch in "/:@?#"): raise ValueError("Enter a valid fully qualified domain name")
        try: domain=domain.encode("idna").decode("ascii")
        except UnicodeError: raise ValueError("Domain name is invalid") from None
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label) for label in domain.split(".")): raise ValueError("Domain name is invalid")
        if domain.endswith((".local",".localhost",".internal",".test",".invalid")): raise ValueError("Private or reserved domains cannot be enriched")
        return kind,domain
    if kind=="url":
        parsed=urlsplit(raw)
        if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname: raise ValueError("URL indicators must use HTTP or HTTPS and include a hostname")
        if parsed.username is not None or parsed.password is not None: raise ValueError("URL indicators cannot contain credentials")
        if parsed.fragment: raise ValueError("URL indicators must not contain fragments")
        try: host=parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError: raise ValueError("URL hostname is invalid") from None
        if host.endswith((".local",".localhost",".internal",".test",".invalid")): raise ValueError("Private or reserved domains cannot be used as URL indicators")
        try:
            address=ipaddress.ip_address(host)
            if not address.is_global: raise ValueError("Private or reserved IPs cannot be used as URL indicators")
            host=f"[{address.compressed}]" if address.version==6 else address.compressed
        except ValueError as exc:
            if "Private or reserved" in str(exc): raise
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}",host): raise ValueError("URL hostname is invalid") from None
        try: port=f":{parsed.port}" if parsed.port else ""
        except ValueError: raise ValueError("URL port is invalid") from None
        normalized=f"{parsed.scheme.lower()}://{host}{port}{parsed.path or '/'}"
        if parsed.query: normalized+="?"+parsed.query
        if len(normalized)>2048: raise ValueError("URL indicator is too long")
        return kind,normalized
    if kind=="hash":
        digest=raw.lower()
        if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})",digest): raise ValueError("File hash must be a valid MD5, SHA-1, SHA-256 or SHA-512 digest")
        return kind,digest
    raise ValueError("Indicator type must be ip, domain, url or hash")

def _bounded_int(value,maximum:int)->int:
    if isinstance(value,bool): return 0
    try: number=int(value or 0)
    except (TypeError,ValueError,OverflowError): return 0
    return max(0,min(number,maximum))

def _short_text(value,limit:int=240)->str|None:
    return value[:limit] if isinstance(value,str) and value.strip() else None

def _provider_result(status:str,verdict:str="unknown",risk_score:int|None=None,details:dict|None=None)->dict:
    return {"status":status,"verdict":verdict,"risk_score":risk_score,"details":details or {}}

class CrowdSecCTIAdapter:
    """Read-only CrowdSec CTI IP reputation lookup (not a Local API client)."""
    BASE_URL="https://cti.api.crowdsec.net/v2"
    def __init__(self,config:Settings=settings,*,transport:httpx.AsyncBaseTransport|None=None):
        self.config,self.transport=config,transport
    async def enrich(self,kind:str,value:str)->dict:
        if kind!="ip": return _provider_result("not_applicable")
        key=getattr(self.config,"crowdsec_cti_api_key",None)
        if not key: return _provider_result("not_configured")
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL,headers={"x-api-key":key,"Accept":"application/json"},
                timeout=httpx.Timeout(self.config.threat_intel_timeout_seconds),verify=True,follow_redirects=False,
                trust_env=False,transport=self.transport) as client:
                response=await client.get("/smoke/"+value)
            if response.status_code==404: return _provider_result("not_found")
            if response.status_code==429: return _provider_result("rate_limited")
            if response.status_code in (401,403): return _provider_result("auth_error")
            response.raise_for_status()
            payload=response.json()
        except (httpx.HTTPError,ValueError): return _provider_result("error")
        if not isinstance(payload,dict): return _provider_result("error")
        score=payload.get("ip_range_score",payload.get("score"))
        if not isinstance(score,(int,float)) or isinstance(score,bool): score=None
        if score is not None: score=max(0,min(round(score),100))
        classifications=payload.get("classifications")
        if not isinstance(classifications,list): classifications=[]
        normalized=[]
        for entry in classifications[:30]:
            if isinstance(entry,dict):
                normalized.append({str(k)[:60]:str(v)[:180] for k,v in entry.items()
                    if isinstance(v,(str,int,float,bool))})
            elif isinstance(entry,str): normalized.append(entry[:180])
        behaviors=payload.get("behaviors")
        if not isinstance(behaviors,list): behaviors=[]
        normalized_behaviors=[{str(k)[:60]:str(v)[:180] for k,v in item.items()
            if isinstance(v,(str,int,float,bool))} for item in behaviors[:30] if isinstance(item,dict)]
        location=payload.get("location") if isinstance(payload.get("location"),dict) else {}
        as_data=payload.get("as") if isinstance(payload.get("as"),dict) else {}
        details={"ip":value,"classifications":normalized,"behaviors":normalized_behaviors}
        for source,target in ((location,"location"),(as_data,"as")):
            safe={str(k)[:60]:str(v)[:180] for k,v in list(source.items())[:20]
                if isinstance(v,(str,int,float,bool))}
            if safe: details[target]=safe
        for key_name in ("ip_range","ip_range_score","confidence","last_seen","first_seen"):
            raw=payload.get(key_name)
            if isinstance(raw,(str,int,float)) and not isinstance(raw,bool):
                details[key_name]=str(raw)[:180] if isinstance(raw,str) else raw
        verdict="malicious" if score is not None and score>=75 else "suspicious" if score is not None and score>=25 else "clean" if score is not None else "unknown"
        return _provider_result("ok",verdict,score,details)

class VirusTotalAdapter:
    BASE_URL="https://www.virustotal.com/api/v3"
    def __init__(self,config:Settings=settings,*,transport:httpx.AsyncBaseTransport|None=None): self.config,self.transport=config,transport
    async def enrich(self,kind:str,value:str)->dict:
        if not self.config.virustotal_api_key: return _provider_result("not_configured")
        if kind=="url": path="/urls/"+base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else: path="/"+{"ip":"ip_addresses","domain":"domains","hash":"files"}[kind]+"/"+value
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL,headers={"x-apikey":self.config.virustotal_api_key},timeout=httpx.Timeout(self.config.threat_intel_timeout_seconds),verify=True,follow_redirects=False,trust_env=False,transport=self.transport) as client:
                response=await client.get(path)
            if response.status_code==404: return _provider_result("not_found")
            if response.status_code==429: return _provider_result("rate_limited")
            if response.status_code in (401,403): return _provider_result("auth_error")
            response.raise_for_status(); payload=response.json()
        except (httpx.HTTPError,ValueError): return _provider_result("error")
        data=payload.get("data") if isinstance(payload,dict) else None
        attrs=data.get("attributes") if isinstance(data,dict) else None
        if not isinstance(attrs,dict): return _provider_result("error")
        stats=attrs.get("last_analysis_stats",{})
        if not isinstance(stats,dict): stats={}
        counts={key:_bounded_int(stats.get(key,0),10000) for key in ("malicious","suspicious","harmless","undetected")}
        total=sum(counts.values()); risk=round(100*(counts["malicious"]+0.5*counts["suspicious"])/total) if total else None
        verdict="malicious" if counts["malicious"] else "suspicious" if counts["suspicious"] else "clean" if total else "unknown"
        details={"analysis":counts}
        if isinstance(attrs.get("reputation"),int): details["reputation"]=max(-100000,min(attrs["reputation"],100000))
        scalar_fields=("asn","as_owner","country","network","regional_internet_registry","registrar","creation_date","expiration_date",
            "last_analysis_date","last_modification_date","first_submission_date","meaningful_name","type_description","whois")
        for key in scalar_fields:
            value=attrs.get(key)
            if isinstance(value,str):
                clipped=_short_text(value,1000 if key=="whois" else 240)
                if clipped: details[key]=clipped
            elif isinstance(value,int) and not isinstance(value,bool): details[key]=value
        categories=attrs.get("categories")
        if isinstance(categories,dict):
            details["categories"]={str(k)[:80]:str(v)[:120] for k,v in list(categories.items())[:30] if isinstance(v,(str,int,float))}
        tags=attrs.get("tags")
        if isinstance(tags,list): details["tags"]=[str(tag)[:80] for tag in tags[:50] if isinstance(tag,(str,int))]
        results=attrs.get("last_analysis_results")
        flags=[]
        if isinstance(results,dict):
            for engine,result in results.items():
                if not isinstance(result,dict) or result.get("category") not in {"malicious","suspicious"}: continue
                flags.append({"engine":str(engine)[:100],"category":str(result.get("category"))[:30],
                    "result":_short_text(result.get("result"),180),"method":_short_text(result.get("method"),80),
                    "engine_update":_short_text(result.get("engine_update"),40)})
        details["detection_flags"]=flags[:100]
        dns=attrs.get("last_dns_records")
        if isinstance(dns,list):
            details["dns_records"]=[{k:v for k,v in record.items() if k in {"type","value","ttl","priority"} and isinstance(v,(str,int,float))}
                for record in dns[:20] if isinstance(record,dict)]
        votes=attrs.get("total_votes")
        if isinstance(votes,dict): details["community_votes"]={k:_bounded_int(v,100000) for k,v in votes.items() if k in {"harmless","malicious"}}
        return _provider_result("ok",verdict,risk,details)

class AbuseIPDBAdapter:
    BASE_URL="https://api.abuseipdb.com/api/v2"
    CATEGORY_NAMES={3:"Fraud Orders",4:"DDoS Attack",5:"FTP Brute-Force",6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",17:"Spoofing",18:"Brute-Force",19:"Bad Web Bot",20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted"}
    def __init__(self,config:Settings=settings,*,transport:httpx.AsyncBaseTransport|None=None): self.config,self.transport=config,transport
    async def enrich(self,kind:str,value:str)->dict:
        if kind!="ip": return _provider_result("not_applicable")
        if not self.config.abuseipdb_api_key: return _provider_result("not_configured")
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL,headers={"Key":self.config.abuseipdb_api_key,"Accept":"application/json"},timeout=httpx.Timeout(self.config.threat_intel_timeout_seconds),verify=True,follow_redirects=False,trust_env=False,transport=self.transport) as client:
                response=await client.get("/check",params={"ipAddress":value,"maxAgeInDays":90,"verbose":1})
            if response.status_code==404: return _provider_result("not_found")
            if response.status_code==429: return _provider_result("rate_limited")
            if response.status_code in (401,403): return _provider_result("auth_error")
            response.raise_for_status(); payload=response.json()
        except (httpx.HTTPError,ValueError): return _provider_result("error")
        data=payload.get("data") if isinstance(payload,dict) else None
        if not isinstance(data,dict): return _provider_result("error")
        score=data.get("abuseConfidenceScore")
        if not isinstance(score,int) or isinstance(score,bool): return _provider_result("error")
        score=max(0,min(score,100)); verdict="malicious" if score>=75 else "suspicious" if score>=25 else "clean"
        details={"abuse_confidence_score":score,"total_reports":_bounded_int(data.get("totalReports",0),1000000),
            "distinct_reporters":_bounded_int(data.get("numDistinctUsers",0),1000000)}
        field_map={"countryCode":"country_code","usageType":"usage_type","isp":"isp","domain":"domain","lastReportedAt":"last_reported_at"}
        for source,target in field_map.items():
            value=_short_text(data.get(source),240)
            if value: details[target]=value
        if isinstance(data.get("ipVersion"),int): details["ip_version"]=_bounded_int(data["ipVersion"],6)
        for source,target in (("isPublic","is_public"),("isWhitelisted","is_whitelisted")):
            if isinstance(data.get(source),bool): details[target]=data[source]
        hostnames=data.get("hostnames")
        if isinstance(hostnames,list): details["hostnames"]=[str(host)[:240] for host in hostnames[:20] if isinstance(host,str)]
        reports=data.get("reports")
        normalized_reports=[]
        if isinstance(reports,list):
            for report in reports[:20]:
                if not isinstance(report,dict): continue
                category_ids=report.get("categories")
                categories=[{"id":_bounded_int(cid,1000),"name":self.CATEGORY_NAMES.get(_bounded_int(cid,1000),"Other / unclassified")}
                    for cid in category_ids[:20] if isinstance(cid,int) and not isinstance(cid,bool)] if isinstance(category_ids,list) else []
                normalized_reports.append({"reported_at":_short_text(report.get("reportedAt"),40),
                    "comment":_short_text(report.get("comment"),500),"reporter_country_code":_short_text(report.get("reporterCountryCode"),8),
                    "categories":categories})
        details["reports"]=normalized_reports
        return _provider_result("ok",verdict,score,details)
