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
        try: host=parsed.hostname.encode("idna").decode("ascii").lower()
        except UnicodeError: raise ValueError("URL hostname is invalid") from None
        try:
            address=ipaddress.ip_address(host)
            if not address.is_global: raise ValueError("Private or reserved IPs cannot be used as URL indicators")
            host=address.compressed
        except ValueError as exc:
            if "Private or reserved" in str(exc): raise
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",host): raise ValueError("URL hostname is invalid") from None
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

class VirusTotalAdapter:
    BASE_URL="https://www.virustotal.com/api/v3"
    def __init__(self,config:Settings=settings,*,transport:httpx.AsyncBaseTransport|None=None): self.config,self.transport=config,transport
    async def enrich(self,kind:str,value:str)->dict:
        if not self.config.virustotal_api_key: return {"status":"not_configured","verdict":"unknown","risk_score":None,"details":{}}
        if kind=="url": path="/urls/"+base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else: path="/"+{"ip":"ip_addresses","domain":"domains","hash":"files"}[kind]+"/"+value
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL,headers={"x-apikey":self.config.virustotal_api_key},timeout=httpx.Timeout(self.config.threat_intel_timeout_seconds),verify=True,follow_redirects=False,trust_env=False,transport=self.transport) as client:
                response=await client.get(path)
            if response.status_code==404: return {"status":"not_found","verdict":"unknown","risk_score":None,"details":{}}
            if response.status_code==429: return {"status":"rate_limited","verdict":"unknown","risk_score":None,"details":{}}
            if response.status_code in (401,403): return {"status":"auth_error","verdict":"unknown","risk_score":None,"details":{}}
            response.raise_for_status(); payload=response.json()
        except (httpx.HTTPError,ValueError): return {"status":"error","verdict":"unknown","risk_score":None,"details":{}}
        attrs=payload.get("data",{}).get("attributes",{}) if isinstance(payload,dict) else {}
        stats=attrs.get("last_analysis_stats",{})
        if not isinstance(stats,dict): stats={}
        counts={key:max(0,min(int(stats.get(key,0) or 0),10000)) for key in ("malicious","suspicious","harmless","undetected")}
        total=sum(counts.values()); risk=round(100*(counts["malicious"]+0.5*counts["suspicious"])/total) if total else None
        verdict="malicious" if counts["malicious"] else "suspicious" if counts["suspicious"] else "clean" if total else "unknown"
        details={"analysis":counts}
        if isinstance(attrs.get("reputation"),int): details["reputation"]=max(-100000,min(attrs["reputation"],100000))
        return {"status":"ok","verdict":verdict,"risk_score":risk,"details":details}

class AbuseIPDBAdapter:
    BASE_URL="https://api.abuseipdb.com/api/v2"
    def __init__(self,config:Settings=settings,*,transport:httpx.AsyncBaseTransport|None=None): self.config,self.transport=config,transport
    async def enrich(self,kind:str,value:str)->dict:
        if kind!="ip": return {"status":"not_applicable","verdict":"unknown","risk_score":None,"details":{}}
        if not self.config.abuseipdb_api_key: return {"status":"not_configured","verdict":"unknown","risk_score":None,"details":{}}
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL,headers={"Key":self.config.abuseipdb_api_key,"Accept":"application/json"},timeout=httpx.Timeout(self.config.threat_intel_timeout_seconds),verify=True,follow_redirects=False,trust_env=False,transport=self.transport) as client:
                response=await client.get("/check",params={"ipAddress":value,"maxAgeInDays":90})
            if response.status_code==404: return {"status":"not_found","verdict":"unknown","risk_score":None,"details":{}}
            if response.status_code==429: return {"status":"rate_limited","verdict":"unknown","risk_score":None,"details":{}}
            if response.status_code in (401,403): return {"status":"auth_error","verdict":"unknown","risk_score":None,"details":{}}
            response.raise_for_status(); payload=response.json()
        except (httpx.HTTPError,ValueError): return {"status":"error","verdict":"unknown","risk_score":None,"details":{}}
        data=payload.get("data",{}) if isinstance(payload,dict) else {}; score=data.get("abuseConfidenceScore")
        if not isinstance(score,int): return {"status":"error","verdict":"unknown","risk_score":None,"details":{}}
        score=max(0,min(score,100)); verdict="malicious" if score>=75 else "suspicious" if score>=25 else "clean"
        details={"total_reports":max(0,min(int(data.get("totalReports",0) or 0),1000000))}
        for key in ("countryCode","usageType","isp","lastReportedAt"):
            if isinstance(data.get(key),str): details[key]=data[key][:160]
        return {"status":"ok","verdict":verdict,"risk_score":score,"details":details}
