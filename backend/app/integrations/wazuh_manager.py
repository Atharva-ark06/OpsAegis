from __future__ import annotations
from datetime import datetime,timezone
from typing import Any
from urllib.parse import urlsplit
import httpx
from app.config import Settings,settings
_FIELDS=("id","name","ip","status","lastKeepAlive","os.name","os.version","os.platform","version")
class WazuhManagerError(RuntimeError):
    """Sanitized Wazuh Manager API error; never includes credentials or response bodies."""
class WazuhManagerAdapter:
    """Read-only Wazuh Manager REST API client for registered endpoint inventory."""
    def __init__(self,config:Settings=settings,*,transport:httpx.AsyncBaseTransport|None=None):
        self.config=config;self.transport=transport
    @property
    def is_configured(self)->bool:
        return bool(self.config.wazuh_manager_url and self.config.wazuh_manager_username and self.config.wazuh_manager_password)
    def _base_url(self)->str:
        if not self.is_configured:raise WazuhManagerError("Wazuh Manager is not configured")
        url=self.config.wazuh_manager_url.rstrip("/");parsed=urlsplit(url)
        if parsed.scheme!="https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise WazuhManagerError("Wazuh Manager URL must be a credential-free HTTPS URL without query or fragment")
        return url
    def _client(self)->httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self._base_url(),timeout=httpx.Timeout(self.config.wazuh_manager_timeout_seconds),
            verify=self.config.wazuh_manager_ca_cert or True,follow_redirects=False,trust_env=False,transport=self.transport)
    async def _authenticate(self,client:httpx.AsyncClient)->str:
        try:
            response=await client.post("/security/user/authenticate",auth=(self.config.wazuh_manager_username,self.config.wazuh_manager_password))
            response.raise_for_status();payload=response.json()
        except (httpx.HTTPError,ValueError) as exc:raise WazuhManagerError(f"Wazuh Manager authentication failed ({type(exc).__name__})") from None
        token=payload.get("data",{}).get("token") if isinstance(payload,dict) and isinstance(payload.get("data"),dict) else None
        if not isinstance(token,str) or not token:raise WazuhManagerError("Wazuh Manager returned an invalid authentication response")
        return token
    async def healthcheck(self)->bool:
        async with self._client() as client:
            token=await self._authenticate(client)
            try:
                response=await client.get("/",headers={"Authorization":"Bearer "+token});response.raise_for_status();payload=response.json()
            except (httpx.HTTPError,ValueError) as exc:raise WazuhManagerError(f"Wazuh Manager health request failed ({type(exc).__name__})") from None
            return isinstance(payload,dict) and isinstance(payload.get("data"),dict)
    @staticmethod
    def _items(payload:Any)->tuple[list[dict[str,Any]],int]:
        if not isinstance(payload,dict) or not isinstance(payload.get("data"),dict):raise WazuhManagerError("Wazuh Manager returned an unexpected response shape")
        data=payload["data"];items=data.get("affected_items");total=data.get("total_affected_items")
        if not isinstance(items,list) or not isinstance(total,int) or total<0:raise WazuhManagerError("Wazuh Manager returned an invalid agent collection")
        return [x for x in items if isinstance(x,dict)],total
    async def collect_agents(self)->list[dict[str,Any]]:
        maximum=self.config.wazuh_manager_max_agents;page_size=min(500,maximum);results=[]
        async with self._client() as client:
            token=await self._authenticate(client);headers={"Authorization":"Bearer "+token};offset=0
            while offset<maximum:
                params=[("limit",str(min(page_size,maximum-offset))),("offset",str(offset))]+[("select",field) for field in _FIELDS]
                try:
                    response=await client.get("/agents",params=params,headers=headers);response.raise_for_status();payload=response.json()
                except (httpx.HTTPError,ValueError) as exc:raise WazuhManagerError(f"Wazuh Manager agent inventory request failed ({type(exc).__name__})") from None
                items,total=self._items(payload);results.extend(items[:maximum-len(results)])
                if not items or len(results)>=maximum or offset+len(items)>=total:break
                offset+=len(items)
        return results
    @staticmethod
    def normalize_agent(item:dict[str,Any])->dict[str,Any]|None:
        agent_id=str(item.get("id") or "").strip()
        if not agent_id or agent_id=="000":return None
        name=str(item.get("name") or ("Wazuh agent "+agent_id)).strip()[:255]
        ip=str(item.get("ip") or "").strip()
        if not ip or ip.lower()=="any":ip=None
        os_data=item.get("os") if isinstance(item.get("os"),dict) else {}
        parts=[str(os_data.get(k)).strip() for k in ("name","version") if os_data.get(k)]
        os_name=" ".join(parts)[:255] or (str(os_data.get("platform"))[:255] if os_data.get("platform") else None)
        status=str(item.get("status") or "unknown").strip().lower()
        if status not in {"active","disconnected","pending","never_connected","duplicate","unknown"}:status="unknown"
        last_seen=None;raw=item.get("lastKeepAlive")
        if isinstance(raw,str):
            try:
                parsed=datetime.fromisoformat(raw.replace("Z","+00:00"))
                if parsed.tzinfo is not None:last_seen=parsed.astimezone(timezone.utc)
            except ValueError:pass
        return {"external_id":agent_id,"name":name,"ip_address":ip,"os_name":os_name,"agent_status":status,"last_seen_at":last_seen}
