from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.routers.health import router as health_router
from app.routers.assets import router as assets_router
from app.routers.findings import router as findings_router
from app.routers.incidents import router as incidents_router
from app.routers.auth import router as auth_router
from app.routers.integrations import router as integrations_router
from app.routers.nuclei import router as nuclei_router
from app.routers.shannon import router as shannon_router
from app.routers.detections import router as detections_router
from app.routers.threat_intel import router as threat_intel_router
from app.routers.vulnerabilities import router as vulnerabilities_router
from app.routers.collections import router as collections_router
from app.routers.incident_timeline import router as incident_timeline_router
from app.routers.playbooks import router as playbooks_router

app = FastAPI(
    title="OpsAegis API",
    version="0.8.0",
    description="Integration and incident-management API for OpsAegis.",
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url=None,
)

# Validate the Host header independently of CORS: CORS is not a host-header defense.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path not in {"/docs", "/openapi.json"}:
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    if request.url.path.startswith("/api/v1/auth/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


for router in (
    health_router, auth_router, assets_router, findings_router, incidents_router,
    integrations_router, nuclei_router, shannon_router, detections_router,
    threat_intel_router, vulnerabilities_router, collections_router, incident_timeline_router, playbooks_router,
):
    app.include_router(router, prefix="/api/v1")


@app.get("/", tags=["root"])
def root() -> dict[str, str]:
    return {"name": "OpsAegis API", "status": "running", "version": "0.8.0"}
