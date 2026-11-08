from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers.health import router as health_router
from app.routers.assets import router as assets_router
from app.routers.findings import router as findings_router
from app.routers.incidents import router as incidents_router
from app.routers.auth import router as auth_router
from app.routers.integrations import router as integrations_router
from app.routers.nuclei import router as nuclei_router
from app.routers.shannon import router as shannon_router

app = FastAPI(title="OpsAegis API", version="0.6.0",
    description="Integration and incident-management API for OpsAegis.",
    docs_url="/docs" if settings.environment == "development" else None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins,
    allow_credentials=True, allow_methods=["GET","POST","PUT","PATCH","DELETE"],
    allow_headers=["Authorization","Content-Type"])
for router in (health_router, auth_router, assets_router, findings_router, incidents_router,
               integrations_router, nuclei_router, shannon_router):
    app.include_router(router, prefix="/api/v1")

@app.get("/", tags=["root"])
def root() -> dict[str,str]:
    return {"name":"OpsAegis API","status":"running","version":"0.6.0"}
