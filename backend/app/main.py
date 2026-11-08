from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers.health import router as health_router

app = FastAPI(
    title="OpsAegis API",
    version="0.1.0",
    description="Integration and incident-management API for OpsAegis.",
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(health_router, prefix="/api/v1")

@app.get("/", tags=["root"])
def root() -> dict[str, str]:
    return {"name": "OpsAegis API", "status": "running", "version": "0.1.0"}
