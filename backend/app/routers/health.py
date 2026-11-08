from fastapi import APIRouter
router = APIRouter(tags=["health"])

@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "opsaegis-api"}

@router.get("/ready")
def readiness() -> dict[str, str]:
    return {"status": "degraded", "database": "not_checked", "redis": "not_checked"}
