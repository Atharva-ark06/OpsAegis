from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from redis import Redis
from redis.exceptions import RedisError
from app.config import settings
from app.database import get_db
router = APIRouter(tags=["health"])
@router.get("/health")
def health(): return {"status":"ok","service":"opsaegis-api"}
@router.get("/ready")
def readiness(db: Session = Depends(get_db)):
    try: db.execute(text("SELECT 1")); db_status = "ok"
    except Exception: db_status = "unavailable"
    try:
        client = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.ping(); client.close(); redis_status = "ok"
    except RedisError: redis_status = "unavailable"
    state = "ready" if db_status == "ok" and redis_status == "ok" else "degraded"
    return {"status":state,"database":db_status,"redis":redis_status}
