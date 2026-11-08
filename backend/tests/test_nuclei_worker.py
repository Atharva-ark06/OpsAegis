from datetime import datetime, timezone
from app.models.entities import NucleiScanRun, NucleiTarget, User, UserRole
from app.security import hash_password
from app.nuclei_worker import recover, enqueue_due

class FakeRedis:
    def __init__(self): self.values=set(); self.items=[]
    def set(self,key,value,nx=False,ex=None):
        if nx and key in self.values: return False
        self.values.add(key); return True
    def lpush(self,key,value): self.items.insert(0,(key,value))

def make_run(db, email, attempts=0, status="queued"):
    user=User(email=email,password_hash=hash_password("Strong-Test-Password-2026!"),role=UserRole.admin,is_active=True)
    db.add(user); db.flush()
    target=NucleiTarget(name="Staging",url=f"https://{email.split('@')[0]}.example.test",authorization_reference="Approved change AUTH-2026-099",created_by=user.id)
    db.add(target); db.flush()
    run=NucleiScanRun(target_id=target.id,requested_by=user.id,status=status,profile="safe",attempts=attempts,next_attempt_at=datetime.now(timezone.utc))
    db.add(run); db.commit()
    return run

def test_recover_requeues_interrupted_scan(db_session):
    run=make_run(db_session,"worker1@example.test",attempts=1,status="running")
    assert recover(db_session)==1
    db_session.refresh(run)
    assert run.status=="queued" and run.error_code=="worker_restart_recovery"

def test_recover_fails_scan_after_attempt_budget(db_session):
    run=make_run(db_session,"worker2@example.test",attempts=3,status="running")
    assert recover(db_session)==1
    db_session.refresh(run)
    assert run.status=="failed" and run.error_code=="worker_restart_max_attempts"

def test_enqueue_due_is_idempotent(db_session):
    make_run(db_session,"worker3@example.test")
    client=FakeRedis()
    assert enqueue_due(db_session,client)==1
    assert enqueue_due(db_session,client)==0
