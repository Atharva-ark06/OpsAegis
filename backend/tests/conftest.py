import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import get_db
from app.main import app
from app.models.entities import Base, User, UserRole
from app.security import create_access_token, hash_password

@pytest.fixture()
def test_session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield factory
    Base.metadata.drop_all(bind=engine)
    engine.dispose()

@pytest.fixture()
def db_session(test_session_factory):
    session = test_session_factory()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture()
def client(test_session_factory):
    def override_get_db():
        db = test_session_factory()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()

@pytest.fixture()
def analyst_headers(db_session):
    analyst = User(
        email="analyst@example.com",
        password_hash=hash_password("Test-Analyst-Password-2026!"),
        role=UserRole.analyst,
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()
    db_session.refresh(analyst)
    token = create_access_token(analyst)
    return {"Authorization": f"Bearer {token}"}
