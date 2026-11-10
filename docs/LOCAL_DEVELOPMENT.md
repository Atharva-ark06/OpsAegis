# Local development setup

## Prerequisites

- Git
- Python version supported by the backend dependency set and CI
- Node.js 22 or the version pinned by the frontend project
- Docker Engine and Docker Compose v2

## Clone and environment

```powershell
git clone https://github.com/Atharva-ark06/OpsAegis.git
cd OpsAegis
Copy-Item .env.example .env
```

The root `.env.example` contains deliberately unsafe local defaults. It is not a production template. Keep real credentials out of Git.

## Start PostgreSQL and Redis

```powershell
docker compose up -d postgres redis
docker compose ps
```

If service names differ in a future Compose revision, check `docker compose config --services` before starting them.

## Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Keep the backend environment configuration available to the process. The API requires a reachable database and Redis for the normal authenticated workflow.

## Frontend

Open a second PowerShell terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Use the Vite development URL printed by the command. The project config provides the development API proxy; do not hardcode production credentials or provider keys in frontend code.

## Useful checks

```powershell
# Backend
cd backend
pytest -q

# Frontend
cd frontend
npm test
npm run build
```

## Resetting local services

Stopping local containers is different from deleting persistent volumes:

```powershell
docker compose down
```

The command above keeps named volumes. Adding `-v` removes Compose volumes and can delete local PostgreSQL/Redis data. Inspect volume contents and back up anything needed before using it.

## Production is separate

Do not use the local development Compose file as a production recipe. Follow [production Docker deployment](PRODUCTION_DEPLOYMENT.md) or [Railway deployment](RAILWAY_DEPLOYMENT.md).
