# Frontend guide

## Stack and build

The frontend is a React/TypeScript application built with Vite. Production assets are compiled in the frontend Docker build stage and served by unprivileged Nginx.

Useful commands:

```powershell
cd frontend
npm ci
npm test
npm run build
npm run dev
```

## API communication

The browser should use the configured same-origin API base path (production: `/api/v1`). Nginx forwards `/api/` requests to the private API service. Do not add direct browser connections to PostgreSQL, Redis, Wazuh, CrowdSec or threat-intelligence providers.

Provider credentials must never be included in frontend source, local storage, query strings or Vite build-time variables.

## UI behavior

- Keep loading, empty, error, success and permission-denied states distinct.
- Disable duplicate submissions while a request is pending.
- Preserve existing handlers and role checks when changing presentation.
- Surface API errors without leaking stack traces, credentials or raw provider payloads.
- Use consistent shared button styles for primary, secondary and compact actions.
- Keep destructive or privileged actions visually distinct and require server-side authorization.
- Ensure keyboard focus, labels and disabled states remain accessible.

## Theme and preferences

The authenticated workspace supports dark, light and system-following appearance. Theme preference is stored locally in the browser; it is not an API-side account setting.

## Validation before a UI pull request

```powershell
npm test
npm run build
```

Also verify the affected screen with viewer, analyst and administrator roles as applicable. A successful frontend build does not prove the API operation or external integration works.
