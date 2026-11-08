# OpsAegis frontend

The frontend is a React 18 + TypeScript single-page application built with Vite.

## Source files

- `index.html` is the small HTML document shell. It intentionally contains only the root mount point and the Vite module entry; the application UI is rendered by React.
- `src/main.tsx` mounts the React application and imports the stylesheet.
- `src/App.tsx` contains the authenticated SOC workspace and navigation.
- `src/api.ts` contains typed API requests. Operational records are loaded from the backend; the UI must not fabricate telemetry.
- `src/style.css` contains the OpsAegis component styles and theme tokens.
- `tailwind.config.cjs` and `postcss.config.cjs` configure Tailwind CSS 3 and PostCSS for utility styling.

## Development

```bash
npm install
npm run dev
```

## Production build

```bash
npm run test
npm run build
```

Vite compiles TypeScript/TSX and CSS into hashed JavaScript and CSS assets under `dist/assets/`. The generated build output is intentionally not committed to source control; the production Docker image builds it in its Node build stage and copies the compiled assets into the Nginx runtime image.

Tailwind's Preflight reset is intentionally not enabled in the current stylesheet. This avoids unexpectedly resetting the established accessible component styling while Tailwind utilities are introduced incrementally.
