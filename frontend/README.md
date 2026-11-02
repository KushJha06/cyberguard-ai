# CyberGuard React Console

Production analyst interface built with React, TypeScript and Vite.

```bash
npm install
npm run dev
```

The Vite server proxies `/api` and `/health` to FastAPI on port 8000. Create an optimized build with `npm run build`. Docker Compose serves the build through Nginx and proxies API requests over the internal Compose network.

The historical Streamlit implementation remains under `src/cyberguard/ui` as an optional reference interface; React is the primary frontend.
