# NetWatch — frontend + backend

## What this project does
- Keeps the existing NetWatch HTML dashboard and browser-side analysis.
- Adds an Express backend on port 5000.
- Adds a **Backend API** tab. Load a CSV in NetWatch, validate it, then click **Send valid records to backend** to run a separate server-side anomaly pass.
- `GET /api/health` checks whether the backend is running.
- `POST /api/analyze` accepts normalized records from the frontend and returns findings.

The backend rules are heuristic detection rules. Alerts are leads for investigation, not proof that an attack happened. Test only with traffic/data you are authorized to inspect.

## Requirements
- Node.js (LTS recommended) and npm
- VS Code

## Run in VS Code on Windows
1. Extract this ZIP to a normal folder, for example `Desktop\NetWatch_Backend_Project`.
2. Open VS Code → **File → Open Folder** → choose `NetWatch_Backend_Project`.
3. Open **Terminal → New Terminal**.
4. Install dependencies once:
   ```bash
   npm install
   ```
5. Start the backend:
   ```bash
   npm run dev
   ```
6. Open **http://localhost:5000** in your browser. The page is served by the Express server.
7. In NetWatch, open **Data**, click **Load synthetic sample** or upload a network-flow CSV, wait for analysis, then click **Send valid records to backend**. Open the **Backend API** tab to see server-side findings.
8. Optional health check: open **http://localhost:5000/api/health**. You should see JSON with `"status":"ok"`.

## Stop the server
In the terminal, press `Ctrl+C`.

## Git workflow
Run these commands from the project folder:
```bash
git init
git add .
git commit -m "Add NetWatch backend API"
```
Create an empty repository on GitHub, then follow GitHub's instructions to add its remote and push. Do not commit `node_modules`.

## Troubleshooting
- `npm is not recognized`: install Node.js LTS, close and reopen VS Code, then run `node -v` and `npm -v`.
- `EADDRINUSE` / port 5000 already in use: stop the other process or start with a different `PORT`, e.g. PowerShell `$env:PORT=5001; npm run dev`. If you change the port, update the frontend fetch URL in `public/index.html` from `http://localhost:5000` to the chosen port.
- `Failed to fetch`: check that `npm run dev` is still running and use `http://localhost:5000`, not opening `index.html` directly as a `file://` URL.
- `Cannot GET /api/health`: confirm you started the server from this project folder and that `server.js` exists.
- If a CSV's timestamp column is absent, this frontend's current validation logic may use row order as time only when the timestamp mapping is omitted; backend API requests need valid timestamps on every submitted record.

## Current scope
This is a local development backend. It does not capture live packets by itself. To analyse real traffic, export authorized network flow/packet metadata to CSV first. Live packet capture requires a separate capture component and OS permissions.
