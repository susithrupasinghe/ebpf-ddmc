'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const { URL } = require('url');

// Unix socket path — must match daemon config
const SOCKET_PATH = '/tmp/eddmc.sock';

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 840,
    minWidth: 960,
    minHeight: 640,
    title: 'EDDMC — Cryptojacking Detection',
    backgroundColor: '#f9f9f7',
    webPreferences: {
      preload: path.join(__dirname, '../preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '../../renderer/dist/index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (!mainWindow) createWindow(); });

// ── Unix socket HTTP helpers (daemon) ───────────────────────────────────────
// Same as docker: HTTP protocol transported over a Unix domain socket.
// Node's http module supports this natively via the socketPath option.

function apiGet(apiPath) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { socketPath: SOCKET_PATH, path: apiPath, headers: { host: 'localhost' } },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error('Bad JSON: ' + data.slice(0, 80))); }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(3000, () => { req.destroy(new Error('timeout')); });
  });
}

function apiPost(apiPath) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath: SOCKET_PATH,
        path: apiPath,
        method: 'POST',
        headers: { host: 'localhost', 'Content-Length': 0 },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(e); }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

function apiPostJson(apiPath, body) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body || {}));
    const req = http.request(
      {
        socketPath: SOCKET_PATH,
        path: apiPath,
        method: 'POST',
        headers: {
          host: 'localhost',
          'Content-Type': 'application/json',
          'Content-Length': data.length,
        },
      },
      (res) => {
        let chunks = '';
        res.on('data', (chunk) => { chunks += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(chunks)); }
          catch (e) { reject(e); }
        });
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ── Registry HTTP helpers ────────────────────────────────────────────────────
// The registry is a separate service reachable over plain TCP (not the Unix
// socket) -- its URL comes from the daemon's own config. Read-only views (the
// confirmed/pending allowlist lists) talk to it directly; submitting a new
// entry still goes through the daemon (see api:submitAllowlist) so the hash is
// computed on the host side, not by the renderer.

async function registryUrl() {
  const cfg = await apiGet('/api/config');
  const url = cfg && cfg.fingerprint_registry && cfg.fingerprint_registry.registry_url;
  if (!url) throw new Error('fingerprint_registry.registry_url is not configured');
  return url;
}

function httpJson(fullUrl, method) {
  return new Promise((resolve, reject) => {
    const u = new URL(fullUrl);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        headers: { 'Content-Length': 0 },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error('Bad JSON from registry: ' + data.slice(0, 80))); }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(new Error('registry timeout')); });
    req.end();
  });
}

async function registryGet(relPath) {
  const base = await registryUrl();
  return httpJson(base.replace(/\/$/, '') + relPath, 'GET');
}

async function registryPost(relPath) {
  const base = await registryUrl();
  return httpJson(base.replace(/\/$/, '') + relPath, 'POST');
}

// ── IPC handlers ───────────────────────────────────────────────────────────

const offline = { status: 'offline', tracked: 0, uptime: 0, transport: 'unix-socket' };

ipcMain.handle('api:status',     () => apiGet('/api/status').catch(() => offline));
ipcMain.handle('api:processes',  () => apiGet('/api/processes').catch(() => []));
ipcMain.handle('api:detections', () => apiGet('/api/detections').catch(() => []));
ipcMain.handle('api:alerts',     () => apiGet('/api/alerts').catch(() => []));
ipcMain.handle('api:config',     () => apiGet('/api/config').catch(() => ({})));

ipcMain.handle('api:revoke', (_e, pid) =>
  apiPost(`/api/revoke/${pid}`).catch((e) => ({ ok: false, error: String(e) }))
);
ipcMain.handle('api:kill', (_e, pid) =>
  apiPost(`/api/kill/${pid}`).catch((e) => ({ ok: false, error: String(e) }))
);

ipcMain.handle('api:updateDetectionConfig', (_e, newValues) =>
  apiPostJson('/api/config/detection', newValues).catch((e) => ({ error: String(e) }))
);

ipcMain.handle('api:submitAllowlist', (_e, filePath, description) =>
  apiPostJson('/api/allowlist/submit', { path: filePath, description }).catch((e) => ({ error: String(e) }))
);

ipcMain.handle('api:registryPending', () =>
  registryGet('/api/v1/allowlist/pending').catch((e) => ({ error: String(e) }))
);
ipcMain.handle('api:registryConfirmed', () =>
  registryGet('/api/v1/allowlist').catch((e) => ({ error: String(e) }))
);
ipcMain.handle('api:registryStats', () =>
  registryGet('/api/v1/allowlist/stats').catch((e) => ({ error: String(e) }))
);
ipcMain.handle('api:registryConfirm', (_e, sha256) =>
  registryPost(`/api/v1/allowlist/${sha256}/confirm`).catch((e) => ({ error: String(e) }))
);
