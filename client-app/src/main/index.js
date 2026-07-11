'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const http = require('http');

// Unix socket path — must match daemon config
const SOCKET_PATH = '/tmp/eddmc.sock';

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'EDDMC — Cryptojacking Detection',
    backgroundColor: '#0f172a',
    webPreferences: {
      preload: path.join(__dirname, '../preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (!mainWindow) createWindow(); });

// ── Unix socket HTTP helpers ───────────────────────────────────────────────
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
