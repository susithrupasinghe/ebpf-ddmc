'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const http = require('http');

const API_BASE = 'http://127.0.0.1:7373';

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

// ── API helpers ───────────────────────────────────────────────────────────────

function apiGet(path) {
  return new Promise((resolve, reject) => {
    http.get(`${API_BASE}${path}`, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function apiPost(path) {
  return new Promise((resolve, reject) => {
    const req = http.request(`${API_BASE}${path}`, { method: 'POST' }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ── IPC handlers (renderer → main → daemon API) ───────────────────────────────

ipcMain.handle('api:status',     () => apiGet('/api/status').catch(() => ({ status: 'offline' })));
ipcMain.handle('api:processes',  () => apiGet('/api/processes').catch(() => []));
ipcMain.handle('api:detections', () => apiGet('/api/detections').catch(() => []));
ipcMain.handle('api:alerts',     () => apiGet('/api/alerts').catch(() => []));
ipcMain.handle('api:config',     () => apiGet('/api/config').catch(() => ({})));

ipcMain.handle('api:revoke', (_event, pid) =>
  apiPost(`/api/revoke/${pid}`).catch((e) => ({ ok: false, error: String(e) }))
);
ipcMain.handle('api:kill', (_event, pid) =>
  apiPost(`/api/kill/${pid}`).catch((e) => ({ ok: false, error: String(e) }))
);
