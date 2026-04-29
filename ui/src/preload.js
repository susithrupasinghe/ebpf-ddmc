'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('eddmc', {
  status:     ()      => ipcRenderer.invoke('api:status'),
  processes:  ()      => ipcRenderer.invoke('api:processes'),
  detections: ()      => ipcRenderer.invoke('api:detections'),
  alerts:     ()      => ipcRenderer.invoke('api:alerts'),
  config:     ()      => ipcRenderer.invoke('api:config'),
  revoke:     (pid)   => ipcRenderer.invoke('api:revoke', pid),
  kill:       (pid)   => ipcRenderer.invoke('api:kill',   pid),
});
