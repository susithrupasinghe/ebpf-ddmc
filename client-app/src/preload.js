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

  updateDetectionConfig: (newValues)          => ipcRenderer.invoke('api:updateDetectionConfig', newValues),
  submitAllowlist:       (path, description)  => ipcRenderer.invoke('api:submitAllowlist', path, description),

  registryPending:   () => ipcRenderer.invoke('api:registryPending'),
  registryConfirmed: () => ipcRenderer.invoke('api:registryConfirmed'),
  registryStats:     () => ipcRenderer.invoke('api:registryStats'),
  registryConfirm:   (sha256) => ipcRenderer.invoke('api:registryConfirm', sha256),
});
