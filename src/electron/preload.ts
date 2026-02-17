import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  onFileOpened: (callback: (data: { content: string; fileName: string }) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { content: string; fileName: string }) => callback(data);
    ipcRenderer.on('file-opened', handler);
    return () => { ipcRenderer.removeListener('file-opened', handler); };
  },
  onTriggerExport: (callback: () => void) => {
    const handler = () => callback();
    ipcRenderer.on('trigger-export', handler);
    return () => { ipcRenderer.removeListener('trigger-export', handler); };
  },
  saveFile: (data: { content: string; defaultName: string; filters?: any[] }) => {
    return ipcRenderer.invoke('save-file', data);
  },
  openFileDialog: () => {
    return ipcRenderer.invoke('open-file-dialog');
  },
});
