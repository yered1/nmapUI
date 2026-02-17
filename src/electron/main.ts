import { app, BrowserWindow, Menu, dialog, ipcMain, shell } from 'electron';
import * as path from 'path';
import * as fs from 'fs';

let mainWindow: BrowserWindow | null = null;

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0a0e1a',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
    show: false,
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  createMenu();
}

function createMenu() {
  const isMac = process.platform === 'darwin';

  const template: Electron.MenuItemConstructorOptions[] = [
    ...(isMac ? [{
      label: app.name,
      submenu: [
        { role: 'about' as const },
        { type: 'separator' as const },
        { role: 'services' as const },
        { type: 'separator' as const },
        { role: 'hide' as const },
        { role: 'hideOthers' as const },
        { role: 'unhide' as const },
        { type: 'separator' as const },
        { role: 'quit' as const },
      ],
    }] : []),
    {
      label: 'File',
      submenu: [
        {
          label: 'Open Nmap File...',
          accelerator: 'CmdOrCtrl+O',
          click: async () => {
            const result = await dialog.showOpenDialog(mainWindow!, {
              properties: ['openFile'],
              filters: [
                { name: 'Nmap Files', extensions: ['xml', 'gnmap', 'nmap', 'txt'] },
                { name: 'NmapUI Projects', extensions: ['nmapui', 'enc'] },
                { name: 'All Files', extensions: ['*'] },
              ],
            });
            if (!result.canceled && result.filePaths.length > 0) {
              const filePath = result.filePaths[0];
              const stat = fs.statSync(filePath);
              if (stat.size > MAX_FILE_SIZE) {
                dialog.showErrorBox('File too large', 'Maximum file size is 100 MB.');
                return;
              }
              const content = fs.readFileSync(filePath, 'utf-8');
              mainWindow?.webContents.send('file-opened', {
                content,
                fileName: path.basename(filePath),
              });
            }
          },
        },
        { type: 'separator' },
        {
          label: 'Export...',
          accelerator: 'CmdOrCtrl+E',
          click: () => {
            mainWindow?.webContents.send('trigger-export');
          },
        },
        { type: 'separator' },
        isMac ? { role: 'close' } : { role: 'quit' },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        ...(isMac ? [
          { type: 'separator' as const },
          { role: 'front' as const },
        ] : [
          { role: 'close' as const },
        ]),
      ],
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About NmapUI',
          click: () => {
            dialog.showMessageBox(mainWindow!, {
              type: 'info',
              title: 'About NmapUI',
              message: 'NmapUI v1.0.0',
              detail: 'Cross-platform UI for parsing, viewing, and exporting Nmap scan results.\n\nSupports XML and Greppable output formats.\nExport to CSV, JSON, HTML, XML, and Markdown.',
            });
          },
        },
        {
          label: 'Nmap Documentation',
          click: () => {
            shell.openExternal('https://nmap.org/book/man.html');
          },
        },
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// Handle file open from command line arguments
// Path traversal is acceptable here: this runs in the Electron main process and
// only opens files passed as CLI arguments by the OS (e.g. double-click or "open with").
// We still validate extension, existence, regular-file check, and size limit.
function handleFileArgs() {
  const allowedExtensions = ['.xml', '.gnmap', '.nmap', '.txt', '.nmapui', '.enc'];
  const filePath = process.argv.find(arg => {
    // Skip electron/chromium flags
    if (arg.startsWith('-')) return false;
    return allowedExtensions.some(ext => arg.endsWith(ext));
  });
  if (filePath && fs.existsSync(filePath)) {
    // Resolve to absolute and verify it's a regular file
    const resolved = path.resolve(filePath);
    try {
      const stat = fs.statSync(resolved);
      if (!stat.isFile()) return;
      if (stat.size > MAX_FILE_SIZE) return;
    } catch {
      return;
    }
    const content = fs.readFileSync(resolved, 'utf-8');
    mainWindow?.webContents.send('file-opened', {
      content,
      fileName: path.basename(resolved),
    });
  }
}

// IPC handlers
ipcMain.handle('save-file', async (_event, { content, defaultName, filters }) => {
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE) {
    return null;
  }
  // Validate filters shape from renderer to prevent misleading dialog
  const safeFilters = Array.isArray(filters)
    ? filters.filter((f: any) => f && typeof f.name === 'string' && Array.isArray(f.extensions))
    : [{ name: 'All Files', extensions: ['*'] }];
  const result = await dialog.showSaveDialog(mainWindow!, {
    defaultPath: defaultName,
    filters: safeFilters.length > 0 ? safeFilters : [{ name: 'All Files', extensions: ['*'] }],
  });
  if (!result.canceled && result.filePath) {
    fs.writeFileSync(result.filePath, content, 'utf-8');
    return result.filePath;
  }
  return null;
});

ipcMain.handle('open-file-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openFile'],
    filters: [
      { name: 'Nmap Files', extensions: ['xml', 'gnmap', 'nmap', 'txt'] },
      { name: 'NmapUI Projects', extensions: ['nmapui', 'enc'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    const filePath = result.filePaths[0];
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      dialog.showErrorBox('File too large', 'Maximum file size is 100 MB.');
      return null;
    }
    const content = fs.readFileSync(filePath, 'utf-8');
    return { content, fileName: path.basename(filePath) };
  }
  return null;
});

// App lifecycle
app.whenReady().then(() => {
  createWindow();

  // Handle file open after window loads
  mainWindow?.webContents.on('did-finish-load', () => {
    handleFileArgs();
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Handle file open on macOS (drag to dock, etc.)
app.on('open-file', (_event, filePath) => {
  if (!mainWindow) return;
  const resolved = path.resolve(filePath);
  const allowedExtensions = ['.xml', '.gnmap', '.nmap', '.txt', '.nmapui', '.enc'];
  if (!allowedExtensions.some(ext => resolved.endsWith(ext))) return;
  try {
    const stat = fs.statSync(resolved);
    if (!stat.isFile()) return;
    if (stat.size > MAX_FILE_SIZE) return;
  } catch { return; }
  const content = fs.readFileSync(resolved, 'utf-8');
  mainWindow.webContents.send('file-opened', {
    content,
    fileName: path.basename(resolved),
  });
});
