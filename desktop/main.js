const { app, BrowserWindow, session, shell, Menu } = require('electron');
const path = require('path');

if (!app.requestSingleInstanceLock()) app.quit();

let win;
app.on('second-instance', () => {
  if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
});

function create() {
  win = new BrowserWindow({
    width: 1100, height: 720, minWidth: 420, minHeight: 520,
    backgroundColor: '#212121', title: 'Мессенджер', autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  Menu.setApplicationMenu(null);
  win.loadFile(path.join(__dirname, 'www', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
}

app.whenReady().then(() => {
  // микрофон и камера для звонков
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(['media', 'fullscreen', 'notifications'].includes(perm)));
  create();
});
app.on('window-all-closed', () => app.quit());
