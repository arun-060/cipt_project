const { app, BrowserWindow } = require('electron');
const path = require('path');
const url = require('url');

// Determine if we're in development or production
const isDev = process.env.NODE_ENV === 'development' || process.argv.includes('--dev');

function createWindow() {
    const mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#ffffff',
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    if (isDev) {
        // Development mode - load from localhost
        mainWindow.loadURL('http://localhost:3000');
        mainWindow.webContents.openDevTools();
    } else {
        // Production mode - load from file system
        // In production, this electron.js file is in the build folder
        // alongside index.html
        const startUrl = url.format({
            pathname: path.join(__dirname, 'index.html'),
            protocol: 'file:',
            slashes: true
        });

        console.log('Loading from:', startUrl);
        mainWindow.loadURL(startUrl);
    }

    mainWindow.setMenuBarVisibility(false);

    // Log errors
    mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
        console.error('Failed to load:', errorCode, errorDescription);
    });

    mainWindow.webContents.on('did-finish-load', () => {
        console.log('Page loaded successfully');
    });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
