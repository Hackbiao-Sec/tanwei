// 无边框窗口的按钮桥：网页侧只拿到这四个方法，接触不到 Node。
// 主窗口去掉了 titleBarOverlay，原生最小化/最大化/关闭按钮不再画在网页上，
// 改由顶栏右侧自绘，风格才能和深色界面统一。
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("suoyu", {
  platform: process.platform,
  minimize: () => ipcRenderer.send("win:minimize"),
  toggleMaximize: () => ipcRenderer.send("win:toggle-maximize"),
  close: () => ipcRenderer.send("win:close"),
  isMaximized: () => ipcRenderer.sendSync("win:is-maximized") === true,
  // 返回取消订阅函数，组件卸载时调用，避免窗口重建后重复挂监听
  onMaximize: (cb) => {
    const handler = (_e, value) => cb(Boolean(value));
    ipcRenderer.on("win:maximized", handler);
    return () => ipcRenderer.removeListener("win:maximized", handler);
  },
});
