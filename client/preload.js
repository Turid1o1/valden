const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("valdenDesktop", {
  saveJson: (defaultName, content) =>
    ipcRenderer.invoke("valden:save-json", { defaultName, content }),
  getMeta: () => ipcRenderer.invoke("valden:get-meta"),
  consumePendingActivation: () => ipcRenderer.invoke("valden:consume-pending-activation"),
  onActivationPayload: (callback) => {
    if (typeof callback !== "function") {
      return () => {};
    }
    const listener = (_event, payload) => {
      callback(payload);
    };
    ipcRenderer.on("valden:activation-payload", listener);
    return () => {
      ipcRenderer.removeListener("valden:activation-payload", listener);
    };
  },
  openExternal: (url) => ipcRenderer.invoke("valden:open-external", url),
  openPath: (filePath) => ipcRenderer.invoke("valden:open-path", filePath),
  getPermissionsStatus: () => ipcRenderer.invoke("valden:get-permissions-status"),
  promptAccessibility: () => ipcRenderer.invoke("valden:prompt-accessibility"),
  openPermissionsSettings: (kind) => ipcRenderer.invoke("valden:open-permissions-settings", kind),
  injectInput: (inputEvent) => ipcRenderer.invoke("valden:inject-input", inputEvent),
  fileHash: (filePath) => ipcRenderer.invoke("valden:file-hash", filePath),
  fileSelectDestination: (request) => ipcRenderer.invoke("valden:file-select-destination", request),
  fileGetResumeOffset: (request) => ipcRenderer.invoke("valden:file-get-resume-offset", request),
  fileWriteChunk: (request) => ipcRenderer.invoke("valden:file-write-chunk", request),
  fileFinalize: (request) => ipcRenderer.invoke("valden:file-finalize", request),
  fileAbort: (request) => ipcRenderer.invoke("valden:file-abort", request)
});
