(() => {
  const $ = (id) => document.getElementById(id);
  const FILE_CHUNK_SIZE = 256 * 1024;
  const FILE_ACK_WINDOW_BYTES = 1024 * 1024;

  const els = {
    themeToggle: $("themeToggle"),
    openBackend: $("openBackend"),
    appMeta: $("appMeta"),

    roleAgentBtn: $("roleAgentBtn"),
    roleViewerBtn: $("roleViewerBtn"),
    agentPanel: $("agentPanel"),
    viewerPanel: $("viewerPanel"),

    signalBase: $("signalBase"),

    agentRegister: $("agentRegister"),
    agentConnectWs: $("agentConnectWs"),
    agentDisconnectWs: $("agentDisconnectWs"),
    agentDeviceId: $("agentDeviceId"),
    agentDeviceToken: $("agentDeviceToken"),
    agentGenerateOtp: $("agentGenerateOtp"),
    agentStartShare: $("agentStartShare"),
    agentOtp: $("agentOtp"),
    agentOtpExpires: $("agentOtpExpires"),
    agentAutoAccept: $("agentAutoAccept"),
    agentAcceptNow: $("agentAcceptNow"),
    agentEnableInput: $("agentEnableInput"),
    agentPendingSession: $("agentPendingSession"),
    permAccessibility: $("permAccessibility"),
    permScreen: $("permScreen"),
    permRefresh: $("permRefresh"),
    permPromptAccessibility: $("permPromptAccessibility"),
    permOpenAccessibility: $("permOpenAccessibility"),
    permOpenScreen: $("permOpenScreen"),

    viewerTargetDeviceId: $("viewerTargetDeviceId"),
    viewerOtp: $("viewerOtp"),
    viewerRequestSession: $("viewerRequestSession"),
    viewerConnectWs: $("viewerConnectWs"),
    viewerDisconnectWs: $("viewerDisconnectWs"),
    viewerDeviceId: $("viewerDeviceId"),
    viewerSessionId: $("viewerSessionId"),

    statusRole: $("statusRole"),
    statusWs: $("statusWs"),
    statusSession: $("statusSession"),
    statusPc: $("statusPc"),
    statusTransport: $("statusTransport"),
    statusRtt: $("statusRtt"),

    localVideo: $("localVideo"),
    remoteVideo: $("remoteVideo"),
    remoteInputToggle: $("remoteInputToggle"),
    remoteTextInput: $("remoteTextInput"),
    sendRemoteText: $("sendRemoteText"),
    hangupBtn: $("hangupBtn"),

    fileInput: $("fileInput"),
    sendFileBtn: $("sendFileBtn"),
    fileOutProgress: $("fileOutProgress"),
    fileOutLabel: $("fileOutLabel"),
    fileInProgress: $("fileInProgress"),
    fileInLabel: $("fileInLabel"),
    incomingDownloads: $("incomingDownloads"),

    clipboardToggle: $("clipboardToggle"),
    clipboardText: $("clipboardText"),
    pushClipboard: $("pushClipboard"),
    pullClipboard: $("pullClipboard"),

    exportDiagnostics: $("exportDiagnostics"),
    clearLogs: $("clearLogs"),
    logOutput: $("logOutput"),

    loginScreen: $("loginScreen"),
    mainScreen: $("mainScreen"),
    sessionScreen: $("sessionScreen"),
    loginEmail: $("loginEmail"),
    loginPassword: $("loginPassword"),
    loginSubmit: $("loginSubmit"),
    bootstrapToken: $("bootstrapToken"),
    bootstrapConsumeBtn: $("bootstrapConsumeBtn"),
    loginError: $("loginError"),
    accountEmail: $("accountEmail"),
    updateAppBtn: $("updateAppBtn"),
    logoutBtn: $("logoutBtn"),
    settingsBtn: $("settingsBtn"),
    devicePublicId: $("devicePublicId"),
    copyPublicIdBtn: $("copyPublicIdBtn"),
    refreshDeviceBtn: $("refreshDeviceBtn"),
    connectInfo: $("connectInfo"),
    serverStateConnected: $("serverStateConnected"),
    serverStateReconnecting: $("serverStateReconnecting"),
    serverStateOffline: $("serverStateOffline"),
    sessionDeviceLabel: $("sessionDeviceLabel"),
    sessionTimer: $("sessionTimer"),
    qualityAutoBtn: $("qualityAutoBtn"),
    quality720Btn: $("quality720Btn"),
    quality1080Btn: $("quality1080Btn"),
    qualityValue: $("qualityValue"),
    fpsValue: $("fpsValue"),
    sessionFullscreenBtn: $("sessionFullscreenBtn"),
    sessionSettingsBtn: $("sessionSettingsBtn"),
    switchMonitorBtn: $("switchMonitorBtn"),
    ctrlAltDelBtn: $("ctrlAltDelBtn"),
    fileTransferBtn: $("fileTransferBtn")
  };

  const state = {
    role: "agent",
    signalBase: localStorage.getItem("valden.signalBase") || "https://api.valden.space",

    auth: {
      accessToken: localStorage.getItem("valden.auth.accessToken") || "",
      refreshToken: localStorage.getItem("valden.auth.refreshToken") || "",
      email: localStorage.getItem("valden.auth.email") || "",
      userId: localStorage.getItem("valden.auth.userId") || ""
    },

    agent: {
      deviceKey: localStorage.getItem("valden.agent.deviceKey") || "",
      deviceId: localStorage.getItem("valden.agent.deviceId") || "",
      deviceToken: localStorage.getItem("valden.agent.deviceToken") || "",
      publicId: localStorage.getItem("valden.agent.publicId") || "",
      otp: "",
      otpExpires: "",
      pendingSessionId: "",
      pendingRequester: {
        email: "",
        platform: "",
        publicId: ""
      }
    },

    viewer: {
      deviceId: localStorage.getItem("valden.viewer.deviceId") || crypto.randomUUID(),
      targetDeviceId: "",
      otp: "",
      sessionId: ""
    },

    ws: {
      agent: null,
      viewer: null
    },

    wsManualClose: {
      agent: false,
      viewer: false
    },

    wsReconnectTimers: {
      agent: null,
      viewer: null
    },

    rtc: {
      pc: null,
      sessionId: "",
      offerer: false,
      signalRole: "",
      reconnectAttempts: 0,
      reconnectTimer: null,
      connectTimeoutTimer: null,
      statsTimer: null,
      lastStats: null,
      pendingCandidates: []
    },

    channels: {
      control: null,
      file: null,
      pingTimer: null,
      pings: new Map()
    },

    localStream: null,
    remoteStream: new MediaStream(),

    fileTransfer: {
      outgoing: null,
      incoming: null
    },

    clipboard: {
      enabled: false,
      pollTimer: null,
      lastText: ""
    },

    permissions: {
      platform: "unknown",
      accessibilityTrusted: false,
      screen: "unknown"
    },

    remoteInput: {
      enabled: false,
      lastMoveSentAt: 0,
      lastInjectErrorAt: 0
    },

    ui: {
      currentScreen: "login",
      sessionStartedAt: null,
      sessionTimerTick: null,
      promptedSessions: {}
    },

    stream: {
      preferredQuality: localStorage.getItem("valden.stream.quality") || "auto"
    },

    runtime: {
      version: "0.0.0",
      platform: "unknown",
      arch: "unknown"
    },

    logs: []
  };

  const desktop = window.valdenDesktop || {};

  localStorage.setItem("valden.viewer.deviceId", state.viewer.deviceId);

  function nowISO() {
    return new Date().toISOString();
  }

  function persistAuthState() {
    localStorage.setItem("valden.auth.accessToken", state.auth.accessToken || "");
    localStorage.setItem("valden.auth.refreshToken", state.auth.refreshToken || "");
    localStorage.setItem("valden.auth.email", state.auth.email || "");
    localStorage.setItem("valden.auth.userId", state.auth.userId || "");
  }

  function clearAuthState() {
    state.auth.accessToken = "";
    state.auth.refreshToken = "";
    state.auth.email = "";
    state.auth.userId = "";
    persistAuthState();
  }

  function setScreen(name) {
    state.ui.currentScreen = name;
    els.loginScreen.classList.toggle("is-hidden", name !== "login");
    els.mainScreen.classList.toggle("is-hidden", name !== "main");
    els.sessionScreen.classList.toggle("is-hidden", name !== "session");
  }

  function setLoginError(message = "") {
    if (!els.loginError) {
      return;
    }
    els.loginError.textContent = String(message || "");
  }

  function formatSessionDuration(ms) {
    const totalSec = Math.max(0, Math.floor(ms / 1000));
    const h = String(Math.floor(totalSec / 3600)).padStart(2, "0");
    const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, "0");
    const s = String(totalSec % 60).padStart(2, "0");
    return `${h}:${m}:${s}`;
  }

  function startSessionTimer() {
    if (!els.sessionTimer) {
      return;
    }
    if (state.ui.sessionTimerTick) {
      clearInterval(state.ui.sessionTimerTick);
      state.ui.sessionTimerTick = null;
    }
    state.ui.sessionStartedAt = Date.now();
    els.sessionTimer.textContent = "00:00:00";
    state.ui.sessionTimerTick = window.setInterval(() => {
      if (!state.ui.sessionStartedAt) {
        els.sessionTimer.textContent = "00:00:00";
        return;
      }
      els.sessionTimer.textContent = formatSessionDuration(Date.now() - state.ui.sessionStartedAt);
    }, 1000);
  }

  function stopSessionTimer() {
    if (state.ui.sessionTimerTick) {
      clearInterval(state.ui.sessionTimerTick);
      state.ui.sessionTimerTick = null;
    }
    state.ui.sessionStartedAt = null;
    if (els.sessionTimer) {
      els.sessionTimer.textContent = "00:00:00";
    }
  }

  function log(level, message, extra = null) {
    const line = {
      t: nowISO(),
      level,
      message,
      extra
    };
    state.logs.push(line);
    if (state.logs.length > 1200) {
      state.logs.splice(0, state.logs.length - 1200);
    }

    const text = state.logs
      .slice(-300)
      .map((entry) => {
        const suffix = entry.extra ? ` ${JSON.stringify(entry.extra)}` : "";
        return `[${entry.t}] ${entry.level.toUpperCase()} ${entry.message}${suffix}`;
      })
      .join("\n");
    els.logOutput.textContent = text;
    els.logOutput.scrollTop = els.logOutput.scrollHeight;
  }

  function setStatusText(el, value) {
    const raw = String(value ?? "");
    if (!raw) {
      el.textContent = raw;
      return;
    }

    if (raw.startsWith("pending:")) {
      el.textContent = `ожидание:${raw.slice("pending:".length)}`;
      return;
    }

    const labels = {
      agent: "Агент",
      viewer: "Наблюдатель",
      disconnected: "отключено",
      connecting: "подключение",
      open: "открыто",
      closing: "закрытие",
      closed: "закрыто",
      connected: "подключено",
      reconnecting: "переподключение",
      accepted: "принято",
      ended: "завершено",
      failed: "ошибка",
      idle: "ожидание",
      new: "новое",
      unknown: "неизвестно",
      direct: "прямой",
      relay: "ретрансляция",
      "manual-hangup": "завершено вручную",
      "remote-hangup": "завершено удалённой стороной",
      "switch-session": "переключение сессии",
      "window-close": "закрытие окна"
    };
    el.textContent = labels[raw] || raw;
  }

  function clampNumber(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function hasDesktopCapability(name) {
    return typeof desktop[name] === "function";
  }

  function localizePermissionState(value) {
    const normalized = String(value || "unknown").toLowerCase();
    const labels = {
      granted: "разрешено",
      denied: "запрещено",
      restricted: "ограничено",
      unsupported: "не поддерживается",
      unknown: "неизвестно"
    };
    return labels[normalized] || normalized;
  }

  function localizeIntegrity(value) {
    const normalized = String(value || "unknown").toLowerCase();
    const labels = {
      ok: "OK",
      mismatch: "несовпадение",
      unknown: "неизвестно"
    };
    return labels[normalized] || normalized;
  }

  function updatePermissionWidgets() {
    if (!els.permAccessibility || !els.permScreen) {
      return;
    }

    const accessibility = state.permissions.accessibilityTrusted ? "разрешено" : "не выдано";
    const screen = localizePermissionState(state.permissions.screen);

    els.permAccessibility.textContent = accessibility;
    els.permScreen.textContent = screen;
  }

  async function refreshPermissionsStatus() {
    if (!hasDesktopCapability("getPermissionsStatus")) {
      state.permissions = {
        platform: "unknown",
        accessibilityTrusted: false,
        screen: "unsupported"
      };
      updatePermissionWidgets();
      return;
    }

    try {
      const status = await desktop.getPermissionsStatus();
      state.permissions = {
        platform: status.platform || "unknown",
        accessibilityTrusted: Boolean(status.accessibilityTrusted),
        screen: String(status.screen || "unknown")
      };
      updatePermissionWidgets();
    } catch (err) {
      log("warn", "Не удалось получить статус разрешений", { err: err.message });
    }
  }

  function normalizeSignalBase() {
    let base = (els.signalBase.value || "").trim();
    if (!base) {
      base = "https://api.valden.space";
    }
    if (!/^https?:\/\//i.test(base)) {
      base = `https://${base}`;
    }
    const url = new URL(base);
    if (url.hostname === "valden.space" || url.hostname === "www.valden.space") {
      url.hostname = "api.valden.space";
    }
    state.signalBase = url.origin;
    els.signalBase.value = state.signalBase;
    localStorage.setItem("valden.signalBase", state.signalBase);
    return state.signalBase;
  }

  function applySignalBaseFromActivation(rawBase) {
    const text = String(rawBase || "").trim();
    if (!text) {
      return;
    }
    try {
      let candidate = text;
      if (!/^https?:\/\//i.test(candidate)) {
        candidate = `https://${candidate}`;
      }
      const url = new URL(candidate);
      if (url.hostname === "valden.space" || url.hostname === "www.valden.space") {
        url.hostname = "api.valden.space";
      }
      state.signalBase = url.origin;
      els.signalBase.value = state.signalBase;
      localStorage.setItem("valden.signalBase", state.signalBase);
    } catch (_err) {
      // ignore invalid deep-link api base values
    }
  }

  function makeWsURL(role, params = {}) {
    const base = normalizeSignalBase();
    const u = new URL(base);
    u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
    u.pathname = "/ws";
    u.search = "";
    u.searchParams.set("role", role);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && String(value).trim() !== "") {
        u.searchParams.set(key, String(value));
      }
    }
    return u.toString();
  }

  function authHeaderToken() {
    if (!state.auth.accessToken) {
      return "";
    }
    return `Bearer ${state.auth.accessToken}`;
  }

  async function tryRefreshAuthToken() {
    if (!state.auth.refreshToken) {
      return false;
    }
    try {
      const base = normalizeSignalBase();
      const res = await fetch(`${base}/v1/auth/refresh`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          refresh_token: state.auth.refreshToken
        })
      });
      const text = await res.text();
      const payload = text ? JSON.parse(text) : {};
      if (!res.ok) {
        clearAuthState();
        return false;
      }

      state.auth.accessToken = payload.access_token || "";
      state.auth.refreshToken = payload.refresh_token || "";
      state.auth.email = payload.user?.email || state.auth.email || "";
      state.auth.userId = payload.user?.id || state.auth.userId || "";
      persistAuthState();
      updateAccountLabels();
      return Boolean(state.auth.accessToken);
    } catch (_err) {
      clearAuthState();
      return false;
    }
  }

  async function apiPost(path, body, options = {}) {
    const requiresAuth = Boolean(options?.auth);
    const base = normalizeSignalBase();
    const headers = {
      "Content-Type": "application/json"
    };
    if (requiresAuth && state.auth.accessToken) {
      headers.Authorization = authHeaderToken();
    }

    let res = await fetch(`${base}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body)
    });

    if (requiresAuth && res.status === 401 && (await tryRefreshAuthToken())) {
      headers.Authorization = authHeaderToken();
      res = await fetch(`${base}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body)
      });
    }

    const text = await res.text();
    const payload = text ? JSON.parse(text) : {};
    if (!res.ok) {
      throw new Error(payload.error || `${res.status} ${res.statusText}`);
    }
    return payload;
  }

  async function apiGet(path, options = {}) {
    const requiresAuth = Boolean(options?.auth);
    const base = normalizeSignalBase();
    const headers = {};
    if (requiresAuth && state.auth.accessToken) {
      headers.Authorization = authHeaderToken();
    }
    let res = await fetch(`${base}${path}`, {
      headers
    });
    if (requiresAuth && res.status === 401 && (await tryRefreshAuthToken())) {
      headers.Authorization = authHeaderToken();
      res = await fetch(`${base}${path}`, { headers });
    }
    const text = await res.text();
    const payload = text ? JSON.parse(text) : {};
    if (!res.ok) {
      throw new Error(payload.error || `${res.status} ${res.statusText}`);
    }
    return payload;
  }

  function encodePayload(payload) {
    if (!payload) {
      return undefined;
    }
    return payload;
  }

  function wsStateLabel() {
    const activeWs = state.ws.agent || state.ws.viewer;
    if (!activeWs) {
      return "disconnected";
    }
    switch (activeWs.readyState) {
      case WebSocket.CONNECTING:
        return "connecting";
      case WebSocket.OPEN:
        return "open";
      case WebSocket.CLOSING:
        return "closing";
      case WebSocket.CLOSED:
      default:
        return "closed";
    }
  }

  function sendWs(role, msg) {
    const ws = state.ws[role];
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error(`WS (${role}) не открыт`);
    }
    ws.send(JSON.stringify(msg));
  }

  function safeSendWs(role, msg) {
    try {
      sendWs(role, msg);
    } catch (err) {
      log("warn", `Не удалось отправить WS (${role})`, { err: err.message, type: msg.type || "ACK" });
    }
  }

  function closeWs(role, reason = "manual") {
    const ws = state.ws[role];
    if (state.wsReconnectTimers[role]) {
      clearTimeout(state.wsReconnectTimers[role]);
      state.wsReconnectTimers[role] = null;
    }
    if (!ws) {
      return;
    }
    if (reason === "manual") {
      state.wsManualClose[role] = true;
    }
    try {
      ws.close(1000, reason);
    } catch (_err) {
      // ignored
    }
    state.ws[role] = null;
    refreshStatus();
  }

  function scheduleWsReconnect(role) {
    if (state.wsManualClose[role]) {
      return;
    }
    if (state.wsReconnectTimers[role]) {
      return;
    }
    const existing = state.ws[role];
    if (existing && (existing.readyState === WebSocket.OPEN || existing.readyState === WebSocket.CONNECTING)) {
      return;
    }
    state.wsReconnectTimers[role] = window.setTimeout(() => {
      state.wsReconnectTimers[role] = null;
      const active = state.ws[role];
      if (active && (active.readyState === WebSocket.OPEN || active.readyState === WebSocket.CONNECTING)) {
        return;
      }
      if (role === "agent" && state.agent.deviceId && state.agent.deviceToken) {
        connectAgentWS().catch((err) => log("error", "Не удалось переподключить WS агента", { err: err.message }));
      }
      if (role === "viewer" && state.viewer.sessionId) {
        connectViewerWS().catch((err) => log("error", "Не удалось переподключить WS наблюдателя", { err: err.message }));
      }
    }, 1800);
  }

  async function openWs(role, params) {
    closeWs(role, "replace");
    state.wsManualClose[role] = false;
    const wsURL = makeWsURL(role, params);
    log("info", `Открывается WS (${role})`, { url: wsURL });

    const ws = new WebSocket(wsURL);
    state.ws[role] = ws;
    refreshStatus();

    ws.addEventListener("open", () => {
      log("info", `WS (${role}) открыт`);
      refreshStatus();

      if (role === "agent") {
        safeSendWs("agent", { type: "AGENT_ONLINE" });
      }

      if (role === "viewer" && state.viewer.sessionId) {
        safeSendWs("viewer", {
          type: "VIEWER_HELLO",
          session_id: state.viewer.sessionId,
          payload: encodePayload({ session_id: state.viewer.sessionId })
        });
      }
    });

    ws.addEventListener("message", (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch (err) {
        log("error", "Ошибка разбора WS-сообщения", { role, err: err.message });
        return;
      }

      if (msg.seq) {
        safeSendWs(role, { ack: msg.seq });
      }

      handleWsMessage(role, msg).catch((err) => {
        log("error", "Ошибка обработки WS-сообщения", { role, type: msg.type, err: err.message });
      });
    });

    ws.addEventListener("close", (event) => {
      log("warn", `WS (${role}) закрыт`, { code: event.code, reason: event.reason || "нет" });
      if (state.ws[role] === ws) {
        state.ws[role] = null;
      }
      refreshStatus();
      if (event.reason === "replace") {
        return;
      }
      scheduleWsReconnect(role);
    });

    ws.addEventListener("error", () => {
      log("warn", `Ошибка WS (${role})`);
      refreshStatus();
    });
  }

  function parsePayload(raw) {
    if (!raw) {
      return {};
    }
    if (typeof raw === "object") {
      return raw;
    }
    try {
      return JSON.parse(raw);
    } catch (_err) {
      return {};
    }
  }

  async function handleWsMessage(role, msg) {
    const payload = parsePayload(msg.payload);

    if (msg.type && msg.type !== "ICE_CANDIDATE") {
      const roleLabel = role === "agent" ? "агент" : role === "viewer" ? "наблюдатель" : role;
      log("info", `WS (${roleLabel}) <= ${msg.type}`, {
        session_id: msg.session_id || msg.sessionID || state.rtc.sessionId || ""
      });
    }

    switch (msg.type) {
      case "WS_READY":
        break;

      case "SESSION_NOTIFY": {
        const sessionId = msg.session_id || payload.session_id || "";
        if (!sessionId) {
          break;
        }
        if (state.ui.promptedSessions[sessionId]) {
          break;
        }
        state.ui.promptedSessions[sessionId] = true;

        const requesterEmail = String(payload.requester_email || "").trim();
        const requesterPlatform = String(payload.requester_platform || "").trim();
        const requesterPublicID = String(payload.requester_device_public_id || "").trim();

        state.agent.pendingRequester = {
          email: requesterEmail,
          platform: requesterPlatform,
          publicId: requesterPublicID
        };
        state.agent.pendingSessionId = sessionId;
        els.agentPendingSession.value = sessionId;
        setStatusText(els.statusSession, `pending:${sessionId.slice(0, 8)}`);
        if (state.auth.accessToken && state.ui.currentScreen !== "session") {
          setScreen("main");
        }

        const details = [];
        if (requesterEmail) {
          details.push(`Email: ${requesterEmail}`);
        }
        if (requesterPlatform) {
          details.push(`OS: ${requesterPlatform}`);
        }
        if (requesterPublicID) {
          details.push(`ID: ${formatPublicId(requesterPublicID)}`);
        }
        if (els.connectInfo) {
          const extra = details.length ? ` ${details.join(" • ")}` : "";
          els.connectInfo.textContent = `Входящий запрос на подключение.${extra}`;
        }

        const promptText = details.length
          ? `Запрос на подключение (${sessionId.slice(0, 8)}).\n${details.join("\n")}\nРазрешить?`
          : `Запрос на подключение (${sessionId.slice(0, 8)}). Разрешить?`;
        const shouldAccept = els.agentAutoAccept.checked || window.confirm(promptText);
        if (shouldAccept) {
          await acceptPendingSession();
        } else {
          safeSendWs("agent", {
            type: "HANGUP",
            session_id: sessionId
          });
        }
        break;
      }

      case "SESSION_ACCEPT": {
        const sessionId = msg.session_id || payload.session_id || state.viewer.sessionId;
        if (!sessionId) {
          break;
        }
        state.viewer.sessionId = sessionId;
        els.viewerSessionId.value = sessionId;
        await ensureViewerOffer("session-accepted", false);
        break;
      }

      case "SDP_OFFER": {
        const sessionId = msg.session_id || payload.session_id || state.agent.pendingSessionId;
        await onRemoteOffer(sessionId, payload);
        break;
      }

      case "SDP_ANSWER": {
        await onRemoteAnswer(payload);
        break;
      }

      case "ICE_CANDIDATE": {
        await onRemoteCandidate(msg.session_id || state.rtc.sessionId, payload);
        break;
      }

      case "ICE_RESTART": {
        await onRemoteIceRestart(msg.session_id || state.rtc.sessionId);
        break;
      }

      case "HANGUP": {
        const endedSessionId = String(msg.session_id || payload.session_id || state.rtc.sessionId || state.agent.pendingSessionId || "");
        if (endedSessionId) {
          delete state.ui.promptedSessions[endedSessionId];
        }
        await teardownRtc("remote-hangup");
        setStatusText(els.statusSession, "ended");
        break;
      }

      case "ERROR": {
        log("error", "Ошибка сигналинга", payload);
        break;
      }

      case "PONG":
      case "PING":
      default:
        break;
    }
  }

  async function registerAgent() {
    if (!state.agent.deviceKey) {
      const secret = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      state.agent.deviceKey = `${crypto.randomUUID()}:${secret}`;
      localStorage.setItem("valden.agent.deviceKey", state.agent.deviceKey);
    }

    const response = await apiPost(
      "/v1/device/register",
      {
        device_key: state.agent.deviceKey,
        device_name: navigator.userAgent.includes("Mac") ? "VALDEN macOS device" : "VALDEN desktop device",
        device_meta: {
          platform: navigator.platform,
          userAgent: navigator.userAgent,
          app: "VALDEN Electron"
        }
      },
      { auth: Boolean(state.auth.accessToken) }
    );

    state.agent.deviceId = response.device_id;
    state.agent.deviceToken = response.device_token;
    state.agent.publicId = response.public_id || "";

    localStorage.setItem("valden.agent.deviceId", state.agent.deviceId);
    localStorage.setItem("valden.agent.deviceToken", state.agent.deviceToken);
    localStorage.setItem("valden.agent.publicId", state.agent.publicId);

    els.agentDeviceId.value = state.agent.deviceId;
    els.agentDeviceToken.value = state.agent.deviceToken;
    if (els.devicePublicId) {
      els.devicePublicId.textContent = formatPublicId(state.agent.publicId || state.agent.deviceId);
    }
    log("info", "Агент зарегистрирован", {
      device_id: response.device_id,
      public_id: response.public_id || ""
    });
  }

  function formatPublicId(value) {
    const digits = String(value || "").replace(/\\D/g, "");
    if (digits.length === 9) {
      return `${digits.slice(0, 3)} ${digits.slice(3, 6)} ${digits.slice(6, 9)}`;
    }
    return String(value || "---");
  }

  async function requestViewerSession() {
    const targetDeviceId = els.viewerTargetDeviceId.value.trim();
    const otp = els.viewerOtp.value.trim();
    if (!targetDeviceId) {
      throw new Error("Введите ID удаленного устройства");
    }

    if (state.auth.accessToken && (!state.agent.deviceId || !state.agent.deviceToken)) {
      await registerAgent();
    }

    const requesterPlatform =
      state.permissions.platform && state.permissions.platform !== "unknown"
        ? state.permissions.platform
        : navigator.userAgentData?.platform || navigator.platform || "unknown";

    const response = await apiPost(
      "/v1/session/request",
      {
        device_id: targetDeviceId,
        otp,
        requester_device_id: state.agent.deviceId || "",
        requester_platform: String(requesterPlatform),
        requester_email: state.auth.email || ""
      },
      { auth: Boolean(state.auth.accessToken) }
    );

    state.viewer.targetDeviceId = targetDeviceId;
    state.viewer.otp = otp;
    state.viewer.sessionId = response.session_id;
    els.viewerSessionId.value = response.session_id;
    if (els.sessionDeviceLabel) {
      els.sessionDeviceLabel.textContent = targetDeviceId;
    }
    setStatusText(els.statusSession, response.status.toLowerCase());
    setRole("viewer");
    if (els.connectInfo) {
      els.connectInfo.textContent = "Запрос отправлен. Ожидание подтверждения...";
    }
    log("info", "Сессия наблюдателя запрошена", {
      session_id: response.session_id,
      status: response.status
    });

    await connectViewerWS();
  }

  async function connectAgentWS() {
    if (!state.agent.deviceId || !state.agent.deviceToken) {
      throw new Error("Сначала зарегистрируйте устройство агента");
    }
    await openWs("agent", {
      device_id: state.agent.deviceId,
      device_token: state.agent.deviceToken
    });
  }

  function updateAccountLabels() {
    if (els.accountEmail) {
      els.accountEmail.textContent = state.auth.email || "-";
    }
  }

  function getUpdateInstallHint() {
    if (state.runtime.platform === "win32") {
      return "Обновление запущено. Приложение закроется и установится автоматически.";
    }
    if (state.runtime.platform === "darwin") {
      return "Обновление запущено. VALDEN автоматически заменится и перезапустится.";
    }
    return "Открыт файл обновления.";
  }

  async function runSelfUpdate() {
    if (!hasDesktopCapability("selfUpdate")) {
      throw new Error("Автообновление недоступно");
    }

    const result = await desktop.selfUpdate();
    if (!result?.ok) {
      throw new Error(result?.error || "Не удалось запустить обновление");
    }
    return result;
  }

  async function loginWithCredentials() {
    const email = (els.loginEmail.value || "").trim();
    const password = els.loginPassword.value || "";
    if (!email || !password) {
      throw new Error("Введите email и пароль");
    }

    const response = await apiPost("/v1/auth/login", {
      email,
      password
    });

    state.auth.accessToken = response.access_token || "";
    state.auth.refreshToken = response.refresh_token || "";
    state.auth.email = response.user?.email || email;
    state.auth.userId = response.user?.id || "";
    persistAuthState();
    updateAccountLabels();

    await registerAgent();
    if (els.devicePublicId) {
      els.devicePublicId.textContent = formatPublicId(state.agent.publicId || state.agent.deviceId);
    }
    await connectAgentWS();
    setScreen("main");
  }

  async function consumeBootstrapTokenWithValue(token) {
    if (!token) {
      throw new Error("Вставьте bootstrap-токен");
    }

    if (!state.agent.deviceKey) {
      const secret = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      state.agent.deviceKey = `${crypto.randomUUID()}:${secret}`;
      localStorage.setItem("valden.agent.deviceKey", state.agent.deviceKey);
    }

    const payload = await apiPost("/v1/client/bootstrap/consume", {
      bootstrap_token: token,
      device_key: state.agent.deviceKey,
      device_name: navigator.userAgent.includes("Mac") ? "VALDEN macOS device" : "VALDEN desktop device",
      device_meta: {
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        app: "VALDEN Electron"
      }
    });

    state.auth.accessToken = payload.access_token || "";
    state.auth.refreshToken = payload.refresh_token || "";
    state.auth.email = payload.user?.email || "";
    state.auth.userId = payload.user?.id || "";
    persistAuthState();
    updateAccountLabels();

    state.agent.deviceId = payload.device?.device_id || "";
    state.agent.deviceToken = payload.device?.device_token || "";
    state.agent.publicId = payload.device?.public_id || "";
    localStorage.setItem("valden.agent.deviceId", state.agent.deviceId);
    localStorage.setItem("valden.agent.deviceToken", state.agent.deviceToken);
    localStorage.setItem("valden.agent.publicId", state.agent.publicId);
    if (els.devicePublicId) {
      els.devicePublicId.textContent = formatPublicId(state.agent.publicId || state.agent.deviceId);
    }

    await connectAgentWS();
    setScreen("main");
  }

  async function consumeBootstrapToken() {
    const token = (els.bootstrapToken?.value || "").trim();
    await consumeBootstrapTokenWithValue(token);
    if (els.bootstrapToken) {
      els.bootstrapToken.value = "";
    }
  }

  async function applyActivationPayload(payload) {
    const token = String(payload?.token || "").trim();
    if (!token) {
      return false;
    }

    applySignalBaseFromActivation(payload?.api);
    setLoginError("");
    if (els.bootstrapToken) {
      els.bootstrapToken.value = token;
    }

    try {
      await consumeBootstrapTokenWithValue(token);
      if (els.bootstrapToken) {
        els.bootstrapToken.value = "";
      }
      setLoginError("");
      log("info", "Приложение активировано без ручного ввода токена");
      return true;
    } catch (err) {
      setLoginError(`Не удалось активировать приложение: ${err.message}`);
      log("warn", "Активация по ссылке завершилась ошибкой", { err: err.message });
      return false;
    }
  }

  async function logoutApp() {
    clearAuthState();
    closeWs("agent", "manual");
    closeWs("viewer", "manual");
    await teardownRtc("manual");
    setScreen("login");
    updateAccountLabels();
    setLoginError("");
  }

  async function generateOtp() {
    if (!state.agent.deviceToken) {
      throw new Error("Отсутствует токен агента");
    }
    const response = await apiPost("/v1/device/otp", {
      device_token: state.agent.deviceToken
    });
    state.agent.otp = response.otp;
    state.agent.otpExpires = response.expires_at;

    els.agentOtp.textContent = response.otp;
    els.agentOtpExpires.textContent = response.expires_at;
    log("info", "OTP сгенерирован", { expires_at: response.expires_at });
  }

  async function ensureAgentLocalStream() {
    if (state.localStream && state.localStream.getTracks().some((t) => t.readyState === "live")) {
      return state.localStream;
    }

    const stream = await navigator.mediaDevices.getDisplayMedia({
      video: {
        frameRate: { ideal: 30, max: 30 },
        width: { ideal: 1920 },
        height: { ideal: 1080 }
      },
      audio: false
    });

    stream.getVideoTracks().forEach((track) => {
      track.addEventListener("ended", () => {
        log("warn", "Трек демонстрации экрана завершён");
      });
    });

    state.localStream = stream;
    els.localVideo.srcObject = stream;
    log("info", "Демонстрация экрана запущена");
    await applyOutboundQuality(state.stream.preferredQuality);

    if (state.rtc.pc && !state.rtc.offerer) {
      attachLocalTracks(state.rtc.pc);
      if (state.rtc.pc.signalingState === "stable" && state.rtc.sessionId) {
        const answer = await state.rtc.pc.createAnswer();
        await state.rtc.pc.setLocalDescription(answer);
        safeSendWs(state.rtc.signalRole, {
          type: "SDP_ANSWER",
          session_id: state.rtc.sessionId,
          payload: encodePayload({ type: answer.type, sdp: answer.sdp, reason: "track-update" })
        });
      }
    }

    return stream;
  }


  async function connectViewerWS() {
    if (!state.viewer.sessionId) {
      throw new Error("Нет активного ID сессии. Сначала запросите сессию.");
    }

    const viewerDeviceID = state.agent.deviceId || state.viewer.deviceId;
    state.viewer.deviceId = viewerDeviceID;
    localStorage.setItem("valden.viewer.deviceId", state.viewer.deviceId);

    await openWs("viewer", {
      device_id: viewerDeviceID,
      session_id: state.viewer.sessionId
    });
  }

  async function fetchIceServers(role, sessionId) {
    const baseServers = [
      {
        urls: ["stun:stun.l.google.com:19302"]
      }
    ];

    try {
      if (role === "agent") {
        if (!state.agent.deviceToken) {
          return baseServers;
        }
        const turn = await apiPost("/v1/turn/credentials", {
          device_token: state.agent.deviceToken
        });
        return [
          ...baseServers,
          {
            urls: turn.urls,
            username: turn.username,
            credential: turn.password
          }
        ];
      }

      if (role === "viewer" && sessionId) {
        const turn = await apiPost("/v1/turn/credentials/session", {
          session_id: sessionId
        });
        return [
          ...baseServers,
          {
            urls: turn.urls,
            username: turn.username,
            credential: turn.password
          }
        ];
      }
    } catch (err) {
      log("warn", "TURN недоступен, используется только STUN", {
        role,
        err: err.message
      });
    }

    return baseServers;
  }

  function preferVideoCodecs(pc) {
    try {
      if (typeof RTCRtpSender === "undefined" || typeof RTCRtpSender.getCapabilities !== "function") {
        return;
      }

      const capabilities = RTCRtpSender.getCapabilities("video");
      const codecs = capabilities?.codecs || [];
      if (!codecs.length) {
        return;
      }

      const h264 = codecs.filter((codec) => /video\/h264/i.test(codec.mimeType || ""));
      const vp8 = codecs.filter((codec) => /video\/vp8/i.test(codec.mimeType || ""));
      const others = codecs.filter((codec) => !/video\/h264|video\/vp8/i.test(codec.mimeType || ""));
      const ordered = [...h264, ...vp8, ...others];
      if (!ordered.length) {
        return;
      }

      for (const transceiver of pc.getTransceivers()) {
        if (transceiver.sender?.track?.kind !== "video") {
          continue;
        }
        if (typeof transceiver.setCodecPreferences === "function") {
          transceiver.setCodecPreferences(ordered);
          log("info", "Применены предпочтения видеокодеков", {
            primary: h264.length ? "H264" : vp8.length ? "VP8" : "browser-default"
          });
        }
      }
    } catch (err) {
      log("warn", "Не удалось применить предпочтения кодеков", { err: err.message });
    }
  }

  function attachLocalTracks(pc) {
    if (!state.localStream) {
      return;
    }

    const existingTrackIds = new Set(pc.getSenders().map((sender) => sender.track?.id).filter(Boolean));
    for (const track of state.localStream.getTracks()) {
      if (!existingTrackIds.has(track.id)) {
        pc.addTrack(track, state.localStream);
      }
    }

    preferVideoCodecs(pc);
  }

  function setQualityUi(mode) {
    const normalized = ["auto", "720p", "1080p"].includes(mode) ? mode : "auto";
    state.stream.preferredQuality = normalized;
    localStorage.setItem("valden.stream.quality", normalized);
    if (els.qualityValue) {
      els.qualityValue.textContent = normalized === "auto" ? "Auto" : normalized;
    }
    if (els.qualityAutoBtn) els.qualityAutoBtn.classList.toggle("is-active", normalized === "auto");
    if (els.quality720Btn) els.quality720Btn.classList.toggle("is-active", normalized === "720p");
    if (els.quality1080Btn) els.quality1080Btn.classList.toggle("is-active", normalized === "1080p");
  }

  async function applyOutboundQuality(mode) {
    const normalized = ["auto", "720p", "1080p"].includes(mode) ? mode : "auto";
    setQualityUi(normalized);

    if (!state.rtc.pc) {
      return;
    }

    const sender = state.rtc.pc
      .getSenders()
      .find((item) => item?.track && item.track.kind === "video");
    if (!sender) {
      return;
    }

    const params = sender.getParameters ? sender.getParameters() : {};
    if (!params.encodings || !params.encodings.length) {
      params.encodings = [{}];
    }
    const encoding = params.encodings[0];

    if (normalized === "auto") {
      delete encoding.maxBitrate;
      delete encoding.scaleResolutionDownBy;
      delete encoding.maxFramerate;
    } else if (normalized === "720p") {
      encoding.maxBitrate = 2500000;
      encoding.scaleResolutionDownBy = 1.5;
      encoding.maxFramerate = 30;
    } else if (normalized === "1080p") {
      encoding.maxBitrate = 4500000;
      encoding.scaleResolutionDownBy = 1;
      encoding.maxFramerate = 30;
    }

    if (sender.setParameters) {
      await sender.setParameters(params);
    }

    const track = sender.track;
    if (track && track.applyConstraints) {
      if (normalized === "720p") {
        await track.applyConstraints({
          width: { ideal: 1280 },
          height: { ideal: 720 },
          frameRate: { ideal: 30, max: 30 }
        });
      } else if (normalized === "1080p") {
        await track.applyConstraints({
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: 30, max: 30 }
        });
      } else {
        await track.applyConstraints({
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: 30, max: 30 }
        });
      }
    }
  }

  async function requestQualityChange(mode) {
    const normalized = ["auto", "720p", "1080p"].includes(mode) ? mode : "auto";
    setQualityUi(normalized);

    if (state.role === "agent") {
      await applyOutboundQuality(normalized);
      return;
    }

    if (!sendControl({ type: "quality-set", mode: normalized })) {
      throw new Error("Канал управления не открыт");
    }
  }

  async function ensurePeerConnection(role, offerer, sessionId) {
    if (!sessionId) {
      throw new Error("Для peer-соединения требуется ID сессии");
    }

    if (state.rtc.pc && state.rtc.sessionId !== sessionId) {
      await teardownRtc("switch-session");
    }

    if (state.rtc.pc) {
      return state.rtc.pc;
    }

    const iceServers = await fetchIceServers(role, sessionId);
    const pc = new RTCPeerConnection({
      iceServers,
      iceTransportPolicy: "all"
    });

    state.rtc.pc = pc;
    state.rtc.sessionId = sessionId;
    state.rtc.offerer = offerer;
    state.rtc.signalRole = role;
    state.rtc.reconnectAttempts = 0;
    state.rtc.pendingCandidates = [];

    if (role === "agent") {
      attachLocalTracks(pc);
    }

    if (offerer) {
      setupControlChannel(pc.createDataChannel("control", { ordered: true }));
      setupFileChannel(pc.createDataChannel("file", { ordered: true }));
    } else {
      pc.ondatachannel = (event) => {
        if (event.channel.label === "control") {
          setupControlChannel(event.channel);
        } else if (event.channel.label === "file") {
          setupFileChannel(event.channel);
        }
      };
    }

    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        return;
      }
      safeSendWs(state.rtc.signalRole, {
        type: "ICE_CANDIDATE",
        session_id: state.rtc.sessionId,
        payload: encodePayload({ candidate: event.candidate })
      });
    };

    pc.ontrack = (event) => {
      for (const track of event.streams[0].getTracks()) {
        state.remoteStream.addTrack(track);
      }
      els.remoteVideo.srcObject = state.remoteStream;
    };

    pc.onconnectionstatechange = () => {
      setStatusText(els.statusPc, pc.connectionState);

      if (pc.connectionState === "connected") {
        setStatusText(els.statusSession, "connected");
        state.rtc.reconnectAttempts = 0;
        clearConnectTimeout();
        if (els.sessionDeviceLabel) {
          els.sessionDeviceLabel.textContent =
            state.viewer.targetDeviceId ||
            state.agent.pendingRequester.publicId ||
            state.agent.pendingRequester.email ||
            "DEVICE";
        }
        setScreen("session");
        startSessionTimer();
      }

      if (pc.connectionState === "failed" || pc.connectionState === "disconnected") {
        setStatusText(els.statusSession, "reconnecting");
        clearConnectTimeout();
        scheduleIceRestart();
      }

      if (pc.connectionState === "closed") {
        setStatusText(els.statusSession, "ended");
        clearConnectTimeout();
        stopSessionTimer();
        setScreen("main");
      }
    };

    pc.oniceconnectionstatechange = () => {
      log("info", "Состояние ICE изменилось", { state: pc.iceConnectionState });
    };

    state.rtc.statsTimer = window.setInterval(() => {
      updateConnectionStats().catch((err) => {
        log("warn", "Не удалось обновить статистику", { err: err.message });
      });
    }, 3000);

    refreshStatus();
    return pc;
  }

  async function acceptPendingSession() {
    const sessionId = state.agent.pendingSessionId || els.agentPendingSession.value.trim();
    if (!sessionId) {
      throw new Error("Нет ожидающего ID сессии");
    }

    await ensureAgentLocalStream();
    await ensurePeerConnection("agent", false, sessionId);

    safeSendWs("agent", {
      type: "SESSION_ACCEPT",
      session_id: sessionId,
      payload: encodePayload({ accepted_at: nowISO() })
    });

    state.rtc.sessionId = sessionId;
    setRole("agent");
    if (els.sessionDeviceLabel) {
      els.sessionDeviceLabel.textContent =
        state.agent.pendingRequester.publicId ||
        state.agent.pendingRequester.email ||
        state.agent.publicId ||
        sessionId;
    }
    setStatusText(els.statusSession, "accepted");
    log("info", "Сессия принята", { session_id: sessionId });
  }

  async function ensureViewerOffer(reason, iceRestart) {
    if (!state.viewer.sessionId) {
      throw new Error("Сессия наблюдателя не инициализирована");
    }

    const pc = await ensurePeerConnection("viewer", true, state.viewer.sessionId);
    const offer = await pc.createOffer({
      offerToReceiveVideo: true,
      offerToReceiveAudio: false,
      iceRestart: Boolean(iceRestart)
    });

    await pc.setLocalDescription(offer);
    safeSendWs("viewer", {
      type: "SDP_OFFER",
      session_id: state.viewer.sessionId,
      payload: encodePayload({
        type: offer.type,
        sdp: offer.sdp,
        reason
      })
    });

    setStatusText(els.statusSession, iceRestart ? "reconnecting" : "connecting");
    armConnectTimeout(iceRestart ? "viewer-ice-restart-offer" : "viewer-offer");
    log("info", "Отправлен SDP Offer", { reason, ice_restart: Boolean(iceRestart) });
  }

  async function onRemoteOffer(sessionId, payload) {
    if (!payload?.sdp || !payload?.type) {
      throw new Error("Некорректные данные SDP Offer");
    }

    if (!state.localStream) {
      await ensureAgentLocalStream();
    }

    const pc = await ensurePeerConnection("agent", false, sessionId);
    await pc.setRemoteDescription(new RTCSessionDescription({ type: payload.type, sdp: payload.sdp }));

    await drainPendingCandidates();

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    safeSendWs("agent", {
      type: "SDP_ANSWER",
      session_id: sessionId,
      payload: encodePayload({ type: answer.type, sdp: answer.sdp })
    });

    setStatusText(els.statusSession, "connecting");
    armConnectTimeout("agent-answer");
    log("info", "Отправлен SDP Answer", { session_id: sessionId });
  }

  async function onRemoteAnswer(payload) {
    if (!payload?.sdp || !payload?.type || !state.rtc.pc) {
      return;
    }
    await state.rtc.pc.setRemoteDescription(new RTCSessionDescription({ type: payload.type, sdp: payload.sdp }));
    await drainPendingCandidates();
    log("info", "Применён удалённый SDP Answer");
  }

  async function onRemoteCandidate(sessionId, payload) {
    const candidate = payload?.candidate || payload;
    if (!candidate) {
      return;
    }

    const pc = state.rtc.pc;
    if (!pc || state.rtc.sessionId !== sessionId || !pc.remoteDescription) {
      state.rtc.pendingCandidates.push({ sessionId, candidate });
      return;
    }

    try {
      await pc.addIceCandidate(candidate);
    } catch (err) {
      log("warn", "Не удалось добавить ICE-кандидат", { err: err.message });
    }
  }

  async function drainPendingCandidates() {
    if (!state.rtc.pc || !state.rtc.pc.remoteDescription) {
      return;
    }

    const pending = [...state.rtc.pendingCandidates];
    state.rtc.pendingCandidates = [];
    for (const item of pending) {
      if (item.sessionId !== state.rtc.sessionId) {
        continue;
      }
      try {
        await state.rtc.pc.addIceCandidate(item.candidate);
      } catch (err) {
        log("warn", "Отложенный ICE-кандидат отклонён", { err: err.message });
      }
    }
  }

  function clearConnectTimeout() {
    if (state.rtc.connectTimeoutTimer) {
      clearTimeout(state.rtc.connectTimeoutTimer);
      state.rtc.connectTimeoutTimer = null;
    }
  }

  function armConnectTimeout(context) {
    clearConnectTimeout();
    state.rtc.connectTimeoutTimer = window.setTimeout(() => {
      state.rtc.connectTimeoutTimer = null;
      if (!state.rtc.pc) {
        return;
      }
      if (state.rtc.pc.connectionState === "connected") {
        return;
      }
      log("warn", "Таймаут peer-соединения (10 с)", {
        state: state.rtc.pc.connectionState,
        context
      });
      setStatusText(els.statusSession, "reconnecting");
      scheduleIceRestart();
    }, 10000);
  }

  function scheduleIceRestart() {
    if (!state.rtc.pc || !state.rtc.sessionId) {
      return;
    }

    if (state.rtc.reconnectAttempts >= 5) {
      log("error", "Превышено число попыток переподключения");
      setStatusText(els.statusSession, "failed");
      return;
    }

    if (state.rtc.reconnectTimer) {
      return;
    }

    state.rtc.reconnectAttempts += 1;
    const waitMs = Math.min(1000 * state.rtc.reconnectAttempts, 5000);

    state.rtc.reconnectTimer = window.setTimeout(async () => {
      state.rtc.reconnectTimer = null;
      try {
        safeSendWs(state.rtc.signalRole, {
          type: "ICE_RESTART",
          session_id: state.rtc.sessionId,
          payload: encodePayload({ by: state.rtc.signalRole, attempt: state.rtc.reconnectAttempts })
        });

        if (state.rtc.offerer) {
          await ensureViewerOffer("ice-restart", true);
        }
      } catch (err) {
        log("error", "Перезапуск ICE завершился ошибкой", { err: err.message });
      }
    }, waitMs);
  }

  async function onRemoteIceRestart(sessionId) {
    if (!state.rtc.pc || state.rtc.sessionId !== sessionId) {
      return;
    }

    log("info", "Запрошен удалённый перезапуск ICE", { session_id: sessionId });
    if (state.rtc.offerer) {
      await ensureViewerOffer("remote-ice-restart", true);
    }
  }

  function mapMouseButton(buttonCode) {
    switch (Number(buttonCode)) {
      case 2:
        return "right";
      case 1:
        return "middle";
      case 0:
      default:
        return "left";
    }
  }

  function normalizeRemotePointer(event) {
    const rect = els.remoteVideo.getBoundingClientRect();
    if (!rect.width || !rect.height) {
      return null;
    }

    const xNorm = clampNumber((event.clientX - rect.left) / rect.width, 0, 1);
    const yNorm = clampNumber((event.clientY - rect.top) / rect.height, 0, 1);
    return { xNorm, yNorm };
  }

  function normalizeRemoteKey(key) {
    if (!key) {
      return "";
    }

    const lowered = String(key).toLowerCase();
    const shiftedSymbolMap = {
      "!": "1",
      "@": "2",
      "#": "3",
      "$": "4",
      "%": "5",
      "^": "6",
      "&": "7",
      "*": "8",
      "(": "9",
      ")": "0",
      "_": "-",
      "+": "=",
      "{": "[",
      "}": "]",
      "|": "\\",
      ":": ";",
      "\"": "'",
      "<": ",",
      ">": ".",
      "?": "/",
      "~": "`"
    };

    if (shiftedSymbolMap[key]) {
      return shiftedSymbolMap[key];
    }

    if (lowered === " ") {
      return "space";
    }
    if (lowered === "control") {
      return "ctrl";
    }
    if (lowered === "altgraph") {
      return "alt";
    }
    if (lowered === "os") {
      return "meta";
    }
    if (lowered === "arrowleft" || lowered === "arrowright" || lowered === "arrowup" || lowered === "arrowdown") {
      return lowered;
    }
    if (lowered.length === 1) {
      return lowered;
    }
    return lowered.replace(/\s+/g, "");
  }

  function canSendRemoteInput() {
    if (state.role !== "viewer") {
      return false;
    }
    if (!els.remoteInputToggle?.checked) {
      return false;
    }
    if (!state.channels.control || state.channels.control.readyState !== "open") {
      return false;
    }
    return true;
  }

  function sendRemoteInput(eventPayload) {
    if (!canSendRemoteInput()) {
      return false;
    }
    return sendControl({ type: "input", event: eventPayload });
  }

  async function applyIncomingInputEvent(inputEvent) {
    if (state.role !== "agent") {
      return;
    }
    if (!els.agentEnableInput?.checked) {
      return;
    }
    if (!hasDesktopCapability("injectInput")) {
      return;
    }

    const result = await desktop.injectInput(inputEvent);
    if (!result?.ok) {
      const now = performance.now();
      if (now - state.remoteInput.lastInjectErrorAt > 1500) {
        state.remoteInput.lastInjectErrorAt = now;
        log("warn", "Удалённый ввод отклонён", {
          action: inputEvent?.action || "",
          error: result?.error || "неизвестно"
        });
      }
    }
  }

  function attachRemoteInputHandlers() {
    if (!els.remoteVideo) {
      return;
    }

    els.remoteVideo.addEventListener("click", () => {
      els.remoteVideo.focus();
    });

    els.remoteVideo.addEventListener("mousemove", (event) => {
      if (!canSendRemoteInput()) {
        return;
      }

      const now = performance.now();
      if (now - state.remoteInput.lastMoveSentAt < 16) {
        return;
      }
      state.remoteInput.lastMoveSentAt = now;

      const point = normalizeRemotePointer(event);
      if (!point) {
        return;
      }
      sendRemoteInput({
        action: "mouse_move",
        xNorm: point.xNorm,
        yNorm: point.yNorm
      });
    });

    els.remoteVideo.addEventListener("mousedown", (event) => {
      if (!canSendRemoteInput()) {
        return;
      }
      event.preventDefault();
      const point = normalizeRemotePointer(event);
      if (point) {
        sendRemoteInput({ action: "mouse_move", xNorm: point.xNorm, yNorm: point.yNorm });
      }
      sendRemoteInput({
        action: "mouse_down",
        button: mapMouseButton(event.button)
      });
    });

    els.remoteVideo.addEventListener("mouseup", (event) => {
      if (!canSendRemoteInput()) {
        return;
      }
      event.preventDefault();
      const point = normalizeRemotePointer(event);
      if (point) {
        sendRemoteInput({ action: "mouse_move", xNorm: point.xNorm, yNorm: point.yNorm });
      }
      sendRemoteInput({
        action: "mouse_up",
        button: mapMouseButton(event.button)
      });
    });

    els.remoteVideo.addEventListener(
      "wheel",
      (event) => {
        if (!canSendRemoteInput()) {
          return;
        }
        event.preventDefault();
        sendRemoteInput({
          action: "mouse_scroll",
          dx: Math.round(event.deltaX),
          dy: Math.round(event.deltaY)
        });
      },
      { passive: false }
    );

    els.remoteVideo.addEventListener("keydown", (event) => {
      if (!canSendRemoteInput()) {
        return;
      }
      const key = normalizeRemoteKey(event.key);
      if (!key) {
        return;
      }
      event.preventDefault();
      sendRemoteInput({
        action: "key_down",
        key
      });
    });

    els.remoteVideo.addEventListener("keyup", (event) => {
      if (!canSendRemoteInput()) {
        return;
      }
      const key = normalizeRemoteKey(event.key);
      if (!key) {
        return;
      }
      event.preventDefault();
      sendRemoteInput({
        action: "key_up",
        key
      });
    });
  }

  function sendControl(msg) {
    const channel = state.channels.control;
    if (!channel || channel.readyState !== "open") {
      return false;
    }
    channel.send(JSON.stringify(msg));
    return true;
  }

  function startPingLoop() {
    stopPingLoop();
    state.channels.pingTimer = window.setInterval(() => {
      if (!state.channels.control || state.channels.control.readyState !== "open") {
        return;
      }
      const id = crypto.randomUUID();
      state.channels.pings.set(id, performance.now());
      sendControl({ type: "ping", id, ts: nowISO() });

      for (const [pid, started] of state.channels.pings.entries()) {
        if (performance.now() - started > 15000) {
          state.channels.pings.delete(pid);
        }
      }
    }, 3000);
  }

  function stopPingLoop() {
    if (state.channels.pingTimer) {
      clearInterval(state.channels.pingTimer);
      state.channels.pingTimer = null;
    }
    state.channels.pings.clear();
  }

  function formatTransferRate(bytesPerSecond) {
    return `${(bytesPerSecond / (1024 * 1024)).toFixed(2)} MB/s`;
  }

  function updateOutgoingProgressLabel(extraLabel = "") {
    const outgoing = state.fileTransfer.outgoing;
    if (!outgoing) {
      els.fileOutProgress.value = 0;
      els.fileOutLabel.textContent = "ожидание";
      return;
    }

    const sent = Math.max(0, Math.min(outgoing.size, outgoing.ackedOffset));
    const percent = outgoing.size > 0 ? Math.min(100, Math.round((sent / outgoing.size) * 100)) : 0;
    const elapsedSec = Math.max(1, (performance.now() - outgoing.startedAt) / 1000);
    const speed = sent / elapsedSec;
    const remain = Math.max(0, outgoing.size - sent);
    const eta = Math.max(0, Math.round(remain / Math.max(1, speed)));

    els.fileOutProgress.value = percent;
    let text = `${outgoing.name} (${percent}%)`;
    if (sent < outgoing.size) {
      text += ` • ${formatTransferRate(speed)} • ETA ${eta}s`;
    }
    if (extraLabel) {
      text += ` • ${extraLabel}`;
    }
    els.fileOutLabel.textContent = text;
  }

  function updateIncomingProgressLabel(extraLabel = "") {
    const incoming = state.fileTransfer.incoming;
    if (!incoming) {
      els.fileInProgress.value = 0;
      els.fileInLabel.textContent = "ожидание";
      return;
    }

    const received = Math.max(0, Math.min(incoming.size, incoming.received));
    const percent = incoming.size > 0 ? Math.min(100, Math.round((received / incoming.size) * 100)) : 0;
    const elapsedSec = Math.max(1, (performance.now() - incoming.startedAt) / 1000);
    const speed = received / elapsedSec;
    const remain = Math.max(0, incoming.size - received);
    const eta = Math.max(0, Math.round(remain / Math.max(1, speed)));

    els.fileInProgress.value = percent;
    let text = `${incoming.name} (${percent}%)`;
    if (received < incoming.size) {
      text += ` • ${formatTransferRate(speed)} • ETA ${eta}s`;
    }
    if (extraLabel) {
      text += ` • ${extraLabel}`;
    }
    els.fileInLabel.textContent = text;
  }

  async function sha256Hex(data) {
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function hashFileForTransfer(file) {
    const filePath = typeof file.path === "string" ? file.path : "";
    if (filePath && hasDesktopCapability("fileHash")) {
      const result = await desktop.fileHash(filePath);
      if (!result?.ok) {
        throw new Error(result?.error || "Не удалось вычислить хеш файла");
      }
      return {
        sha256: String(result.sha256 || ""),
        filePath,
        size: Number(result.size || file.size)
      };
    }

    if (file.size > 512 * 1024 * 1024) {
      throw new Error("Для хеширования больших файлов требуется десктоп-режим с файловым мостом");
    }

    const buffer = await file.arrayBuffer();
    return {
      sha256: await sha256Hex(buffer),
      filePath,
      size: file.size
    };
  }

  function getOpenFileChannel() {
    const channel = state.channels.file;
    if (!channel || channel.readyState !== "open") {
      return null;
    }
    return channel;
  }

  async function waitForBackpressure(channel) {
    while (channel.bufferedAmount > 2 * 1024 * 1024) {
      await new Promise((resolve) => {
        const handler = () => {
          channel.removeEventListener("bufferedamountlow", handler);
          resolve();
        };
        channel.addEventListener("bufferedamountlow", handler, { once: true });
      });
    }
  }

  function resolveOutgoingAckWaiter(outgoing) {
    if (outgoing?.ackWaiterResolve) {
      const resolve = outgoing.ackWaiterResolve;
      outgoing.ackWaiterResolve = null;
      resolve();
    }
  }

  async function waitForAckWindow(outgoing) {
    while (outgoing.nextOffset - outgoing.ackedOffset > FILE_ACK_WINDOW_BYTES) {
      await new Promise((resolve) => {
        outgoing.ackWaiterResolve = resolve;
        window.setTimeout(resolve, 200);
      });
      if (state.fileTransfer.outgoing !== outgoing || !outgoing.remoteAccepted) {
        return;
      }
    }
  }

  function buildFileOfferMessage(outgoing, reason) {
    return {
      type: "file-offer",
      id: outgoing.id,
      name: outgoing.name,
      size: outgoing.size,
      sha256: outgoing.sha256,
      chunk_size: outgoing.chunkSize,
      reason
    };
  }

  function announceOutgoingTransfer(reason) {
    const outgoing = state.fileTransfer.outgoing;
    if (!outgoing || outgoing.completed) {
      return false;
    }
    outgoing.remoteAccepted = false;
    const sent = sendControl(buildFileOfferMessage(outgoing, reason));
    if (sent) {
      updateOutgoingProgressLabel(reason.includes("resume") ? "запрошено возобновление" : "ожидание подтверждения");
    }
    return sent;
  }

  async function processOutgoingTransferLoop(outgoing) {
    if (!outgoing || outgoing.sending || outgoing.completed || !outgoing.remoteAccepted) {
      return;
    }

    outgoing.sending = true;
    try {
      while (state.fileTransfer.outgoing === outgoing && outgoing.remoteAccepted && outgoing.nextOffset < outgoing.size) {
        const fileChannel = getOpenFileChannel();
        if (!fileChannel) {
          updateOutgoingProgressLabel("пауза (ожидание файлового канала)");
          return;
        }

        await waitForAckWindow(outgoing);
        if (state.fileTransfer.outgoing !== outgoing || !outgoing.remoteAccepted) {
          return;
        }

        const endOffset = Math.min(outgoing.nextOffset + outgoing.chunkSize, outgoing.size);
        const chunkBuffer = await outgoing.file.slice(outgoing.nextOffset, endOffset).arrayBuffer();
        if (!chunkBuffer.byteLength) {
          break;
        }

        await waitForBackpressure(fileChannel);
        if (state.fileTransfer.outgoing !== outgoing || !outgoing.remoteAccepted) {
          return;
        }

        fileChannel.send(chunkBuffer);
        outgoing.nextOffset += chunkBuffer.byteLength;
        updateOutgoingProgressLabel(outgoing.nextOffset < outgoing.size ? "отправка" : "завершение");
      }

      if (state.fileTransfer.outgoing === outgoing && outgoing.remoteAccepted && outgoing.nextOffset >= outgoing.size && !outgoing.completeSent) {
        outgoing.completeSent = true;
        sendControl({
          type: "file-complete",
          id: outgoing.id,
          size: outgoing.size,
          sha256: outgoing.sha256
        });
        updateOutgoingProgressLabel("ожидание подтверждения целостности");
      }
    } catch (err) {
      log("error", "Исходящая передача завершилась ошибкой", { id: outgoing.id, err: err.message });
      updateOutgoingProgressLabel("пауза (ошибка)");
    } finally {
      outgoing.sending = false;
      resolveOutgoingAckWaiter(outgoing);
    }
  }

  async function maybeResumeTransfersOnChannelOpen() {
    const outgoing = state.fileTransfer.outgoing;
    if (outgoing && !outgoing.completed) {
      announceOutgoingTransfer("resume-after-reconnect");
    }

    const incoming = state.fileTransfer.incoming;
    if (incoming && !incoming.completed) {
      sendControl({
        type: "file-resume-request",
        id: incoming.id,
        resume_offset: incoming.received
      });
      updateIncomingProgressLabel("запрошено возобновление");
    }
  }

  function renderIncomingDownloadItem({ filePath, name, integrity, sha256Remote, sha256Local }) {
    const item = document.createElement("div");
    item.className = "download-item";

    const nameNode = document.createElement("span");
    nameNode.textContent = `${name} (${localizeIntegrity(integrity)})`;

    const openBtn = document.createElement("button");
    openBtn.textContent = "Открыть";
    openBtn.className = "ghost";
    openBtn.addEventListener("click", async () => {
      if (!hasDesktopCapability("openPath")) {
        return;
      }
      const result = await desktop.openPath(filePath);
      if (!result?.ok) {
        log("warn", "Не удалось открыть файл", { file: filePath, error: result?.error || "неизвестно" });
      }
    });

    item.appendChild(nameNode);
    item.appendChild(openBtn);
    els.incomingDownloads.prepend(item);

    if (integrity !== "ok") {
      log("warn", "Несовпадение целостности входящего файла", {
        file: filePath,
        expected: sha256Remote,
        actual: sha256Local
      });
    }
  }

  async function finalizeIncomingTransfer(incoming) {
    if (!incoming || incoming.finalizing || incoming.completed) {
      return;
    }
    if (!hasDesktopCapability("fileFinalize")) {
      throw new Error("Мост финализации файла недоступен");
    }
    incoming.finalizing = true;

    try {
      const result = await desktop.fileFinalize({ transferId: incoming.id });
      if (!result?.ok) {
        throw new Error(result?.error || "Финализация файла завершилась ошибкой");
      }

      const localHash = String(result.sha256 || "");
      const integrity = incoming.sha256 ? (localHash === incoming.sha256 ? "ok" : "mismatch") : "unknown";

      renderIncomingDownloadItem({
        filePath: result.filePath,
        name: incoming.name,
        integrity,
        sha256Remote: incoming.sha256,
        sha256Local: localHash
      });

      sendControl({
        type: "file-complete-ack",
        id: incoming.id,
        integrity,
        sha256_local: localHash
      });

      updateIncomingProgressLabel(`готово (${localizeIntegrity(integrity)})`);
      incoming.completed = true;
      state.fileTransfer.incoming = null;

      log("info", "Файл получен", {
        name: incoming.name,
        size: incoming.size,
        sha256_remote: incoming.sha256,
        sha256_local: localHash,
        integrity
      });
    } catch (err) {
      updateIncomingProgressLabel(`ошибка (${err.message})`);
      sendControl({
        type: "file-error",
        id: incoming.id,
        error: err.message
      });
      throw err;
    } finally {
      incoming.finalizing = false;
    }
  }

  async function onFileOffer(msg) {
    const id = String(msg.id || "");
    const name = String(msg.name || "входящий.bin");
    const size = Number(msg.size || 0);
    const sha256 = String(msg.sha256 || "");
    const chunkSize = Math.max(64 * 1024, Math.min(FILE_CHUNK_SIZE, Number(msg.chunk_size || FILE_CHUNK_SIZE)));

    if (!id || !Number.isFinite(size) || size < 0) {
      return;
    }

    let incoming = state.fileTransfer.incoming;

    if (incoming && incoming.id !== id && !incoming.completed) {
      sendControl({ type: "file-error", id, error: "уже активна другая передача" });
      return;
    }

    if (!incoming) {
      if (!hasDesktopCapability("fileSelectDestination")) {
        sendControl({ type: "file-error", id, error: "файловый мост недоступен" });
        return;
      }

      const destination = await desktop.fileSelectDestination({
        transferId: id,
        suggestedName: name,
        expectedSize: size
      });

      if (!destination?.ok) {
        sendControl({ type: "file-error", id, error: destination?.error || "не удалось выбрать место сохранения" });
        return;
      }
      if (destination.canceled) {
        sendControl({ type: "file-cancel", id, reason: "пользователь отменил диалог сохранения" });
        return;
      }

      incoming = {
        id,
        name,
        size,
        sha256,
        chunkSize,
        filePath: destination.filePath,
        received: Number(destination.resumeOffset || 0),
        startedAt: performance.now(),
        completed: false,
        finalizing: false,
        completeRequested: false,
        writeQueue: Promise.resolve()
      };
      state.fileTransfer.incoming = incoming;
      log("info", "Входящее предложение передачи принято", {
        id,
        name,
        size,
        resume_offset: incoming.received
      });
    }

    sendControl({
      type: "file-accept",
      id: incoming.id,
      resume_offset: incoming.received
    });
    updateIncomingProgressLabel(incoming.received > 0 ? "возобновление" : "получение");
  }

  async function onFileAccept(msg) {
    const outgoing = state.fileTransfer.outgoing;
    if (!outgoing || String(msg.id || "") !== outgoing.id) {
      return;
    }

    const resumeRaw = Number(msg.resume_offset || 0);
    const resumeOffset = Number.isFinite(resumeRaw) ? clampNumber(resumeRaw, 0, outgoing.size) : 0;

    outgoing.remoteAccepted = true;
    outgoing.completeSent = false;
    outgoing.ackedOffset = resumeOffset;
    outgoing.nextOffset = resumeOffset;
    resolveOutgoingAckWaiter(outgoing);

    log("info", "Исходящая передача подтверждена", {
      id: outgoing.id,
      resume_offset: resumeOffset
    });
    updateOutgoingProgressLabel(resumeOffset > 0 ? "возобновление" : "отправка");
    await processOutgoingTransferLoop(outgoing);
  }

  function onFileAck(msg) {
    const outgoing = state.fileTransfer.outgoing;
    if (!outgoing || String(msg.id || "") !== outgoing.id) {
      return;
    }
    const receivedRaw = Number(msg.received || 0);
    if (!Number.isFinite(receivedRaw)) {
      return;
    }

    const received = clampNumber(receivedRaw, 0, outgoing.size);
    if (received > outgoing.ackedOffset) {
      outgoing.ackedOffset = received;
      updateOutgoingProgressLabel(outgoing.completeSent ? "ожидание подтверждения целостности" : "отправка");
    }
    resolveOutgoingAckWaiter(outgoing);
  }

  function onFileErrorMessage(msg) {
    const id = String(msg.id || "");
    const error = String(msg.error || msg.reason || "ошибка передачи");

    const outgoing = state.fileTransfer.outgoing;
    if (outgoing && outgoing.id === id) {
      outgoing.remoteAccepted = false;
      outgoing.sending = false;
      resolveOutgoingAckWaiter(outgoing);
      updateOutgoingProgressLabel(`пауза (${error})`);
      log("warn", "Исходящая передача поставлена на паузу", { id, error });
    }

    const incoming = state.fileTransfer.incoming;
    if (incoming && incoming.id === id) {
      incoming.completed = true;
      if (hasDesktopCapability("fileAbort")) {
        desktop.fileAbort({ transferId: incoming.id }).catch(() => {});
      }
      state.fileTransfer.incoming = null;
      updateIncomingProgressLabel(`ошибка (${error})`);
      log("warn", "Входящая передача прервана", { id, error });
    }
  }

  async function onFileResumeRequest(msg) {
    const outgoing = state.fileTransfer.outgoing;
    if (!outgoing || outgoing.completed) {
      return;
    }
    if (String(msg.id || "") !== outgoing.id) {
      return;
    }
    announceOutgoingTransfer("receiver-resume-request");
  }

  async function onFileComplete(msg) {
    const incoming = state.fileTransfer.incoming;
    if (!incoming || String(msg.id || "") !== incoming.id) {
      return;
    }
    incoming.completeRequested = true;
    if (incoming.received >= incoming.size) {
      await finalizeIncomingTransfer(incoming);
    } else {
      updateIncomingProgressLabel("ожидание оставшихся чанков");
    }
  }

  function onFileCompleteAck(msg) {
    const outgoing = state.fileTransfer.outgoing;
    if (!outgoing || String(msg.id || "") !== outgoing.id) {
      return;
    }
    outgoing.completed = true;
    outgoing.remoteAccepted = false;
    outgoing.sending = false;
    outgoing.ackedOffset = outgoing.size;
    resolveOutgoingAckWaiter(outgoing);

    const integrity = String(msg.integrity || "unknown");
    updateOutgoingProgressLabel(`готово (${localizeIntegrity(integrity)})`);
    log("info", "Исходящая передача завершена", {
      id: outgoing.id,
      integrity,
      sha256_remote: outgoing.sha256,
      sha256_local: msg.sha256_local || ""
    });

    state.fileTransfer.outgoing = null;
  }

  async function handleFileControlMessage(msg) {
    switch (msg.type) {
      case "file-offer":
        await onFileOffer(msg);
        break;
      case "file-accept":
        await onFileAccept(msg);
        break;
      case "file-ack":
        onFileAck(msg);
        break;
      case "file-resume-request":
        await onFileResumeRequest(msg);
        break;
      case "file-complete":
        await onFileComplete(msg);
        break;
      case "file-complete-ack":
        onFileCompleteAck(msg);
        break;
      case "file-error":
      case "file-cancel":
        onFileErrorMessage(msg);
        break;
      default:
        break;
    }
  }

  async function handleIncomingFileChunk(data) {
    const incoming = state.fileTransfer.incoming;
    if (!incoming || incoming.completed) {
      return;
    }
    if (!hasDesktopCapability("fileWriteChunk")) {
      throw new Error("Мост записи файла недоступен");
    }

    let chunkBytes;
    if (data instanceof ArrayBuffer) {
      chunkBytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      chunkBytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else if (data instanceof Blob) {
      chunkBytes = new Uint8Array(await data.arrayBuffer());
    } else {
      throw new Error("неподдерживаемый тип входящего чанка");
    }

    const result = await desktop.fileWriteChunk({
      transferId: incoming.id,
      offset: incoming.received,
      chunk: chunkBytes
    });

    if (!result?.ok) {
      if (Number.isFinite(result?.expectedOffset)) {
        incoming.received = Number(result.expectedOffset);
        sendControl({
          type: "file-ack",
          id: incoming.id,
          received: incoming.received
        });
      }
      throw new Error(result?.error || "не удалось записать чанк");
    }

    incoming.received = Number(result.bytesWritten || incoming.received);
    updateIncomingProgressLabel("получение");

    sendControl({
      type: "file-ack",
      id: incoming.id,
      received: incoming.received
    });

    if (incoming.completeRequested && incoming.received >= incoming.size) {
      await finalizeIncomingTransfer(incoming);
    }
  }

  async function sendFile() {
    const file = els.fileInput.files?.[0];
    if (!file) {
      throw new Error("Сначала выберите файл");
    }
    if (!state.channels.control || state.channels.control.readyState !== "open") {
      throw new Error("Канал управления не открыт");
    }
    if (state.fileTransfer.outgoing && !state.fileTransfer.outgoing.completed) {
      throw new Error("Уже активна другая исходящая передача");
    }

    const hashInfo = await hashFileForTransfer(file);
    const transferID = crypto.randomUUID();

    state.fileTransfer.outgoing = {
      id: transferID,
      name: file.name,
      size: Number(hashInfo.size || file.size),
      sha256: hashInfo.sha256,
      file,
      filePath: hashInfo.filePath,
      chunkSize: FILE_CHUNK_SIZE,
      startedAt: performance.now(),
      ackedOffset: 0,
      nextOffset: 0,
      remoteAccepted: false,
      completeSent: false,
      completed: false,
      sending: false,
      ackWaiterResolve: null
    };

    updateOutgoingProgressLabel("ожидание подтверждения");
    announceOutgoingTransfer("new-transfer");
    log("info", "Предложение исходящей передачи отправлено", {
      id: transferID,
      name: file.name,
      size: file.size,
      sha256: hashInfo.sha256
    });
  }

  function setupControlChannel(channel) {
    state.channels.control = channel;

    channel.addEventListener("open", () => {
      log("info", "Канал управления открыт");
      startPingLoop();
      maybeResumeTransfersOnChannelOpen().catch((err) => {
        log("warn", "Не удалось отправить сигнал возобновления", { err: err.message });
      });
    });

    channel.addEventListener("close", () => {
      log("warn", "Канал управления закрыт");
      stopPingLoop();
    });

    channel.addEventListener("message", (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch (_err) {
        return;
      }

      if (msg.type === "ping") {
        sendControl({ type: "pong", id: msg.id, ts: msg.ts });
      }

      if (msg.type === "pong" && msg.id && state.channels.pings.has(msg.id)) {
        const started = state.channels.pings.get(msg.id);
        state.channels.pings.delete(msg.id);
        const rtt = Math.max(1, Math.round(performance.now() - started));
        setStatusText(els.statusRtt, `${rtt} ms`);
      }

      if (msg.type === "clipboard" && state.clipboard.enabled) {
        const text = String(msg.text || "");
        state.clipboard.lastText = text;
        els.clipboardText.value = text;
        navigator.clipboard.writeText(text).catch(() => {});
      }

      if (msg.type === "quality-set") {
        const requestedMode = String(msg.mode || "auto").toLowerCase();
        applyOutboundQuality(requestedMode)
          .then(() => {
            sendControl({ type: "quality-applied", mode: requestedMode });
          })
          .catch((err) => {
            log("warn", "Не удалось применить качество", { mode: requestedMode, err: err.message });
          });
      }

      if (msg.type === "quality-applied") {
        const appliedMode = String(msg.mode || "auto").toLowerCase();
        setQualityUi(appliedMode);
      }

      if (msg.type === "input" && msg.event) {
        applyIncomingInputEvent(msg.event).catch((err) => {
          log("warn", "Не удалось применить удалённый ввод", { err: err.message });
        });
      }

      if (String(msg.type || "").startsWith("file-")) {
        handleFileControlMessage(msg).catch((err) => {
          log("error", "Ошибка обработки сообщения управления файлами", { type: msg.type, err: err.message });
        });
      }
    });
  }

  function setupFileChannel(channel) {
    state.channels.file = channel;
    channel.binaryType = "arraybuffer";
    channel.bufferedAmountLowThreshold = 256 * 1024;

    channel.addEventListener("open", () => {
      log("info", "Файловый канал открыт");
      const outgoing = state.fileTransfer.outgoing;
      if (outgoing && outgoing.remoteAccepted && !outgoing.completed) {
        processOutgoingTransferLoop(outgoing).catch((err) => {
          log("error", "Не удалось возобновить исходящую передачу", { err: err.message });
        });
      }
    });

    channel.addEventListener("close", () => {
      log("warn", "Файловый канал закрыт");
      const outgoing = state.fileTransfer.outgoing;
      if (outgoing && !outgoing.completed) {
        outgoing.sending = false;
        resolveOutgoingAckWaiter(outgoing);
        updateOutgoingProgressLabel("пауза (канал закрыт)");
      }
      const incoming = state.fileTransfer.incoming;
      if (incoming && !incoming.completed) {
        updateIncomingProgressLabel("пауза (канал закрыт)");
      }
    });

    channel.addEventListener("message", (event) => {
      const incoming = state.fileTransfer.incoming;
      if (!incoming || incoming.completed) {
        return;
      }

      incoming.writeQueue = incoming.writeQueue
        .then(() => handleIncomingFileChunk(event.data))
        .catch((err) => {
          log("error", "Ошибка входящего чанка", { err: err.message });
          sendControl({
            type: "file-error",
            id: incoming.id,
            error: err.message
          });
        });
    });
  }

  async function pushClipboard() {
    const text = els.clipboardText.value || "";
    if (!sendControl({ type: "clipboard", text })) {
      throw new Error("Канал управления не открыт");
    }
    state.clipboard.lastText = text;
    log("info", "Текст буфера обмена отправлен", { length: text.length });
  }

  async function pullClipboard() {
    const text = await navigator.clipboard.readText();
    state.clipboard.lastText = text;
    els.clipboardText.value = text;
    return text;
  }

  function setClipboardSyncEnabled(enabled) {
    state.clipboard.enabled = enabled;

    if (state.clipboard.pollTimer) {
      clearInterval(state.clipboard.pollTimer);
      state.clipboard.pollTimer = null;
    }

    if (!enabled) {
      return;
    }

    state.clipboard.pollTimer = window.setInterval(async () => {
      if (!state.channels.control || state.channels.control.readyState !== "open") {
        return;
      }
      try {
        const text = await navigator.clipboard.readText();
        if (text !== state.clipboard.lastText) {
          state.clipboard.lastText = text;
          sendControl({ type: "clipboard", text });
        }
      } catch (_err) {
        // permission can be denied depending on OS state
      }
    }, 2000);
  }

  async function sendRemoteText() {
    const text = String(els.remoteTextInput.value || "");
    if (!text.trim()) {
      throw new Error("Поле текста пустое");
    }

    const ok = sendRemoteInput({
      action: "text_input",
      text: text.slice(0, 2000)
    });
    if (!ok) {
      throw new Error("Удалённый ввод не активен");
    }

    els.remoteTextInput.value = "";
    log("info", "Удалённый текст отправлен", { length: text.length });
  }

  async function updateConnectionStats() {
    const pc = state.rtc.pc;
    if (!pc || pc.connectionState === "closed") {
      return;
    }

    const stats = await pc.getStats();
    let selectedPair = null;
    let localCandidate = null;
    let fps = null;

    stats.forEach((report) => {
      if (report.type === "transport" && report.selectedCandidatePairId) {
        selectedPair = stats.get(report.selectedCandidatePairId) || selectedPair;
      }
    });

    if (!selectedPair) {
      stats.forEach((report) => {
        if (report.type === "candidate-pair" && report.nominated && report.state === "succeeded") {
          selectedPair = report;
        }
      });
    }

    stats.forEach((report) => {
      if (fps !== null) {
        return;
      }
      if ((report.type === "inbound-rtp" || report.type === "outbound-rtp") && report.kind === "video") {
        if (typeof report.framesPerSecond === "number" && report.framesPerSecond > 0) {
          fps = Math.round(report.framesPerSecond);
        }
      }
    });

    if (selectedPair && selectedPair.localCandidateId) {
      localCandidate = stats.get(selectedPair.localCandidateId) || null;
    }

    let transport = "unknown";
    if (localCandidate?.candidateType === "relay") {
      transport = "relay";
    } else if (localCandidate?.candidateType) {
      transport = "direct";
    }

    state.rtc.lastStats = {
      sampledAt: nowISO(),
      transport,
      localCandidateType: localCandidate?.candidateType || "",
      currentRoundTripTime: selectedPair?.currentRoundTripTime || null,
      bytesSent: selectedPair?.bytesSent || null,
      bytesReceived: selectedPair?.bytesReceived || null
    };

    setStatusText(els.statusTransport, transport);
    if (selectedPair?.currentRoundTripTime) {
      setStatusText(els.statusRtt, `${Math.round(selectedPair.currentRoundTripTime * 1000)} ms`);
    }
    if (els.fpsValue) {
      els.fpsValue.textContent = fps !== null ? String(fps) : "-";
    }
  }

  async function teardownRtc(reason = "manual") {
    const previousSessionID = state.rtc.sessionId || state.agent.pendingSessionId || state.viewer.sessionId;
    clearConnectTimeout();

    if (state.rtc.reconnectTimer) {
      clearTimeout(state.rtc.reconnectTimer);
      state.rtc.reconnectTimer = null;
    }

    if (state.rtc.statsTimer) {
      clearInterval(state.rtc.statsTimer);
      state.rtc.statsTimer = null;
    }

    stopPingLoop();

    if (state.channels.control) {
      try {
        state.channels.control.close();
      } catch (_err) {
        // ignored
      }
    }

    if (state.channels.file) {
      try {
        state.channels.file.close();
      } catch (_err) {
        // ignored
      }
    }

    state.channels.control = null;
    state.channels.file = null;

    if (state.rtc.pc) {
      try {
        state.rtc.pc.close();
      } catch (_err) {
        // ignored
      }
    }

    state.rtc.pc = null;
    state.rtc.sessionId = "";
    state.rtc.offerer = false;
    state.rtc.signalRole = "";
    state.rtc.pendingCandidates = [];
    if (previousSessionID) {
      delete state.ui.promptedSessions[previousSessionID];
    }
    state.agent.pendingSessionId = "";
    state.agent.pendingRequester = { email: "", platform: "", publicId: "" };
    if (els.agentPendingSession) {
      els.agentPendingSession.value = "";
    }

    if (state.remoteStream) {
      state.remoteStream.getTracks().forEach((track) => {
        state.remoteStream.removeTrack(track);
      });
    }
    els.remoteVideo.srcObject = state.remoteStream;

    setStatusText(els.statusPc, "closed");
    setStatusText(els.statusSession, reason === "manual" ? "idle" : reason);
    setStatusText(els.statusTransport, "unknown");
    setStatusText(els.statusRtt, "-");
    stopSessionTimer();
    if (els.fpsValue) {
      els.fpsValue.textContent = "-";
    }
    if (state.auth.accessToken) {
      setScreen("main");
    } else {
      setScreen("login");
    }

    log("info", "RTC-сессия завершена", { reason });
  }

  async function hangupSession() {
    if (state.rtc.sessionId && state.rtc.signalRole) {
      safeSendWs(state.rtc.signalRole, {
        type: "HANGUP",
        session_id: state.rtc.sessionId
      });
    }
    await teardownRtc("manual-hangup");
  }

  function refreshStatus() {
    const wsLabel = wsStateLabel();
    setStatusText(els.statusRole, state.role);
    setStatusText(els.statusWs, wsLabel);

    if (!state.rtc.pc) {
      setStatusText(els.statusPc, "new");
    }

    if (els.serverStateConnected && els.serverStateReconnecting && els.serverStateOffline) {
      els.serverStateConnected.style.opacity = wsLabel === "open" ? "1" : "0.55";
      els.serverStateReconnecting.style.opacity = wsLabel === "connecting" ? "1" : "0.55";
      els.serverStateOffline.style.opacity = wsLabel === "closed" || wsLabel === "disconnected" ? "1" : "0.55";
    }

    if (els.connectInfo && state.ui.currentScreen === "main") {
      if (wsLabel === "open") {
        els.connectInfo.textContent = "Сервер доступен. Можно подключаться.";
      } else if (wsLabel === "connecting") {
        els.connectInfo.textContent = "Переподключение к серверу...";
      } else {
        els.connectInfo.textContent = "Нет соединения с сервером.";
      }
    }
    if (els.viewerRequestSession) {
      els.viewerRequestSession.disabled = wsLabel !== "open";
    }
  }

  function setRole(role) {
    state.role = role;
    els.roleAgentBtn.classList.toggle("active", role === "agent");
    els.roleViewerBtn.classList.toggle("active", role === "viewer");
    els.agentPanel.classList.toggle("active", role === "agent");
    els.viewerPanel.classList.toggle("active", role === "viewer");
    refreshStatus();
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("valden.theme", theme);
  }

  async function exportDiagnostics() {
    const payload = {
      exported_at: nowISO(),
      role: state.role,
      signal_base: state.signalBase,
      agent_device_id: state.agent.deviceId,
      viewer_device_id: state.viewer.deviceId,
      session_id: state.rtc.sessionId || state.viewer.sessionId || state.agent.pendingSessionId,
      rtc: {
        has_peer: Boolean(state.rtc.pc),
        offerer: state.rtc.offerer,
        reconnect_attempts: state.rtc.reconnectAttempts,
        stats: state.rtc.lastStats
      },
      permissions: state.permissions,
      remote_input: {
        agent_enabled: Boolean(els.agentEnableInput?.checked),
        viewer_enabled: Boolean(els.remoteInputToggle?.checked)
      },
      file_transfer: {
        outgoing: state.fileTransfer.outgoing
          ? {
              id: state.fileTransfer.outgoing.id,
              name: state.fileTransfer.outgoing.name,
              size: state.fileTransfer.outgoing.size,
              acked_offset: state.fileTransfer.outgoing.ackedOffset,
              next_offset: state.fileTransfer.outgoing.nextOffset,
              remote_accepted: state.fileTransfer.outgoing.remoteAccepted,
              complete_sent: state.fileTransfer.outgoing.completeSent
            }
          : null,
        incoming: state.fileTransfer.incoming
          ? {
              id: state.fileTransfer.incoming.id,
              name: state.fileTransfer.incoming.name,
              size: state.fileTransfer.incoming.size,
              received: state.fileTransfer.incoming.received,
              complete_requested: state.fileTransfer.incoming.completeRequested
            }
          : null
      },
      ws: {
        agent_state: state.ws.agent?.readyState ?? null,
        viewer_state: state.ws.viewer?.readyState ?? null
      },
      logs: state.logs
    };

    const content = JSON.stringify(payload, null, 2);
    const defaultName = `valden-diagnostics-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    if (!hasDesktopCapability("saveJson")) {
      throw new Error("Мост сохранения недоступен");
    }
    const result = await desktop.saveJson(defaultName, content);

    if (!result.canceled) {
      log("info", "Диагностика экспортирована", { file: result.filePath });
    }
  }

  async function initMeta() {
    if (!hasDesktopCapability("getMeta")) {
      if (els.appMeta) {
        els.appMeta.textContent = "веб-режим";
      }
      if (els.updateAppBtn) {
        els.updateAppBtn.disabled = true;
      }
      return;
    }

    const meta = await desktop.getMeta();
    state.runtime.version = String(meta.version || "0.0.0");
    state.runtime.platform = String(meta.platform || "unknown");
    state.runtime.arch = String(meta.arch || "unknown");

    if (els.appMeta) {
      els.appMeta.textContent = `${state.runtime.platform}/${state.runtime.arch} • v${state.runtime.version}`;
    }

    if (els.updateAppBtn) {
      if (state.runtime.platform === "win32") {
        els.updateAppBtn.textContent = "Обновить приложение";
      } else if (state.runtime.platform === "darwin") {
        els.updateAppBtn.textContent =
          state.runtime.arch === "arm64" ? "Обновить (macOS M-серия)" : "Обновить (macOS Intel)";
      } else {
        els.updateAppBtn.textContent = "Обновление недоступно";
        els.updateAppBtn.disabled = true;
      }
    }
  }

  function attachEvents() {
    els.roleAgentBtn.addEventListener("click", () => setRole("agent"));
    els.roleViewerBtn.addEventListener("click", () => setRole("viewer"));

    els.signalBase.addEventListener("change", () => normalizeSignalBase());

    if (els.loginSubmit) {
      els.loginSubmit.addEventListener("click", async () => {
        setLoginError("");
        els.loginSubmit.disabled = true;
        try {
          await loginWithCredentials();
        } catch (err) {
          setLoginError(err.message || "Ошибка входа");
        } finally {
          els.loginSubmit.disabled = false;
        }
      });
    }

    if (els.loginPassword) {
      els.loginPassword.addEventListener("keydown", async (event) => {
        if (event.key !== "Enter") {
          return;
        }
        event.preventDefault();
        if (!els.loginSubmit) {
          return;
        }
        els.loginSubmit.click();
      });
    }

    if (els.bootstrapConsumeBtn) {
      els.bootstrapConsumeBtn.addEventListener("click", async () => {
        setLoginError("");
        els.bootstrapConsumeBtn.disabled = true;
        try {
          await consumeBootstrapToken();
        } catch (err) {
          setLoginError(err.message || "Не удалось активировать токен");
        } finally {
          els.bootstrapConsumeBtn.disabled = false;
        }
      });
    }

    if (els.bootstrapToken) {
      els.bootstrapToken.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && els.bootstrapConsumeBtn) {
          event.preventDefault();
          els.bootstrapConsumeBtn.click();
        }
      });
    }

    if (els.logoutBtn) {
      els.logoutBtn.addEventListener("click", async () => {
        await logoutApp();
      });
    }

    if (els.updateAppBtn) {
      els.updateAppBtn.addEventListener("click", async () => {
        const originalText = els.updateAppBtn.textContent;
        els.updateAppBtn.disabled = true;
        if (els.connectInfo) {
          els.connectInfo.textContent = "Подготовка обновления...";
        }
        try {
          const result = await runSelfUpdate();
          if (els.connectInfo) {
            els.connectInfo.textContent = getUpdateInstallHint();
          }
          log("info", "Запущено обновление приложения", result);
        } catch (err) {
          if (els.connectInfo) {
            els.connectInfo.textContent = `Не удалось запустить обновление: ${err.message}`;
          }
          log("warn", "Ошибка запуска автообновления", { err: err.message });
          els.updateAppBtn.disabled = false;
          els.updateAppBtn.textContent = originalText;
          return;
        }

        if (state.runtime.platform !== "win32") {
          window.setTimeout(() => {
            if (els.updateAppBtn) {
              els.updateAppBtn.disabled = false;
              els.updateAppBtn.textContent = originalText;
            }
          }, 1500);
        }
      });
    }

    if (els.copyPublicIdBtn) {
      els.copyPublicIdBtn.addEventListener("click", async () => {
        const idValue = String(state.agent.publicId || state.agent.deviceId || "").trim();
        if (!idValue) {
          return;
        }
        try {
          await navigator.clipboard.writeText(idValue);
          if (els.connectInfo) {
            els.connectInfo.textContent = "ID скопирован в буфер обмена.";
          }
        } catch (_err) {
          if (els.connectInfo) {
            els.connectInfo.textContent = "Не удалось скопировать ID.";
          }
        }
      });
    }

    if (els.refreshDeviceBtn) {
      els.refreshDeviceBtn.addEventListener("click", async () => {
        try {
          await registerAgent();
          await connectAgentWS();
          refreshStatus();
        } catch (err) {
          if (els.connectInfo) {
            els.connectInfo.textContent = `Ошибка обновления устройства: ${err.message}`;
          }
        }
      });
    }

    if (els.qualityAutoBtn) {
      els.qualityAutoBtn.addEventListener("click", async () => {
        try {
          await requestQualityChange("auto");
        } catch (err) {
          log("warn", "Не удалось сменить качество", { err: err.message });
        }
      });
    }
    if (els.quality720Btn) {
      els.quality720Btn.addEventListener("click", async () => {
        try {
          await requestQualityChange("720p");
        } catch (err) {
          log("warn", "Не удалось сменить качество", { err: err.message });
        }
      });
    }
    if (els.quality1080Btn) {
      els.quality1080Btn.addEventListener("click", async () => {
        try {
          await requestQualityChange("1080p");
        } catch (err) {
          log("warn", "Не удалось сменить качество", { err: err.message });
        }
      });
    }

    if (els.sessionFullscreenBtn) {
      els.sessionFullscreenBtn.addEventListener("click", async () => {
        const target = els.remoteVideo;
        if (!target) {
          return;
        }
        if (!document.fullscreenElement) {
          await target.requestFullscreen?.().catch(() => {});
        } else {
          await document.exitFullscreen?.().catch(() => {});
        }
      });
    }

    if (els.sessionSettingsBtn) {
      els.sessionSettingsBtn.addEventListener("click", () => {
        if (hasDesktopCapability("openExternal")) {
          desktop.openExternal(normalizeSignalBase());
        }
      });
    }

    if (els.ctrlAltDelBtn) {
      els.ctrlAltDelBtn.addEventListener("click", () => {
        const sequence = [
          { action: "key_down", key: "ctrl" },
          { action: "key_down", key: "alt" },
          { action: "key_down", key: "delete" },
          { action: "key_up", key: "delete" },
          { action: "key_up", key: "alt" },
          { action: "key_up", key: "ctrl" }
        ];
        for (const inputEvent of sequence) {
          sendControl({ type: "input", event: inputEvent });
        }
      });
    }

    if (els.switchMonitorBtn) {
      els.switchMonitorBtn.addEventListener("click", () => {
        log("info", "Переключение монитора пока в разработке");
      });
    }

    if (els.settingsBtn) {
      els.settingsBtn.addEventListener("click", () => {
        if (hasDesktopCapability("openExternal")) {
          desktop.openExternal(normalizeSignalBase());
        }
      });
    }

    els.themeToggle.addEventListener("click", () => {
      const current = document.documentElement.dataset.theme || "dark";
      setTheme(current === "dark" ? "light" : "dark");
    });

    if (els.openBackend) {
      els.openBackend.addEventListener("click", () => {
        if (hasDesktopCapability("openExternal")) {
          desktop.openExternal(normalizeSignalBase());
        }
      });
    }

    els.agentRegister.addEventListener("click", async () => {
      try {
        await registerAgent();
      } catch (err) {
        log("error", "Регистрация завершилась ошибкой", { err: err.message });
      }
    });

    els.agentConnectWs.addEventListener("click", async () => {
      try {
        await connectAgentWS();
      } catch (err) {
        log("error", "Не удалось подключить WS агента", { err: err.message });
      }
    });

    els.agentDisconnectWs.addEventListener("click", () => {
      closeWs("agent", "manual");
    });

    els.agentGenerateOtp.addEventListener("click", async () => {
      try {
        await generateOtp();
      } catch (err) {
        log("error", "Ошибка генерации OTP", { err: err.message });
      }
    });

    els.agentStartShare.addEventListener("click", async () => {
      try {
        await ensureAgentLocalStream();
      } catch (err) {
        log("error", "Ошибка демонстрации экрана", { err: err.message });
      }
    });

    els.agentAcceptNow.addEventListener("click", async () => {
      try {
        await acceptPendingSession();
      } catch (err) {
        log("error", "Не удалось принять сессию", { err: err.message });
      }
    });

    els.agentAutoAccept.addEventListener("change", () => {
      log("info", "Параметр автопринятия изменён", { enabled: els.agentAutoAccept.checked });
    });

    els.agentEnableInput.addEventListener("change", () => {
      log("info", "Параметр удалённого ввода агента изменён", { enabled: els.agentEnableInput.checked });
    });

    els.permRefresh.addEventListener("click", async () => {
      await refreshPermissionsStatus();
      log("info", "Статус разрешений обновлён");
    });

    els.permPromptAccessibility.addEventListener("click", async () => {
      if (!hasDesktopCapability("promptAccessibility")) {
        log("warn", "Запрос доступа недоступен");
        return;
      }
      try {
        const result = await desktop.promptAccessibility();
        await refreshPermissionsStatus();
        log("info", "Результат запроса доступа", result);
      } catch (err) {
        log("warn", "Запрос доступа завершился ошибкой", { err: err.message });
      }
    });

    els.permOpenAccessibility.addEventListener("click", async () => {
      if (!hasDesktopCapability("openPermissionsSettings")) {
        log("warn", "Действие открытия настроек недоступно");
        return;
      }
      await desktop.openPermissionsSettings("accessibility");
    });

    els.permOpenScreen.addEventListener("click", async () => {
      if (!hasDesktopCapability("openPermissionsSettings")) {
        log("warn", "Действие открытия настроек недоступно");
        return;
      }
      await desktop.openPermissionsSettings("screen");
    });

    els.viewerRequestSession.addEventListener("click", async () => {
      try {
        await requestViewerSession();
      } catch (err) {
        log("error", "Ошибка запроса сессии", { err: err.message });
      }
    });

    els.viewerConnectWs.addEventListener("click", async () => {
      try {
        await connectViewerWS();
      } catch (err) {
        log("error", "Не удалось подключить WS наблюдателя", { err: err.message });
      }
    });

    els.viewerDisconnectWs.addEventListener("click", () => {
      closeWs("viewer", "manual");
    });

    els.remoteInputToggle.addEventListener("change", () => {
      state.remoteInput.enabled = els.remoteInputToggle.checked;
      state.remoteInput.lastMoveSentAt = 0;
      log("info", "Параметр удалённого ввода наблюдателя изменён", { enabled: state.remoteInput.enabled });
      if (state.remoteInput.enabled) {
        els.remoteVideo.focus();
      }
    });

    els.sendRemoteText.addEventListener("click", async () => {
      try {
        await sendRemoteText();
      } catch (err) {
        log("error", "Не удалось отправить удалённый текст", { err: err.message });
      }
    });

    els.remoteTextInput.addEventListener("keydown", async (event) => {
      if (event.key !== "Enter") {
        return;
      }
      event.preventDefault();
      try {
        await sendRemoteText();
      } catch (err) {
        log("error", "Не удалось отправить удалённый текст", { err: err.message });
      }
    });

    els.sendFileBtn.addEventListener("click", async () => {
      try {
        await sendFile();
      } catch (err) {
        log("error", "Ошибка передачи файла", { err: err.message });
      }
    });

    document.addEventListener("dragover", (event) => {
      event.preventDefault();
    });
    document.addEventListener("drop", (event) => {
      event.preventDefault();
      const droppedFiles = event.dataTransfer?.files;
      if (!droppedFiles || droppedFiles.length === 0) {
        return;
      }
      const dt = new DataTransfer();
      dt.items.add(droppedFiles[0]);
      els.fileInput.files = dt.files;
      log("info", "Файл выбран перетаскиванием", {
        name: droppedFiles[0].name,
        size: droppedFiles[0].size
      });
    });

    els.clipboardToggle.addEventListener("change", () => {
      setClipboardSyncEnabled(els.clipboardToggle.checked);
      log("info", "Синхронизация буфера обмена переключена", { enabled: els.clipboardToggle.checked });
    });

    els.pushClipboard.addEventListener("click", async () => {
      try {
        await pushClipboard();
      } catch (err) {
        log("error", "Не удалось отправить буфер обмена", { err: err.message });
      }
    });

    els.pullClipboard.addEventListener("click", async () => {
      try {
        await pullClipboard();
      } catch (err) {
        log("warn", "Не удалось прочитать буфер обмена", { err: err.message });
      }
    });

    els.hangupBtn.addEventListener("click", async () => {
      await hangupSession();
    });

    els.exportDiagnostics.addEventListener("click", async () => {
      try {
        await exportDiagnostics();
      } catch (err) {
        log("error", "Экспорт завершился ошибкой", { err: err.message });
      }
    });

    els.clearLogs.addEventListener("click", () => {
      state.logs = [];
      els.logOutput.textContent = "";
    });

    attachRemoteInputHandlers();

    window.addEventListener("beforeunload", async () => {
      setClipboardSyncEnabled(false);
      closeWs("agent", "manual");
      closeWs("viewer", "manual");
      await teardownRtc("window-close");
      if (state.localStream) {
        state.localStream.getTracks().forEach((t) => t.stop());
      }
    });
  }

  function hydrateUi() {
    els.signalBase.value = state.signalBase;
    els.agentDeviceId.value = state.agent.deviceId;
    els.agentDeviceToken.value = state.agent.deviceToken;
    els.viewerDeviceId.value = state.viewer.deviceId;
    els.viewerSessionId.value = state.viewer.sessionId;
    if (els.devicePublicId) {
      els.devicePublicId.textContent = formatPublicId(state.agent.publicId || state.agent.deviceId);
    }
    updateAccountLabels();
    setQualityUi(state.stream.preferredQuality);
    setLoginError("");

    const theme = localStorage.getItem("valden.theme") || "dark";
    setTheme(theme);
    state.remoteInput.enabled = Boolean(els.remoteInputToggle?.checked);
    updatePermissionWidgets();
    setRole(state.role);
    if (state.auth.accessToken && state.agent.deviceId && state.agent.deviceToken) {
      setScreen("main");
    } else if (state.auth.accessToken) {
      setScreen("main");
    } else {
      setScreen("login");
    }
    refreshStatus();
  }

  async function init() {
    hydrateUi();
    attachEvents();
    await initMeta();
    await refreshPermissionsStatus();

    if (hasDesktopCapability("onActivationPayload")) {
      desktop.onActivationPayload((payload) => {
        applyActivationPayload(payload).catch((err) => {
          setLoginError(`Не удалось активировать приложение: ${err.message}`);
        });
      });
    }

    try {
      const health = await apiGet("/healthz");
      log("info", "Состояние сервера", health);
    } catch (err) {
      log("warn", "Проверка состояния сервера завершилась ошибкой", { err: err.message });
    }

    let activationHandled = false;
    if (hasDesktopCapability("consumePendingActivation")) {
      try {
        const pendingActivation = await desktop.consumePendingActivation();
        if (pendingActivation?.token) {
          activationHandled = await applyActivationPayload(pendingActivation);
        }
      } catch (err) {
        log("warn", "Не удалось прочитать отложенную активацию", { err: err.message });
      }
    }

    if (!activationHandled && state.auth.accessToken) {
      try {
        await registerAgent();
        await connectAgentWS();
        setScreen("main");
      } catch (err) {
        const message = String(err.message || "");
        const shouldResetAuth = /401|unauthorized|invalid|forbidden/i.test(message);
        if (shouldResetAuth) {
          clearAuthState();
          setScreen("login");
          setLoginError("Сессия истекла. Войдите снова.");
        }
        log("warn", "Автоподключение после авторизации не удалось", { err: message });
      }
    }
  }

  init().catch((err) => {
    log("error", "Ошибка инициализации", { err: err.message });
  });
})();
