(() => {
  const API_BASE_KEY = "valden.apiBase";
  const ACCESS_TOKEN_KEY = "valden.auth.accessToken";
  const REFRESH_TOKEN_KEY = "valden.auth.refreshToken";
  const USER_EMAIL_KEY = "valden.auth.userEmail";
  const USER_ID_KEY = "valden.auth.userId";
  const PENDING_ACTIVATION_URL_KEY = "valden.pendingActivationUrl";
  const PENDING_ACTIVATION_TIME_KEY = "valden.pendingActivationAt";

  const defaultApiBase = "https://api.valden.space";

  const pageName = (() => {
    const path = window.location.pathname || "";
    if (path.endsWith("/login.html") || path === "/login.html") return "login";
    if (path.endsWith("/register.html") || path === "/register.html") return "register";
    if (path.endsWith("/downloads.html") || path === "/downloads.html") return "downloads";
    return "other";
  })();

  const apiBase = (() => {
    const custom = (localStorage.getItem(API_BASE_KEY) || "").trim();
    if (custom) {
      return custom.replace(/\/$/, "");
    }
    return defaultApiBase;
  })();

  const getAuthState = () => ({
    accessToken: (localStorage.getItem(ACCESS_TOKEN_KEY) || "").trim(),
    refreshToken: (localStorage.getItem(REFRESH_TOKEN_KEY) || "").trim(),
    email: (localStorage.getItem(USER_EMAIL_KEY) || "").trim(),
    userId: (localStorage.getItem(USER_ID_KEY) || "").trim()
  });

  const saveAuthState = (payload) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, payload.accessToken || "");
    localStorage.setItem(REFRESH_TOKEN_KEY, payload.refreshToken || "");
    localStorage.setItem(USER_EMAIL_KEY, payload.email || "");
    localStorage.setItem(USER_ID_KEY, payload.userId || "");
  };

  const clearAuthState = () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_EMAIL_KEY);
    localStorage.removeItem(USER_ID_KEY);
    localStorage.removeItem(PENDING_ACTIVATION_URL_KEY);
    localStorage.removeItem(PENDING_ACTIVATION_TIME_KEY);
  };

  const parseJsonSafe = async (response) => {
    const text = await response.text();
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch (_err) {
      return {};
    }
  };

  const postJson = async (path, body, accessToken = "") => {
    const headers = { "Content-Type": "application/json" };
    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }

    const response = await fetch(`${apiBase}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body || {})
    });

    const payload = await parseJsonSafe(response);
    if (!response.ok) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }

    return payload;
  };

  const tryRefreshToken = async () => {
    const auth = getAuthState();
    if (!auth.refreshToken) {
      return false;
    }

    try {
      const refreshed = await postJson("/v1/auth/refresh", {
        refresh_token: auth.refreshToken
      });
      saveAuthState({
        accessToken: refreshed.access_token,
        refreshToken: refreshed.refresh_token,
        email: refreshed.user?.email || auth.email,
        userId: refreshed.user?.id || auth.userId
      });
      return true;
    } catch (_err) {
      clearAuthState();
      return false;
    }
  };

  const setAuthMessage = (message, isError = false) => {
    const el = document.getElementById("authMessage") || document.getElementById("bootstrapHint");
    if (!el) {
      return;
    }
    el.textContent = message;
    el.classList.toggle("is-error", Boolean(isError));
    el.classList.toggle("is-success", !isError && Boolean(message));
  };

  const handleLoginPage = () => {
    const form = document.querySelector(".auth-form");
    const emailInput = document.getElementById("loginEmail");
    const passwordInput = document.getElementById("loginPassword");
    const submitBtn = document.getElementById("loginSubmit");
    if (!form || !emailInput || !passwordInput || !submitBtn) {
      return;
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      setAuthMessage("");
      submitBtn.disabled = true;

      try {
        const payload = await postJson("/v1/auth/login", {
          email: emailInput.value.trim(),
          password: passwordInput.value
        });

        saveAuthState({
          accessToken: payload.access_token,
          refreshToken: payload.refresh_token,
          email: payload.user?.email || emailInput.value.trim(),
          userId: payload.user?.id || ""
        });

        setAuthMessage("Вход успешен. Перенаправляем на скачивание...");
        window.setTimeout(() => {
          window.location.href = "./downloads.html";
        }, 420);
      } catch (err) {
        setAuthMessage(err.message || "Не удалось войти", true);
      } finally {
        submitBtn.disabled = false;
      }
    });
  };

  const handleRegisterPage = () => {
    const form = document.querySelector(".auth-form");
    const emailInput = document.getElementById("registerEmail");
    const passwordInput = document.getElementById("registerPassword");
    const confirmInput = document.getElementById("registerPasswordConfirm");
    const submitBtn = document.getElementById("registerSubmit");
    if (!form || !emailInput || !passwordInput || !confirmInput || !submitBtn) {
      return;
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      setAuthMessage("");

      if (passwordInput.value !== confirmInput.value) {
        setAuthMessage("Пароли не совпадают", true);
        return;
      }
      if (passwordInput.value.length < 8) {
        setAuthMessage("Пароль должен содержать минимум 8 символов", true);
        return;
      }

      submitBtn.disabled = true;
      try {
        const payload = await postJson("/v1/auth/register", {
          email: emailInput.value.trim(),
          password: passwordInput.value
        });

        saveAuthState({
          accessToken: payload.access_token,
          refreshToken: payload.refresh_token,
          email: payload.user?.email || emailInput.value.trim(),
          userId: payload.user?.id || ""
        });

        setAuthMessage("Регистрация успешна. Перенаправляем на скачивание...");
        window.setTimeout(() => {
          window.location.href = "./downloads.html";
        }, 420);
      } catch (err) {
        setAuthMessage(err.message || "Не удалось зарегистрироваться", true);
      } finally {
        submitBtn.disabled = false;
      }
    });
  };

  const handleDownloadsPage = () => {
    const statusEl = document.getElementById("downloadAuthState");
    const hintEl = document.getElementById("bootstrapHint");
    const buttons = Array.from(document.querySelectorAll(".download-btn[data-platform]"));
    if (!statusEl || !buttons.length) {
      return;
    }

    const openInstallerDownload = (url) => {
      if (!url) {
        return;
      }
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.rel = "noopener";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    };

    const buildActivationUrl = (token) => {
      const params = new URLSearchParams();
      params.set("token", token);
      params.set("api", apiBase);
      return `valden://activate#${params.toString()}`;
    };

    const openActivationUrl = (activationUrl) => {
      if (!activationUrl) {
        return;
      }
      window.location.href = activationUrl;
    };

    const setHint = ({ message = "", isError = false, activationUrl = "" } = {}) => {
      if (!hintEl) {
        return;
      }

      hintEl.textContent = "";
      hintEl.classList.toggle("is-error", Boolean(isError));
      hintEl.classList.toggle("is-success", !isError && Boolean(message));
      if (!message) {
        return;
      }

      const text = document.createElement("span");
      text.textContent = message;
      hintEl.appendChild(text);

      if (activationUrl) {
        hintEl.appendChild(document.createTextNode(" "));
        const openBtn = document.createElement("button");
        openBtn.type = "button";
        openBtn.className = "download-mini-btn";
        openBtn.textContent = "Открыть и активировать";
        openBtn.addEventListener("click", () => {
          openActivationUrl(activationUrl);
        });
        hintEl.appendChild(openBtn);
      }
    };

    const showPendingActivationHint = () => {
      const pendingUrl = String(localStorage.getItem(PENDING_ACTIVATION_URL_KEY) || "").trim();
      const createdAt = String(localStorage.getItem(PENDING_ACTIVATION_TIME_KEY) || "").trim();
      if (!pendingUrl) {
        return;
      }
      const timeSuffix = createdAt ? ` (${new Date(createdAt).toLocaleTimeString()})` : "";
      setHint({
        message: `У вас уже есть подготовленная активация${timeSuffix}. Установите приложение и нажмите кнопку:`,
        activationUrl: pendingUrl
      });
    };

    const renderState = () => {
      const auth = getAuthState();
      if (!auth.accessToken) {
        statusEl.innerHTML = `
          <strong>Для персональной активации нужно войти в аккаунт.</strong>
          <a href="./login.html">Войти</a>
        `;
        return false;
      }

      statusEl.innerHTML = `<strong>Вы вошли как ${auth.email || "пользователь"}</strong><button id="logoutSiteBtn" class="download-mini-btn">Выйти</button>`;
      const logoutBtn = document.getElementById("logoutSiteBtn");
      if (logoutBtn) {
        logoutBtn.addEventListener("click", () => {
          clearAuthState();
          setHint({ message: "" });
          renderState();
        });
      }
      return true;
    };

    const createBootstrap = async (platform) => {
      const auth = getAuthState();
      let accessToken = auth.accessToken;
      if (!accessToken) {
        throw new Error("Нужна авторизация");
      }

      try {
        return await postJson(
          "/v1/client/bootstrap/create",
          {
            platform,
            device_name: `VALDEN ${platform}`
          },
          accessToken
        );
      } catch (err) {
        if (!String(err.message || "").toLowerCase().includes("unauthorized")) {
          throw err;
        }

        const refreshed = await tryRefreshToken();
        if (!refreshed) {
          throw new Error("Сессия истекла. Войдите заново.");
        }

        accessToken = getAuthState().accessToken;
        return postJson(
          "/v1/client/bootstrap/create",
          {
            platform,
            device_name: `VALDEN ${platform}`
          },
          accessToken
        );
      }
    };

    buttons.forEach((button) => {
      const defaultLabel = button.textContent;
      button.addEventListener("click", async () => {
        if (!renderState()) {
          window.location.href = "./login.html";
          return;
        }

        const platform = String(button.getAttribute("data-platform") || "unknown");
        const installerUrl = String(button.getAttribute("data-installer-url") || "");

        button.disabled = true;
        button.textContent = "Подготовка персональной активации...";
        setHint({ message: "" });

        try {
          const payload = await createBootstrap(platform);
          const token = String(payload.bootstrap_token || "").trim();
          if (!token) {
            throw new Error("Сервер не вернул bootstrap-токен");
          }

          const activationUrl = buildActivationUrl(token);
          localStorage.setItem(PENDING_ACTIVATION_URL_KEY, activationUrl);
          localStorage.setItem(PENDING_ACTIVATION_TIME_KEY, new Date().toISOString());

          setHint({
            message: "Готово. Установите приложение и нажмите кнопку активации:",
            activationUrl
          });

          if (installerUrl) {
            openInstallerDownload(installerUrl);
          }
          window.setTimeout(() => openActivationUrl(activationUrl), 650);
        } catch (err) {
          setHint({
            message: err.message || "Не удалось подготовить персональную активацию",
            isError: true
          });
        } finally {
          button.disabled = false;
          button.textContent = defaultLabel;
        }
      });
    });

    renderState();
    showPendingActivationHint();
  };

  if (pageName === "login") {
    handleLoginPage();
  } else if (pageName === "register") {
    handleRegisterPage();
  } else if (pageName === "downloads") {
    handleDownloadsPage();
  }

  window.ValdenSiteAuth = {
    apiBase,
    getAuthState,
    clearAuthState,
    tryRefreshToken
  };
})();
