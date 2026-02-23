(() => {
  const armBtn = document.getElementById("downloadArm64");
  const x64Btn = document.getElementById("downloadX64");
  const statusNode = document.getElementById("downloadStatus");

  if (!armBtn || !x64Btn || !statusNode) {
    return;
  }

  function setDisabled(button, text) {
    button.classList.add("disabled");
    button.setAttribute("aria-disabled", "true");
    button.removeAttribute("download");
    button.removeAttribute("href");
    button.textContent = text;
  }

  function setEnabled(button, url, text) {
    button.classList.remove("disabled");
    button.removeAttribute("aria-disabled");
    button.href = url;
    button.setAttribute("download", "");
    button.textContent = text;
  }

  function formatSize(sizeBytes) {
    if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) {
      return "";
    }
    const mib = sizeBytes / (1024 * 1024);
    return `${mib.toFixed(1)} MB`;
  }

  function formatUpdatedAt(ts) {
    const value = String(ts || "");
    if (!value) {
      return "";
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return new Intl.DateTimeFormat("ru-RU", {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(date);
  }

  function findInstaller(items, arch) {
    return items.find((item) => item && item.arch === arch && item.format === "dmg");
  }

  function applyInstaller(button, installer, label) {
    if (!installer || !installer.url) {
      setDisabled(button, `${label} недоступен`);
      return false;
    }

    const size = formatSize(Number(installer.size_bytes));
    const version = installer.version ? `v${installer.version}` : "";
    const suffix = [version, size].filter(Boolean).join(" • ");
    const title = suffix ? `${label} (${suffix})` : label;
    setEnabled(button, installer.url, title);
    return true;
  }

  async function hydrateDownloads() {
    setDisabled(armBtn, "Apple Silicon недоступен");
    setDisabled(x64Btn, "Intel Mac недоступен");
    statusNode.textContent = "Проверка актуальных установщиков...";

    try {
      const res = await fetch(`/downloads/latest.json?ts=${Date.now()}`, { cache: "no-store" });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const manifest = await res.json();
      const installers = Array.isArray(manifest.installers) ? manifest.installers : [];

      const arm = findInstaller(installers, "arm64");
      const x64 = findInstaller(installers, "x64");

      const hasArm = applyInstaller(armBtn, arm, "Скачать для Apple Silicon");
      const hasX64 = applyInstaller(x64Btn, x64, "Скачать для Intel Mac");

      const isMac = /Mac/i.test(String(navigator.platform || ""));
      const isArmMac = /arm|apple/i.test(String(navigator.userAgent || ""));
      if (isMac) {
        if (isArmMac && hasArm) {
          armBtn.classList.add("recommended");
          x64Btn.classList.remove("recommended");
        } else if (!isArmMac && hasX64) {
          x64Btn.classList.add("recommended");
          armBtn.classList.remove("recommended");
        }
      }

      if (hasArm || hasX64) {
        const version = manifest.version ? `v${manifest.version}` : "";
        const updatedAt = formatUpdatedAt(manifest.generated_at);
        statusNode.textContent =
          `Актуальные установщики ${version}${updatedAt ? ` • обновлено: ${updatedAt}` : ""}`.trim();
      } else {
        statusNode.textContent = "Актуальные установщики пока не опубликованы.";
      }
    } catch (err) {
      statusNode.textContent = "Не удалось загрузить список актуальных установщиков.";
      console.warn("VALDEN downloads manifest load failed", err);
    }
  }

  hydrateDownloads();
})();
