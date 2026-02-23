const inlineNavLinks = document.querySelectorAll("a[data-popup]");

inlineNavLinks.forEach((link) => {
  link.addEventListener("click", (event) => {
    // Keep modifier-click behavior in browser, but default to same-tab page transition.
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }

    event.preventDefault();

    const targetUrl = link.getAttribute("href");
    if (!targetUrl) {
      return;
    }

    document.body.classList.add("page-transition-out");
    window.setTimeout(() => {
      window.location.href = targetUrl;
    }, 140);
  });
});

const toast = document.createElement("div");
toast.className = "toast";
document.body.appendChild(toast);

let toastTimer = 0;
const showToast = (message) => {
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toast.classList.remove("is-visible");
  }, 1700);
};

document.querySelectorAll("[data-coming-soon]").forEach((button) => {
  button.addEventListener("click", () => {
    const platform = button.getAttribute("data-coming-soon") || "Платформа";
    showToast(`${platform} установщик скоро появится`);
  });
});
