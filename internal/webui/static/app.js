// app.js — theme toggle, toasts, tiny htmx wiring. No framework.
(function () {
  // Theme: stored preference wins; else system.
  const saved = localStorage.getItem("freens-theme");
  if (saved === "light" || saved === "dark") {
    document.documentElement.dataset.theme = saved;
  }
  window.toggleTheme = function () {
    const cur = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = cur;
    localStorage.setItem("freens-theme", cur);
  };

  // Toasts: any element with data-toast triggers one after settle.
  document.body.addEventListener("htmx:afterRequest", function (ev) {
    const el = ev.detail.elt;
    const msg = el && el.dataset && (el.dataset.toast || (ev.detail.successful ? "" : ""));
    if (msg) toast(msg, el.dataset.toastKind || "");
    const hdr = ev.detail.xhr && ev.detail.xhr.getResponseHeader("X-Toast");
    if (hdr) toast(decodeURIComponent(hdr), "");
  });

  function toast(msg, kind) {
    const host = document.getElementById("toasts");
    if (!host) return;
    const t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.textContent = msg;
    host.appendChild(t);
    setTimeout(function () { t.remove(); }, 5000);
  }
  window.freensToast = toast;
})();
