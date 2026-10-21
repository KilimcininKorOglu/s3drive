/* s3drive UI behaviour: theme, upload progress, copy buttons, small niceties. */
(function () {
  "use strict";

  var root = document.documentElement;

  function preferred() {
    var saved = null;
    try { saved = localStorage.getItem("s3drive-theme"); } catch (e) {}
    return saved === "light" || saved === "dark" || saved === "auto" ? saved : "auto";
  }

  function applyTheme(mode) {
    root.setAttribute("data-theme", mode);
    try { localStorage.setItem("s3drive-theme", mode); } catch (e) {}
    var btn = document.querySelector("[data-theme-toggle]");
    if (btn) {
      var label = mode === "auto" ? btn.dataset.labelAuto : mode === "light" ? btn.dataset.labelLight : btn.dataset.labelDark;
      btn.setAttribute("aria-label", label);
      btn.setAttribute("title", label);
      btn.dataset.mode = mode;
    }
  }

  applyTheme(preferred());

  document.addEventListener("click", function (ev) {
    var toggle = ev.target.closest("[data-theme-toggle]");
    if (toggle) {
      ev.preventDefault();
      var order = ["auto", "light", "dark"];
      var current = root.getAttribute("data-theme") || "auto";
      var next = order[(order.indexOf(current) + 1) % order.length];
      applyTheme(next);
      return;
    }

    var copy = ev.target.closest("[data-copy]");
    if (copy) {
      ev.preventDefault();
      var value = copy.getAttribute("data-copy");
      if (value) {
        navigator.clipboard.writeText(value).then(function () {
          var old = copy.getAttribute("title") || "";
          copy.setAttribute("title", copy.dataset.copiedLabel || "Copied");
          copy.classList.add("copied");
          setTimeout(function () {
            copy.classList.remove("copied");
            copy.setAttribute("title", old);
          }, 1600);
        });
      }
      return;
    }

    var folderToggle = ev.target.closest("[data-toggle-folder]");
    if (folderToggle) {
      ev.preventDefault();
      var target = document.querySelector(folderToggle.getAttribute("data-toggle-folder"));
      if (target) {
        target.classList.toggle("hidden");
        var input = target.querySelector("input[name=name]");
        if (input && !target.classList.contains("hidden")) input.focus();
      }
    }
  });

  document.addEventListener("change", function (ev) {
    var input = ev.target.closest("[data-file-input]");
    if (!input) return;
    var label = document.querySelector("[data-file-label]");
    if (label && input.files) {
      label.textContent = input.files.length === 1 ? input.files[0].name : input.files.length + " files";
    }
  });

  function setupUpload(form) {
    var bar = form.querySelector("[data-upload-bar]");
    var fill = form.querySelector("[data-upload-progress]");
    var text = form.querySelector("[data-upload-text]");
    if (!bar) return;
    form.addEventListener("htmx:xhr:progress", function (ev) {
      if (!ev.detail || !ev.detail.lengthComputable) return;
      var pct = Math.max(1, Math.round((ev.detail.loaded / ev.detail.total) * 100));
      bar.classList.add("on");
      if (fill) fill.style.width = pct + "%";
      if (text) text.textContent = pct + "%";
    });
    form.addEventListener("htmx:beforeRequest", function () {
      bar.classList.add("on");
      if (fill) fill.style.width = "2%";
      if (text) text.textContent = "0%";
    });
    form.addEventListener("htmx:afterRequest", function () {
      setTimeout(function () {
        bar.classList.remove("on");
        if (fill) fill.style.width = "0%";
      }, 450);
    });
  }

  function setup() {
    document.querySelectorAll("[data-upload-form]").forEach(setupUpload);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setup);
  } else {
    setup();
  }

  document.body && document.addEventListener("htmx:afterSwap", setup);

  document.addEventListener("htmx:responseError", function (ev) {
    var region = document.querySelector("[data-toasts]");
    if (!region) return;
    var toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = "Request failed (" + (ev.detail && ev.detail.xhr ? ev.detail.xhr.status : "error") + ")";
    region.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 5000);
  });

  window.addEventListener("load", function () {
    document.querySelectorAll("[data-auto-hide]").forEach(function (el) {
      setTimeout(function () {
        el.style.transition = "opacity .25s";
        el.style.opacity = "0";
        setTimeout(function () { el.remove(); }, 300);
      }, 6500);
    });
  });
})();
