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

    var selectAll = ev.target.closest("[data-select-all]");
    if (selectAll) {
      var panel = selectAll.closest("#file-panel") || document;
      panel.querySelectorAll(".row-check").forEach(function (box) { box.checked = selectAll.checked; });
      return;
    }

    var bulk = ev.target.closest("[data-bulk-delete]");
    if (bulk) {
      ev.preventDefault();
      var checks = [];
      document.querySelectorAll("#file-panel .row-check:checked").forEach(function (box) { checks.push(box.value); });
      if (!checks.length) { alert(bulk.dataset.emptyLabel || "Select at least one item."); return; }
      if (!confirm(bulk.dataset.confirmLabel || "Delete selected items?")) return;
      var csrf = document.querySelector("input[name=csrf]");
      htmx.ajax("POST", "/files/bulk-delete", {
        target: "#file-panel", swap: "innerHTML",
        values: { csrf: csrf ? csrf.value : "", bucket: bulk.dataset.bucket, prefix: bulk.dataset.prefix, keys: checks.join("\n") }
      });
      return;
    }

    var accountRename = ev.target.closest("[data-account-rename]");
    if (accountRename) {
      ev.preventDefault();
      var accountName = prompt(accountRename.dataset.promptLabel || "Account nickname", accountRename.dataset.name);
      if (!accountName || accountName === accountRename.dataset.name) return;
      submitAction("/accounts/rename", { id: accountRename.dataset.id, name: accountName });
      return;
    }

    var bucketRename = ev.target.closest("[data-bucket-rename]");
    if (bucketRename) {
      ev.preventDefault();
      var nextName = prompt(bucketRename.dataset.promptLabel || "New bucket name", bucketRename.dataset.name);
      if (!nextName || nextName === bucketRename.dataset.name) return;
      submitAction("/buckets/rename", { name: bucketRename.dataset.name, new_name: nextName });
      return;
    }

    var rename = ev.target.closest("[data-rename]");
    if (rename) {
      ev.preventDefault();
      var newName = prompt(rename.dataset.promptLabel || "New name", rename.dataset.name);
      if (!newName || newName === rename.dataset.name) return;
      sendFileAction("/files/rename", { key: rename.dataset.key, name: newName, bucket: rename.dataset.bucket, prefix: rename.dataset.prefix });
      return;
    }

    var move = ev.target.closest("[data-move]");
    if (move) {
      ev.preventDefault();
      var dest = prompt(move.dataset.promptLabel || "New full key", move.dataset.key);
      if (!dest || dest === move.dataset.key) return;
      sendFileAction("/files/move", { key: move.dataset.key, dest: dest, bucket: move.dataset.bucket, prefix: move.dataset.prefix });
      return;
    }

    var copy = ev.target.closest("[data-copy]");
    if (copy) {
      ev.preventDefault();
      var destBucket = prompt(copy.dataset.bucketLabel || "Destination bucket", copy.dataset.bucket);
      if (!destBucket) return;
      var destKey = prompt(copy.dataset.keyLabel || "Destination key", copy.dataset.key);
      if (!destKey) return;
      sendFileAction("/files/copy", { key: copy.dataset.key, dest_bucket: destBucket, dest_key: destKey, bucket: copy.dataset.bucket, prefix: copy.dataset.prefix });
      return;
    }

    var preview = ev.target.closest("[data-preview]");
    if (preview) {
      ev.preventDefault();
      openPreview(preview.dataset.url, preview.dataset.kind, preview.textContent);
      return;
    }
    if (ev.target.closest("[data-preview-close]") || ev.target.id === "preview-dialog") {
      var dialog = document.getElementById("preview-dialog");
      if (dialog) { dialog.close(); dialog.querySelector("[data-preview-body]").innerHTML = ""; }
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

  function csrfValue() {
    var el = document.querySelector("input[name=csrf]");
    return el ? el.value : "";
  }

  function submitAction(url, values) {
    var form = document.createElement("form");
    form.method = "post";
    form.action = url;
    form.style.display = "none";
    values.csrf = csrfValue();
    Object.keys(values).forEach(function (key) {
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = key;
      input.value = values[key];
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  }

  function sendFileAction(url, values) {
    values.csrf = csrfValue();
    htmx.ajax("POST", url, { target: "#file-panel", swap: "innerHTML", values: values });
  }

  function openPreview(url, kind, title) {
    var dialog = document.getElementById("preview-dialog");
    if (!dialog) return;
    var body = dialog.querySelector("[data-preview-body]");
    var heading = dialog.querySelector("[data-preview-title]");
    if (heading) heading.textContent = title || "Preview";
    body.innerHTML = "";
    if (kind === "image") {
      var img = document.createElement("img");
      img.src = url;
      img.alt = title || "";
      body.appendChild(img);
    } else {
      var frame = document.createElement("iframe");
      frame.src = url;
      frame.title = title || "Preview";
      body.appendChild(frame);
    }
    if (dialog.showModal) dialog.showModal(); else dialog.setAttribute("open", "");
  }

  function setupFolderUpload(input) {
    if (!input) return;
    input.addEventListener("change", function () {
      if (!input.files || !input.files.length) return;
      var form = new FormData();
      form.append("csrf", csrfValue());
      form.append("bucket", input.dataset.bucket || "");
      form.append("prefix", input.dataset.prefix || "");
      for (var i = 0; i < input.files.length; i++) {
        var file = input.files[i];
        form.append("files", file, file.name);
        form.append("rel", file.webkitRelativePath || file.name);
      }
      var panel = document.getElementById("file-panel");
      if (panel) panel.setAttribute("aria-busy", "true");
      fetch("/files/upload-folder", { method: "POST", body: form, credentials: "same-origin", headers: { "X-CSRF-Token": csrfValue() } })
        .then(function (res) {
          if (!res.ok) throw new Error("folder upload failed");
          return res.text();
        })
        .then(function (html) {
          if (panel) { panel.innerHTML = html; panel.removeAttribute("aria-busy"); }
          if (window.htmx) htmx.process(panel);
          setup();
        })
        .catch(function () {
          if (panel) panel.removeAttribute("aria-busy");
          alert(input.dataset.failedLabel || "Folder upload failed.");
        });
      input.value = "";
    });
  }

  function setupDropZone() {
    var panel = document.getElementById("file-panel");
    if (!panel || panel.dataset.dropReady) return;
    panel.dataset.dropReady = "1";
    panel.addEventListener("dragover", function (ev) {
      if (!ev.dataTransfer || !ev.dataTransfer.types || ev.dataTransfer.types.indexOf("Files") < 0) return;
      ev.preventDefault();
      panel.classList.add("dragging");
    });
    panel.addEventListener("dragleave", function (ev) {
      if (ev.target === panel) panel.classList.remove("dragging");
    });
    panel.addEventListener("drop", function (ev) {
      if (!ev.dataTransfer || !ev.dataTransfer.files || !ev.dataTransfer.files.length) return;
      ev.preventDefault();
      panel.classList.remove("dragging");
      var input = panel.querySelector("[data-file-input]");
      if (!input) return;
      input.files = ev.dataTransfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
      var form = input.closest("form");
      if (form) form.requestSubmit ? form.requestSubmit() : form.submit();
    });
  }

  function setupUpload(form) {
    if (form.dataset.uploadReady) return;
    form.dataset.uploadReady = "1";
    var bar = form.querySelector("[data-upload-bar]");
    var fill = form.querySelector("[data-upload-progress]");
    var text = form.querySelector("[data-upload-text]");
    var pause = form.querySelector("[data-upload-pause]");
    var cancel = form.querySelector("[data-upload-cancel]");
    var input = form.querySelector("[data-file-input]");
    var label = form.querySelector("[data-file-label]");
    if (!bar || !input) return;

    var state = { paused: false, cancelled: false, uploadID: "", currentFile: null };

    function setProgress(pct) {
      bar.classList.add("on");
      if (fill) fill.style.width = Math.max(1, Math.min(100, pct)) + "%";
      if (text) text.textContent = Math.round(pct) + "%";
    }

    function resetBar() {
      bar.classList.remove("on");
      if (fill) fill.style.width = "0%";
      if (text) text.textContent = "0%";
      if (pause) pause.textContent = pause.dataset.pauseLabel || "Pause";
    }

    if (pause) {
      pause.addEventListener("click", function () {
        state.paused = !state.paused;
        pause.textContent = state.paused
          ? (pause.dataset.resumeLabel || "Resume")
          : (pause.dataset.pauseLabel || "Pause");
      });
    }
    if (cancel) {
      cancel.addEventListener("click", function () {
        state.cancelled = true;
        state.paused = false;
        if (state.uploadID) {
          var body = new FormData();
          body.append("upload_id", state.uploadID);
          fetch("/files/upload/abort", { method: "POST", body: body, credentials: "same-origin", headers: { "X-CSRF-Token": csrfValue() } });
        }
        if (state.currentFile) clearResume(state.currentFile);
        state.uploadID = "";
        resetBar();
      });
    }

    function waitForResume() {
      return new Promise(function (resolve) {
        (function tick() {
          if (!state.paused || state.cancelled) { resolve(); return; }
          setTimeout(tick, 200);
        })();
      });
    }

    function resumeKey(file) {
      var bucket = form.querySelector("input[name=bucket]").value;
      var prefix = form.querySelector("input[name=prefix]").value;
      return "s3drive-upload:" + bucket + "/" + prefix + file.name + ":" + file.size + ":" + (file.lastModified || 0);
    }

    function loadResume(file) {
      try {
        var raw = localStorage.getItem(resumeKey(file));
        return raw ? JSON.parse(raw) : null;
      } catch (e) { return null; }
    }

    function saveResume(file, value) {
      try { localStorage.setItem(resumeKey(file), JSON.stringify(value)); } catch (e) {}
    }

    function clearResume(file) {
      try { localStorage.removeItem(resumeKey(file)); } catch (e) {}
    }

    async function uploadOne(file, doneBytes, totalBytes) {
      state.currentFile = file;
      var saved = loadResume(file);
      var session = null;
      var partSize = 8 * 1024 * 1024;
      var sent = 0;
      var part = 1;
      if (saved && saved.id && saved.partSize) {
        session = { id: saved.id, part_size: saved.partSize };
        partSize = saved.partSize;
        sent = saved.sent || 0;
        part = saved.part || Math.floor(sent / partSize) + 1;
        setProgress(((doneBytes + sent) / Math.max(1, totalBytes)) * 97);
      }
      if (!session) {
        var init = new FormData();
        init.append("csrf", csrfValue());
        init.append("bucket", form.querySelector("input[name=bucket]").value);
        init.append("prefix", form.querySelector("input[name=prefix]").value);
        init.append("name", file.name);
        init.append("size", String(file.size));
        init.append("content_type", file.type || "application/octet-stream");
        var res = await fetch("/files/upload/init", { method: "POST", body: init, credentials: "same-origin" });
        if (!res.ok) throw new Error(await res.text());
        session = await res.json();
        partSize = session.part_size || 8 * 1024 * 1024;
        saveResume(file, { id: session.id, partSize: partSize, sent: 0, part: 1 });
      }
      state.uploadID = session.id;
      var uploadedParts = saved ? Math.max(0, part - 1) : 0;
      while (sent < file.size || (file.size === 0 && uploadedParts === 0)) {
        await waitForResume();
        if (state.cancelled) return false;
        var end = Math.min(file.size, sent + partSize);
        var blob = file.slice(sent, end);
        var url = "/files/upload/part?upload_id=" + encodeURIComponent(session.id) + "&part=" + part;
        var partRes = await fetch(url, {
          method: "POST", body: blob, credentials: "same-origin",
          headers: { "X-CSRF-Token": csrfValue(), "Content-Type": "application/octet-stream" }
        });
        if (partRes.status === 404) {
          clearResume(file);
          throw new Error(form.dataset.uploadExpired || "The upload session expired. Select the file and start again.");
        }
        if (!partRes.ok) throw new Error(await partRes.text());
        sent = end;
        part++;
        uploadedParts++;
        saveResume(file, { id: session.id, partSize: partSize, sent: sent, part: part });
        setProgress(((doneBytes + sent) / Math.max(1, totalBytes)) * 97);
      }

      var done = new FormData();
      done.append("csrf", csrfValue());
      done.append("upload_id", session.id);
      done.append("bucket", form.querySelector("input[name=bucket]").value);
      done.append("prefix", form.querySelector("input[name=prefix]").value);
      var doneRes = await fetch("/files/upload/complete", { method: "POST", body: done, credentials: "same-origin" });
      if (!doneRes.ok) {
        var failureHTML = await doneRes.text();
        if (failureHTML) {
          var target = document.getElementById("file-panel");
          if (target) {
            target.innerHTML = failureHTML;
            if (window.htmx) htmx.process(target);
            setup();
          }
        }
        if (doneRes.status === 404) {
          clearResume(file);
          throw new Error(form.dataset.uploadExpired || "The upload session expired. Select the file and start again.");
        }
        throw new Error(form.dataset.uploadFailed || "Upload failed. Staged parts were kept so you can retry.");
      }
      state.uploadID = "";
      clearResume(file);
      return await doneRes.text();
    }

    form.addEventListener("submit", async function (ev) {
      if (!input.files || !input.files.length) return;
      ev.preventDefault();
      state.paused = false;
      state.cancelled = false;
      var files = Array.prototype.slice.call(input.files);
      var total = files.reduce(function (sum, f) { return sum + f.size; }, 0);
      var doneBytes = 0;
      var finalHTML = "";
      try {
        setProgress(1);
        for (var i = 0; i < files.length; i++) {
          var html = await uploadOne(files[i], doneBytes, total);
          if (state.cancelled || html === false) { finalHTML = ""; break; }
          doneBytes += files[i].size;
          finalHTML = html;
          setProgress(((doneBytes / Math.max(1, total)) * 100));
        }
        if (state.cancelled) {
          resetBar();
          input.value = "";
          if (label) label.textContent = "";
          return;
        }
        var panel = document.getElementById("file-panel");
        if (panel && finalHTML) {
          panel.innerHTML = finalHTML;
          if (window.htmx) htmx.process(panel);
          setup();
        }
      } catch (err) {
        // Keep the upload record and staged parts on failure so selecting the
        // same file resumes from the last completed part.
        var region = document.querySelector("[data-toasts]");
        if (region) {
          var toast = document.createElement("div");
          toast.className = "toast";
          toast.textContent = err && err.message ? err.message : "Upload failed.";
          region.appendChild(toast);
          setTimeout(function () { toast.remove(); }, 7000);
        }
      } finally {
        resetBar();
        input.value = "";
        if (label) label.textContent = "";
      }
    });
  }

  function setup() {
    document.querySelectorAll("[data-upload-form]").forEach(setupUpload);
    setupFolderUpload(document.querySelector("[data-folder-input]"));
    setupDropZone();
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
