(() => {
  let hideTimer;
  let deployTrigger;
  let deployRowID;

  function showToast(message, type) {
    const toast = document.getElementById("toast");
    if (!toast) {
      return;
    }

    const isError = type === "error";
    toast.textContent = message || "请求失败，请稍后重试";
    toast.dataset.type = isError ? "error" : "success";
    toast.setAttribute("role", isError ? "alert" : "status");
    toast.setAttribute("aria-live", isError ? "assertive" : "polite");
    toast.hidden = false;

    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      toast.hidden = true;
    }, 5000);
  }

  function updateDeploySelection(form) {
    const options = form.querySelectorAll('input[name="agents"]:not(:disabled)');
    const selected = Array.from(options).filter((option) => option.checked).length;
    form.querySelector("[data-deploy-count]").textContent = `已选择 ${selected} / ${options.length} 个 Agent`;
    form.querySelector("[data-deploy-submit]").disabled = selected === 0 || form.dataset.submitting === "true";
    const error = form.querySelector(".deploy-selection-error");
    error.textContent = selected === 0 ? "请至少选择一个 Agent" : "";
    error.hidden = selected > 0;
  }

  function showRequestError(event, message) {
    const element = event.detail && event.detail.elt;
    const form = element && element.closest("[data-deploy-form]");
    if (form) {
      const error = form.querySelector(".deploy-selection-error");
      error.textContent = message;
      error.hidden = false;
    } else if (element && element.getAttribute("aria-controls") === "certificate-deploy-dialog") {
      const loading = document.querySelector("[data-deploy-loading]");
      if (loading) {
        loading.textContent = message;
        loading.setAttribute("role", "alert");
      }
    }
    showToast(message, "error");
  }

  // Resolve the dialog when handling events: it may not exist yet when this
  // script loads, or may have been replaced by a page navigation.
  document.addEventListener("close", (event) => {
    if (event.target.id === "certificate-deploy-dialog") {
      const row = document.getElementById(deployRowID);
      const target = deployTrigger && deployTrigger.isConnected && !deployTrigger.disabled
        ? deployTrigger
        : row && row.querySelector("a, button:not(:disabled)");
      if (target) {
        target.focus();
      }
    }
  }, true);

  function initializeDeployForm(event) {
    const deployDialog = document.getElementById("certificate-deploy-dialog");
    const content = document.getElementById("certificate-deploy-content");
    const element = (event.detail && event.detail.elt) || event.target;
    if (!deployDialog || !content || !content.contains(element)) {
      return;
    }
    const form = content.querySelector("[data-deploy-form]");
    if (form) {
      updateDeploySelection(form);
      if (deployDialog.open) {
        form.querySelector("[data-deploy-cancel]").focus();
      }
    }
  }

  document.addEventListener("htmx:afterSwap", initializeDeployForm);
  document.addEventListener("htmx:load", initializeDeployForm);

  document.addEventListener("click", (event) => {
    const cancel = event.target.closest("[data-deploy-cancel]");
    if (cancel) {
      cancel.closest("dialog").close();
      return;
    }
    const select = event.target.closest("[data-deploy-select]");
    if (select) {
      const form = select.closest("[data-deploy-form]");
      form.querySelectorAll('input[name="agents"]:not(:disabled)').forEach((option) => {
        option.checked = select.dataset.deploySelect === "all";
      });
      updateDeploySelection(form);
    }
  });

  document.addEventListener("change", (event) => {
    const form = event.target.closest("[data-deploy-form]");
    if (form) {
      updateDeploySelection(form);
    }
  });

  document.addEventListener("htmx:beforeRequest", (event) => {
    const element = event.detail.elt;
    if (element.getAttribute("aria-controls") === "certificate-deploy-dialog") {
      const deployDialog = document.getElementById("certificate-deploy-dialog");
      const content = document.getElementById("certificate-deploy-content");
      if (!deployDialog || !content) {
        return;
      }
      deployTrigger = element;
      deployRowID = element.closest("tr").id;
      const loading = document.createElement("p");
      loading.dataset.deployLoading = "";
      loading.id = "deploy-dialog-title";
      loading.setAttribute("role", "status");
      loading.textContent = "正在加载 Agent…";
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.dataset.deployCancel = "";
      cancel.className = "secondary";
      cancel.textContent = "取消";
      content.replaceChildren(loading, cancel);
      if (!deployDialog.open) {
        deployDialog.showModal();
      }
      return;
    }
    if (!element.matches("[data-deploy-form]")) {
      return;
    }
    if (!element.querySelector('input[name="agents"]:checked:not(:disabled)')) {
      event.preventDefault();
      updateDeploySelection(element);
      return;
    }
    element.dataset.submitting = "true";
    element.querySelector("[data-deploy-submit]").textContent = "正在提交…";
    updateDeploySelection(element);
  });

  document.addEventListener("htmx:afterRequest", (event) => {
    const form = event.detail.elt;
    if (!form.matches("[data-deploy-form]")) {
      return;
    }
    delete form.dataset.submitting;
    form.querySelector("[data-deploy-submit]").textContent = "确认下发";
    const selected = form.querySelector('input[name="agents"]:checked:not(:disabled)');
    form.querySelector("[data-deploy-submit]").disabled = !selected;
    const deployDialog = form.closest("dialog");
    if (deployDialog) {
      if (event.detail.successful) {
        deployDialog.close();
      } else if (deployDialog.open) {
        form.querySelector("[data-deploy-submit]").focus();
      }
    }
  });

  document.addEventListener("showToast", (event) => {
    const detail = event.detail || {};
    showToast(detail.message, detail.type);
  });

  document.addEventListener("htmx:responseError", (event) => {
    const responseText = event.detail && event.detail.xhr && event.detail.xhr.responseText;
    let message = "请求失败，请稍后重试";
    try {
      const response = JSON.parse(responseText);
      if (typeof response.error === "string" && response.error) {
        message = response.error;
      }
    } catch (_) {
      // Keep the fallback message when the response is not JSON.
    }
    showRequestError(event, message);
  });

  ["htmx:sendError", "htmx:timeout"].forEach((eventName) => {
    document.addEventListener(eventName, (event) => {
      showRequestError(event, "网络连接失败，请稍后重试");
    });
  });
})();
