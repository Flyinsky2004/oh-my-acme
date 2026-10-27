(() => {
  const toast = document.getElementById("toast");
  let hideTimer;

  function showToast(message, type) {
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

  const deployDialog = document.getElementById("certificate-deploy-dialog");

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
    }
    showToast(message, "error");
  }

  if (deployDialog) {
    let deployTrigger;
    let deployRowID;

    document.body.addEventListener("htmx:beforeRequest", (event) => {
      const element = event.detail.elt;
      if (element.getAttribute("aria-controls") === "certificate-deploy-dialog") {
        deployTrigger = element;
        deployRowID = element.closest("tr").id;
      }
    });

    deployDialog.addEventListener("close", () => {
      const row = document.getElementById(deployRowID);
      const target = deployTrigger && deployTrigger.isConnected && !deployTrigger.disabled
        ? deployTrigger
        : row && row.querySelector("a, button:not(:disabled)");
      if (target) {
        target.focus();
      }
    });

    document.body.addEventListener("htmx:afterSwap", (event) => {
      if (event.detail.target.id !== "certificate-deploy-content") {
        return;
      }
      const form = deployDialog.querySelector("[data-deploy-form]");
      if (form) {
        updateDeploySelection(form);
        if (!deployDialog.open) {
          deployDialog.showModal();
        }
      }
    });

    deployDialog.addEventListener("click", (event) => {
      const cancel = event.target.closest("[data-deploy-cancel]");
      if (cancel) {
        deployDialog.close();
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

    deployDialog.addEventListener("change", (event) => {
      const form = event.target.closest("[data-deploy-form]");
      if (form) {
        updateDeploySelection(form);
      }
    });

    deployDialog.addEventListener("htmx:beforeRequest", (event) => {
      const form = event.detail.elt;
      if (!form.matches("[data-deploy-form]")) {
        return;
      }
      if (!form.querySelector('input[name="agents"]:checked:not(:disabled)')) {
        event.preventDefault();
        updateDeploySelection(form);
        return;
      }
      form.dataset.submitting = "true";
      form.querySelector("[data-deploy-submit]").textContent = "正在提交…";
      updateDeploySelection(form);
    });

    deployDialog.addEventListener("htmx:afterRequest", (event) => {
      const form = event.detail.elt;
      if (!form.matches("[data-deploy-form]")) {
        return;
      }
      delete form.dataset.submitting;
      form.querySelector("[data-deploy-submit]").textContent = "确认下发";
      const selected = form.querySelector('input[name="agents"]:checked:not(:disabled)');
      form.querySelector("[data-deploy-submit]").disabled = !selected;
      if (event.detail.successful) {
        deployDialog.close();
      } else if (deployDialog.open) {
        form.querySelector("[data-deploy-submit]").focus();
      }
    });
  }

  document.body.addEventListener("showToast", (event) => {
    const detail = event.detail || {};
    showToast(detail.message, detail.type);
  });

  document.body.addEventListener("htmx:responseError", (event) => {
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
    document.body.addEventListener(eventName, (event) => {
      showRequestError(event, "网络连接失败，请稍后重试");
    });
  });
})();
