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
    showToast(message, "error");
  });

  ["htmx:sendError", "htmx:timeout"].forEach((eventName) => {
    document.body.addEventListener(eventName, () => {
      showToast("网络连接失败，请稍后重试", "error");
    });
  });
})();
