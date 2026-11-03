(() => {
  const field = document.getElementById("browser-metadata");
  if (!field) return;
  try {
    field.value = JSON.stringify({
      platform: navigator.platform || "",
      language: navigator.language || "",
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      cores: navigator.hardwareConcurrency || 0,
      touch: navigator.maxTouchPoints || 0,
    });
  } catch (_) {
    // Login remains usable when environment information is unavailable.
  }
})();
