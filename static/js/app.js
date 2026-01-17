document.addEventListener("DOMContentLoaded", () => {
  // ========================================
  // DARK MODE FUNCTIONALITY
  // ========================================

  // Initialize dark mode from localStorage or system preference
  function initTheme() {
    const savedTheme = localStorage.getItem("theme");
    const systemPrefersDark = window.matchMedia(
      "(prefers-color-scheme: dark)"
    ).matches;
    const theme = savedTheme || (systemPrefersDark ? "dark" : "light");

    document.documentElement.setAttribute("data-theme", theme);
    updateThemeIcon();
  }

  // Update theme icon in popup
  function updateThemeIcon() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const lightIcon = document.querySelector('[data-theme-icon="light"]');
    const darkIcon = document.querySelector('[data-theme-icon="dark"]');
    const themeLabel = document.getElementById("theme-label");

    if (lightIcon && darkIcon) {
      if (currentTheme === "dark") {
        lightIcon.style.display = "none";
        darkIcon.style.display = "inline";
        if (themeLabel) themeLabel.textContent = "Light Mode";
      } else {
        lightIcon.style.display = "inline";
        darkIcon.style.display = "none";
        if (themeLabel) themeLabel.textContent = "Dark Mode";
      }
    }
  }

  // Toggle theme and persist to localStorage
  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";

    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
    updateThemeIcon();
  }

  // Initialize theme on page load
  initTheme();

  // Listen for system theme changes
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener("change", (e) => {
      // Only auto-switch if user hasn't manually set a preference
      if (!localStorage.getItem("theme")) {
        document.documentElement.setAttribute(
          "data-theme",
          e.matches ? "dark" : "light"
        );
      }
    });

  // ========================================
  // SETTINGS POPUP FUNCTIONALITY
  // ========================================

  const settingsFab = document.querySelector(".settings-fab");
  const settingsPopup = document.querySelector(".settings-popup");
  const themeSwitch = document.querySelector(".theme-switch");

  // Toggle settings popup
  if (settingsFab && settingsPopup) {
    settingsFab.addEventListener("click", (e) => {
      e.stopPropagation();
      settingsPopup.classList.toggle("show");
      settingsFab.classList.toggle("active");
    });

    // Close popup when clicking outside
    document.addEventListener("click", (e) => {
      if (
        !settingsPopup.contains(e.target) &&
        !settingsFab.contains(e.target)
      ) {
        settingsPopup.classList.remove("show");
        settingsFab.classList.remove("active");
      }
    });

    // Prevent popup from closing when clicking inside it
    settingsPopup.addEventListener("click", (e) => {
      e.stopPropagation();
    });
  }

  // Theme toggle in popup
  if (themeSwitch) {
    themeSwitch.addEventListener("click", toggleTheme);

    // Keyboard accessibility
    themeSwitch.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleTheme();
      }
    });
  }

  // Add click handler for old theme toggle button (backward compatibility)
  const themeToggle = document.querySelector(".theme-toggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme);

    // Add keyboard accessibility
    themeToggle.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleTheme();
      }
    });
  }

  // ========================================
  // EXISTING FUNCTIONALITY
  // ========================================

  // attach the decor image if provided (unchanged)
  const hero = document.querySelector(".hero");
  if (hero) {
    const src = hero.getAttribute("data-decor-src");
    if (src) {
      const img = document.createElement("img");
      img.src = src;
      img.alt = "";
      img.className = "decor";
      img.loading = "lazy";
      hero.appendChild(img);
    }
  }

  const form = document.getElementById("intake");
  const submitBtn = document.getElementById("submitBtn");
  const spinner = document.getElementById("btnSpinner");
  const label = document.getElementById("btnLabel");
  const errorArea = document.getElementById("errorArea");
  const patientSummaryContainer = document.getElementById(
    "patientSummaryContainer"
  );
  const aiResultContainer = document.getElementById("aiResultContainer");

  // helper to toggle submit UI
  function setLoading(isLoading) {
    if (!submitBtn) return;
    submitBtn.disabled = isLoading;
    if (isLoading) {
      spinner.classList.remove("d-none");
      label.textContent = "Analyzing...";
    } else {
      spinner.classList.add("d-none");
      label.innerHTML =
        '<i class="fas fa-stethoscope me-2"></i>Analyze & Generate Plan';
    }
  }

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault(); // prevent normal POST form reload
      errorArea.innerHTML = ""; // clear any previous
      setLoading(true);

      // build FormData
      const fd = new FormData(form);

      try {
        // send AJAX request - server will return JSON on XHR
        const res = await fetch("/diagnose", {
          method: "POST",
          headers: {
            "X-Requested-With": "XMLHttpRequest",
            Accept: "application/json",
          },
          body: fd,
        });

        if (!res.ok) {
          const txt = await res.text();
          throw new Error(res.status + " — " + (txt || res.statusText));
        }

        const payload = await res.json();

        if (payload.error) {
          errorArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>${payload.error}</div>`;
          setLoading(false);
          return;
        }

        // inject patient summary and AI result (safe HTML from server)
        if (payload.patient_info) {
          patientSummaryContainer.innerHTML = `<div class="result-box mb-4"><h5 class="mb-2 text-muted"><i class="fas fa-user"></i> Patient Summary</h5><hr>${payload.patient_info}</div>`;
        } else {
          patientSummaryContainer.innerHTML = "";
        }

        if (payload.result) {
          aiResultContainer.innerHTML = `<div class="result-box"><h5 class="mb-2"><i class="fas fa-file-medical-alt me-2 text-primary"></i> AI Assessment & Plan</h5><hr>${payload.result}<div class="mt-3 text-end"><button onclick="window.print()" class="btn btn-outline-secondary btn-sm"><i class="fas fa-print me-2"></i>Print</button><a href="/" class="btn btn-outline-primary btn-sm ms-2">New Consultation</a></div></div>`;
        } else {
          aiResultContainer.innerHTML = `<div class="result-box small-muted">No plan returned.</div>`;
        }

        // smooth scroll to the results section below the form
        if (aiResultContainer)
          aiResultContainer.scrollIntoView({
            behavior: "smooth",
            block: "start",
          });
      } catch (err) {
        const msg = err && err.message ? err.message : "Unknown error";
        errorArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Request failed — ${msg}</div>`;
      } finally {
        setLoading(false);
      }
    });
  }

  // allow graceful re-enable if ajax hangs
  window.addEventListener("pagehide", () => {
    if (submitBtn) submitBtn.disabled = false;
  });
});
