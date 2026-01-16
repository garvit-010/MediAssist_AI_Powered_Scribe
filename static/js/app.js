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

  const form = document.getElementById("intakeForm");
  const submitBtn = document.getElementById("submitBtn");
  const btnIcon = document.getElementById("btnIcon");
  const spinner = document.getElementById("btnSpinner");
  const label = document.getElementById("btnLabel");

  // helper to toggle submit UI
  function setLoading(isLoading) {
    if (!submitBtn) return;
    submitBtn.disabled = isLoading;
    if (isLoading) {
      if (spinner) spinner.classList.remove("d-none");
      if (btnIcon) btnIcon.classList.add("d-none");
      if (label) label.textContent = "Processing...";
    } else {
      if (spinner) spinner.classList.add("d-none");
      if (btnIcon) btnIcon.classList.remove("d-none");
      if (label) label.textContent = "Generate Analysis";
    }
  }

  if (form) {
    form.addEventListener("submit", (e) => {
      // Allow the form to submit normally to /patient/submit
      // But show the loading state for better UX
      setLoading(true);
    });
  }

  // allow graceful re-enable if ajax hangs
  window.addEventListener("pagehide", () => {
    if (submitBtn) submitBtn.disabled = false;
  });
});
