/**
 * Минимальный JS для dashboard: переключатель темы.
 * Вся вёрстка перенесена в Jinja-шаблоны, действия выполняются через form POST.
 */
(function () {
  const root = document.documentElement;
  const THEME_STORAGE_KEY = "theme";

  function updateThemeIcons(theme) {
    const toggle = document.getElementById("theme-toggle");
    if (!toggle) return;
    const darkIcon = toggle.querySelector('[data-theme-icon="dark"]');
    const lightIcon = toggle.querySelector('[data-theme-icon="light"]');
    if (darkIcon) darkIcon.classList.toggle("d-none", theme !== "dark");
    if (lightIcon) lightIcon.classList.toggle("d-none", theme !== "light");
  }

  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.onclick = function () {
      const now = root.getAttribute("data-bs-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-bs-theme", now);
      localStorage.setItem(THEME_STORAGE_KEY, now);
      updateThemeIcons(now);
    };
  }

  const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
  const initialTheme =
    storedTheme === "light" || storedTheme === "dark" ? storedTheme : "dark";
  root.setAttribute("data-bs-theme", initialTheme);
  updateThemeIcons(initialTheme);
})();
