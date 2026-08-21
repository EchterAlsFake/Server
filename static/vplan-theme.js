(() => {
    "use strict";

    const DEFAULT_THEME = "dark";
    const ALLOWED_THEMES = new Set(["dark", "light"]);

    try {
        const savedTheme = localStorage.getItem("vplan-theme");
        document.documentElement.dataset.theme = ALLOWED_THEMES.has(savedTheme)
            ? savedTheme
            : DEFAULT_THEME;
    } catch (error) {
        document.documentElement.dataset.theme = DEFAULT_THEME;
    }

    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) {
        themeColor.content = document.documentElement.dataset.theme === "dark"
            ? "#0c111d"
            : "#f5f7fb";
    }
})();
