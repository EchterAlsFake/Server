(() => {
    "use strict";

    const THEME_KEY = "vplan-theme";
    const PREFERENCES_KEY = "vplan-preferences";
    const root = document.documentElement;

    const safeStorage = {
        get(key) {
            try {
                return localStorage.getItem(key);
            } catch (error) {
                return null;
            }
        },
        set(key, value) {
            try {
                localStorage.setItem(key, value);
                return true;
            } catch (error) {
                return false;
            }
        },
        remove(key) {
            try {
                localStorage.removeItem(key);
            } catch (error) {
                // The UI still resets for this page when storage is unavailable.
            }
        },
    };

    const themeToggle = document.querySelector("[data-theme-toggle]");
    const themeColor = document.querySelector('meta[name="theme-color"]');

    const updateThemeControls = () => {
        const isDark = root.dataset.theme === "dark";
        if (themeToggle) {
            themeToggle.setAttribute("aria-label", isDark ? "Hellmodus aktivieren" : "Dunkelmodus aktivieren");
        }
        if (themeColor) themeColor.content = isDark ? "#0c111d" : "#f5f7fb";
    };

    updateThemeControls();
    themeToggle?.addEventListener("click", () => {
        const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
        root.dataset.theme = nextTheme;
        safeStorage.set(THEME_KEY, nextTheme);
        updateThemeControls();
    });

    const disclaimerDialog = document.querySelector("[data-disclaimer-dialog]");
    const disclaimerForm = document.querySelector("[data-disclaimer-form]");
    const disclaimerCheckbox = document.querySelector("[data-disclaimer-checkbox]");
    const disclaimerSubmit = document.querySelector("[data-disclaimer-submit]");

    if (disclaimerDialog) {
        if (disclaimerDialog.open) disclaimerDialog.close();
        disclaimerDialog.showModal();
        disclaimerDialog.addEventListener("cancel", (event) => event.preventDefault());
    }

    disclaimerCheckbox?.addEventListener("change", () => {
        disclaimerSubmit.disabled = !disclaimerCheckbox.checked;
    });

    disclaimerForm?.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!disclaimerCheckbox?.checked) return;
        disclaimerDialog?.close();
        document.body.classList.remove("disclaimer-pending");
        document.querySelector("#plan-content")?.focus({ preventScroll: true });
    });

    const tabs = Array.from(document.querySelectorAll("[data-day-target]"));
    const panels = Array.from(document.querySelectorAll(".day-panel"));

    const activateTab = (tab, moveFocus = false) => {
        const targetId = tab.dataset.dayTarget;

        tabs.forEach((candidate) => {
            const isActive = candidate === tab;
            candidate.classList.toggle("is-active", isActive);
            candidate.setAttribute("aria-selected", String(isActive));
            candidate.tabIndex = isActive ? 0 : -1;
        });

        panels.forEach((panel) => {
            const isActive = panel.id === targetId;
            panel.hidden = !isActive;
            panel.classList.toggle("is-active", isActive);
        });

        tab.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
        if (moveFocus) tab.focus();
    };

    tabs.forEach((tab, index) => {
        tab.addEventListener("click", () => activateTab(tab));
        tab.addEventListener("keydown", (event) => {
            let nextIndex;
            if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
            if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
            if (event.key === "Home") nextIndex = 0;
            if (event.key === "End") nextIndex = tabs.length - 1;
            if (nextIndex === undefined) return;

            event.preventDefault();
            activateTab(tabs[nextIndex], true);
        });
    });

    const defaultPreferences = () => ({
        enabled: false,
        grade: "",
        classLetter: "",
        courses: [],
    });

    const loadPreferences = () => {
        const rawPreferences = safeStorage.get(PREFERENCES_KEY);
        if (!rawPreferences) return defaultPreferences();

        try {
            const saved = JSON.parse(rawPreferences);
            return {
                enabled: saved.enabled === true,
                grade: /^(0[5-9]|1[0-2])$/.test(saved.grade) ? saved.grade : "",
                classLetter: /^[a-z]$/i.test(saved.classLetter) ? saved.classLetter.toLowerCase() : "",
                courses: Array.isArray(saved.courses)
                    ? [...new Set(saved.courses.filter((course) => typeof course === "string" && course.trim()).map((course) => course.trim()))]
                    : [],
            };
        } catch (error) {
            return defaultPreferences();
        }
    };

    let preferences = loadPreferences();
    const normalize = (value) => String(value || "").toLocaleLowerCase("de-DE").trim();
    const allPlanCodes = [...new Set(
        Array.from(document.querySelectorAll("[data-plan-code]"))
            .map((entry) => entry.dataset.planCode?.trim())
            .filter(Boolean),
    )].sort((first, second) => first.localeCompare(second, "de", { numeric: true }));

    const extractGrade = (code) => {
        const match = String(code || "").match(/^(0?[5-9]|1[0-2])/);
        if (!match) return "";
        return String(Number(match[1])).padStart(2, "0");
    };

    const isBaseClass = (code, grade) => {
        const gradeNumber = String(Number(grade));
        return new RegExp(`^0?${gradeNumber}[a-z]$`, "i").test(code);
    };

    const matchesPersonalPlan = (code) => {
        if (!preferences.enabled) return true;
        if (extractGrade(code) !== preferences.grade) return false;

        const normalizedCode = normalize(code);
        const selectedCourses = new Set(preferences.courses.map(normalize));
        if (Number(preferences.grade) <= 10) {
            const selectedClass = `${Number(preferences.grade)}${preferences.classLetter}`;
            const matchesClass = normalize(code).replace(/^0/, "") === normalize(selectedClass);
            return matchesClass || selectedCourses.has(normalizedCode);
        }

        return selectedCourses.has(normalizedCode);
    };

    const filterControllers = [];
    document.querySelectorAll(".changes").forEach((section) => {
        const search = section.querySelector("[data-plan-search]");
        const entries = Array.from(section.querySelectorAll("[data-plan-entry]"));
        const filterButtons = Array.from(section.querySelectorAll("[data-filter]"));
        const resultCount = section.querySelector("[data-result-count]");
        const noResults = section.querySelector("[data-no-results]");
        let activeFilter = "all";

        const updateResults = () => {
            const query = normalize(search?.value);
            let visibleCount = 0;

            entries.forEach((entry) => {
                const matchesText = !query || normalize(entry.textContent).includes(query);
                const matchesStatus = activeFilter === "all" || entry.dataset.status === activeFilter;
                const matchesPersonal = matchesPersonalPlan(entry.dataset.planCode);
                const isVisible = matchesText && matchesStatus && matchesPersonal;
                entry.hidden = !isVisible;
                if (isVisible) visibleCount += 1;
            });

            if (resultCount) {
                resultCount.textContent = `${visibleCount} ${visibleCount === 1 ? "Eintrag" : "Einträge"}`;
            }
            if (noResults) noResults.hidden = visibleCount !== 0 || entries.length === 0;
        };

        search?.addEventListener("input", updateResults);
        filterButtons.forEach((button) => {
            button.addEventListener("click", () => {
                activeFilter = button.dataset.filter;
                filterButtons.forEach((candidate) => {
                    const isActive = candidate === button;
                    candidate.classList.toggle("is-active", isActive);
                    candidate.setAttribute("aria-pressed", String(isActive));
                });
                updateResults();
            });
        });

        filterControllers.push(updateResults);
    });

    const settingsDialog = document.querySelector("[data-settings-dialog]");
    const settingsForm = document.querySelector("[data-settings-form]");
    const settingsOpen = document.querySelector("[data-personalization-open]");
    const settingsCloseButtons = document.querySelectorAll("[data-settings-close]");
    const settingsReset = document.querySelector("[data-settings-reset]");
    const enabledInput = document.querySelector("[data-preference-enabled]");
    const gradeSelect = document.querySelector("[data-grade-select]");
    const classField = document.querySelector("[data-class-field]");
    const classLetterSelect = document.querySelector("[data-class-letter]");
    const courseSettings = document.querySelector("[data-course-settings]");
    const courseOptions = document.querySelector("[data-course-options]");
    const courseEmpty = document.querySelector("[data-course-empty]");
    const courseHelp = document.querySelector("[data-course-help]");
    const customCourses = document.querySelector("[data-custom-courses]");
    const settingsError = document.querySelector("[data-settings-error]");
    const personalizationSummary = document.querySelector("[data-personalization-summary]");

    const courseName = (code) => {
        const normalizedCode = normalize(code);
        const subjects = [
            ["frz", "Französisch"], ["lat", "Latein"], ["krel", "Katholische Religion"],
            ["erel", "Evangelische Religion"], ["mat", "Mathematik"], ["deu", "Deutsch"],
            ["eng", "Englisch"], ["che", "Chemie"], ["phy", "Physik"],
            ["bio", "Biologie"], ["mus", "Musik"], ["ges", "Geschichte"],
            ["geo", "Geografie"], ["spo", "Sport"], ["kar", "Religion"], ["gw", "GW"],
        ];
        return subjects.find(([key]) => normalizedCode.includes(key))?.[1] || "Kurs";
    };

    const renderCourseOptions = () => {
        if (!courseOptions || !gradeSelect) return;
        const grade = gradeSelect.value;
        const currentlySelected = new Set(preferences.courses.map(normalize));
        const discovered = allPlanCodes.filter((code) => extractGrade(code) === grade && !isBaseClass(code, grade));
        const savedForGrade = preferences.courses.filter((code) => extractGrade(code) === grade);
        const availableCourses = [...new Set([...discovered, ...savedForGrade])]
            .sort((first, second) => first.localeCompare(second, "de", { numeric: true }));

        courseOptions.replaceChildren();
        availableCourses.forEach((code) => {
            const label = document.createElement("label");
            label.className = "course-option";

            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.value = code;
            checkbox.checked = currentlySelected.has(normalize(code));
            checkbox.dataset.courseChoice = "";

            const text = document.createElement("span");
            text.textContent = courseName(code);
            const identifier = document.createElement("code");
            identifier.textContent = code;
            text.append(identifier);

            label.append(checkbox, text);
            courseOptions.append(label);
        });

        if (courseEmpty) courseEmpty.hidden = availableCourses.length !== 0;
    };

    const updateSettingsVisibility = () => {
        if (!gradeSelect || !classField || !courseSettings) return;
        const grade = gradeSelect.value;
        const isLowerGrade = grade && Number(grade) <= 10;
        classField.hidden = !isLowerGrade;
        courseSettings.hidden = !grade;
        if (courseHelp) {
            courseHelp.textContent = isLowerGrade
                ? "Wähle z. B. nur Latein oder Französisch – nicht beides."
                : "Wähle alle Kurse, die du in der Oberstufe besuchst.";
        }
        renderCourseOptions();
    };

    const fillSettingsForm = () => {
        if (!enabledInput || !gradeSelect || !classLetterSelect || !customCourses) return;
        enabledInput.checked = preferences.enabled;
        gradeSelect.value = preferences.grade;
        classLetterSelect.value = preferences.classLetter;
        customCourses.value = "";
        if (settingsError) settingsError.hidden = true;
        updateSettingsVisibility();
    };

    const updatePersonalizationSummary = () => {
        if (!personalizationSummary || !settingsOpen) return;
        if (!preferences.grade) {
            personalizationSummary.textContent = "Optional: Klasse und Kurse auswählen";
            settingsOpen.textContent = "Einrichten";
            return;
        }

        const gradeLabel = Number(preferences.grade) <= 10
            ? `Klasse ${Number(preferences.grade)}${preferences.classLetter}`
            : `Jahrgang ${Number(preferences.grade)}`;
        const courseLabel = `${preferences.courses.length} ${preferences.courses.length === 1 ? "Kurs" : "Kurse"}`;
        personalizationSummary.textContent = `${preferences.enabled ? "Aktiv" : "Pausiert"} · ${gradeLabel} · ${courseLabel}`;
        settingsOpen.textContent = "Bearbeiten";
    };

    const applyPreferences = () => {
        updatePersonalizationSummary();
        filterControllers.forEach((updateResults) => updateResults());
    };

    gradeSelect?.addEventListener("change", updateSettingsVisibility);
    settingsOpen?.addEventListener("click", () => {
        fillSettingsForm();
        settingsDialog?.showModal();
    });
    settingsCloseButtons.forEach((button) => button.addEventListener("click", () => settingsDialog?.close()));

    settingsForm?.addEventListener("submit", (event) => {
        event.preventDefault();
        const grade = gradeSelect?.value || "";
        const classLetter = classLetterSelect?.value || "";
        const selectedCourses = Array.from(document.querySelectorAll("[data-course-choice]:checked"))
            .map((input) => input.value);
        const additionalCourses = (customCourses?.value || "")
            .split(",")
            .map((course) => course.trim())
            .filter(Boolean);
        const courses = [...new Set([...selectedCourses, ...additionalCourses])];
        const enabled = enabledInput?.checked === true;

        let errorMessage = "";
        if (enabled && !grade) errorMessage = "Bitte wähle deinen Jahrgang aus.";
        if (enabled && grade && Number(grade) <= 10 && !classLetter) errorMessage = "Bitte wähle deine Klasse aus.";
        if (enabled && grade && Number(grade) >= 11 && courses.length === 0) errorMessage = "Bitte wähle mindestens einen Oberstufenkurs aus.";

        if (errorMessage) {
            settingsError.textContent = errorMessage;
            settingsError.hidden = false;
            return;
        }

        preferences = { enabled, grade, classLetter, courses };
        safeStorage.set(PREFERENCES_KEY, JSON.stringify(preferences));
        settingsDialog?.close();
        applyPreferences();
    });

    settingsReset?.addEventListener("click", () => {
        preferences = defaultPreferences();
        safeStorage.remove(PREFERENCES_KEY);
        fillSettingsForm();
        settingsDialog?.close();
        applyPreferences();
    });

    document.querySelectorAll("[data-info-open]").forEach((button) => {
        button.addEventListener("click", () => {
            const dialog = document.getElementById(button.dataset.infoOpen || "");
            if (dialog instanceof HTMLDialogElement && !dialog.open) dialog.showModal();
        });
    });

    document.querySelectorAll("[data-info-dialog]").forEach((dialog) => {
        dialog.querySelectorAll("[data-info-close]").forEach((button) => {
            button.addEventListener("click", () => dialog.close());
        });
    });

    applyPreferences();
})();
