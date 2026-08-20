(async () => {
    "use strict";

    const THEME_KEY = "vplan-theme";
    const LANGUAGE_KEY = "vplan-language";
    const DAY_ROLLOVER_HOUR = 15;
    const PREFERENCES_KEY = "vplan-preferences";
    const SUBJECT_OVERRIDES_KEY = "vplan-subject-overrides";
    const DISCLAIMER_ACCEPTED_KEY = "vplan-disclaimer-accepted-v1";
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
                return true;
            } catch (error) {
                // The UI still resets for this page when storage is unavailable.
                return false;
            }
        },
    };

    const fetchJson = async (url) => {
        const response = await fetch(url, {
            credentials: "omit",
            referrerPolicy: "no-referrer",
        });
        if (!response.ok) throw new Error(`Could not load ${url}`);
        return response.json();
    };

    const safeCatalog = (value) => {
        if (!value || typeof value !== "object" || Array.isArray(value)) return {};
        return Object.fromEntries(
            Object.entries(value).filter(([key, text]) => key !== "_meta" && typeof text === "string"),
        );
    };

    const interpolate = (template, variables = {}) => String(template).replace(
        /\{([A-Za-z][A-Za-z0-9_]*)\}/g,
        (match, name) => Object.prototype.hasOwnProperty.call(variables, name)
            ? String(variables[name])
            : match,
    );

    const defaultLanguages = [
        { code: "de", name: "Deutsch", status: "source", flag: "🇩🇪" },
        { code: "en", name: "English", status: "beta", flag: "🇬🇧" },
    ];
    let languageConfig = { default: "de", languages: defaultLanguages };
    try {
        const loadedConfig = await fetchJson("/static/i18n/languages.json");
        const languages = Array.isArray(loadedConfig.languages)
            ? loadedConfig.languages.filter((item) => (
                item && /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(item.code)
                && typeof item.name === "string"
                && typeof item.flag === "string"
                && item.flag.trim().length > 0
                && item.flag.length <= 12
            ))
            : [];
        if (languages.length) {
            languageConfig = {
                default: languages.some((item) => item.code === loadedConfig.default)
                    ? loadedConfig.default
                    : "de",
                languages,
            };
        }
    } catch (error) {
        // German HTML remains a complete fallback when static language files fail.
    }

    const supportedLanguageCodes = new Set(languageConfig.languages.map((item) => item.code));
    const browserLanguage = String(navigator.language || "").split("-")[0].toLowerCase();
    const storedLanguage = safeStorage.get(LANGUAGE_KEY);
    const activeLanguage = supportedLanguageCodes.has(storedLanguage)
        ? storedLanguage
        : (supportedLanguageCodes.has(browserLanguage) ? browserLanguage : languageConfig.default);

    let sourceCatalog = {};
    let activeCatalog = {};
    try {
        const sourcePayload = await fetchJson("/static/i18n/de.json");
        sourceCatalog = safeCatalog(sourcePayload);
        if (activeLanguage === "de") {
            activeCatalog = sourceCatalog;
        } else {
            activeCatalog = safeCatalog(await fetchJson(`/static/i18n/${encodeURIComponent(activeLanguage)}.json`));
        }
    } catch (error) {
        activeCatalog = sourceCatalog;
    }

    const t = (key, variables = {}, fallback = key) => interpolate(
        activeCatalog[key] || sourceCatalog[key] || fallback,
        variables,
    );
    const tp = (key, count, variables = {}, fallback = "") => t(
        `${key}.${Number(count) === 1 ? "one" : "other"}`,
        { ...variables, count },
        fallback,
    );
    const elementVariables = (element) => {
        if (!element.dataset.i18nVars) return {};
        try {
            const parsed = JSON.parse(element.dataset.i18nVars);
            return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
        } catch (error) {
            return {};
        }
    };
    const applyTranslations = (scope = document) => {
        scope.querySelectorAll("[data-i18n]").forEach((element) => {
            const variables = elementVariables(element);
            const count = Number(element.dataset.i18nCount);
            element.textContent = element.dataset.i18nPlural
                ? tp(element.dataset.i18n, count, variables, element.textContent.trim())
                : t(element.dataset.i18n, variables, element.textContent.trim());
        });
        const translatedAttributes = {
            "data-i18n-aria-label": "aria-label",
            "data-i18n-title": "title",
            "data-i18n-placeholder": "placeholder",
            "data-i18n-content": "content",
        };
        Object.entries(translatedAttributes).forEach(([selector, attribute]) => {
            scope.querySelectorAll(`[${selector}]`).forEach((element) => {
                const key = element.getAttribute(selector);
                element.setAttribute(attribute, t(key, elementVariables(element), element.getAttribute(attribute) || ""));
            });
        });
        scope.querySelectorAll("time[data-i18n-date][datetime]").forEach((element) => {
            const date = new Date(`${element.dateTime}T12:00:00`);
            if (!Number.isNaN(date.valueOf())) {
                element.textContent = new Intl.DateTimeFormat(activeLanguage, { dateStyle: "long" }).format(date);
            }
        });
    };

    document.documentElement.lang = activeLanguage;
    document.documentElement.dataset.language = activeLanguage;
    applyTranslations();
    document.querySelectorAll("time[data-vplan-updated][datetime]").forEach((element) => {
        const date = new Date(element.dateTime);
        if (!Number.isNaN(date.valueOf())) {
            element.textContent = new Intl.DateTimeFormat(activeLanguage, {
                dateStyle: "medium",
                timeStyle: "short",
            }).format(date);
        }
    });
    const storageNotice = document.querySelector("[data-storage-notice]");
    const showStorageNotice = () => {
        if (!storageNotice) return;
        storageNotice.hidden = false;
        window.setTimeout(() => {
            storageNotice.hidden = true;
        }, 6000);
    };
    const languageNotice = document.querySelector("[data-translation-notice]");
    if (languageNotice) languageNotice.hidden = activeLanguage === languageConfig.default;
    const languagePicker = document.querySelector("[data-language-picker]");
    if (languagePicker) {
        languagePicker.replaceChildren(...languageConfig.languages.map((language) => {
            const button = document.createElement("button");
            const label = language.status === "beta"
                ? t("language.beta_name", { name: language.name }, `${language.name} (Beta)`)
                : language.name;
            button.type = "button";
            button.className = "language-option";
            button.dataset.languageOption = language.code;
            button.setAttribute("aria-pressed", String(language.code === activeLanguage));
            button.setAttribute("aria-label", label);
            button.title = label;

            const flag = document.createElement("span");
            flag.className = "language-flag";
            flag.setAttribute("aria-hidden", "true");
            flag.textContent = language.flag;
            button.append(flag);

            button.addEventListener("click", () => {
                if (language.code === activeLanguage) return;
                if (!safeStorage.set(LANGUAGE_KEY, language.code)) {
                    showStorageNotice();
                    return;
                }
                window.location.reload();
            });
            return button;
        }));
    }
    window.vplanI18n = Object.freeze({
        language: activeLanguage,
        languages: languageConfig.languages,
        sourceCatalog,
        activeCatalog,
        t,
        plural: tp,
        apply: applyTranslations,
    });

    const themeToggle = document.querySelector("[data-theme-toggle]");
    const themeColor = document.querySelector('meta[name="theme-color"]');

    const updateThemeControls = () => {
        const isDark = root.dataset.theme === "dark";
        if (themeToggle) {
            themeToggle.setAttribute("aria-label", isDark
                ? t("theme.enable_light", {}, "Hellmodus aktivieren")
                : t("theme.enable_dark", {}, "Dunkelmodus aktivieren"));
        }
        if (themeColor) themeColor.content = isDark ? "#0c111d" : "#f5f7fb";
    };

    updateThemeControls();
    themeToggle?.addEventListener("click", () => {
        const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
        root.dataset.theme = nextTheme;
        if (!safeStorage.set(THEME_KEY, nextTheme)) showStorageNotice();
        updateThemeControls();
    });

    const disclaimerDialog = document.querySelector("[data-disclaimer-dialog]");
    const disclaimerForm = document.querySelector("[data-disclaimer-form]");
    const disclaimerCheckbox = document.querySelector("[data-disclaimer-checkbox]");
    const disclaimerSubmit = document.querySelector("[data-disclaimer-submit]");

    if (disclaimerDialog) {
        if (safeStorage.get(DISCLAIMER_ACCEPTED_KEY) === "true") {
            if (disclaimerDialog.open) disclaimerDialog.close();
            document.body.classList.remove("disclaimer-pending");
        } else {
            document.body.classList.add("disclaimer-pending");
            if (disclaimerDialog.open) disclaimerDialog.close();
            disclaimerDialog.showModal();
            disclaimerDialog.addEventListener("cancel", (event) => event.preventDefault());
        }
    }

    disclaimerCheckbox?.addEventListener("change", () => {
        disclaimerSubmit.disabled = !disclaimerCheckbox.checked;
    });

    disclaimerForm?.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!disclaimerCheckbox?.checked) return;
        if (!safeStorage.set(DISCLAIMER_ACCEPTED_KEY, "true")) showStorageNotice();
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

    const localDateTimestamp = (isoDate) => {
        const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(isoDate || ""));
        if (!match) return Number.NaN;

        const year = Number(match[1]);
        const monthIndex = Number(match[2]) - 1;
        const day = Number(match[3]);
        const date = new Date(year, monthIndex, day);
        return date.getFullYear() === year
            && date.getMonth() === monthIndex
            && date.getDate() === day
            ? date.getTime()
            : Number.NaN;
    };

    const selectInitialDayTab = (now = new Date()) => {
        const datedTabs = tabs.map((tab) => ({
            tab,
            timestamp: localDateTimestamp(tab.dataset.dayDate),
        })).filter(({ timestamp }) => Number.isFinite(timestamp))
            .sort((left, right) => left.timestamp - right.timestamp);
        if (!datedTabs.length) return;

        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
        const currentDay = datedTabs.find(({ timestamp }) => timestamp === today);
        const nextDay = datedTabs.find(({ timestamp }) => timestamp > today);
        const pastDays = datedTabs.filter(({ timestamp }) => timestamp < today);
        const latestPastDay = pastDays[pastDays.length - 1];
        const preferredDay = now.getHours() >= DAY_ROLLOVER_HOUR && nextDay
            ? nextDay
            : (currentDay || nextDay || latestPastDay);

        if (preferredDay) activateTab(preferredDay.tab);
    };

    selectInitialDayTab();

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
                classLetter: /^[abc]$/i.test(saved.classLetter) ? saved.classLetter.toLowerCase() : "",
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
    const SUBJECT_COLOR_IDS = Object.freeze([
        "violet", "blue", "cyan", "green", "lime", "amber", "orange", "pink",
    ]);
    const validSubjectColor = (value) => (
        typeof value === "string" && SUBJECT_COLOR_IDS.includes(value)
            ? value
            : ""
    );

    const loadSubjectOverrides = () => {
        const rawOverrides = safeStorage.get(SUBJECT_OVERRIDES_KEY);
        if (!rawOverrides) return {};

        try {
            const saved = JSON.parse(rawOverrides);
            if (!saved || typeof saved !== "object" || Array.isArray(saved)) return {};

            return Object.fromEntries(
                Object.entries(saved)
                    .filter(([, value]) => value && typeof value === "object")
                    .map(([code, value]) => {
                        const override = {
                            name: typeof value.name === "string" ? value.name.trim().slice(0, 60) : "",
                            teacher: typeof value.teacher === "string" ? value.teacher.trim().slice(0, 60) : "",
                            color: validSubjectColor(value.color),
                        };
                        return [normalize(code), override];
                    })
                    .filter(([code, value]) => code && (value.name || value.teacher || value.color)),
            );
        } catch (error) {
            return {};
        }
    };

    let subjectOverrides = loadSubjectOverrides();
    const allPlanCodes = [...new Set(
        Array.from(document.querySelectorAll("[data-plan-code], [data-learned-plan-code]"))
            .map((entry) => (entry.dataset.planCode || entry.dataset.learnedPlanCode)?.trim())
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
                const searchableText = `${entry.textContent} ${entry.dataset.planCode || ""}`;
                const matchesText = !query || normalize(searchableText).includes(query);
                const matchesStatus = activeFilter === "all" || entry.dataset.status === activeFilter;
                const matchesPersonal = matchesPersonalPlan(entry.dataset.planCode);
                const isVisible = matchesText && matchesStatus && matchesPersonal;
                entry.hidden = !isVisible;
                if (isVisible) visibleCount += 1;
            });

            if (resultCount) {
                resultCount.textContent = tp("plan.entry", visibleCount, {}, `${visibleCount} Einträge`);
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

    const subjects = [
        { id: "frz", name: t("course.frz", {}, "Französisch"), code: "frz", pattern: /\b(?:frz|französisch)\b/i },
        { id: "lat", name: t("course.lat", {}, "Latein"), code: "lat", pattern: /\b(?:lat|latein)\b/i },
        { id: "krel", name: t("course.krel", {}, "Katholische Religion"), aliases: ["krel", "katr"], pattern: /\b(?:krel|katr|kat\.?\s*r|kath(?:olische)?\s+religion)\b/i },
        { id: "erel", name: t("course.erel", {}, "Evangelische Religion"), aliases: ["erel", "evr"], pattern: /\b(?:erel|evr|ev\.?\s*r|ev(?:angelische)?\s+religion)\b/i },
        { id: "mat", name: t("course.mat", {}, "Mathematik"), code: "mat", pattern: /\b(?:ma|mat|mathe|mathematik)\b/i },
        { id: "deu", name: t("course.deu", {}, "Deutsch"), code: "deu", pattern: /\b(?:deu|deutsch)\b/i },
        { id: "eng", name: t("course.eng", {}, "Englisch"), code: "eng", pattern: /\b(?:eng|englisch)\b/i },
        { id: "che", name: t("course.che", {}, "Chemie"), code: "che", pattern: /\b(?:che|chemie)\b/i },
        { id: "phy", name: t("course.phy", {}, "Physik"), code: "phy", pattern: /\b(?:phy|physik)\b/i },
        { id: "bio", name: t("course.bio", {}, "Biologie"), code: "bio", pattern: /\b(?:bio|biologie)\b/i },
        { id: "mus", name: t("course.mus", {}, "Musik"), code: "mus", pattern: /\b(?:mu|mus|musik)\b/i },
        { id: "ges", name: t("course.ges", {}, "Geschichte"), code: "ges", pattern: /\b(?:ges|gesch|geschichte)\b/i },
        { id: "geo", name: t("course.geo", {}, "Geografie"), code: "geo", pattern: /\b(?:geo|geografie|geographie|erdkunde)\b/i },
        { id: "spo", name: t("course.spo", {}, "Sport"), code: "spo", pattern: /\b(?:sp|spo|sport)\b/i },
        { id: "kun", name: t("course.kun", {}, "Kunst"), code: "kun", pattern: /\b(?:ku|kun|kunst)\b/i },
        { id: "inf", name: t("course.inf", {}, "Informatik"), code: "inf", pattern: /\b(?:inf|informatik)\b/i },
        { id: "eth", name: t("course.eth", {}, "Ethik"), code: "eth", pattern: /\b(?:eth|ethik)\b/i },
        { id: "rel", name: t("course.rel", {}, "Religion"), code: "rel", pattern: /\b(?:rel|religion)\b/i },
        { id: "gw", name: t("course.gw", {}, "GW"), code: "gw", pattern: /\bgw\b/i },
    ];

    const genericCourseName = t("course.generic", {}, "Kurs");
    const courseName = (code) => {
        const normalizedCode = normalize(code);
        const courseTokens = normalizedCode.split(/[^a-zäöüß0-9]+/).filter(Boolean);
        return subjects.find((subject) => {
            const aliases = subject.aliases || [subject.code];
            return aliases.some((alias) => courseTokens.some(
                (token) => new RegExp(`^${alias}\\d*$`, "i").test(token),
            ));
        })?.name
            || genericCourseName;
    };

    const subjectOverrideFor = (storageKey) => {
        const normalizedKey = normalize(storageKey);
        return Object.prototype.hasOwnProperty.call(subjectOverrides, normalizedKey)
            ? subjectOverrides[normalizedKey]
            : undefined;
    };
    const subjectDisplayName = (code) => subjectOverrideFor(code)?.name || courseName(code);
    const originalSubjectName = (code) => {
        const detectedName = courseName(code);
        return detectedName === genericCourseName ? code : detectedName;
    };
    const isEditableSubject = (code) => Boolean(String(code || "").trim());

    const detectSubject = (description) => subjects
        .map((subject) => ({ subject, index: String(description || "").search(subject.pattern) }))
        .filter((match) => match.index >= 0)
        .sort((first, second) => first.index - second.index)[0]?.subject;

    const fallbackSubjectName = (description) => {
        const withoutStatus = String(description || "")
            .replace(/^\s*(?:ausfall|vertretung|änderung|raumänderung|entfall)\s*:?\s*/i, "")
            .trim();
        const firstSegment = withoutStatus
            .split(/\s+(?:bei|durch|in|statt|wird|entfällt)\b|[,;(]/i)[0]
            ?.trim();
        return firstSegment || withoutStatus || t("subject.generic", {}, "Fach");
    };

    const entrySubjectDetails = (entry) => {
        const code = entry?.dataset.planCode?.trim() || "";
        const grade = extractGrade(code);
        if (!grade || !isBaseClass(code, grade)) {
            return {
                code,
                key: normalize(code),
                name: originalSubjectName(code),
                label: code,
            };
        }

        const description = entry?.querySelector(".entry-description")?.textContent || "";
        const detectedSubject = detectSubject(description);
        const fallbackName = fallbackSubjectName(description);
        const fallbackId = normalize(fallbackName)
            .replace(/[^a-z0-9äöüß]+/g, "-")
            .replace(/^-|-$/g, "")
            .slice(0, 60) || "fach";
        const subjectId = detectedSubject?.id || fallbackId;
        const subjectName = detectedSubject?.name || fallbackName;

        return {
            code,
            key: `${normalize(code)}::${subjectId}`,
            name: subjectName,
            label: `${code} · ${subjectName}`,
        };
    };

    const subjectDialog = document.querySelector("[data-subject-dialog]");
    const subjectForm = document.querySelector("[data-subject-form]");
    const subjectNameInput = document.querySelector("[data-subject-new-name]");
    const subjectTeacherInput = document.querySelector("[data-subject-new-teacher]");
    const subjectOriginalName = document.querySelector("[data-subject-original-name]");
    const subjectOriginalCode = document.querySelector("[data-subject-original-code]");
    const subjectError = document.querySelector("[data-subject-error]");
    const subjectReset = document.querySelector("[data-subject-reset]");
    const subjectColorPreview = document.querySelector("[data-subject-color-preview]");
    const subjectColorChoices = Array.from(document.querySelectorAll("[data-subject-color-choice]"));
    let activeSubjectKey = "";

    const applySubjectColor = (element, color) => {
        if (!element) return;
        const validColor = validSubjectColor(color);
        if (validColor) {
            element.dataset.subjectAccent = validColor;
            return;
        }
        delete element.dataset.subjectAccent;
    };

    const selectedSubjectColor = () => validSubjectColor(
        subjectColorChoices.find((choice) => choice.checked)?.value,
    );

    const selectSubjectColor = (color) => {
        const validColor = validSubjectColor(color);
        subjectColorChoices.forEach((choice) => {
            choice.checked = choice.value === validColor;
        });
        applySubjectColor(subjectColorPreview, validColor);
    };

    subjectColorChoices.forEach((choice) => {
        choice.addEventListener("change", () => {
            if (choice.checked) applySubjectColor(subjectColorPreview, choice.value);
        });
    });

    const updateSubjectEntries = () => {
        document.querySelectorAll("[data-plan-entry]").forEach((entry) => {
            const subject = entrySubjectDetails(entry);
            const override = subjectOverrideFor(subject.key);
            const name = entry.querySelector("[data-subject-name]");
            const editButton = entry.querySelector("[data-subject-edit]");
            const teacherRow = entry.querySelector("[data-subject-teacher-row]");
            const teacher = entry.querySelector("[data-subject-teacher]");

            applySubjectColor(entry, override?.color);

            if (name) {
                name.textContent = override?.name || subject.code || "–";
                name.classList.toggle("is-customized", Boolean(override?.name));
                name.title = override?.name
                    ? t("entry.original", { name: subject.label }, `Original: ${subject.label}`)
                    : "";
            }

            if (editButton) {
                const editable = isEditableSubject(subject.code);
                editButton.hidden = !editable;
                const displayName = override?.name || subject.name;
                editButton.setAttribute(
                    "aria-label",
                    t("entry.adjust_named", { name: displayName }, `${displayName} anpassen`),
                );
            }

            if (teacher) teacher.textContent = override?.teacher || "";
            if (teacherRow) teacherRow.hidden = !override?.teacher;
        });
    };

    const openSubjectDialog = (entry) => {
        const subject = entrySubjectDetails(entry);
        if (!subjectDialog || !subjectNameInput || !subjectTeacherInput || !isEditableSubject(subject.code)) return;
        activeSubjectKey = subject.key;
        const override = subjectOverrideFor(activeSubjectKey);

        if (subjectOriginalName) subjectOriginalName.textContent = subject.name;
        if (subjectOriginalCode) subjectOriginalCode.textContent = subject.label;
        subjectNameInput.value = override?.name || "";
        subjectTeacherInput.value = override?.teacher || "";
        selectSubjectColor(override?.color || "");
        if (subjectReset) subjectReset.hidden = !override;
        if (subjectError) subjectError.hidden = true;

        subjectDialog.showModal();
        window.setTimeout(() => subjectNameInput.focus(), 0);
    };

    document.querySelectorAll("[data-subject-edit]").forEach((button) => {
        button.addEventListener("click", () => {
            const entry = button.closest("[data-plan-entry]");
            openSubjectDialog(entry);
        });
    });

    document.querySelectorAll("[data-subject-close]").forEach((button) => {
        button.addEventListener("click", () => subjectDialog?.close());
    });

    subjectForm?.addEventListener("submit", (event) => {
        event.preventDefault();
        const name = subjectNameInput?.value.trim() || "";
        const teacher = subjectTeacherInput?.value.trim() || "";
        const color = selectedSubjectColor();

        const nextOverrides = { ...subjectOverrides };
        if (name || teacher || color) {
            nextOverrides[normalize(activeSubjectKey)] = { name, teacher, color };
        } else {
            delete nextOverrides[normalize(activeSubjectKey)];
        }
        const stored = Object.keys(nextOverrides).length
            ? safeStorage.set(SUBJECT_OVERRIDES_KEY, JSON.stringify(nextOverrides))
            : safeStorage.remove(SUBJECT_OVERRIDES_KEY);
        if (!stored) {
            if (subjectError) {
                subjectError.textContent = t("subject.storage_error", {}, "Die Anpassung konnte in diesem Browser nicht gespeichert werden.");
                subjectError.hidden = false;
            }
            return;
        }

        subjectOverrides = nextOverrides;
        updateSubjectEntries();
        renderCourseOptions();
        filterControllers.forEach((updateResults) => updateResults());
        subjectDialog?.close();
    });

    subjectReset?.addEventListener("click", () => {
        const nextOverrides = { ...subjectOverrides };
        delete nextOverrides[normalize(activeSubjectKey)];
        const stored = Object.keys(nextOverrides).length
            ? safeStorage.set(SUBJECT_OVERRIDES_KEY, JSON.stringify(nextOverrides))
            : safeStorage.remove(SUBJECT_OVERRIDES_KEY);

        if (!stored) {
            if (subjectError) {
                subjectError.textContent = t("subject.delete_error", {}, "Die eigene Bezeichnung konnte nicht gelöscht werden.");
                subjectError.hidden = false;
            }
            return;
        }

        subjectOverrides = nextOverrides;
        updateSubjectEntries();
        renderCourseOptions();
        filterControllers.forEach((updateResults) => updateResults());
        subjectDialog?.close();
    });

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
            text.textContent = subjectDisplayName(code);
            const identifier = document.createElement("code");
            const teacher = subjectOverrideFor(code)?.teacher;
            identifier.textContent = teacher ? `${code} · ${teacher}` : code;
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
                ? t("settings.course_help_lower", {}, "Wähle z. B. nur Latein oder Französisch – nicht beides.")
                : t("settings.course_help_upper", {}, "Wähle alle Kurse, die du in der Oberstufe besuchst.");
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
            personalizationSummary.textContent = t("settings.summary.empty", {}, "Klasse und Kurse auswählen");
            settingsOpen.title = t("settings.setup", {}, "Persönlichen Plan einrichten");
            return;
        }

        const gradeLabel = Number(preferences.grade) <= 10
            ? t("settings.summary.class", {
                grade: Number(preferences.grade),
                letter: preferences.classLetter.toUpperCase(),
            }, `Klasse ${Number(preferences.grade)}${preferences.classLetter.toUpperCase()}`)
            : t("settings.summary.grade", { number: Number(preferences.grade) }, `Jahrgang ${Number(preferences.grade)}`);
        const courseLabel = tp("settings.course", preferences.courses.length, {}, `${preferences.courses.length} Kurse`);
        const stateLabel = preferences.enabled
            ? t("settings.summary.active", {}, "Aktiv")
            : t("settings.summary.paused", {}, "Pausiert");
        personalizationSummary.textContent = `${stateLabel} · ${gradeLabel} · ${courseLabel}`;
        settingsOpen.title = t("settings.edit", {}, "Persönlichen Plan bearbeiten");
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
        if (enabled && !grade) errorMessage = t("settings.error.grade", {}, "Bitte wähle deinen Jahrgang aus.");
        if (enabled && grade && Number(grade) <= 10 && !classLetter) errorMessage = t("settings.error.class", {}, "Bitte wähle deine Klasse aus.");
        if (enabled && grade && Number(grade) >= 11 && courses.length === 0) errorMessage = t("settings.error.course", {}, "Bitte wähle mindestens einen Oberstufenkurs aus.");

        if (errorMessage) {
            settingsError.textContent = errorMessage;
            settingsError.hidden = false;
            return;
        }

        const nextPreferences = { enabled, grade, classLetter, courses };
        if (!safeStorage.set(PREFERENCES_KEY, JSON.stringify(nextPreferences))) {
            settingsError.textContent = t("settings.error.storage", {}, "Die Auswahl konnte in diesem Browser nicht gespeichert werden.");
            settingsError.hidden = false;
            showStorageNotice();
            return;
        }
        preferences = nextPreferences;
        settingsDialog?.close();
        applyPreferences();
    });

    settingsReset?.addEventListener("click", () => {
        if (!safeStorage.remove(PREFERENCES_KEY)) {
            settingsError.textContent = t("settings.error.delete", {}, "Die gespeicherte Auswahl konnte nicht gelöscht werden.");
            settingsError.hidden = false;
            showStorageNotice();
            return;
        }
        preferences = defaultPreferences();
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

    const feedbackDialog = document.querySelector("[data-feedback-dialog]");
    const feedbackForm = document.querySelector("[data-feedback-form]");
    const feedbackMessage = document.querySelector("[data-feedback-message]");
    const feedbackPrivacy = document.querySelector("[data-feedback-privacy]");
    const feedbackCount = document.querySelector("[data-feedback-count]");
    const feedbackError = document.querySelector("[data-feedback-error]");
    const feedbackSuccess = document.querySelector("[data-feedback-success]");
    const feedbackSubmit = document.querySelector("[data-feedback-submit]");

    const feedbackContentError = (message) => {
        if (/<[^>\n]{1,100}>/.test(message)) {
            return t("feedback.error.html", {}, "Bitte verwende ausschließlich normalen Text ohne HTML.");
        }
        if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(message)
            || /(?:https?:\/\/|www\.)\S+/i.test(message)) {
            return t("feedback.error.contact", {}, "Bitte entferne E-Mail-Adressen und Links aus der Nachricht.");
        }

        const phoneCandidates = message.match(/\+?\d[\d\s()./-]{5,}\d/g) || [];
        if (phoneCandidates.some((candidate) => {
            const digits = candidate.replace(/\D/g, "");
            return digits.length >= 7
                && (/^[+0]/.test(candidate.trim()) || digits.length >= 10);
        })) {
            return t("feedback.error.phone", {}, "Bitte entferne Telefonnummern aus der Nachricht.");
        }
        return "";
    };

    const resetFeedbackForm = () => {
        feedbackForm?.reset();
        if (feedbackCount) feedbackCount.textContent = "0";
        if (feedbackError) feedbackError.hidden = true;
        if (feedbackSuccess) feedbackSuccess.hidden = true;
        if (feedbackMessage) feedbackMessage.disabled = false;
        if (feedbackPrivacy) feedbackPrivacy.disabled = false;
        if (feedbackSubmit) {
            feedbackSubmit.disabled = false;
            feedbackSubmit.textContent = t("feedback.send", {}, "Nachricht senden");
        }
    };

    document.querySelector("[data-feedback-open]")?.addEventListener("click", () => {
        resetFeedbackForm();
        feedbackDialog?.showModal();
        window.setTimeout(() => feedbackMessage?.focus(), 0);
    });
    document.querySelectorAll("[data-feedback-close]").forEach((button) => {
        button.addEventListener("click", () => feedbackDialog?.close());
    });
    feedbackMessage?.addEventListener("input", () => {
        if (feedbackCount) feedbackCount.textContent = String(feedbackMessage.value.length);
        if (feedbackError) feedbackError.hidden = true;
    });

    feedbackForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const message = feedbackMessage?.value.trim() || "";
        if (feedbackError) feedbackError.hidden = true;
        if (feedbackSuccess) feedbackSuccess.hidden = true;

        if (message.length < 10) {
            if (feedbackError) {
                feedbackError.textContent = t("feedback.error.too_short", {}, "Bitte beschreibe den Fehler mit mindestens 10 Zeichen.");
                feedbackError.hidden = false;
            }
            feedbackMessage?.focus();
            return;
        }
        const contentError = feedbackContentError(message);
        if (contentError) {
            if (feedbackError) {
                feedbackError.textContent = contentError;
                feedbackError.hidden = false;
            }
            feedbackMessage?.focus();
            return;
        }
        if (!feedbackPrivacy?.checked) {
            if (feedbackError) {
                feedbackError.textContent = t("feedback.error.confirm", {}, "Bitte bestätige, dass deine Nachricht keine personenbezogenen Informationen enthält.");
                feedbackError.hidden = false;
            }
            feedbackPrivacy?.focus();
            return;
        }

        if (feedbackSubmit) {
            feedbackSubmit.disabled = true;
            feedbackSubmit.textContent = t("feedback.sending", {}, "Wird gesendet …");
        }

        try {
            const response = await fetch("/vplan/feedback", {
                method: "POST",
                credentials: "omit",
                referrerPolicy: "no-referrer",
                headers: {
                    "Content-Type": "application/json",
                    "X-VPlan-Request": "feedback",
                },
                body: JSON.stringify({ message, privacy_confirmed: true }),
            });
            const result = await response.json().catch(() => ({}));
            if (!response.ok) {
                const errorMessages = {
                    invalid_request: t("feedback.error.invalid_request", {}, "Ungültige Anfrage."),
                    rate_limited: t("feedback.error.rate_limited", {}, "Zu viele Meldungen auf einmal. Bitte versuche es in einer Minute erneut."),
                    privacy_required: t("feedback.error.confirm", {}, "Bitte bestätige, dass deine Nachricht keine personenbezogenen Informationen enthält."),
                    text_required: t("feedback.error.text_required", {}, "Bitte gib eine Textnachricht ein."),
                    too_short: t("feedback.error.too_short", {}, "Bitte beschreibe den Fehler mit mindestens 10 Zeichen."),
                    too_long: t("feedback.error.too_long", {}, "Die Nachricht ist zu lang."),
                    control_characters: t("feedback.error.control", {}, "Die Nachricht enthält nicht unterstützte Zeichen."),
                    html: t("feedback.error.html", {}, "Bitte verwende ausschließlich normalen Text ohne HTML."),
                    contact: t("feedback.error.contact", {}, "Bitte entferne E-Mail-Adressen und Links aus der Nachricht."),
                    phone: t("feedback.error.phone", {}, "Bitte entferne Telefonnummern aus der Nachricht."),
                    storage_unavailable: t("feedback.error.save", {}, "Die Nachricht konnte nicht gespeichert werden."),
                };
                throw new Error(errorMessages[result.error] || t("feedback.error.save", {}, "Die Nachricht konnte nicht gespeichert werden."));
            }

            if (feedbackSuccess) feedbackSuccess.hidden = false;
            if (feedbackMessage) feedbackMessage.disabled = true;
            if (feedbackPrivacy) feedbackPrivacy.disabled = true;
            if (feedbackSubmit) feedbackSubmit.textContent = t("feedback.sent", {}, "Gesendet");
        } catch (error) {
            if (feedbackError) {
                feedbackError.textContent = error instanceof Error
                    ? error.message
                    : t("feedback.error.save", {}, "Die Nachricht konnte nicht gespeichert werden.");
                feedbackError.hidden = false;
            }
            if (feedbackSubmit) {
                feedbackSubmit.disabled = false;
                feedbackSubmit.textContent = t("feedback.retry", {}, "Erneut versuchen");
            }
        }
    });

    const pwaEnabled = window.vplanPwa?.enabled === true;
    const installButtons = document.querySelectorAll("[data-install-app], [data-install-help]");
    const installLabel = document.querySelector("[data-install-label]");
    const installDescription = document.querySelector("[data-install-description]");
    const installDialog = document.querySelector("[data-install-dialog]");
    const installIntro = document.querySelector("[data-install-intro]");
    const installSteps = document.querySelector("[data-install-steps]");
    const isIos = /iphone|ipad|ipod/i.test(window.navigator.userAgent)
        || (window.navigator.platform === "MacIntel" && window.navigator.maxTouchPoints > 1);

    const showInstalledState = () => {
        installButtons.forEach((button) => button.disabled = true);
        if (installLabel) installLabel.textContent = t("install.installed", {}, "App installiert");
        if (installDescription) installDescription.textContent = t("install.ready", {}, "Bereit im Startmenü");
    };

    const setInstallInstructions = () => {
        if (!installIntro || !installSteps) return;
        const instructions = isIos
            ? [
                t("install.ios_step_1", {}, "Tippe in Safari auf das Teilen-Symbol."),
                t("install.ios_step_2", {}, "Wähle „Zum Home-Bildschirm“."),
                t("install.ios_step_3", {}, "Bestätige oben rechts mit „Hinzufügen“."),
            ]
            : [
                t("install.browser_step_1", {}, "Öffne das Menü deines Browsers."),
                t("install.browser_step_2", {}, "Wähle „Vertretungsplan installieren“ oder „App installieren“."),
                t("install.browser_step_3", {}, "Bestätige die Installation."),
            ];

        installIntro.textContent = isIos
            ? t("install.ios_intro", {}, "Auf iPhone und iPad wird die App direkt über Safari hinzugefügt:")
            : t("install.fallback_intro", {}, "Falls kein direkter Installationsdialog erscheint, füge die App über das Browsermenü hinzu:");
        installSteps.replaceChildren(...instructions.map((instruction) => {
            const item = document.createElement("li");
            item.textContent = instruction;
            return item;
        }));
    };

    const requestAppInstall = async () => {
        const installPrompt = window.vplanPwa?.takeInstallPrompt() || null;
        if (!installPrompt) {
            setInstallInstructions();
            installDialog?.showModal();
            return;
        }

        try {
            await installPrompt.prompt();
            const choice = await installPrompt.userChoice;
            if (choice.outcome === "accepted") showInstalledState();
        } catch (error) {
            setInstallInstructions();
            installDialog?.showModal();
        }
    };

    installButtons.forEach((button) => {
        button.addEventListener("click", requestAppInstall);
    });
    document.querySelectorAll("[data-install-close]").forEach((button) => {
        button.addEventListener("click", () => installDialog?.close());
    });

    window.addEventListener("vplan-pwa-state-change", () => {
        if (!window.vplanPwa?.installPrompt) showInstalledState();
    });

    if (pwaEnabled && (window.vplanPwa?.installed || window.vplanPwa?.isStandalone())) {
        showInstalledState();
    }

    updateSubjectEntries();
    applyPreferences();
})();
