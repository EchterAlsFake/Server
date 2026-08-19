(() => {
    "use strict";

    const THEME_KEY = "vplan-theme";
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
        if (safeStorage.get(DISCLAIMER_ACCEPTED_KEY) === "true") {
            if (disclaimerDialog.open) disclaimerDialog.close();
            document.body.classList.remove("disclaimer-pending");
        } else {
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
        safeStorage.set(DISCLAIMER_ACCEPTED_KEY, "true");
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

    const loadSubjectOverrides = () => {
        const rawOverrides = safeStorage.get(SUBJECT_OVERRIDES_KEY);
        if (!rawOverrides) return {};

        try {
            const saved = JSON.parse(rawOverrides);
            if (!saved || typeof saved !== "object" || Array.isArray(saved)) return {};

            return Object.fromEntries(
                Object.entries(saved)
                    .filter(([, value]) => value && typeof value === "object" && typeof value.name === "string" && value.name.trim())
                    .map(([code, value]) => [
                        normalize(code),
                        {
                            name: value.name.trim().slice(0, 60),
                            teacher: typeof value.teacher === "string" ? value.teacher.trim().slice(0, 60) : "",
                        },
                    ])
                    .filter(([code]) => code),
            );
        } catch (error) {
            return {};
        }
    };

    let subjectOverrides = loadSubjectOverrides();
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
                const searchableText = `${entry.textContent} ${entry.dataset.planCode || ""}`;
                const matchesText = !query || normalize(searchableText).includes(query);
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

    const subjects = [
        { id: "frz", name: "Französisch", code: "frz", pattern: /\b(?:frz|französisch)\b/i },
        { id: "lat", name: "Latein", code: "lat", pattern: /\b(?:lat|latein)\b/i },
        { id: "krel", name: "Katholische Religion", code: "krel", pattern: /\b(?:krel|kath(?:olische)?\s+religion)\b/i },
        { id: "erel", name: "Evangelische Religion", code: "erel", pattern: /\b(?:erel|ev(?:angelische)?\s+religion)\b/i },
        { id: "mat", name: "Mathematik", code: "mat", pattern: /\b(?:ma|mat|mathe|mathematik)\b/i },
        { id: "deu", name: "Deutsch", code: "deu", pattern: /\b(?:deu|deutsch)\b/i },
        { id: "eng", name: "Englisch", code: "eng", pattern: /\b(?:eng|englisch)\b/i },
        { id: "che", name: "Chemie", code: "che", pattern: /\b(?:che|chemie)\b/i },
        { id: "phy", name: "Physik", code: "phy", pattern: /\b(?:phy|physik)\b/i },
        { id: "bio", name: "Biologie", code: "bio", pattern: /\b(?:bio|biologie)\b/i },
        { id: "mus", name: "Musik", code: "mus", pattern: /\b(?:mu|mus|musik)\b/i },
        { id: "ges", name: "Geschichte", code: "ges", pattern: /\b(?:ges|gesch|geschichte)\b/i },
        { id: "geo", name: "Geografie", code: "geo", pattern: /\b(?:geo|geografie|geographie|erdkunde)\b/i },
        { id: "spo", name: "Sport", code: "spo", pattern: /\b(?:sp|spo|sport)\b/i },
        { id: "kun", name: "Kunst", code: "kun", pattern: /\b(?:ku|kun|kunst)\b/i },
        { id: "inf", name: "Informatik", code: "inf", pattern: /\b(?:inf|informatik)\b/i },
        { id: "eth", name: "Ethik", code: "eth", pattern: /\b(?:eth|ethik)\b/i },
        { id: "rel", name: "Religion", code: "kar", pattern: /\b(?:rel|religion)\b/i },
        { id: "gw", name: "GW", code: "gw", pattern: /\bgw\b/i },
    ];

    const courseName = (code) => {
        const normalizedCode = normalize(code);
        return subjects.find((subject) => normalizedCode.includes(subject.code))?.name || "Kurs";
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
        return detectedName === "Kurs" ? code : detectedName;
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
        return firstSegment || withoutStatus || "Fach";
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
    let activeSubjectKey = "";

    const updateSubjectEntries = () => {
        document.querySelectorAll("[data-plan-entry]").forEach((entry) => {
            const subject = entrySubjectDetails(entry);
            const override = subjectOverrideFor(subject.key);
            const name = entry.querySelector("[data-subject-name]");
            const editButton = entry.querySelector("[data-subject-edit]");
            const teacherRow = entry.querySelector("[data-subject-teacher-row]");
            const teacher = entry.querySelector("[data-subject-teacher]");

            if (name) {
                name.textContent = override?.name || subject.code || "–";
                name.classList.toggle("is-customized", Boolean(override));
                name.title = override ? `Original: ${subject.label}` : "";
            }

            if (editButton) {
                const editable = isEditableSubject(subject.code);
                editButton.hidden = !editable;
                editButton.setAttribute("aria-label", `${override?.name || subject.name} umbenennen`);
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

        if (!name) {
            if (subjectError) {
                subjectError.textContent = "Bitte gib einen neuen Namen für das Fach ein.";
                subjectError.hidden = false;
            }
            subjectNameInput?.focus();
            return;
        }

        const nextOverrides = {
            ...subjectOverrides,
            [normalize(activeSubjectKey)]: { name, teacher },
        };
        if (!safeStorage.set(SUBJECT_OVERRIDES_KEY, JSON.stringify(nextOverrides))) {
            if (subjectError) {
                subjectError.textContent = "Die Bezeichnung konnte in diesem Browser nicht gespeichert werden.";
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
                subjectError.textContent = "Die eigene Bezeichnung konnte nicht gelöscht werden.";
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
            personalizationSummary.textContent = "Klasse und Kurse auswählen";
            settingsOpen.title = "Persönlichen Plan einrichten";
            return;
        }

        const gradeLabel = Number(preferences.grade) <= 10
            ? `Klasse ${Number(preferences.grade)}${preferences.classLetter}`
            : `Jahrgang ${Number(preferences.grade)}`;
        const courseLabel = `${preferences.courses.length} ${preferences.courses.length === 1 ? "Kurs" : "Kurse"}`;
        personalizationSummary.textContent = `${preferences.enabled ? "Aktiv" : "Pausiert"} · ${gradeLabel} · ${courseLabel}`;
        settingsOpen.title = "Persönlichen Plan bearbeiten";
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
            return "Bitte verwende ausschließlich normalen Text ohne HTML.";
        }
        if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(message)
            || /(?:https?:\/\/|www\.)\S+/i.test(message)) {
            return "Bitte entferne E-Mail-Adressen und Links aus der Nachricht.";
        }

        const phoneCandidates = message.match(/\+?\d[\d\s()./-]{5,}\d/g) || [];
        if (phoneCandidates.some((candidate) => {
            const digits = candidate.replace(/\D/g, "");
            return digits.length >= 7
                && (/^[+0]/.test(candidate.trim()) || digits.length >= 10);
        })) {
            return "Bitte entferne Telefonnummern aus der Nachricht.";
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
            feedbackSubmit.textContent = "Nachricht senden";
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
                feedbackError.textContent = "Bitte beschreibe den Fehler mit mindestens 10 Zeichen.";
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
                feedbackError.textContent = "Bitte bestätige, dass deine Nachricht keine personenbezogenen Informationen enthält.";
                feedbackError.hidden = false;
            }
            feedbackPrivacy?.focus();
            return;
        }

        if (feedbackSubmit) {
            feedbackSubmit.disabled = true;
            feedbackSubmit.textContent = "Wird gesendet …";
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
            if (!response.ok) throw new Error(result.error || "Die Nachricht konnte nicht gespeichert werden.");

            if (feedbackSuccess) feedbackSuccess.hidden = false;
            if (feedbackMessage) feedbackMessage.disabled = true;
            if (feedbackPrivacy) feedbackPrivacy.disabled = true;
            if (feedbackSubmit) feedbackSubmit.textContent = "Gesendet";
        } catch (error) {
            if (feedbackError) {
                feedbackError.textContent = error instanceof Error
                    ? error.message
                    : "Die Nachricht konnte nicht gespeichert werden.";
                feedbackError.hidden = false;
            }
            if (feedbackSubmit) {
                feedbackSubmit.disabled = false;
                feedbackSubmit.textContent = "Erneut versuchen";
            }
        }
    });

    const pwaEnabled = document.body.dataset.pwaEnabled === "true";
    const installButtons = document.querySelectorAll("[data-install-app], [data-install-help]");
    const installLabel = document.querySelector("[data-install-label]");
    const installDescription = document.querySelector("[data-install-description]");
    const installDialog = document.querySelector("[data-install-dialog]");
    const installIntro = document.querySelector("[data-install-intro]");
    const installSteps = document.querySelector("[data-install-steps]");
    let installPrompt = null;

    const isStandalone = () => (
        window.matchMedia("(display-mode: standalone)").matches
        || window.navigator.standalone === true
    );
    const isIos = /iphone|ipad|ipod/i.test(window.navigator.userAgent)
        || (window.navigator.platform === "MacIntel" && window.navigator.maxTouchPoints > 1);

    const showInstalledState = () => {
        installButtons.forEach((button) => button.disabled = true);
        if (installLabel) installLabel.textContent = "App installiert";
        if (installDescription) installDescription.textContent = "Bereit im Startmenü";
    };

    const setInstallInstructions = () => {
        if (!installIntro || !installSteps) return;
        const instructions = isIos
            ? [
                "Tippe in Safari auf das Teilen-Symbol.",
                "Wähle „Zum Home-Bildschirm“.",
                "Bestätige oben rechts mit „Hinzufügen“.",
            ]
            : [
                "Öffne das Menü deines Browsers.",
                "Wähle „Vertretungsplan installieren“ oder „App installieren“.",
                "Bestätige die Installation.",
            ];

        installIntro.textContent = isIos
            ? "Auf iPhone und iPad wird die App direkt über Safari hinzugefügt:"
            : "Falls kein direkter Installationsdialog erscheint, füge die App über das Browsermenü hinzu:";
        installSteps.replaceChildren(...instructions.map((instruction) => {
            const item = document.createElement("li");
            item.textContent = instruction;
            return item;
        }));
    };

    const requestAppInstall = async () => {
        if (!installPrompt) {
            setInstallInstructions();
            installDialog?.showModal();
            return;
        }

        const prompt = installPrompt;
        installPrompt = null;
        try {
            await prompt.prompt();
            const choice = await prompt.userChoice;
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

    window.addEventListener("beforeinstallprompt", (event) => {
        if (!pwaEnabled) return;
        event.preventDefault();
        installPrompt = event;
    });
    window.addEventListener("appinstalled", () => {
        installPrompt = null;
        showInstalledState();
    });

    if (pwaEnabled && isStandalone()) {
        showInstalledState();
    }

    if (pwaEnabled && "serviceWorker" in navigator) {
        window.addEventListener("load", () => {
            navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {
                // Installation remains optional; the normal website still works.
            });
        });
    }

    updateSubjectEntries();
    applyPreferences();
})();
