(() => {
    "use strict";

    const sourceUrl = "/static/i18n/de.json";
    const languagesUrl = "/static/i18n/languages.json";
    const list = document.querySelector("[data-translation-list]");
    const template = document.querySelector("[data-translation-row-template]");
    const codeInput = document.querySelector("[data-language-code]");
    const nameInput = document.querySelector("[data-language-name]");
    const existingSelect = document.querySelector("[data-existing-language]");
    const searchInput = document.querySelector("[data-translation-search]");
    const missingOnly = document.querySelector("[data-missing-only]");
    const progress = document.querySelector("[data-progress]");
    const status = document.querySelector("[data-editor-status]");
    const emptyResult = document.querySelector("[data-empty-result]");
    let sourceCatalog = {};
    let uiCatalog = {};
    let translations = {};
    let languages = [];

    const fetchJson = async (url) => {
        const response = await fetch(url, {
            credentials: "omit",
            referrerPolicy: "no-referrer",
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
    };

    const catalogStrings = (payload) => {
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) return {};
        return Object.fromEntries(
            Object.entries(payload).filter(([key, value]) => key !== "_meta" && typeof value === "string"),
        );
    };

    const placeholders = (value) => [...String(value).matchAll(/\{[A-Za-z][A-Za-z0-9_]*\}/g)]
        .map((match) => match[0])
        .sort();

    const samePlaceholders = (source, translated) => (
        JSON.stringify(placeholders(source)) === JSON.stringify(placeholders(translated))
    );

    const interpolate = (templateValue, variables = {}) => String(templateValue).replace(
        /\{([A-Za-z][A-Za-z0-9_]*)\}/g,
        (match, name) => Object.prototype.hasOwnProperty.call(variables, name)
            ? String(variables[name])
            : match,
    );

    const t = (key, variables = {}, fallback = key) => interpolate(
        uiCatalog[key] || sourceCatalog[key] || fallback,
        variables,
    );

    const applyUiTranslations = () => {
        document.querySelectorAll("[data-i18n]").forEach((element) => {
            element.textContent = t(element.dataset.i18n, {}, element.textContent.trim());
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
            element.setAttribute(
                "placeholder",
                t(element.dataset.i18nPlaceholder, {}, element.getAttribute("placeholder") || ""),
            );
        });
    };

    const rowValidationError = (key, value) => {
        if (!value.trim()) return "";
        if (/<[^>\n]{1,200}>/.test(value)) {
            return t("translator.error.html", {}, "HTML ist in Übersetzungen nicht erlaubt.");
        }
        if (!samePlaceholders(sourceCatalog[key], value)) {
            return t("translator.error.placeholders", {
                placeholders: placeholders(sourceCatalog[key]).join(", ")
                    || t("translator.none", {}, "keine"),
            }, `Platzhalter müssen erhalten bleiben: ${placeholders(sourceCatalog[key]).join(", ") || "keine"}`);
        }
        return "";
    };

    const setStatus = (message, kind = "") => {
        if (!status) return;
        status.textContent = message;
        status.dataset.kind = kind;
    };

    const updateProgress = () => {
        const keys = Object.keys(sourceCatalog);
        const translated = keys.filter((key) => String(translations[key] || "").trim()).length;
        if (progress) {
            progress.textContent = t("translator.progress", {
                translated,
                total: keys.length,
            }, `${translated} von ${keys.length} Texten übersetzt`);
        }
    };

    const applyFilters = () => {
        const query = String(searchInput?.value || "").trim().toLocaleLowerCase("de-DE");
        let visible = 0;
        list?.querySelectorAll("[data-translation-key]").forEach((row) => {
            const key = row.dataset.translationKey;
            const missing = !String(translations[key] || "").trim();
            const haystack = `${key} ${sourceCatalog[key]}`.toLocaleLowerCase("de-DE");
            const matches = (!query || haystack.includes(query)) && (!missingOnly?.checked || missing);
            row.hidden = !matches;
            if (matches) visible += 1;
        });
        if (emptyResult) emptyResult.hidden = visible !== 0;
    };

    const validateRow = (row) => {
        const key = row.dataset.translationKey;
        const errorElement = row.querySelector("[data-row-error]");
        const input = row.querySelector("[data-translation-input]");
        const error = rowValidationError(key, input?.value || "");
        row.classList.toggle("has-error", Boolean(error));
        if (errorElement) {
            errorElement.textContent = error;
            errorElement.hidden = !error;
        }
        return !error;
    };

    const render = () => {
        if (!list || !template) return;
        list.replaceChildren();
        Object.keys(sourceCatalog).sort().forEach((key) => {
            const row = template.content.firstElementChild.cloneNode(true);
            row.dataset.translationKey = key;
            row.querySelector("[data-key]").textContent = key;
            row.querySelector("[data-source]").textContent = sourceCatalog[key];
            const placeholderList = placeholders(sourceCatalog[key]);
            const placeholderElement = row.querySelector("[data-placeholders]");
            if (placeholderList.length) {
                placeholderElement.textContent = t(
                    "translator.placeholders",
                    { placeholders: placeholderList.join(", ") },
                    `Platzhalter: ${placeholderList.join(", ")}`,
                );
                placeholderElement.hidden = false;
            }
            const input = row.querySelector("[data-translation-input]");
            input.value = translations[key] || "";
            input.addEventListener("input", () => {
                translations[key] = input.value;
                validateRow(row);
                updateProgress();
                applyFilters();
            });
            list.append(row);
        });
        updateProgress();
        applyFilters();
    };

    const loadCatalog = async (code) => {
        if (!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(code)) {
            setStatus(t("translator.status.invalid_code", {}, "Bitte gib einen gültigen Sprachcode ein."), "error");
            return;
        }
        try {
            const payload = await fetchJson(`/static/i18n/${encodeURIComponent(code)}.json`);
            translations = catalogStrings(payload);
            codeInput.value = payload._meta?.code || code;
            nameInput.value = payload._meta?.name || languages.find((item) => item.code === code)?.name || "";
            render();
            setStatus(t("translator.status.loaded", {
                count: Object.keys(translations).length,
            }, `${Object.keys(translations).length} vorhandene Texte wurden geladen.`), "success");
        } catch (error) {
            setStatus(t("translator.status.load_error", {}, "Diese Sprachdatei konnte nicht geladen werden. Du kannst eine neue Übersetzung beginnen."), "error");
        }
    };

    const validateAll = () => {
        let valid = true;
        list?.querySelectorAll("[data-translation-key]").forEach((row) => {
            if (!validateRow(row)) valid = false;
        });
        const code = String(codeInput?.value || "").trim();
        const name = String(nameInput?.value || "").trim();
        if (!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(code)) {
            setStatus(t("translator.status.invalid_code", {}, "Der Sprachcode ist ungültig."), "error");
            return false;
        }
        if (code === "de") {
            setStatus(t("translator.status.source_protected", {}, "Deutsch ist der geschützte Ausgangskatalog. Bitte wähle einen anderen Sprachcode."), "error");
            return false;
        }
        if (!name) {
            setStatus(t("translator.status.name_required", {}, "Bitte gib den Namen der Sprache ein."), "error");
            return false;
        }
        if (!valid) {
            setStatus(t("translator.status.invalid_rows", {}, "Einige Übersetzungen enthalten ungültiges HTML oder veränderte Platzhalter."), "error");
            return false;
        }
        const missing = Object.keys(sourceCatalog).filter((key) => !String(translations[key] || "").trim()).length;
        setStatus(
            missing
                ? t("translator.status.valid_missing", { count: missing }, `Prüfung bestanden. ${missing} fehlende Texte verwenden weiterhin Deutsch.`)
                : t("translator.status.valid_complete", {}, "Prüfung bestanden. Die Übersetzung ist vollständig."),
            missing ? "warning" : "success",
        );
        return true;
    };

    const download = () => {
        if (!validateAll()) return;
        const code = codeInput.value.trim();
        const payload = {
            _meta: {
                code,
                name: nameInput.value.trim(),
                source: false,
                reviewed: false,
            },
        };
        Object.keys(sourceCatalog).sort().forEach((key) => {
            payload[key] = String(translations[key] || "").trim();
        });
        const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${code.replace(/[^A-Za-z0-9-]/g, "-")}.json`;
        document.body.append(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 0);
    };

    document.querySelector("[data-load-language]")?.addEventListener("click", () => {
        loadCatalog(existingSelect.value);
    });
    document.querySelector("[data-new-language]")?.addEventListener("click", () => {
        translations = {};
        codeInput.value = "";
        nameInput.value = "";
        render();
        setStatus(t("translator.status.new", {}, "Neue Übersetzung begonnen. Wähle Sprachcode und Namen."), "success");
        codeInput.focus();
    });
    document.querySelector("[data-import-file]")?.addEventListener("change", async (event) => {
        const file = event.target.files?.[0];
        if (!file) return;
        try {
            if (file.size > 1024 * 1024) {
                throw new Error("Translation file exceeds the local size limit");
            }
            const payload = JSON.parse(await file.text());
            translations = catalogStrings(payload);
            if (typeof payload._meta?.code === "string") codeInput.value = payload._meta.code;
            if (typeof payload._meta?.name === "string") nameInput.value = payload._meta.name;
            render();
            setStatus(t("translator.status.imported", { name: file.name }, `${file.name} wurde lokal importiert.`), "success");
        } catch (error) {
            setStatus(t("translator.status.import_error", {}, "Die ausgewählte Datei ist kein gültiger JSON-Katalog."), "error");
        } finally {
            event.target.value = "";
        }
    });
    searchInput?.addEventListener("input", applyFilters);
    missingOnly?.addEventListener("change", applyFilters);
    document.querySelector("[data-validate]")?.addEventListener("click", validateAll);
    document.querySelector("[data-download]")?.addEventListener("click", download);

    const initialize = async () => {
        try {
            const [sourcePayload, languagePayload] = await Promise.all([
                fetchJson(sourceUrl),
                fetchJson(languagesUrl),
            ]);
            sourceCatalog = catalogStrings(sourcePayload);
            languages = Array.isArray(languagePayload.languages)
                ? languagePayload.languages.filter((item) => item.code !== "de")
                : [];
            let selectedUiLanguage = "de";
            try {
                const storedLanguage = localStorage.getItem("vplan-language");
                if (languagePayload.languages?.some((item) => item.code === storedLanguage)) {
                    selectedUiLanguage = storedLanguage;
                }
            } catch (error) {
                // The German source catalog remains the UI fallback.
            }
            uiCatalog = selectedUiLanguage === "de"
                ? sourceCatalog
                : catalogStrings(await fetchJson(`/static/i18n/${encodeURIComponent(selectedUiLanguage)}.json`));
            document.documentElement.lang = selectedUiLanguage;
            applyUiTranslations();
            existingSelect.replaceChildren(...languages.map((language) => {
                const option = document.createElement("option");
                option.value = language.code;
                option.textContent = language.status === "beta" ? `${language.name} (Beta)` : language.name;
                return option;
            }));
            render();
            if (languages.length) await loadCatalog(languages[0].code);
        } catch (error) {
            setStatus(t("translator.status.source_error", {}, "Der deutsche Ausgangskatalog konnte nicht geladen werden. Bitte versuche es später erneut."), "error");
            document.querySelector("[data-download]").disabled = true;
        }
    };

    initialize();
})();
