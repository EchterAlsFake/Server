(() => {
    "use strict";

    const searchInput = document.getElementById("apiSearch");
    const clearButton = document.getElementById("clearSearch");
    const filterButtons = [...document.querySelectorAll(".filter-btn")];
    const scraperCards = [...document.querySelectorAll("#scrapers-section .api-card")];
    const coreCard = document.querySelector("#core-networking-section .api-card");
    const coreSection = document.getElementById("core-networking-section");
    const scrapersSection = document.getElementById("scrapers-section");
    const emptyState = document.getElementById("emptyState");
    const searchCount = document.getElementById("searchCount");
    let activeFilter = "all";

    const cardMatches = (card, query) => {
        const searchable = [card.dataset.title, card.dataset.package, card.dataset.desc]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();
        return searchable.includes(query);
    };

    const updateResults = () => {
        const query = searchInput?.value.trim().toLowerCase() || "";
        let visibleScrapers = 0;

        scraperCards.forEach((card) => {
            const visible = activeFilter !== "core" && cardMatches(card, query);
            card.hidden = !visible;
            if (visible) visibleScrapers += 1;
        });

        const coreVisible = Boolean(
            coreCard
            && activeFilter !== "scrapers"
            && cardMatches(coreCard, query)
        );
        if (coreCard) coreCard.hidden = !coreVisible;
        if (coreSection) coreSection.hidden = !coreVisible;

        const totalVisible = visibleScrapers + Number(coreVisible);
        const totalPackages = scraperCards.length + Number(Boolean(coreCard));
        const showEmptyState = totalVisible === 0;

        if (scrapersSection) {
            scrapersSection.hidden = activeFilter === "core"
                ? !showEmptyState
                : visibleScrapers === 0 && !showEmptyState;
        }
        if (emptyState) emptyState.hidden = !showEmptyState;
        document.querySelector('.toc-link[href="#core-networking"]')?.toggleAttribute("hidden", !coreVisible);
        document.querySelector('.toc-link[href="#scrapers"]')?.toggleAttribute(
            "hidden",
            Boolean(scrapersSection?.hidden)
        );
        if (searchCount) searchCount.textContent = `${totalVisible} of ${totalPackages} packages`;
        if (clearButton) clearButton.hidden = query.length === 0;
        window.dispatchEvent(new Event("scroll"));
    };

    searchInput?.addEventListener("input", updateResults);
    clearButton?.addEventListener("click", () => {
        if (!searchInput) return;
        searchInput.value = "";
        searchInput.focus();
        updateResults();
    });

    filterButtons.forEach((button) => {
        button.addEventListener("click", () => {
            activeFilter = button.dataset.filter || "all";
            filterButtons.forEach((candidate) => {
                const active = candidate === button;
                candidate.classList.toggle("active", active);
                candidate.setAttribute("aria-pressed", String(active));
            });
            updateResults();
        });
    });

    document.addEventListener("keydown", (event) => {
        const target = event.target;
        const isTyping = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
        if (event.key === "/" && !isTyping) {
            event.preventDefault();
            searchInput?.focus();
        }
        if (event.key === "Escape" && document.activeElement === searchInput && searchInput?.value) {
            searchInput.value = "";
            updateResults();
        }
    });

    updateResults();
})();
