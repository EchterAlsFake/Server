(() => {
    "use strict";

    const sidebar = document.getElementById("sidebar");
    const mobileToggle = document.getElementById("mobileToggle");
    const mobileOverlay = document.getElementById("mobileOverlay");
    const backToTop = document.getElementById("backToTop");
    const sidebarLinks = [...document.querySelectorAll(".sidebar-nav .nav-link")];
    const collapsibleGroups = [...document.querySelectorAll(".nav-collapsible")];

    const setNavigationOpen = (open) => {
        if (!sidebar || !mobileToggle || !mobileOverlay) return;
        sidebar.classList.toggle("open", open);
        mobileToggle.setAttribute("aria-expanded", String(open));
        mobileToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
        mobileOverlay.hidden = !open;
        document.body.classList.toggle("nav-open", open);
    };

    mobileToggle?.addEventListener("click", () => {
        setNavigationOpen(!sidebar?.classList.contains("open"));
    });
    mobileOverlay?.addEventListener("click", () => setNavigationOpen(false));
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") setNavigationOpen(false);
    });

    const setGroupCollapsed = (group, collapsed) => {
        const parent = group.querySelector(".nav-link-parent");
        const children = group.querySelector(".nav-sub-links");
        group.classList.toggle("collapsed", collapsed);
        parent?.setAttribute("aria-expanded", String(!collapsed));
        if (children) children.setAttribute("aria-hidden", String(collapsed));
    };

    collapsibleGroups.forEach((group, index) => {
        const parent = group.querySelector(".nav-link-parent");
        const children = group.querySelector(".nav-sub-links");
        if (children && !children.id) children.id = `nav-group-${index + 1}`;
        if (children) parent?.setAttribute("aria-controls", children.id);
        setGroupCollapsed(group, index !== 0);
        parent?.addEventListener("click", () => {
            setGroupCollapsed(group, !group.classList.contains("collapsed"));
        });
    });

    sidebarLinks.forEach((link) => {
        link.addEventListener("click", () => {
            if (window.matchMedia("(max-width: 820px)").matches) {
                setNavigationOpen(false);
            }
        });
    });

    const writeClipboard = async (text) => {
        if (navigator.clipboard?.writeText && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return;
        }

        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.append(textarea);
        textarea.select();
        const copied = document.execCommand("copy");
        textarea.remove();
        if (!copied) throw new Error("Clipboard copy failed");
    };

    const showCopiedState = (element, idleText = "Copy") => {
        const previous = element.textContent;
        element.textContent = "Copied";
        element.setAttribute("aria-live", "polite");
        window.setTimeout(() => {
            element.textContent = previous || idleText;
            element.removeAttribute("aria-live");
        }, 1400);
    };

    window.copyCode = async (button) => {
        const code = button.closest(".code-window")?.querySelector("pre code");
        if (!code) return;
        try {
            await writeClipboard(code.textContent);
            showCopiedState(button);
        } catch {
            button.textContent = "Copy failed";
        }
    };

    window.copyInstall = async (button) => {
        const command = button.querySelector("code")?.textContent.trim();
        const status = button.querySelector(".copy-icon");
        if (!command || !status) return;
        try {
            await writeClipboard(command);
            showCopiedState(status);
        } catch {
            status.textContent = "Copy failed";
        }
    };

    const usedHeadingIds = new Set([...document.querySelectorAll("[id]")].map((node) => node.id));
    const slugify = (value) => value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "") || "section";

    const uniqueHeadingId = (base) => {
        let candidate = base;
        let suffix = 2;
        while (usedHeadingIds.has(candidate)) candidate = `${base}-${suffix++}`;
        usedHeadingIds.add(candidate);
        return candidate;
    };

    const headingLabel = (heading) => {
        const clone = heading.cloneNode(true);
        clone.querySelectorAll(".section-icon, .heading-anchor").forEach((node) => node.remove());
        return clone.textContent.trim();
    };

    const targetForHeading = (heading) => {
        if (heading.id) return heading.id;

        const methodCard = heading.closest(".method-card");
        const methodAnchor = methodCard?.previousElementSibling;
        if (methodAnchor?.classList.contains("section-anchor") && methodAnchor.id) {
            return methodAnchor.id;
        }

        const section = heading.closest(".section");
        const sectionAnchor = section
            ? [...section.children].find((child) => child.classList?.contains("section-anchor") && child.id)
            : null;
        if (heading.tagName === "H2" && sectionAnchor) return sectionAnchor.id;

        heading.id = uniqueHeadingId(slugify(heading.textContent));
        return heading.id;
    };

    document.querySelectorAll(
        ".content-area .section > h2, .content-area .section > h3, .content-area .section > h4, "
        + ".content-area .method-card h3, .content-area .method-card h4"
    ).forEach((heading) => {
        const target = targetForHeading(heading);
        const anchor = document.createElement("a");
        anchor.className = "heading-anchor";
        anchor.href = `#${target}`;
        anchor.setAttribute("aria-label", `Link to ${headingLabel(heading)}`);
        anchor.textContent = "#";
        heading.append(anchor);
    });

    const toc = document.getElementById("pageTocList");
    const tocEntries = [];
    document.querySelectorAll(".content-area .section").forEach((section) => {
        const heading = [...section.children].find((child) => child.tagName === "H2");
        const anchor = [...section.children].find((child) => child.classList?.contains("section-anchor") && child.id);
        if (!heading || !anchor || !toc) return;

        const link = document.createElement("a");
        link.className = "toc-link";
        link.href = `#${anchor.id}`;
        link.textContent = headingLabel(heading);
        toc.append(link);
        tocEntries.push({ id: anchor.id, link });
    });

    const scrollAnchors = [...document.querySelectorAll(".section-anchor[id]")];
    const sectionIdForAnchor = (anchor) => {
        const section = anchor.closest(".section");
        return [...(section?.children || [])]
            .find((child) => child.classList?.contains("section-anchor") && child.id)?.id || anchor.id;
    };

    const updateActiveNavigation = () => {
        const activationLine = window.innerWidth <= 820 ? 88 : 40;
        let activeAnchor = scrollAnchors[0] || null;
        for (const anchor of scrollAnchors) {
            if (anchor.getClientRects().length === 0) continue;
            if (anchor.getBoundingClientRect().top <= activationLine) activeAnchor = anchor;
            else break;
        }

        const activeId = activeAnchor?.id;
        sidebarLinks.forEach((link) => {
            const active = link.getAttribute("href") === `#${activeId}`;
            link.classList.toggle("active", active);
            if (active) {
                const group = link.closest(".nav-collapsible");
                if (group) setGroupCollapsed(group, false);
            }
        });

        const activeSectionId = activeAnchor ? sectionIdForAnchor(activeAnchor) : null;
        tocEntries.forEach(({ id, link }) => link.classList.toggle("active", id === activeSectionId));
        backToTop?.classList.toggle("visible", window.scrollY > 480);
    };

    let scrollFrame = 0;
    const requestNavigationUpdate = () => {
        if (scrollFrame) return;
        scrollFrame = window.requestAnimationFrame(() => {
            updateActiveNavigation();
            scrollFrame = 0;
        });
    };

    window.addEventListener("scroll", requestNavigationUpdate, { passive: true });
    window.addEventListener("resize", requestNavigationUpdate);
    updateActiveNavigation();
})();
