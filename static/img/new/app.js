(() => {
    const root = document.documentElement;
    const storageKey = "onlyus-theme";
    const themeSelect = document.querySelector("[data-theme-select]");
    const systemQuery = window.matchMedia("(prefers-color-scheme: light)");

    function resolveTheme(value) {
        if (value === "system") {
            return systemQuery.matches ? "light" : "dark";
        }
        return value === "light" ? "light" : "dark";
    }

    function applyTheme(value) {
        root.dataset.theme = resolveTheme(value);
        if (themeSelect) themeSelect.value = value;
    }

    const savedTheme = localStorage.getItem(storageKey) || "dark";
    applyTheme(savedTheme);

    themeSelect?.addEventListener("change", (event) => {
        const value = event.target.value;
        localStorage.setItem(storageKey, value);
        applyTheme(value);
    });

    document.querySelectorAll("[data-theme-choice]").forEach((button) => {
        button.addEventListener("click", () => {
            const value = button.dataset.themeChoice || "dark";
            localStorage.setItem(storageKey, value);
            applyTheme(value);
        });
    });

    systemQuery.addEventListener?.("change", () => {
        if ((localStorage.getItem(storageKey) || "dark") === "system") {
            applyTheme("system");
        }
    });

    const sidebar = document.getElementById("sidebar");
    const menuToggle = document.querySelector("[data-menu-toggle]");
    const backdrop = document.querySelector("[data-menu-backdrop]");

    function setMenu(open) {
        sidebar?.classList.toggle("open", open);
        backdrop?.classList.toggle("open", open);
        menuToggle?.setAttribute("aria-expanded", String(open));
    }

    menuToggle?.addEventListener("click", () => setMenu(!sidebar?.classList.contains("open")));
    backdrop?.addEventListener("click", () => setMenu(false));

    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = document.getElementById(button.dataset.copyTarget || "");
            if (!target || !target.value) return;
            await navigator.clipboard.writeText(target.value);
            const original = button.textContent;
            button.textContent = "Скопировано";
            window.setTimeout(() => { button.textContent = original; }, 1600);
        });
    });
})();
