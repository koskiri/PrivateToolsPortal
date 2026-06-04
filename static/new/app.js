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

    const connectionQrModal = document.getElementById("connection-qr-modal");
    let activeConnectionTrigger = null;

    function closeConnectionModal() {
        if (!connectionQrModal?.classList.contains("open")) return;
        connectionQrModal.classList.remove("open");
        connectionQrModal.setAttribute("aria-hidden", "true");
        connectionQrModal.querySelector("[data-connection-modal-qr]").innerHTML = "";
        if (!connectionQrModal?.classList.contains("open")) {
            document.body.classList.remove("modal-open");
        }
        activeConnectionTrigger?.focus();
        activeConnectionTrigger = null;
    }

    function openConnectionModal(card, trigger) {
        if (!connectionQrModal || !card) return;
        closeInstructionModal();
        activeConnectionTrigger = trigger;
        const title = card.dataset.connectionName || "Подключение";
        const device = card.dataset.connectionDevice || "Подключение";
        const qrTemplate = card.querySelector("[data-connection-qr]");
        const qrTarget = connectionQrModal.querySelector("[data-connection-modal-qr]");
        const qrUrl = card.dataset.connectionQrUrl || "";
        connectionQrModal.querySelector("[data-connection-modal-title]").textContent = title;
        connectionQrModal.querySelector("[data-connection-modal-device]").textContent = device;
        qrTarget.innerHTML = "";
        if (qrUrl) {
            const image = document.createElement("img");
            image.src = qrUrl;
            image.alt = `QR-код подключения ${title}`;
            image.loading = "lazy";
            qrTarget.append(image);
        } else {
            qrTarget.innerHTML = qrTemplate?.innerHTML || "";
        }
        connectionQrModal.classList.add("open");
        connectionQrModal.setAttribute("aria-hidden", "false");
        document.body.classList.add("modal-open");
        connectionQrModal.querySelector(".connection-modal__panel")?.focus();
    }

    const instructionButtons = document.querySelectorAll("[data-instruction-open]");
    const instructionModals = document.querySelectorAll(".instruction-modal");
    let activeInstructionTrigger = null;

    function getOpenInstructionModal() {
        return document.querySelector(".instruction-modal.open");
    }

    function closeInstructionModal() {
        const modal = getOpenInstructionModal();
        if (!modal) return;
        modal.classList.remove("open");
        modal.setAttribute("aria-hidden", "true");
        document.body.classList.remove("modal-open");
        activeInstructionTrigger?.focus();
        activeInstructionTrigger = null;
    }

    function openInstructionModal(platform, trigger) {
        const modal = document.getElementById(`instruction-${platform}`);
        if (!modal) return;
        closeInstructionModal();
        closeConnectionModal();
        activeInstructionTrigger = trigger;
        modal.classList.add("open");
        modal.setAttribute("aria-hidden", "false");
        document.body.classList.add("modal-open");
        modal.querySelector(".instruction-modal__panel")?.focus();
    }

    instructionButtons.forEach((button) => {
        button.addEventListener("click", () => {
            openInstructionModal(button.dataset.instructionOpen || "", button);
        });
    });

    instructionModals.forEach((modal) => {
        modal.querySelectorAll("[data-instruction-close]").forEach((closeButton) => {
            closeButton.addEventListener("click", closeInstructionModal);
        });
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeInstructionModal();
            closeConnectionModal();
        }
    });

    async function copyText(value) {
        if (!value) return false;
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(value);
            return true;
        }
        const helper = document.createElement("textarea");
        helper.value = value;
        helper.setAttribute("readonly", "");
        helper.style.position = "fixed";
        helper.style.inset = "-1000px auto auto -1000px";
        document.body.append(helper);
        helper.select();
        const copied = document.execCommand("copy");
        helper.remove();
        return copied;
    }

    function flashButtonLabel(button, label = "Скопировано") {
        const original = button.textContent;
        button.textContent = label;
        window.setTimeout(() => { button.textContent = original; }, 1600);
    }


    document.querySelectorAll("[data-connection-copy]").forEach((button) => {
        button.addEventListener("click", async () => {
            const card = button.closest("[data-connection-card]");
            const value = card?.dataset.connectionLink || "";
            if (!value) return;
            await copyText(value);
            flashButtonLabel(button);
        });
    });

    document.querySelectorAll("[data-connection-qr-open]").forEach((button) => {
        button.addEventListener("click", () => {
            openConnectionModal(button.closest("[data-connection-card]"), button);
        });
    });

    connectionQrModal?.querySelectorAll("[data-connection-modal-close]").forEach((button) => {
        button.addEventListener("click", closeConnectionModal);
    });

    document.querySelectorAll("[data-connection-form]").forEach((form) => {
        form.addEventListener("submit", () => {
            const device = form.querySelector("[data-connection-device]")?.value || "Android";
            const label = form.querySelector("[data-connection-label]")?.value.trim() || "профиль";
            const title = form.querySelector("[data-connection-title]");
            if (title) {
                const safeLabel = label.toLowerCase().includes("vless") ? label : `VLESS ${label}`;
                title.value = `${device} · ${safeLabel}`;
            }
        });
    });

    document.querySelectorAll("[data-connection-delete-form]").forEach((form) => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const card = form.closest("[data-connection-card]");
            const button = form.querySelector("button[type='submit']");
            button.disabled = true;
            try {
                const response = await fetch(form.action, {
                    method: "POST",
                    body: new FormData(form),
                    credentials: "same-origin",
                });
                if (!response.ok || response.url.includes("error=")) throw new Error("delete failed");
                card?.remove();
            } catch (error) {
                button.disabled = false;
                form.submit();
            }
        });
    });

    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = document.getElementById(button.dataset.copyTarget || "");
            if (!target || !target.value) return;
            await copyText(target.value);
            flashButtonLabel(button);
        });
    });
})();
