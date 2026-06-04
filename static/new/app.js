(() => {
    document.addEventListener("DOMContentLoaded", () => {
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

    let activeConnectionTrigger = null;
    let activeProfileCreateTrigger = null;

    function getProfileCreateModal() {
        return document.getElementById("profile-create-modal");
    }

    function closeProfileCreateModal() {
        const modal = getProfileCreateModal();
        if (!modal?.classList.contains("open")) return;
        modal.classList.remove("open");
        modal.setAttribute("aria-hidden", "true");
        if (!getOpenInstructionModal() && !getConnectionModal()?.classList.contains("open")) {
            document.body.classList.remove("modal-open");
        }
        activeProfileCreateTrigger?.focus();
        activeProfileCreateTrigger = null;
    }

    function openProfileCreateModal(trigger) {
        const modal = getProfileCreateModal();
        if (!modal) {
            console.warn("OnlyUs new UI: profile create modal was not found.");
            return;
        }
        closeInstructionModal();
        closeConnectionModal();
        activeProfileCreateTrigger = trigger;
        modal.classList.add("open");
        modal.setAttribute("aria-hidden", "false");
        document.body.classList.add("modal-open");
        modal.querySelector(".connection-modal__panel")?.focus();
        modal.querySelector("[data-connection-label]")?.focus();
    }

    function bindProfileCreateButton() {
        const button = document.getElementById("open-create-profile-modal");
        if (!button) {
            console.warn("OnlyUs new UI: #open-create-profile-modal button was not found.");
            return;
        }
        if (button.dataset.profileCreateBound === "true") return;
        button.dataset.profileCreateBound = "true";
        button.addEventListener("click", () => openProfileCreateModal(button));
    }

    function getConnectionModal() {
        return document.getElementById("connection-qr-modal");
    }

    function closeConnectionModal() {
        const connectionQrModal = getConnectionModal();
        if (!connectionQrModal?.classList.contains("open")) return;
        connectionQrModal.classList.remove("open");
        connectionQrModal.setAttribute("aria-hidden", "true");
        const qrFrame = connectionQrModal.querySelector("[data-connection-modal-qr]");
        if (qrFrame) qrFrame.innerHTML = "";
        if (!getOpenInstructionModal() && !getProfileCreateModal()?.classList.contains("open")) {
            document.body.classList.remove("modal-open");
        }
        activeConnectionTrigger?.focus();
        activeConnectionTrigger = null;
    }

    function openConnectionModal(card, trigger) {
        const connectionQrModal = getConnectionModal();
        if (!connectionQrModal || !card) return;
        closeInstructionModal();
        closeProfileCreateModal();
        activeConnectionTrigger = trigger;
        const title = card.dataset.connectionName || "Подключение";
        const device = card.dataset.connectionDevice || "Подключение";
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
        if (!getConnectionModal()?.classList.contains("open") && !getProfileCreateModal()?.classList.contains("open")) {
            document.body.classList.remove("modal-open");
        }
        activeInstructionTrigger?.focus();
        activeInstructionTrigger = null;
    }

    function openInstructionModal(platform, trigger) {
        const modal = document.getElementById(`instruction-${platform}`);
        if (!modal) return;
        closeInstructionModal();
        closeConnectionModal();
        closeProfileCreateModal();
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
            closeProfileCreateModal();
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

    function prepareConnectionTitle(form) {
        const device = form.querySelector("[data-connection-device]")?.value || "Android";
        const label = form.querySelector("[data-connection-label]")?.value.trim() || "профиль";
        const title = form.querySelector("[data-connection-title]");
        if (title) {
            const safeLabel = label.toLowerCase().includes("vless") ? label : `VLESS ${label}`;
            title.value = `${device} · ${safeLabel}`;
        }
    }


    async function replaceConnectionsFromResponse(response) {
        const html = await response.text();
        const parsed = new DOMParser().parseFromString(html, "text/html");
        const nextConnections = parsed.getElementById("connections");
        const currentConnections = document.getElementById("connections");
        if (!nextConnections || !currentConnections) {
            window.location.href = response.url || "/new-ui#connections";
            return;
        }
        closeConnectionModal();
        closeProfileCreateModal();
        currentConnections.replaceWith(nextConnections);
        bindProfileCreateButton();
        document.getElementById("connections")?.scrollIntoView({ block: "start" });
    }

    document.addEventListener("click", async (event) => {

        if (event.target.closest("[data-profile-create-close]")) {
            closeProfileCreateModal();
            return;
        }
        const copyButton = event.target.closest("[data-connection-copy]");
        if (copyButton) {
            const card = copyButton.closest("[data-connection-card]");
            const value = card?.dataset.connectionLink || "";
            if (!value) return;
            await copyText(value);
            flashButtonLabel(copyButton);
            return;
        }

        const qrButton = event.target.closest("[data-connection-qr-open]");
        if (qrButton) {
            openConnectionModal(qrButton.closest("[data-connection-card]"), qrButton);
            return;
        }

        if (event.target.closest("[data-connection-modal-close]")) {
            closeConnectionModal();
        }
    });

    document.addEventListener("submit", async (event) => {
        const createForm = event.target.closest("[data-profile-create-form]");
        if (createForm) {
            prepareConnectionTitle(createForm);
            return;
        }

        const deleteForm = event.target.closest("[data-connection-delete-form]");
        if (deleteForm) {
            event.preventDefault();
            const button = deleteForm.querySelector("button[type='submit']");
            button.disabled = true;
            try {
                const response = await fetch(deleteForm.action, {
                    method: "POST",
                    body: new FormData(deleteForm),
                    credentials: "same-origin",
                });
                if (!response.ok) throw new Error("delete failed");
                await replaceConnectionsFromResponse(response);
            } catch (error) {
                HTMLFormElement.prototype.submit.call(deleteForm);
            } finally {
                button.disabled = false;
            }
        }
    });

    bindProfileCreateButton();

    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = document.getElementById(button.dataset.copyTarget || "");
            if (!target || !target.value) return;
            await copyText(target.value);
            flashButtonLabel(button);
        });
    });
    });
})();
