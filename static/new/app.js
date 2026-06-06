(() => {
    function closeProfileCreateModalFallback() {
        const modal = document.getElementById("profile-create-modal");
        if (!modal) {
            console.warn("profile-create-modal not found");
            return;
        }

        modal.classList.remove("open");
        modal.setAttribute("aria-hidden", "true");
        modal.style.display = "none";
        modal.setAttribute("hidden", "");
        document.body.classList.remove("modal-open");
    }

    document.addEventListener("click", function(event) {
        const button = event.target.closest("#open-create-profile-modal");
        if (!button) return;

        event.preventDefault();
        event.stopPropagation();

        const modal = document.getElementById("profile-create-modal");
        if (!modal) {
            console.warn("profile-create-modal not found");
            return;
        }

        modal.classList.add("open");
        modal.removeAttribute("hidden");
        modal.setAttribute("aria-hidden", "false");
        modal.style.display = "flex";
        document.body.classList.add("modal-open");
    });

    document.addEventListener("click", function(event) {
        const modal = document.getElementById("profile-create-modal");
        if (!modal) return;

        const closeButton = event.target.closest("[data-profile-create-close]");
        const isBackdrop = event.target === modal.querySelector(".connection-modal__backdrop");
        if (!closeButton && !isBackdrop) return;

        event.preventDefault();
        event.stopPropagation();

        closeProfileCreateModalFallback();
    });
    document.addEventListener("DOMContentLoaded", () => {
        const root = document.documentElement;
        const storageKey = "onlyus-theme";
        const themeSelect = document.querySelector("[data-theme-select]");
        const systemQuery = window.matchMedia("(prefers-color-scheme: light)");

        const sidebar = document.getElementById("sidebar");
        const menuToggle = document.querySelector("[data-menu-toggle]");
        const backdrop = document.querySelector("[data-menu-backdrop]");

        const instructionButtons = document.querySelectorAll("[data-instruction-open]");
        const instructionModals = document.querySelectorAll(".instruction-modal");

        let activeInstructionTrigger = null;
        let activeConnectionTrigger = null;
        let activeProfileCreateTrigger = null;
        const warnedMissingElements = new Set();

        function warnMissingElement(key, message) {
            if (warnedMissingElements.has(key)) return;
            warnedMissingElements.add(key);
            console.warn(message);
        }

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

        function setMenu(open) {
            sidebar?.classList.toggle("open", open);
            backdrop?.classList.toggle("open", open);
            menuToggle?.setAttribute("aria-expanded", String(open));
        }
        function getProfileCreateModal() {
            return document.getElementById("profile-create-modal");
        }
        function getConnectionModal() {
            return document.getElementById("connection-qr-modal");
        }
        function getOpenInstructionModal() {
            return document.querySelector(".instruction-modal.open");
        }
        function hasOpenModal() {
            return Boolean(
                getOpenInstructionModal()
                || getConnectionModal()?.classList.contains("open")
                || getProfileCreateModal()?.classList.contains("open"),
            );
        }
        function closeProfileCreateModal() {
            const modal = getProfileCreateModal();
            if (!modal?.classList.contains("open")) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            modal.style.display = "none";
            modal.setAttribute("hidden", "");
            modal.querySelector("[data-profile-create-form]")?.reset();
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            activeProfileCreateTrigger?.focus();
            activeProfileCreateTrigger = null;
        }

        function closeConnectionModal() {
            const modal = getConnectionModal();
            if (!modal?.classList.contains("open")) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            const qrFrame = modal.querySelector("[data-connection-modal-qr]");
            if (qrFrame) qrFrame.innerHTML = "";
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            activeConnectionTrigger?.focus();
            activeConnectionTrigger = null;
        }

        function closeInstructionModal() {
            const modal = getOpenInstructionModal();
            if (!modal) {
                warnMissingElement("profile-create-modal", "Profile create modal #profile-create-modal was not found.");
                return;
            }
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            activeInstructionTrigger?.focus();
            activeInstructionTrigger = null;
        }

        function openProfileCreateModal(trigger) {
            const modal = getProfileCreateModal();
            if (!modal) return;
            closeInstructionModal();
            closeConnectionModal();
            activeProfileCreateTrigger = trigger;
            modal.classList.add("open");
            modal.removeAttribute("hidden");
            modal.setAttribute("aria-hidden", "false");
            modal.style.display = "flex";
            document.body.classList.add("modal-open");
            updateConnectionProtocolState(modal.querySelector("[data-profile-create-form]"));
            const labelInput = modal.querySelector("[data-connection-label]");
            modal.querySelector(".connection-modal__panel")?.focus();
            labelInput?.focus();
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

        function openConnectionModal(card, trigger) {
            const modal = getConnectionModal();
            if (!modal || !card) return;
            closeInstructionModal();
            closeProfileCreateModal();
            activeConnectionTrigger = trigger;

            const title = card.dataset.connectionName || "Подключение";
            const device = card.dataset.connectionDevice || "Подключение";
            const qrTarget = modal.querySelector("[data-connection-modal-qr]");
            const qrUrl = card.dataset.connectionQrUrl || "";

            modal.querySelector("[data-connection-modal-title]").textContent = title;
            modal.querySelector("[data-connection-modal-device]").textContent = device;
            if (qrTarget) {
                qrTarget.innerHTML = "";
                if (qrUrl) {
                    const image = document.createElement("img");
                    image.src = qrUrl;
                    image.alt = `QR-код подключения ${title}`;
                    image.loading = "lazy";
                    qrTarget.append(image);
                }
            }


            modal.classList.add("open");
            modal.setAttribute("aria-hidden", "false");
            document.body.classList.add("modal-open");
            modal.querySelector(".connection-modal__panel")?.focus();
        }

        function isAppleDevice(value) {
            return ["iphone_macos", "iphone", "macos", "apple"].includes(String(value || "").toLowerCase());
        }

        function updateConnectionProtocolState(form) {
            if (!form) return;
            const deviceSelect = form.querySelector("[data-connection-device]");
            const protocolField = form.querySelector("[data-connection-protocol-field]");
            const protocolSelect = form.querySelector("[data-connection-protocol]");
            const keyKind = form.querySelector("[data-connection-kind]");
            const appleSelected = isAppleDevice(deviceSelect?.value);

            if (protocolField) protocolField.hidden = appleSelected;
            if (appleSelected) {
                if (keyKind) keyKind.value = "xray";
                if (protocolSelect) protocolSelect.value = "xray";
                return;
            }

            if (keyKind) keyKind.value = protocolSelect?.value === "awg" ? "awg" : "xray";
        }

        function prepareConnectionTitle(form) {
            updateConnectionProtocolState(form);
            const deviceSelect = form.querySelector("[data-connection-device]");
            const protocolSelect = form.querySelector("[data-connection-protocol]");
            const keyKind = form.querySelector("[data-connection-kind]")?.value || "xray";
            const device = deviceSelect?.selectedOptions?.[0]?.textContent.trim() || "Android";
            const label = form.querySelector("[data-connection-label]")?.value.trim() || "профиль";
            const title = form.querySelector("[data-connection-title]");
            if (!title) return;

            if (isAppleDevice(deviceSelect?.value)) {
                title.value = `iPhone / macOS · Reality + WS · ${label}`;
                return;
            }

            const protocolLabel = keyKind === "awg" || protocolSelect?.value === "awg" ? "WG" : "Reality";
            title.value = `${device} · ${protocolLabel} · ${label}`;
        }
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
            bindConnectionProtocolControls();
            document.getElementById("connections")?.scrollIntoView({ block: "start" });
        }

        function bindConnectionProtocolControls() {
            document.querySelectorAll("[data-profile-create-form]").forEach((form) => {
                if (form.dataset.connectionProtocolBound === "true") {
                    updateConnectionProtocolState(form);
                    return;
                }
                form.dataset.connectionProtocolBound = "true";
                form.querySelector("[data-connection-device]")?.addEventListener("change", () => updateConnectionProtocolState(form));
                form.querySelector("[data-connection-protocol]")?.addEventListener("change", () => updateConnectionProtocolState(form));
                updateConnectionProtocolState(form);
            });
        }


        function bindProfileCreateButton() {
            const connectionsSection = document.getElementById("connections");
            if (!connectionsSection) return;
            const button = document.getElementById("open-create-profile-modal");
            const modal = getProfileCreateModal();

            if (!button) {
                warnMissingElement("open-create-profile-modal", "Profile create button #open-create-profile-modal was not found.");
                return;
            }
            if (!modal) {
                warnMissingElement("profile-create-modal", "Profile create modal #profile-create-modal was not found.");
            }
            if (button.dataset.profileCreateBound === "true") return;
            button.dataset.profileCreateBound = "true";
            button.addEventListener("click", (event) => {
                event.preventDefault();
                openProfileCreateModal(button);
            });
        }

        applyTheme(localStorage.getItem(storageKey) || "dark");

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

        menuToggle?.addEventListener("click", () => setMenu(!sidebar?.classList.contains("open")));
        backdrop?.addEventListener("click", () => setMenu(false));

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
            const downloadLink = event.target.closest("[data-connection-download]");
            if (downloadLink && !downloadLink.getAttribute("href")) {
                event.preventDefault();
                warnMissingElement("connection-download-url", "Connection download link is missing an href.");
                return;
            }

            if (event.target.closest("[data-connection-modal-close]")) {
                closeConnectionModal();
            }
        });

        document.addEventListener("submit", async (event) => {
            const createForm = event.target.closest("[data-profile-create-form]");
            if (createForm) {
                event.preventDefault();
                prepareConnectionTitle(createForm);
                const button = createForm.querySelector("button[type='submit']");
                if (button) button.disabled = true;
                try {
                    const formData = new FormData(createForm);
                    const response = await fetch(createForm.action, {
                        method: "POST",
                        body: formData,
                        credentials: "same-origin",
                    });
                    if (!response.ok) throw new Error("create failed");
                    await replaceConnectionsFromResponse(response);
                } catch (error) {
                    HTMLFormElement.prototype.submit.call(createForm);
                } finally {
                    if (button) button.disabled = false;
                }
                return;
            }

            const deleteForm = event.target.closest("[data-connection-delete-form]");
            if (deleteForm) {
                event.preventDefault();
                const button = deleteForm.querySelector("button[type='submit']");
                if (button) button.disabled = true;
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
                    if (button) button.disabled = false;
                }
            }
        });

        bindProfileCreateButton();
        bindConnectionProtocolControls();

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
