(() => {
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
        let activeProfileModalTrigger = null;
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

        function updateThemeChoices(value) {
            document.querySelectorAll("[data-theme-choice]").forEach((button) => {
                button.setAttribute("aria-pressed", String(button.dataset.themeChoice === value));
            });
        }

        function applyTheme(value) {
            root.dataset.theme = resolveTheme(value);
            if (themeSelect) themeSelect.value = value;
            updateThemeChoices(value);
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
        function getProfileVkModal() {
            return document.getElementById("profile-vk-modal");
        }
        function getProfileModal(name) {
            if (!name) return null;
            return Array.from(document.querySelectorAll("[data-profile-modal]")).find((modal) => modal.dataset.profileModal === name) || null;
        }
        function getOpenProfileModal() {
            return document.querySelector("[data-profile-modal].open");
        }
        function getOpenInstructionModal() {
            return document.querySelector(".instruction-modal.open");
        }
        function hasOpenModal() {
            return Boolean(
                getOpenInstructionModal()
                || getConnectionModal()?.classList.contains("open")
                || getProfileCreateModal()?.classList.contains("open")
                || getProfileVkModal()?.classList.contains("open")
                || getOpenProfileModal(),
            );
        }
        function getModalPanel(modal) {
            return modal?.querySelector(".instruction-modal__panel, .connection-modal__panel, .profile-modal__panel") || null;
        }

        function getFocusableElements(container) {
            if (!container) return [];
            const selector = [
                "a[href]",
                "button:not([disabled])",
                "input:not([disabled])",
                "select:not([disabled])",
                "textarea:not([disabled])",
                "[tabindex]:not([tabindex='-1'])",
            ].join(",");
            return Array.from(container.querySelectorAll(selector)).filter((element) => {
                if (element.getAttribute("aria-disabled") === "true") return false;
                return Boolean(element.offsetWidth || element.offsetHeight || element.getClientRects().length);
            });
        }

        function getActiveModalPanel() {
            return getModalPanel(getConnectionModal()?.classList.contains("open") ? getConnectionModal() : null)
                || getModalPanel(getProfileCreateModal()?.classList.contains("open") ? getProfileCreateModal() : null)
                || getModalPanel(getProfileVkModal()?.classList.contains("open") ? getProfileVkModal() : null)
                || getModalPanel(getOpenProfileModal())
                || getModalPanel(getOpenInstructionModal());
        }

        function focusSafely(element) {
            if (!element || !document.contains(element)) return false;
            if (element.matches?.(":disabled, [aria-disabled='true']")) return false;
            element.focus();
            return true;
        }

        function focusSection(section) {
            if (!section || !document.contains(section)) return false;
            const hadTabindex = section.hasAttribute("tabindex");
            if (!hadTabindex) section.setAttribute("tabindex", "-1");
            section.focus({ preventScroll: true });
            if (!hadTabindex) {
                section.addEventListener("blur", () => section.removeAttribute("tabindex"), { once: true });
            }
            return true;
        }

        function resetProfileCreateForm(form) {
            if (!form) return;
            form.reset();
            const keyKind = form.querySelector("[data-connection-kind]");
            const title = form.querySelector("[data-connection-title]");
            const protocolSelect = form.querySelector("[data-connection-protocol]");
            const labelInput = form.querySelector("[data-connection-label]");
            if (keyKind) keyKind.value = "xray";
            if (title) title.value = "";
            if (protocolSelect) protocolSelect.value = "xray";
            if (labelInput) labelInput.value = "";
            updateConnectionProtocolState(form);
        }
        function closeProfileCreateModal() {
            const modal = getProfileCreateModal();
            if (!modal?.classList.contains("open")) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            modal.style.display = "none";
            modal.setAttribute("hidden", "");
            resetProfileCreateForm(modal.querySelector("[data-profile-create-form]"));
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            focusSafely(activeProfileCreateTrigger);
            activeProfileCreateTrigger = null;
        }

        function setProfileVkError(message) {
            const errorElement = getProfileVkModal()?.querySelector("[data-vk-link-error]");
            if (!errorElement) return;
            const normalizedMessage = (message || "").trim();
            errorElement.textContent = normalizedMessage;
            errorElement.hidden = !normalizedMessage;
        }

        function openProfileVkModal(trigger) {
            const modal = getProfileVkModal();
            if (!modal) return;
            activeProfileCreateTrigger = trigger || null;
            modal.classList.add("open");
            modal.removeAttribute("hidden");
            modal.setAttribute("aria-hidden", "false");
            document.body.classList.add("modal-open");
            focusSafely(getModalPanel(modal));
        }

        function closeProfileVkModal() {
            const modal = getProfileVkModal();
            if (!modal?.classList.contains("open")) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            modal.setAttribute("hidden", "");
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            focusSafely(activeProfileCreateTrigger);
            activeProfileCreateTrigger = null;
        }

        function closeConnectionModal() {
            const modal = getConnectionModal();
            if (!modal?.classList.contains("open")) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            const qrFrame = modal.querySelector("[data-connection-modal-qr]");
            if (qrFrame) qrFrame.innerHTML = "";
            const title = modal.querySelector("[data-connection-modal-title]");
            const device = modal.querySelector("[data-connection-modal-device]");
            if (title) title.textContent = "QR-код";
            if (device) device.textContent = "Подключение";
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            focusSafely(activeConnectionTrigger);
            activeConnectionTrigger = null;
        }

        function closeInstructionModal() {
            const modal = getOpenInstructionModal();
            if (!modal) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            focusSafely(activeInstructionTrigger);
            activeInstructionTrigger = null;
        }

        function closeProfileModal() {
            const modal = getOpenProfileModal();
            if (!modal) return;
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            modal.setAttribute("hidden", "");
            if (!hasOpenModal()) document.body.classList.remove("modal-open");
            focusSafely(activeProfileModalTrigger);
            activeProfileModalTrigger = null;
        }

        function openProfileModal(name, trigger) {
            const modal = getProfileModal(name);
            if (!modal) return;
            closeInstructionModal();
            closeConnectionModal();
            closeProfileCreateModal();
            closeProfileVkModal();
            closeProfileModal();
            activeProfileModalTrigger = trigger || null;
            modal.classList.add("open");
            modal.removeAttribute("hidden");
            modal.setAttribute("aria-hidden", "false");
            document.body.classList.add("modal-open");
            const panel = getModalPanel(modal);
            const firstInput = modal.querySelector("input:not([type='hidden']):not([disabled]), button:not([disabled]), a[href]");
            focusSafely(firstInput) || focusSafely(panel);
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
            const form = modal.querySelector("[data-profile-create-form]");
            resetProfileCreateForm(form);
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
            const connectionLink = card.dataset.connectionLink || "";
            const qrUrl = card.dataset.connectionQrUrl || "";
            if (!connectionLink || !qrUrl) {
                flashButtonLabel(trigger, !connectionLink ? "Ссылка недоступна" : "QR недоступен");
                activeConnectionTrigger = null;
                return;
            }

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
                } else {
                    qrTarget.textContent = "QR недоступен";
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
            const protocolField = form.querySelector("[data-connection-protocol-field]");
            const protocolSelect = form.querySelector("[data-connection-protocol]");
            const keyKind = form.querySelector("[data-connection-kind]");
            if (protocolField) protocolField.hidden = false;

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

            const protocolLabel = keyKind === "awg" || protocolSelect?.value === "awg" ? "WireGuard" : "Reality + WS";
            title.value = `${isAppleDevice(deviceSelect?.value) ? "iPhone / macOS" : device} · ${protocolLabel} · ${label}`;
        }
        async function copyText(value) {
            if (!value) return false;
            if (navigator.clipboard?.writeText) {
                try {
                    await navigator.clipboard.writeText(value);
                    return true;
                } catch (error) {
                    // Fall through to the textarea fallback for insecure contexts or denied permissions.
                }
            }

            const helper = document.createElement("textarea");
            helper.value = value;
            helper.setAttribute("readonly", "");
            helper.style.position = "fixed";
            helper.style.inset = "-1000px auto auto -1000px";
            document.body.append(helper);
            helper.select();
            let copied = false;
            try {
                copied = document.execCommand("copy");
            } catch (error) {
                copied = false;
            }
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
            const updatedConnections = document.getElementById("connections");
            updatedConnections?.scrollIntoView({ block: "start" });
            const createButton = updatedConnections?.querySelector("#open-create-profile-modal");
            focusSection(updatedConnections) || focusSafely(createButton) || focusSection(currentConnections);
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
                closeProfileVkModal();
                closeProfileModal();
                return;
            }
            if (event.key === "Tab") {
                const panel = getActiveModalPanel();
                if (!panel) return;
                const focusable = getFocusableElements(panel);
                if (!focusable.length) {
                    event.preventDefault();
                    panel.focus();
                    return;
                }
                const first = focusable[0];
                const last = focusable[focusable.length - 1];
                if (!panel.contains(document.activeElement)) {
                    event.preventDefault();
                    (event.shiftKey ? last : first).focus();
                } else if (event.shiftKey && document.activeElement === first) {
                    event.preventDefault();
                    last.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            }
        });

        document.addEventListener("click", async (event) => {
            if (event.target.closest("[data-profile-create-close]")) {
                closeProfileCreateModal();
                return;
            }
            if (event.target.closest("[data-vk-link-close]")) {
                closeProfileVkModal();
                return;
            }
            const profileModalClose = event.target.closest("[data-profile-modal-close]");
            if (profileModalClose) {
                closeProfileModal();
                return;
            }
            if (event.target.closest('[aria-disabled="true"]')) {
                event.preventDefault();
                return;
            }

            const profileModalOpen = event.target.closest("[data-profile-modal-open]");
            if (profileModalOpen) {
                event.preventDefault();
                openProfileModal(profileModalOpen.dataset.profileModalOpen || "", profileModalOpen);
                return;
            }

            const copyButton = event.target.closest("[data-connection-copy]");
            if (copyButton) {
                const card = copyButton.closest("[data-connection-card]");
                const value = card?.dataset.connectionLink || "";
                if (!value) {
                    flashButtonLabel(copyButton, "Ссылка недоступна");
                    return;
                }
                const copied = await copyText(value);
                flashButtonLabel(copyButton, copied ? "Скопировано" : "Не удалось скопировать");
                return;
            }

            const qrButton = event.target.closest("[data-connection-qr-open]");
            if (qrButton) {
                const card = qrButton.closest("[data-connection-card]");
                const connectionLink = card?.dataset.connectionLink || "";
                const qrUrl = card?.dataset.connectionQrUrl || "";
                if (!connectionLink || !qrUrl) {
                    flashButtonLabel(qrButton, !connectionLink ? "Ссылка недоступна" : "QR недоступен");
                    return;
                }
                openConnectionModal(card, qrButton);
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
                return;
            }

            const vkOpenButton = event.target.closest("[data-vk-link-open]");
            if (vkOpenButton) {
                event.preventDefault();
                const previousText = vkOpenButton.textContent;
                vkOpenButton.disabled = true;
                vkOpenButton.textContent = "Создаем код...";
                try {
                    const response = await fetch("/dashboard/vk-link", {
                        method: "POST",
                        headers: { "X-Requested-With": "XMLHttpRequest" },
                        credentials: "same-origin",
                    });
                    const payload = await response.json();
                    if (!response.ok || !payload.ok) {
                        throw new Error(payload.error || "Не удалось получить код привязки.");
                    }
                    const modal = getProfileVkModal();
                    const code = payload.code || "—";
                    const botLink = payload.vk_bot_link || document.querySelector("[data-vk-bot-link]")?.getAttribute("href") || "";
                    const codeElement = modal?.querySelector("[data-vk-link-code]");
                    const botLinkElement = modal?.querySelector("[data-vk-bot-link]");
                    setProfileVkError("");
                    if (codeElement) codeElement.textContent = code;
                    if (botLinkElement instanceof HTMLAnchorElement) {
                        if (botLink && botLink !== "#") {
                            botLinkElement.href = botLink;
                            botLinkElement.hidden = false;
                        } else {
                            botLinkElement.hidden = true;
                        }
                    }
                    closeProfileModal();
                    openProfileVkModal(vkOpenButton);
                } catch (error) {
                    const message = error instanceof Error ? error.message : "Не удалось получить код привязки.";
                    const modal = getProfileVkModal();
                    const codeElement = modal?.querySelector("[data-vk-link-code]");
                    if (codeElement) codeElement.textContent = "—";
                    setProfileVkError(message);
                    closeProfileModal();
                    openProfileVkModal(vkOpenButton);
                } finally {
                    vkOpenButton.disabled = false;
                    vkOpenButton.textContent = previousText || "Привязать VK";
                }
                return;
            }

            const vkCopyButton = event.target.closest("[data-vk-link-copy]");
            if (vkCopyButton) {
                const code = getProfileVkModal()?.querySelector("[data-vk-link-code]")?.textContent.trim() || "";
                if (!code || code === "—") {
                    flashButtonLabel(vkCopyButton, "Код недоступен");
                    return;
                }
                const copied = await copyText(`привязать ${code}`);
                flashButtonLabel(vkCopyButton, copied ? "Скопировано" : "Не удалось скопировать");
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

            const revokeInviteForm = event.target.closest("[data-invite-revoke-form]");
            if (revokeInviteForm && !window.confirm("Отозвать это неиспользованное приглашение?")) {
                event.preventDefault();
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
                const copied = await copyText(target.value);
                flashButtonLabel(button, copied ? "Скопировано" : "Не удалось скопировать");
            });
        });
    });
})();
