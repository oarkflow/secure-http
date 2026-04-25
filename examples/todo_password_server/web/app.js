import { SecureClient } from "./secure_http.js";

const state = {
    client: new SecureClient({ wasmUrl: "fetch.wasm" }),
    username: "",
    items: [],
};

const elements = {
    loginForm: document.querySelector("#login-form"),
    username: document.querySelector("#username"),
    password: document.querySelector("#password"),
    loginButton: document.querySelector("#login-button"),
    logoutButton: document.querySelector("#logout-button"),
    refreshButton: document.querySelector("#refresh-button"),
    statusPill: document.querySelector("#status-pill"),
    currentUser: document.querySelector("#current-user"),
    transportState: document.querySelector("#transport-state"),
    todoForm: document.querySelector("#todo-form"),
    todoID: document.querySelector("#todo-id"),
    todoTitle: document.querySelector("#todo-title"),
    todoDescription: document.querySelector("#todo-description"),
    todoDone: document.querySelector("#todo-done"),
    saveButton: document.querySelector("#save-button"),
    cancelButton: document.querySelector("#cancel-button"),
    todoList: document.querySelector("#todo-list"),
    emptyState: document.querySelector("#empty-state"),
    console: document.querySelector("#console"),
    clearConsole: document.querySelector("#clear-console"),
};

function log(message, payload) {
    const stamp = new Date().toISOString();
    let line = `[${stamp}] ${message}`;
    if (payload !== undefined) {
        line += `\n${JSON.stringify(payload, null, 2)}`;
    }
    elements.console.textContent = `${line}\n${elements.console.textContent}`.slice(0, 8000);
}

function setStatus(label, variant) {
    elements.statusPill.textContent = label;
    elements.statusPill.dataset.variant = variant;
}

function readCookie(name) {
    const cookies = document.cookie ? document.cookie.split("; ") : [];
    const prefix = `${name}=`;
    for (const entry of cookies) {
        if (entry.startsWith(prefix)) {
            return decodeURIComponent(entry.slice(prefix.length));
        }
    }
    return "";
}

function saveSession(session) {
    try {
        sessionStorage.setItem("todo_password_session", JSON.stringify(session));
    } catch (error) {
        log("Could not save session state", { error: error.message });
    }
}

function clearSession() {
    try {
        sessionStorage.removeItem("todo_password_session");
    } catch (error) {}
}

function isExpiredAuthError(error) {
    const message = String(error?.message || error || "").toLowerCase();
    return message.includes("bootstrap failed with status 401") ||
        message.includes("bootstrap failed with status 403") ||
        message.includes("bootstrap failed with status 404") ||
        message.includes("auth claims missing");
}

function isAuthenticated() {
    return Boolean(state.username && state.client.isReady);
}

function setFormEnabled(enabled) {
    elements.todoTitle.disabled = !enabled;
    elements.todoDescription.disabled = !enabled;
    elements.todoDone.disabled = !enabled;
    elements.saveButton.disabled = !enabled;
    elements.cancelButton.disabled = !enabled;
    elements.refreshButton.disabled = !enabled;
    elements.logoutButton.disabled = !enabled;
}

function resetEditor() {
    elements.todoID.value = "";
    elements.todoTitle.value = "";
    elements.todoDescription.value = "";
    elements.todoDone.checked = false;
}

function syncView() {
    const authed = isAuthenticated();
    elements.loginButton.disabled = authed;
    elements.username.disabled = authed;
    elements.password.disabled = authed;
    elements.currentUser.textContent = authed ? state.username : "Not signed in";
    elements.transportState.textContent = authed ? "Secure channel ready" : "Not initialized";
    setFormEnabled(authed);
    renderTodos();
}

function renderTodos() {
    const authed = isAuthenticated();
    elements.todoList.innerHTML = "";
    if (!authed) {
        elements.emptyState.textContent = "Sign in to load your encrypted todo list.";
        elements.emptyState.hidden = false;
        return;
    }
    if (state.items.length === 0) {
        elements.emptyState.textContent = "No todos yet. Add one above.";
        elements.emptyState.hidden = false;
        return;
    }
    elements.emptyState.hidden = true;
    for (const item of state.items) {
        const li = document.createElement("li");
        li.className = "todo-item";
        li.dataset.done = String(Boolean(item.done));
        li.innerHTML = `
            <header>
                <div>
                    <h3>${escapeHTML(item.title)}</h3>
                    <p>${escapeHTML(item.description || "No description")}</p>
                </div>
                <span class="status-pill" data-variant="${item.done ? "ok" : "idle"}">${item.done ? "Done" : "Open"}</span>
            </header>
            <div class="todo-meta">
                <span>Created ${formatDate(item.created_at)}</span>
                <span>Updated ${formatDate(item.updated_at)}</span>
            </div>
            <div class="todo-actions">
                <button type="button" data-action="edit">Edit</button>
                <button type="button" data-action="toggle" class="ghost">${item.done ? "Mark Open" : "Mark Done"}</button>
                <button type="button" data-action="delete" class="ghost">Delete</button>
            </div>
        `;
        li.querySelector('[data-action="edit"]').addEventListener("click", () => {
            elements.todoID.value = item.id;
            elements.todoTitle.value = item.title;
            elements.todoDescription.value = item.description || "";
            elements.todoDone.checked = Boolean(item.done);
            elements.todoTitle.focus();
        });
        li.querySelector('[data-action="toggle"]').addEventListener("click", async () => {
            await saveTodo({
                id: item.id,
                title: item.title,
                description: item.description || "",
                done: !item.done,
            });
        });
        li.querySelector('[data-action="delete"]').addEventListener("click", async () => {
            await deleteTodo(item.id);
        });
        elements.todoList.appendChild(li);
    }
}

function formatDate(value) {
    if (!value) {
        return "unknown";
    }
    return new Date(value).toLocaleString();
}

function escapeHTML(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

async function login(event) {
    event.preventDefault();
    const username = elements.username.value.trim();
    const password = elements.password.value;
    if (!username || !password) {
        setStatus("Missing credentials", "error");
        return;
    }

    try {
        setStatus("Signing in", "idle");
        const response = await fetch("/auth/login", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || "login failed");
        }

        const config = {
            baseURL: payload.baseURL || window.location.origin,
            handshakePath: payload.handshakePath || "/handshake",
            bootstrapPath: payload.bootstrapPath || "/auth/bootstrap",
            csrfCookieName: payload.csrfCookieName || "securehttp_csrf",
            csrfHeaderName: payload.csrfHeaderName || "X-CSRF-Token",
            csrfToken: readCookie(payload.csrfCookieName || "securehttp_csrf"),
            autoHandshake: true,
        };
        await state.client.init(config);
        state.username = username;
        saveSession({
            username,
            timestamp: Date.now(),
            config: {
                baseURL: config.baseURL,
                handshakePath: config.handshakePath,
                bootstrapPath: config.bootstrapPath,
                csrfCookieName: config.csrfCookieName,
                csrfHeaderName: config.csrfHeaderName,
                autoHandshake: true,
            },
        });
        elements.password.value = "";
        setStatus("Connected", "ok");
        log("Authenticated and initialized secure transport", { username });
        syncView();
        await refreshTodos();
    } catch (error) {
        await state.client.reset();
        state.username = "";
        state.items = [];
        clearSession();
        setStatus(error.message, "error");
        log("Login failed", { error: error.message });
        syncView();
    }
}

async function restoreSession() {
    try {
        const raw = sessionStorage.getItem("todo_password_session");
        if (!raw) {
            log("No saved session state found");
            return;
        }
        const saved = JSON.parse(raw);
        if (!saved?.username || !saved?.config) {
            clearSession();
            return;
        }
        const csrfCookieName = saved.config.csrfCookieName || "securehttp_csrf";
        const csrfToken = readCookie(csrfCookieName);
        if (!csrfToken) {
            log("Saved session found but CSRF cookie is missing");
            clearSession();
            return;
        }
        const restoreConfig = {
            ...saved.config,
            csrfToken,
            autoHandshake: true,
        };
        setStatus("Restoring session", "idle");
        await state.client.init(restoreConfig);
        state.username = saved.username;
        log("Restored session from cookies", { username: saved.username });
        setStatus("Connected", "ok");
        syncView();
        await refreshTodos();
    } catch (error) {
        await state.client.reset();
        state.username = "";
        state.items = [];
        if (isExpiredAuthError(error)) {
            clearSession();
            setStatus("Session expired", "idle");
        } else {
            setStatus("Reconnecting", "idle");
        }
        log("Failed to restore session", { error: error.message });
        syncView();
    }
}

async function refreshTodos() {
    if (!isAuthenticated()) {
        return;
    }
    try {
        const response = await state.client.get("/api/todos");
        state.items = Array.isArray(response.items) ? response.items : [];
        log("Fetched todos", { count: state.items.length });
        renderTodos();
    } catch (error) {
        setStatus(error.message, "error");
        log("Todo fetch failed", { error: error.message });
    }
}

async function saveTodo(input) {
    try {
        if (!input.title.trim()) {
            throw new Error("title is required");
        }
        if (input.id) {
            await state.client.put(`/api/todos/${encodeURIComponent(input.id)}`, {
                title: input.title,
                description: input.description,
                done: Boolean(input.done),
            });
            log("Updated todo", { id: input.id });
        } else {
            await state.client.post("/api/todos", {
                title: input.title,
                description: input.description,
            });
            log("Created todo", { title: input.title });
        }
        resetEditor();
        setStatus("Saved", "ok");
        await refreshTodos();
    } catch (error) {
        setStatus(error.message, "error");
        log("Save failed", { error: error.message });
    }
}

async function submitTodo(event) {
    event.preventDefault();
    await saveTodo({
        id: elements.todoID.value.trim(),
        title: elements.todoTitle.value,
        description: elements.todoDescription.value,
        done: elements.todoDone.checked,
    });
}

async function deleteTodo(id) {
    try {
        await state.client.delete(`/api/todos/${encodeURIComponent(id)}`);
        if (elements.todoID.value === id) {
            resetEditor();
        }
        setStatus("Deleted", "ok");
        log("Deleted todo", { id });
        await refreshTodos();
    } catch (error) {
        setStatus(error.message, "error");
        log("Delete failed", { error: error.message });
    }
}

async function logout() {
    try {
        if (state.client.isReady) {
            await fetch("/auth/logout", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": readCookie("securehttp_csrf"),
                },
                body: "{}",
            });
        }
    } finally {
        await state.client.reset();
        state.username = "";
        state.items = [];
        clearSession();
        resetEditor();
        setStatus("Offline", "idle");
        log("Session cleared");
        syncView();
    }
}

elements.loginForm.addEventListener("submit", login);
elements.todoForm.addEventListener("submit", submitTodo);
elements.cancelButton.addEventListener("click", resetEditor);
elements.refreshButton.addEventListener("click", refreshTodos);
elements.logoutButton.addEventListener("click", logout);
elements.clearConsole.addEventListener("click", () => {
    elements.console.textContent = "";
});

syncView();
restoreSession();
