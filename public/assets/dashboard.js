const state = { status: null, items: [], counter: { count: 0, goal: 0, label: "" } };
const q = (s) => document.querySelector(s);
const qa = (s) => [...document.querySelectorAll(s)];
const errorBox = q("#globalError");
const statusBox = q("#globalStatus");
function notify(message, error = false) {
  const box = error ? errorBox : statusBox;
  box.textContent = message;
  box.hidden = false;
  window.setTimeout(() => box.hidden = true, 3500);
}
async function api(url, options = {}) {
  const response = await fetch(url, { cache: "no-store", ...options, headers: { "Content-Type": "application/json", ...options.headers || {} } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `B\u0142\u0105d ${response.status}`);
  return data;
}
const viewMeta = { overview: ["STUDIO / OVERVIEW", "Witaj w swoim studio."], wheel: ["STUDIO / WHEEL", "Skonfiguruj swoje ko\u0142o."], counter: ["STUDIO / COUNTER", "Steruj licznikiem na \u017Cywo."], obs: ["STUDIO / OBS SETUP", "Po\u0142\u0105cz studio z OBS."], account: ["STUDIO / ACCOUNT", "Konto i bezpiecze\u0144stwo."] };
function openView(name, { focus = true } = {}) {
  qa("[data-view-panel]").forEach((panel) => {
    const active = panel.dataset.viewPanel === name;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
  qa(".nav-item").forEach((button) => button.classList.toggle("is-active", button.dataset.view === name));
  q("#viewEyebrow").textContent = viewMeta[name][0];
  q("#viewTitle").textContent = viewMeta[name][1];
  history.replaceState(null, "", `#${name}`);
  q("#mobileNav").hidden = true;
  q("#menuToggle").setAttribute("aria-expanded", "false");
  if (focus) q("#workspace").focus();
}
qa("[data-view]").forEach((button) => button.addEventListener("click", () => openView(button.dataset.view)));
qa("[data-open-view]").forEach((button) => button.addEventListener("click", () => openView(button.dataset.openView)));
q("#menuToggle").addEventListener("click", () => {
  const nav = q("#mobileNav");
  nav.hidden = !nav.hidden;
  q("#menuToggle").setAttribute("aria-expanded", String(!nav.hidden));
});
function renderItems() {
  const box = q("#wheelItems");
  box.replaceChildren();
  state.items.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "wheel-item";
    const label = document.createElement("input");
    label.value = item.label || "";
    label.maxLength = 100;
    label.setAttribute("aria-label", `Nazwa pozycji ${index + 1}`);
    label.addEventListener("input", () => {
      item.label = label.value;
      renderWheelPreview();
    });
    const weight = document.createElement("input");
    weight.type = "number";
    weight.min = "0";
    weight.max = "100";
    weight.value = String(item.weight ?? 1);
    weight.setAttribute("aria-label", `Waga pozycji ${index + 1}`);
    weight.addEventListener("input", () => item.weight = Number(weight.value) || 0);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "\xD7";
    remove.setAttribute("aria-label", `Usu\u0144 pozycj\u0119 ${index + 1}`);
    remove.addEventListener("click", () => {
      state.items.splice(index, 1);
      renderItems();
      renderWheelPreview();
    });
    row.append(label, weight, remove);
    box.append(row);
  });
  renderWheelPreview();
}
function renderWheelPreview() {
  q("#wheelOpacityValue").value = `${Math.round(Number(q("#wheelOpacity").value) * 100)}%`;
}
q("#addWheelItem").addEventListener("click", () => {
  if (state.items.length >= 100) return notify("Maksymalnie 100 pozycji.", true);
  state.items.push({ label: `Nagroda ${state.items.length + 1}`, weight: 1, bonus: false });
  renderItems();
});
q("#wheelForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.items.length < 2) return notify("Dodaj co najmniej dwie pozycje.", true);
  try {
    const data = await api("/dashboard/config", { method: "POST", body: JSON.stringify({ items: state.items, accent_color: q("#accentColor").value, secondary_color: q("#secondaryColor").value, wheel_opacity: Number(q("#wheelOpacity").value), gifts_per_spin: 5 }) });
    state.items = data.items;
    q("#wheelSaveState").textContent = "Zapisano";
    updateReadiness();
    notify("Konfiguracja Wheel zapisana.");
  } catch (error) {
    notify(error.message, true);
  }
});
q("#testWheel").addEventListener("click", async () => {
  q("#wheelResult").textContent = "Trwa testowe losowanie\u2026";
  try {
    await api("/dashboard/test/1");
    q("#wheelResult").textContent = "Losowanie uruchomione w prawdziwym podglądzie OBS.";
  } catch {
    q("#wheelResult").textContent = "Nie udało się uruchomić losowania.";
  }
});
["#accentColor", "#secondaryColor", "#wheelOpacity"].forEach((selector) => {
  q(selector).addEventListener("input", () => {
    q("#wheelSaveState").textContent = "Zmiany niezapisane";
    renderWheelPreview();
  });
});
function renderCounter() {
  const { count, goal, label } = state.counter;
  q("#counterLabel").value = label;
  q("#counterValue").value = String(count);
  q("#counterGoal").value = String(goal);
  q("#counterPreviewLabel").textContent = (label || "COUNTER").toUpperCase();
  q("#counterPreviewValue").textContent = String(count);
  q("#counterPreviewGoal").textContent = goal > 0 ? `/ ${goal}` : "";
  q("#counterProgress").style.width = goal > 0 ? `${Math.min(100, count / goal * 100)}%` : "0%";
  q("#overviewCount").textContent = String(count);
  q("#overviewGoal").textContent = goal > 0 ? `z ${goal}` : "bez celu";
}
async function saveCounter(delta = null) {
  const body = { label: q("#counterLabel").value, count: Number(q("#counterValue").value) || 0, goal: Number(q("#counterGoal").value) || 0 };
  if (delta != null) {
    delete body.count;
    body.delta = delta;
  }
  const data = await api("/dashboard/counter", { method: "POST", body: JSON.stringify(body) });
  state.counter = { count: data.count, goal: data.goal, label: data.label };
  renderCounter();
  updateReadiness();
  notify("Counter zaktualizowany.");
}
q("#counterForm").addEventListener("submit", (event) => {
  event.preventDefault();
  saveCounter().catch((error) => notify(error.message, true));
});
qa("[data-counter-delta]").forEach((button) => button.addEventListener("click", () => saveCounter(Number(button.dataset.counterDelta)).catch((error) => notify(error.message, true))));
qa("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
  const value = q(`#${button.dataset.copy}`).textContent;
  try {
    await navigator.clipboard.writeText(value);
    notify("Adres skopiowany do schowka.");
  } catch {
    notify("Nie uda\u0142o si\u0119 skopiowa\u0107 adresu.", true);
  }
}));
q("#logoutButton").addEventListener("click", async () => {
  try {
    const data = await api("/auth/logout", { method: "POST", body: "{}" });
    location.assign(data.redirect || "/");
  } catch (error) {
    notify(error.message, true);
  }
});
function updateReadiness() {
  const wheelReady = state.items.length >= 2;
  const counterReady = Boolean(state.counter.label || state.counter.goal > 0);
  q("#wheelState").textContent = wheelReady ? "Gotowe" : "Do konfiguracji";
  q("#wheelState").classList.toggle("is-ready", wheelReady);
  q("#counterState").textContent = counterReady ? "Gotowe" : "Do konfiguracji";
  q("#counterState").classList.toggle("is-ready", counterReady);
  q("#readyCount").textContent = `${Number(wheelReady) + Number(counterReady)}/2`;
  q("#wheelSummary").textContent = wheelReady ? `${state.items.length} pozycji zapisanych w kole.` : "Dodaj minimum dwie pozycje, aby rozpocz\u0105\u0107.";
  q("#counterSummary").textContent = counterReady ? `${state.counter.label || "Counter"}: ${state.counter.count}${state.counter.goal ? `/${state.counter.goal}` : ""}.` : "Ustaw etykiet\u0119 i cel dla widz\xF3w.";
}
async function load() {
  try {
    const [status, config, counter] = await Promise.all([api("/dashboard/status"), api("/dashboard/config"), api("/dashboard/counter")]);
    state.status = status;
    state.items = Array.isArray(config.items) ? config.items : [];
    state.counter = { count: counter.count || 0, goal: counter.goal || 0, label: counter.label || "" };
    const name = status.display_name || status.kick_username || "Streamer";
    const username = status.kick_username ? `@${status.kick_username}` : "Kick account";
    ["#displayName", "#accountName"].forEach((id) => q(id).textContent = name);
    ["#username", "#accountUsername"].forEach((id) => q(id).textContent = username);
    ["#avatar", "#accountAvatar"].forEach((id) => q(id).textContent = name.slice(0, 1).toUpperCase());
    q("#accentColor").value = config.accent_color || "#7c3aed";
    q("#secondaryColor").value = config.secondary_color || "#121228";
    q("#wheelOpacity").value = String(config.wheel_opacity ?? 0.9);
    const base = location.origin;
    const wheelUrl = `${base}/overlay/${status.overlay_key}`;
    const counterUrl = `${base}/counter/${status.overlay_key}`;
    q("#wheelUrl").textContent = wheelUrl;
    q("#counterUrl").textContent = counterUrl;
    q("#wheelOpen").href = wheelUrl;
    q("#counterOpen").href = counterUrl;
    q("#wheelPreview").src = `${wheelUrl}?preview=1`;
    renderItems();
    renderCounter();
    updateReadiness();
  } catch (error) {
    notify(`Nie uda\u0142o si\u0119 za\u0142adowa\u0107 studia: ${error.message}`, true);
  }
}
openView(location.hash.slice(1) in viewMeta ? location.hash.slice(1) : "overview", { focus: false });
load();
