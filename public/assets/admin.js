(() => {
  "use strict";
  const params = new URLSearchParams(location.search);
  const adminKey = params.get("admin_key") || "";
  if (params.has("admin_key")) { params.delete("admin_key"); history.replaceState(null, "", `${location.pathname}${params.size ? `?${params}` : ""}${location.hash}`); }
  const state = { data: null, query: "", busy: new Set() };
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>'"]/g, (c) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", "'":"&#39;", '"':"&quot;" })[c]);
  const time = () => new Intl.DateTimeFormat("pl-PL", { hour:"2-digit", minute:"2-digit", second:"2-digit" }).format(new Date());
  const date = (s) => s ? new Intl.DateTimeFormat("pl-PL", { dateStyle:"medium" }).format(new Date(s * 1000)) : "—";

  async function api(method, path, body) {
    const headers = { Accept:"application/json" };
    if (adminKey) headers["X-Admin-Key"] = adminKey;
    const options = { method, headers };
    if (body !== undefined) { headers["Content-Type"] = "application/json"; options.body = JSON.stringify(body); }
    const response = await fetch(path, options);
    const payload = await response.json().catch(() => ({ ok:false, error:`HTTP ${response.status}` }));
    if (!response.ok || !payload.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }
  function log(message, type = "") {
    const li = document.createElement("li"); if (type) li.className = `is-${type}`;
    const t = document.createElement("time"); t.textContent = time();
    const text = document.createElement("span"); text.textContent = message;
    li.append(t, text); $("#activityLog").prepend(li);
  }
  function toast(message, type = "success") {
    const el = document.createElement("div"); el.className = `toast is-${type}`; el.setAttribute("role", type === "error" ? "alert" : "status"); el.textContent = message;
    $("#toastStack").append(el); setTimeout(() => el.remove(), 3600);
  }
  async function copy(value) { try { await navigator.clipboard.writeText(value); toast("Adres OBS skopiowany"); } catch { toast("Nie udało się skopiować adresu", "error"); } }
  function connection(ok, meta) { $(".sidebar-status").classList.toggle("is-error", !ok); $("#sidebarStatus").textContent = ok ? "API online" : "Brak połączenia"; $("#sidebarMeta").textContent = meta; }
  function setBusy(key, value) { value ? state.busy.add(key) : state.busy.delete(key); $$(`[data-busy-key="${CSS.escape(key)}"]`).forEach((el) => { el.disabled = value; }); }

  function renderOverview(data) {
    const items = data.streamers || [];
    $("#metricStreamers").textContent = items.length;
    $("#metricTokens").textContent = `${items.filter((x) => x.has_tokens).length}/${items.length}`;
    $("#metricSubscriptions").textContent = items.reduce((n,x) => n + Number(x.subscriptions_count || 0), 0);
    $("#metricPending").textContent = items.reduce((n,x) => n + Number(x.spins?.pending || 0), 0);
    const env = data.env || {};
    $("#envBadge").textContent = env.NODE_ENV || "unknown";
    const healthy = env.KICK_CLIENT_ID === "(set)";
    $("#healthBadge").textContent = healthy ? "Gotowe" : "Wymaga konfiguracji";
    $("#healthBadge").classList.toggle("is-warning", !healthy);
    const labels = { NODE_ENV:"Tryb", PORT_HTTP:"Port HTTP", DEV_BYPASS_AUTH:"Dev bypass", KICK_CLIENT_ID:"Kick OAuth", PUBLIC_BASE_URL:"Public URL", DB_PATH:"Baza danych" };
    $("#envInfo").innerHTML = Object.entries(labels).map(([key,label]) => `<div><dt>${label}</dt><dd>${esc(String(env[key] ?? "—"))}</dd></div>`).join("");
    $("#lastUpdated").textContent = `Aktualizacja: ${time()}`;
    connection(true, `${env.NODE_ENV || "unknown"} · port ${env.PORT_HTTP || "—"}`);
  }
  function urls(item) {
    const base = location.origin, key = encodeURIComponent(item.overlay_key);
    return [["Koło",`${base}/overlay/${key}`],["Slots",`${base}/slots/${key}`],["Delay",`${base}/delay/${key}`],["Suby",`${base}/subs/${key}`],["Counter",`${base}/counter/${key}`]];
  }
  function card(item) {
    const bid = Number(item.broadcaster_id), name = esc(item.display_name || item.kick_username || `Streamer ${bid}`), username = esc(item.kick_username || "bez nazwy");
    const accent = /^#[0-9a-f]{6}$/i.test(item.config?.accent_color || "") ? item.config.accent_color : "#53fc18";
    const rows = urls(item).map(([label,url]) => `<div class="url-row"><span>${label}</span><code title="${esc(url)}">${esc(url)}</code><button class="icon-button" type="button" data-action="copy" data-value="${esc(url)}" aria-label="Kopiuj adres ${label}">⧉</button></div>`).join("");
    return `<article class="streamer-card" data-bid="${bid}"><button class="streamer-summary" type="button" data-action="toggle" aria-expanded="false" aria-controls="details-${bid}"><span class="streamer-identity"><span class="avatar" style="--avatar-color:${accent}">${esc((item.display_name || item.kick_username || "S").slice(0,1).toUpperCase())}</span><span class="identity-copy"><strong>${name}</strong><span>@${username} · ID ${bid}</span></span></span><span class="status-chip${item.has_tokens ? "" : " is-warning"}">${item.has_tokens ? "Kick połączony" : "Brak tokenów"}</span><span class="summary-stat"><span>Kolejka</span><strong>${Number(item.spins?.pending || 0)} obrotów</strong></span><span class="summary-chevron">⌄</span></button>
      <div class="streamer-details" id="details-${bid}"><div class="detail-grid">
      <section class="detail-block"><h4>Adresy OBS</h4><div class="url-list">${rows}</div><div class="account-actions"><button class="button-mini" data-action="login" type="button">Zaloguj jako</button><button class="button-mini" data-action="rename" type="button">Zmień nazwę</button><button class="button-mini is-danger" data-action="delete" type="button">Usuń konto</button></div></section>
      <section class="detail-block"><h4>Licznik ogólny</h4><form class="counter-form" data-counter><label><span>Etykieta</span><input name="label" maxlength="60" value="${esc(item.config?.manual_label || "Counter")}"></label><label><span>Wartość</span><input name="count" type="number" min="0" value="${Number(item.config?.manual_count || 0)}"></label><label><span>Cel</span><input name="goal" type="number" min="0" value="${Number(item.config?.manual_goal || 0)}"></label><div class="counter-actions"><button class="button-mini is-accent" type="submit" data-busy-key="counter-${bid}">Zapisz</button><button class="button-mini" data-action="delta" data-delta="-1" type="button">−1</button><button class="button-mini" data-action="delta" data-delta="1" type="button">+1</button></div></form></section>
      <section class="detail-block"><h4>Narzędzia testowe</h4><div class="test-actions"><button class="button-mini is-accent" data-action="spin" data-count="1">1 obrót</button><button class="button-mini" data-action="spin" data-count="3">3 obroty</button><button class="button-mini" data-action="gift" data-count="5">5 giftów</button><button class="button-mini" data-action="gift" data-count="15">15 giftów</button><button class="button-mini" data-action="slots">Test slots</button><button class="button-mini" data-action="delay">Pomiń cooldown</button><button class="button-mini" data-action="reset">Wyczyść kolejkę</button></div></section>
      <section class="detail-block"><h4>Stan konfiguracji</h4><div class="detail-meta"><span>${Number(item.config?.items_count || 0)} nagród</span><span>${Number(item.config?.tiers_count || 0)} tierów</span><span>${Number(item.goals_count || 0)} celów</span><span>${Number(item.subscriptions_count || 0)} webhooków</span><span>${Number(item.config?.gifts_per_spin || 5)} giftów / obrót</span><span>utworzono ${esc(date(item.created_at))}</span></div></section>
      </div></div></article>`;
  }
  function renderStreamers() {
    const all = state.data?.streamers || [], q = state.query.trim().toLowerCase();
    const filtered = q ? all.filter((x) => `${x.display_name || ""} ${x.kick_username || ""} ${x.broadcaster_id}`.toLowerCase().includes(q)) : all;
    $("#streamerCount").textContent = q ? `${filtered.length} z ${all.length} kont` : `${all.length} ${all.length === 1 ? "konto" : "kont"}`;
    const box = $("#streamersBox"); box.setAttribute("aria-busy", "false");
    box.innerHTML = filtered.length ? filtered.map(card).join("") : `<div class="empty-state"><strong>${q ? "Brak pasujących streamerów" : "Brak streamerów"}</strong><p>${q ? "Zmień wyszukiwaną frazę." : "Dodaj pierwsze konto testowe."}</p></div>`;
  }
  async function load({ quiet = false } = {}) {
    const btn = $("#refreshButton"); btn.disabled = true; btn.textContent = "Odświeżam…";
    try { const data = await api("GET", "/admin/overview"); state.data = data; renderOverview(data); renderStreamers(); if (!quiet) log("Dane panelu zostały odświeżone.", "success"); }
    catch (e) { connection(false, e.message); log(`Błąd odświeżania: ${e.message}`, "error"); toast(e.message, "error"); $("#streamersBox").innerHTML = `<div class="empty-state"><strong>Nie udało się pobrać danych</strong><p>${esc(e.message)}</p></div>`; }
    finally { btn.disabled = false; btn.textContent = "Odśwież dane"; }
  }
  async function run(key, label, task) {
    if (state.busy.has(key)) return; setBusy(key, true);
    try { const result = await task(); log(result.message || label, "success"); toast(label); await load({ quiet:true }); return result; }
    catch (e) { log(`${label}: ${e.message}`, "error"); toast(e.message, "error"); }
    finally { setBusy(key, false); }
  }
  function confirm({ title, message, phrase = "", label = "Potwierdź" }) {
    const dialog = $("#confirmDialog"), input = $("#confirmPhraseInput"), accept = $("#confirmAccept");
    $("#confirmTitle").textContent = title; $("#confirmMessage").textContent = message; accept.textContent = label; $("#confirmPhraseWrap").hidden = !phrase; $("#confirmPhraseLabel").textContent = phrase; input.value = ""; accept.disabled = !!phrase;
    input.oninput = () => { accept.disabled = input.value !== phrase; }; dialog.showModal(); if (phrase) setTimeout(() => input.focus(), 0);
    return new Promise((resolve) => dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once:true }));
  }
  async function action(event) {
    const button = event.target.closest("[data-action]"), article = button?.closest(".streamer-card"); if (!button || !article) return;
    const bid = Number(article.dataset.bid), type = button.dataset.action;
    if (type === "toggle") { article.classList.toggle("is-open"); button.setAttribute("aria-expanded", String(article.classList.contains("is-open"))); return; }
    if (type === "copy") return copy(button.dataset.value);
    if (type === "login") return window.open(`/auth/dev-login?bid=${bid}&ret=/dashboard`, "_blank", "noopener");
    if (type === "rename") { const item = state.data.streamers.find((x) => Number(x.broadcaster_id) === bid), value = prompt("Nowa nazwa wyświetlana:", item?.display_name || item?.kick_username || ""); if (value?.trim()) return run(`rename-${bid}`, "Nazwa została zmieniona", () => api("PATCH", `/admin/streamers/${bid}`, { display_name:value.trim() })); return; }
    if (type === "delete") { const ok = await confirm({ title:"Usunąć streamera?", message:"Konto oraz jego konfiguracja zostaną trwale usunięte.", phrase:String(bid), label:"Usuń konto" }); if (ok) return run(`delete-${bid}`, "Konto usunięte", () => api("DELETE", `/admin/streamers/${bid}`)); return; }
    if (type === "spin") return run(`spin-${bid}`, `Dodano ${button.dataset.count} obrót`, () => api("POST", `/admin/streamers/${bid}/spin`, { count:Number(button.dataset.count) }));
    if (type === "gift") return run(`gift-${bid}`, `Zasymulowano ${button.dataset.count} giftów`, () => api("POST", `/admin/streamers/${bid}/simulate-gift`, { gift_count:Number(button.dataset.count) }));
    if (type === "slots") return run(`slots-${bid}`, "Uruchomiono test slots", () => api("POST", `/admin/streamers/${bid}/test-slots`, { n:1 }));
    if (type === "delay") return run(`delay-${bid}`, "Cooldown pominięty", () => api("POST", `/admin/streamers/${bid}/spin/complete`, {}));
    if (type === "reset") { if (await confirm({ title:"Wyczyścić kolejkę?", message:"Wszystkie oczekujące obroty zostaną usunięte.", label:"Wyczyść kolejkę" })) return run(`reset-${bid}`, "Kolejka wyczyszczona", () => api("POST", `/admin/streamers/${bid}/spin/reset`, {})); return; }
    if (type === "delta") return run(`counter-${bid}`, "Licznik zaktualizowany", () => api("POST", `/admin/streamers/${bid}/counter`, { delta:Number(button.dataset.delta) }));
  }
  function bind() {
    $("#refreshButton").onclick = () => load();
    $("#streamerSearch").oninput = (e) => { state.query = e.target.value; renderStreamers(); };
    $("#streamersBox").addEventListener("click", action);
    $("#streamersBox").addEventListener("submit", async (e) => { const form = e.target.closest("[data-counter]"); if (!form) return; e.preventDefault(); const bid = Number(form.closest(".streamer-card").dataset.bid), v = Object.fromEntries(new FormData(form)); await run(`counter-${bid}`, "Licznik zapisany", () => api("POST", `/admin/streamers/${bid}/counter`, { label:v.label, count:Number(v.count), goal:Number(v.goal) })); });
    $("#clearLogButton").onclick = () => { $("#activityLog").innerHTML = ""; log("Log lokalny został wyczyszczony."); };
    $("#createStreamer").onsubmit = async (e) => { e.preventDefault(); const bid = Number($("#newBid").value), username = $("#newUsername").value.trim(); $("#createError").textContent = ""; if (!Number.isFinite(bid) || bid <= 0 || !username) { $("#createError").textContent = "Podaj dodatni Broadcaster ID i nazwę Kick."; return; } const result = await run("create", "Streamer utworzony", () => api("POST", "/admin/streamers", { broadcaster_id:bid, kick_username:username })); if (result) e.currentTarget.reset(); };
    $("#quickSetupButton").onclick = async () => { const result = await run("quick", "Konto testowe jest gotowe", () => api("POST", "/admin/quick-setup", {})); if (result?.urls?.dev_login) window.open(result.urls.dev_login, "_blank", "noopener"); };
    $("#resetDbButton").onclick = async () => { if (await confirm({ title:"Wyczyścić całą bazę?", message:"Operacja usuwa wszystkie konta i konfiguracje w środowisku developerskim.", phrase:"WYCZYŚĆ", label:"Usuń wszystkie dane" })) await run("reset-db", "Baza została wyczyszczona", () => api("POST", "/admin/reset-db", {})); };
  }
  bind(); load();
})();
