(() => {
  const $ = (id) => document.getElementById(id);
  const select = $("channelSelect");
  let bid = "", busy = false, revision = 0;
  function notice(message, error = false) {
    $("modNotice").textContent = message;
    $("modNotice").setAttribute("role", error ? "alert" : "status");
  }
  async function request(url, body) {
    const response = await fetch(url, body === undefined ? { cache: "no-store" } : {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) location.assign(`/moderator?channel=${encodeURIComponent(bid)}`);
      if (response.status === 403) { $("modControls").hidden = true; bid = ""; revision++; }
      throw new Error(response.status === 403 ? "Brak dostępu. Poproś streamera o dodanie Twojego konta i odśwież stronę." : data.error || "Nie udało się wykonać operacji.");
    }
    return data;
  }
  async function refresh() {
    if (!bid) return;
    const current = bid, version = ++revision;
    try {
      const data = await request(`/mod/${current}/status`);
      if (current !== bid || version !== revision) return;
      $("modPending").textContent = data.pending_spins;
      $("modDelay").textContent = data.spin_in_progress ? "W trakcie" : `${data.time_until_next} s`;
      $("modSlots").textContent = data.slots_pending;
      $("modCount").textContent = `${data.counter.count} / ${data.counter.goal}`;
    } catch (error) { if (current === bid || !bid) notice(error.message, true); }
  }
  async function action(endpoint, body, message) {
    if (busy || !bid) return;
    busy = true;
    select.disabled = true;
    document.querySelectorAll("#modControls button").forEach((button) => button.disabled = true);
    try {
      const data = await request(`/mod/${bid}/${endpoint}`, body);
      notice(endpoint === "test-spin" && !data.delivered ? "Brak połączonego koła OBS. Otwórz overlay i ponów test." : message);
      await refresh();
    } catch (error) { notice(error.message, true); }
    finally {
      busy = false;
      select.disabled = false;
      document.querySelectorAll("#modControls button").forEach((button) => button.disabled = false);
    }
  }
  select.addEventListener("change", () => {
    bid = select.value;
    revision++;
    $("modControls").hidden = !bid;
    history.replaceState(null, "", `/mod?channel=${encodeURIComponent(bid)}`);
    notice("");
    refresh();
  });
  $("modRefresh").onclick = refresh;
  $("modTest").onclick = () => action("test-spin", { n: 1 }, "Wysłano test koła. Prawdziwa kolejka pozostaje bez zmian.");
  $("modResetDelay").onclick = () => {
    if (confirm(`Pominąć oczekiwanie na kanale ${select.selectedOptions[0].textContent}? Może to rozpocząć prawdziwe losowanie.`))
      action("reset-delay", {}, "Pominięto oczekiwanie.");
  };
  document.querySelectorAll("[data-delta]").forEach((button) => {
    button.onclick = () => action("counter", { delta: Number(button.dataset.delta) }, "Zaktualizowano licznik.");
  });
  $("modGiftForm").onsubmit = (event) => {
    event.preventDefault();
    const count = Number($("modGiftCount").value);
    if (!Number.isInteger(count) || count < 1 || count > 100) return;
    if (confirm(`Zasymulować ${count} giftów na kanale ${select.selectedOptions[0].textContent}? To zmieni licznik i kolejki na transmisji.`))
      action("simulate-gift", { gift_count: count }, "Symulacja wykonana. Stan transmisji został zmieniony.");
  };
  $("modLogout").onclick = async () => {
    try { await request("/auth/logout", {}); location.assign("/moderator"); }
    catch (error) { notice(error.message, true); }
  };
  async function init() {
    try {
      const data = await request("/mod/channels");
      select.replaceChildren();
      const requested = new URLSearchParams(location.search).get("channel");
      data.channels.forEach((channel) => {
        const option = document.createElement("option");
        option.value = String(channel.broadcaster_id);
        option.textContent = channel.display_name || channel.username;
        select.append(option);
      });
      if (requested && !data.channels.some((channel) => String(channel.broadcaster_id) === requested)) {
        const option = new Option("Wybierz dostępny kanał", "", true, true);
        select.prepend(option);
        notice("Nie masz dostępu do kanału z tego linku. Wybierz inny kanał lub poproś streamera o dostęp.", true);
      } else bid = requested || select.value;
      select.disabled = !data.channels.length;
      $("modControls").hidden = !bid;
      await refresh();
    } catch (error) { notice(error.message, true); }
  }
  init();
  setInterval(() => { if (!document.hidden && !busy) refresh(); }, 10000);
})();
