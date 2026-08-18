document.querySelector("#logoutAllButton")?.addEventListener("click", async () => {
  const status = document.querySelector("#sessionSummary");
  try {
    const response = await fetch("/auth/logout-all", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Nie udało się wylogować urządzeń.");
    location.assign(data.redirect || "/");
  } catch (error) {
    if (status) status.textContent = error.message;
  }
});

fetch("/account/sessions", { cache: "no-store" })
  .then((response) => response.ok ? response.json() : null)
  .then((data) => {
    const status = document.querySelector("#sessionSummary");
    if (!status || !Array.isArray(data?.sessions)) return;
    const count = data.sessions.length;
    status.textContent = count === 1
      ? "Masz jedną aktywną sesję — tę przeglądarkę."
      : `Masz ${count} aktywne sesje. Możesz unieważnić je wszystkie jednym kliknięciem.`;
  })
  .catch(() => {});
