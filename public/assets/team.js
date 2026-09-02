(() => {
  const el = id => document.getElementById(id);
  const notice = (message, error = false) => { el('teamNotice').textContent = message; el('teamNotice').setAttribute('role', error ? 'alert' : 'status'); };
  async function request(url, options = {}) {
    const response = await fetch(url, { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json' } });
    const data = await response.json().catch(() => null);
    if (!response.ok || !data) throw new Error(data?.error || 'Nie udało się pobrać danych. Spróbuj ponownie lub zaloguj się.');
    return data;
  }
  function renderModerators(items) {
    const list = el('moderatorList'); list.replaceChildren();
    if (!items.length) { const empty = document.createElement('li'); empty.textContent = 'Nie dodano jeszcze moderatorów.'; list.append(empty); }
    items.forEach(item => {
      const row = document.createElement('li'), name = document.createElement('span'), button = document.createElement('button');
      name.textContent = item.mod_username || String(item.mod_kick_user_id);
      button.type = 'button'; button.textContent = 'Odbierz dostęp'; button.className = 'text-action';
      button.setAttribute('aria-label', `Odbierz dostęp: ${name.textContent}`);
      button.onclick = async () => {
        if (!confirm(`Odebrać dostęp użytkownikowi ${name.textContent}?`)) return;
        button.disabled = true;
        try { const result = await request(`/dashboard/moderators/${item.mod_kick_user_id}`, { method: 'DELETE' }); renderModerators(result.moderators); notice('Dostęp został odebrany.'); }
        catch (error) { notice(error.message, true); button.disabled = false; }
      };
      row.append(name, button); list.append(row);
    });
  }
  el('addModeratorForm').onsubmit = async event => {
    event.preventDefault(); const button = event.currentTarget.querySelector('button'); button.disabled = true;
    try { const data = await request('/dashboard/moderators', { method: 'POST', body: JSON.stringify({ username: el('moderatorName').value.trim() }) }); renderModerators(data.moderators); el('moderatorName').value = ''; notice('Moderator dodany. Teraz wyślij mu link do logowania.'); }
    catch (error) { notice(error.message, true); }
    finally { button.disabled = false; }
  };
  async function copy(id, button) {
    try { if (!el(id).value) return; await navigator.clipboard.writeText(el(id).value); const previous = button.textContent; button.textContent = 'Skopiowano'; setTimeout(() => button.textContent = previous, 2000); }
    catch { el(id).focus(); el(id).select(); button.textContent = 'Zaznaczono link — skopiuj ręcznie'; }
  }
  el('copyModeratorInvite').onclick = event => copy('moderatorInvite', event.currentTarget);
  el('copyActiveSubsUrl').onclick = event => copy('activeSubsUrl', event.currentTarget);
  let subsLoading = false;
  async function refreshSubs() {
    if (subsLoading) return; subsLoading = true; el('refreshActiveSubs').disabled = true;
    try { const data = await request('/dashboard/sub-counter'); if (Number.isFinite(data.active_subscribers_count)) el('activeSubsValue').textContent = data.active_subscribers_count; el('activeSubsStatus').textContent = data.stale ? 'Brak aktualnej odpowiedzi Kicka. Zachowano ostatni wynik, jeśli był dostępny.' : 'Zsynchronizowano z Kickiem · razem z giftami'; }
    catch (error) { el('activeSubsStatus').textContent = error.message; }
    finally { subsLoading = false; el('refreshActiveSubs').disabled = false; }
  }
  el('refreshActiveSubs').onclick = refreshSubs;
  request('/dashboard/status').then(data => {
    el('moderatorInvite').value = `${location.origin}/moderator?channel=${encodeURIComponent(data.broadcaster_user_id)}`;
    el('activeSubsUrl').value = `${location.origin}/subs/${encodeURIComponent(data.overlay_key)}`;
  }).catch(error => notice(error.message, true));
  request('/dashboard/moderators').then(data => renderModerators(data.moderators)).catch(error => notice(error.message, true));
  refreshSubs(); setInterval(() => { if (!document.hidden && !el('activeSubsTitle').closest('section').hidden) refreshSubs(); }, 60000);
})();
