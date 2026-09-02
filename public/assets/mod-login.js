const query = new URLSearchParams(location.search);
const channel = query.get('channel');
const returnPath = channel && /^\d+$/.test(channel) ? `/mod?channel=${encodeURIComponent(channel)}` : '/mod';
document.getElementById('modLogin').href = `/auth/login?ret=${encodeURIComponent(returnPath)}`;
document.getElementById('loginDenied').hidden = query.get('denied') !== '1';
document.getElementById('switchModAccount').onclick = async () => {
  try {
  const response = await fetch('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  document.getElementById('loginStatus').textContent = response.ok ? 'Wylogowano. Możesz teraz zalogować właściwe konto Kick.' : 'Nie udało się wylogować. Spróbuj ponownie.';
  } catch {
    document.getElementById('loginStatus').textContent = 'Brak połączenia. Spróbuj ponownie.';
  }
};
