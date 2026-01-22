let PENDING_SPINS_COUNT = 0;
let broadcastFn = null;

function addPending(n) { const x = Number(n)||0; if (x>0) PENDING_SPINS_COUNT += x; }
function consumePending(n) { const want = Math.max(0, Number(n)||0); const take = Math.min(PENDING_SPINS_COUNT, want); PENDING_SPINS_COUNT -= take; return take; }

function broadcast(obj) {
  if (!broadcastFn) return 0;
  return broadcastFn(obj) || 0;
}

export const spins = {
  getPending: () => PENDING_SPINS_COUNT,
  setBroadcaster: (fn) => { broadcastFn = fn; },
  deliverSpinOrQueue(times) {
    const safe = Math.max(0, Number(times)||0);
    if (!safe) return 0;
    const delivered = broadcast({ action: "spin", times: safe });
    if (delivered === 0) { addPending(safe); console.log(`[SPIN] queued +${safe} (pending=${PENDING_SPINS_COUNT})`); }
    else { console.log(`[SPIN] delivered to ${delivered} client(s)`); }
    return delivered;
  },
  addPending,
  consumePending
};


export function wsBroadcast(msg) {
    return broadcast(msg);
}