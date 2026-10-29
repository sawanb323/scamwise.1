// SCAMWISE admin dashboard.
// Authorisation is enforced in Postgres: every admin_* RPC checks admin_users membership AND an
// MFA-verified (aal2) session. This page only decides what to display.
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm';
import { SUPABASE_URL, SUPABASE_KEY } from '../assets/config.js';

const sb = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: true, storageKey: 'scamwise-admin' } });
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const VIEWS = ['login', 'mfa', 'denied', 'app'];
const show = (v) => VIEWS.forEach((x) => $('#view-' + x).classList.toggle('hidden', x !== v));
const short = (id) => esc(String(id ?? '').split('-')[0]);
const when = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now'; if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`; return `${Math.floor(s / 86400)} d ago`;
}
const risk = (r) => `<span class="risk ${esc(r)}">${esc(String(r).toUpperCase())}</span>`;

// ------------------------------------------------------------------ auth flow
async function route() {
  const { data: { session } } = await sb.auth.getSession();
  if (!session) { $('#logout').classList.add('hidden'); $('#who').textContent = ''; return show('login'); }
  $('#who').textContent = session.user.email ?? '';
  $('#logout').classList.remove('hidden');

  const { data: who, error } = await sb.rpc('admin_whoami');
  if (error) { $('#login-error').textContent = error.message; return show('login'); }
  if (!who.is_member) return show('denied');

  const { data: aal } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
  if (aal?.currentLevel !== 'aal2') return startMfa();
  if (!who.is_admin) {           // refresh JWT so the aal2 claim is present
    await sb.auth.refreshSession();
    const again = await sb.rpc('admin_whoami');
    if (!again.data?.is_admin) return show('denied');
  }
  show('app');
  loadAll();
}

let mfaFactorId = null;
async function startMfa() {
  show('mfa');
  $('#mfa-error').textContent = '';
  const { data: f, error } = await sb.auth.mfa.listFactors();
  if (error) { $('#mfa-error').textContent = error.message; return; }
  const verified = (f.totp || []).filter((x) => x.status === 'verified');
  if (verified.length) {
    mfaFactorId = verified[0].id;
    $('#mfa-enroll').classList.add('hidden');
    $('#mfa-title').textContent = 'Two-step verification';
    return;
  }
  // first login: clean up abandoned enrolments, then enrol a new TOTP factor
  for (const x of (f.all || []).filter((x) => x.status !== 'verified')) await sb.auth.mfa.unenroll({ factorId: x.id });
  const { data: en, error: enErr } = await sb.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'SCAMWISE admin ' + new Date().toISOString().slice(0, 10) });
  if (enErr) { $('#mfa-error').textContent = enErr.message; return; }
  mfaFactorId = en.id;
  $('#mfa-title').textContent = 'Set up two-step verification';
  $('#mfa-qr').src = en.totp.qr_code;
  $('#mfa-secret').textContent = en.totp.secret;
  $('#mfa-enroll').classList.remove('hidden');
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  $('#login-error').textContent = '';
  const { error } = await sb.auth.signInWithPassword({ email: f.get('email'), password: f.get('password') });
  if (error) { $('#login-error').textContent = error.message.includes('Invalid') ? 'Incorrect email or password.' : error.message; return; }
  e.target.reset();
  route();
});

$('#mfa-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = new FormData(e.target).get('code');
  const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: mfaFactorId, code });
  if (error) { $('#mfa-error').textContent = 'That code is not valid. Check the time on your phone and try again.'; return; }
  e.target.reset();
  route();
});

for (const id of ['#logout', '#denied-logout']) $(id).onclick = async () => { await sb.auth.signOut(); stopLive(); route(); };

// ------------------------------------------------------------------ dashboard
let tab = 'overview';
document.querySelectorAll('.side button').forEach((b) => (b.onclick = () => {
  document.querySelectorAll('.side button').forEach((x) => x.classList.toggle('on', x === b));
  tab = b.dataset.tab;
  ['overview', 'users', 'devices', 'incidents', 'audit', 'feedback'].forEach((t) => $('#tab-' + t).classList.toggle('hidden', t !== tab));
  $('#tab-title').textContent = b.textContent.replace(/^\S+\s/, '');
  loadAll();
}));
$('#refresh').onclick = () => loadAll();
$('#risk-filter').onchange = () => loadAll();

let timer = null;
function stopLive() { clearInterval(timer); timer = null; }
function startLive() { stopLive(); if ($('#live').checked) timer = setInterval(loadAll, 15000); }
$('#live').onchange = startLive;

async function rpc(name, params) {
  const { data, error } = await sb.rpc(name, params);
  if (error) {
    if (/admin_required/.test(error.message)) { stopLive(); route(); }
    throw error;
  }
  return data;
}

async function loadAll() {
  try {
    if (tab === 'overview') await loadOverview();
    if (tab === 'users') await loadUsers();
    if (tab === 'devices') await loadDevices();
    if (tab === 'incidents') await loadIncidents();
    if (tab === 'audit') await loadAudit();
    if (tab === 'feedback') await loadFeedback();
    $('#refreshed').textContent = 'Last refreshed ' + new Date().toLocaleTimeString();
    if (!timer) startLive();
  } catch (e) {
    $('#refreshed').textContent = 'Refresh failed: ' + (e.message || e);
  }
}

function bars(el, obj, colors) {
  const total = Object.values(obj).reduce((a, b) => a + b, 0) || 1;
  el.innerHTML = Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, v]) => `
    <div class="row"><span>${esc(k)}</span><div class="bar" style="margin:0"><i style="width:${(v / total) * 100}%;background:${colors[k] || 'var(--teal)'}"></i></div><b>${v}</b></div>`).join('') || '<p class="note">No data yet.</p>';
}

async function loadOverview() {
  const o = await rpc('admin_overview');
  const k = [
    ['Registered users', o.users], ['Registered devices', o.devices_total],
    ['Online now (2 min)', o.devices_online], ['Synced in last 15 min', o.devices_synced_15m],
    ['Active / pending / revoked', `${o.devices_active} / ${o.devices_pending} / ${o.devices_revoked}`],
    ['Total analysed items', o.analysed_total], ['Analysed in last 24 h', o.analysed_24h],
    ['Auth-code exposure events', o.auth_code_events],
  ];
  try {
    const s = await rpc('admin_plan_summary');
    k.push(['Paid subscribers', s.paid_active], ['On free trial', s.trial], ['Expired', s.expired],
      ['Monthly revenue (₹)', Number(s.mrr_inr).toLocaleString('en-IN')]);
  } catch { /* subscriptions migration not applied yet */ }
  $('#kpis').innerHTML = k.map(([l, v]) => `<div class="kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join('');
  bars($('#riskbars'), o.risk || {}, { high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', inconclusive: 'var(--inc)' });
  bars($('#tibars'), o.ti || {}, { match: 'var(--high)', no_match: 'var(--inc)', not_configured: 'var(--medium)', unavailable: 'var(--medium)', not_applicable: 'var(--line)' });
  const rows = await rpc('admin_list_incidents', { p_limit: 8, p_risk: null });
  $('#recent').innerHTML = incidentRows(rows, false);
}

function incidentRows(rows, actions) {
  if (!rows.length) return '<tr><td class="note">No incidents shared with administrators yet.</td></tr>';
  return `<tr><th>Time</th><th>Incident</th><th>Account / device</th><th>Risk</th><th>Category</th><th>Threat intel</th><th>Status</th>${actions ? '<th></th>' : ''}</tr>` +
    rows.map((r) => `<tr data-id="${esc(r.id)}">
      <td>${esc(ago(r.created_at))}<div class="note">${esc(when(r.created_at))}</div></td>
      <td class="mono"><a href="#" data-open="${esc(r.id)}">${short(r.id)}</a></td>
      <td>${esc(r.account_phone ?? '—')}<div class="note">${esc(r.device_name ?? '')} · ${esc(r.source)}</div></td>
      <td>${risk(r.risk_level)} <b>${r.score}</b>${r.contained_auth_code ? '<div class="note">🔒 code redacted</div>' : ''}</td>
      <td>${esc(r.category)}<div class="note">${(r.indicators || []).length} indicator(s)</div></td>
      <td><span class="pill">${esc(r.ti_status)}</span></td>
      <td>${actions ? `<select data-status="${esc(r.id)}" style="padding:6px;width:auto">${['open', 'acknowledged', 'resolved', 'false_positive'].map((s) => `<option ${s === r.status ? 'selected' : ''}>${s}</option>`).join('')}</select>` : esc(r.status)}</td>
      ${actions ? `<td><button class="btn small" style="background:var(--line)" data-del="${esc(r.id)}">Delete</button></td>` : ''}
    </tr>`).join('');
}

let incidentCache = [];
async function loadIncidents() {
  incidentCache = await rpc('admin_list_incidents', { p_limit: 200, p_risk: $('#risk-filter').value || null });
  $('#incidents').innerHTML = incidentRows(incidentCache, true);
}

document.addEventListener('click', async (e) => {
  const t = e.target;
  if (t.dataset?.open) {
    e.preventDefault();
    let r = incidentCache.find((x) => x.id === t.dataset.open);
    if (!r) r = (await rpc('admin_list_incidents', { p_limit: 500, p_risk: null })).find((x) => x.id === t.dataset.open);
    if (r) openIncident(r);
  }
  if (t.dataset?.del) {
    const reason = prompt('Reason for deleting this incident record (recorded in the audit log):');
    if (reason === null) return;
    try { await rpc('admin_delete_incident', { p_incident: t.dataset.del, p_reason: reason }); loadAll(); } catch (err) { alert(err.message); }
  }
  if (t.dataset?.revoke) {
    const reason = prompt('Reason for unlinking this device (recorded in the audit log). Its session will be ended immediately:');
    if (reason === null) return;
    try { await rpc('admin_revoke_device', { p_device: t.dataset.revoke, p_reason: reason }); loadAll(); } catch (err) { alert(err.message); }
  }
  if (t.dataset?.close) $('#drawer').classList.add('hidden');
});
document.addEventListener('change', async (e) => {
  const id = e.target.dataset?.status;
  if (!id) return;
  try { await rpc('admin_set_incident_status', { p_incident: id, p_status: e.target.value, p_note: 'set from dashboard' }); } catch (err) { alert(err.message); }
});

function openIncident(r) {
  const d = $('#drawer');
  d.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">Incident ${short(r.id)}</h3><button class="btn small" style="background:var(--line)" data-close="1">Close</button></div>
    <p class="mono note">${esc(r.id)}</p>
    <p>${risk(r.risk_level)} score <b>${r.score}/100</b> · ${esc(r.category)}</p>
    <table>
      <tr><th>Time</th><td>${esc(when(r.created_at))}</td></tr>
      <tr><th>Account</th><td>${esc(r.account_phone ?? '—')} <span class="mono note">${short(r.account_id)}</span></td></tr>
      <tr><th>Device</th><td>${esc(r.device_name ?? '—')} <span class="mono note">${short(r.device_id)}</span></td></tr>
      <tr><th>Source</th><td>${esc(r.source)}</td></tr>
      <tr><th>Method</th><td>${esc(r.analysis_method)} (engine ${esc(r.engine_version)})</td></tr>
      <tr><th>Threat intel</th><td><span class="pill">${esc(r.ti_status)}</span>${r.ti_detail?.matches?.length ? '<div class="note">' + r.ti_detail.matches.map((m) => esc(`${m.match_type} match: ${m.threat} (${m.url_status})`)).join('<br>') + '</div>' : ''}</td></tr>
      <tr><th>Domains</th><td class="mono">${esc((r.url_domains || []).join(', ') || '—')}</td></tr>
      <tr><th>Auth code</th><td>${r.contained_auth_code ? 'Present – redacted on the device, never transmitted' : 'No'}</td></tr>
      <tr><th>Status</th><td>${esc(r.status)}</td></tr>
    </table>
    <h3 style="margin-top:18px">Indicators</h3>
    ${(r.indicators || []).map((i) => `<div class="ind"><b>+${esc(i.weight)}</b><div><b>${esc(i.label)}</b><div class="note">${esc(i.code)}${i.detail ? ' · ' + esc(i.detail) : ''}</div></div></div>`).join('') || '<p class="note">None</p>'}
    <h3 style="margin-top:18px">Message content</h3>
    <p class="note">${r.redacted_excerpt ? 'User opted in to a masked excerpt:<br>' + esc(r.redacted_excerpt) : 'Not stored. SCAMWISE does not keep message text.'}</p>`;
  d.classList.remove('hidden');
}

async function loadDevices() {
  const rows = await rpc('admin_list_devices', { p_limit: 300 });
  $('#devices').innerHTML = !rows.length ? '<tr><td class="note">No devices registered yet.</td></tr>' :
    `<tr><th>Device</th><th>Platform / app</th><th>Account</th><th>Status</th><th>Connection</th><th>Registered</th><th>Approved</th><th></th></tr>` +
    rows.map((d) => {
      const online = d.status === 'active' && d.last_seen_at && Date.now() - new Date(d.last_seen_at).getTime() < 120000;
      return `<tr>
        <td><b>${esc(d.name)}</b>${d.is_primary ? ' <span class="pill">first</span>' : ''}<div class="mono note">${short(d.id)}</div></td>
        <td>${esc(d.platform ?? '—')}<div class="note">app ${esc(d.app_version ?? '—')}</div></td>
        <td>${esc(d.account_phone ?? '—')}<div class="mono note">${short(d.account_id)}</div></td>
        <td><span class="pill ${esc(d.status)}">${esc(d.status)}</span>${d.revoked_reason ? `<div class="note">${esc(d.revoked_reason)}</div>` : ''}</td>
        <td>${online ? '<span class="pill online">online</span>' : `<span class="note">last seen ${esc(ago(d.last_seen_at))}</span>`}</td>
        <td class="note">${esc(when(d.created_at))}</td>
        <td class="note">${esc(when(d.approved_at))}</td>
        <td>${d.status !== 'revoked' ? `<button class="btn small" style="background:rgba(220,38,38,.12);color:var(--high)" data-revoke="${esc(d.id)}">Unlink</button>` : ''}</td>
      </tr>`;
    }).join('');
}

// ------------------------------------------------------------------ users & plans
const PLANS = {
  trial: { name: 'Free trial', price: 0, devices: 1 },
  individual: { name: 'Individual', price: 299, devices: 1 },
  family: { name: 'Family', price: 699, devices: 3 },
  business: { name: 'Business', price: 1899, devices: 8 },
  enterprise: { name: 'Enterprise & Banking', price: null, devices: 25 },
};
const stateTag = (u) => u.plan_state === 'expired' ? '<span class="pill revoked">expired</span>'
  : u.plan_state === 'trial' ? '<span class="pill pending">trial</span>' : '<span class="pill active">active</span>';
const day = (iso) => (iso ? new Date(iso).toLocaleDateString() : '—');
let userCache = [];

function filteredUsers() {
  const q = $('#user-search').value.trim().toLowerCase();
  const pf = $('#plan-filter').value, sf = $('#state-filter').value;
  return userCache.filter((u) =>
    (!q || [u.email, u.display_name, u.phone].some((x) => String(x ?? '').toLowerCase().includes(q))) &&
    (!pf || u.plan === pf) &&
    (!sf || (sf === 'expiring' ? u.plan_state !== 'expired' && u.days_left <= 7 : u.plan_state === sf)));
}

async function loadUsers() {
  const [rows, s] = await Promise.all([rpc('admin_list_users', { p_limit: 2000 }), rpc('admin_plan_summary')]);
  userCache = rows;
  const bp = s.by_plan || {};
  $('#plan-kpis').innerHTML = [
    ['Total users', rows.length], ['Paid active', s.paid_active], ['On trial', s.trial], ['Expired', s.expired],
    ['Expiring in 7 days', s.expiring_7d], ['Monthly revenue (₹)', Number(s.mrr_inr).toLocaleString('en-IN')],
    ['Individual / Family', `${bp.individual || 0} / ${bp.family || 0}`], ['Business / Enterprise', `${bp.business || 0} / ${bp.enterprise || 0}`],
  ].map(([l, v]) => `<div class="kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join('');
  renderUsers();
}

function renderUsers() {
  const rows = filteredUsers();
  $('#user-count').textContent = `${rows.length} of ${userCache.length} users`;
  $('#users').innerHTML = !rows.length ? '<tr><td class="note">No users match.</td></tr>' :
    `<tr><th>User</th><th>Plan</th><th>Validity</th><th>Devices</th><th>Usage</th><th>Joined / last active</th><th></th></tr>` +
    rows.map((u) => {
      const over = u.devices_total - u.devices_revoked > u.device_limit;
      return `<tr>
        <td><b>${esc(u.display_name || '—')}</b><div>${esc(u.email ?? '—')}${u.email_confirmed ? '' : ' <span class="note">(unconfirmed)</span>'}</div><div class="note">${esc(u.phone ?? '')} <span class="mono">${short(u.id)}</span></div></td>
        <td><b>${esc(PLANS[u.plan]?.name ?? u.plan)}</b> ${stateTag(u)}<div class="note">₹${Number(u.price_inr).toLocaleString('en-IN')}/month${u.plan_note ? ' · ' + esc(u.plan_note) : ''}</div></td>
        <td>${esc(day(u.plan_started_at))} → <b>${esc(day(u.plan_expires_at))}</b><div class="note">${u.plan_state === 'expired' ? 'expired ' + esc(ago(u.plan_expires_at)) : `${u.days_left} day(s) left`}</div></td>
        <td><b style="${over ? 'color:var(--high)' : ''}">${u.devices_total - u.devices_revoked} / ${u.device_limit}</b>${over ? ' <span class="note" style="color:var(--high)">over limit</span>' : ''}
          <div class="note">${u.devices_active} active · ${u.devices_pending} pending · ${u.devices_revoked} revoked${u.devices_online ? ` · <span class="pill online">${u.devices_online} online</span>` : ''}</div></td>
        <td>${u.scans_total} scans<div class="note">${u.scans_high} high-risk${u.plan === 'trial' ? ` · trial ${u.checks_today}/2 today, ${u.checks_total}/14` : ''}</div></td>
        <td class="note">${esc(day(u.joined_at))}<div>active ${esc(ago(u.last_seen_at || u.last_sign_in_at))}</div></td>
        <td><button class="btn btn-dark small" data-user="${esc(u.id)}">Manage</button></td>
      </tr>`;
    }).join('');
}
['#user-search', '#plan-filter', '#state-filter'].forEach((s) => $(s).addEventListener('input', renderUsers));

const isoDate = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
function addDays(base, n) { const d = new Date(base); d.setDate(d.getDate() + n); return d; }

function openUser(u) {
  const d = $('#drawer');
  const exp = new Date(u.plan_expires_at);
  const renewBase = exp > new Date() ? exp : new Date();
  d.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">${esc(u.display_name || u.email)}</h3><button class="btn small" style="background:var(--line)" data-close="1">Close</button></div>
    <p class="mono note">${esc(u.id)}</p>
    <table>
      <tr><th>Email</th><td>${esc(u.email ?? '—')}${u.email_confirmed ? '' : ' (unconfirmed)'}</td></tr>
      <tr><th>Phone</th><td>${esc(u.phone ?? '—')}</td></tr>
      <tr><th>Joined</th><td>${esc(when(u.joined_at))}</td></tr>
      <tr><th>Last sign-in</th><td>${esc(when(u.last_sign_in_at))}</td></tr>
      <tr><th>Current plan</th><td>${esc(PLANS[u.plan]?.name ?? u.plan)} ${stateTag(u)}</td></tr>
      <tr><th>Validity</th><td>${esc(when(u.plan_started_at))} → ${esc(when(u.plan_expires_at))}</td></tr>
      <tr><th>Devices</th><td>${u.devices_total - u.devices_revoked} of ${u.device_limit} used<div class="note">${(u.device_names || []).map(esc).join('<br>') || 'none'}</div></td></tr>
      <tr><th>Scans</th><td>${u.scans_total} total · ${u.scans_high} high-risk · ${u.checks_total} counted this plan</td></tr>
    </table>
    <h3 style="margin-top:18px">Change plan</h3>
    <form id="plan-form">
      <label class="note">Plan</label>
      <select name="plan">${Object.entries(PLANS).map(([k, p]) => `<option value="${k}" ${k === u.plan ? 'selected' : ''}>${esc(p.name)}${p.price != null ? ` · ₹${p.price.toLocaleString('en-IN')}/mo · ${p.devices} device${p.devices > 1 ? 's' : ''}` : ' · custom'}</option>`).join('')}</select>
      <div id="ent-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px">
        <div><label class="note">Device limit</label><input name="devices" type="number" min="1" value="${esc(u.device_limit_override ?? '')}" placeholder="25"></div>
        <div><label class="note">Price ₹/month</label><input name="price" type="number" min="0" value="${u.plan === 'enterprise' ? esc(u.price_inr) : ''}"></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px">
        <div><label class="note">Start date</label><input name="start" type="date" value="${isoDate(new Date(u.plan_started_at))}"></div>
        <div><label class="note">Valid until</label><input name="expires" type="date" required value="${isoDate(exp)}"></div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
        ${[[30, '+1 month'], [90, '+3 months'], [180, '+6 months'], [365, '+1 year']].map(([n, l]) => `<button type="button" class="btn small" style="background:var(--line)" data-extend="${n}">${l}</button>`).join('')}
        <button type="button" class="btn small" style="background:rgba(220,38,38,.12);color:var(--high)" data-expire-now="1">Expire now</button>
      </div>
      <label class="note" style="display:block;margin-top:8px">Note (payment ref, invoice no.)</label>
      <input name="note" maxlength="300" value="${esc(u.plan_note ?? '')}">
      <label class="note" style="display:flex;gap:6px;align-items:center;margin-top:8px"><input type="checkbox" name="reset" style="width:auto"> Reset check counters</label>
      <button class="btn btn-dark" style="margin-top:12px;width:100%" type="submit">Save plan</button>
      <p class="note" id="plan-msg"></p>
    </form>`;
  d.classList.remove('hidden');
  const f = $('#plan-form');
  const syncEnt = () => { $('#ent-fields').style.display = f.plan.value === 'enterprise' ? 'grid' : 'none'; };
  f.plan.onchange = syncEnt; syncEnt();
  d.querySelectorAll('[data-extend]').forEach((b) => (b.onclick = () => {
    if (!f.start.value || new Date(u.plan_expires_at) <= new Date()) f.start.value = isoDate(new Date());
    f.expires.value = isoDate(addDays(renewBase, +b.dataset.extend));
  }));
  let expireNow = false;
  f.expires.oninput = () => { expireNow = false; };
  d.querySelectorAll('[data-extend]').forEach((b) => b.addEventListener('click', () => { expireNow = false; }));
  d.querySelector('[data-expire-now]').onclick = () => { f.expires.value = isoDate(new Date()); expireNow = true; $('#plan-msg').textContent = 'Will expire immediately when saved.'; };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const expires = expireNow ? new Date() : new Date(f.expires.value + 'T23:59:59');   // valid through the end of that day
    try {
      await rpc('admin_set_plan', {
        p_user: u.id, p_plan: f.plan.value,
        p_expires_at: expires.toISOString(),
        p_started_at: f.start.value ? new Date(f.start.value + 'T00:00:00').toISOString() : null,
        p_device_limit: f.plan.value === 'enterprise' && f.devices.value ? +f.devices.value : null,
        p_custom_price: f.plan.value === 'enterprise' && f.price.value ? +f.price.value : null,
        p_note: f.note.value, p_reset_checks: f.reset.checked,
      });
      $('#plan-msg').textContent = 'Saved.';
      await loadUsers();
      const fresh = userCache.find((x) => x.id === u.id);
      if (fresh) openUser(fresh);
    } catch (err) { $('#plan-msg').textContent = err.message; }
  };
}
document.addEventListener('click', (e) => {
  const id = e.target.dataset?.user;
  if (!id) return;
  const u = userCache.find((x) => x.id === id);
  if (u) openUser(u);
});

$('#export-users').onclick = () => {
  const cols = ['email', 'display_name', 'phone', 'plan', 'plan_state', 'plan_started_at', 'plan_expires_at', 'days_left', 'price_inr',
    'device_limit', 'devices_active', 'devices_pending', 'devices_revoked', 'scans_total', 'scans_high', 'checks_total', 'joined_at', 'last_seen_at', 'plan_note'];
  const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = [cols.join(','), ...filteredUsers().map((u) => cols.map((c) => q(u[c])).join(','))].join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = `scamwise-users-${isoDate(new Date())}.csv`;
  a.click();
};

async function loadAudit() {
  const rows = await rpc('admin_audit_log', { p_limit: 200 });
  $('#audit').innerHTML = `<tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>` +
    rows.map((a) => `<tr><td>${a.id}</td><td class="note">${esc(when(a.at))}</td><td>${esc(a.actor_kind)} <span class="mono note">${short(a.actor_id)}</span></td>
      <td><b>${esc(a.action)}</b></td><td class="mono note">${esc(a.target_type ?? '')} ${short(a.target_id)}</td><td class="mono note">${esc(a.detail ? JSON.stringify(a.detail) : '')}</td></tr>`).join('');
}

async function loadFeedback() {
  const rows = await rpc('admin_list_feedback', { p_limit: 200 });
  $('#feedback').innerHTML = !rows.length ? '<tr><td class="note">No feedback yet.</td></tr>' :
    `<tr><th>Time</th><th>From</th><th>Type</th><th>Message</th></tr>` +
    rows.map((f) => `<tr><td class="note">${esc(when(f.created_at))}</td><td>${esc(f.name ?? '—')}<div class="note">${esc(f.email ?? '')}</div></td><td>${esc(f.kind)}</td><td>${esc(f.message)}</td></tr>`).join('');
}

sb.auth.onAuthStateChange((evt) => { if (evt === 'SIGNED_OUT') { stopLive(); show('login'); } });
route();
