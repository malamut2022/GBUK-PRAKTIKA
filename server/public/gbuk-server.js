/* ГБУК-ПРАКТИКА — подключение приложения к серверу театра.
 * Загружается только в серверной версии (после входа), до основных скриптов приложения.
 * Общие данные (дела, реестр договоров, настройки налогового календаря) хранятся на сервере;
 * личные настройки (история Глафиры, положение окна и т.п.) — в браузере, отдельно для каждого пользователя. */
(function () {
  'use strict';
  const B = window.__GBUK_BOOT__;
  if (!B || !B.user) return;
  const user = B.user;
  window.__GBUK_SERVER__ = { user };
  const SHARED = ['gbuk_praktika_v9_events', 'gbuk_praktika_contract_registry_v1', 'gbuk_praktika_tax_settings_v1'];
  const SP = Storage.prototype, oGet = SP.getItem, oSet = SP.setItem, oRem = SP.removeItem;
  const isApp = k => typeof k === 'string' && k.startsWith('gbuk_');
  const ns = k => 'u:' + user.login + ':' + k;
  const bases = {};
  let rev = B.rev;
  for (const k of SHARED) {
    const v = B.values[k];
    bases[k] = v == null ? null : v;
    try { if (v == null) oRem.call(localStorage, k); else oSet.call(localStorage, k, v); } catch {}
  }
  SP.getItem = function (k) { return this === localStorage && isApp(k) && !SHARED.includes(k) ? oGet.call(this, ns(k)) : oGet.call(this, k); };
  SP.setItem = function (k, v) {
    if (this === localStorage && isApp(k)) {
      if (SHARED.includes(k)) { oSet.call(this, k, String(v)); queue(k); return; }
      return oSet.call(this, ns(k), String(v));
    }
    return oSet.call(this, k, v);
  };
  SP.removeItem = function (k) { return this === localStorage && isApp(k) && !SHARED.includes(k) ? oRem.call(this, ns(k)) : oRem.call(this, k); };

  /* ---------- api ---------- */
  async function api(method, url, body, headers) {
    const r = await fetch(url, { method, credentials: 'same-origin', headers: { 'X-GBUK': '1', ...(body && typeof body === 'string' ? { 'Content-Type': 'application/json' } : {}), ...(headers || {}) }, body });
    if (r.status === 401) { location.href = '/login'; throw new Error('Нужно войти'); }
    const j = r.headers.get('content-type') || '';
    const data = j.includes('json') ? await r.json().catch(() => ({})) : null;
    if (!r.ok) { const e = new Error((data && data.error) || 'Ошибка сервера'); e.status = r.status; if (data && data.name) e.name = data.name; throw e; }
    return data;
  }
  window.gbukApi = api;

  /* ---------- sync of shared data ---------- */
  const pending = new Set(); let timer = null, flushing = false, offline = false;
  function queue(k) { pending.add(k); clearTimeout(timer); timer = setTimeout(flush, 350); }
  function apply(k, v) {
    try {
      if (k === 'gbuk_praktika_v9_events' && typeof events !== 'undefined') { events = JSON.parse(v || '[]'); if (typeof render === 'function') render(); }
      if (k === 'gbuk_praktika_contract_registry_v1' && window.gbukRegistry) window.gbukRegistry.set(JSON.parse(v || '[]'));
    } catch {}
  }
  function banner(on) {
    let b = document.getElementById('srvOffline');
    if (!on) { if (b) b.remove(); offline = false; return; }
    offline = true;
    if (!b && document.body) {
      b = document.createElement('div'); b.id = 'srvOffline'; b.setAttribute('role', 'alert');
      b.textContent = 'Нет связи с сервером — последние изменения пока не сохранены. Не закрывайте страницу, приложение повторит попытку.';
      document.body.prepend(b);
    }
  }
  async function flush() {
    if (flushing) { clearTimeout(timer); timer = setTimeout(flush, 300); return; }
    flushing = true;
    try {
      for (const k of [...pending]) {
        pending.delete(k);
        const value = oGet.call(localStorage, k);
        if (value == null) continue;
        try {
          const res = await api('POST', '/api/state', JSON.stringify({ key: k, base: bases[k], value }));
          bases[k] = res.value; rev = res.rev; banner(false);
          if (res.value !== value && !pending.has(k)) { oSet.call(localStorage, k, res.value); apply(k, res.value); note('Данные объединены с изменениями коллег'); }
        } catch (e) {
          pending.add(k);
          if (e.status && e.status < 500 && e.status !== 429) { pending.delete(k); note('Не удалось сохранить: ' + e.message); }
          else { banner(true); clearTimeout(timer); timer = setTimeout(flush, 5000); }
        }
      }
    } finally { flushing = false; }
  }
  async function poll() {
    if (pending.size || flushing || document.hidden) return;
    try {
      const res = await api('GET', '/api/state?since=' + rev);
      if (offline) banner(false);
      if (!res.values || res.rev === rev) return;
      let changed = false;
      for (const k of SHARED) {
        if (pending.has(k)) continue;
        const v = res.values[k];
        if (v != null && v !== oGet.call(localStorage, k)) { oSet.call(localStorage, k, v); bases[k] = v; apply(k, v); changed = true; }
        else bases[k] = v;
      }
      rev = res.rev;
      if (changed) note('Обновлено: внесены изменения коллег');
    } catch (e) { if (!e.status) banner(true); }
  }
  setInterval(poll, 15000);
  window.addEventListener('focus', poll);
  window.addEventListener('beforeunload', e => { if (pending.size || offline) { flush(); e.preventDefault(); e.returnValue = ''; } });
  function note(t) { if (typeof toast === 'function') toast(t); }

  /* ---------- interface ---------- */
  const css = `#backupNudge{display:none!important}#srvOffline{position:sticky;top:0;z-index:9998;background:#a5403a;color:#fff;padding:10px 16px;font-size:14px;text-align:center}
.userbox{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:14px;color:#43534a}.userbox strong{color:#264c3b}.userbox button{background:#f2f5f1;border:1px solid #dbe4dc;border-radius:9px;padding:7px 10px;cursor:pointer;color:#385744;font:inherit;font-size:13px}
.userbox .role{font-size:12px;padding:3px 8px;border-radius:20px;background:#edf2ec;color:#41614e}
#access table{width:100%;border-collapse:collapse;font-size:14px}#access th,#access td{text-align:left;padding:9px 8px;border-top:1px solid #edf0eb;vertical-align:middle}#access th{font-size:12px;color:#747d76;border-top:0}
#access .pw{font:600 18px ui-monospace,Menlo,monospace;letter-spacing:.04em;background:#f6f5f0;border:1px dashed #b9d1bd;padding:10px 12px;border-radius:9px;display:inline-block;margin:6px 0}
#access .audit div{font-size:13px;padding:6px 0;border-top:1px solid #f0f2ee;color:#4b5650}@media(max-width:700px){#access .hide-m{display:none}}`;
  const ROLE_ACTIONS = { 'login.ok': 'вход', 'login.fail': 'неудачный вход', 'login.locked': 'вход заблокирован (много попыток)', logout: 'выход', 'password.change': 'сменил(а) пароль', 'password.fail': 'неверный текущий пароль',
    'user.create': 'создан доступ бухгалтера', 'user.reset': 'сброшен пароль', 'user.disable': 'доступ заблокирован', 'user.enable': 'доступ разблокирован', 'user.delete': 'доступ удалён', 'user.reset.cli': 'пароль сброшен администратором',
    'data.save': 'изменены данные', 'docs.file': 'загружен файл', 'docs.save': 'сохранён документ', 'docs.trash': 'документ в корзине', 'docs.restore': 'документ восстановлен', 'docs.delete': 'документ удалён навсегда', 'docs.quota': 'не хватило места', 'trash.purge': 'очищена корзина', init: 'первичная настройка' };
  const KEY_NAMES = { gbuk_praktika_v9_events: 'дела и сроки', gbuk_praktika_contract_registry_v1: 'реестр договоров', gbuk_praktika_tax_settings_v1: 'настройки налогов' };
  const h = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const when = v => v ? new Date(v).toLocaleString('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';

  function setupUi() {
    const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
    document.documentElement.classList.add('srv-mode');
    const ver = document.getElementById('appVersion'); if (ver) ver.textContent = ver.textContent.replace('· демо', '· сервер театра');
    const foot = document.querySelector('footer'); if (foot) foot.textContent = foot.textContent.replace('локальный демонстрационный прототип', 'сервер театра «Практика»');
    const header = document.querySelector('header');
    if (header) {
      const box = document.createElement('div'); box.className = 'userbox';
      box.innerHTML = `<span>👤 <strong>${h(user.name)}</strong></span><span class="role">${h(user.roleName)}</span><button type="button" id="srvPw">Сменить пароль</button><button type="button" id="srvLogout">Выйти</button>`;
      const th = header.querySelector('.theatre'); header.insertBefore(box, th || null);
      box.querySelector('#srvPw').onclick = () => { location.href = '/change-password'; };
      box.querySelector('#srvLogout').onclick = async () => { if (pending.size) await flush(); try { await api('POST', '/api/logout', '{}'); } catch {} location.href = '/login'; };
    }
    if (user.role === 'owner') setupAccess();
  }

  function setupAccess() {
    const groupBtn = document.querySelector('nav button[data-page="data"]');
    const btn = document.createElement('button'); btn.dataset.page = 'access'; btn.textContent = '🔑 Доступы';
    if (groupBtn && groupBtn.parentElement) groupBtn.parentElement.appendChild(btn); else document.getElementById('nav').appendChild(btn);
    const main = document.querySelector('main');
    const sec = document.createElement('section'); sec.id = 'access'; sec.className = 'hidden';
    sec.innerHTML = `<h1>Доступы</h1><p class="sub">Кто может входить в приложение. Вы можете выдавать доступ только бухгалтерам.</p>
<div class="panel"><h2>Пользователи</h2><div id="accUsers" style="overflow-x:auto"></div></div>
<div class="panel"><h2>Выдать доступ бухгалтеру</h2><div class="fields"><div><label for="accName">Имя и фамилия</label><input id="accName" maxlength="80" placeholder="Например, Анна Смирнова"></div>
<div><label for="accLogin">Логин</label><input id="accLogin" maxlength="32" placeholder="латиницей, например a.smirnova" autocapitalize="none" spellcheck="false"></div></div>
<button class="primary" type="button" id="accCreate">Создать доступ</button><div id="accResult" style="margin-top:12px" role="status"></div>
<p class="hint">Бухгалтер получит временный пароль и при первом входе задаст свой. Передайте временный пароль лично, не в общем чате. Доступ можно в любой момент заблокировать или удалить.</p></div>
<div class="panel"><h2>Журнал входов и действий</h2><div class="audit" id="accAudit"></div></div>`;
    const foot = main.querySelector('footer'); if (foot && foot.parentNode) foot.parentNode.insertBefore(sec, foot); else main.appendChild(sec);
    btn.onclick = () => { const g = btn.closest('details'); if (g) g.open = true; if (typeof page === 'function') page('access'); else { document.querySelectorAll('main section').forEach(s => s.classList.toggle('hidden', s.id !== 'access')); } document.querySelectorAll('nav button').forEach(x => x.classList.toggle('active', x === btn)); loadAccess(); };
    sec.querySelector('#accCreate').onclick = async () => {
      const name = sec.querySelector('#accName').value.trim(), login = sec.querySelector('#accLogin').value.trim().toLowerCase(), out = sec.querySelector('#accResult');
      out.textContent = '';
      try {
        const r = await api('POST', '/api/users', JSON.stringify({ name, login }));
        out.innerHTML = `Доступ создан. Логин: <strong>${h(r.login)}</strong><br>Временный пароль (показывается один раз):<br><span class="pw">${h(r.tempPassword)}</span>`;
        sec.querySelector('#accName').value = ''; sec.querySelector('#accLogin').value = ''; loadAccess();
      } catch (e) { out.textContent = e.message; }
    };
    sec.addEventListener('click', async e => {
      const b = e.target.closest('button[data-acc]'); if (!b) return;
      const login = b.dataset.login, act = b.dataset.acc, out = sec.querySelector('#accResult');
      try {
        if (act === 'reset') { if (!confirm('Выдать новый временный пароль для ' + login + '? Старый перестанет работать.')) return; const r = await api('POST', '/api/users/' + encodeURIComponent(login) + '/reset', '{}'); out.innerHTML = `Новый временный пароль для <strong>${h(login)}</strong>:<br><span class="pw">${h(r.tempPassword)}</span>`; out.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
        if (act === 'disable' || act === 'enable') await api('POST', '/api/users/' + encodeURIComponent(login) + '/' + act, '{}');
        if (act === 'delete') { if (!confirm('Удалить доступ ' + login + ' навсегда?')) return; await api('DELETE', '/api/users/' + encodeURIComponent(login)); }
        loadAccess();
      } catch (err) { out.textContent = err.message; }
    });
  }
  async function loadAccess() {
    try {
      const list = await api('GET', '/api/users');
      document.getElementById('accUsers').innerHTML = '<table><thead><tr><th>Имя</th><th>Логин</th><th>Роль</th><th class="hide-m">Последний вход</th><th></th></tr></thead><tbody>' + list.map(u => `<tr><td>${h(u.name)}${u.login === user.login ? ' (вы)' : ''}</td><td>${h(u.login)}</td><td>${h(u.roleName)}${u.disabled ? ' · <span style="color:#a5403a">заблокирован</span>' : u.mustChange ? ' · ждёт первого входа' : ''}</td><td class="hide-m">${when(u.lastLoginAt)}</td><td><div class="actions">${u.manageable ? `<button class="secondary" type="button" data-acc="reset" data-login="${h(u.login)}">Новый пароль</button><button class="secondary" type="button" data-acc="${u.disabled ? 'enable' : 'disable'}" data-login="${h(u.login)}">${u.disabled ? 'Разблокировать' : 'Заблокировать'}</button><button class="secondary danger" type="button" data-acc="delete" data-login="${h(u.login)}">Удалить</button>` : ''}</div></td></tr>`).join('') + '</tbody></table>';
      const log = await api('GET', '/api/audit?limit=60');
      document.getElementById('accAudit').innerHTML = log.length ? log.map(a => `<div>${h(when(a.at))} · <strong>${h(a.user || (a.details && a.details.login) || 'система')}</strong> — ${h(ROLE_ACTIONS[a.action] || a.action)}${a.details && a.details.key ? ': ' + h(KEY_NAMES[a.details.key] || a.details.key) : ''}${a.details && a.details.title ? ': «' + h(a.details.title) + '»' : ''}${a.action.startsWith('user.') && a.details && a.details.login ? ' (' + h(a.details.login) + ')' : ''}</div>`).join('') : '<div class="empty">Пока пусто</div>';
    } catch (e) { document.getElementById('accUsers').textContent = e.message; }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setupUi); else setupUi();
})();
