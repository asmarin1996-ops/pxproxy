let cfgData = null;

async function api(path, opts = {}) {
  const res = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  if (res.status === 401) { location.href = '/auth/login'; throw new Error('sesion expirada'); }
  let data = {};
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.toggle('err', !!isErr);
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), 3500);
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

function initTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tabpane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('form-setup-' + btn.dataset.tab).classList.add('active');
    });
  });
}

const KNOWN_VIEWS = ['estado', 'reglas', 'ajustes', 'identidad', 'seguridad', 'backups', 'twofa', 'certs'];

function showView(name) {
  if (!KNOWN_VIEWS.includes(name)) name = 'estado';
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.dataset.viewName === name));
  const nav = document.getElementById('nav');
  nav.querySelectorAll('a').forEach(a => a.classList.toggle('active', a.dataset.view === name));
  history.replaceState(null, '', '#' + name);
}

document.getElementById('nav').addEventListener('click', e => {
  const a = e.target.closest('a[data-view]');
  if (!a) return;
  e.preventDefault();
  showView(a.dataset.view);
});

window.addEventListener('hashchange', () => showView(location.hash.slice(1)));

async function loadSession() {
  const s = await api('/api/session');
  document.getElementById('setup-card').classList.toggle('hidden', !s.setup_required);
  document.getElementById('user-name').textContent = s.user ? s.user.email : '';
  document.getElementById('user-role').textContent = s.authenticated ? (s.is_admin ? 'administrador' : 'solo lectura') : '';
  document.getElementById('st-entra').textContent = s.entra_enabled ? 'activo' : 'no configurado';
  document.getElementById('st-ldap').textContent = s.ldap_enabled ? 'activo' : 'no configurado';
  document.getElementById('form-test-ldap').classList.toggle('hidden', !s.ldap_enabled);
  document.getElementById('pw-warning').classList.toggle('hidden', !s.default_password);
  if (s.setup_required) { showView('setup'); }
  else { showView(location.hash ? location.hash.slice(1) : 'estado'); }
  api('/api/health').then(() => {
    const p = document.getElementById('health-pill');
    p.textContent = 'operativo';
    p.style.color = 'var(--green)';
    p.style.borderColor = 'rgba(63,185,80,.5)';
  }).catch(() => {
    const p = document.getElementById('health-pill');
    p.textContent = 'sin respuesta';
    p.style.color = 'var(--red)';
  });
}

function renderRules(rules) {
  const tbody = document.getElementById('rules-tbody');
  document.getElementById('rules-count').textContent = rules.length + ' regla(s)';
  if (!rules.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">Sin reglas. Añade una abajo.</td></tr>';
    return;
  }
  tbody.innerHTML = rules.map(r => `
    <tr data-host="${esc(r.host)}">
      <td><code>${esc(r.host)}</code></td>
      <td><code>${esc(r.target)}</code></td>
      <td><input type="checkbox" class="tgl-auth" ${r.require_auth ? 'checked' : ''}></td>
      <td><input type="checkbox" class="tgl-en" ${r.enabled ? 'checked' : ''}></td>
      <td><button class="btn danger small del-rule" type="button">Eliminar</button></td>
    </tr>`).join('');
}

async function loadSecurity() {
  const [sec, cfg] = await Promise.all([api('/api/security'), api('/api/config')]);
  document.getElementById('security-list').innerHTML = [
    ['Intentos antes de bloqueo', sec.login_max_fails],
    ['Minutos de bloqueo', sec.lockout_minutes],
    ['Bloqueos activos', sec.active_lockouts],
    ['Lista blanca panel', (cfg.admin_allowed_cidrs || []).length ? cfg.admin_allowed_cidrs.join(', ') : 'sin restricciones'],
    ['Administradores', (cfg.panel_admins || []).length ? cfg.panel_admins.join(', ') : 'todos los autenticados'],
    ['Cookies Secure', sec.secure_cookies ? 'si' : 'no'],
    ['Epoca de sesion', sec.session_epoch],
  ].map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('');
  const f = document.getElementById('form-security');
  f.admin_allowed_cidrs.value = (cfg.admin_allowed_cidrs || []).join(', ');
  f.panel_admins.value = (cfg.panel_admins || []).join(', ');
  f.login_max_fails.value = sec.login_max_fails;
  f.lockout_minutes.value = sec.lockout_minutes;
  f.secure_cookies.checked = !!cfg.secure_cookies;
}

async function loadBackups() {
  try {
    const data = await api('/api/storage/backups');
    const list = data.backups || [];
    const el = document.getElementById('bd-list');
    if (!list.length) {
      el.innerHTML = '<p class="muted small">No hay copias de seguridad aun</p>';
      return;
    }
    el.innerHTML = list.map(b => {
      const kb = Math.ceil(b.size_bytes / 1024);
      const d = new Date(b.modified);
      const fecha = d.toLocaleDateString('es-CL') + ' ' + d.toLocaleTimeString('es-CL', {hour:'2-digit', minute:'2-digit'});
      return `<div class="backup-row" style="display:flex;align-items:center;gap:12px;padding:6px 0;border-bottom:1px solid #eee">
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(b.file)}">${esc(b.file)}</span>
        <span style="min-width:60px;text-align:right" class="muted small">${kb} KB</span>
        <span style="min-width:90px;text-align:right" class="muted small">${fecha}</span>
        <button class="btn small danger bd-restore" data-file="${esc(b.file)}" type="button">Restaurar</button>
        <button class="btn small ghost bd-delete" data-file="${esc(b.file)}" type="button" title="Eliminar copia">&#10005;</button>
      </div>`;
    }).join('');
  } catch (e) {
    document.getElementById('bd-list').innerHTML = '<p class="muted small">BD no disponible para backups (requiere postgres)</p>';
  }
}

async function doBackup() {
  const el = document.getElementById('bd-action');
  try {
    el.textContent = 'Generando...';
    await api('/api/storage/backup', { method: 'POST' });
    el.textContent = 'Copia creada';
    loadBackups();
    setTimeout(() => el.textContent = '', 2000);
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

async function restoreBackup(file) {
  if (!confirm('Restaurar la copia de seguridad?\nEsto reemplazara configuracion, bloqueos y auditoria actuales.\nTodos los nodos del cluster recargaran.'));
    return;
  const el = document.getElementById('bd-action');
  try {
    el.textContent = 'Restaurando...';
    await api('/api/storage/restore', { method: 'POST', body: JSON.stringify({file}) });
    el.textContent = 'Restaurado correctamente';
    loadBackups();
    setTimeout(() => el.textContent = '', 2000);
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

async function deleteBackup(file) {
  if (!confirm('Eliminar la copia de seguridad?\nEsta accion no se puede deshacer.'));
    return;
  const el = document.getElementById('bd-action');
  try {
    el.textContent = 'Eliminando...';
    await api('/api/storage/delete', { method: 'POST', body: JSON.stringify({file}) });
    el.textContent = 'Eliminado';
    loadBackups();
    setTimeout(() => el.textContent = '', 2000);
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

async function loadRules() {
  const data = await api('/api/rules');
  renderRules(data.rules || []);
}

function fillForm(form, obj, map) {
  Object.entries(map || {}).forEach(([name, path]) => {
    const input = form.querySelector(`[name="${name}"]`);
    if (!input) return;
    if (input.type === 'checkbox') { input.checked = !!path.get(obj); return; }
    input.value = path.get(obj) == null ? '' : path.get(obj);
  });
}

function readForm(form, map) {
  const out = {};
  Object.entries(map).forEach(([name, path]) => {
    const input = form.querySelector(`[name="${name}"]`);
    if (!input) return;
    if (input.type === 'checkbox') path.set(out, input.checked);
    else path.set(out, input.value.trim());
  });
  return out;
}

const P = (...keys) => ({
  get: o => keys.reduce((a, k) => (a == null ? a : a[k]), o),
  set: (o, v) => {
    let cur = o;
    for (let i = 0; i < keys.length - 1; i++) {
      if (typeof cur[keys[i]] !== 'object' || cur[keys[i]] === null) cur[keys[i]] = {};
      cur = cur[keys[i]];
    }
    cur[keys[keys.length - 1]] = v;
  }
});

async function loadConfig() {
  cfgData = await api('/api/config');
  const f = document.getElementById('form-config');
  ['admin_port', 'proxy_http_port', 'proxy_https_port', 'session_hours', 'tls_cert_file', 'tls_key_file', 'panel_tls_cert_file', 'panel_tls_key_file'].forEach(n => {
    f.querySelector(`[name="${n}"]`).value = cfgData[n] == null ? '' : cfgData[n];
  });
  f.querySelector('[name="insecure_upstream"]').checked = !!cfgData.insecure_upstream;

  document.getElementById('status-list').innerHTML = [
    ['Puerto admin', cfgData.admin_port],
    ['Panel TLS', (cfgData.panel_tls_cert_file && cfgData.panel_tls_key_file) ? 'activo' : 'no'],
    ['Proxy HTTP', cfgData.proxy_http_port],
    ['Proxy HTTPS', (cfgData.tls_cert_file && cfgData.tls_key_file) ? cfgData.proxy_https_port : 'off'],
    ['Sesion', cfgData.session_hours + ' h'],
    ['Upstream TLS laxo', cfgData.insecure_upstream ? 'si' : 'no'],
    ['Redirect URI', cfgData.azure.redirect_url],
  ].map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('');

  const ee = document.getElementById('form-edit-entra');
  ee.innerHTML = `
    <label>Tenant ID<input name="tenant_id"></label>
    <label>Client ID<input name="client_id"></label>
    <label>Client Secret<input name="client_secret" type="password" placeholder="${cfgData.azure.client_secret ? '(sin cambios)' : '(vacio)'}"></label>
    <label>Redirect URI<input name="redirect_url"></label>
    <label>Correos permitidos<input name="allowed_emails"></label>
    <button class="btn small primary">Guardar Entra ID</button>`;
  fillForm(ee, cfgData.azure, { tenant_id: P('tenant_id'), client_id: P('client_id'), redirect_url: P('redirect_url') });
  ee.querySelector('[name="allowed_emails"]').value = (cfgData.azure.allowed_emails || []).join(', ');

  const le = document.getElementById('form-edit-ldap');
  le.innerHTML = `
    <label>Habilitado<input type="checkbox" name="enabled"></label>
    <label>Servidor LDAP<input name="url"></label>
    <label>Base DN<input name="base_dn"></label>
    <label>Sufijo UPN<input name="bind_upn_suffix"></label>
    <label>Filtro de usuario<input name="user_filter"></label>
    <label>Grupos permitidos<input name="allowed_groups"></label>
    <label class="check"><input type="checkbox" name="insecure_tls"> Ignorar TLS</label>
    <button class="btn small primary">Guardar LDAP</button>`;
  fillForm(le, cfgData.ldap, { url: P('url'), base_dn: P('base_dn'), bind_upn_suffix: P('bind_upn_suffix'), user_filter: P('user_filter'), enabled: P('enabled'), insecure_tls: P('insecure_tls') });
  le.querySelector('[name="allowed_groups"]').value = (cfgData.ldap.allowed_groups || []).join(', ');
}

document.getElementById('btn-logout').addEventListener('click', () => location.href = '/auth/logout');

document.getElementById('form-add-rule').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('/api/rules', { method: 'POST', body: JSON.stringify({
      host: f.host.value.trim(),
      target: f.target.value.trim(),
      require_auth: f.require_auth.checked,
      enabled: true,
    })});
    f.reset();
    toast('Regla guardada');
    await loadRules();
  } catch (err) { toast(err.message, true); }
});

document.getElementById('rules-tbody').addEventListener('change', async e => {
  const tr = e.target.closest('tr[data-host]');
  if (!tr) return;
  const host = tr.dataset.host;
  const rule = (await api('/api/rules')).rules.find(r => r.host === host);
  if (!rule) return;
  if (e.target.classList.contains('tgl-auth')) rule.require_auth = e.target.checked;
  if (e.target.classList.contains('tgl-en')) rule.enabled = e.target.checked;
  try {
    const res = await api('/api/rules', { method: 'POST', body: JSON.stringify(rule) });
    renderRules(res.rules);
    toast('Regla actualizada');
  } catch (err) { toast(err.message, true); }
});

document.getElementById('rules-tbody').addEventListener('click', async e => {
  if (!e.target.classList.contains('del-rule')) return;
  const tr = e.target.closest('tr[data-host]');
  if (!confirm('Eliminar la regla ' + tr.dataset.host + '?')) return;
  try {
    const res = await api('/api/rules/delete', { method: 'POST', body: JSON.stringify({ host: tr.dataset.host }) });
    renderRules(res.rules);
    toast('Regla eliminada');
  } catch (err) { toast(err.message, true); }
});

document.getElementById('form-config').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  const body = Object.assign({}, cfgData, {
    admin_port: parseInt(f.admin_port.value, 10),
    proxy_http_port: parseInt(f.proxy_http_port.value, 10),
    proxy_https_port: parseInt(f.proxy_https_port.value, 10),
    session_hours: parseInt(f.session_hours.value, 10),
    tls_cert_file: f.tls_cert_file.value.trim(),
    tls_key_file: f.tls_key_file.value.trim(),
    panel_tls_cert_file: f.panel_tls_cert_file.value.trim(),
    panel_tls_key_file: f.panel_tls_key_file.value.trim(),
    insecure_upstream: f.insecure_upstream.checked,
  });
  try {
    const res = await api('/api/config', { method: 'POST', body: JSON.stringify(body) });
    if (res.warning) toast('Guardado con aviso: ' + res.warning, true);
    else toast('Ajustes guardados. Reinicia si cambiaste puertos/TLS.');
    await loadConfig();
  } catch (err) { toast(err.message, true); }
});

document.getElementById('form-setup-entra').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('/api/setup', { method: 'POST', body: JSON.stringify({
      tenant_id: f.tenant_id.value.trim(),
      client_id: f.client_id.value.trim(),
      client_secret: f.client_secret.value.trim(),
      redirect_url: f.redirect_url.value.trim(),
      allowed_emails: f.allowed_emails.value.split(',').map(s => s.trim()).filter(Boolean),
    })});
    location.href = '/auth/login';
  } catch (err) { toast(err.message, true); }
});

document.getElementById('form-setup-ldap').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('/api/setup', { method: 'POST', body: JSON.stringify({
      enable_ldap: true,
      ldap: {
        url: f.url.value.trim(),
        base_dn: f.base_dn.value.trim(),
        bind_upn_suffix: f.bind_upn_suffix.value.trim(),
        user_filter: f.user_filter.value.trim(),
        insecure_tls: f.insecure_tls.checked,
        allowed_groups: f.allowed_groups.value.split(',').map(s => s.trim()).filter(Boolean),
      },
    })});
    location.href = '/auth/login';
  } catch (err) { toast(err.message, true); }
});

document.getElementById('btn-revoke').addEventListener('click', async () => {
  if (!confirm('Se invalidaran todas las sesiones (incluida la tuya). Continuar?')) return;
  try {
    await api('/api/sessions/revoke', { method: 'POST' });
    location.href = '/auth/login';
  } catch (err) { toast(err.message, true); }
});

async function loadTOTP() {
  const t = await api('/api/totp');
  const f = document.getElementById('form-totp');
  f.querySelector('[name="require_for"]').value = (t.require_for || []).join(', ');
  const box = document.getElementById('totp-enrolled');
  if (!t.enrolled || !t.enrolled.length) {
    box.innerHTML = '<p class="muted small">Nadie ha inscrito un dispositivo 2FA todavia.</p>';
    return;
  }
  box.innerHTML = '<p class="muted small" style="margin-bottom:6px">Dispositivos inscritos:</p>' +
    t.enrolled.map(e => `<div class="row mt-8"><code>${esc(e.identity)}</code><span class="pill">${e.confirmed ? 'confirmado' : 'pendiente'}</span><button class="btn danger small totp-reset" data-id="${esc(e.identity)}" type="button">Resetear</button></div>`).join('');
}

document.getElementById('totp-enrolled').addEventListener('click', async e => {
  if (!e.target.classList.contains('totp-reset')) return;
  const id = e.target.dataset.id;
  if (!confirm('Resetear el 2FA de ' + id + '? Tendra que volver a escanear el QR en su proximo inicio de sesion.')) return;
  try {
    await api('/api/totp/reset', { method: 'POST', body: JSON.stringify({ identity: id }) });
    toast('2FA reseteado para ' + id);
    await loadTOTP();
  } catch (err) { toast(err.message, true); }
});

document.addEventListener('submit', async e => {
  if (e.target.id === 'form-totp') {
    e.preventDefault();
    const f = e.target;
    try {
      await api('/api/totp/settings', { method: 'POST', body: JSON.stringify({
        require_for: f.require_for.value.split(',').map(s => s.trim()).filter(Boolean),
      })});
      toast('Configuracion 2FA guardada');
      await loadTOTP();
    } catch (err) { toast(err.message, true); }
  }
  if (e.target.id === 'form-security') {
    e.preventDefault();
    const f = e.target;
    const body = Object.assign({}, cfgData, {
      admin_allowed_cidrs: f.admin_allowed_cidrs.value.split(',').map(x => x.trim()).filter(Boolean),
      panel_admins: f.panel_admins.value.split(',').map(x => x.trim()).filter(Boolean),
      login_max_fails: parseInt(f.login_max_fails.value, 10),
      lockout_minutes: parseInt(f.lockout_minutes.value, 10),
      secure_cookies: f.secure_cookies.checked,
    });
    try {
      await api('/api/config', { method: 'POST', body: JSON.stringify(body) });
      toast('Seguridad actualizada');
      await loadSecurity();
    } catch (err) { toast(err.message, true); }
  }
  if (e.target.id === 'form-edit-entra' || e.target.id === 'form-edit-ldap') {
    e.preventDefault();
    const f = e.target;
    const body = Object.assign({}, cfgData);
    body.azure = Object.assign({}, cfgData.azure);
    body.ldap = Object.assign({}, cfgData.ldap);
    if (f.id === 'form-edit-entra') {
      body.azure.tenant_id = f.tenant_id.value.trim();
      body.azure.client_id = f.client_id.value.trim();
      if (f.client_secret.value.trim()) body.azure.client_secret = f.client_secret.value.trim();
      body.azure.redirect_url = f.redirect_url.value.trim();
      body.azure.allowed_emails = f.allowed_emails.value.split(',').map(s => s.trim()).filter(Boolean);
    } else {
      body.ldap.enabled = f.enabled.checked;
      body.ldap.url = f.url.value.trim();
      body.ldap.base_dn = f.base_dn.value.trim();
      body.ldap.bind_upn_suffix = f.bind_upn_suffix.value.trim();
      body.ldap.user_filter = f.user_filter.value.trim() || '(sAMAccountName=%s)';
      body.ldap.insecure_tls = f.insecure_tls.checked;
      body.ldap.allowed_groups = f.allowed_groups.value.split(',').map(s => s.trim()).filter(Boolean);
    }
    try {
      const res = await api('/api/config', { method: 'POST', body: JSON.stringify(body) });
      toast(res.warning ? 'Guardado con aviso: ' + res.warning : 'Autenticacion actualizada', !!res.warning);
      await loadConfig();
    } catch (err) { toast(err.message, true); }
  }
  if (e.target.id === 'form-local-pw') {
    e.preventDefault();
    try {
      await api('/api/local-password', { method: 'POST', body: JSON.stringify({
        current_password: e.target.current.value,
        new_password: e.target.next.value,
      })});
      e.target.reset();
      toast('Contrasena actualizada');
      await loadSession();
    } catch (err) { toast(err.message, true); }
  }
  if (e.target.id === 'form-test-ldap') {
    e.preventDefault();
    try {
      const res = await api('/api/ldap-test', { method: 'POST', body: JSON.stringify({
        username: e.target.username.value, password: e.target.password.value,
      })});
      toast(res.ok ? 'LDAP OK: ' + res.user.name : 'Error LDAP: ' + res.error, !res.ok);
    } catch (err) { toast(err.message, true); }
  }
});

initTabs();
async function loadCerts() {
  const d = await api('/api/certs');
  const f = document.getElementById('form-certs-acme');
  f.acme_enabled.checked = !!d.acme.enabled;
  f.acme_domains.value = (d.acme.domains || []).join(', ');
  f.acme_redirect.checked = !!d.acme.redirect_http;
  renderCerts(d.domains || []);
}

function fmtDate(iso) { return iso ? new Date(iso).toLocaleString() : '-'; }
function cnOf(dn) { const m = /CN=([^,]+)/.exec(dn || ''); return m ? m[1] : (dn || ''); }

function renderCerts(list) {
  const tb = document.getElementById('certs-tbody');
  if (!list.length) { tb.innerHTML = '<tr><td colspan="5" class="muted small">Sin dominios todavia. Crea una regla o agrega dominios ACME.</td></tr>'; return; }
  tb.innerHTML = list.map(c => `
    <tr data-domain="${esc(c.domain)}">
      <td><code>${esc(c.domain)}</code></td>
      <td>${c.custom ? 'propio' : 'ACME'}</td>
      <td class="c-exp">${fmtDate(c.not_after)}</td>
      <td class="c-live muted small">${c.custom ? esc(cnOf(c.issuer)) : 'sin verificar'}</td>
      <td>
        <button class="btn small cert-probe" type="button">Verificar</button>
        ${c.custom
          ? '<button class="btn danger small cert-del" type="button">Borrar</button>'
          : '<button class="btn small cert-renew" type="button">Renovar</button>'}
      </td>
    </tr>`).join('');
}

document.getElementById('btn-certs-verify').addEventListener('click', async () => {
  toast('Verificando certificados en vivo...');
  try {
    const d = await api('/api/certs/status');
    renderCertsStatus(d.domains || []);
    toast('Verificacion completada');
  } catch (err) { toast(err.message, true); }
});

function renderCertsStatus(list) {
  list.forEach(c => {
    const tr = document.querySelector(`#certs-tbody tr[data-domain="${CSS.escape(c.domain)}"]`);
    if (!tr) return;
    tr.querySelector('.c-exp').textContent = c.live && c.live.ok ? fmtDate(c.live.not_after) : fmtDate(c.not_after);
    const cell = tr.querySelector('.c-live');
    if (!c.live) { cell.textContent = 'sin verificar'; return; }
    if (c.live.ok) { cell.className = 'c-live small'; cell.textContent = 'OK - ' + cnOf(c.live.issuer); }
    else { cell.className = 'c-live small'; cell.textContent = c.custom ? cnOf(c.issuer) : ('error: ' + c.live.error); }
  });
}

document.getElementById('form-certs-acme').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('/api/certs/acme', { method: 'POST', body: JSON.stringify({
      enabled: f.acme_enabled.checked,
      domains: f.acme_domains.value.split(',').map(s => s.trim()).filter(Boolean),
      redirect_http: f.acme_redirect.checked,
    })});
    toast('Ajustes ACME guardados');
    await loadCerts();
  } catch (err) { toast(err.message, true); }
});

document.getElementById('form-certs-upload').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  try {
    await api('/api/certs/custom', { method: 'POST', body: JSON.stringify({
      domain: f.domain.value.trim(),
      cert_pem: f.cert_pem.value,
      key_pem: f.key_pem.value,
    })});
    toast('Certificado propio guardado para ' + f.domain.value.trim());
    f.cert_pem.value = ''; f.key_pem.value = '';
    await loadCerts();
  } catch (err) { toast(err.message, true); }
});

document.getElementById('certs-tbody').addEventListener('click', async e => {
  const tr = e.target.closest('tr'); if (!tr) return;
  const domain = tr.dataset.domain;
  try {
    if (e.target.classList.contains('cert-probe')) {
      const st = await api('/api/certs/status');
      const row = (st.domains || []).find(x => x.domain === domain);
      renderCertsStatus([row].filter(Boolean));
    }
    if (e.target.classList.contains('cert-renew')) {
      if (!confirm('Forzar renovacion ACME de ' + domain + '?')) return;
      await api('/api/certs/renew', { method: 'POST', body: JSON.stringify({ domain }) });
      toast('Renovacion programada para ' + domain);
    }
    if (e.target.classList.contains('cert-del')) {
      if (!confirm('Eliminar el certificado propio de ' + domain + '? El dominio volvera a usar ACME o quedara sin TLS.')) return;
      await api('/api/certs/custom/delete', { method: 'POST', body: JSON.stringify({ domain }) });
      toast('Certificado eliminado');
      await loadCerts();
    }
  } catch (err) { toast(err.message, true); }
});

document.getElementById('btn-bd-backup').addEventListener('click', doBackup);

document.getElementById('bd-list').addEventListener('click', e => {
  const restore = e.target.closest('.bd-restore');
  if (restore) { restoreBackup(restore.dataset.file); return; }
  const del = e.target.closest('.bd-delete');
  if (del) deleteBackup(del.dataset.file);
});

loadSession().then(() => Promise.all([loadRules(), loadConfig(), loadSecurity(), loadBackups(), loadTOTP(), loadCerts()])).catch(err => console.error(err));
