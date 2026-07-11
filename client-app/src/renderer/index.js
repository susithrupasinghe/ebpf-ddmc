'use strict';

// ── Tab navigation ─────────────────────────────────────────────────────────

document.querySelectorAll('nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`panel-${btn.dataset.panel}`).classList.add('active');
  });
});

// ── Helpers ────────────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score >= 80) return '#dc2626';
  if (score >= 60) return '#fb923c';
  if (score >= 40) return '#facc15';
  if (score >= 20) return '#38bdf8';
  return '#334155';
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function badgeHtml(conf) {
  return `<span class="badge badge-${conf}">${conf}</span>`;
}

// ── Status bar ─────────────────────────────────────────────────────────────

async function refreshStatus() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const upEl = document.getElementById('uptime-text');
  try {
    const s = await window.eddmc.status();
    if (s.status === 'running') {
      dot.className = 'online';
      text.textContent = 'Daemon online';
      upEl.textContent = `uptime ${Math.floor(s.uptime)}s`;
    } else {
      throw new Error('offline');
    }
  } catch {
    dot.className = '';
    text.textContent = 'Daemon offline';
    upEl.textContent = '';
  }
}

// ── Dashboard ──────────────────────────────────────────────────────────────

async function refreshDashboard() {
  const [procs, alerts] = await Promise.all([
    window.eddmc.processes(),
    window.eddmc.alerts(),
  ]);

  const suspicious = procs.filter((p) => p.confidence !== 'NONE');
  const highCrit   = procs.filter((p) => p.confidence === 'HIGH' || p.confidence === 'CRITICAL');

  document.getElementById('stat-tracked').textContent    = procs.length;
  document.getElementById('stat-suspicious').textContent = suspicious.length;
  document.getElementById('stat-high').textContent       = highCrit.length;
  document.getElementById('stat-alerts').textContent     = alerts.length;

  // Alert badge on tab
  const badge = document.getElementById('alert-badge');
  badge.textContent = alerts.length ? ` (${alerts.length})` : '';

  // Top processes by score
  const top = [...procs]
    .sort((a, b) => (b.score || 0) - (a.score || 0))
    .slice(0, 10)
    .filter((p) => (p.score || 0) > 0);

  const tbody = document.getElementById('dashboard-tbody');
  tbody.innerHTML = top.map((p) => `
    <tr>
      <td>${p.pid}</td>
      <td><code>${p.comm}</code></td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-bar">
            <div class="score-bar-fill"
                 style="width:${p.score||0}%;background:${scoreColor(p.score||0)}"></div>
          </div>
          ${(p.score||0).toFixed(1)}
        </div>
      </td>
      <td>${badgeHtml(p.confidence || 'NONE')}</td>
      <td>${p.mitigation || 'NONE'}</td>
      <td style="font-size:11px;color:#94a3b8;max-width:280px;white-space:normal">
        ${(p.reasons || []).slice(0,2).join(' · ') || '—'}
      </td>
    </tr>
  `).join('');

  // Recent alerts (last 5)
  const recentEl = document.getElementById('recent-alerts');
  const recent   = [...alerts].reverse().slice(0, 5);
  recentEl.innerHTML = recent.map((a) => alertHtml(a)).join('');
}

// ── Processes panel ────────────────────────────────────────────────────────

async function refreshProcesses() {
  const procs = await window.eddmc.processes();
  const sorted = [...procs].sort((a, b) => (b.score || 0) - (a.score || 0));

  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = sorted.map((p) => {
    const score = (p.score || 0).toFixed(1);
    const sched = p.sched || {};
    const cpu   = (p.sched && p.sched.cpu_percent != null) ? Number(p.sched.cpu_percent).toFixed(1) : '—';
    const isSuspicious = p.confidence !== 'NONE';
    return `
      <tr>
        <td>${p.pid}</td>
        <td><code>${p.comm}</code></td>
        <td>
          <div class="score-bar-wrap">
            <div class="score-bar">
              <div class="score-bar-fill"
                   style="width:${p.score||0}%;background:${scoreColor(p.score||0)}"></div>
            </div>
            ${score}
          </div>
        </td>
        <td>${badgeHtml(p.confidence || 'NONE')}</td>
        <td>${p.mitigation || 'NONE'}</td>
        <td>${sched.thread_count || '—'}</td>
        <td>${cpu}%</td>
        <td>
          ${isSuspicious ? `
            <button class="btn-sm" onclick="revokeAction(${p.pid})">Revoke</button>
            <button class="btn-sm danger" onclick="killAction(${p.pid})">Kill</button>
          ` : ''}
        </td>
      </tr>
    `;
  }).join('');
}

// ── Alerts panel ───────────────────────────────────────────────────────────

function alertHtml(a) {
  return `
    <div class="alert-item ${a.confidence}">
      <div class="alert-header">
        ${badgeHtml(a.confidence)}
        <strong>${a.comm}</strong>
        <span style="color:#94a3b8">pid ${a.pid}</span>
        <span style="color:#94a3b8">score ${a.score.toFixed(1)}</span>
        <span style="color:#94a3b8">→ ${a.action}</span>
        <span class="alert-time">${fmtTime(a.timestamp)}</span>
      </div>
      <ul class="alert-reasons">
        ${(a.reasons || []).map((r) => `<li>${r}</li>`).join('')}
      </ul>
    </div>
  `;
}

async function refreshAlerts() {
  const alerts = await window.eddmc.alerts();
  const el = document.getElementById('alerts-list');
  if (!alerts.length) {
    el.innerHTML = '<p style="color:#94a3b8;padding:20px">No alerts yet.</p>';
    return;
  }
  el.innerHTML = [...alerts].reverse().map(alertHtml).join('');
}

// ── Config panel ───────────────────────────────────────────────────────────

async function refreshConfig() {
  const cfg = await window.eddmc.config();
  document.getElementById('config-pre').textContent = JSON.stringify(cfg, null, 2);
}

// ── Action handlers ────────────────────────────────────────────────────────

window.revokeAction = async (pid) => {
  if (!confirm(`Revoke all mitigations for pid ${pid}?`)) return;
  await window.eddmc.revoke(pid);
};

window.killAction = async (pid) => {
  if (!confirm(`Terminate pid ${pid}? This sends SIGKILL.`)) return;
  await window.eddmc.kill(pid);
};

// ── Polling loop ───────────────────────────────────────────────────────────

function activePanel() {
  const active = document.querySelector('.panel.active');
  return active ? active.id.replace('panel-', '') : 'dashboard';
}

async function tick() {
  document.getElementById('footer-time').textContent = new Date().toLocaleTimeString();
  await refreshStatus();
  const panel = activePanel();
  if (panel === 'dashboard')  await refreshDashboard();
  if (panel === 'processes')  await refreshProcesses();
  if (panel === 'alerts')     await refreshAlerts();
  if (panel === 'config')     await refreshConfig();
}

// Refresh config once on load, then poll every 4 seconds
refreshConfig();
tick();
setInterval(tick, 4000);
