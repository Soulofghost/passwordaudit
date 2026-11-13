const API_BASE = '/api';

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initToggle();
  initSingleAudit();
  initBatchAudit();
  loadStats();
  loadLogs();
});

function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const target = tab.dataset.tab === 'single' ? 'paneSingle' :
                     tab.dataset.tab === 'batch' ? 'paneBatch' : 'paneHistory';
      document.getElementById(target)?.classList.add('active');

      if (tab.dataset.tab === 'history') {
        loadLogs();
      }
    });
  });
}

function initToggle() {
  const input = document.getElementById('passwordInput');
  const toggle = document.getElementById('toggleVisibility');
  toggle?.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    toggle.innerText = isPassword ? '🔒' : '👁️';
  });
}

function initSingleAudit() {
  const input = document.getElementById('passwordInput');
  const runBtn = document.getElementById('runAuditBtn');

  input?.addEventListener('input', () => {
    updateLiveMetrics(input.value);
  });

  runBtn?.addEventListener('click', async () => {
    const password = input.value.trim();
    const identifier = document.getElementById('userInput').value.trim() || 'corp\\analyst_01';
    if (!password) {
      alert('Please enter a password to audit.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, identifier })
      });

      if (!res.ok) throw new Error('Audit evaluation failed');
      const data = await res.json();
      renderAuditResult(data);
      loadStats();
    } catch (err) {
      alert(err.message);
    }
  });
}

function updateLiveMetrics(pwd) {
  const len = pwd.length;
  document.getElementById('charLength').innerText = `${len} chars`;

  let charset = 0;
  if (/[a-z]/.test(pwd)) charset += 26;
  if (/[A-Z]/.test(pwd)) charset += 26;
  if (/[0-9]/.test(pwd)) charset += 10;
  if (/[^a-zA-Z0-9\s]/.test(pwd)) charset += 32;

  document.getElementById('charsetPool').innerText = `${charset} Symbols`;

  const bits = len > 0 && charset > 0 ? (len * Math.log2(charset)).toFixed(1) : 0.0;
  const pct = Math.min(100, Math.round((bits / 100) * 100));

  const fill = document.getElementById('meterFill');
  fill.style.width = `${pct}%`;

  if (bits < 36) {
    fill.style.backgroundColor = 'var(--accent-red)';
    document.getElementById('entropyScoreText').innerText = `${bits} Bits (Critical/Weak)`;
  } else if (bits < 60) {
    fill.style.backgroundColor = 'var(--accent-amber)';
    document.getElementById('entropyScoreText').innerText = `${bits} Bits (Moderate)`;
  } else {
    fill.style.backgroundColor = 'var(--accent-emerald)';
    document.getElementById('entropyScoreText').innerText = `${bits} Bits (Strong/Robust)`;
  }
}

function renderAuditResult(data) {
  document.getElementById('shannonH').innerText = data.shannon_entropy.toFixed(2);
  document.getElementById('sha1Prefix').innerText = data.sha1_hash_prefix;

  const badge = document.getElementById('ratingBadge');
  badge.innerText = data.rating;
  badge.className = 'badge ' + (
    data.rating === 'CRITICAL_RISK' ? 'badge-fail' :
    data.rating === 'WEAK' ? 'badge-warn' :
    'badge-pass'
  );

  // Attack times
  document.getElementById('timeOnlineThrottled').innerText = data.crack_times.online_throttled;
  document.getElementById('timeOnlineFast').innerText = data.crack_times.online_fast;
  document.getElementById('timeOfflineSlow').innerText = data.crack_times.offline_slow_hash;
  document.getElementById('timeOfflineGpu').innerText = data.crack_times.offline_gpu_cluster;

  // NIST Rules
  const compList = document.getElementById('complianceList');
  compList.innerHTML = data.nist_checks.map(c => `
    <div class="compliance-item ${c.passed ? 'passed' : 'failed'}">
      <span>${c.passed ? '✅' : '❌'}</span>
      <div>
        <strong>${c.rule}</strong>: ${c.detail}
      </div>
    </div>
  `).join('');

  // Patterns
  const patList = document.getElementById('patternsList');
  if (data.patterns.length === 0) {
    patList.innerHTML = `<div class="pattern-item passed"><span>🛡️</span> Zero compromised patterns or keyboard walks detected.</div>`;
  } else {
    patList.innerHTML = data.patterns.map(p => `
      <div class="pattern-item ${p.severity.toLowerCase()}">
        <span>⚠️</span>
        <div><strong>[${p.severity}] ${p.type}</strong>: ${p.message}</div>
      </div>
    `).join('');
  }
}

function initBatchAudit() {
  const btn = document.getElementById('runBatchBtn');
  btn?.addEventListener('click', async () => {
    const raw = document.getElementById('batchInput').value.trim();
    if (!raw) {
      alert('Please enter at least one password.');
      return;
    }
    const passwords = raw.split('\n').map(s => s.trim()).filter(Boolean);

    try {
      const res = await fetch(`${API_BASE}/audit/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passwords })
      });

      if (!res.ok) throw new Error('Batch audit failed');
      const data = await res.json();
      renderBatchResults(data);
    } catch (err) {
      alert(err.message);
    }
  });
}

function renderBatchResults(data) {
  document.getElementById('batchResults').style.display = 'block';
  document.getElementById('sumTotal').innerText = data.total_evaluated;
  document.getElementById('sumCompliance').innerText = `${data.compliant_percentage}%`;
  document.getElementById('sumCritical').innerText = data.critical_risk_count;
  document.getElementById('sumEntropy').innerText = `${data.average_entropy_bits} Bits`;

  const tbody = document.getElementById('batchTableBody');
  tbody.innerHTML = data.results.map(r => `
    <tr>
      <td class="text-mono">${escapeHtml(r.masked)}</td>
      <td>${r.length}</td>
      <td>${r.entropy_bits} Bits</td>
      <td><span class="badge ${r.rating === 'CRITICAL_RISK' ? 'badge-fail' : r.rating === 'WEAK' ? 'badge-warn' : 'badge-pass'}">${r.rating}</span></td>
      <td>${r.nist_compliant ? '✅ Compliant' : '❌ Non-Compliant'}</td>
      <td>${r.anomalies_detected > 0 ? `<span class="text-red">${r.anomalies_detected} Alert(s)</span>` : '<span class="text-emerald">Clean</span>'}</td>
    </tr>
  `).join('');
}

async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    const data = await res.json();
    document.getElementById('totalAudits').innerText = data.totalAudits;
    document.getElementById('complianceRate').innerText = `${data.complianceRate}%`;
    document.getElementById('avgEntropy').innerText = `${data.avgEntropyBits} Bits`;
  } catch (err) {
    console.warn('Failed to load stats', err);
  }
}

async function loadLogs() {
  const tbody = document.getElementById('historyTableBody');
  try {
    const res = await fetch(`${API_BASE}/logs`);
    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No audit logs recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => `
      <tr>
        <td class="text-mono">${l.id}</td>
        <td>${escapeHtml(l.identifier)}</td>
        <td>${l.entropy_score.toFixed(2)}</td>
        <td>${l.keyspace_bits.toFixed(1)} Bits</td>
        <td><span class="badge ${l.rating === 'CRITICAL_RISK' ? 'badge-fail' : l.rating === 'WEAK' ? 'badge-warn' : 'badge-pass'}">${l.rating}</span></td>
        <td>${l.nist_compliant ? '✅ Yes' : '❌ No'}</td>
        <td>${new Date(l.created_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color: var(--accent-red);">Error loading audit telemetry: ${err.message}</td></tr>`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
