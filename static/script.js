/* CyberX v2 – frontend */

const SEV_COLOR = {
  CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb'
};
const SEV_BG = {
  CRITICAL: '#fee2e2', HIGH: '#ffedd5', MEDIUM: '#fef3c7', LOW: '#dbeafe'
};

class CyberXUI {
  constructor() {
    this.scanId      = sessionStorage.getItem('cyberx_active_scan');
    this.pollTimer   = null;
    this.allResults  = [];
    this.activeFilter = 'ALL';
    this._bind();

    if (this.scanId && window.location.pathname === '/') {
      // Resume polling if we navigate back to the scanner page
      document.getElementById('configPanel')?.classList.add('hidden');
      document.getElementById('progressPanel')?.classList.remove('hidden');
      this.pollTimer = setInterval(() => this.poll(), 1000);
      this.poll();
    }
  }

  _bind() {
    document.getElementById('startScan')   .addEventListener('click', () => this.startScan());
    document.getElementById('cancelScan') ?.addEventListener('click', () => this.cancelScan());
    document.getElementById('viewResults')?.addEventListener('click', () => this.showResults());
    document.getElementById('newScan')    ?.addEventListener('click', () => this.reset());
    document.getElementById('downloadHTML')?.addEventListener('click', () => this.download('html'));
    document.getElementById('downloadJSON')?.addEventListener('click', () => this.download('json'));
    document.getElementById('downloadCSV') ?.addEventListener('click', () => this.download('csv'));

    document.querySelectorAll('.filter-btn').forEach(btn =>
      btn.addEventListener('click', e => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        this.activeFilter = e.target.dataset.sev;
        this.renderTable(this.allResults);
      })
    );
  }

  _getUrls() {
    return (document.getElementById('urls').value || '')
      .split('\n').map(s => s.trim()).filter(Boolean);
  }

  async startScan() {
    const urls = this._getUrls();
    if (!urls.length) { alert('Enter at least one URL'); return; }

    const timeout  = parseInt(document.getElementById('timeout').value) || 7;
    const mode     = document.getElementById('mode').value;
    const bearer   = document.getElementById('bearerToken')?.value?.trim() || '';
    const session  = document.getElementById('sessionCookie')?.value?.trim() || '';
    let   extraH   = {};
    try {
      const raw = document.getElementById('customHeaders')?.value?.trim();
      if (raw) extraH = JSON.parse(raw);
    } catch(_) { alert('Custom headers must be valid JSON'); return; }

    const body = { urls, timeout, mode,
                   bearer_token: bearer, session_cookie: session,
                   auth_headers: extraH };

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!resp.ok) {
        const e = await resp.json().catch(() => ({ error: resp.statusText }));
        alert('Error: ' + (e.error || resp.statusText));
        return;
      }
      const data = await resp.json();
      this.scanId = data.scan_id;
      sessionStorage.setItem('cyberx_active_scan', this.scanId);

      document.getElementById('configPanel')  ?.classList.add('hidden');
      document.getElementById('progressPanel')  .classList.remove('hidden');
      document.getElementById('resultsPanel')   .classList.add('hidden');
      this.pollTimer = setInterval(() => this.poll(), 1000);

    } catch(err) { console.error(err); alert('Failed to start scan.'); }
  }

  async poll() {
    if (!this.scanId) return;
    try {
      const r = await fetch(`/api/scan/${this.scanId}/status`);
      const d = await r.json();

      document.getElementById('progressPercent').textContent = Math.round(d.progress) + '%';
      document.getElementById('completed').textContent = `${d.completed} of ${d.urls_count}`;
      document.getElementById('progressFill').style.width = d.progress + '%';
      document.getElementById('status').textContent = d.current_test || '';
      document.getElementById('vulnsLive').textContent = d.vulnerabilities_found || 0;

      if (d.test_progress?.length) {
        document.getElementById('testProgress').innerHTML =
          d.test_progress.slice(-5).map(t => `<div class="test-item">✓ ${t}</div>`).join('');
      }

      if (d.status === 'completed') {
        clearInterval(this.pollTimer);
        const vBtn = document.getElementById('viewResults');
        if (vBtn) { vBtn.style.display = ''; }
        
        // Auto-transition to results panel after 800ms so it doesn't feel stuck
        if (!this._transitioning) {
            this._transitioning = true;
            document.getElementById('status').textContent = 'Finalising report...';
            setTimeout(() => {
                this.showResults();
                this._transitioning = false;
            }, 800);
        }
      }
      if (d.status === 'error') {
        clearInterval(this.pollTimer);
        document.getElementById('status').textContent = 'Error – see console';
      }
    } catch(err) { console.error(err); }
  }

  async showResults() {
    const r = await fetch(`/api/scan/${this.scanId}/results`);
    const d = await r.json();
    this.allResults = d.results || [];
    const s = d.summary || {};

    document.getElementById('progressPanel').classList.add('hidden');
    document.getElementById('resultsPanel').classList.remove('hidden');

    document.getElementById('totalScans').textContent = this.allResults.length;
    document.getElementById('critCount').textContent  = s.critical || 0;
    document.getElementById('highCount').textContent  = s.high     || 0;
    document.getElementById('medCount').textContent   = s.medium   || 0;
    document.getElementById('lowCount').textContent   = s.low      || 0;

    this.renderTable(this.allResults);
  }

  renderTable(results) {
    const filtered = this.activeFilter === 'ALL'
      ? results
      : results.filter(r => r.severity === this.activeFilter);

    const tbody = document.getElementById('resultsTableBody');
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:24px;color:#6b7280;">No findings for this filter.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(r => {
      const c  = SEV_COLOR[r.severity] || '#6b7280';
      const bg = SEV_BG[r.severity]   || '#f3f4f6';
      const urlShort = (r.target_url || '').length > 55
        ? r.target_url.substring(0, 55) + '…' : r.target_url;
      return `<tr style="background:${bg}18;">
        <td><strong>${r.owasp_category || '–'}</strong></td>
        <td style="font-size:13px;">${r.scan_type}</td>
        <td style="font-family:monospace;font-size:11px;color:#475569;" title="${r.target_url}">${urlShort}</td>
        <td><span class="badge" style="background:${c};color:#fff;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;">${r.severity}</span></td>
        <td style="font-weight:700;color:${c};">${r.cvss_score}</td>
        <td style="font-size:12px;max-width:320px;">${r.details}</td>
        <td style="font-family:monospace;font-size:11px;color:#64748b;">${(r.evidence||'').substring(0,60)}</td>
      </tr>`;
    }).join('');
  }

  download(fmt) {
    if (!this.scanId) return;
    window.location.href = `/api/report/${this.scanId}/${fmt}`;
  }

  cancelScan() {
    clearInterval(this.pollTimer);
    this.reset();
  }

  reset() {
    clearInterval(this.pollTimer);
    this.scanId = null; this.allResults = [];
    sessionStorage.removeItem('cyberx_active_scan');
    document.getElementById('configPanel')  ?.classList.remove('hidden');
    document.getElementById('progressPanel')  .classList.add('hidden');
    document.getElementById('resultsPanel')   .classList.add('hidden');
    document.getElementById('urls').value = '';
  }
}

document.addEventListener('DOMContentLoaded', () => new CyberXUI());
