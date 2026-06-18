"""CyberX – Flask API server. Full OWASP Top 10 scanner."""

import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import urllib3
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from scanner.owasp_scanner import OWASPScanner
from scanner.report import ScanResult, ScanReportGenerator
from scanner.logger import setup_logger
from scanner.database import (
    init_db, save_scan, save_findings, mark_scan_error,
    get_all_scans, get_scan, get_findings,
    get_user, get_user_by_username, create_user
)

# Suppress InsecureRequestWarning emitted by requests when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.secret_key = os.environ.get('CYBERX_SECRET_KEY', 'cyberx-super-secret-dev-key')

# ── Authentication ───────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_dict):
        self.id = user_dict['id']
        self.username = user_dict['username']
        self.role = user_dict['role']
        self.password_hash = user_dict['password_hash']

@login_manager.user_loader
def load_user(user_id):
    u = get_user(int(user_id))
    return User(u) if u else None

# ── Rate limiting ──────────────────────────────────────────────────
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=['200 per day', '50 per hour'],
    storage_uri='memory://',
)

logger = setup_logger(__name__, level='INFO')

# ── in-memory store for live progress (NOT persisted) ────────────────
# This only holds running-scan metadata: progress %, current test name,
# and the live ScanResult objects while the scan is still in flight.
# Once the scan completes, results are written to SQLite and this entry
# can be discarded. We keep it around for the session so the UI can
# still call /results without a DB round-trip for the active tab.
active_scans: dict = {}
_scans_lock = threading.Lock()   # guards all reads/writes of active_scans

# Evict entries that have been completed/errored for more than this long.
_EVICT_AFTER = timedelta(hours=1)
_EVICT_INTERVAL = 300  # seconds between eviction sweeps

REPORTS_DIR = Path('reports')
REPORTS_DIR.mkdir(exist_ok=True)

# ── optional API-key auth ─────────────────────────────────────────────
API_KEY = os.environ.get('CYBERX_API_KEY', '')

IS_PRODUCTION = os.environ.get('FLASK_DEBUG', '0') != '1'


def _check_api_key():
    if not API_KEY:
        return None
    key = request.headers.get('X-API-Key', '')
    if key != API_KEY:
        return jsonify({'error': 'Unauthorized – provide X-API-Key header'}), 401
    return None


def _validate_urls(urls: list) -> tuple:
    """Return (valid_urls, error_message). error_message is None when all OK."""
    validated = []
    for raw in urls:
        parsed = urlparse(raw)
        if parsed.scheme not in ('http', 'https'):
            return [], f'Invalid URL (must start with http:// or https://): {raw!r}'
        if not parsed.netloc:
            return [], f'Invalid URL (missing host): {raw!r}'
        validated.append(raw)
    return validated, None


def _evict_old_scans():
    """Background thread: remove stale completed/errored entries from active_scans."""
    while True:
        time.sleep(_EVICT_INTERVAL)
        cutoff = datetime.now() - _EVICT_AFTER
        to_delete = []
        with _scans_lock:
            for sid, info in active_scans.items():
                if info['status'] in ('completed', 'error'):
                    try:
                        started = datetime.fromisoformat(info['started'])
                        if started < cutoff:
                            to_delete.append(sid)
                    except Exception:
                        pass
            for sid in to_delete:
                del active_scans[sid]
        if to_delete:
            logger.info(f'Evicted {len(to_delete)} stale scan(s) from memory')


# ── initialise DB on startup ──────────────────────────────────────────
# Called once when the module is imported. Safe because init_db uses
# CREATE TABLE IF NOT EXISTS — running it multiple times is harmless.
init_db()
logger.info('Database initialised')

# ── start background eviction thread ─────────────────────────────────
_evict_thread = threading.Thread(target=_evict_old_scans, daemon=True, name='scan-evictor')
_evict_thread.start()
logger.info('Scan eviction thread started')


# ─────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/history')
@login_required
def history_page():
    """Scan history dashboard."""
    return render_template('history.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        username = data.get('username')
        password = data.get('password')
        
        user_dict = get_user_by_username(username)
        if user_dict and check_password_hash(user_dict['password_hash'], password):
            user = User(user_dict)
            login_user(user)
            return jsonify({'success': True}) if request.is_json else redirect(url_for('index'))
            
        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        return render_template('login.html', error='Invalid credentials')
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password or len(password) < 6:
            msg = 'Username required, password min 6 chars.'
            if request.is_json: return jsonify({'error': msg}), 400
            return render_template('login.html', error=msg)
            
        try:
            # For this deployed version, everyone defaults to guest to prevent abuse
            role = 'guest'
            if username == 'admin': # Convenience for the owner
                role = 'admin'
                
            create_user(username, generate_password_hash(password), role)
            user_dict = get_user_by_username(username)
            login_user(User(user_dict))
            return jsonify({'success': True}) if request.is_json else redirect(url_for('index'))
        except ValueError:
            msg = 'Username already taken'
            if request.is_json: return jsonify({'error': msg}), 409
            return render_template('login.html', error=msg)
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/api/history')
@login_required
def api_history():
    """Return the most recent 50 scans for the history dashboard."""
    try:
        scans = get_all_scans(user_id=current_user.id, limit=50)
        return jsonify({'scans': scans}), 200
    except Exception as exc:
        logger.error(f'History fetch error: {exc}')
        return jsonify({'error': 'Failed to load history'}), 500


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'version': '2.0.0'}), 200


@app.route('/api/scan', methods=['POST'])
@limiter.limit('10 per minute', error_message='Rate limit exceeded — max 10 scans per minute per IP')
@login_required
def api_scan():
    try:
        data = request.get_json(force=True) or {}

        urls = data.get('urls', [])
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.splitlines()]
        urls = [u.strip() for u in urls if u.strip()]
        if not urls:
            return jsonify({'error': 'No valid URLs provided'}), 400

        # Validate URL format before kicking off any scanning
        urls, url_error = _validate_urls(urls)
        if url_error:
            return jsonify({'error': url_error}), 400

        # Safe-Mode Enforcement
        if current_user.role != 'admin':
            safe_targets = ['juice-shop.herokuapp.com', 'httpbin.org']
            for u in urls:
                parsed = urlparse(u)
                if parsed.hostname not in safe_targets:
                    return jsonify({
                        'error': f'Guest accounts are restricted to safe targets to prevent abuse. Unauthorised target: {parsed.hostname}. Allowed targets: {", ".join(safe_targets)}'
                    }), 403

        timeout  = int(data.get('timeout', 7))
        mode     = data.get('mode', 'default')
        if mode not in ('default', 'aggressive'):
            mode = 'default'

        auth_headers = data.get('auth_headers', {})
        auth_cookies = data.get('auth_cookies', {})
        bearer = data.get('bearer_token', '')
        if bearer:
            auth_headers['Authorization'] = f'Bearer {bearer}'
        session_cookie = data.get('session_cookie', '')
        if session_cookie:
            auth_cookies['session'] = session_cookie

        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')

        # 1. Write scan row to DB immediately (status='running')
        save_scan(scan_id, urls, mode, user_id=current_user.id)

        # 2. Seed the in-memory progress tracker for live polling
        with _scans_lock:
            active_scans[scan_id] = {
                'status':        'running',
                'progress':      0,
                'urls_count':    len(urls),
                'completed':     0,
                'current_test':  'Initialising…',
                'test_progress': [],
                'results':       [],
                'started':       datetime.now().isoformat(),
            }

        thread = threading.Thread(
            target=_run_scan,
            args=(scan_id, urls, timeout, mode, auth_headers, auth_cookies),
            daemon=True,
        )
        thread.start()

        return jsonify({'scan_id': scan_id, 'urls_count': len(urls)}), 202

    except Exception as exc:
        logger.error(f'Error starting scan: {exc}')
        # Never leak raw tracebacks in production — return a generic message
        msg = str(exc) if not IS_PRODUCTION else 'Internal error starting scan'
        return jsonify({'error': msg}), 500


@app.route('/api/scan/<scan_id>/status')
@limiter.exempt
@login_required
def api_scan_status(scan_id):

    # Check live memory first (fast path for running scans)
    with _scans_lock:
        info = active_scans.get(scan_id)
        if info:
            info_copy = dict(info)
    if info:
        vulns_found = sum(1 for r in info_copy['results'] if r.vulnerability_found)
        return jsonify({
            'scan_id':               scan_id,
            'status':                info_copy['status'],
            'progress':              info_copy['progress'],
            'urls_count':            info_copy['urls_count'],
            'completed':             info_copy['completed'],
            'current_test':          info_copy.get('current_test', ''),
            'test_progress':         info_copy.get('test_progress', []),
            'vulnerabilities_found': vulns_found,
        }), 200

    # Fall back to DB for historical scans (server was restarted etc.)
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify({
        'scan_id':               scan_id,
        'status':                scan['status'],
        'progress':              100,
        'urls_count':            scan['urls_count'],
        'completed':             scan['urls_count'],
        'current_test':          'Loaded from history',
        'test_progress':         [],
        'vulnerabilities_found': scan['total_findings'],
    }), 200


@app.route('/api/scan/<scan_id>/results')
@limiter.exempt
@login_required
def api_scan_results(scan_id):

    # Try live memory first
    with _scans_lock:
        info = active_scans.get(scan_id)
        if info:
            info_copy = dict(info)
    if info:
        if info_copy['status'] == 'error':
            return jsonify({'error': 'Scan failed: ' + info_copy.get('error', 'unknown')}), 500
        if info_copy['status'] != 'completed':
            return jsonify({'error': 'Scan still in progress'}), 202
        results = [r.to_dict() for r in info_copy['results']]
    else:
        # Load from DB — handles history page and post-restart access
        scan = get_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        if scan['status'] == 'error':
            return jsonify({'error': 'Scan failed'}), 500
        if scan['status'] != 'completed':
            return jsonify({'error': 'Scan still in progress'}), 202
        results = get_findings(scan_id)

    return jsonify({
        'scan_id': scan_id,
        'results': results,
        'summary': {
            'total_findings': len(results),
            'critical': sum(1 for r in results if r.get('severity') == 'CRITICAL'),
            'high':     sum(1 for r in results if r.get('severity') == 'HIGH'),
            'medium':   sum(1 for r in results if r.get('severity') == 'MEDIUM'),
            'low':      sum(1 for r in results if r.get('severity') == 'LOW'),
        },
    }), 200



@app.route('/api/report/<scan_id>/<fmt>')
@login_required
def api_download_report(scan_id, fmt):

    # Try live memory first, then DB
    info = active_scans.get(scan_id)
    if info:
        if info['status'] == 'error':
            return jsonify({'error': 'Scan failed, no report available'}), 500
        if info['status'] != 'completed':
            return jsonify({'error': 'Scan still in progress'}), 202
        results = info['results']
        if not results:
            return jsonify({'error': 'No results'}), 404
    else:
        scan = get_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        if scan['status'] == 'error':
            return jsonify({'error': 'Scan failed, no report available'}), 500
        if scan['status'] != 'completed':
            return jsonify({'error': 'Scan still in progress'}), 202
        # Reconstruct ScanResult objects from DB rows for the report generator
        rows = get_findings(scan_id)
        if not rows:
            return jsonify({'error': 'No results'}), 404
        results = [
            ScanResult(
                scan_type=r['scan_type'],
                target_url=r['target_url'],
                vulnerability_found=True,
                severity=r['severity'],
                details=r['details'],
                cvss_score=r['cvss_score'],
                scan_duration=0.0,
                owasp_category=r['owasp_category'],
                evidence=r['evidence'],
            )
            for r in rows
        ]

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    try:
        if fmt == 'html':
            fp = REPORTS_DIR / f'report_{scan_id}.html'
            ScanReportGenerator.to_html(results, str(fp))
            return send_file(str(fp), mimetype='text/html', as_attachment=True,
                             download_name=f'cyberx_report_{ts}.html')
        elif fmt == 'json':
            fp = REPORTS_DIR / f'report_{scan_id}.json'
            ScanReportGenerator.to_json(results, str(fp))
            return send_file(str(fp), mimetype='application/json', as_attachment=True,
                             download_name=f'cyberx_report_{ts}.json')
        elif fmt == 'csv':
            fp = REPORTS_DIR / f'report_{scan_id}.csv'
            ScanReportGenerator.to_csv(results, str(fp))
            return send_file(str(fp), mimetype='text/csv', as_attachment=True,
                             download_name=f'cyberx_report_{ts}.csv')
        else:
            return jsonify({'error': 'Use html, json, or csv'}), 400
    except Exception as exc:
        logger.error(f'Report error: {exc}')
        return jsonify({'error': str(exc)}), 500


# ─────────────────────────────────────────────────────────────────────
# Background worker
# ─────────────────────────────────────────────────────────────────────

def _run_scan(scan_id, urls, timeout, mode, auth_headers, auth_cookies):
    try:
        logger.info(f'Scan {scan_id} starting – {len(urls)} URL(s), mode={mode}')

        scanner = OWASPScanner(
            timeout=timeout,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            mode=mode,
        )

        all_results = []

        def _cb(msg):
            with _scans_lock:
                active_scans[scan_id]['current_test'] = msg
                prog = active_scans[scan_id]['test_progress']
                if msg not in prog:
                    prog.append(msg)
                active_scans[scan_id]['test_progress'] = prog[-12:]

        scanner.set_progress_callback(_cb)

        # Aggressive mode: crawl each URL for additional parameterised endpoints
        if mode == 'aggressive':
            _cb('Crawling links…')
            discovered: list = []
            seen_urls = set(urls)
            for seed_url in list(urls):
                try:
                    found = scanner.crawl_links(seed_url)
                    for link in found:
                        if link not in seen_urls:
                            seen_urls.add(link)
                            discovered.append(link)
                except Exception as exc:
                    logger.debug(f'Crawler error for {seed_url}: {exc}')
            if discovered:
                logger.info(f'Crawler discovered {len(discovered)} additional URL(s) to scan')
                urls = list(urls) + discovered
                with _scans_lock:
                    active_scans[scan_id]['urls_count'] = len(urls)

        for idx, url in enumerate(urls):

            with _scans_lock:
                active_scans[scan_id]['current_test'] = f'Scanning: {url}'
            url_start = time.time()
            try:
                raw = scanner.scan_url(url)
                url_duration = time.time() - url_start
                for v in raw.get('vulnerabilities', []):
                    sev = v.get('severity', 'MEDIUM')
                    all_results.append(ScanResult(
                        scan_type=v.get('type', 'Unknown'),
                        target_url=v.get('url', url) or url,
                        vulnerability_found=sev not in ('INFO',),
                        severity=sev,
                        details=v.get('description', ''),
                        cvss_score=float(v.get('cvss_score', 0.0)),
                        scan_duration=round(url_duration, 3),
                        owasp_category=v.get('owasp_category', ''),
                        evidence=v.get('evidence', ''),
                    ))
                time.sleep(0.3)
            except Exception as exc:
                logger.error(f'Error scanning {url}: {exc}')
                all_results.append(ScanResult(
                    scan_type='Scanner Error',
                    target_url=url,
                    vulnerability_found=False,
                    severity='MEDIUM',
                    details=str(exc),
                    cvss_score=0.0,
                    scan_duration=round(time.time() - url_start, 3),
                    owasp_category='Error',
                ))

            with _scans_lock:
                active_scans[scan_id]['completed'] = idx + 1
                active_scans[scan_id]['progress']  = int((idx + 1) / len(urls) * 100)

        # Update in-memory store
        with _scans_lock:
            active_scans[scan_id].update({
                'results':      all_results,
                'status':       'completed',
                'progress':     100,
                'current_test': 'Scan complete ✓',
            })

        # Persist to SQLite
        save_findings(scan_id, all_results)
        logger.info(f'Scan {scan_id} done – {len(all_results)} findings saved to DB')

    except Exception as exc:
        logger.error(f'Fatal scan error {scan_id}: {exc}')
        with _scans_lock:
            active_scans[scan_id].update({
                'status':       'error',
                'error':        str(exc),
                'current_test': f'Error: {exc}',
            })
        mark_scan_error(scan_id, str(exc))


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug, host='0.0.0.0', port=5000)
