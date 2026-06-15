"""CyberX – Flask API server. Full OWASP Top 10 scanner."""

import os
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file
from scanner.owasp_scanner import OWASPScanner
from scanner.config import ScannerConfig
from scanner.report import ScanResult, ScanReportGenerator
from scanner.logger import setup_logger

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

logger = setup_logger(__name__, level='INFO')

# ── simple in-memory scan store (swap for Redis in prod) ─────────────
active_scans: dict = {}
REPORTS_DIR = Path('reports')
REPORTS_DIR.mkdir(exist_ok=True)

# ── optional API-key auth (set CYBERX_API_KEY env var to enable) ─────
API_KEY = os.environ.get('CYBERX_API_KEY', '')


def _check_api_key():
    if not API_KEY:
        return None  # auth disabled
    key = request.headers.get('X-API-Key', '')
    if key != API_KEY:
        return jsonify({'error': 'Unauthorized – provide X-API-Key header'}), 401
    return None


# ─────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'version': '2.0.0'}), 200


@app.route('/api/scan', methods=['POST'])
def api_scan():
    denied = _check_api_key()
    if denied:
        return denied

    try:
        data = request.get_json(force=True) or {}

        urls = data.get('urls', [])
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.splitlines()]
        urls = [u.strip() for u in urls if u.strip()]
        if not urls:
            return jsonify({'error': 'No valid URLs provided'}), 400

        timeout  = int(data.get('timeout', 7))
        mode     = data.get('mode', 'default')   # default | aggressive | stealth

        # Auth material for authenticated scans
        auth_headers = data.get('auth_headers', {})
        auth_cookies = data.get('auth_cookies', {})
        # Convenience: accept a single "Authorization" Bearer token
        bearer = data.get('bearer_token', '')
        if bearer:
            auth_headers['Authorization'] = f'Bearer {bearer}'
        session_cookie = data.get('session_cookie', '')
        if session_cookie:
            auth_cookies['session'] = session_cookie

        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        active_scans[scan_id] = {
            'status':       'running',
            'progress':     0,
            'urls_count':   len(urls),
            'completed':    0,
            'current_test': 'Initialising…',
            'test_progress': [],
            'results':      [],
            'started':      datetime.now().isoformat(),
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
        return jsonify({'error': str(exc)}), 500


@app.route('/api/scan/<scan_id>/status')
def api_scan_status(scan_id):
    denied = _check_api_key()
    if denied:
        return denied

    info = active_scans.get(scan_id)
    if not info:
        return jsonify({'error': 'Scan not found'}), 404

    vulns_found = sum(1 for r in info['results'] if r.vulnerability_found)
    return jsonify({
        'scan_id':           scan_id,
        'status':            info['status'],
        'progress':          info['progress'],
        'urls_count':        info['urls_count'],
        'completed':         info['completed'],
        'current_test':      info.get('current_test', ''),
        'test_progress':     info.get('test_progress', []),
        'vulnerabilities_found': vulns_found,
    }), 200


@app.route('/api/scan/<scan_id>/results')
def api_scan_results(scan_id):
    denied = _check_api_key()
    if denied:
        return denied

    info = active_scans.get(scan_id)
    if not info:
        return jsonify({'error': 'Scan not found'}), 404
    if info['status'] != 'completed':
        return jsonify({'error': 'Scan still in progress'}), 202

    results = [r.to_dict() for r in info['results']]
    return jsonify({
        'scan_id': scan_id,
        'results': results,
        'summary': {
            'total_findings':   len(results),
            'critical': sum(1 for r in results if r['severity'] == 'CRITICAL'),
            'high':     sum(1 for r in results if r['severity'] == 'HIGH'),
            'medium':   sum(1 for r in results if r['severity'] == 'MEDIUM'),
            'low':      sum(1 for r in results if r['severity'] == 'LOW'),
        },
    }), 200


@app.route('/api/report/<scan_id>/<fmt>')
def api_download_report(scan_id, fmt):
    denied = _check_api_key()
    if denied:
        return denied

    info = active_scans.get(scan_id)
    if not info:
        return jsonify({'error': 'Scan not found'}), 404
    if info['status'] != 'completed':
        return jsonify({'error': 'Scan still in progress'}), 202

    results = info['results']
    if not results:
        return jsonify({'error': 'No results'}), 404

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
        )

        all_results = []

        def _cb(msg):
            active_scans[scan_id]['current_test'] = msg
            prog = active_scans[scan_id]['test_progress']
            if msg not in prog:
                prog.append(msg)
            active_scans[scan_id]['test_progress'] = prog[-12:]

        scanner.set_progress_callback(_cb)

        for idx, url in enumerate(urls):
            active_scans[scan_id]['current_test'] = f'Scanning: {url}'
            try:
                raw = scanner.scan_url(url)
                for v in raw.get('vulnerabilities', []):
                    sev = v.get('severity', 'MEDIUM')
                    all_results.append(ScanResult(
                        scan_type=v.get('type', 'Unknown'),
                        target_url=v.get('url', url) or url,
                        vulnerability_found=sev not in ('INFO',),
                        severity=sev,
                        details=v.get('description', ''),
                        cvss_score=float(v.get('cvss_score', 0.0)),
                        scan_duration=0.0,
                        owasp_category=v.get('owasp_category', ''),
                        evidence=v.get('evidence', ''),
                    ))
                # brief pause between URLs to be polite
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
                    scan_duration=0.0,
                    owasp_category='Error',
                ))

            active_scans[scan_id]['completed'] = idx + 1
            active_scans[scan_id]['progress'] = int((idx + 1) / len(urls) * 100)

        active_scans[scan_id].update({
            'results':      all_results,
            'status':       'completed',
            'progress':     100,
            'current_test': 'Scan complete ✓',
        })
        logger.info(f'Scan {scan_id} done – {len(all_results)} findings')

    except Exception as exc:
        logger.error(f'Fatal scan error {scan_id}: {exc}')
        active_scans[scan_id].update({
            'status':       'error',
            'error':        str(exc),
            'current_test': f'Error: {exc}',
        })


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug, host='0.0.0.0', port=5000)
