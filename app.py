"""Flask web application for CyberScan vulnerability detection engine."""

import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path

from scanner.sql_injection import scan_sqli
from scanner.xss import scan_reflected_xss
from scanner.batch import BatchScanner
from scanner.config import ScannerConfig
from scanner.report import ScanResult, ScanReportGenerator
from scanner.logger import setup_logger
from scanner.owasp_scanner import OWASPScanner
import time

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

logger = setup_logger(__name__, level='INFO')

# Store active scans for progress tracking
active_scans = {}
REPORTS_DIR = Path('reports')
REPORTS_DIR.mkdir(exist_ok=True)


@app.route('/')
def index():
    """Render main scan interface."""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for starting a scan."""
    try:
        data = request.get_json()
        
        # Validate input
        urls = data.get('urls', [])
        scan_type = data.get('scan_type', 'all')
        timeout = data.get('timeout', 5)
        aggressive = data.get('aggressive', False)
        stealth = data.get('stealth', False)
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        if isinstance(urls, str):
            urls = [urls]
        
        urls = [u.strip() for u in urls if u.strip()]
        
        if not urls:
            return jsonify({'error': 'No valid URLs provided'}), 400
        
        # Configure scanner
        if aggressive:
            config = ScannerConfig.get_aggressive()
        elif stealth:
            config = ScannerConfig.get_stealth()
        else:
            config = ScannerConfig.get_default()
        
        config.request_timeout = timeout
        
        # Generate scan ID
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        
        # Store scan info
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'urls_count': len(urls),
            'completed': 0,
            'current_test': 'Initializing...',
            'test_progress': [],
            'results': [],
            'started': datetime.now().isoformat()
        }
        
        # Start scan in background thread
        thread = threading.Thread(
            target=_run_scan,
            args=(scan_id, urls, scan_type, config)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'urls_count': len(urls)}), 202
    
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def api_scan_status(scan_id):
    """Get scan progress and status."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_info = active_scans[scan_id]
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan_info['status'],
        'progress': scan_info['progress'],
        'urls_count': scan_info['urls_count'],
        'completed': scan_info['completed'],
        'current_test': scan_info.get('current_test', ''),
        'test_progress': scan_info.get('test_progress', []),
        'vulnerabilities_found': sum(
            1 for r in scan_info['results'] if r.get('vulnerability_found', False)
        )
    }), 200


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def api_scan_results(scan_id):
    """Get scan results."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_info = active_scans[scan_id]
    
    if scan_info['status'] != 'completed':
        return jsonify({'error': 'Scan still in progress'}), 202
    
    results = [r.to_dict() for r in scan_info['results']]
    
    return jsonify({
        'scan_id': scan_id,
        'results': results,
        'summary': {
            'total_scans': len(results),
            'vulnerabilities_found': sum(1 for r in results if r['vulnerability_found']),
            'critical_high': sum(
                1 for r in results if r['severity'] in ['CRITICAL', 'HIGH']
            )
        }
    }), 200


@app.route('/api/report/<scan_id>/<format>', methods=['GET'])
def api_download_report(scan_id, format):
    """Download report in specified format."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_info = active_scans[scan_id]
    results = scan_info['results']
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    try:
        if format == 'html':
            filepath = REPORTS_DIR / f'report_{scan_id}.html'
            ScanReportGenerator.to_html(results, str(filepath))
            return send_file(
                str(filepath),
                mimetype='text/html',
                as_attachment=True,
                download_name=f'cyberscan_report_{timestamp}.html'
            )
        
        elif format == 'json':
            filepath = REPORTS_DIR / f'report_{scan_id}.json'
            json_str = ScanReportGenerator.to_json(results, str(filepath))
            return send_file(
                str(filepath),
                mimetype='application/json',
                as_attachment=True,
                download_name=f'cyberscan_report_{timestamp}.json'
            )
        
        elif format == 'csv':
            filepath = REPORTS_DIR / f'report_{scan_id}.csv'
            ScanReportGenerator.to_csv(results, str(filepath))
            return send_file(
                str(filepath),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'cyberscan_report_{timestamp}.csv'
            )
        
        else:
            return jsonify({'error': 'Invalid format'}), 400
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


def _run_scan(scan_id, urls, scan_type, config):
    """Background scan worker using OWASP Top 10 scanner."""
    try:
        logger.info(f"Starting OWASP scan {scan_id} on {len(urls)} URLs")
        
        # Initialize OWASP scanner
        scanner = OWASPScanner(timeout=config.request_timeout)
        all_results = []
        
        # Process each URL
        for idx, url in enumerate(urls):
            def progress_callback(message):
                """Update progress with current test."""
                active_scans[scan_id]['current_test'] = message
                if message not in active_scans[scan_id]['test_progress']:
                    active_scans[scan_id]['test_progress'].append(message)
                active_scans[scan_id]['test_progress'] = active_scans[scan_id]['test_progress'][-10:]  # Keep last 10
            
            scanner.set_progress_callback(progress_callback)
            
            # Simulate realistic scan time with delays between tests
            active_scans[scan_id]['current_test'] = f"Scanning: {url}"
            
            try:
                # Run OWASP comprehensive scan
                scan_result = scanner.scan_url(url)
                
                # Convert to result format
                for vuln in scan_result.get('vulnerabilities', []):
                    result = {
                        'url': url,
                        'owasp_category': vuln.get('owasp_category', 'Unknown'),
                        'vulnerability_type': vuln.get('type', 'Unknown'),
                        'severity': vuln.get('severity', 'MEDIUM'),
                        'description': vuln.get('description', ''),
                        'cvss_score': vuln.get('cvss_score', 0),
                        'vulnerability_found': vuln.get('severity') != 'INFO'
                    }
                    all_results.append(result)
                
                # Add scan timing
                time.sleep(0.5)  # Realistic scan delay
                
            except Exception as e:
                logger.error(f"Error scanning {url}: {str(e)}")
                all_results.append({
                    'url': url,
                    'owasp_category': 'Scan Error',
                    'vulnerability_type': 'Scanner Error',
                    'severity': 'MEDIUM',
                    'description': str(e),
                    'cvss_score': 0,
                    'vulnerability_found': False
                })
            
            # Update progress
            active_scans[scan_id]['completed'] = idx + 1
            active_scans[scan_id]['progress'] = int((idx + 1) / len(urls) * 100)
        
        # Store results
        active_scans[scan_id]['results'] = all_results
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['current_test'] = 'Scan Complete ✓'
        
        logger.info(f"Scan {scan_id} completed with {len(all_results)} findings")
    
    except Exception as e:
        logger.error(f"Error in scan {scan_id}: {str(e)}")
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['error'] = str(e)
        active_scans[scan_id]['current_test'] = f'Error: {str(e)}'


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'version': '1.0.0'}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
