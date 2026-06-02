"""Scan result management and reporting for CyberScan."""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


class ScanResult:
    """Represents a single vulnerability scan result.
    
    Attributes:
        scan_type: Type of scan (SQL_INJECTION, REFLECTED_XSS).
        target_url: Target URL that was scanned.
        vulnerability_found: Whether a vulnerability was detected.
        severity: Severity level (Critical, High, Medium, Low).
        cvss_score: CVSS v3.1 score (0-10).
        details: Detailed description of findings.
        timestamp: When the scan was performed.
        scan_duration: Duration of scan in seconds.
    """
    
    def __init__(
        self,
        scan_type: str,
        target_url: str,
        vulnerability_found: bool,
        severity: str,
        details: str,
        cvss_score: float = 0.0,
        scan_duration: float = 0.0
    ):
        self.scan_type = scan_type
        self.target_url = target_url
        self.vulnerability_found = vulnerability_found
        self.severity = severity
        self.cvss_score = cvss_score
        self.details = details
        self.timestamp = datetime.now()
        self.scan_duration = scan_duration
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary.
        
        Returns:
            Dictionary representation of scan result.
        """
        return {
            'scan_type': self.scan_type,
            'target_url': self.target_url,
            'vulnerability_found': self.vulnerability_found,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'scan_duration_seconds': round(self.scan_duration, 3)
        }


class ScanReportGenerator:
    """Generate vulnerability scan reports in multiple formats."""
    
    @staticmethod
    def to_json(results: List[ScanResult], filepath: Optional[str] = None) -> str:
        """Export scan results to JSON format.
        
        Args:
            results: List of ScanResult objects.
            filepath: Optional file path to save JSON report.
            
        Returns:
            JSON string of results.
        """
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_scans': len(results),
            'vulnerabilities_found': sum(1 for r in results if r.vulnerability_found),
            'results': [r.to_dict() for r in results]
        }
        
        json_str = json.dumps(report, indent=2)
        
        if filepath:
            Path(filepath).write_text(json_str)
        
        return json_str
    
    @staticmethod
    def to_csv(results: List[ScanResult], filepath: str) -> None:
        """Export scan results to CSV format.
        
        Args:
            results: List of ScanResult objects.
            filepath: File path to save CSV report.
        """
        if not results:
            return
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].to_dict().keys())
            writer.writeheader()
            for result in results:
                writer.writerow(result.to_dict())
    
    @staticmethod
    def to_html(results: List[ScanResult], filepath: str) -> None:
        """Export scan results to HTML format with styling.
        
        Args:
            results: List of ScanResult objects.
            filepath: File path to save HTML report.
        """
        vulnerability_count = sum(1 for r in results if r.vulnerability_found)
        
        severity_colors = {
            'CRITICAL': '#d9534f',
            'HIGH': '#ec971f',
            'MEDIUM': '#f0ad4e',
            'LOW': '#5bc0de',
            'Info': '#5bc0de',
            'Error': '#d9534f'
        }
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberScan - Vulnerability Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card h3 {{ font-size: 28px; margin: 10px 0; }}
        .summary-card p {{ opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #333; color: white; padding: 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f9f9f9; }}
        .severity-badge {{ display: inline-block; padding: 6px 12px; border-radius: 4px; color: white; font-weight: 600; }}
        .vuln-found {{ background: #d9534f; color: white; }}
        .vuln-not-found {{ background: #5cb85c; color: white; }}
        .timestamp {{ color: #666; font-size: 14px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 CyberScan Vulnerability Report</h1>
        <p style="color: #666; margin-bottom: 20px;">Automated Security Vulnerability Detection</p>
        
        <div class="summary">
            <div class="summary-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <p>Total Scans</p>
                <h3>{len(results)}</h3>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <p>Vulnerabilities</p>
                <h3>{vulnerability_count}</h3>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                <p>Critical/High</p>
                <h3>{sum(1 for r in results if r.severity in ['CRITICAL', 'HIGH'])}</h3>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                <p>Clean</p>
                <h3>{sum(1 for r in results if not r.vulnerability_found)}</h3>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Scan Type</th>
                    <th>Target URL</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>CVSS Score</th>
                    <th>Details</th>
                    <th>Duration</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in results:
            status_class = 'vuln-found' if result.vulnerability_found else 'vuln-not-found'
            status_text = '✓ VULNERABLE' if result.vulnerability_found else '✓ CLEAN'
            severity_color = severity_colors.get(result.severity, '#5bc0de')
            
            html_content += f"""
                <tr>
                    <td><strong>{result.scan_type}</strong></td>
                    <td><code>{result.target_url}</code></td>
                    <td><span class="severity-badge {status_class}">{status_text}</span></td>
                    <td><span class="severity-badge" style="background: {severity_color};">{result.severity}</span></td>
                    <td><strong>{result.cvss_score}</strong></td>
                    <td>{result.details}</td>
                    <td>{result.scan_duration_seconds:.3f}s</td>
                </tr>
"""
        
        html_content += f"""
            </tbody>
        </table>
        
        <div class="timestamp">
            <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>CyberScan v1.0</strong> - Production-Grade Vulnerability Detection Engine</p>
        </div>
    </div>
</body>
</html>
"""
        
        Path(filepath).write_text(html_content)
