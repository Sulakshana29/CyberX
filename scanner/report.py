"""Scan result management and multi-format reporting for CyberX."""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


class ScanResult:
    """One vulnerability finding."""

    def __init__(self, scan_type: str, target_url: str, vulnerability_found: bool,
                 severity: str, details: str, cvss_score: float = 0.0,
                 scan_duration: float = 0.0, owasp_category: str = '',
                 evidence: str = ''):
        self.scan_type          = scan_type
        self.target_url         = target_url
        self.vulnerability_found = vulnerability_found
        self.severity           = severity
        self.cvss_score         = cvss_score
        self.details            = details
        self.evidence           = evidence
        self.timestamp          = datetime.now()
        self.scan_duration      = scan_duration
        self.owasp_category     = owasp_category

    def to_dict(self) -> Dict:
        return {
            'owasp_category':       self.owasp_category,
            'scan_type':            self.scan_type,
            'target_url':           self.target_url,
            'vulnerability_found':  self.vulnerability_found,
            'severity':             self.severity,
            'cvss_score':           self.cvss_score,
            'details':              self.details,
            'evidence':             self.evidence,
            'timestamp':            self.timestamp.isoformat(),
            'scan_duration_seconds': round(self.scan_duration, 3),
        }


class ScanReportGenerator:
    """Generate vulnerability reports as HTML / JSON / CSV."""

    # ------------------------------------------------------------------ JSON
    @staticmethod
    def to_json(results: List[ScanResult], filepath: Optional[str] = None) -> str:
        report = {
            'generator':    'CyberX v2.0',
            'generated_at': datetime.now().isoformat(),
            'total':        len(results),
            'critical':     sum(1 for r in results if r.severity == 'CRITICAL'),
            'high':         sum(1 for r in results if r.severity == 'HIGH'),
            'medium':       sum(1 for r in results if r.severity == 'MEDIUM'),
            'low':          sum(1 for r in results if r.severity == 'LOW'),
            'results':      [r.to_dict() for r in results],
        }
        out = json.dumps(report, indent=2)
        if filepath:
            Path(filepath).write_text(out)
        return out

    # ------------------------------------------------------------------ CSV
    @staticmethod
    def to_csv(results: List[ScanResult], filepath: str) -> None:
        if not results:
            return
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].to_dict().keys())
            writer.writeheader()
            for r in results:
                writer.writerow(r.to_dict())

    # ------------------------------------------------------------------ HTML
    @staticmethod
    def to_html(results: List[ScanResult], filepath: str) -> None:
        sev_color = {
            'CRITICAL': '#dc2626', 'HIGH': '#ea580c',
            'MEDIUM':   '#d97706', 'LOW':  '#2563eb',
        }
        sev_bg = {
            'CRITICAL': '#fee2e2', 'HIGH': '#ffedd5',
            'MEDIUM':   '#fef3c7', 'LOW':  '#dbeafe',
        }

        total    = len(results)
        critical = sum(1 for r in results if r.severity == 'CRITICAL')
        high     = sum(1 for r in results if r.severity == 'HIGH')
        medium   = sum(1 for r in results if r.severity == 'MEDIUM')
        low      = sum(1 for r in results if r.severity == 'LOW')

        rows = ''
        for r in results:
            color = sev_color.get(r.severity, '#6b7280')
            bg    = sev_bg.get(r.severity, '#f3f4f6')
            rows += f"""
            <tr style="background:{bg}10;">
              <td style="font-weight:600;color:#1e293b;">{r.owasp_category}</td>
              <td>{r.scan_type}</td>
              <td style="font-family:monospace;font-size:12px;color:#475569;">{r.target_url[:80]}</td>
              <td><span class="badge" style="background:{color};">{r.severity}</span></td>
              <td style="font-weight:700;color:{color};">{r.cvss_score}</td>
              <td style="font-size:13px;">{r.details}</td>
              <td style="font-family:monospace;font-size:11px;color:#64748b;">{r.evidence[:60]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CyberX Security Report</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}
    .wrap{{max-width:1400px;margin:0 auto}}
    h1{{font-size:28px;font-weight:800;background:linear-gradient(135deg,#38bdf8,#818cf8);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}}
    .sub{{color:#64748b;margin-bottom:24px;font-size:14px}}
    .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}}
    .card{{background:#1e293b;border-radius:12px;padding:20px;text-align:center;
           border:1px solid #334155}}
    .card .num{{font-size:32px;font-weight:800;margin:6px 0}}
    .card .lbl{{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em}}
    .c-red{{color:#ef4444}}.c-ora{{color:#f97316}}.c-yel{{color:#f59e0b}}.c-blu{{color:#3b82f6}}
    table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;
           overflow:hidden;border:1px solid #334155}}
    thead th{{background:#0f172a;color:#94a3b8;padding:12px 14px;text-align:left;
              font-size:12px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #334155}}
    tbody td{{padding:12px 14px;border-bottom:1px solid #1e293b20;vertical-align:top}}
    tbody tr:hover td{{background:#ffffff08}}
    .badge{{display:inline-block;padding:3px 10px;border-radius:999px;color:#fff;
            font-size:11px;font-weight:700;letter-spacing:.04em}}
    .footer{{margin-top:24px;color:#475569;font-size:12px;text-align:center}}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡 CyberX Security Report</h1>
  <p class="sub">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} — OWASP Top 10 (2021)</p>

  <div class="cards">
    <div class="card"><div class="lbl">Total Findings</div><div class="num" style="color:#e2e8f0">{total}</div></div>
    <div class="card"><div class="lbl">Critical</div><div class="num c-red">{critical}</div></div>
    <div class="card"><div class="lbl">High</div><div class="num c-ora">{high}</div></div>
    <div class="card"><div class="lbl">Medium / Low</div><div class="num c-yel">{medium + low}</div></div>
  </div>

  <table>
    <thead><tr>
      <th>OWASP</th><th>Type</th><th>URL</th><th>Severity</th>
      <th>CVSS</th><th>Description</th><th>Evidence</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <div class="footer">CyberX v2.0 — for authorised security testing only</div>
</div>
</body>
</html>"""
        Path(filepath).write_text(html, encoding='utf-8')
