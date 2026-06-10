"""OWASP Top 10 comprehensive vulnerability scanner with WSTG categories."""

import requests
import secrets
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from scanner.logger import setup_logger
from scanner.cvss import calculate_cvss_score

logger = setup_logger(__name__)


class OWASPScanner:
    """Comprehensive OWASP Top 10 vulnerability scanner."""

    # --- A03: SQL Injection ---
    # Error-based signatures per DBMS (lowercase for case-insensitive match)
    SQL_ERROR_SIGNATURES = {
        'MySQL':      ['you have an error in your sql syntax', 'warning: mysql_',
                       'mysql_fetch', 'mysql_error', 'mysql_num_rows'],
        'PostgreSQL': ['pg_query(): query error', 'error: syntax error at or near',
                       'pg_connect', 'sqlstate'],
        'SQLite':     ['operationalerror: near', 'sqlite3.operationalerror',
                       'sqlite error', 'database disk image is malformed'],
        'MSSQL':      ['sql server error', 'incorrect syntax near',
                       'odbc error', 'adodb.recordset'],
        'Oracle':     ['ora-01756', 'ora-00907', 'oracle error',
                       'quoted string not properly terminated'],
    }

    SQL_INJECTION_PAYLOADS = ["'", '"', "')", '")', "1' OR '1'='1", "' OR 1=1 --"]

    # --- A03: XSS (canary-based to avoid false positives) ---
    XSS_VECTOR_TEMPLATES = [
        "<script>alert('{canary}')</script>",
        "<img src=x onerror=\"alert('{canary}')\">",
        "<svg onload=\"alert('{canary}')\">",
        "'\"><script>alert('{canary}')</script>",
        '" onfocus="alert(\'{canary}\')" autofocus="',
    ]

    # --- A03: Command Injection ---
    CMD_INJECTION_PAYLOADS = ["; echo CMDINJECT_{canary}", "| echo CMDINJECT_{canary}",
                               "& echo CMDINJECT_{canary}"]

    # --- A05: Security headers ---
    REQUIRED_SECURITY_HEADERS = {
        'Content-Security-Policy': 'prevents XSS and data injection attacks',
        'X-Frame-Options': 'prevents clickjacking',
        'X-Content-Type-Options': 'prevents MIME-type sniffing',
        'Strict-Transport-Security': 'enforces HTTPS',
        'Referrer-Policy': 'controls referrer leakage',
    }

    # TRACE/CONNECT are dangerous; OPTIONS is informational
    DANGEROUS_METHODS = ['TRACE', 'CONNECT']

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.vulnerabilities: List[Dict] = []
        self.progress_callback = None

    def set_progress_callback(self, callback):
        self.progress_callback = callback

    def _report_progress(self, test_name: str, status: str):
        if self.progress_callback:
            self.progress_callback(f"{test_name}: {status}")

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan_url(self, url: str) -> Dict:
        """Scan a URL for all OWASP Top 10 vulnerabilities."""
        self.vulnerabilities = []

        try:
            self._report_progress("A02 Cryptographic Failures", "Testing...")
            self._scan_cryptographic_failures(url)

            self._report_progress("A03 Injection (SQLi)", "Testing...")
            self._scan_sql_injection(url)

            self._report_progress("A03 Injection (XSS)", "Testing...")
            self._scan_xss(url)

            self._report_progress("A05 Security Misconfiguration", "Testing...")
            self._scan_security_misconfiguration(url)

            self._report_progress("A01 Broken Access Control", "Testing...")
            self._scan_broken_access_control(url)

            self._report_progress("A07 Authentication Failures", "Testing...")
            self._scan_authentication(url)

            self._report_progress("A10 SSRF", "Testing...")
            self._scan_ssrf(url)

            self._report_progress("Scan", "Complete!")

        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            self.vulnerabilities.append({
                'owasp_category': 'Scan Error',
                'type': 'Scanner Error',
                'severity': 'MEDIUM',
                'description': str(e),
                'cvss_score': 0,
            })

        return self._generate_report()

    # ------------------------------------------------------------------
    # A01 – Broken Access Control
    # ------------------------------------------------------------------

    def _scan_broken_access_control(self, url: str):
        """
        A01: Test for IDOR and forced browsing.

        IDOR check: only flags if the URL has a numeric ID-style parameter
        (e.g. ?id=3, ?user_id=42) — not just any param containing 'id'.
        Auth-bypass: checks HTTP 200 on an admin/dashboard path without
        session credentials, but does NOT keyword-scan the response body
        (too noisy).
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # --- IDOR: numeric ID parameters ---
        idor_param_patterns = re.compile(
            r'^(id|user_?id|post_?id|account_?id|record_?id|file_?id|item_?id)$',
            re.IGNORECASE
        )
        for param, values in params.items():
            if idor_param_patterns.match(param) and values and values[0].isdigit():
                self.vulnerabilities.append({
                    'owasp_category': 'A01',
                    'type': 'Potential IDOR',
                    'severity': 'HIGH',
                    'description': (
                        f'Parameter "{param}={values[0]}" looks like a direct object '
                        f'reference. Verify that access control prevents horizontal/vertical '
                        f'privilege escalation by altering this value.'
                    ),
                    'url': url,
                    'cvss_score': 7.5,
                })
                break  # One finding per URL is enough

        # --- Forced browsing: admin/dashboard paths without cookies ---
        admin_paths = ['/admin', '/admin/', '/dashboard', '/administrator',
                       '/wp-admin', '/manage', '/console']
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in admin_paths:
            test_url = base + path
            try:
                resp = requests.get(
                    test_url, timeout=self.timeout,
                    allow_redirects=False,
                    headers={'User-Agent': 'CyberScan/1.0'}
                )
                # 200 on an admin path with no session = possible auth bypass
                if resp.status_code == 200:
                    self.vulnerabilities.append({
                        'owasp_category': 'A01',
                        'type': 'Unprotected Admin Endpoint',
                        'severity': 'CRITICAL',
                        'description': (
                            f'Admin path "{path}" returned HTTP 200 without '
                            f'authentication. Verify this is intentional.'
                        ),
                        'url': test_url,
                        'cvss_score': 9.1,
                    })
                    break
            except Exception:
                pass

    # ------------------------------------------------------------------
    # A02 – Cryptographic Failures
    # ------------------------------------------------------------------

    def _scan_cryptographic_failures(self, url: str):
        """A02: HTTP instead of HTTPS; invalid SSL certificate."""
        parsed = urlparse(url)

        if parsed.scheme == 'http':
            self.vulnerabilities.append({
                'owasp_category': 'A02',
                'type': 'Unencrypted Connection',
                'severity': 'HIGH',
                'description': 'Site uses HTTP — data is transmitted in plaintext.',
                'url': url,
                'cvss_score': 7.5,
            })

        if parsed.scheme == 'https':
            try:
                requests.get(url, timeout=self.timeout, verify=True)
            except requests.exceptions.SSLError:
                self.vulnerabilities.append({
                    'owasp_category': 'A02',
                    'type': 'SSL/TLS Certificate Error',
                    'severity': 'MEDIUM',
                    'description': 'Invalid or self-signed SSL/TLS certificate detected.',
                    'url': url,
                    'cvss_score': 6.5,
                })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # A03 – Injection: SQL
    # ------------------------------------------------------------------

    def _build_injected_url(self, url: str, param: str, payload: str) -> str:
        """Return a URL with `payload` appended to `param`'s value."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        original = params.get(param, [''])[0]
        params[param] = [original + payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _detect_sqli_in_response(self, text: str) -> Optional[Tuple[str, str]]:
        """Return (db_type, signature) if a SQL error is found, else None."""
        lower = text.lower()
        for db_type, signatures in self.SQL_ERROR_SIGNATURES.items():
            for sig in signatures:
                if sig in lower:
                    return db_type, sig
        return None

    def _scan_sql_injection(self, url: str):
        """
        A03/SQLi: Inject error-triggering payloads into every existing query
        parameter. Only reports if a known DB error signature appears in the
        response — avoids the false 'SQL' keyword match.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param in params:
            for payload in self.SQL_INJECTION_PAYLOADS:
                test_url = self._build_injected_url(url, param, payload)
                try:
                    resp = requests.get(
                        test_url, timeout=self.timeout,
                        headers={'User-Agent': 'CyberScan/1.0'}
                    )
                    match = self._detect_sqli_in_response(resp.text)
                    if match:
                        db_type, sig = match
                        self.vulnerabilities.append({
                            'owasp_category': 'A03',
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'description': (
                                f'SQL injection detected in parameter "{param}" '
                                f'(payload: {payload!r}). DB fingerprint: {db_type} '
                                f'— matched signature: "{sig}".'
                            ),
                            'url': test_url,
                            'cvss_score': 9.8,
                        })
                        return  # One confirmed SQLi finding is enough
                except Exception as e:
                    logger.debug(f"SQLi test error on {param}: {e}")

    # ------------------------------------------------------------------
    # A03 – Injection: XSS (canary-based)
    # ------------------------------------------------------------------

    def _scan_xss(self, url: str):
        """
        A03/XSS: Canary-token approach — each payload contains a unique random
        hex string. A positive only fires when that exact canary appears
        unescaped in the response, preventing false positives from generic
        echo behaviour or coincidental matches.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # If no existing params, probe a common reflected search parameter
        probe_params = list(params.keys()) if params else ['q', 'search', 'query']

        for param in probe_params:
            for template in self.XSS_VECTOR_TEMPLATES:
                canary = secrets.token_hex(8)
                payload = template.replace('{canary}', canary)

                # Build test URL — inject into existing param or add new one
                if params:
                    test_url = self._build_injected_url(url, param, payload)
                else:
                    base = url.split('?')[0]
                    test_url = f"{base}?{param}={requests.utils.quote(payload)}"

                try:
                    resp = requests.get(
                        test_url, timeout=self.timeout,
                        headers={'User-Agent': 'CyberScan/1.0'}
                    )
                    # Require the full payload (with canary) to appear verbatim
                    if canary in resp.text and payload in resp.text:
                        self.vulnerabilities.append({
                            'owasp_category': 'A03',
                            'type': 'Reflected XSS',
                            'severity': 'HIGH',
                            'description': (
                                f'Reflected XSS in parameter "{param}". '
                                f'Canary "{canary}" reflected verbatim and unescaped.'
                            ),
                            'url': test_url,
                            'cvss_score': 6.1,
                        })
                        return
                except Exception as e:
                    logger.debug(f"XSS test error on {param}: {e}")

    # ------------------------------------------------------------------
    # A05 – Security Misconfiguration
    # ------------------------------------------------------------------

    def _scan_security_misconfiguration(self, url: str):
        """
        A05: Missing security response headers; server version disclosure;
        dangerous HTTP methods. Uses a HEAD request for header checks to
        avoid downloading large bodies unnecessarily.
        """
        try:
            resp = requests.head(
                url, timeout=self.timeout,
                headers={'User-Agent': 'CyberScan/1.0'},
                allow_redirects=True
            )
            headers = resp.headers

            # Missing security headers
            missing = [
                f"{h} ({desc})"
                for h, desc in self.REQUIRED_SECURITY_HEADERS.items()
                if h not in headers
            ]
            if missing:
                severity = 'HIGH' if len(missing) >= 4 else 'MEDIUM'
                self.vulnerabilities.append({
                    'owasp_category': 'A05',
                    'type': 'Missing Security Headers',
                    'severity': severity,
                    'description': f'Missing: {", ".join(missing)}.',
                    'url': url,
                    'cvss_score': 6.5 if severity == 'HIGH' else 5.3,
                })

            # Server/version disclosure
            for disclosure_header in ('Server', 'X-Powered-By', 'X-AspNet-Version'):
                if disclosure_header in headers:
                    self.vulnerabilities.append({
                        'owasp_category': 'A05',
                        'type': 'Technology Disclosure',
                        'severity': 'LOW',
                        'description': (
                            f'Header "{disclosure_header}" reveals server '
                            f'technology: {headers[disclosure_header]}'
                        ),
                        'url': url,
                        'cvss_score': 3.7,
                    })

            # Dangerous HTTP methods
            for method in self.DANGEROUS_METHODS:
                try:
                    method_resp = requests.request(
                        method, url, timeout=self.timeout,
                        headers={'User-Agent': 'CyberScan/1.0'}
                    )
                    if method_resp.status_code not in (405, 501, 400):
                        self.vulnerabilities.append({
                            'owasp_category': 'A05',
                            'type': f'{method} Method Enabled',
                            'severity': 'HIGH',
                            'description': (
                                f'HTTP method {method} returned '
                                f'{method_resp.status_code} (expected 405).'
                            ),
                            'url': url,
                            'cvss_score': 7.5,
                        })
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"A05 scan error: {e}")

    # ------------------------------------------------------------------
    # A07 – Authentication Failures
    # ------------------------------------------------------------------

    def _scan_authentication(self, url: str):
        """
        A07: Detect insecure cookie attributes by inspecting the raw
        Set-Cookie header, not the string repr of the Cookie object.
        """
        try:
            resp = requests.get(
                url, timeout=self.timeout,
                headers={'User-Agent': 'CyberScan/1.0'}
            )

            # Check raw Set-Cookie headers (requests doesn't expose flags via .cookies)
            set_cookie_headers = resp.headers.get('Set-Cookie', '')
            if not set_cookie_headers:
                # Some servers return multiple Set-Cookie headers
                set_cookie_headers = '\n'.join(
                    v for k, v in resp.headers.items()
                    if k.lower() == 'set-cookie'
                )

            if set_cookie_headers:
                flags_lower = set_cookie_headers.lower()
                missing_flags = []
                if 'httponly' not in flags_lower:
                    missing_flags.append('HttpOnly')
                if 'secure' not in flags_lower:
                    missing_flags.append('Secure')
                if 'samesite' not in flags_lower:
                    missing_flags.append('SameSite')

                if missing_flags:
                    self.vulnerabilities.append({
                        'owasp_category': 'A07',
                        'type': 'Insecure Cookie Flags',
                        'severity': 'MEDIUM',
                        'description': (
                            f'Session cookie missing flags: '
                            f'{", ".join(missing_flags)}.'
                        ),
                        'url': url,
                        'cvss_score': 5.3,
                    })

        except Exception as e:
            logger.debug(f"A07 scan error: {e}")

    # ------------------------------------------------------------------
    # A10 – SSRF
    # ------------------------------------------------------------------

    def _scan_ssrf(self, url: str):
        """
        A10: SSRF detection.

        Strategy: inject an internal address into known URL-like parameters.
        A hit is flagged only when the response contains content that would
        only originate from the internal host (e.g. its title/body text) —
        NOT simply because the word "localhost" appears anywhere on the page
        (that would be a false positive).

        For blind SSRF, response-time deviation is used as a secondary signal.
        """
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)

        # Known SSRF-prone parameter names
        ssrf_param_pattern = re.compile(
            r'^(url|uri|src|href|redirect|next|to|file|path|image|fetch|'
            r'download|load|resource|endpoint|proxy|callback|open)$',
            re.IGNORECASE
        )

        candidate_params = [
            p for p in existing_params if ssrf_param_pattern.match(p)
        ]

        if not candidate_params:
            return  # No URL-like params found — skip to reduce noise

        internal_targets = ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/']

        for param in candidate_params:
            for target in internal_targets:
                test_url = self._build_injected_url(url, param, '')
                # Replace the param value entirely
                test_parsed = urlparse(test_url)
                all_params = parse_qs(test_parsed.query, keep_blank_values=True)
                all_params[param] = [target]
                new_query = urlencode({k: v[0] for k, v in all_params.items()})
                test_url = urlunparse(test_parsed._replace(query=new_query))

                try:
                    import time
                    t0 = time.time()
                    resp = requests.get(
                        test_url, timeout=self.timeout,
                        headers={'User-Agent': 'CyberScan/1.0'}
                    )
                    elapsed = time.time() - t0

                    # Look for AWS metadata or loopback service fingerprints
                    body_lower = resp.text.lower()
                    ssrf_indicators = [
                        'ami-id', 'instance-id', 'local-ipv4',  # AWS metadata
                        'root:x:0:0',                            # /etc/passwd
                        '<title>apache',                         # internal apache
                    ]
                    if any(ind in body_lower for ind in ssrf_indicators):
                        self.vulnerabilities.append({
                            'owasp_category': 'A10',
                            'type': 'SSRF (Confirmed)',
                            'severity': 'CRITICAL',
                            'description': (
                                f'Parameter "{param}" fetched internal resource '
                                f'({target}) and returned internal content.'
                            ),
                            'url': test_url,
                            'cvss_score': 9.0,
                        })
                        return

                    # Blind SSRF signal: timeout or unusual latency
                    if elapsed >= self.timeout * 0.9:
                        self.vulnerabilities.append({
                            'owasp_category': 'A10',
                            'type': 'Potential Blind SSRF',
                            'severity': 'HIGH',
                            'description': (
                                f'Parameter "{param}" caused a near-timeout '
                                f'({elapsed:.1f}s) when pointed at {target}. '
                                f'Manual verification recommended.'
                            ),
                            'url': test_url,
                            'cvss_score': 8.6,
                        })
                        return

                except requests.Timeout:
                    # A full timeout is a stronger blind SSRF signal
                    self.vulnerabilities.append({
                        'owasp_category': 'A10',
                        'type': 'Potential Blind SSRF (Timeout)',
                        'severity': 'HIGH',
                        'description': (
                            f'Request to {test_url} timed out when parameter '
                            f'"{param}" was set to {target}. Possible blind SSRF.'
                        ),
                        'url': test_url,
                        'cvss_score': 8.6,
                    })
                    return
                except Exception as e:
                    logger.debug(f"SSRF test error: {e}")

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _generate_report(self) -> Dict:
        critical = sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')
        high = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': critical,
            'high': high,
            'vulnerabilities': self.vulnerabilities,
        }
