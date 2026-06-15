"""
CyberX – OWASP Top 10 (2021) comprehensive vulnerability scanner.

Coverage
--------
A01 Broken Access Control        – IDOR, forced-browsing admin paths
A02 Cryptographic Failures       – HTTP plaintext, invalid TLS cert, weak cipher hints
A03 Injection                    – SQL injection (GET + POST + headers), Reflected XSS,
                                   Command injection, LDAP injection, NoSQL injection
A04 Insecure Design              – Path traversal, Open redirect
A05 Security Misconfiguration    – Missing headers, server disclosure, dangerous HTTP methods,
                                   directory listing, debug endpoints
A06 Vulnerable Components        – Server/framework version extraction + CVE hint
A07 Auth Failures                – Insecure cookie flags, HTTP Basic over HTTP,
                                   default credential probing
A08 Software Integrity Failures  – Missing Subresource Integrity on CDN scripts
A09 Logging Failures             – Verbose error pages leaking stack traces
A10 SSRF                         – URL-param injection, AWS metadata, blind SSRF via timing

Next phase: spider/crawl module to auto-discover endpoints.
"""

import re
import time
import secrets
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode, urlunparse, quote
)

from scanner.logger import setup_logger
from scanner.cvss import calculate_cvss_score

logger = setup_logger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vuln(
    category: str,
    vtype: str,
    severity: str,
    description: str,
    url: str = '',
    cvss: float = 0.0,
    evidence: str = '',
) -> Dict:
    """Construct a normalised vulnerability dict."""
    return {
        'owasp_category': category,
        'type': vtype,
        'severity': severity,
        'description': description,
        'url': url,
        'cvss_score': cvss,
        'evidence': evidence,
    }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class OWASPScanner:
    """Full OWASP Top 10 (2021) scanner – GET, POST body, and header injection."""

    # ------------------------------------------------------------------ A03 SQL
    SQL_ERROR_SIGNATURES: Dict[str, List[str]] = {
        'MySQL':      ['you have an error in your sql syntax', 'warning: mysql_',
                       'mysql_fetch', 'mysql_num_rows', 'supplied argument is not a valid mysql'],
        'PostgreSQL': ['pg_query(): query error', 'error: syntax error at or near',
                       'pg_connect', 'sqlstate', 'unterminated quoted string'],
        'SQLite':     ['operationalerror: near', 'sqlite3.operationalerror',
                       'sqlite error', 'database disk image is malformed'],
        'MSSQL':      ['sql server error', 'incorrect syntax near',
                       'odbc error', 'adodb.recordset', 'unclosed quotation mark'],
        'Oracle':     ['ora-01756', 'ora-00907', 'oracle error',
                       'quoted string not properly terminated'],
    }

    SQL_PAYLOADS = ["'", '"', "')", '")', "1' OR '1'='1", "' OR 1=1 --",
                    "' OR 'x'='x", "'; DROP TABLE users; --", "1; SELECT SLEEP(2)--"]

    # ------------------------------------------------------------------ A03 XSS
    XSS_TEMPLATES = [
        "<script>alert('{c}')</script>",
        "<img src=x onerror=\"alert('{c}')\">",
        "<svg onload=\"alert('{c}')\">",
        "'\"><script>alert('{c}')</script>",
        '" onfocus="alert(\'{c}\')" autofocus="',
        "javascript:alert('{c}')",
        "<details open ontoggle=\"alert('{c}')\">",
    ]

    # ------------------------------------------------------------------ A03 CMD
    CMD_PAYLOADS = ["; echo CMDX_{c}", "| echo CMDX_{c}", "& echo CMDX_{c}",
                    "`echo CMDX_{c}`", "$(echo CMDX_{c})"]

    CMD_PATTERN = re.compile(r'CMDX_[a-f0-9]{8}')

    # ------------------------------------------------------------------ A03 LDAP
    LDAP_PAYLOADS = ["*)(uid=*))(\0", "*()|%26'", "*()|&'", "admin)(&)"]
    LDAP_ERRORS   = ['ldap_bind', 'ldap error', 'invalid dn syntax',
                     'object class violation', 'ldap_search']

    # ------------------------------------------------------------------ A03 NoSQL
    NOSQL_PAYLOADS = ['{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(1000)"}',
                      "' || '1'=='1", '[$ne]=1']
    NOSQL_ERRORS   = ['castError', 'mongo', 'bson', 'mongoose', '_id',
                      'objectid', 'nosql', 'couchdb']

    # ------------------------------------------------------------------ A04 Path Traversal
    PATH_TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd', '%2e%2e%2fetc%2fpasswd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
    ]
    PATH_TRAVERSAL_SIGS = ['root:x:0:0', '[extensions]', 'daemon:x:', 'bin/bash']

    # ------------------------------------------------------------------ A04 Open Redirect
    OPEN_REDIRECT_PAYLOADS = [
        'https://evil.com', '//evil.com', '/\\evil.com', 'https://evil.com%2F@target.com',
    ]
    REDIRECT_PARAMS = re.compile(
        r'^(url|uri|redirect|next|to|goto|target|redir|return|returnurl|'
        r'destination|location|forward|back|link|continue)$', re.I
    )

    # ------------------------------------------------------------------ A05 Headers
    REQUIRED_HEADERS = {
        'Content-Security-Policy':   'prevents XSS and data injection',
        'X-Frame-Options':           'prevents clickjacking',
        'X-Content-Type-Options':    'prevents MIME-type sniffing',
        'Strict-Transport-Security': 'enforces HTTPS',
        'Referrer-Policy':           'controls referrer leakage',
        'Permissions-Policy':        'controls browser feature access',
    }

    DANGEROUS_METHODS = ['TRACE', 'CONNECT', 'PUT', 'DELETE']

    DEBUG_PATHS = ['/debug', '/.env', '/phpinfo.php', '/server-status',
                   '/actuator', '/actuator/env', '/actuator/health',
                   '/_profiler', '/telescope', '/horizon']

    DIR_LISTING_SIGS = ['index of /', 'parent directory', 'directory listing']

    # ------------------------------------------------------------------ A07 Default creds
    DEFAULT_CREDS = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('root', 'root'), ('test', 'test'), ('guest', 'guest'),
    ]

    # ------------------------------------------------------------------ A10 SSRF
    SSRF_PARAMS = re.compile(
        r'^(url|uri|src|href|redirect|next|to|file|path|image|fetch|'
        r'download|load|resource|endpoint|proxy|callback|open|webhook|dest)$', re.I
    )

    SSRF_TARGETS   = ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/']
    SSRF_INDICATORS = ['ami-id', 'instance-id', 'local-ipv4', 'root:x:0:0',
                       'instance-type', 'mac', 'security-credentials']

    # ------------------------------------------------------------------
    def __init__(self, timeout: int = 7, auth_headers: Optional[Dict] = None,
                 auth_cookies: Optional[Dict] = None):
        """
        Args:
            timeout:      HTTP request timeout in seconds.
            auth_headers: Optional dict of auth headers (e.g. Authorization Bearer).
            auth_cookies: Optional dict of session cookies for authenticated scanning.
        """
        self.timeout = timeout
        self.auth_headers: Dict = auth_headers or {}
        self.auth_cookies: Dict = auth_cookies or {}
        self.vulnerabilities: List[Dict] = []
        self._progress_cb = None

    # ------------------------------------------------------------------ progress
    def set_progress_callback(self, cb):
        self._progress_cb = cb

    def _progress(self, msg: str):
        if self._progress_cb:
            self._progress_cb(msg)

    # ------------------------------------------------------------------ HTTP helpers
    def _headers(self, extra: Optional[Dict] = None) -> Dict:
        h = {'User-Agent': 'CyberX-Scanner/2.0'}
        h.update(self.auth_headers)
        if extra:
            h.update(extra)
        return h

    def _get(self, url: str, allow_redirects: bool = True,
             extra_headers: Optional[Dict] = None) -> Optional[requests.Response]:
        try:
            return requests.get(
                url, timeout=self.timeout, headers=self._headers(extra_headers),
                cookies=self.auth_cookies, allow_redirects=allow_redirects, verify=False
            )
        except Exception as e:
            logger.debug(f'GET {url} failed: {e}')
            return None

    def _post(self, url: str, data: Optional[Dict] = None,
              json_body=None, extra_headers: Optional[Dict] = None) -> Optional[requests.Response]:
        try:
            return requests.post(
                url, timeout=self.timeout, headers=self._headers(extra_headers),
                cookies=self.auth_cookies, data=data, json=json_body, verify=False
            )
        except Exception as e:
            logger.debug(f'POST {url} failed: {e}')
            return None

    def _head(self, url: str) -> Optional[requests.Response]:
        try:
            return requests.head(
                url, timeout=self.timeout, headers=self._headers(),
                cookies=self.auth_cookies, allow_redirects=True, verify=False
            )
        except Exception as e:
            logger.debug(f'HEAD {url} failed: {e}')
            return None

    # ------------------------------------------------------------------ URL helpers
    @staticmethod
    def _inject_get_param(url: str, param: str, payload: str) -> str:
        """Return URL with `payload` replacing `param`'s value entirely."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in params.items()})))

    @staticmethod
    def _append_get_param(url: str, param: str, payload: str) -> str:
        """Return URL with `payload` appended to `param`'s existing value."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        original = params.get(param, [''])[0]
        params[param] = [original + payload]
        return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in params.items()})))

    # ------------------------------------------------------------------ SQL helpers
    def _sql_hit(self, text: str) -> Optional[Tuple[str, str]]:
        low = text.lower()
        for db, sigs in self.SQL_ERROR_SIGNATURES.items():
            for sig in sigs:
                if sig in low:
                    return db, sig
        return None

    # ====================================================================
    # Public entry point
    # ====================================================================

    def scan_url(self, url: str) -> Dict:
        """Run all OWASP Top 10 checks against `url`."""
        self.vulnerabilities = []

        checks = [
            ('A01 Broken Access Control',        self._scan_a01),
            ('A02 Cryptographic Failures',        self._scan_a02),
            ('A03 SQLi – GET params',             self._scan_a03_sqli_get),
            ('A03 SQLi – POST body',              self._scan_a03_sqli_post),
            ('A03 SQLi – Headers',                self._scan_a03_sqli_headers),
            ('A03 XSS – Reflected',               self._scan_a03_xss),
            ('A03 Command Injection',             self._scan_a03_cmd),
            ('A03 LDAP Injection',                self._scan_a03_ldap),
            ('A03 NoSQL Injection',               self._scan_a03_nosql),
            ('A04 Path Traversal',                self._scan_a04_path_traversal),
            ('A04 Open Redirect',                 self._scan_a04_open_redirect),
            ('A05 Security Misconfiguration',     self._scan_a05),
            ('A06 Vulnerable Components',         self._scan_a06),
            ('A07 Auth Failures',                 self._scan_a07),
            ('A08 Software Integrity Failures',   self._scan_a08),
            ('A09 Logging Failures',              self._scan_a09),
            ('A10 SSRF',                          self._scan_a10),
        ]

        for label, fn in checks:
            self._progress(f'{label}: Testing…')
            try:
                fn(url)
            except Exception as exc:
                logger.error(f'{label} error: {exc}')

        self._progress('Scan complete ✓')
        return self._build_report()

    # ====================================================================
    # A01 – Broken Access Control
    # ====================================================================

    def _scan_a01(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # IDOR – numeric ID params
        id_pat = re.compile(
            r'^(id|user_?id|post_?id|account_?id|record_?id|file_?id|item_?id|order_?id)$', re.I
        )
        for param, vals in params.items():
            if id_pat.match(param) and vals and vals[0].isdigit():
                self.vulnerabilities.append(_vuln(
                    'A01', 'Potential IDOR', 'HIGH',
                    f'Parameter "{param}={vals[0]}" is a direct object reference. '
                    f'Verify access control prevents horizontal/vertical privilege escalation.',
                    url, 7.5, f'param={param}&value={vals[0]}'
                ))
                break

        # Forced browsing – admin paths (no session cookies)
        base = f"{parsed.scheme}://{parsed.netloc}"
        admin_paths = ['/admin', '/admin/', '/dashboard', '/administrator',
                       '/wp-admin', '/manage', '/console', '/control-panel',
                       '/superuser', '/backoffice', '/staff', '/internal']
        for path in admin_paths:
            resp = self._get(base + path, allow_redirects=False,
                             extra_headers={'Cookie': ''})
            if resp and resp.status_code == 200:
                self.vulnerabilities.append(_vuln(
                    'A01', 'Unprotected Admin Endpoint', 'CRITICAL',
                    f'"{path}" returned HTTP 200 without authentication.',
                    base + path, 9.1, f'HTTP {resp.status_code}'
                ))
                break  # one finding is enough

    # ====================================================================
    # A02 – Cryptographic Failures
    # ====================================================================

    def _scan_a02(self, url: str):
        parsed = urlparse(url)

        if parsed.scheme == 'http':
            self.vulnerabilities.append(_vuln(
                'A02', 'Unencrypted Connection', 'HIGH',
                'Site transmits data over HTTP (plaintext). All traffic can be intercepted.',
                url, 7.5
            ))
            # Also check if HTTPS redirect exists
            https_url = url.replace('http://', 'https://', 1)
            resp = self._get(https_url)
            if resp is None:
                self.vulnerabilities.append(_vuln(
                    'A02', 'No HTTPS Available', 'HIGH',
                    'HTTPS equivalent of this URL is unreachable — no fallback encryption.',
                    https_url, 7.5
                ))

        if parsed.scheme == 'https':
            try:
                requests.get(url, timeout=self.timeout, verify=True,
                             headers=self._headers())
            except requests.exceptions.SSLError as e:
                self.vulnerabilities.append(_vuln(
                    'A02', 'SSL/TLS Certificate Error', 'HIGH',
                    'Invalid, expired, or self-signed TLS certificate detected.',
                    url, 7.4, str(e)[:200]
                ))
            except Exception:
                pass

        # Check HSTS only on HTTPS
        if parsed.scheme == 'https':
            resp = self._head(url)
            if resp and 'Strict-Transport-Security' not in resp.headers:
                self.vulnerabilities.append(_vuln(
                    'A02', 'Missing HSTS Header', 'MEDIUM',
                    'Strict-Transport-Security header absent. Browsers may downgrade to HTTP.',
                    url, 5.9
                ))

    # ====================================================================
    # A03 – SQL Injection (GET parameters)
    # ====================================================================

    def _scan_a03_sqli_get(self, url: str):
        params = parse_qs(urlparse(url).query, keep_blank_values=True)
        if not params:
            return

        for param in params:
            for payload in self.SQL_PAYLOADS:
                test_url = self._append_get_param(url, param, payload)
                resp = self._get(test_url)
                if resp:
                    hit = self._sql_hit(resp.text)
                    if hit:
                        db, sig = hit
                        self.vulnerabilities.append(_vuln(
                            'A03', 'SQL Injection (GET)', 'CRITICAL',
                            f'SQLi in GET param "{param}" with payload {payload!r}. '
                            f'DB fingerprint: {db}. Matched: "{sig}".',
                            test_url, 9.8, sig
                        ))
                        return

    # ====================================================================
    # A03 – SQL Injection (POST body)
    # ====================================================================

    def _scan_a03_sqli_post(self, url: str):
        """
        Probe common POST form field names with SQL payloads.
        Covers login forms, search boxes, contact forms, API endpoints.
        """
        # Common field names found in web forms
        common_fields = ['username', 'user', 'email', 'password', 'search',
                         'query', 'q', 'id', 'name', 'input', 'data', 'value',
                         'comment', 'message', 'title', 'content', 'filter']

        for field in common_fields:
            for payload in self.SQL_PAYLOADS[:4]:  # keep POST tests lean
                data = {field: payload}
                resp = self._post(url, data=data)
                if resp:
                    hit = self._sql_hit(resp.text)
                    if hit:
                        db, sig = hit
                        self.vulnerabilities.append(_vuln(
                            'A03', 'SQL Injection (POST body)', 'CRITICAL',
                            f'SQLi in POST field "{field}" with payload {payload!r}. '
                            f'DB fingerprint: {db}. Matched: "{sig}".',
                            url, 9.8, sig
                        ))
                        return

        # Also try JSON body (REST APIs)
        for payload in self.SQL_PAYLOADS[:3]:
            json_body = {'id': payload, 'query': payload}
            resp = self._post(url, json_body=json_body,
                              extra_headers={'Content-Type': 'application/json'})
            if resp:
                hit = self._sql_hit(resp.text)
                if hit:
                    db, sig = hit
                    self.vulnerabilities.append(_vuln(
                        'A03', 'SQL Injection (JSON body)', 'CRITICAL',
                        f'SQLi in JSON body with payload {payload!r}. '
                        f'DB fingerprint: {db}.',
                        url, 9.8, sig
                    ))
                    return

    # ====================================================================
    # A03 – SQL Injection (HTTP headers)
    # ====================================================================

    def _scan_a03_sqli_headers(self, url: str):
        """
        Inject SQL payloads into headers commonly logged / parsed server-side:
        X-Forwarded-For, User-Agent, Referer, X-Custom-IP-Authorization, Cookie.
        """
        injectable_headers = {
            'X-Forwarded-For':          "192.168.1.1{p}",
            'User-Agent':               "Mozilla/5.0{p}",
            'Referer':                  f"{url}{{p}}",
            'X-Custom-IP-Authorization': "127.0.0.1{p}",
        }

        for header, template in injectable_headers.items():
            for payload in self.SQL_PAYLOADS[:3]:
                injected = template.format(p=payload)
                resp = self._get(url, extra_headers={header: injected})
                if resp:
                    hit = self._sql_hit(resp.text)
                    if hit:
                        db, sig = hit
                        self.vulnerabilities.append(_vuln(
                            'A03', f'SQL Injection (Header: {header})', 'CRITICAL',
                            f'SQLi via HTTP header "{header}" with payload {payload!r}. '
                            f'DB fingerprint: {db}.',
                            url, 9.8, sig
                        ))
                        return

    # ====================================================================
    # A03 – Reflected XSS
    # ====================================================================

    def _scan_a03_xss(self, url: str):
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys()) or ['q', 'search', 'query', 'input', 's']

        for param in params:
            for template in self.XSS_TEMPLATES:
                canary = secrets.token_hex(8)
                payload = template.replace('{c}', canary)

                if parse_qs(parsed.query):
                    test_url = self._inject_get_param(url, param, payload)
                else:
                    test_url = f"{url.split('?')[0]}?{param}={quote(payload)}"

                resp = self._get(test_url)
                if resp and canary in resp.text and payload in resp.text:
                    self.vulnerabilities.append(_vuln(
                        'A03', 'Reflected XSS', 'HIGH',
                        f'Reflected XSS in param "{param}". '
                        f'Canary "{canary}" reflected verbatim.',
                        test_url, 6.1, payload[:80]
                    ))
                    return

        # Also test POST body XSS
        for field in ['search', 'q', 'query', 'input', 'comment', 'message']:
            canary = secrets.token_hex(8)
            payload = f"<script>alert('{canary}')</script>"
            resp = self._post(url, data={field: payload})
            if resp and canary in resp.text and payload in resp.text:
                self.vulnerabilities.append(_vuln(
                    'A03', 'Reflected XSS (POST)', 'HIGH',
                    f'POST XSS in field "{field}". Canary "{canary}" reflected.',
                    url, 6.1, payload
                ))
                return

    # ====================================================================
    # A03 – Command Injection
    # ====================================================================

    def _scan_a03_cmd(self, url: str):
        params = list(parse_qs(urlparse(url).query).keys())
        if not params:
            return

        for param in params:
            for tmpl in self.CMD_PAYLOADS[:3]:
                canary = secrets.token_hex(4)
                payload = tmpl.replace('{c}', canary)
                test_url = self._append_get_param(url, param, payload)
                resp = self._get(test_url)
                if resp and f'CMDX_{canary}' in resp.text:
                    self.vulnerabilities.append(_vuln(
                        'A03', 'Command Injection', 'CRITICAL',
                        f'OS command injection in param "{param}" with payload {payload!r}.',
                        test_url, 9.8, f'CMDX_{canary} found in response'
                    ))
                    return

    # ====================================================================
    # A03 – LDAP Injection
    # ====================================================================

    def _scan_a03_ldap(self, url: str):
        params = list(parse_qs(urlparse(url).query).keys())
        if not params:
            return

        for param in params:
            for payload in self.LDAP_PAYLOADS:
                test_url = self._inject_get_param(url, param, payload)
                resp = self._get(test_url)
                if resp:
                    low = resp.text.lower()
                    for sig in self.LDAP_ERRORS:
                        if sig in low:
                            self.vulnerabilities.append(_vuln(
                                'A03', 'LDAP Injection', 'HIGH',
                                f'LDAP injection in param "{param}". Matched error: "{sig}".',
                                test_url, 8.1, sig
                            ))
                            return

    # ====================================================================
    # A03 – NoSQL Injection
    # ====================================================================

    def _scan_a03_nosql(self, url: str):
        params = list(parse_qs(urlparse(url).query).keys())
        test_params = params or ['id', 'user', 'name']

        for param in test_params:
            for payload in self.NOSQL_PAYLOADS:
                # GET param
                test_url = self._inject_get_param(url, param, payload)
                resp = self._get(test_url)
                if resp:
                    low = resp.text.lower()
                    for sig in self.NOSQL_ERRORS:
                        if sig in low:
                            self.vulnerabilities.append(_vuln(
                                'A03', 'NoSQL Injection', 'HIGH',
                                f'NoSQL injection in param "{param}" with payload {payload!r}. '
                                f'Matched: "{sig}".',
                                test_url, 8.1, sig
                            ))
                            return

                # JSON POST
                try:
                    import json as _json
                    json_payload = _json.loads(payload) if payload.startswith('{') else payload
                except Exception:
                    json_payload = payload
                resp2 = self._post(url, json_body={param: json_payload},
                                   extra_headers={'Content-Type': 'application/json'})
                if resp2:
                    low2 = resp2.text.lower()
                    for sig in self.NOSQL_ERRORS:
                        if sig in low2:
                            self.vulnerabilities.append(_vuln(
                                'A03', 'NoSQL Injection (JSON)', 'HIGH',
                                f'NoSQL injection via JSON body in field "{param}".',
                                url, 8.1, sig
                            ))
                            return

    # ====================================================================
    # A04 – Insecure Design: Path Traversal
    # ====================================================================

    def _scan_a04_path_traversal(self, url: str):
        params = list(parse_qs(urlparse(url).query).keys())
        file_params = [p for p in params if re.search(
            r'(file|path|doc|page|include|load|template|view|dir|folder|name)', p, re.I
        )]
        probe_params = file_params or params or ['file', 'path', 'page']

        for param in probe_params[:3]:
            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                test_url = self._inject_get_param(url, param, payload)
                resp = self._get(test_url)
                if resp:
                    for sig in self.PATH_TRAVERSAL_SIGS:
                        if sig in resp.text:
                            self.vulnerabilities.append(_vuln(
                                'A04', 'Path Traversal', 'CRITICAL',
                                f'Path traversal in param "{param}". '
                                f'Matched: "{sig}" in response.',
                                test_url, 9.1, sig
                            ))
                            return

    # ====================================================================
    # A04 – Insecure Design: Open Redirect
    # ====================================================================

    def _scan_a04_open_redirect(self, url: str):
        params = parse_qs(urlparse(url).query)
        redirect_params = [p for p in params if self.REDIRECT_PARAMS.match(p)]

        if not redirect_params:
            return

        for param in redirect_params:
            for payload in self.OPEN_REDIRECT_PAYLOADS:
                test_url = self._inject_get_param(url, param, payload)
                resp = self._get(test_url, allow_redirects=False)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location', '')
                    if 'evil.com' in loc or loc.startswith('//') :
                        self.vulnerabilities.append(_vuln(
                            'A04', 'Open Redirect', 'MEDIUM',
                            f'Open redirect via param "{param}". '
                            f'Location header: {loc}',
                            test_url, 6.1, f'Location: {loc}'
                        ))
                        return

    # ====================================================================
    # A05 – Security Misconfiguration
    # ====================================================================

    def _scan_a05(self, url: str):
        resp = self._head(url)
        if not resp:
            return

        headers = resp.headers

        # Missing security headers
        missing = [f"{h} ({d})" for h, d in self.REQUIRED_HEADERS.items() if h not in headers]
        if missing:
            severity = 'HIGH' if len(missing) >= 4 else 'MEDIUM'
            self.vulnerabilities.append(_vuln(
                'A05', 'Missing Security Headers', severity,
                f'Missing: {", ".join(missing)}.',
                url, 6.5 if severity == 'HIGH' else 5.3, ', '.join(missing)
            ))

        # Server version disclosure
        for dh in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator',
                    'X-Drupal-Cache', 'X-Runtime', 'X-Version'):
            if dh in headers:
                self.vulnerabilities.append(_vuln(
                    'A05', 'Technology Disclosure', 'LOW',
                    f'Header "{dh}" reveals technology: {headers[dh]}',
                    url, 3.7, f'{dh}: {headers[dh]}'
                ))

        # Dangerous HTTP methods
        for method in self.DANGEROUS_METHODS:
            try:
                r = requests.request(method, url, timeout=self.timeout,
                                     headers=self._headers(), verify=False)
                if r.status_code not in (405, 501, 400, 403):
                    self.vulnerabilities.append(_vuln(
                        'A05', f'{method} Method Enabled', 'HIGH',
                        f'HTTP {method} returned {r.status_code} (expected 405/403).',
                        url, 7.5, f'HTTP {r.status_code}'
                    ))
            except Exception:
                pass

        # Debug / sensitive paths
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.DEBUG_PATHS:
            r = self._get(base + path, allow_redirects=False)
            if r and r.status_code == 200 and len(r.text) > 50:
                self.vulnerabilities.append(_vuln(
                    'A05', 'Exposed Debug/Config Endpoint', 'HIGH',
                    f'"{path}" returned HTTP 200 with {len(r.text)} bytes of content.',
                    base + path, 7.5, f'HTTP 200, {len(r.text)} bytes'
                ))
                break

        # Directory listing
        dir_url = base + '/'
        r = self._get(dir_url)
        if r:
            low = r.text.lower()
            for sig in self.DIR_LISTING_SIGS:
                if sig in low:
                    self.vulnerabilities.append(_vuln(
                        'A05', 'Directory Listing Enabled', 'MEDIUM',
                        f'Web root appears to expose a directory listing (matched "{sig}").',
                        dir_url, 5.3, sig
                    ))
                    break

    # ====================================================================
    # A06 – Vulnerable and Outdated Components
    # ====================================================================

    def _scan_a06(self, url: str):
        """Extract server/framework version strings and flag known-old patterns."""
        resp = self._head(url)
        if not resp:
            return

        # Version disclosure via headers
        version_headers = {
            'Server':            r'(apache|nginx|iis|lighttpd)[/\s]+([\d.]+)',
            'X-Powered-By':      r'(php|asp\.net|express)[/\s]*([\d.]*)',
            'X-AspNet-Version':  r'([\d.]+)',
            'X-Generator':       r'(.+)',
        }

        KNOWN_OLD = {
            'apache': ('2.2', '2.4.49', '2.4.50'),
            'nginx':  ('1.12', '1.14', '1.16'),
            'php':    ('5.', '7.0', '7.1', '7.2'),
            'asp.net': ('1.', '2.', '3.5'),
        }

        for header, pattern in version_headers.items():
            val = resp.headers.get(header, '')
            if not val:
                continue
            m = re.search(pattern, val, re.I)
            if m:
                tech = m.group(1).lower() if m.lastindex and m.lastindex >= 1 else ''
                version = m.group(2) if m.lastindex and m.lastindex >= 2 else val

                is_old = any(
                    version.startswith(old)
                    for old_versions in KNOWN_OLD.get(tech, [])
                    for old in [old_versions]
                )

                if is_old:
                    self.vulnerabilities.append(_vuln(
                        'A06', 'Outdated Component', 'HIGH',
                        f'{header} reveals {val!r} — this version has known CVEs. '
                        f'Update immediately.',
                        url, 8.1, val
                    ))
                else:
                    self.vulnerabilities.append(_vuln(
                        'A06', 'Component Version Disclosed', 'LOW',
                        f'{header} discloses "{val}". Confirm this is up-to-date.',
                        url, 3.7, val
                    ))

    # ====================================================================
    # A07 – Identification and Authentication Failures
    # ====================================================================

    def _scan_a07(self, url: str):
        resp = self._get(url)
        if not resp:
            return

        # Insecure cookie flags
        raw_cookie = resp.headers.get('Set-Cookie', '')
        if not raw_cookie:
            raw_cookie = '\n'.join(
                v for k, v in resp.headers.items() if k.lower() == 'set-cookie'
            )

        if raw_cookie:
            low = raw_cookie.lower()
            missing_flags = []
            if 'httponly' not in low:
                missing_flags.append('HttpOnly')
            if 'secure' not in low:
                missing_flags.append('Secure')
            if 'samesite' not in low:
                missing_flags.append('SameSite')
            if missing_flags:
                self.vulnerabilities.append(_vuln(
                    'A07', 'Insecure Cookie Flags', 'MEDIUM',
                    f'Session cookie missing: {", ".join(missing_flags)}.',
                    url, 5.3, f'Missing: {", ".join(missing_flags)}'
                ))

        # HTTP Basic Auth over HTTP
        parsed = urlparse(url)
        if parsed.scheme == 'http' and resp.status_code == 401:
            www_auth = resp.headers.get('WWW-Authenticate', '')
            if 'basic' in www_auth.lower():
                self.vulnerabilities.append(_vuln(
                    'A07', 'HTTP Basic Auth over HTTP', 'HIGH',
                    'Server requests HTTP Basic authentication over unencrypted HTTP. '
                    'Credentials are base64-encoded and trivially decoded.',
                    url, 8.1, www_auth
                ))

        # Default credential probe on login-like paths
        login_paths = ['/login', '/admin/login', '/wp-login.php', '/signin',
                       '/user/login', '/auth', '/administrator']
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in login_paths:
            login_url = base + path
            r = self._get(login_url, allow_redirects=False)
            if r and r.status_code == 200:
                for user, pwd in self.DEFAULT_CREDS[:3]:
                    pr = self._post(
                        login_url,
                        data={'username': user, 'password': pwd,
                              'user': user, 'pass': pwd, 'email': user}
                    )
                    if pr and pr.status_code in (200, 302):
                        # Heuristic: if response body changes significantly vs blank creds
                        blank = self._post(login_url,
                                           data={'username': '', 'password': ''})
                        if blank and abs(len(pr.text) - len(blank.text)) > 200:
                            self.vulnerabilities.append(_vuln(
                                'A07', 'Default Credentials (Potential)', 'HIGH',
                                f'Login at "{path}" responded differently for '
                                f'{user!r}/{pwd!r} vs blank credentials — manual verification needed.',
                                login_url, 9.8, f'user={user}&pass={pwd}'
                            ))
                            return
                break  # only probe the first reachable login

    # ====================================================================
    # A08 – Software and Data Integrity Failures
    # ====================================================================

    def _scan_a08(self, url: str):
        """Check for CDN <script>/<link> tags lacking SRI (integrity attribute)."""
        resp = self._get(url)
        if not resp:
            return

        cdn_pattern = re.compile(
            r'<(script|link)[^>]+'
            r'(?:src|href)=["\']https?://(?!(?:' + re.escape(urlparse(url).netloc) + r'))[^"\']+["\']'
            r'(?![^>]*integrity=)',
            re.I
        )

        matches = cdn_pattern.findall(resp.text)
        if matches:
            self.vulnerabilities.append(_vuln(
                'A08', 'Missing Subresource Integrity (SRI)', 'MEDIUM',
                f'{len(matches)} external script/stylesheet tag(s) lack an '
                f'"integrity" attribute. A compromised CDN could inject malicious code.',
                url, 6.1, f'{len(matches)} tag(s) without SRI'
            ))

    # ====================================================================
    # A09 – Security Logging and Monitoring Failures
    # ====================================================================

    def _scan_a09(self, url: str):
        """Probe for verbose error pages that leak stack traces or config."""
        error_triggers = [
            url + ('&' if '?' in url else '?') + '__error__=1',
            url.rstrip('/') + '/nonexistent-path-xyz-12345',
        ]

        stack_trace_patterns = re.compile(
            r'(traceback|stack trace|at \w+\.\w+\(|exception in thread|'
            r'debug_mode|werkzeug debugger|laravel debugger|symfony exception|'
            r'django\.core\.exceptions|rails error|at System\.|NullPointerException)',
            re.I
        )

        for trigger_url in error_triggers:
            resp = self._get(trigger_url)
            if resp and resp.status_code in (200, 500, 400):
                m = stack_trace_patterns.search(resp.text)
                if m:
                    self.vulnerabilities.append(_vuln(
                        'A09', 'Verbose Error / Stack Trace Disclosure', 'MEDIUM',
                        f'Error page leaks internal stack trace or framework debug info. '
                        f'Matched: "{m.group(0)}".',
                        trigger_url, 5.3, m.group(0)[:120]
                    ))
                    return

    # ====================================================================
    # A10 – Server-Side Request Forgery (SSRF)
    # ====================================================================

    def _scan_a10(self, url: str):
        params = parse_qs(urlparse(url).query)
        candidates = [p for p in params if self.SSRF_PARAMS.match(p)]

        if not candidates:
            return

        for param in candidates:
            for target in self.SSRF_TARGETS:
                test_url = self._inject_get_param(url, param, target)
                t0 = time.time()
                resp = self._get(test_url)
                elapsed = time.time() - t0

                if resp:
                    low = resp.text.lower()
                    if any(ind in low for ind in self.SSRF_INDICATORS):
                        self.vulnerabilities.append(_vuln(
                            'A10', 'SSRF (Confirmed)', 'CRITICAL',
                            f'Param "{param}" fetched {target} and returned internal content.',
                            test_url, 9.0, ', '.join(
                                i for i in self.SSRF_INDICATORS if i in low
                            )
                        ))
                        return

                    if elapsed >= self.timeout * 0.85:
                        self.vulnerabilities.append(_vuln(
                            'A10', 'Potential Blind SSRF (Timing)', 'HIGH',
                            f'Param "{param}" caused {elapsed:.1f}s delay when pointed at {target}.',
                            test_url, 8.6, f'{elapsed:.1f}s response time'
                        ))
                        return

    # ====================================================================
    # Report builder
    # ====================================================================

    def _build_report(self) -> Dict:
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for v in self.vulnerabilities:
            sev = v.get('severity', 'LOW')
            counts[sev] = counts.get(sev, 0) + 1

        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': counts['CRITICAL'],
            'high':     counts['HIGH'],
            'medium':   counts['MEDIUM'],
            'low':      counts['LOW'],
            'vulnerabilities': self.vulnerabilities,
        }
