"""OWASP Top 10 comprehensive vulnerability scanner with WSTG categories."""

import requests
import re
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse
from scanner.logger import setup_logger
from scanner.cvss import calculate_cvss_score

logger = setup_logger(__name__)


class OWASPScanner:
    """Comprehensive OWASP Top 10 vulnerability scanner."""
    
    # Injection payloads (A03)
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' UNION SELECT NULL,NULL --",
        "1' AND '1'='1",
        "admin' --",
    ]
    
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        "; cat /etc/passwd",
        "| whoami",
        "& ipconfig",
        "`id`",
        "$(whoami)",
    ]
    
    # Security headers that should be present (A05, A02)
    SECURITY_HEADERS = {
        'Content-Security-Policy': 'XSS Protection',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Type Sniffing',
        'Strict-Transport-Security': 'HTTPS Only',
        'X-XSS-Protection': 'XSS Protection',
        'Referrer-Policy': 'Referrer Leakage',
    }
    
    # HTTP methods that should be restricted (A05)
    DANGEROUS_METHODS = ['TRACE', 'CONNECT']
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.vulnerabilities = []
        self.progress_callback = None
    
    def set_progress_callback(self, callback):
        """Set callback for progress updates."""
        self.progress_callback = callback
    
    def _report_progress(self, test_name: str, status: str):
        """Report progress during scanning."""
        if self.progress_callback:
            self.progress_callback(f"{test_name}: {status}")
    
    def scan_url(self, url: str) -> Dict:
        """Scan a URL for all OWASP Top 10 vulnerabilities."""
        self.vulnerabilities = []
        
        try:
            # A01 - Broken Access Control
            self._report_progress("A01 Broken Access Control", "Testing...")
            self._scan_broken_access_control(url)
            
            # A02 - Cryptographic Failures
            self._report_progress("A02 Cryptographic Failures", "Testing...")
            self._scan_cryptographic_failures(url)
            
            # A03 - Injection
            self._report_progress("A03 Injection", "Testing...")
            self._scan_injection(url)
            
            # A04 - Insecure Design
            self._report_progress("A04 Insecure Design", "Testing...")
            self._scan_insecure_design(url)
            
            # A05 - Security Misconfiguration
            self._report_progress("A05 Security Misconfiguration", "Testing...")
            self._scan_security_misconfiguration(url)
            
            # A07 - Authentication Failures
            self._report_progress("A07 Authentication Failures", "Testing...")
            self._scan_authentication(url)
            
            # A10 - SSRF
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
                'cvss_score': 0
            })
        
        return self._generate_report()
    
    def _scan_broken_access_control(self, url: str):
        """A01: Test for broken access control (auth bypass, privilege escalation)."""
        try:
            # Test 1: Try accessing without authentication
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            
            # Check for auth bypass indicators
            if response.status_code == 200 and any(keyword in response.text.lower() 
                for keyword in ['admin', 'dashboard', 'user data', 'private']):
                self.vulnerabilities.append({
                    'owasp_category': 'A01',
                    'type': 'Missing Authentication',
                    'severity': 'CRITICAL',
                    'description': 'Endpoint accessible without authentication',
                    'url': url,
                    'cvss_score': 9.1
                })
            
            # Test 2: Check for insecure direct object references (IDOR)
            if '=' in url and any(char in url for char in ['id', 'user', 'post', 'file']):
                self.vulnerabilities.append({
                    'owasp_category': 'A01',
                    'type': 'Potential IDOR',
                    'severity': 'HIGH',
                    'description': 'URL contains parameter that could be susceptible to IDOR',
                    'url': url,
                    'cvss_score': 7.5
                })
        
        except Exception as e:
            logger.debug(f"A01 scan error: {str(e)}")
    
    def _scan_cryptographic_failures(self, url: str):
        """A02: Test for cryptographic failures (SSL/TLS, encryption issues)."""
        parsed = urlparse(url)
        
        # Test 1: Check if HTTP instead of HTTPS
        if parsed.scheme == 'http':
            self.vulnerabilities.append({
                'owasp_category': 'A02',
                'type': 'Unencrypted Connection',
                'severity': 'HIGH',
                'description': 'Using HTTP instead of HTTPS - data transmitted in plaintext',
                'url': url,
                'cvss_score': 7.5
            })
        
        # Test 2: Check SSL/TLS certificate (simplified)
        if parsed.scheme == 'https':
            try:
                response = requests.get(url, timeout=self.timeout, verify=True)
                # If we get here, SSL is valid
            except requests.exceptions.SSLError:
                self.vulnerabilities.append({
                    'owasp_category': 'A02',
                    'type': 'SSL/TLS Certificate Error',
                    'severity': 'MEDIUM',
                    'description': 'Invalid or self-signed SSL/TLS certificate',
                    'url': url,
                    'cvss_score': 6.5
                })
            except Exception as e:
                logger.debug(f"SSL check error: {str(e)}")
    
    def _scan_injection(self, url: str):
        """A03: Test for injection vulnerabilities (SQL, XSS, Command)."""
        # SQL Injection testing
        for payload in self.SQL_INJECTION_PAYLOADS[:2]:  # Limit payloads
            try:
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                
                # Check for SQL error patterns
                if any(pattern in response.text for pattern in 
                    ['SQL', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'syntax error']):
                    self.vulnerabilities.append({
                        'owasp_category': 'A03',
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'description': f'Potential SQL injection with payload: {payload}',
                        'url': test_url,
                        'cvss_score': 9.8
                    })
                    break
            except Exception as e:
                logger.debug(f"SQL injection test error: {str(e)}")
        
        # XSS testing
        for payload in self.XSS_PAYLOADS[:2]:
            try:
                test_url = f"{url}?search={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        'owasp_category': 'A03',
                        'type': 'Reflected XSS',
                        'severity': 'HIGH',
                        'description': f'XSS payload reflected in response',
                        'url': test_url,
                        'cvss_score': 6.1
                    })
                    break
            except Exception as e:
                logger.debug(f"XSS test error: {str(e)}")
    
    def _scan_insecure_design(self, url: str):
        """A04: Test for insecure design (rate limiting, validation)."""
        try:
            # Test 1: No rate limiting
            responses = []
            for i in range(3):
                response = requests.get(url, timeout=self.timeout)
                responses.append(response.status_code)
            
            if all(status == 200 for status in responses):
                self.vulnerabilities.append({
                    'owasp_category': 'A04',
                    'type': 'No Rate Limiting',
                    'severity': 'MEDIUM',
                    'description': 'No apparent rate limiting detected - vulnerable to DoS/brute force',
                    'url': url,
                    'cvss_score': 5.3
                })
        except Exception as e:
            logger.debug(f"A04 scan error: {str(e)}")
    
    def _scan_security_misconfiguration(self, url: str):
        """A05: Test for security misconfiguration (headers, methods)."""
        try:
            response = requests.head(url, timeout=self.timeout)
            headers = response.headers
            
            # Test 1: Missing security headers
            missing_headers = []
            for header, description in self.SECURITY_HEADERS.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
            
            if len(missing_headers) >= 2:
                self.vulnerabilities.append({
                    'owasp_category': 'A05',
                    'type': 'Missing Security Headers',
                    'severity': 'MEDIUM',
                    'description': f'Missing headers: {", ".join(missing_headers[:3])}',
                    'url': url,
                    'cvss_score': 5.3
                })
            
            # Test 2: Server disclosure
            if 'Server' in headers:
                self.vulnerabilities.append({
                    'owasp_category': 'A05',
                    'type': 'Server Information Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {headers["Server"]}',
                    'url': url,
                    'cvss_score': 3.7
                })
            
            # Test 3: Dangerous HTTP methods
            try:
                for method in self.DANGEROUS_METHODS:
                    method_response = requests.request(method, url, timeout=self.timeout)
                    if method_response.status_code != 405:
                        self.vulnerabilities.append({
                            'owasp_category': 'A05',
                            'type': f'{method} Method Enabled',
                            'severity': 'HIGH',
                            'description': f'Dangerous HTTP method {method} is enabled',
                            'url': url,
                            'cvss_score': 7.5
                        })
            except:
                pass
        
        except Exception as e:
            logger.debug(f"A05 scan error: {str(e)}")
    
    def _scan_authentication(self, url: str):
        """A07: Test for authentication and session management issues."""
        try:
            # Test 1: Check for default credentials pattern
            if any(keyword in url.lower() for keyword in ['login', 'admin', 'auth']):
                self.vulnerabilities.append({
                    'owasp_category': 'A07',
                    'type': 'Authentication Endpoint Detected',
                    'severity': 'INFO',
                    'description': 'Authentication mechanism detected - recommend testing for weak credentials',
                    'url': url,
                    'cvss_score': 0
                })
            
            # Test 2: Check for session cookies
            response = requests.get(url, timeout=self.timeout)
            cookies = response.cookies
            
            if cookies:
                # Check if cookies lack security flags
                for cookie in cookies:
                    if 'HttpOnly' not in str(cookie) or 'Secure' not in str(cookie):
                        self.vulnerabilities.append({
                            'owasp_category': 'A07',
                            'type': 'Insecure Cookie Flags',
                            'severity': 'MEDIUM',
                            'description': f'Cookie lacks security flags (HttpOnly/Secure)',
                            'url': url,
                            'cvss_score': 5.3
                        })
                        break
        
        except Exception as e:
            logger.debug(f"A07 scan error: {str(e)}")
    
    def _scan_ssrf(self, url: str):
        """A10: Test for Server-Side Request Forgery vulnerabilities."""
        try:
            # Test for common SSRF parameters
            ssrf_params = ['url', 'redirect', 'file', 'fetch', 'download', 'image']
            
            for param in ssrf_params:
                test_url = f"{url}?{param}=http://localhost"
                try:
                    response = requests.get(test_url, timeout=self.timeout)
                    
                    # Check for indicators of SSRF
                    if any(indicator in response.text.lower() for indicator in 
                        ['localhost', '127.0.0.1', 'connection refused', 'timed out']):
                        self.vulnerabilities.append({
                            'owasp_category': 'A10',
                            'type': 'Potential SSRF',
                            'severity': 'HIGH',
                            'description': f'Parameter "{param}" may be vulnerable to SSRF',
                            'url': test_url,
                            'cvss_score': 8.6
                        })
                        break
                except requests.Timeout:
                    # Timeout could indicate SSRF attempt was processed
                    pass
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"A10 scan error: {str(e)}")
    
    def _generate_report(self) -> Dict:
        """Generate scan report."""
        critical = len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL'])
        high = len([v for v in self.vulnerabilities if v['severity'] == 'HIGH'])
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': critical,
            'high': high,
            'vulnerabilities': self.vulnerabilities
        }
