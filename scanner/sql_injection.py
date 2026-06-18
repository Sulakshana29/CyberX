"""SQL Injection vulnerability scanner module for CyberScan.

This module implements error-based SQL injection detection using signature
matching against database-specific error messages.
"""

import requests
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, List, Tuple

from scanner.config import ScannerConfig
from scanner.logger import setup_logger
from scanner.cvss import get_sqli_cvss

logger = setup_logger(__name__)


# Database error signatures for multi-DBMS detection.
# NOTE: keep signatures specific — generic strings like 'fatal error'
# match PHP errors, framework exceptions and unrelated server messages,
# producing false positives.
DATABASE_ERROR_SIGNATURES = {
    'MySQL': [
        'you have an error in your sql syntax',
        'warning: mysql_',
        'mysql_fetch',
        'mysql_error',
        'mysql_num_rows',
        'mysql_query',
        'sql syntax',
        'mysql error',
    ],
    'PostgreSQL': [
        'pg_query(): query error',
        'error: syntax error at or near',
        'postgresql error',
        'postgres error',
        'pgerror',
        'sqlstate',
        'pg_connect',
        # Removed 'fatal error' — too generic, matches PHP/Apache errors.
    ],
    'SQLite': [
        'operationalerror: near',
        'sqlite3.operationalerror',
        'sqlite error',
        'sqliteerror',
        'database disk image is malformed',
        'attempt to write a readonly database',
        'disk i/o error',
    ],
    'MSSQL': [
        'sql server error',
        'mssql error',
        'incorrect syntax near',
        'odbc error',
        'adodb.recordset',
    ],
    'Oracle': [
        'ora-01756',
        'ora-00907',
        'oracle error',
        'quoted string not properly terminated',
    ],
}

# SQLi payload templates for error-based detection
SQLI_PAYLOADS = [
    "'",
    '"',
    "')",
    '")',
    "1' OR '1'='1",
    "' OR 1=1 --",
]

REQUEST_TIMEOUT = 5


def _extract_params_from_url(url: str) -> Dict[str, str]:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] if v else '' for k, v in params.items()}


def _identify_database(response_body: str) -> Optional[str]:
    """Identify database system from error signatures in response body."""
    body_lower = response_body.lower()
    for db_type, signatures in DATABASE_ERROR_SIGNATURES.items():
        for signature in signatures:
            if signature.lower() in body_lower:
                return db_type
    return None


def _test_parameter_injection(
    target_url: str,
    param_name: str,
    param_value: str,
    payload: str,
    config: ScannerConfig,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Test a single parameter for SQLi with a specific payload.

    Returns:
        (is_vulnerable, db_type, error_signature)
    """
    try:
        params = _extract_params_from_url(target_url)
        params[param_name] = f"{param_value}{payload}"

        response = requests.get(
            target_url.split('?')[0],
            params=params,
            timeout=config.request_timeout,
            allow_redirects=config.follow_redirects,
            verify=config.verify_ssl,
            headers={'User-Agent': config.user_agent},
        )

        db_type = _identify_database(response.text)
        if db_type:
            body_lower = response.text.lower()
            for signature in DATABASE_ERROR_SIGNATURES[db_type]:
                if signature.lower() in body_lower:
                    logger.debug(f"SQLi signature found: {db_type} — {signature}")
                    return True, db_type, signature

        return False, None, None

    except requests.exceptions.RequestException as e:
        logger.debug(f"Request exception during parameter test: {e}")
        return False, None, None


def scan_sqli(
    target_url: str,
    params: Optional[Dict[str, str]] = None,
    config: Optional[ScannerConfig] = None,
) -> Dict:
    """Scan target URL for SQL injection vulnerabilities.

    Returns:
        Dictionary with vulnerability_found, severity, details, cvss_score,
        cvss_vector, and scan_duration.
    """
    if config is None:
        config = ScannerConfig.get_default()

    start_time = time.time()

    try:
        logger.info(f"Starting SQL injection scan on {target_url}")

        if params is None:
            params = _extract_params_from_url(target_url)

        if not params:
            return {
                'vulnerability_found': False,
                'severity': 'Info',
                'details': 'No query parameters found in target URL.',
                'cvss_score': 0.0,
                'cvss_vector': '',
                'scan_duration': time.time() - start_time,
            }

        logger.debug(f"Found {len(params)} parameters to test: {list(params.keys())}")

        for param_name, param_value in params.items():
            logger.debug(f"Testing parameter: {param_name}")
            for payload in SQLI_PAYLOADS:
                is_vulnerable, db_type, error_sig = _test_parameter_injection(
                    target_url, param_name, param_value, payload, config
                )
                if is_vulnerable:
                    elapsed = time.time() - start_time
                    cvss = get_sqli_cvss()
                    logger.warning(
                        f"SQL Injection FOUND in parameter '{param_name}' "
                        f"with {db_type} database — CVSS {cvss['score']} ({cvss['severity']})"
                    )
                    return {
                        'vulnerability_found': True,
                        'severity': cvss['severity'],
                        'details': (
                            f'SQL Injection in parameter "{param_name}". '
                            f'Database: {db_type}. Payload: {payload!r}. '
                            f'Error signature: "{error_sig}".'
                        ),
                        'cvss_score': cvss['score'],
                        'cvss_vector': cvss['vector'],
                        'scan_duration': elapsed,
                    }

        return {
            'vulnerability_found': False,
            'severity': 'Info',
            'details': 'No SQL injection vulnerabilities detected.',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': time.time() - start_time,
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during SQLi scan: {e}")
        return {
            'vulnerability_found': False,
            'severity': 'Error',
            'details': f'Network error during SQLi scan: {e}',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': time.time() - start_time,
        }
    except Exception as e:
        logger.error(f"Unexpected error during SQLi scan: {e}")
        return {
            'vulnerability_found': False,
            'severity': 'Error',
            'details': f'Unexpected error during SQLi scan: {e}',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': time.time() - start_time,
        }
