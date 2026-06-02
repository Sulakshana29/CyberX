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


# Database error signatures for multi-DBMS detection
DATABASE_ERROR_SIGNATURES = {
    'MySQL': [
        'you have an error in your sql syntax',
        'warning: mysql_',
        'mysql_fetch',
        'mysql_error',
        'mysql_num_rows',
        'mysql_query',
        "sql syntax",
        "mysql error",
    ],
    'PostgreSQL': [
        'pg_query(): query error',
        'error: syntax error at or near',
        'postgresql error',
        'postgres error',
        'pgerror',
        'sqlstate',
        'fatal error',
        'pg_connect',
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
    ]
}

# SQLi payload templates for error-based detection
SQLI_PAYLOADS = [
    "'",
    '"',
    "')",
    '")',
    "1' OR '1'='1",
]

REQUEST_TIMEOUT = 5


def _extract_params_from_url(url: str) -> Dict[str, str]:
    """Extract query parameters from URL.
    
    Args:
        url: Target URL to extract parameters from.
        
    Returns:
        Dictionary of extracted query parameters.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # Convert list values to single strings for requests compatibility
    return {k: v[0] if v else '' for k, v in params.items()}


def _identify_database(response_body: str) -> Optional[str]:
    """Identify database system from error signatures in response.
    
    Args:
        response_body: Response body text to analyze.
        
    Returns:
        Database system name if identified, None otherwise.
    """
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
    config: ScannerConfig
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Test a single parameter for SQLi vulnerability with a specific payload.
    
    Args:
        target_url: Target URL for testing.
        param_name: Parameter name to inject into.
        param_value: Original parameter value.
        payload: SQLi payload to inject.
        
    Returns:
        Tuple of (is_vulnerable, db_type, error_signature) where
        is_vulnerable indicates if vulnerability was found, db_type is the
        identified database system, and error_signature is the matched signature.
    """
    try:
        # Extract existing params from URL
        params = _extract_params_from_url(target_url)
        
        # Inject payload into target parameter
        injected_value = f"{param_value}{payload}"
        params[param_name] = injected_value
        
        # Send request with payload
        response = requests.get(
            target_url.split('?')[0],  # Use base URL without query string
            params=params,
            timeout=config.request_timeout,
            allow_redirects=config.follow_redirects,
            verify=config.verify_ssl,
            headers={'User-Agent': config.user_agent}
        )
        
        # Check for database error signatures
        db_type = _identify_database(response.text)
        if db_type:
            # Find which signature matched for reporting
            body_lower = response.text.lower()
            for signature in DATABASE_ERROR_SIGNATURES[db_type]:
                if signature.lower() in body_lower:
                    logger.debug(f"SQLi signature found: {db_type} - {signature}")
                    return True, db_type, signature
        
        return False, None, None
        
    except requests.exceptions.RequestException as e:
        # Log network errors but continue scanning
        logger.debug(f"Request exception during parameter test: {str(e)}")
        return False, None, None


def scan_sqli(
    target_url: str,
    params: Optional[Dict[str, str]] = None,
    config: Optional[ScannerConfig] = None
) -> Dict:
    """Scan target URL for SQL injection vulnerabilities.
    
    Performs error-based SQL injection detection by injecting classic boundary-
    breaking payloads and analyzing responses for database-specific error
    signatures. Stops fuzzing immediately upon detection on each parameter.
    
    Args:
        target_url: URL to scan for SQL injection vulnerabilities.
        params: Optional dictionary of query parameters to test. If not provided,
                parameters will be extracted from the target URL's query string.
        config: Optional ScannerConfig for customizing scan behavior.
                
    Returns:
        Dictionary with keys:
            - vulnerability_found (bool): Whether a vulnerability was detected.
            - severity (str): Severity level (High for SQL injection).
            - details (str): Human-readable description of findings including
                           vulnerable parameter, payload, and DBMS type.
            - cvss_score (float): CVSS v3.1 score (0-10).
            - cvss_vector (str): CVSS vector string.
            - scan_duration (float): Scan duration in seconds.
    """
    if config is None:
        config = ScannerConfig.get_default()
    
    start_time = time.time()
    
    try:
        logger.info(f"Starting SQL injection scan on {target_url}")
        
        # Extract parameters from URL if not provided
        if params is None:
            params = _extract_params_from_url(target_url)
        
        if not params:
            elapsed_time = time.time() - start_time
            logger.info(f"No query parameters found in {target_url}")
            return {
                'vulnerability_found': False,
                'severity': 'Info',
                'details': 'No query parameters found in target URL.',
                'cvss_score': 0.0,
                'cvss_vector': '',
                'scan_duration': elapsed_time
            }
        
        logger.debug(f"Found {len(params)} parameters to test: {list(params.keys())}")
        
        # Test each parameter with SQLi payloads
        for param_name, param_value in params.items():
            logger.debug(f"Testing parameter: {param_name}")
            
            for payload in SQLI_PAYLOADS:
                is_vulnerable, db_type, error_sig = _test_parameter_injection(
                    target_url,
                    param_name,
                    param_value,
                    payload,
                    config
                )
                
                if is_vulnerable:
                    elapsed_time = time.time() - start_time
                    cvss = get_sqli_cvss()
                    
                    logger.warning(
                        f"SQL Injection FOUND in parameter '{param_name}' "
                        f"with {db_type} database"
                    )
                    
                    return {
                        'vulnerability_found': True,
                        'severity': 'High',
                        'details': (
                            f'SQL Injection vulnerability detected in parameter '
                            f'"{param_name}". Database: {db_type}. '
                            f'Payload: {payload}. '
                            f'Error signature: {error_sig}'
                        ),
                        'cvss_score': cvss['score'],
                        'cvss_vector': cvss['vector'],
                        'scan_duration': elapsed_time
                    }
        
        elapsed_time = time.time() - start_time
        logger.info(f"SQL injection scan complete (no vulnerabilities found)")
        
        return {
            'vulnerability_found': False,
            'severity': 'Info',
            'details': 'No SQL injection vulnerabilities detected.',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': elapsed_time
        }
        
    except requests.exceptions.RequestException as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Network error during SQLi scan: {str(e)}")
        
        return {
            'vulnerability_found': False,
            'severity': 'Error',
            'details': f'Network error during SQLi scan: {str(e)}',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': elapsed_time
        }
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Unexpected error during SQLi scan: {str(e)}")
        
        return {
            'vulnerability_found': False,
            'severity': 'Error',
            'details': f'Unexpected error during SQLi scan: {str(e)}',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': elapsed_time
        }
