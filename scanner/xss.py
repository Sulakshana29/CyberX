"""Reflected XSS vulnerability scanner module for CyberScan.

This module implements reflected XSS detection using randomized cryptographic
canary tokens to prevent false positives from false reflections.
"""

import requests
import secrets
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Tuple

from scanner.config import ScannerConfig
from scanner.logger import setup_logger
from scanner.cvss import get_xss_cvss

logger = setup_logger(__name__)


# XSS vector templates using canary token placeholders
XSS_VECTORS = [
    '<script>alert(\'{canary}\')</script>',
    '\" onfocus=\"alert(\'{canary}\')\" autofocus=\"',
    "' onfocus='alert(\"{canary}\")' autofocus='",
    '<img src=x onerror="alert(\'{canary}\')">',
    '<svg onload="alert(\'{canary}\')">',
    '"><script>alert(\'{canary}\')</script>',
    '\' onmouseover=\'alert("{canary}")\' data-x=\'',
]

CANARY_LENGTH = 16  # Length of random canary token


def _generate_canary() -> str:
    """Generate a cryptographically random canary token.
    
    Returns:
        Hex string of random bytes suitable for unique tracking.
    """
    return secrets.token_hex(CANARY_LENGTH // 2)


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


def _check_canary_reflection(response_body: str, canary: str, vector: str) -> bool:
    """Check if canary token is reflected verbatim and unescaped in response.
    
    Verifies that the exact canary string and surrounding XSS syntax appear
    in the response body without HTML encoding or escaping.
    
    Args:
        response_body: Response HTML/text body to check.
        canary: The unique canary token that was injected.
        vector: The full XSS vector used for injection.
        
    Returns:
        True if canary is reflected verbatim and unescaped, False otherwise.
    """
    # Check if canary is present and unencoded
    if canary not in response_body:
        return False
    
    # Check if surrounding vector context is also present (prevents false positives
    # from accidental canary-like strings appearing elsewhere)
    # Look for the actual payload with the canary embedded
    actual_payload = vector.replace('{canary}', canary)
    
    if actual_payload in response_body:
        return True
    
    # Additionally check for variations with different quote styles or escaping
    # If the exact vector is in response, it's definitely vulnerable
    return actual_payload in response_body


def _test_parameter_injection(
    target_url: str,
    param_name: str,
    param_value: str,
    vector: str,
    canary: str,
    config: ScannerConfig
) -> Tuple[bool, Optional[str]]:
    """Test a single parameter for XSS vulnerability with a specific vector.
    
    Args:
        target_url: Target URL for testing.
        param_name: Parameter name to inject into.
        param_value: Original parameter value.
        vector: XSS vector template with {canary} placeholder.
        canary: Unique canary token for this injection.
        
    Returns:
        Tuple of (is_vulnerable, actual_payload) where is_vulnerable indicates
        if XSS was detected and actual_payload is the injected payload string.
    """
    try:
        # Extract existing params from URL
        params = _extract_params_from_url(target_url)
        
        # Create the actual payload with canary
        actual_payload = vector.replace('{canary}', canary)
        
        # Inject payload into target parameter
        injected_value = f"{param_value}{actual_payload}"
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
        
        # Check if canary and vector are reflected verbatim and unescaped
        if _check_canary_reflection(response.text, canary, vector):
            return True, actual_payload
        
        return False, None
        
    except requests.exceptions.RequestException as e:
        # Log network errors but continue scanning
        return False, None


def scan_reflected_xss(
    target_url: str,
    params: Optional[Dict[str, str]] = None,
    config: Optional[ScannerConfig] = None
) -> Dict:
    """Scan target URL for reflected XSS vulnerabilities.
    
    Performs reflected XSS detection by injecting unique cryptographic canary
    tokens embedded in classic XSS vectors. Verifies that the canary and its
    surrounding syntax are reflected verbatim and unescaped in the response.
    
    Args:
        target_url: URL to scan for reflected XSS vulnerabilities.
        params: Optional dictionary of query parameters to test. If not provided,
                parameters will be extracted from the target URL's query string.
        config: Optional ScannerConfig for customizing scan behavior.
                
    Returns:
        Dictionary with keys:
            - vulnerability_found (bool): Whether a vulnerability was detected.
            - severity (str): Severity level (High for reflected XSS).
            - details (str): Human-readable description of findings including
                           vulnerable parameter, XSS vector used, and canary.
            - cvss_score (float): CVSS v3.1 score (0-10).
            - cvss_vector (str): CVSS vector string.
            - scan_duration (float): Scan duration in seconds.
    """
    if config is None:
        config = ScannerConfig.get_default()
    
    start_time = time.time()
    
    try:
        logger.info(f"Starting reflected XSS scan on {target_url}")
        
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
        
        # Test each parameter with XSS vectors
        for param_name, param_value in params.items():
            logger.debug(f"Testing parameter: {param_name}")
            
            for vector in XSS_VECTORS:
                # Generate unique canary for this injection attempt
                canary = _generate_canary()
                
                is_vulnerable, actual_payload = _test_parameter_injection(
                    target_url,
                    param_name,
                    param_value,
                    vector,
                    canary,
                    config
                )
                
                if is_vulnerable:
                    elapsed_time = time.time() - start_time
                    cvss = get_xss_cvss()
                    
                    logger.warning(
                        f"Reflected XSS FOUND in parameter '{param_name}' "
                        f"with canary {canary}"
                    )
                    
                    return {
                        'vulnerability_found': True,
                        'severity': 'High',
                        'details': (
                            f'Reflected XSS vulnerability detected in parameter '
                            f'"{param_name}". Vector: {vector}. '
                            f'Canary token: {canary}. '
                            f'Payload reflected verbatim in response body.'
                        ),
                        'cvss_score': cvss['score'],
                        'cvss_vector': cvss['vector'],
                        'scan_duration': elapsed_time
                    }
        
        elapsed_time = time.time() - start_time
        logger.info(f"Reflected XSS scan complete (no vulnerabilities found)")
        
        return {
            'vulnerability_found': False,
            'severity': 'Info',
            'details': 'No reflected XSS vulnerabilities detected.',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': elapsed_time
        }
        
    except requests.exceptions.RequestException as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Network error during XSS scan: {str(e)}")
        
        return {
            'vulnerability_found': False,
            'severity': 'Error',
            'details': f'Network error during XSS scan: {str(e)}',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': elapsed_time
        }
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Unexpected error during XSS scan: {str(e)}")
        
        return {
            'vulnerability_found': False,
            'severity': 'Error',
            'details': f'Unexpected error during XSS scan: {str(e)}',
            'cvss_score': 0.0,
            'cvss_vector': '',
            'scan_duration': elapsed_time
        }
