#!/usr/bin/env python3
"""Example script demonstrating CyberScan vulnerability detection.

This script shows how to use the SQL injection and XSS scanners.
"""

from scanner.sql_injection import scan_sqli
from scanner.xss import scan_reflected_xss


def main():
    """Run vulnerability scans on test targets."""
    
    print("=" * 70)
    print("CyberScan - Automated Vulnerability Detection")
    print("=" * 70)
    
    # Example 1: SQL Injection Scan
    print("\n[1] SQL Injection Scanner")
    print("-" * 70)
    
    # Test URL with query parameters (vulnerable app example)
    sqli_target = "http://localhost:8080/search?q=test&id=1"
    
    print(f"Target: {sqli_target}")
    print("Scanning for SQL injection vulnerabilities...")
    
    sqli_result = scan_sqli(sqli_target)
    print(f"Vulnerability Found: {sqli_result['vulnerability_found']}")
    print(f"Severity: {sqli_result['severity']}")
    print(f"Details: {sqli_result['details']}")
    
    # Example 2: XSS Scan
    print("\n[2] Reflected XSS Scanner")
    print("-" * 70)
    
    xss_target = "http://localhost:8080/search?query=test&keyword=hello"
    
    print(f"Target: {xss_target}")
    print("Scanning for reflected XSS vulnerabilities...")
    
    xss_result = scan_reflected_xss(xss_target)
    print(f"Vulnerability Found: {xss_result['vulnerability_found']}")
    print(f"Severity: {xss_result['severity']}")
    print(f"Details: {xss_result['details']}")
    
    # Example 3: Custom parameters scan
    print("\n[3] Scan with explicit parameters")
    print("-" * 70)
    
    custom_target = "http://localhost:8080/api/search"
    custom_params = {
        "username": "admin",
        "email": "test@example.com"
    }
    
    print(f"Target: {custom_target}")
    print(f"Parameters: {custom_params}")
    print("Scanning SQL injection on custom parameters...")
    
    sqli_custom = scan_sqli(custom_target, params=custom_params)
    print(f"Result: {sqli_custom['details']}")
    
    print("\n" + "=" * 70)
    print("Scan complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
