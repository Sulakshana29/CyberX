#!/usr/bin/env python3
"""CyberScan command-line interface for vulnerability detection."""

import sys
import argparse
import json
from pathlib import Path

from scanner.config import ScannerConfig
from scanner.sql_injection import scan_sqli
from scanner.xss import scan_reflected_xss
from scanner.batch import BatchScanner
from scanner.report import ScanReportGenerator, ScanResult
from scanner.logger import setup_logger

logger = setup_logger(__name__, level='INFO', enable_file=True, log_file='cyberscan.log')


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='CyberScan - Production-Grade Vulnerability Detection Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single URL for SQL injection
  %(prog)s --sqli --url "http://example.com/search?q=test"
  
  # Scan URL for XSS
  %(prog)s --xss --url "http://example.com/search?q=test"
  
  # Comprehensive scan on multiple URLs
  %(prog)s --all --batch-file urls.txt --output report.html
  
  # Aggressive scanning with custom timeout
  %(prog)s --sqli --url "http://example.com/search?id=1" --aggressive --timeout 10
        """
    )
    
    # Scan type arguments
    parser.add_argument('--sqli', action='store_true', help='Scan for SQL injection vulnerabilities')
    parser.add_argument('--xss', action='store_true', help='Scan for reflected XSS vulnerabilities')
    parser.add_argument('--all', action='store_true', help='Scan for all vulnerability types')
    
    # Target arguments
    parser.add_argument('--url', type=str, help='Single URL to scan')
    parser.add_argument('--batch-file', type=str, help='File containing URLs to scan (one per line)')
    
    # Configuration arguments
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--workers', type=int, default=3, help='Number of concurrent workers (default: 3)')
    parser.add_argument('--aggressive', action='store_true', help='Use aggressive scan settings')
    parser.add_argument('--stealth', action='store_true', help='Use stealth scan settings')
    
    # Output arguments
    parser.add_argument('--output', type=str, help='Output report file (html, json, or csv)')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.sqli and not args.xss and not args.all:
        parser.error('Please specify scan type: --sqli, --xss, or --all')
    
    if not args.url and not args.batch_file:
        parser.error('Please specify target: --url or --batch-file')
    
    # Configure logger
    if args.verbose:
        logger.setLevel('DEBUG')
    
    # Select scan configuration
    if args.aggressive:
        config = ScannerConfig.get_aggressive()
        config.request_timeout = args.timeout
    elif args.stealth:
        config = ScannerConfig.get_stealth()
        config.request_timeout = args.timeout
    else:
        config = ScannerConfig.get_default()
        config.request_timeout = args.timeout
    
    # Determine scan type
    scan_types = []
    if args.sqli:
        scan_types.append('sqli')
    if args.xss:
        scan_types.append('xss')
    if args.all:
        scan_types = ['sqli', 'xss']
    
    # Get targets
    targets = []
    if args.url:
        targets = [args.url]
    elif args.batch_file:
        try:
            with open(args.batch_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Batch file not found: {args.batch_file}")
            return 1
    
    if not targets:
        logger.error("No targets to scan")
        return 1
    
    logger.info(f"Starting CyberScan on {len(targets)} target(s)")
    logger.info(f"Scan types: {', '.join(scan_types)}")
    
    results = []
    
    # Single URL scans
    if len(targets) == 1:
        url = targets[0]
        logger.info(f"Scanning: {url}")
        
        if 'sqli' in scan_types:
            logger.info("Running SQL injection scan...")
            result = scan_sqli(url, config=config)
            results.append(ScanResult(
                scan_type='SQL_INJECTION',
                target_url=url,
                vulnerability_found=result['vulnerability_found'],
                severity=result['severity'],
                details=result['details'],
                cvss_score=result.get('cvss_score', 0.0),
                scan_duration=result.get('scan_duration', 0.0)
            ))
            print_result(result)
        
        if 'xss' in scan_types:
            logger.info("Running reflected XSS scan...")
            result = scan_reflected_xss(url, config=config)
            results.append(ScanResult(
                scan_type='REFLECTED_XSS',
                target_url=url,
                vulnerability_found=result['vulnerability_found'],
                severity=result['severity'],
                details=result['details'],
                cvss_score=result.get('cvss_score', 0.0),
                scan_duration=result.get('scan_duration', 0.0)
            ))
            print_result(result)
    
    # Batch scans
    else:
        logger.info(f"Starting batch scan on {len(targets)} URLs with {args.workers} workers")
        batch_scanner = BatchScanner(config=config, max_workers=args.workers)
        
        if len(scan_types) == 2:  # All vulnerability types
            results = batch_scanner.scan_all_vulnerabilities(targets)
        elif 'sqli' in scan_types:
            results = batch_scanner.scan_sqli_batch(targets)
        else:
            results = batch_scanner.scan_xss_batch(targets)
        
        summary = batch_scanner.get_summary()
        print_batch_summary(summary)
    
    # Generate reports
    if args.output:
        logger.info(f"Generating report: {args.output}")
        
        if args.output.endswith('.html'):
            ScanReportGenerator.to_html(results, args.output)
        elif args.output.endswith('.json'):
            ScanReportGenerator.to_json(results, args.output)
        elif args.output.endswith('.csv'):
            ScanReportGenerator.to_csv(results, args.output)
        else:
            # Default to JSON
            ScanReportGenerator.to_json(results, args.output)
        
        logger.info(f"Report saved to: {args.output}")
    
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    
    logger.info("CyberScan completed successfully")
    return 0


def print_result(result: dict) -> None:
    """Print single scan result in formatted table.
    
    Args:
        result: Scan result dictionary.
    """
    print("\n" + "=" * 80)
    print(f"Vulnerability Found: {result['vulnerability_found']}")
    print(f"Severity: {result['severity']}")
    if result.get('cvss_score'):
        print(f"CVSS Score: {result['cvss_score']}")
    print(f"Details: {result['details']}")
    if result.get('scan_duration'):
        print(f"Scan Duration: {result['scan_duration']:.3f}s")
    print("=" * 80)


def print_batch_summary(summary: dict) -> None:
    """Print batch scan summary statistics.
    
    Args:
        summary: Summary statistics dictionary.
    """
    print("\n" + "=" * 80)
    print("BATCH SCAN SUMMARY")
    print("=" * 80)
    print(f"Total Scans: {summary['total_scans']}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    print(f"Critical/High Severity: {summary['critical_high_severity']}")
    print(f"Total Duration: {summary['total_duration_seconds']}s")
    print(f"Average Scan Time: {summary['average_scan_time']}s")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    sys.exit(main())
