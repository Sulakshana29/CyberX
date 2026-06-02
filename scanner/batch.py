"""Batch vulnerability scanning engine for CyberScan."""

import time
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.config import ScannerConfig
from scanner.logger import setup_logger
from scanner.report import ScanResult
from scanner.sql_injection import scan_sqli
from scanner.xss import scan_reflected_xss

logger = setup_logger(__name__)


class BatchScanner:
    """Batch vulnerability scanner for testing multiple targets concurrently."""
    
    def __init__(self, config: Optional[ScannerConfig] = None, max_workers: int = 3):
        """Initialize batch scanner.
        
        Args:
            config: Scanner configuration.
            max_workers: Maximum number of concurrent scanning threads.
        """
        self.config = config or ScannerConfig.get_default()
        self.max_workers = max_workers
        self.results: List[ScanResult] = []
    
    def scan_sqli_batch(self, urls: List[str]) -> List[ScanResult]:
        """Scan multiple URLs for SQL injection vulnerabilities.
        
        Args:
            urls: List of URLs to scan.
            
        Returns:
            List of ScanResult objects.
        """
        logger.info(f"Starting batch SQL injection scan on {len(urls)} URLs")
        self.results.clear()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_url_sqli, url): url
                for url in urls
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    logger.error(f"Error scanning {url}: {str(e)}")
        
        return self.results
    
    def scan_xss_batch(self, urls: List[str]) -> List[ScanResult]:
        """Scan multiple URLs for reflected XSS vulnerabilities.
        
        Args:
            urls: List of URLs to scan.
            
        Returns:
            List of ScanResult objects.
        """
        logger.info(f"Starting batch reflected XSS scan on {len(urls)} URLs")
        self.results.clear()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_url_xss, url): url
                for url in urls
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    logger.error(f"Error scanning {url}: {str(e)}")
        
        return self.results
    
    def scan_all_vulnerabilities(self, urls: List[str]) -> List[ScanResult]:
        """Scan multiple URLs for all vulnerability types.
        
        Tests each URL for both SQL injection and reflected XSS.
        
        Args:
            urls: List of URLs to scan.
            
        Returns:
            List of ScanResult objects.
        """
        logger.info(f"Starting comprehensive scan on {len(urls)} URLs")
        self.results.clear()
        
        total_urls = len(urls)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            # Submit both SQLi and XSS scans for each URL
            for url in urls:
                futures[executor.submit(self._scan_url_sqli, url)] = (url, 'SQLi')
                futures[executor.submit(self._scan_url_xss, url)] = (url, 'XSS')
            
            completed = 0
            for future in as_completed(futures):
                url, scan_type = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    completed += 1
                    progress = (completed / (total_urls * 2)) * 100
                    logger.info(f"Progress: {progress:.1f}% ({completed}/{total_urls * 2} scans)")
                except Exception as e:
                    logger.error(f"Error scanning {url} ({scan_type}): {str(e)}")
        
        return self.results
    
    def _scan_url_sqli(self, url: str) -> ScanResult:
        """Internal method to scan a single URL for SQL injection.
        
        Args:
            url: URL to scan.
            
        Returns:
            ScanResult object.
        """
        logger.debug(f"SQLi scan: {url}")
        result_dict = scan_sqli(url, config=self.config)
        
        return ScanResult(
            scan_type='SQL_INJECTION',
            target_url=url,
            vulnerability_found=result_dict['vulnerability_found'],
            severity=result_dict['severity'],
            details=result_dict['details'],
            cvss_score=result_dict.get('cvss_score', 0.0),
            scan_duration=result_dict.get('scan_duration', 0.0)
        )
    
    def _scan_url_xss(self, url: str) -> ScanResult:
        """Internal method to scan a single URL for reflected XSS.
        
        Args:
            url: URL to scan.
            
        Returns:
            ScanResult object.
        """
        logger.debug(f"XSS scan: {url}")
        result_dict = scan_reflected_xss(url, config=self.config)
        
        return ScanResult(
            scan_type='REFLECTED_XSS',
            target_url=url,
            vulnerability_found=result_dict['vulnerability_found'],
            severity=result_dict['severity'],
            details=result_dict['details'],
            cvss_score=result_dict.get('cvss_score', 0.0),
            scan_duration=result_dict.get('scan_duration', 0.0)
        )
    
    def get_summary(self) -> Dict:
        """Get summary statistics from scan results.
        
        Returns:
            Dictionary with summary statistics.
        """
        total_scans = len(self.results)
        vulnerabilities_found = sum(1 for r in self.results if r.vulnerability_found)
        critical_high = sum(1 for r in self.results if r.severity in ['CRITICAL', 'HIGH'])
        total_duration = sum(r.scan_duration for r in self.results)
        
        return {
            'total_scans': total_scans,
            'vulnerabilities_found': vulnerabilities_found,
            'critical_high_severity': critical_high,
            'total_duration_seconds': round(total_duration, 2),
            'average_scan_time': round(total_duration / total_scans, 3) if total_scans > 0 else 0
        }
