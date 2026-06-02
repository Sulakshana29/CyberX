"""Configuration management for CyberScan vulnerability detection engine."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScannerConfig:
    """Configuration for vulnerability scanners.
    
    Attributes:
        request_timeout: HTTP request timeout in seconds.
        max_retries: Maximum retry attempts on network failure.
        follow_redirects: Whether to follow HTTP redirects.
        verify_ssl: Whether to verify SSL certificates.
        user_agent: Custom User-Agent header for requests.
        enable_logging: Enable detailed scan logging.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """
    
    request_timeout: int = 5
    max_retries: int = 1
    follow_redirects: bool = False
    verify_ssl: bool = False
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    )
    enable_logging: bool = True
    log_level: str = "INFO"
    
    @staticmethod
    def get_default() -> 'ScannerConfig':
        """Get default scanner configuration.
        
        Returns:
            Default ScannerConfig instance.
        """
        return ScannerConfig()
    
    @staticmethod
    def get_aggressive() -> 'ScannerConfig':
        """Get aggressive scanning configuration with higher timeout.
        
        Returns:
            Aggressive ScannerConfig instance.
        """
        return ScannerConfig(
            request_timeout=10,
            max_retries=2,
            enable_logging=True
        )
    
    @staticmethod
    def get_stealth() -> 'ScannerConfig':
        """Get stealth scanning configuration.
        
        Returns:
            Stealth ScannerConfig instance.
        """
        return ScannerConfig(
            request_timeout=3,
            max_retries=0,
            enable_logging=False
        )
