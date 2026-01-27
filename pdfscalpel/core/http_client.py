"""
HTTP Client with Retry Logic and Session Management

Provides robust HTTP client for web scraping with:
- Automatic retry with exponential backoff
- Session/cookie management
- Rate limiting and jitter
- Progress tracking
"""

import time
import random
from typing import Optional, Dict, Any, List
from pathlib import Path
from dataclasses import dataclass
import json

try:
    import httpx
except ImportError:
    httpx = None

try:
    import browser_cookie3
except ImportError:
    browser_cookie3 = None

from pdfscalpel.core.logging import get_logger

logger = get_logger()


@dataclass
class RetryConfig:
    max_retries: int = 5
    retry_delay_ms: int = 3000
    exponential_backoff: bool = True
    timeout_seconds: int = 30


@dataclass
class RateLimitConfig:
    base_delay_ms: int = 2000
    jitter_ms: int = 1000


class HTTPClient:
    """
    HTTP client with automatic retry, rate limiting, and session management
    """
    
    def __init__(
        self,
        retry_config: Optional[RetryConfig] = None,
        rate_limit_config: Optional[RateLimitConfig] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None
    ):
        if not httpx:
            raise ImportError("httpx is required for web extraction. Install with: pip install httpx")
        
        self.retry_config = retry_config or RetryConfig()
        self.rate_limit_config = rate_limit_config or RateLimitConfig()
        
        default_headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
        }
        if headers:
            default_headers.update(headers)
        
        self.client = httpx.Client(
            timeout=self.retry_config.timeout_seconds,
            headers=default_headers,
            cookies=cookies,
            follow_redirects=True
        )
        
        self.stats = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'retries': 0,
            'timeouts': 0,
            'gateway_errors': 0
        }
    
    def get(self, url: str, retry_count: int = 0) -> Optional[httpx.Response]:
        """
        Perform GET request with automatic retry logic
        
        Args:
            url: URL to fetch
            retry_count: Current retry attempt (internal use)
        
        Returns:
            Response object or None if all retries failed
        """
        self.stats['total_requests'] += 1
        
        if self.stats['total_requests'] == 1:
            logger.debug(f"First request URL: {url}")
            logger.debug(f"Cookies being sent: {list(self.client.cookies.keys())}")
            logger.debug(f"Headers: {dict(self.client.headers)}")
        
        try:
            response = self.client.get(url)
            
            if response.status_code == 200:
                self.stats['successful'] += 1
                return response
            elif response.status_code in [502, 503, 504]:
                self.stats['gateway_errors'] += 1
                raise Exception(f"Gateway error: {response.status_code}")
            else:
                self.stats['failed'] += 1
                logger.warning(f"HTTP {response.status_code} for {url}")
                return None
        
        except httpx.TimeoutException:
            self.stats['timeouts'] += 1
            logger.warning(f"Timeout for {url}")
        except Exception as e:
            logger.debug(f"Request failed: {e}")
        
        if retry_count < self.retry_config.max_retries:
            self.stats['retries'] += 1
            delay = self._calculate_retry_delay(retry_count)
            logger.debug(f"Retrying in {delay/1000:.1f}s (attempt {retry_count + 1}/{self.retry_config.max_retries})")
            time.sleep(delay / 1000)
            return self.get(url, retry_count + 1)
        
        self.stats['failed'] += 1
        return None
    
    def _calculate_retry_delay(self, retry_count: int) -> float:
        """Calculate retry delay with optional exponential backoff"""
        base = self.retry_config.retry_delay_ms
        if self.retry_config.exponential_backoff:
            return base * (2 ** retry_count)
        return base
    
    def rate_limit_delay(self):
        """Apply rate limiting delay with jitter"""
        delay = self.rate_limit_config.base_delay_ms
        if self.rate_limit_config.jitter_ms > 0:
            jitter = random.randint(-self.rate_limit_config.jitter_ms, self.rate_limit_config.jitter_ms)
            delay += jitter
        
        time.sleep(max(0, delay) / 1000)
    
    def load_cookies_from_browser(self, browser: str = 'firefox', domain: Optional[str] = None) -> Dict[str, str]:
        """
        Load cookies from browser
        
        Args:
            browser: Browser name (firefox, chrome, edge, safari)
            domain: Optional domain to filter cookies
        
        Returns:
            Dictionary of cookies
        """
        if not browser_cookie3:
            raise ImportError("browser-cookie3 is required. Install with: pip install browser-cookie3")
        
        logger.info(f"Loading cookies from {browser}...")
        
        try:
            if browser.lower() == 'firefox':
                cookies = browser_cookie3.firefox(domain_name=domain)
            elif browser.lower() == 'chrome':
                cookies = browser_cookie3.chrome(domain_name=domain)
            elif browser.lower() == 'edge':
                cookies = browser_cookie3.edge(domain_name=domain)
            elif browser.lower() == 'chromium':
                cookies = browser_cookie3.chromium(domain_name=domain)
            else:
                raise ValueError(f"Unsupported browser: {browser}")
            
            cookie_dict = {cookie.name: cookie.value for cookie in cookies}
            logger.info(f"Loaded {len(cookie_dict)} cookies from {browser}")
            
            self.client.cookies.update(cookie_dict)
            return cookie_dict
            
        except Exception as e:
            logger.error(f"Failed to load cookies from {browser}: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, int]:
        """Get request statistics"""
        return self.stats.copy()
    
    def close(self):
        """Close HTTP client"""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
