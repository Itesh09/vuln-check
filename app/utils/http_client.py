import os
import time
import random
import logging
import requests
from requests.exceptions import RequestException, HTTPError
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from app.utils.stealth import StealthConfig, StealthEngine, get_stealth_engine

logger = logging.getLogger(__name__)


class PoliteHTTPClient:
    def __init__(self, config: Optional[Dict] = None, stealth_engine: Optional[Any] = None):
        self.config = config or {}
        self.min_delay = self.config.get('min_delay', 1.0)
        self.max_delay = self.config.get('max_delay', 3.0)
        self.max_retries = self.config.get('max_retries', 5)
        self.base_wait = self.config.get('base_wait', 1)
        self.max_wait = self.config.get('max_wait', 60)
        self.rate_limit_wait = self.config.get('rate_limit_wait', 60)
        self.user_agent = self.config.get('user_agent', 'VulnCheck-Scanner/1.0 (Security Scanner; +https://github.com/Itesh09/vuln-check)')
        
        self.stealth = stealth_engine if stealth_engine else get_stealth_engine()
        self._stealth_enabled = self.stealth.config.enabled
        
        self.session = requests.Session()
        self._setup_session_headers()
        
        self._robots_cache: Dict[str, Dict] = {}
        self._crawl_delay: Optional[float] = None
        self._last_request_time = 0.0

    def _setup_session_headers(self):
        if self._stealth_enabled:
            stealth_headers = self.stealth.get_headers()
            self.session.headers.update(stealth_headers)
        else:
            self.session.headers.update({
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
            })

    def _random_delay(self):
        delay = random.uniform(self.min_delay, self.max_delay)
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time = time.time()

    def _exponential_backoff(self, attempt: int) -> float:
        wait_time = min(self.base_wait * (2 ** attempt), self.max_wait)
        jitter = random.uniform(0, 0.5)
        return wait_time + jitter

    def _parse_robots_txt(self, domain: str) -> Optional[float]:
        if domain in self._robots_cache:
            return self._robots_cache[domain].get('crawl_delay')

        try:
            robots_url = f"{domain}/robots.txt"
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if line.startswith('crawl-delay:'):
                        delay = float(line.split(':')[1].strip())
                        self._robots_cache[domain] = {'crawl_delay': delay}
                        logger.info(f" robots.txt crawl-delay: {delay}s")
                        return delay
            self._robots_cache[domain] = {'crawl_delay': None}
        except Exception:
            pass
        return None

    def _check_rate_limit(self, response: requests.Response) -> tuple[bool, int]:
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    return True, int(retry_after)
                except ValueError:
                    pass
            return True, self.rate_limit_wait
        return False, 0

    def fetch(self, url: str, method: str = "GET", params: Optional[Dict] = None,
              data: Optional[Dict] = None, json: Optional[Dict] = None,
              headers: Optional[Dict] = None, timeout: int = 10,
              allow_redirects: bool = True, respect_robots: bool = True,
              use_stealth: bool = True) -> Optional[requests.Response]:
        parsed = urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"

        if respect_robots and self._crawl_delay is None:
            self._crawl_delay = self._parse_robots_txt(domain)

        for attempt in range(self.max_retries):
            try:
                if self._stealth_enabled and use_stealth:
                    self.stealth.apply_delay()
                    
                    if self.stealth.should_rotate_ip():
                        proxy = self.stealth.get_proxy()
                        if proxy:
                            self.session.proxies.update(proxy)
                        self.stealth.reset_request_count()
                else:
                    self._random_delay()

                if self._crawl_delay:
                    time.sleep(self._crawl_delay)

                request_headers = dict(self.session.headers)
                
                if self._stealth_enabled and use_stealth:
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    stealth_headers = self.stealth.get_headers(base_url)
                    request_headers.update(stealth_headers)
                    
                    if params and random.random() > 0.5:
                        params = self.stealth.pollute_params(params)
                
                if headers:
                    request_headers.update(headers)

                proxies = None
                if self._stealth_enabled and use_stealth:
                    proxies = self.stealth.get_proxy()

                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=request_headers,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    proxies=proxies
                )

                if self._stealth_enabled and use_stealth:
                    waf_detected = self.stealth.detect_waf(dict(response.headers), response.text[:1000])
                    if waf_detected:
                        logger.warning(f"WAF detected: {waf_detected}")
                        adaptation = self.stealth.adapt_to_waf(waf_detected)
                        if adaptation.get('delay_multiplier', 1.0) > 1.0:
                            time.sleep(adaptation['delay_multiplier'] - 1.0)

                is_ratelimited, wait_time = self._check_rate_limit(response)
                if is_ratelimited:
                    logger.warning(f"Rate limited (429). Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    if self._stealth_enabled:
                        self.stealth.reset_request_count()
                    continue

                if response.status_code >= 500:
                    wait_time = self._exponential_backoff(attempt)
                    logger.warning(f"Server error {response.status_code}. Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                    continue

                if response.status_code == 403:
                    logger.warning(f"Access forbidden (403). Trying with different headers...")
                    request_headers['X-Requested-With'] = 'XMLHttpRequest'
                    response = self.session.request(
                        method=method, url=url, params=params, data=data,
                        json=json, headers=request_headers, timeout=timeout,
                        allow_redirects=allow_redirects, proxies=proxies
                    )

                logger.info(f"[{response.status_code}] {method} {url}")
                return response

            except HTTPError as e:
                logger.error(f"HTTP error for {url}: {e}")
                return None
            except RequestException as e:
                if attempt < self.max_retries - 1:
                    wait_time = self._exponential_backoff(attempt)
                    logger.warning(f"Request failed: {e}. Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Max retries exceeded for {url}: {e}")
                    return None
            except Exception as e:
                logger.error(f"Unexpected error for {url}: {e}")
                return None

        return None


_global_client: Optional[PoliteHTTPClient] = None


def get_polite_client(config: Optional[Dict] = None) -> PoliteHTTPClient:
    global _global_client
    if _global_client is None or config is not None:
        _global_client = PoliteHTTPClient(config)
    return _global_client


def fetch_url(url: str, method: str = "GET", params: Optional[Dict] = None,
              data: Optional[Dict] = None, json: Optional[Dict] = None,
              headers: Optional[Dict] = None, timeout: int = 10,
              respect_robots: bool = True) -> Optional[requests.Response]:
    client = get_polite_client()
    return client.fetch(url, method, params, data, json, headers, timeout, respect_robots=respect_robots)