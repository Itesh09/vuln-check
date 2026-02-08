import time
from threading import Lock
from typing import Dict, Optional

class RateLimiter:
    """
    A simple token bucket rate limiter.
    """
    def __init__(self, rate_per_second: float, burst: int):
        self.rate = rate_per_second
        self.burst = burst
        self.tokens = burst
        self.last_refill_time = time.monotonic()
        self.lock = Lock()

    def _refill_tokens(self):
        now = time.monotonic()
        time_passed = now - self.last_refill_time
        new_tokens = time_passed * self.rate
        self.tokens = min(self.burst, self.tokens + new_tokens)
        self.last_refill_time = now

    def acquire(self, tokens: int = 1) -> bool:
        """
        Attempts to acquire a number of tokens.
        Returns True if tokens were acquired, False otherwise.
        """
        with self.lock:
            self._refill_tokens()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_for_token(self, tokens: int = 1):
        """
        Waits until tokens can be acquired.
        """
        while not self.acquire(tokens):
            time.sleep(0.01) # Small sleep to prevent busy-waiting

_global_rate_limiters: Dict[str, RateLimiter] = {}
_lock = Lock()

def get_rate_limiter(name: str, rate_per_second: float, burst: int) -> RateLimiter:
    """
    Gets or creates a named global rate limiter.
    """
    with _lock:
        if name not in _global_rate_limiters:
            _global_rate_limiters[name] = RateLimiter(rate_per_second, burst)
        return _global_rate_limiters[name]

def limit_requests(name: str = "default", rate_per_second: float = 1.0, burst: int = 5):
    """
    Decorator to apply rate limiting to a function.
    """
    def decorator(func):
        limiter = get_rate_limiter(name, rate_per_second, burst)
        def wrapper(*args, **kwargs):
            limiter.wait_for_token()
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Example usage:
# @limit_requests(name="external_api", rate_per_second=0.5, burst=2)
# def call_external_api():
#     print("Calling external API...")
#
# for _ in range(10):
#     call_external_api()
