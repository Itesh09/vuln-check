from typing import Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum


class ScanMode(Enum):
    FAST = "fast"
    STEALTH = "stealth"
    DEEP = "deep"
    DEFAULT = "default"


FAST_SCANNERS = [
    "xss",
    "sql_injection",
    "headers",
]

STEALTH_SCANNERS = [
    "xss",
    "sql_injection",
    "headers",
    "ssrf",
    "open_redirect",
]

DEEP_SCANNERS = [
    "xss",
    "sql_injection",
    "headers",
    "ssrf",
    "open_redirect",
    "ssti",
    "xxe",
    "nosql_injection",
    "cors",
    "csrf",
    "ssl_tls",
    "path_traversal",
    "jwt",
]


@dataclass
class ScanModeConfig:
    name: str
    enabled_scanners: List[str]
    timeout: int = 30
    max_payloads: int = 10
    max_retries: int = 3
    min_delay: float = 1.0
    max_delay: float = 3.0
    verify_findings: bool = True
    respect_robots_txt: bool = True
    stealth_enabled: bool = False
    stealth_min_delay: float = 1.0
    stealth_max_delay: float = 5.0
    stealth_mean_delay: float = 3.0
    stealth_user_agent_rotation: bool = True
    stealth_header_randomization: bool = True
    stealth_timing_obfuscation: bool = True
    stealth_payload_encoding: bool = False
    stealth_waf_adaptive: bool = True
    max_concurrent_requests: int = 3
    follow_redirects: bool = True
    scan_additional_ports: bool = False
    test_all_http_methods: bool = False
    enumerate_subdirectories: bool = False


SCAN_MODE_CONFIGS: Dict[str, ScanModeConfig] = {
    "fast": ScanModeConfig(
        name="fast",
        enabled_scanners=FAST_SCANNERS,
        timeout=20,
        max_payloads=5,
        max_retries=2,
        min_delay=0.5,
        max_delay=1.5,
        verify_findings=True,
        respect_robots_txt=True,
        stealth_enabled=False,
        max_concurrent_requests=5,
    ),
    "stealth": ScanModeConfig(
        name="stealth",
        enabled_scanners=STEALTH_SCANNERS,
        timeout=45,
        max_payloads=8,
        max_retries=5,
        min_delay=2.0,
        max_delay=5.0,
        verify_findings=True,
        respect_robots_txt=True,
        stealth_enabled=True,
        stealth_min_delay=2.0,
        stealth_max_delay=6.0,
        stealth_mean_delay=4.0,
        stealth_user_agent_rotation=True,
        stealth_header_randomization=True,
        stealth_timing_obfuscation=True,
        stealth_payload_encoding=True,
        stealth_waf_adaptive=True,
        max_concurrent_requests=1,
    ),
    "deep": ScanModeConfig(
        name="deep",
        enabled_scanners=DEEP_SCANNERS,
        timeout=60,
        max_payloads=50,
        max_retries=5,
        min_delay=1.0,
        max_delay=3.0,
        verify_findings=True,
        respect_robots_txt=True,
        stealth_enabled=False,
        stealth_min_delay=1.0,
        stealth_max_delay=4.0,
        stealth_mean_delay=2.5,
        stealth_user_agent_rotation=False,
        stealth_header_randomization=False,
        stealth_timing_obfuscation=True,
        stealth_payload_encoding=False,
        stealth_waf_adaptive=False,
        max_concurrent_requests=3,
        follow_redirects=True,
        scan_additional_ports=False,
        test_all_http_methods=True,
        enumerate_subdirectories=True,
    ),
}


def get_scan_mode_config(mode: str) -> ScanModeConfig:
    mode = mode.lower()
    if mode in SCAN_MODE_CONFIGS:
        return SCAN_MODE_CONFIGS[mode]
    return SCAN_MODE_CONFIGS["fast"]


def get_scanners_for_mode(mode: str) -> List[str]:
    config = get_scan_mode_config(mode)
    return config.enabled_scanners


def apply_scan_mode_settings(mode: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    config = get_scan_mode_config(mode)
    
    settings["timeout"] = config.timeout
    settings["max_payloads"] = config.max_payloads
    settings["max_retries"] = config.max_retries
    settings["min_delay"] = config.min_delay
    settings["max_delay"] = config.max_delay
    settings["verify_findings"] = config.verify_findings
    settings["respect_robots_txt"] = config.respect_robots_txt
    settings["max_concurrent_requests"] = config.max_concurrent_requests
    
    settings["stealth_enabled"] = config.stealth_enabled
    settings["stealth_min_delay"] = config.stealth_min_delay
    settings["stealth_max_delay"] = config.stealth_max_delay
    settings["stealth_mean_delay"] = config.stealth_mean_delay
    settings["stealth_user_agent_rotation"] = config.stealth_user_agent_rotation
    settings["stealth_header_randomization"] = config.stealth_header_randomization
    settings["stealth_timing_obfuscation"] = config.stealth_timing_obfuscation
    settings["stealth_payload_encoding"] = config.stealth_payload_encoding
    settings["stealth_waf_adaptive"] = config.stealth_waf_adaptive
    
    return settings
