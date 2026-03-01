import os
import random
import time
import hashlib
import urllib.parse
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from threading import Lock


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,image/jxr,*/*;q=0.8",
]

ACCEPT_LANGUAGE = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9",
    "en;q=0.9,en-US;q=0.8",
]


@dataclass
class StealthConfig:
    enabled: bool = False
    user_agent_rotation: bool = True
    header_randomization: bool = True
    timing_obfuscation: bool = True
    payload_encoding: bool = False
    proxy_rotation: bool = False
    waf_adaptive: bool = True
    
    min_delay: float = 1.0
    max_delay: float = 5.0
    mean_delay: float = 3.0
    delay_stddev: float = 1.5
    
    max_requests_per_ip: int = 50
    proxy_list: List[str] = field(default_factory=list)
    
    encoding_methods: List[str] = field(default_factory=lambda: ['none'])
    
    waf_bypass_mode: str = 'adaptive'


class StealthEngine:
    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self._request_count = 0
        self._current_proxy_index = 0
        self._lock = Lock()
        self._detected_waf: Optional[str] = None
        self._waf_signatures: Dict[str, List[str]] = self._load_waf_signatures()
        
    def _load_waf_signatures(self) -> Dict[str, List[str]]:
        return {
            'cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'cf-cache-status'],
            'akamai': ['akamai', 'akamai-ghost', 'akamai-origin'],
            'aws_waf': ['aws-waf', 'x-amzn-requestid', 'x-amz-cf-id'],
            'imperva': ['imperva', 'x-cdn', 'x-iinfo'],
            'incapsula': ['incapsula', 'x-cdn', 'x-iinfo'],
            'sucuri': ['sucuri', 'x-sucuri', 'x-sucuri-id'],
            'modsecurity': ['mod_security', 'modsecurity', 'paranoia'],
            'f5_asm': ['x-cnection', 'bigip', 'asm-cache'],
            'radware': ['radware', 'x-cache'],
            'fortiweb': ['fortiweb', 'fortigate'],
        }
    
    def get_headers(self, base_url: str = "") -> Dict[str, str]:
        headers = {}
        
        if self.config.user_agent_rotation:
            headers['User-Agent'] = random.choice(USER_AGENTS)
        else:
            headers['User-Agent'] = 'VulnCheck-Scanner/1.0'
        
        if self.config.header_randomization:
            headers['Accept'] = random.choice(ACCEPT_HEADERS)
            headers['Accept-Language'] = random.choice(ACCEPT_LANGUAGE)
            headers['Accept-Encoding'] = 'gzip, deflate, br'
            headers['DNT'] = '1'
            headers['Connection'] = 'keep-alive'
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty'])
            headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'cors'])
            headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin'])
            headers['Cache-Control'] = 'max-age=0'
            
            if random.random() > 0.7:
                headers['Referer'] = base_url if base_url else '/'
        
        return headers
    
    def apply_delay(self):
        if not self.config.timing_obfuscation:
            return
            
        with self._lock:
            self._request_count += 1
            
        if self.config.timing_obfuscation:
            delay = max(0.1, random.gauss(self.config.mean_delay, self.config.delay_stddev))
            delay = max(self.config.min_delay, min(self.config.max_delay, delay))
            time.sleep(delay)
        else:
            delay = random.uniform(self.config.min_delay, self.config.max_delay)
            time.sleep(delay)
    
    def encode_payload(self, payload: str, vuln_type: str = 'xss') -> List[str]:
        if not self.config.payload_encoding:
            return [payload]
        
        encoded = [payload]
        
        for method in self.config.encoding_methods:
            if method == 'none':
                continue
            elif method == 'url':
                encoded.append(urllib.parse.quote(payload))
            elif method == 'double_url':
                encoded.append(urllib.parse.quote(urllib.parse.quote(payload)))
            elif method == 'html':
                encoded.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            elif method == 'unicode':
                encoded.append(''.join(f'\\x{ord(c):02x}' for c in payload))
            elif method == 'base64':
                import base64
                encoded.append(base64.b64encode(payload.encode()).decode())
            elif method == 'case_random':
                encoded.append(''.join(
                    c.upper() if random.random() > 0.5 else c.lower() 
                    for c in payload
                ))
            elif method == 'null_byte':
                encoded.append('%00' + payload)
        
        if 'none' not in self.config.encoding_methods:
            encoded.append(payload)
            
        return list(set(encoded))
    
    def tamper_sql(self, payload: str) -> List[str]:
        tamper_functions = [
            lambda p: p,
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace('SELECT', 'SEL/**/ECT'),
            lambda p: p.replace('UNION', 'UN/**/ION'),
            lambda p: p.replace('AND', 'A/**/ND'),
            lambda p: p.replace('OR', 'O/**/R'),
            lambda p: p.upper(),
            lambda p: p.lower(),
            lambda p: p.replace("'", "''"),
            lambda p: p.replace('1=1', '1=1--'),
            lambda p: p.replace('=', ' LIKE '),
        ]
        
        return [f(payload) for f in random.sample(tamper_functions, min(3, len(tamper_functions)))]
    
    def tamper_xss(self, payload: str) -> List[str]:
        tamper_functions = [
            lambda p: p,
            lambda p: p.replace('<script>', '<ScRiPt>'),
            lambda p: p.replace('<script>', '<SCRIPT>'),
            lambda p: p.replace('alert', 'aLeRt'),
            lambda p: p.replace('onerror', 'onErRoR'),
            lambda p: p.replace('onload', 'OnLoAd'),
            lambda p: '<!' + '--' + p[1:-1] + '-->' if p.startswith('<') and p.endswith('>') else p,
            lambda p: p.replace(' ', '%20'),
            lambda p: p.replace('=', '%3D'),
        ]
        
        return [f(payload) for f in random.sample(tamper_functions, min(3, len(tamper_functions)))]
    
    def get_proxy(self) -> Optional[Dict]:
        if not self.config.proxy_rotation or not self.config.proxy_list:
            return None
            
        with self._lock:
            proxy = self.config.proxy_list[self._current_proxy_index]
            self._current_proxy_index = (self._current_proxy_index + 1) % len(self.config.proxy_list)
        
        if proxy.startswith('http://') or proxy.startswith('https://'):
            return {'http': proxy, 'https': proxy}
        elif proxy.count(':') == 3:
            ip, port, user, pwd = proxy.split(':')
            return {'http': f'http://{user}:{pwd}@{ip}:{port}',
                    'https': f'http://{user}:{pwd}@{ip}:{port}'}
        else:
            return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    
    def detect_waf(self, response_headers: Dict[str, str], response_text: str = "") -> Optional[str]:
        if self._detected_waf:
            return self._detected_waf
            
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        combined = headers_lower.get('server', '') + ' ' + headers_lower.get('x-powered-by', '')
        
        for waf_name, signatures in self._waf_signatures.items():
            for sig in signatures:
                if sig.lower() in combined or sig.lower() in response_text.lower():
                    self._detected_waf = waf_name
                    return waf_name
                    
        return None
    
    def adapt_to_waf(self, waf_type: Optional[str]) -> Dict[str, Any]:
        if not waf_type or not self.config.waf_adaptive:
            return {'delay_multiplier': 1.0, 'encoding': ['none']}
        
        adaptations = {
            'cloudflare': {'delay_multiplier': 2.0, 'encoding': ['url', 'double_url']},
            'akamai': {'delay_multiplier': 1.5, 'encoding': ['url']},
            'aws_waf': {'delay_multiplier': 1.0, 'encoding': ['none']},
            'imperva': {'delay_multiplier': 2.5, 'encoding': ['url', 'double_url', 'null_byte']},
            'incapsula': {'delay_multiplier': 2.0, 'encoding': ['url', 'double_url']},
            'modsecurity': {'delay_multiplier': 1.5, 'encoding': ['case_random']},
            'sucuri': {'delay_multiplier': 1.5, 'encoding': ['url']},
        }
        
        return adaptations.get(waf_type, {'delay_multiplier': 1.0, 'encoding': ['none']})
    
    def should_rotate_ip(self) -> bool:
        return (self.config.proxy_rotation and 
                self._request_count >= self.config.max_requests_per_ip)
    
    def reset_request_count(self):
        with self._lock:
            self._request_count = 0
    
    def get_cache_buster(self) -> str:
        return str(random.randint(100000, 999999))
    
    def pollute_params(self, params: Dict) -> Dict:
        polluted = params.copy()
        polluted['_'] = self.get_cache_buster()
        polluted['t'] = str(int(time.time() * 1000))
        
        if random.random() > 0.7 and params:
            key = random.choice(list(params.keys()))
            polluted[key] = params[key]
            
        return polluted


_global_stealth: Optional[StealthEngine] = None
_stealth_lock = Lock()


def get_stealth_engine(config: Optional[StealthConfig] = None) -> StealthEngine:
    global _global_stealth
    with _stealth_lock:
        if _global_stealth is None or config is not None:
            _global_stealth = StealthEngine(config)
        return _global_stealth


def configure_stealth(**kwargs):
    engine = get_stealth_engine()
    for key, value in kwargs.items():
        if hasattr(engine.config, key):
            setattr(engine.config, key, value)


def load_stealth_from_env():
    config = StealthConfig(
        enabled=os.environ.get('STEALTH_MODE', 'false').lower() == 'true',
        user_agent_rotation=os.environ.get('STEALTH_UA_ROTATION', 'true').lower() == 'true',
        header_randomization=os.environ.get('STEALTH_HEADERS', 'true').lower() == 'true',
        timing_obfuscation=os.environ.get('STEALTH_DELAY', 'true').lower() == 'true',
        payload_encoding=os.environ.get('STEALTH_ENCODING', 'false').lower() == 'true',
        proxy_rotation=os.environ.get('STEALTH_PROXY', 'false').lower() == 'true',
        min_delay=float(os.environ.get('STEALTH_MIN_DELAY', '1.0')),
        max_delay=float(os.environ.get('STEALTH_MAX_DELAY', '5.0')),
        mean_delay=float(os.environ.get('STEALTH_MEAN_DELAY', '3.0')),
    )
    
    proxy_list = os.environ.get('STEALTH_PROXY_LIST', '').split(',')
    if proxy_list and proxy_list[0]:
        config.proxy_list = [p.strip() for p in proxy_list if p.strip()]
    
    encoding = os.environ.get('STEALTH_ENCODING_METHODS', 'none')
    config.encoding_methods = encoding.split(',') if encoding != 'none' else ['none']
    
    get_stealth_engine(config)
