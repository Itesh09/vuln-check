import re
import urllib.parse
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_ssrf(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0

    ssrf_payloads = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://kubernetes.default.svc.cluster.local/",
        "http://app.prototype.poll.er",
        "https://example.com@127.0.0.1",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:5432/",
        "http://127.0.0.1:6379/",
        "dict://localhost:11211/stats",
        "gopher://127.0.0.1:6379/_INFO",
        "sftp://localhost:22/",
        "ldap://localhost:389/",
    ]

    internal_ips = [
        "192.168.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "10.0.0.2",
        "172.16.0.1",
        "172.16.0.2",
        "172.17.0.1",
    ]

    try:
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        common_ssrf_params = [
            'url', 'uri', 'path', 'dest', 'redirect', 'next', 'data',
            'reference', 'site', 'html', 'val', 'validate', 'domain',
            'callback', 'return', 'page', 'feed', 'host', 'port', 'to',
            'out', 'view', 'dir', 'show', 'navigation', 'open', 'file',
            'document', 'folder', 'pg', 'style', 'doc', 'img', 'source',
            'callback_url', 'return_url', 'page_url', 'image_url', 'share',
            'go', 'follow', 'target', 'frame', 'href', 'src', 'link', 'u'
        ]

        test_params = list(params.keys())
        if not test_params:
            test_params = common_ssrf_params[:5]

        for param_name in test_params:
            for payload in ssrf_payloads[:8]:
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
                    vuln_data = analyze_ssrf_response(response.text, payload, param_name, test_url)
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

        for param_name in test_params:
            for ip in internal_ips[:3]:
                payload = f"http://{ip}/"
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
                    if "Instance ID" in response.text or "meta-data" in response.text:
                        is_vulnerable = True
                        highest_confidence = 0.9
                        evidence.append({
                            "type": "internal_access",
                            "parameter": param_name,
                            "payload": payload,
                            "test_url": test_url,
                            "evidence": "Successfully accessed cloud metadata endpoint",
                            "confidence": 0.9
                        })
                        break

    except Exception as e:
        return {
            "vulnerability_type": "ssrf",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during SSRF scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "ssrf",
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_ssrf_recommendation(is_vulnerable, highest_confidence)
    }


def analyze_ssrf_response(response_text: str, payload: str, param_name: str, test_url: str) -> Optional[Dict]:
    indicators = {
        "localhost": ["localhost", "127.0.0.1", "::1", "0.0.0.0"],
        "metadata": ["instance id", "ami-id", "meta-data", "metadata", "kubernetes"],
        "internal": ["internal server error", "connection refused", "timeout", "refused"],
        "cloud": ["amazon", "aws", "google", "azure", "digitalocean"],
    }

    response_lower = response_text.lower()

    for category, keywords in indicators.items():
        for keyword in keywords:
            if keyword in payload.lower() and keyword in response_lower:
                return {
                    "type": category,
                    "parameter": param_name,
                    "payload": payload,
                    "test_url": test_url,
                    "evidence": f"Potential {category} access via {param_name}",
                    "confidence": 0.8
                }

    if "localhost" in payload.lower():
        if response_lower != response_text[:100].lower():
            return {
                "type": "reflection",
                "parameter": param_name,
                "payload": payload,
                "test_url": test_url,
                "evidence": "Payload reflected in response",
                "confidence": 0.5
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


def get_ssrf_recommendation(is_vulnerable: bool, confidence: float) -> str:
    if not is_vulnerable:
        return "No SSRF vulnerabilities detected. Continue following secure coding practices."

    if confidence >= 0.9:
        return ("CRITICAL: Server-Side Request Forgery vulnerability confirmed. "
                "The application can be forced to make requests to internal systems. "
                "Immediate action required: "
                "1. Validate and sanitize all URL inputs. "
                "2. Use allowlists for permitted domains. "
                "3. Disable unnecessary URL schemas (gopher, dict, ldap). "
                "4. Block access to internal IP ranges and metadata endpoints.")
    else:
        return ("Potential SSRF vulnerability detected. Review URL validation logic, "
                "implement allowlists, and restrict access to internal resources.")
