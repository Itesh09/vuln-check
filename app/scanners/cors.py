import urllib.parse
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_cors(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0

    test_origins = [
        "http://evil.com",
        "https://evil.com",
        "http://attacker.com",
        "https://attacker.com",
        "null",
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "null",
    ]

    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

        response = fetch_url(url)
        if not response:
            return {
                "vulnerability_type": "cors",
                "is_vulnerable": False,
                "severity": "info",
                "confidence": 0.0,
                "evidence": [{"type": "error", "value": "Failed to fetch target URL"}],
                "recommendation": "Unable to analyze CORS configuration."
            }

        cors_headers = {
            "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
            "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials"),
            "Access-Control-Expose-Headers": response.headers.get("Access-Control-Expose-Headers"),
            "Access-Control-Max-Age": response.headers.get("Access-Control-Max-Age"),
        }

        if cors_headers["Access-Control-Allow-Origin"]:
            vuln_data = analyze_cors_headers(cors_headers, domain)
            if vuln_data:
                evidence.append(vuln_data)
                highest_confidence = vuln_data.get('confidence', 0)
                if highest_confidence >= 0.7:
                    is_vulnerable = True

        for test_origin in test_origins[:6]:
            headers = {"Origin": test_origin}
            response = fetch_url(url, headers=headers)

            if response:
                acao = response.headers.get("Access-Control-Allow-Origin")
                acac = response.headers.get("Access-Control-Allow-Credentials")

                if acao:
                    if acao == "*":
                        evidence.append({
                            "type": "wildcard_origin",
                            "test_origin": test_origin,
                            "acao": acao,
                            "evidence": "Access-Control-Allow-Origin set to wildcard (*)",
                            "confidence": 0.9
                        })
                        if not is_vulnerable:
                            highest_confidence = 0.9
                            is_vulnerable = True

                    elif acao == test_origin:
                        evidence.append({
                            "type": "origin_reflection",
                            "test_origin": test_origin,
                            "acao": acao,
                            "evidence": f"Origin '{test_origin}' is reflected in CORS header",
                            "confidence": 0.7
                        })
                        if highest_confidence < 0.7:
                            highest_confidence = 0.7
                            is_vulnerable = True

                    elif "null" in acao.lower() or acao == test_origin:
                        evidence.append({
                            "type": "null_origin",
                            "test_origin": test_origin,
                            "acao": acao,
                            "evidence": "CORS allows null origin",
                            "confidence": 0.6
                        })

                    if acac and acac.lower() == "true":
                        if acao in ["*", test_origin, "null"]:
                            evidence.append({
                                "type": "credentials_with_wildcard",
                                "test_origin": test_origin,
                                "acao": acao,
                                "acac": acac,
                                "evidence": "CORS allows credentials with insecure origin",
                                "confidence": 0.95
                            })
                            highest_confidence = 0.95
                            is_vulnerable = True

                if response.headers.get("Access-Control-Allow-Methods"):
                    methods = response.headers.get("Access-Control-Allow-Methods", "").upper()
                    dangerous_methods = ["PUT", "DELETE", "PATCH", "OPTIONS"]
                    for method in dangerous_methods:
                        if method in methods:
                            evidence.append({
                                "type": "dangerous_methods",
                                "methods": methods,
                                "evidence": f"CORS allows dangerous HTTP method: {method}",
                                "confidence": 0.5
                            })

    except Exception as e:
        return {
            "vulnerability_type": "cors",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during CORS scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "cors",
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_cors_recommendation(is_vulnerable, highest_confidence)
    }


def analyze_cors_headers(cors_headers: Dict, domain: str) -> Optional[Dict]:
    acao = cors_headers.get("Access-Control-Allow-Origin")
    acac = cors_headers.get("Access-Control-Allow-Credentials")

    if acao == "*":
        if acac and acac.lower() == "true":
            return {
                "type": "wildcard_with_credentials",
                "acao": acao,
                "acac": acac,
                "evidence": "CORS allows wildcard origin with credentials",
                "confidence": 0.95
            }
        else:
            return {
                "type": "wildcard_origin",
                "acao": acao,
                "evidence": "CORS allows all origins (wildcard)",
                "confidence": 0.7
            }

    if not acao:
        return {
            "type": "no_cors",
            "evidence": "No CORS headers found",
            "confidence": 0.0
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


def get_cors_recommendation(is_vulnerable: bool, confidence: float) -> str:
    if not is_vulnerable:
        return "No CORS misconfigurations detected. CORS appears to be properly configured."

    if confidence >= 0.9:
        return ("CRITICAL: Severe CORS misconfiguration detected. "
                "The application allows cross-origin access with credentials from any origin. "
                "Immediate action required: "
                "1. Use explicit origin allowlist instead of wildcard (*). "
                "2. Never use 'Access-Control-Allow-Credentials: true' with wildcard origin. "
                "3. Validate and match Origin header exactly. "
                "4. Use 'Access-Control-Allow-Origin' only for trusted domains. "
                "5. Implement CORS for specific routes only, not globally.")
    elif confidence >= 0.7:
        return ("HIGH: CORS misconfiguration detected. "
                "The application allows cross-origin access from untrusted origins. "
                "Review and restrict CORS policy to specific trusted domains only.")
    else:
        return ("Potential CORS issue detected. "
                "Review CORS configuration and implement strict origin allowlists.")
