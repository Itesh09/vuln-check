import base64
import json
import re
import urllib.parse
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_jwt(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0

    try:
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        common_jwt_params = [
            'token', 'jwt', 'access_token', 'auth_token', 'api_key',
            'bearer', 'authorization', 'token_id', 'session_token'
        ]

        test_params = list(params.keys())
        if not test_params:
            test_params = common_jwt_params[:3]

        response = fetch_url(url)
        if not response:
            return {
                "vulnerability_type": "jwt",
                "is_vulnerable": False,
                "severity": "info",
                "confidence": 0.0,
                "evidence": [{"type": "error", "value": "Failed to fetch target URL"}],
                "recommendation": "Unable to analyze JWT configuration."
            }

        response_text = response.text

        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        jwt_matches = re.findall(jwt_pattern, response_text)

        jwt_tokens = set(jwt_matches)

        for jwt in jwt_tokens:
            vuln_data = analyze_jwt_token(jwt, url)
            if vuln_data:
                evidence.append(vuln_data)
                if vuln_data.get('confidence', 0) > highest_confidence:
                    highest_confidence = vuln_data['confidence']
                    if highest_confidence >= 0.7:
                        is_vulnerable = True

        for param_name in test_params:
            for jwt in jwt_tokens:
                test_params_dict = params.copy()
                test_params_dict[param_name] = [jwt]

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
                    jwt_in_response = re.findall(jwt_pattern, response.text)
                    if jwt_in_response:
                        vuln_data = test_jwt_algorithm_tampering(jwt, test_url)
                        if vuln_data:
                            evidence.append(vuln_data)
                            if vuln_data.get('confidence', 0) > highest_confidence:
                                highest_confidence = vuln_data['confidence']
                                if highest_confidence >= 0.7:
                                    is_vulnerable = True

        auth_header = response.headers.get('Authorization', '')
        if 'bearer' in auth_header.lower() or 'jwt' in auth_header.lower():
            jwt_from_header = re.findall(jwt_pattern, auth_header)
            if jwt_from_header:
                vuln_data = analyze_jwt_token(jwt_from_header[0], url)
                if vuln_data:
                    evidence.append(vuln_data)
                    if vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        if highest_confidence >= 0.7:
                            is_vulnerable = True

    except Exception as e:
        return {
            "vulnerability_type": "jwt",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during JWT scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "jwt",
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_jwt_recommendation(is_vulnerable, highest_confidence)
    }


def decode_jwt(token: str) -> Optional[Dict]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_b64 = parts[0]
        payload_b64 = parts[1]

        if len(header_b64) % 4:
            header_b64 += '=' * (4 - len(header_b64) % 4)
        if len(payload_b64) % 4:
            payload_b64 += '=' * (4 - len(payload_b64) % 4)

        header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
        payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')

        return {
            'header': json.loads(header_json),
            'payload': json.loads(payload_json)
        }
    except Exception:
        return None


def analyze_jwt_token(token: str, source: str) -> Optional[Dict]:
    decoded = decode_jwt(token)
    if not decoded:
        return None

    header = decoded.get('header', {})
    payload = decoded.get('payload', {})
    alg = header.get('alg', '').lower()

    if alg == 'none' or alg == 'None':
        return {
            "type": "algorithm_none",
            "token_source": source,
            "algorithm": alg,
            "evidence": "JWT uses 'none' algorithm - signature verification can be bypassed",
            "confidence": 0.95
        }

    if alg == 'HS256':
        return {
            "type": "weak_algorithm",
            "token_source": source,
            "algorithm": alg,
            "evidence": "JWT uses HMAC-SHA256 with symmetric key - ensure strong secret",
            "confidence": 0.4
        }

    if alg not in ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
        return {
            "type": "unknown_algorithm",
            "token_source": source,
            "algorithm": alg,
            "evidence": f"JWT uses unusual algorithm: {alg}",
            "confidence": 0.3
        }

    if 'exp' not in payload and 'iat' not in payload:
        return {
            "type": "no_expiration",
            "token_source": source,
            "evidence": "JWT has no expiration time - token never expires",
            "confidence": 0.6
        }

    if 'admin' in str(payload).lower() or 'role' in payload or 'privileges' in payload:
        return {
            "type": "sensitive_claims",
            "token_source": source,
            "evidence": "JWT contains sensitive claims that should be verified server-side",
            "confidence": 0.3
        }

    return {
        "type": "jwt_found",
        "token_source": source,
        "algorithm": alg,
        "payload_keys": list(payload.keys()),
        "evidence": "JWT token found with standard configuration",
        "confidence": 0.1
    }


def test_jwt_algorithm_tampering(token: str, source: str) -> Optional[Dict]:
    decoded = decode_jwt(token)
    if not decoded:
        return None

    header = decoded['header']
    header['alg'] = 'none'

    try:
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')

        tampered_token = f"{header_b64}.{token.split('.')[1]}."

        test_headers = {"Authorization": f"Bearer {tampered_token}"}
        response = fetch_url(source, headers=test_headers)

        if response:
            if response.status_code in [200, 201, 202]:
                return {
                    "type": "algorithm_tampering",
                    "token_source": source,
                    "evidence": "Token with 'none' algorithm was accepted",
                    "confidence": 0.9
                }

    except Exception:
        pass

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


def get_jwt_recommendation(is_vulnerable: bool, confidence: float) -> str:
    if not is_vulnerable:
        return "No significant JWT vulnerabilities detected. Continue following secure token practices."

    if confidence >= 0.9:
        return ("CRITICAL: Severe JWT vulnerabilities confirmed. "
                "The application has critical JWT security issues. "
                "Immediate action required: "
                "1. Reject tokens with 'alg: none'. "
                "2. Use strong asymmetric algorithms (RS256, ES256). "
                "3. Implement proper token expiration (exp claim). "
                "4. Validate all claims server-side. "
                "5. Use secure, random secrets with sufficient length. "
                "6. Implement token revocation mechanism.")
    elif confidence >= 0.7:
        return ("HIGH: JWT vulnerabilities detected. "
                "Review JWT implementation, reject 'none' algorithm, "
                "use strong signing keys, and implement expiration.")
    else:
        return ("Potential JWT issues detected. "
                "Review token handling, implement expiration, "
                "and use strong cryptographic algorithms.")
