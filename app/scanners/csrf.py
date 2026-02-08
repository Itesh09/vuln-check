import re
from bs4 import BeautifulSoup
from app.utils.http_client import fetch_url


def scan_csrf(scan_context: dict) -> dict:
    """
    Advanced CSRF vulnerability scanner that checks for:
    - Missing CSRF tokens in forms
    - Inadequate SameSite cookie policies
    - Unprotected state-changing actions
    - Weak referer validation
    """
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    vulnerabilities = []
    
    try:
        # Fetch the page to analyze
        response = fetch_url(url)
        if not response:
            return {
                "vulnerability_type": "csrf",
                "is_vulnerable": False,
                "severity": "info",
                "confidence": 0.0,
                "evidence": [{"type": "error", "value": "Failed to fetch target URL"}],
                "recommendation": "Ensure target URL is accessible for CSRF analysis."
            }
        
        # Parse HTML and analyze forms
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # Analyze forms for CSRF protection
        form_vulnerabilities = analyze_forms_csrf(forms, url, response.headers)
        vulnerabilities.extend(form_vulnerabilities)
        
        # Analyze response headers for CSRF protection
        header_vulnerabilities = analyze_headers_csrf(response.headers)
        vulnerabilities.extend(header_vulnerabilities)
        
        # Check for state-changing endpoints
        state_change_vulnerabilities = analyze_state_change_endpoints(url, response.text)
        vulnerabilities.extend(state_change_vulnerabilities)
        
        # Determine overall vulnerability status
        is_vulnerable = len(vulnerabilities) > 0
        
        if is_vulnerable:
            critical_issues = [v for v in vulnerabilities if v.get("severity") == "critical"]
            high_issues = [v for v in vulnerabilities if v.get("severity") == "high"]
            medium_issues = [v for v in vulnerabilities if v.get("severity") == "medium"]
            
            if critical_issues:
                severity = "critical"
                confidence = 0.9
            elif high_issues:
                severity = "high"
                confidence = 0.85
            elif medium_issues:
                severity = "medium"
                confidence = 0.8
            else:
                severity = "low"
                confidence = 0.75
        else:
            severity = "info"
            confidence = 0.0
        
        for vuln in vulnerabilities:
            evidence.append(vuln)
        
        return {
            "vulnerability_type": "csrf",
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": generate_csrf_recommendations(vulnerabilities)
        }
        
    except Exception as e:
        return {
            "vulnerability_type": "csrf",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during CSRF scanning."
        }


def analyze_forms_csrf(forms: list, url: str, headers: dict) -> list:
    """Analyze HTML forms for CSRF protection"""
    vulnerabilities = []
    
    for i, form in enumerate(forms):
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET').upper()
        
        # Skip GET forms (typically not state-changing)
        if form_method == 'GET':
            continue
        
        # Check for CSRF token
        csrf_token_found = False
        csrf_token_name = None
        
        # Common CSRF token patterns
        csrf_patterns = [
            r'csrf[_-]?token',
            r'anti[_-]?csrf[_-]?token',
            r'_token',
            r'authenticity[_-]?token',
            r'xsrf[_-]?token',
            r'request[_-]?verification[_-]?token'
        ]
        
        # Check hidden inputs for CSRF tokens
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        for hidden_input in hidden_inputs:
            input_name = hidden_input.get('name', '').lower()
            input_value = hidden_input.get('value', '')
            
            # Check if input name matches CSRF patterns
            for pattern in csrf_patterns:
                if re.search(pattern, input_name, re.IGNORECASE):
                    csrf_token_found = True
                    csrf_token_name = hidden_input.get('name')
                    break
            
            # Check if input value looks like a CSRF token
            if input_value and len(input_value) > 20:  # CSRF tokens are typically long
                csrf_token_found = True
                csrf_token_name = hidden_input.get('name')
                break
        
        # Check for CSRF token in meta tags (for frameworks like Django)
        if not csrf_token_found:
            meta_tags = form.find_all_previous('meta')
            for meta in meta_tags:
                meta_name = meta.get('name', '').lower()
                if re.search(r'csrf[_-]?token', meta_name, re.IGNORECASE):
                    csrf_token_found = True
                    csrf_token_name = meta.get('name')
                    break
        
        # Determine if form is vulnerable
        if not csrf_token_found:
            # Check if form is state-changing (POST, PUT, DELETE, PATCH)
            state_changing_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
            is_state_changing = form_method in state_changing_methods
            
            if is_state_changing:
                severity = "high"
                description = f"Form lacks CSRF token (method: {form_method})"
            else:
                severity = "medium"
                description = f"Form may lack CSRF protection (method: {form_method})"
            
            vulnerabilities.append({
                "type": "missing_csrf_token",
                "severity": severity,
                "form_index": i,
                "form_action": form_action,
                "form_method": form_method,
                "description": description,
                "recommendation": "Implement CSRF token for this form"
            })
        else:
            # Token found, but check if it's properly implemented
            if csrf_token_name:
                vulnerabilities.append({
                    "type": "csrf_token_present",
                    "severity": "info",
                    "form_index": i,
                    "form_action": form_action,
                    "form_method": form_method,
                    "csrf_token_name": csrf_token_name,
                    "description": "CSRF token found in form",
                    "recommendation": "Ensure CSRF token is properly validated server-side"
                })
    
    return vulnerabilities


def analyze_headers_csrf(headers: dict) -> list:
    """Analyze HTTP headers for CSRF protection"""
    vulnerabilities = []
    
    # Check SameSite cookie attribute
    set_cookie_headers = headers.get_all('Set-Cookie', []) if hasattr(headers, 'get_all') else []
    
    same_site_found = False
    same_site_strict = False
    
    for cookie_header in set_cookie_headers:
        if 'samesite=strict' in cookie_header.lower():
            same_site_found = True
            same_site_strict = True
        elif 'samesite=' in cookie_header.lower():
            same_site_found = True
    
    if not same_site_found:
        vulnerabilities.append({
            "type": "missing_samesite",
            "severity": "medium",
            "description": "No SameSite cookie attribute found",
            "recommendation": "Implement SameSite=Strict or SameSite=Lax for cookies"
        })
    
    # Check for custom CSRF protection headers
    csrf_headers = [
        'X-CSRF-Token',
        'X-XSRF-Token',
        'X-Requested-With',
        'X-Frame-Options'  # Helps prevent clickjacking which can be used for CSRF
    ]
    
    missing_headers = []
    for header in csrf_headers:
        if header not in headers:
            missing_headers.append(header)
    
    if missing_headers:
        vulnerabilities.append({
            "type": "missing_csrf_headers",
            "severity": "low",
            "description": f"Missing CSRF-related headers: {', '.join(missing_headers)}",
            "recommendation": "Consider implementing additional CSRF protection headers"
        })
    
    # Check Origin and Referer header validation
    if 'Origin' not in headers and 'Referer' not in headers:
        vulnerabilities.append({
            "type": "missing_origin_referer_validation",
            "severity": "medium",
            "description": "No Origin or Referer header validation detected",
            "recommendation": "Implement Origin/Referer header validation for state-changing requests"
        })
    
    return vulnerabilities


def analyze_state_change_endpoints(url: str, html_content: str) -> list:
    """Analyze page for unprotected state-changing endpoints"""
    vulnerabilities = []
    
    # Look for AJAX endpoints that might be vulnerable
    ajax_patterns = [
        r'fetch\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*{\s*method\s*:\s*[\'"]?(post|put|delete|patch)',
        r'\.post\s*\(',
        r'\.put\s*\(',
        r'\.delete\s*\(',
        r'\.patch\s*\(',
        r'XMLHttpRequest.*open\s*\(\s*[\'"]?(post|put|delete|patch)'
    ]
    
    for pattern in ajax_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if matches:
            vulnerabilities.append({
                "type": "unprotected_ajax_endpoint",
                "severity": "medium",
                "description": f"Found {len(matches)} AJAX endpoints that may lack CSRF protection",
                "recommendation": "Ensure all AJAX endpoints have CSRF protection"
            })
            break
    
    # Look for form actions without CSRF tokens
    form_action_pattern = r'<form[^>]*action\s*=\s*[\'"]([^\'"]+)[\'"][^>]*method\s*=\s*[\'"]?(post|put|delete|patch)'
    form_matches = re.findall(form_action_pattern, html_content, re.IGNORECASE)
    
    for action, method in form_matches:
        # This is simplified - in real implementation, we'd check if the form has CSRF token
        if method.lower() in ['post', 'put', 'delete', 'patch']:
            vulnerabilities.append({
                "type": "potentially_unprotected_form",
                "severity": "medium",
                "description": f"Form action {action} with method {method} may lack CSRF protection",
                "recommendation": "Verify this form has proper CSRF token implementation"
            })
    
    return vulnerabilities


def generate_csrf_recommendations(vulnerabilities: list) -> str:
    """Generate comprehensive CSRF protection recommendations"""
    if not vulnerabilities:
        return "CSRF protection appears adequate. Continue following security best practices."
    
    recommendations = [
        "CSRF vulnerabilities detected. Implement the following recommendations:",
    ]
    
    # Group recommendations by type
    token_issues = [v for v in vulnerabilities if v.get("type") == "missing_csrf_token"]
    header_issues = [v for v in vulnerabilities if v.get("type") in ["missing_samesite", "missing_csrf_headers"]]
    endpoint_issues = [v for v in vulnerabilities if v.get("type") in ["unprotected_ajax_endpoint", "potentially_unprotected_form"]]
    
    if token_issues:
        recommendations.append("\n🔴 HIGH - CSRF Token Issues:")
        recommendations.append("• Implement anti-CSRF tokens for all state-changing forms")
        recommendations.append("• Use cryptographically strong, unpredictable tokens")
        recommendations.append("• Ensure tokens are single-use and expire appropriately")
        recommendations.append("• Validate tokens server-side for every state-changing request")
    
    if header_issues:
        recommendations.append("\n🟠 MEDIUM - Header Protection:")
        recommendations.append("• Implement SameSite cookie attribute (Strict or Lax)")
        recommendations.append("• Validate Origin and Referer headers for cross-origin requests")
        recommendations.append("• Use X-Frame-Options to prevent clickjacking")
        recommendations.append("• Consider custom CSRF protection headers")
    
    if endpoint_issues:
        recommendations.append("\n🟡 MEDIUM - Endpoint Protection:")
        recommendations.append("• Protect all AJAX endpoints with CSRF tokens")
        recommendations.append("• Use same-origin policies for sensitive operations")
        recommendations.append("• Implement double-submit cookie pattern for AJAX requests")
        recommendations.append("• Verify all state-changing API endpoints have CSRF protection")
    
    recommendations.extend([
        "\n📋 General CSRF Protection Recommendations:",
        "• Use established CSRF protection libraries (e.g., OWASP CSRFGuard)",
        "• Implement defense-in-depth with multiple CSRF protection mechanisms",
        "• Test CSRF protection with automated security testing tools",
        "• Educate developers about CSRF risks and prevention techniques",
        "• Regularly audit CSRF protection implementation",
        "• Consider using SameSite cookies as additional protection layer",
        "• Implement proper session management and authentication",
        "• Use HTTPS to prevent token interception",
        "• Monitor for CSRF attack attempts in logs",
        "• Keep web frameworks and security libraries updated"
    ])
    
    return "\n".join(recommendations)
