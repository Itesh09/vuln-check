import re
import urllib.parse
from bs4 import BeautifulSoup
from app.utils.http_client import fetch_url


def scan_open_redirect(scan_context: dict) -> dict:
    """
    Advanced Open Redirect vulnerability scanner that checks for:
    - URL parameter reflection in redirects
    - Form-based redirect vulnerabilities
    - Unsafe URL validation
    - Data URL and JavaScript redirects
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
                "vulnerability_type": "open_redirect",
                "is_vulnerable": False,
                "severity": "info",
                "confidence": 0.0,
                "evidence": [{"type": "error", "value": "Failed to fetch target URL"}],
                "recommendation": "Ensure target URL is accessible for redirect analysis."
            }
        
        # Parse HTML to find forms and redirect mechanisms
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # Test URL parameters for open redirect
        url_vulnerabilities = test_url_redirect_vulnerabilities(url, response.headers)
        vulnerabilities.extend(url_vulnerabilities)
        
        # Test forms for open redirect
        form_vulnerabilities = test_form_redirect_vulnerabilities(url, forms)
        vulnerabilities.extend(form_vulnerabilities)
        
        # Test JavaScript redirect mechanisms
        js_vulnerabilities = test_javascript_redirects(response.text)
        vulnerabilities.extend(js_vulnerabilities)
        
        # Test meta refresh redirects
        meta_vulnerabilities = test_meta_redirects(response.text)
        vulnerabilities.extend(meta_vulnerabilities)
        
        # Determine overall vulnerability status
        is_vulnerable = len(vulnerabilities) > 0
        
        if is_vulnerable:
            severity = "high" if any(v.get("severity") == "high" for v in vulnerabilities) else "medium"
            confidence = max(v.get("confidence", 0) for v in vulnerabilities)
        else:
            severity = "info"
            confidence = 0.0
        
        for vuln in vulnerabilities:
            evidence.append(vuln)
        
        return {
            "vulnerability_type": "open_redirect",
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": generate_redirect_recommendations(vulnerabilities)
        }
        
    except Exception as e:
        return {
            "vulnerability_type": "open_redirect",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during open redirect scanning."
        }


def test_url_redirect_vulnerabilities(url: str, headers: dict) -> list:
    """Test URL parameters for open redirect vulnerabilities"""
    vulnerabilities = []
    
    # Extract existing parameters from URL
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    
    # If no parameters, test common redirect parameter names
    if not params:
        common_redirect_params = [
            'redirect', 'url', 'return', 'goto', 'link', 'target', 'destination',
            'next', 'back', 'ref', 'redirect_uri', 'return_url', 'callback',
            'continue', 'forward', 'go', 'rurl', 'goto_url', 'redirect_to'
        ]
        params = {param: ['http://example.com'] for param in common_redirect_params}
    
    # Redirect payloads to test
    redirect_payloads = [
        "http://evil.com",
        "https://evil.com", 
        "http://attacker.com",
        "//evil.com",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(1)",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "ftp://evil.com",
        "mailto:evil@evil.com",
        "//google.com",
        "/\\evil.com"  # Path traversal that becomes redirect
    ]
    
    # Test each parameter with each payload
    for param_name, param_values in params.items():
        for payload in redirect_payloads:
            # Create test URL with payload
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Test the URL
            try:
                test_response = fetch_url(test_url, allow_redirects=False)
                
                # Check for redirects in response
                if test_response:
                    redirect_vuln = analyze_redirect_response(test_response, payload, test_url, param_name)
                    if redirect_vuln:
                        vulnerabilities.append(redirect_vuln)
                        break  # Found vulnerability with this parameter
                        
            except Exception:
                continue
    
    return vulnerabilities


def test_form_redirect_vulnerabilities(base_url: str, forms: list) -> list:
    """Test HTML forms for open redirect vulnerabilities"""
    vulnerabilities = []
    
    for form in forms:
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET').upper()
        
        # Construct full URL for form action
        if form_action:
            if form_action.startswith('http'):
                action_url = form_action
            else:
                action_url = urllib.parse.urljoin(base_url, form_action)
        else:
            action_url = base_url
        
        # Find all input fields in form
        inputs = form.find_all(['input', 'textarea', 'select'])
        if not inputs:
            continue
        
        # Test each input field for redirect vulnerabilities
        for input_field in inputs:
            input_name = input_field.get('name')
            if not input_name:
                continue
            
            input_type = input_field.get('type', 'text')
            if input_type in ['hidden', 'submit', 'button']:
                continue
            
            # Redirect payloads for form testing
            redirect_payloads = [
                "http://evil.com",
                "https://evil.com",
                "//evil.com",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "/\\evil.com"
            ]
            
            for payload in redirect_payloads:
                # Prepare form data
                form_data = {}
                for inp in inputs:
                    inp_name = inp.get('name')
                    if inp_name:
                        form_data[inp_name] = payload if inp_name == input_name else 'test'
                
                try:
                    # Submit form
                    if form_method == 'POST':
                        test_response = fetch_url(action_url, method='POST', data=form_data, allow_redirects=False)
                    else:
                        test_response = fetch_url(action_url, method='GET', params=form_data, allow_redirects=False)
                    
                    if test_response:
                        redirect_vuln = analyze_redirect_response(test_response, payload, action_url, input_name)
                        if redirect_vuln:
                            redirect_vuln["form_method"] = form_method
                            redirect_vuln["form_action"] = action_url
                            vulnerabilities.append(redirect_vuln)
                            break  # Found vulnerability with this field
                            
                except Exception:
                    continue
    
    return vulnerabilities


def test_javascript_redirects(html_content: str) -> list:
    """Test JavaScript code for redirect vulnerabilities"""
    vulnerabilities = []
    
    # Look for redirect patterns in JavaScript
    js_redirect_patterns = [
        r'window\.location\s*=\s*["\']([^"\']+)["\']',
        r'window\.open\s*\(\s*["\']([^"\']+)["\']',
        r'document\.location\s*=\s*["\']([^"\']+)["\']',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
        r'window\.assign\s*\(\s*["\']([^"\']+)["\']',
        r'window\.navigate\s*\(\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in js_redirect_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            url = match.strip() if match else ""
            if url and looks_like_user_input(url, html_content):
                vulnerabilities.append({
                    "type": "javascript_redirect",
                    "severity": "medium",
                    "redirect_url": url,
                    "pattern": pattern,
                    "description": f"JavaScript redirect to user-controlled URL: {url}",
                    "recommendation": "Validate and sanitize all URLs used in JavaScript redirects"
                })
    
    return vulnerabilities


def test_meta_redirects(html_content: str) -> list:
    """Test meta refresh tags for redirect vulnerabilities"""
    vulnerabilities = []
    
    # Look for meta refresh tags
    meta_refresh_pattern = r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^;]*;?url=([^"\']+)["\']'
    matches = re.findall(meta_refresh_pattern, html_content, re.IGNORECASE)
    
    for match in matches:
        redirect_url = match.strip()
        if redirect_url and looks_like_user_input(redirect_url, html_content):
            vulnerabilities.append({
                "type": "meta_refresh_redirect",
                "severity": "medium",
                "redirect_url": redirect_url,
                "description": f"Meta refresh redirect to user-controlled URL: {redirect_url}",
                "recommendation": "Validate meta refresh URLs and avoid user input in redirect targets"
            })
    
    return vulnerabilities


def looks_like_user_input(url: str, html_content: str) -> bool:
    """Check if URL appears to be from user input"""
    # Common indicators of user input in URLs
    user_input_indicators = [
        "http://evil.com", "https://evil.com", "//evil.com",
        "http://attacker.com", "https://attacker.com",
        "javascript:", "data:",
        "vbscript:",
        "ftp://", "file://",
        "127.0.0.1", "0.0.0.0", "localhost"
    ]
    
    url_lower = url.lower()
    return any(indicator in url_lower for indicator in user_input_indicators)


def analyze_redirect_response(response, payload: str, test_url: str, param_name: str) -> dict:
    """Analyze HTTP response for redirect vulnerabilities"""
    # Check for 3xx redirects
    if response.status_code >= 300 and response.status_code < 400:
        location = response.headers.get('Location', '')
        if location and (payload in location or any(indicator in location.lower() for indicator in ['evil.com', 'attacker.com', '127.0.0.1'])):
            return {
                "type": "url_redirect",
                "severity": "high",
                "parameter": param_name,
                "payload": payload,
                "test_url": test_url,
                "redirect_location": location,
                "status_code": response.status_code,
                "description": f"HTTP {response.status_code} redirect to user-controlled URL: {location}",
                "recommendation": "Validate and sanitize redirect parameters to prevent open redirects"
            }
    
    # Check for JavaScript in response that executes redirects
    if response.text and payload in response.text:
        if any(pattern in response.text.lower() for pattern in ['location=', 'window.location', 'document.location']):
            return {
                "type": "reflected_redirect",
                "severity": "medium",
                "parameter": param_name,
                "payload": payload,
                "test_url": test_url,
                "description": f"Payload reflected in JavaScript redirect context",
                "recommendation": "Encode user input before using in JavaScript redirect contexts"
            }
    
    # Check for HTML injection that could lead to redirects
    if response.text and f'<meta http-equiv="refresh"' in response.text.lower():
        if payload in response.text:
            return {
                "type": "meta_redirect_injection",
                "severity": "medium",
                "parameter": param_name,
                "payload": payload,
                "test_url": test_url,
                "description": "Payload injected into meta refresh tag",
                "recommendation": "Validate input used in meta refresh tags"
            }
    
    return None


def generate_redirect_recommendations(vulnerabilities: list) -> str:
    """Generate comprehensive open redirect recommendations"""
    if not vulnerabilities:
        return "No open redirect vulnerabilities detected. Continue following secure coding practices."
    
    recommendations = [
        "Open redirect vulnerabilities detected. Implement the following recommendations:",
    ]
    
    # Group recommendations by vulnerability type
    url_redirects = [v for v in vulnerabilities if v.get("type") == "url_redirect"]
    form_redirects = [v for v in vulnerabilities if v.get("type") in ["reflected_redirect", "form_redirect"]]
    js_redirects = [v for v in vulnerabilities if v.get("type") == "javascript_redirect"]
    meta_redirects = [v for v in vulnerabilities if v.get("type") == "meta_refresh_redirect"]
    
    if url_redirects or form_redirects:
        recommendations.append("\n🔴 HIGH - Immediate action required:")
        recommendations.append("• Validate all redirect URLs against allowlist of trusted domains")
        recommendations.append("• Use relative URLs instead of absolute URLs when possible")
        recommendations.append("• Sanitize and encode user input before using in redirects")
        recommendations.append("• Implement proper URL validation and parsing")
    
    if js_redirects or meta_redirects:
        recommendations.append("\n🟠 MEDIUM - Important fixes:")
        recommendations.append("• Encode user input before using in JavaScript redirect contexts")
        recommendations.append("• Avoid using user input in meta refresh tags")
        recommendations.append("• Use Content Security Policy to restrict JavaScript execution")
        recommendations.append("• Validate URLs in JavaScript location assignments")
    
    recommendations.extend([
        "\n📋 General Open Redirect Protection:",
        "• Use allowlist validation instead of denylist for redirect URLs",
        "• Implement URL parsing and validation libraries",
        "• Consider using OpenID/OAuth for external authentication",
        "• Test redirect functionality with automated security tools",
        "• Monitor for redirect-based attacks in application logs",
        "• Educate developers about open redirect risks",
        "• Keep web frameworks and libraries updated with security patches",
        "• Use security headers like X-Content-Type-Options: nosniff",
        "• Implement proper error handling that doesn't expose sensitive URLs"
    ])
    
    return "\n".join(recommendations)
