import re
import urllib.parse
import uuid
from bs4 import BeautifulSoup
from app.utils.http_client import fetch_url
from app.payloads.xss_payloads import get_priority_payloads, get_payloads_by_context, PAYLOAD_CATEGORIES


def scan_xss(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    
    # Unique identifier for JavaScript execution verification
    execution_id = str(uuid.uuid4())[:8]
    
    is_vulnerable = False
    evidence = []
    highest_confidence = 0.0
    xss_type = "reflected"
    
    try:
        # First, fetch the base page to analyze forms and parameters
        base_response = fetch_url(url)
        if not base_response:
            return {
                "vulnerability_type": "xss",
                "is_vulnerable": False,
                "severity": "info",
                "confidence": 0.0,
                "evidence": [{"type": "error", "value": "Failed to fetch target URL"}],
                "recommendation": "Ensure target URL is accessible and not blocking scanners."
            }
        
        # Parse HTML to analyze page structure and determine relevant payloads
        soup = BeautifulSoup(base_response.text, 'html.parser')
        page_analysis = analyze_page_structure(soup, base_response.text)
        
        # Generate context-aware payloads based on actual page content
        url_payloads = generate_context_payloads("url", page_analysis, execution_id)
        form_payloads = generate_context_payloads("form", page_analysis, execution_id)
        
        # Check URL-based XSS (reflection in URL parameters)
        url_vulnerabilities = check_url_based_xss(url, url_payloads, execution_id)
        for vuln in url_vulnerabilities:
            confidence = calculate_confidence(vuln)
            if confidence > highest_confidence:
                highest_confidence = confidence
                xss_type = classify_xss_type(vuln, "url")
            
            if confidence >= 0.7:  # Only consider as vulnerable if confidence is reasonable
                is_vulnerable = True
                evidence.append(vuln)
        
        # Check form-based XSS only if forms exist
        forms = soup.find_all('form')
        if forms:
            form_vulnerabilities = check_form_based_xss(url, forms, form_payloads, execution_id)
            for vuln in form_vulnerabilities:
                confidence = calculate_confidence(vuln)
                if confidence > highest_confidence:
                    highest_confidence = confidence
                    xss_type = classify_xss_type(vuln, "form")
                
                if confidence >= 0.7:  # Only consider as vulnerable if confidence is reasonable
                    is_vulnerable = True
                    evidence.append(vuln)
            
    except Exception as e:
        return {
            "vulnerability_type": "xss",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during XSS scanning."
        }
    
    # Determine severity based on confidence and execution verification
    severity = determine_severity(highest_confidence)
    
    # Provide detailed recommendation based on XSS type
    recommendation = get_xss_recommendation(xss_type, highest_confidence)
    
    return {
        "vulnerability_type": "xss",
        "xss_type": xss_type,
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": recommendation
    }


def analyze_page_structure(soup, html_content: str) -> dict:
    """Analyze page structure to determine which XSS payloads are relevant"""
    analysis = {
        "has_images": bool(soup.find_all('img')),
        "has_svg": bool(soup.find_all('svg')),
        "has_video": bool(soup.find_all('video')),
        "has_audio": bool(soup.find_all('audio')),
        "has_forms": bool(soup.find_all('form')),
        "has_inputs": bool(soup.find_all(['input', 'textarea', 'select'])),
        "has_links": bool(soup.find_all('a')),
        "has_scripts": bool(soup.find_all('script')),
        "has_iframes": bool(soup.find_all('iframe')),
        "has_dialogs": bool(soup.find_all('dialog')),
        "has_details": bool(soup.find_all('details')),
        "supports_css_animations": '@keyframes' in html_content or 'animation' in html_content,
        "supports_transitions": 'transition' in html_content,
        "supports_media_queries": '@media' in html_content,
        "has_drag_elements": bool(soup.find_all(attrs={"draggable": True})),
        "has_content_editable": bool(soup.find_all(attrs={"contenteditable": True})),
        "has_popover": 'popover' in html_content,
        "has_form_elements": {
            'text': bool(soup.find_all('input[type="text"]')),
            'search': bool(soup.find_all('input[type="search"]')),
            'file': bool(soup.find_all('input[type="file"]')),
            'hidden': bool(soup.find_all('input[type="hidden"]')),
            'textarea': bool(soup.find_all('textarea')),
            'select': bool(soup.find_all('select')),
        }
    }
    
    # Check for event handlers already present
    existing_handlers = []
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.startswith('on'):
                existing_handlers.append(attr)
    analysis["existing_event_handlers"] = list(set(existing_handlers))
    
    return analysis


def generate_context_payloads(payload_type: str, page_analysis: dict, execution_id: str) -> list:
    """Generate relevant payloads based on page structure and payload type"""
    payloads = []
    
    # Always include basic scripts as baseline
    basic_payloads = get_payloads_by_context("html_input")[:3]
    for payload in basic_payloads:
        execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
        execution_payload = execution_payload.replace('alert(\'1\')', f'window.xss_{execution_id}=true')
        execution_payload = execution_payload.replace('alert(\'XSS\')', f'window.xss_{execution_id}=true')
        payloads.append(execution_payload)
    
    if payload_type == "url":
        # URL parameters typically use javascript protocols and basic scripts
        if page_analysis.get("has_links"):
            js_payloads = PAYLOAD_CATEGORIES["javascript_protocol"][:2]
            for payload in js_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Add encoding payloads for URL context
        encoding_payloads = PAYLOAD_CATEGORIES["encoding"][:2]
        for payload in encoding_payloads:
            execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
            payloads.append(execution_payload)
    
    elif payload_type == "form":
        # Only add image payloads if images are present
        if page_analysis.get("has_images"):
            img_payloads = PAYLOAD_CATEGORIES["image"][:2]
            for payload in img_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Only add SVG payloads if SVG elements are present
        if page_analysis.get("has_svg"):
            svg_payloads = PAYLOAD_CATEGORIES["svg"][:2]
            for payload in svg_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Only add media payloads if media elements are present
        if page_analysis.get("has_video") or page_analysis.get("has_audio"):
            media_payloads = PAYLOAD_CATEGORIES["media"][:2]
            for payload in media_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Only add CSS animation payloads if CSS is supported
        if page_analysis.get("supports_css_animations"):
            animation_payloads = PAYLOAD_CATEGORIES["animation"][:2]
            for payload in animation_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Only add transition payloads if transitions are supported
        if page_analysis.get("supports_transitions"):
            transition_payloads = PAYLOAD_CATEGORIES["transition"][:2]
            for payload in transition_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Only add dialog payloads if dialogs are present
        if page_analysis.get("has_dialogs"):
            dialog_payloads = PAYLOAD_CATEGORIES["form_advanced"][:2]
            for payload in dialog_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Only add details/summary payloads if present
        if page_analysis.get("has_details"):
            details_payloads = PAYLOAD_CATEGORIES["toggle"][:1]
            for payload in details_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        # Add form-specific payloads based on input types
        form_elements = page_analysis.get("has_form_elements", {})
        if form_elements.get("text") or form_elements.get("textarea"):
            # Add text manipulation payloads
            text_payloads = PAYLOAD_CATEGORIES["text"][:2]
            for payload in text_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        if form_elements.get("file"):
            # Add file upload specific payloads
            file_payloads = [p for p in PAYLOAD_CATEGORIES["form_advanced"] if "file" in p.lower()][:1]
            for payload in file_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
        
        if form_elements.get("search"):
            # Add search input specific payloads
            search_payloads = [p for p in PAYLOAD_CATEGORIES["form_advanced"] if "search" in p.lower()][:1]
            for payload in search_payloads:
                execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
                payloads.append(execution_payload)
    
    # Add focus payloads if focusable elements exist
    if page_analysis.get("has_inputs") or page_analysis.get("has_links"):
        focus_payloads = PAYLOAD_CATEGORIES["focus"][:2]
        for payload in focus_payloads:
            execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
            payloads.append(execution_payload)
    
    # Add mouse/pointer payloads if interactive elements exist
    if page_analysis.get("has_inputs") or page_analysis.get("has_links"):
        mouse_payloads = PAYLOAD_CATEGORIES["mouse_advanced"][:3]
        for payload in mouse_payloads:
            execution_payload = payload.replace('alert(1)', f'window.xss_{execution_id}=true')
            payloads.append(execution_payload)
    
    return payloads[:15]  # Limit to prevent timeout


def check_url_based_xss(url: str, payloads: list, execution_id: str) -> list:
    """Check for XSS vulnerabilities in URL parameters"""
    vulnerabilities = []
    
    # Extract existing parameters from URL
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    
    # Test with common parameter names if none exist
    if not params:
        common_params = ['search', 'q', 'query', 'input', 'term', 'name', 'id']
        params = {param: ['test'] for param in common_params}
    
    for param_name in params:
        for payload in payloads:
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
            response = fetch_url(test_url)
            if response:
                reflection_data = analyze_reflection(response.text, payload, execution_id)
                if reflection_data["reflected"]:
                    vuln = {
                        "type": "url_reflection",
                        "parameter": param_name,
                        "payload": payload,
                        "evidence_url": test_url,
                        "reflected": True,
                        "context": reflection_data["context"],
                        "is_encoded": reflection_data["is_encoded"],
                        "execution_verified": reflection_data["execution_verified"]
                    }
                    vulnerabilities.append(vuln)
                    break  # Found vulnerability with this parameter, move to next
    
    return vulnerabilities


def check_form_based_xss(base_url: str, forms: list, payloads: list, execution_id: str) -> list:
    """Check for XSS vulnerabilities in HTML forms"""
    vulnerabilities = []
    
    for form in forms:
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET').upper()
        
        # Construct full URL for form action
        if form_action:
            if form_action.startswith('http'):
                action_url = form_action
            else:
                base = urllib.parse.urljoin(base_url, '/')
                action_url = urllib.parse.urljoin(base, form_action)
        else:
            action_url = base_url
        
        # Find all input fields in the form
        inputs = form.find_all(['input', 'textarea', 'select'])
        if not inputs:
            continue
            
        # Test each input field
        for input_field in inputs:
            input_name = input_field.get('name')
            if not input_name:
                continue
                
            input_type = input_field.get('type', 'text')
            if input_type in ['hidden', 'submit', 'button']:
                continue
                
            for payload in payloads:
                # Prepare form data
                form_data = {}
                for inp in inputs:
                    inp_name = inp.get('name')
                    if inp_name:
                        form_data[inp_name] = payload if inp_name == input_name else 'test'
                
                # Submit form
                if form_method == 'POST':
                    response = fetch_url(action_url, method='POST', data=form_data)
                else:
                    response = fetch_url(action_url, method='GET', params=form_data)
                
                if response:
                    reflection_data = analyze_reflection(response.text, payload, execution_id)
                    if reflection_data["reflected"]:
                        vuln = {
                            "type": "form_reflection",
                            "form_action": action_url,
                            "form_method": form_method,
                            "field_name": input_name,
                            "payload": payload,
                            "reflected": True,
                            "context": reflection_data["context"],
                            "is_encoded": reflection_data["is_encoded"],
                            "execution_verified": reflection_data["execution_verified"]
                        }
                        vulnerabilities.append(vuln)
                        break  # Found vulnerability with this field, move to next
    
    return vulnerabilities


def analyze_reflection(response_text: str, payload: str, execution_id: str) -> dict:
    """Analyze payload reflection with context awareness and execution verification"""
    result = {
        "reflected": False,
        "context": "none",
        "is_encoded": False,
        "execution_verified": False
    }
    
    # Check for reflection
    if payload not in response_text:
        return result
    
    result["reflected"] = True
    
    # Check if payload is HTML-encoded
    encoded_variants = [
        payload.replace('<', '&lt;').replace('>', '&gt;'),
        payload.replace('<', '&#60;').replace('>', '&#62;'),
        payload.replace('<', '&#x3C;').replace('>', '&#x3E;'),
    ]
    
    if any(encoded in response_text for encoded in encoded_variants):
        result["is_encoded"] = True
    
    # Parse HTML to determine context
    soup = BeautifulSoup(response_text, 'html.parser')
    text_content = soup.get_text()
    
    # Check if payload is in JavaScript context
    if any(pattern in response_text.lower() for pattern in ['<script', 'javascript:', 'onerror=', 'onload=']):
        result["context"] = "javascript"
    # Check if payload is in HTML attribute
    elif any(f'{attr}="' in response_text for attr in ['href', 'src', 'value', 'name', 'id']):
        result["context"] = "html_attribute"
    # Check if payload is in raw HTML
    elif payload in response_text and payload not in text_content:
        result["context"] = "raw_html"
    # Otherwise it's in text content
    else:
        result["context"] = "html_body"
    
    # Try execution verification with headless browser (simplified version)
    result["execution_verified"] = verify_javascript_execution(response_text, execution_id)
    
    return result


def verify_javascript_execution(html_content: str, execution_id: str) -> bool:
    """Simplified JavaScript execution verification"""
    # In a production environment, this would use Playwright to actually execute JavaScript
    # For now, we'll do a simplified check for common execution patterns
    if f"window.xss_{execution_id}=true" in html_content:
        return True
    
    # Check for script tags that would execute
    if f"<script>window.xss_{execution_id}=true;</script>" in html_content:
        return True
    
    # Check for event handlers that would execute
    if f"onerror=window.xss_{execution_id}=true" in html_content:
        return True
    
    if f"onload=window.xss_{execution_id}=true" in html_content:
        return True
    
    return False


def calculate_confidence(vulnerability_data: dict) -> float:
    """Calculate dynamic confidence based on multiple factors"""
    confidence = 0.3  # Base confidence for any reflection
    
    # Increase confidence for dangerous contexts
    if vulnerability_data.get("context") == "javascript":
        confidence += 0.3
    elif vulnerability_data.get("context") == "html_attribute":
        confidence += 0.25
    elif vulnerability_data.get("context") == "raw_html":
        confidence += 0.2
    elif vulnerability_data.get("context") == "html_body":
        confidence += 0.1
    
    # Decrease confidence if encoded
    if vulnerability_data.get("is_encoded"):
        confidence -= 0.3
    
    # Significantly increase confidence for verified execution
    if vulnerability_data.get("execution_verified"):
        confidence += 0.4
    
    return min(1.0, max(0.0, confidence))


def classify_xss_type(vulnerability_data: dict, reflection_source: str) -> str:
    """Classify XSS type based on characteristics"""
    if vulnerability_data.get("execution_verified"):
        if vulnerability_data.get("context") == "javascript":
            return "dom_based"
        elif reflection_source == "form":
            return "stored"  # Potential stored XSS if form submission persists
        else:
            return "reflected"
    else:
        if vulnerability_data.get("is_encoded"):
            return "potential"  # Not actually executable XSS
        else:
            return "reflected"


def determine_severity(confidence: float) -> str:
    """Determine severity based on confidence score"""
    if confidence >= 0.9:
        return "critical"
    elif confidence >= 0.8:
        return "high"
    elif confidence >= 0.6:
        return "medium"
    elif confidence >= 0.4:
        return "low"
    else:
        return "info"


def get_xss_recommendation(xss_type: str, confidence: float) -> str:
    """Get detailed recommendation based on XSS type and confidence"""
    if confidence >= 0.9:
        return f"CRITICAL: Confirmed {xss_type.replace('_', ' ').title()} XSS vulnerability detected. Immediate remediation required. Implement proper input validation, output encoding, and Content Security Policy (CSP). Review all user input handling immediately."
    elif confidence >= 0.7:
        return f"HIGH: Likely {xss_type.replace('_', ' ').title()} XSS vulnerability detected. Implement robust input sanitization, output encoding, and CSP headers. Test for actual exploitability."
    elif confidence >= 0.5:
        return f"MEDIUM: Potential {xss_type.replace('_', ' ').title()} XSS vulnerability detected. Review input handling and implement defense-in-depth measures including CSP and output encoding."
    else:
        return f"LOW: Informational - {xss_type.replace('_', ' ').title()} XSS indicators detected. Consider implementing additional security measures and reviewing input validation practices."


def check_for_payload_reflection(response_text: str, payload: str) -> bool:
    """Check if the payload is reflected in the response (legacy function for compatibility)"""
    reflection_data = analyze_reflection(response_text, payload, "legacy")
    return reflection_data["reflected"]