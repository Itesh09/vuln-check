from app.utils.http_client import fetch_url


def scan_headers(scan_context: dict) -> dict:
    """
    Advanced Security Headers scanner that checks for presence, configuration,
    and best practices of security-related HTTP headers.
    """
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    
    try:
        # Fetch the target URL to analyze response headers
        response = fetch_url(url)
        if not response:
            return {
                "vulnerability_type": "insecure_headers",
                "is_vulnerable": False,
                "severity": "info",
                "confidence": 0.0,
                "evidence": [{"type": "error", "value": "Failed to fetch target URL"}],
                "recommendation": "Ensure target URL is accessible for header analysis."
            }
        
        headers = response.headers
        evidence = []
        header_analysis = {}
        
        # Security headers to check with their analysis functions
        security_headers = {
            "Strict-Transport-Security": analyze_hsts,
            "Content-Security-Policy": analyze_csp,
            "X-Content-Type-Options": analyze_x_content_type_options,
            "X-Frame-Options": analyze_x_frame_options,
            "Referrer-Policy": analyze_referrer_policy,
            "Permissions-Policy": analyze_permissions_policy,
            "X-XSS-Protection": analyze_x_xss_protection,
            "Expect-CT": analyze_expect_ct,
            "Cross-Origin-Embedder-Policy": analyze_coep,
            "Cross-Origin-Opener-Policy": analyze_coop,
            "Cross-Origin-Resource-Policy": analyze_corp,
        }
        
        # Analyze each security header
        for header_name, analyze_func in security_headers.items():
            header_value = headers.get(header_name)
            analysis = analyze_func(header_value, url)
            header_analysis[header_name] = analysis
            
            if not analysis["present"]:
                evidence.append({
                    "header": header_name,
                    "status": "missing",
                    "severity": analysis["severity"],
                    "recommendation": analysis["recommendation"]
                })
            elif not analysis["secure"]:
                evidence.append({
                    "header": header_name,
                    "status": "misconfigured",
                    "value": header_value,
                    "severity": analysis["severity"],
                    "issues": analysis["issues"],
                    "recommendation": analysis["recommendation"]
                })
        
        # Additional security checks
        additional_checks = perform_additional_security_checks(headers, url)
        evidence.extend(additional_checks)
        
        # Calculate overall vulnerability status
        critical_issues = [e for e in evidence if e.get("severity") == "critical"]
        high_issues = [e for e in evidence if e.get("severity") == "high"]
        medium_issues = [e for e in evidence if e.get("severity") == "medium"]
        
        is_vulnerable = len(evidence) > 0
        
        if critical_issues:
            severity = "critical"
            confidence = 0.95
        elif high_issues:
            severity = "high"
            confidence = 0.9
        elif medium_issues:
            severity = "medium"
            confidence = 0.85
        elif evidence:
            severity = "low"
            confidence = 0.8
        else:
            severity = "info"
            confidence = 0.0
        
        return {
            "vulnerability_type": "insecure_headers",
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "header_analysis": header_analysis,
            "recommendation": generate_header_recommendations(evidence, header_analysis)
        }
        
    except Exception as e:
        return {
            "vulnerability_type": "insecure_headers",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during security header scanning."
        }


def analyze_hsts(header_value: str, url: str) -> dict:
    """Analyze Strict-Transport-Security (HSTS) header"""
    if not header_value:
        return {
            "present": False,
            "secure": False,
            "severity": "high" if url.startswith("https") else "medium",
            "recommendation": "Implement HSTS with 'max-age=31536000; includeSubDomains' for HTTPS sites."
        }
    
    issues = []
    secure = True
    
    # Check max-age
    if "max-age=" not in header_value:
        issues.append("Missing max-age directive")
        secure = False
    else:
        import re
        max_age_match = re.search(r'max-age=(\d+)', header_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(f"max-age too short ({max_age} seconds)")
                secure = False
    
    # Check includeSubDomains
    if "includeSubDomains" not in header_value:
        issues.append("Missing includeSubDomains directive")
        secure = False
    
    # Check preload
    if "preload" not in header_value:
        issues.append("Missing preload directive (optional but recommended)")
    
    return {
        "present": True,
        "secure": secure,
        "issues": issues,
        "severity": "medium" if secure else "high",
        "recommendation": "Use 'max-age=31536000; includeSubDomains; preload' for optimal HSTS configuration."
    }


def analyze_csp(header_value: str, url: str) -> dict:
    """Analyze Content-Security-Policy (CSP) header"""
    if not header_value:
        return {
            "present": False,
            "secure": False,
            "severity": "high",
            "recommendation": "Implement a strong CSP with 'default-src https:' and specific directives for each content type."
        }
    
    issues = []
    secure = True
    
    # Check for unsafe directives
    unsafe_patterns = [
        ("unsafe-inline", "Allows inline scripts - XSS risk"),
        ("unsafe-eval", "Allows eval() - XSS risk"),
        ("*", "Wildcards allow any source - security risk"),
        ("data:", "Allows data: URLs - potential XSS risk")
    ]
    
    for pattern, description in unsafe_patterns:
        if pattern in header_value:
            issues.append(description)
            secure = False
    
    # Check for missing important directives
    required_directives = ["default-src", "script-src", "style-src"]
    for directive in required_directives:
        if directive not in header_value:
            issues.append(f"Missing {directive} directive")
            secure = False
    
    return {
        "present": True,
        "secure": secure,
        "issues": issues,
        "severity": "medium" if secure else "high",
        "recommendation": "Use strict CSP without unsafe-inline/unsafe-eval, and define specific trusted sources."
    }


def analyze_x_content_type_options(header_value: str, url: str) -> dict:
    """Analyze X-Content-Type-Options header"""
    if not header_value:
        return {
            "present": False,
            "secure": False,
            "severity": "medium",
            "recommendation": "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing attacks."
        }
    
    if header_value.strip().lower() != "nosniff":
        return {
            "present": True,
            "secure": False,
            "issues": ["Invalid value, should be 'nosniff'"],
            "severity": "medium",
            "recommendation": "Set header value to 'nosniff'."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_x_frame_options(header_value: str, url: str) -> dict:
    """Analyze X-Frame-Options header"""
    if not header_value:
        return {
            "present": False,
            "secure": False,
            "severity": "medium",
            "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks."
        }
    
    valid_values = ["DENY", "SAMEORIGIN", "ALLOW-FROM"]
    header_value_upper = header_value.strip().upper()
    
    if header_value_upper not in valid_values:
        return {
            "present": True,
            "secure": False,
            "issues": ["Invalid value, should be 'DENY', 'SAMEORIGIN', or 'ALLOW-FROM'"],
            "severity": "medium",
            "recommendation": "Use 'DENY' for maximum protection or 'SAMEORIGIN' to allow same-origin framing."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_referrer_policy(header_value: str, url: str) -> dict:
    """Analyze Referrer-Policy header"""
    if not header_value:
        return {
            "present": False,
            "secure": False,
            "severity": "low",
            "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' for better privacy."
        }
    
    valid_policies = [
        "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
        "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"
    ]
    
    if header_value.strip().lower() not in valid_policies:
        return {
            "present": True,
            "secure": False,
            "issues": ["Invalid referrer policy value"],
            "severity": "low",
            "recommendation": "Use 'strict-origin-when-cross-origin' for balanced privacy and functionality."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_permissions_policy(header_value: str, url: str) -> dict:
    """Analyze Permissions-Policy (formerly Feature-Policy) header"""
    if not header_value:
        return {
            "present": False,
            "secure": False,
            "severity": "low",
            "recommendation": "Implement Permissions-Policy to restrict access to sensitive browser features."
        }
    
    # Check for overly permissive policies
    if "*" in header_value:
        return {
            "present": True,
            "secure": False,
            "issues": ["Overly permissive wildcard policy"],
            "severity": "low",
            "recommendation": "Specify exact permissions for each feature instead of using wildcards."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_x_xss_protection(header_value: str, url: str) -> dict:
    """Analyze X-XSS-Protection header (deprecated but still relevant)"""
    if not header_value:
        return {
            "present": False,
            "secure": True,  # Not required if CSP is present
            "issues": [],
            "severity": "info",
            "recommendation": "X-XSS-Protection is deprecated. Use CSP instead."
        }
    
    if "1; mode=block" not in header_value:
        return {
            "present": True,
            "secure": False,
            "issues": ["Should use '1; mode=block' for better protection"],
            "severity": "low",
            "recommendation": "Use '1; mode=block' or rely on CSP for XSS protection."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_expect_ct(header_value: str, url: str) -> dict:
    """Analyze Expect-CT header"""
    if not header_value:
        return {
            "present": False,
            "secure": True,  # Optional header
            "issues": [],
            "severity": "info",
            "recommendation": "Consider implementing Expect-CT for certificate transparency."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_coep(header_value: str, url: str) -> dict:
    """Analyze Cross-Origin-Embedder-Policy header"""
    if not header_value:
        return {
            "present": False,
            "secure": True,  # Optional header
            "issues": [],
            "severity": "info",
            "recommendation": "Consider implementing COEP for cross-origin isolation."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_coop(header_value: str, url: str) -> dict:
    """Analyze Cross-Origin-Opener-Policy header"""
    if not header_value:
        return {
            "present": False,
            "secure": True,  # Optional header
            "issues": [],
            "severity": "info",
            "recommendation": "Consider implementing COOP for cross-origin isolation."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def analyze_corp(header_value: str, url: str) -> dict:
    """Analyze Cross-Origin-Resource-Policy header"""
    if not header_value:
        return {
            "present": False,
            "secure": True,  # Optional header
            "issues": [],
            "severity": "info",
            "recommendation": "Consider implementing CORP for resource protection."
        }
    
    return {
        "present": True,
        "secure": True,
        "issues": [],
        "severity": "info",
        "recommendation": "Header is correctly configured."
    }


def perform_additional_security_checks(headers: dict, url: str) -> list:
    """Perform additional security-related header checks"""
    additional_evidence = []
    
    # Check for information disclosure headers
    info_disclosure_headers = {
        "Server": "Server version disclosure",
        "X-Powered-By": "Technology stack disclosure",
        "X-AspNet-Version": "ASP.NET version disclosure",
        "X-Generator": "CMS/generator disclosure"
    }
    
    for header_name, description in info_disclosure_headers.items():
        if headers.get(header_name):
            additional_evidence.append({
                "header": header_name,
                "status": "information_disclosure",
                "value": headers.get(header_name),
                "severity": "low",
                "recommendation": f"Remove {header_name} header to prevent technology stack disclosure."
            })
    
    # Check for caching headers on sensitive content
    cache_control = headers.get("Cache-Control", "")
    pragma = headers.get("Pragma", "")
    
    if not cache_control and not pragma:
        additional_evidence.append({
            "header": "Cache-Control",
            "status": "missing",
            "severity": "low",
            "recommendation": "Implement proper caching headers to control browser caching behavior."
        })
    
    return additional_evidence


def generate_header_recommendations(evidence: list, header_analysis: dict) -> str:
    """Generate comprehensive security header recommendations"""
    if not evidence:
        return "All critical security headers are properly configured. Continue following security best practices."
    
    recommendations = [
        "Security header vulnerabilities detected. Implement the following recommendations:",
    ]
    
    # Group recommendations by severity
    critical_headers = [e for e in evidence if e.get("severity") == "critical"]
    high_headers = [e for e in evidence if e.get("severity") == "high"]
    medium_headers = [e for e in evidence if e.get("severity") == "medium"]
    
    if critical_headers:
        recommendations.append("\n🔴 CRITICAL - Immediate action required:")
        for header in critical_headers:
            recommendations.append(f"• {header['header']}: {header['recommendation']}")
    
    if high_headers:
        recommendations.append("\n🟠 HIGH - Priority fixes:")
        for header in high_headers:
            recommendations.append(f"• {header['header']}: {header['recommendation']}")
    
    if medium_headers:
        recommendations.append("\n🟡 MEDIUM - Important improvements:")
        for header in medium_headers:
            recommendations.append(f"• {header['header']}: {header['recommendation']}")
    
    recommendations.extend([
        "\n📋 General recommendations:",
        "• Use security header testing tools to verify implementation.",
        "• Implement headers incrementally, starting with critical ones.",
        "• Test headers in staging environment before production deployment.",
        "• Monitor security header compliance regularly.",
        "• Consider using security-focused web server configurations."
    ])
    
    return "\n".join(recommendations)
