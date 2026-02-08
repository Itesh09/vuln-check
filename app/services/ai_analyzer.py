from typing import List, Dict, Any
import re

def ai_analyze_results(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Advanced AI analysis for XSS vulnerability scan results.
    Uses rule-based machine learning techniques to provide intelligent insights.
    
    Args:
        scan_results: A list of vulnerability scan results.

    Returns:
        A dictionary containing AI-enhanced insights.
    """
    if not scan_results:
        return {
            "summary": "No vulnerabilities detected. The application appears secure against common XSS attacks.",
            "risk_assessment": "LOW",
            "false_positive_analysis": [],
            "attack_surface_analysis": {
                "total_vectors": 0,
                "high_risk_vectors": 0,
                "most_critical_type": None
            },
            "remediation_priority": [],
            "security_recommendations": []
        }
    
    # Analyze all vulnerability types comprehensively
    vulnerability_analysis = analyze_all_vulnerability_types(scan_results)
    
    if not scan_results:
        return {
            "summary": "No vulnerabilities detected. The application appears secure against common web vulnerabilities.",
            "risk_assessment": "LOW",
            "false_positive_analysis": [],
            "attack_surface_analysis": {
                "total_vectors": 0,
                "high_risk_vectors": 0,
                "most_critical_type": None,
                "vulnerability_distribution": {}
            },
            "remediation_priority": [],
            "security_recommendations": []
        }
    
    # AI Analysis Components for all vulnerabilities
    false_positive_analysis = analyze_false_positives_comprehensive(scan_results)
    risk_assessment = assess_overall_risk_comprehensive(scan_results)
    remediation_priority = prioritize_remediation_comprehensive(scan_results)
    
    # Generate vulnerability analysis first
    vulnerability_analysis = analyze_all_vulnerability_types(scan_results)
    attack_surface = analyze_attack_surface_comprehensive(scan_results, vulnerability_analysis)
    security_recommendations = generate_security_recommendations_comprehensive(scan_results, vulnerability_analysis)
    
    return {
        "summary": generate_ai_summary_comprehensive(scan_results, risk_assessment, vulnerability_analysis),
        "risk_assessment": risk_assessment,
        "false_positive_analysis": false_positive_analysis,
        "attack_surface_analysis": attack_surface,
        "remediation_priority": remediation_priority,
        "security_recommendations": security_recommendations
    }


def analyze_false_positives(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AI analysis to identify potential false positives"""
    false_positives = []
    
    for vuln in vulnerabilities:
        confidence = vuln.get("confidence", 0)
        evidence = vuln.get("evidence", [])
        is_encoded = vuln.get("is_encoded", False)
        
        # Low confidence + encoding = likely false positive
        if confidence < 0.6 and is_encoded:
            false_positives.append({
                "vulnerability_id": vuln.get("id", "unknown"),
                "reason": "Low confidence with encoding suggests safe reflection",
                "confidence": confidence,
                "recommendation": "Manual verification recommended"
            })
        
        # Check for JSON reflection patterns
        for evidence_item in evidence:
            payload = evidence_item.get("payload", "")
            if "window.xss_" in payload and confidence < 0.7:
                false_positives.append({
                    "vulnerability_id": vuln.get("id", "unknown"),
                    "reason": "Likely JSON response reflection (safe context)",
                    "confidence": confidence,
                    "recommendation": "Verify actual executable context"
                })
        
        # Check for HTML-only reflections without dangerous context
        context = vuln.get("context", "none")
        if context == "html_body" and confidence < 0.7:
            false_positives.append({
                "vulnerability_id": vuln.get("id", "unknown"),
                "reason": "Reflection in HTML body without execution context",
                "confidence": confidence,
                "recommendation": "Verify if content can execute scripts"
            })
    
    return false_positives


def analyze_attack_surface(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """AI analysis of attack surface and vector types"""
    total_vectors = len(vulnerabilities)
    high_risk_vectors = 0
    
    xss_types = {}
    contexts = {}
    
    for vuln in vulnerabilities:
        # Count XSS types
        xss_type = vuln.get("xss_type", "unknown")
        xss_types[xss_type] = xss_types.get(xss_type, 0) + 1
        
        # Count contexts
        context = vuln.get("context", "unknown")
        contexts[context] = contexts.get(context, 0) + 1
        
        # Count high risk vectors
        if vuln.get("severity") in ["critical", "high"] and vuln.get("confidence", 0) >= 0.8:
            high_risk_vectors += 1
    
    # Determine most critical type
    most_critical_type = None
    if xss_types:
        risk_scores = {
            "dom_based": 10,
            "reflected": 8,
            "stored": 9,
            "potential": 3
        }
        most_critical_type = max(xss_types.keys(), key=lambda x: risk_scores.get(x, 0) * xss_types[x])
    
    return {
        "total_vectors": total_vectors,
        "high_risk_vectors": high_risk_vectors,
        "xss_type_distribution": xss_types,
        "context_distribution": contexts,
        "most_critical_type": most_critical_type
    }


def assess_overall_risk(vulnerabilities: List[Dict[str, Any]]) -> str:
    """AI-powered risk assessment"""
    if not vulnerabilities:
        return "LOW"
    
    # Calculate risk score
    risk_score = 0
    for vuln in vulnerabilities:
        severity_multiplier = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 2,
            "info": 1
        }
        severity = vuln.get("severity", "info")
        confidence = vuln.get("confidence", 0)
        
        vuln_risk = severity_multiplier.get(severity, 1) * confidence
        risk_score += vuln_risk
    
    # Determine overall risk
    if risk_score >= 15:
        return "CRITICAL"
    elif risk_score >= 10:
        return "HIGH"
    elif risk_score >= 5:
        return "MEDIUM"
    elif risk_score >= 2:
        return "LOW"
    else:
        return "INFO"


def prioritize_remediation(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AI-powered remediation prioritization"""
    prioritized = []
    
    for vuln in vulnerabilities:
        # Calculate priority score
        severity_weight = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        
        confidence_weight = vuln.get("confidence", 0) * 20
        context_weight = {
            "javascript": 30,
            "html_attribute": 25,
            "raw_html": 20,
            "html_body": 15,
            "none": 5
        }
        
        priority_score = (
            severity_weight.get(vuln.get("severity", "info"), 10) +
            confidence_weight +
            context_weight.get(vuln.get("context", "none"), 5)
        )
        
        prioritized.append({
            "vulnerability": vuln,
            "priority_score": priority_score,
            "urgency": determine_urgency(priority_score),
            "estimated_effort": estimate_remediation_effort(vuln),
            "business_impact": assess_business_impact(vuln)
        })
    
    # Sort by priority score (highest first)
    prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
    
    return prioritized[:5]  # Top 5 priorities


def determine_urgency(priority_score: float) -> str:
    """Determine urgency level based on priority score"""
    if priority_score >= 120:
        return "IMMEDIATE"
    elif priority_score >= 90:
        return "HIGH"
    elif priority_score >= 60:
        return "MEDIUM"
    else:
        return "LOW"


def estimate_remediation_effort(vuln: Dict[str, Any]) -> str:
    """Estimate remediation effort"""
    context = vuln.get("context", "none")
    xss_type = vuln.get("xss_type", "unknown")
    
    # DOM-based XSS requires more effort
    if xss_type == "dom_based":
        return "HIGH"
    elif context in ["javascript", "html_attribute"]:
        return "MEDIUM"
    else:
        return "LOW"


def assess_business_impact(vuln: Dict[str, Any]) -> str:
    """Assess business impact"""
    severity = vuln.get("severity", "info")
    context = vuln.get("context", "none")
    
    if severity == "critical" or context == "javascript":
        return "CRITICAL"
    elif severity == "high":
        return "HIGH"
    elif severity == "medium":
        return "MEDIUM"
    else:
        return "LOW"


def generate_security_recommendations(vulnerabilities: List[Dict[str, Any]]) -> List[str]:
    """Generate AI-powered security recommendations"""
    recommendations = []
    
    if not vulnerabilities:
        recommendations.append("Continue following secure coding practices and regular security testing.")
        return recommendations
    
    # Analyze common patterns and generate specific recommendations
    contexts = [v.get("context", "none") for v in vulnerabilities]
    xss_types = [v.get("xss_type", "unknown") for v in vulnerabilities]
    
    # Content Security Policy recommendations
    if "javascript" in contexts or "dom_based" in xss_types:
        recommendations.append("Implement strict Content Security Policy (CSP) to prevent JavaScript execution in untrusted contexts.")
    
    # Input validation recommendations
    if "html_attribute" in contexts:
        recommendations.append("Implement strict input validation and output encoding for HTML attributes.")
    
    # Framework-specific recommendations
    if len(vulnerabilities) > 3:
        recommendations.append("Consider using established security frameworks like OWASP Java Encoder, ESAPI, or framework-specific encoding functions.")
    
    # WAF recommendations
    high_confidence_count = sum(1 for v in vulnerabilities if v.get("confidence", 0) >= 0.8)
    if high_confidence_count >= 2:
        recommendations.append("Deploy and configure a Web Application Firewall (WAF) with XSS protection rules.")
    
    # DOM-specific recommendations
    if "dom_based" in xss_types:
        recommendations.append("Review client-side JavaScript for DOM manipulation vulnerabilities and implement safe DOM handling practices.")
    
    # General recommendations
    recommendations.extend([
        "Implement secure coding guidelines and regular code reviews focusing on XSS prevention.",
        "Set up automated security testing in CI/CD pipeline for early detection.",
        "Provide security training for developers on XSS prevention techniques."
    ])
    
    return list(set(recommendations))  # Remove duplicates


def generate_ai_summary(vulnerabilities: List[Dict[str, Any]], risk_assessment: str) -> str:
    """Generate AI-powered summary"""
    if not vulnerabilities:
        return "AI analysis confirms no XSS vulnerabilities were detected. The application demonstrates good security practices against XSS attacks."
    
    critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
    high_count = sum(1 for v in vulnerabilities if v.get("severity") == "high")
    exec_verified_count = sum(1 for v in vulnerabilities if v.get("execution_verified", False))
    
    if risk_assessment == "CRITICAL":
        return f"AI analysis indicates CRITICAL XSS risk with {len(vulnerabilities)} total vectors ({critical_count} critical, {high_count} high). {exec_verified_count} vectors verified as executable. Immediate remediation required to prevent potential data theft and session hijacking."
    elif risk_assessment == "HIGH":
        return f"AI analysis identifies HIGH XSS risk with {len(vulnerabilities)} vulnerability vectors ({critical_count} critical, {high_count} high). {exec_verified_count} vectors confirmed executable. Prompt action needed to secure user input handling."
    elif risk_assessment == "MEDIUM":
        return f"AI analysis shows MODERATE XSS risk with {len(vulnerabilities)} potential vectors. {exec_verified_count} vectors verified. Systematic remediation recommended to improve security posture."
    else:
        return f"AI analysis indicates LOW XSS risk with {len(vulnerabilities)} minor issues. {exec_verified_count} vectors verified. Focus on hardening input validation and implementing CSP for enhanced protection."


def analyze_all_vulnerability_types(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Comprehensive analysis of all vulnerability types"""
    vuln_types = {}
    severity_distribution = {}
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get("vulnerability_type", "unknown")
        severity = vuln.get("severity", "info")
        
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
    
    # Type-specific analysis
    xss_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "xss"]
    sql_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "sql_injection"]
    header_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "headers"]
    ssl_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "ssl_tls"]
    csrf_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "csrf"]
    redirect_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == "open_redirect"]
    
    return {
        "type_distribution": vuln_types,
        "severity_distribution": severity_distribution,
        "xss_analysis": {
            "count": len(xss_vulns),
            "types": list(set([v.get("xss_type", "unknown") for v in xss_vulns])),
            "contexts": list(set([v.get("context", "unknown") for v in xss_vulns])),
            "execution_verified": sum(1 for v in xss_vulns if v.get("execution_verified", False))
        },
        "sql_injection_analysis": {
            "count": len(sql_vulns),
            "confidence_levels": [v.get("confidence", 0) for v in sql_vulns]
        },
        "headers_analysis": {
            "count": len(header_vulns),
            "missing_headers": [v.get("evidence", []) for v in header_vulns if v.get("evidence")]
        },
        "ssl_analysis": {
            "count": len(ssl_vulns),
            "certificate_issues": [v.get("evidence", []) for v in ssl_vulns if v.get("evidence")]
        },
        "csrf_analysis": {
            "count": len(csrf_vulns),
            "token_missing": sum(1 for v in csrf_vulns if "token" in str(v.get("evidence", "")).lower())
        },
        "redirect_analysis": {
            "count": len(redirect_vulns),
            "open_redirects": len(redirect_vulns)
        }
    }


def analyze_false_positives_comprehensive(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Comprehensive false positive analysis for all vulnerability types"""
    false_positives = []
    
    for vuln in vulnerabilities:
        confidence = vuln.get("confidence", 0)
        vuln_type = vuln.get("vulnerability_type", "unknown")
        
        # Low confidence vulnerabilities are potential false positives
        if confidence < 0.6:
            false_positives.append({
                "vulnerability_id": vuln.get("id", "unknown"),
                "type": vuln_type,
                "reason": "Low confidence score indicates potential false positive",
                "confidence": confidence,
                "recommendation": "Manual verification recommended"
            })
        
        # Type-specific false positive analysis
        if vuln_type == "xss":
            # XSS-specific false positive checks
            evidence = vuln.get("evidence", [])
            is_encoded = vuln.get("is_encoded", False)
            
            if is_encoded and confidence < 0.7:
                false_positives.append({
                    "vulnerability_id": vuln.get("id", "unknown"),
                    "type": vuln_type,
                    "reason": "XSS payload appears HTML-encoded (safe)",
                    "confidence": confidence,
                    "recommendation": "Verify if encoding defeats XSS"
                })
        
        elif vuln_type == "headers":
            # Headers-specific false positives
            evidence = vuln.get("evidence", [])
            if isinstance(evidence, list) and not evidence:
                false_positives.append({
                    "vulnerability_id": vuln.get("id", "unknown"),
                    "type": vuln_type,
                    "reason": "No specific missing security headers identified",
                    "confidence": confidence,
                    "recommendation": "Manual header verification needed"
                })
        
        elif vuln_type == "sql_injection":
            # SQL injection false positives
            evidence = vuln.get("evidence", [])
            if isinstance(evidence, str) and "error" in evidence.lower():
                false_positives.append({
                    "vulnerability_id": vuln.get("id", "unknown"),
                    "type": vuln_type,
                    "reason": "Based on generic error messages, may be false positive",
                    "confidence": confidence,
                    "recommendation": "Manual SQL injection testing required"
                })
    
    return false_positives


def analyze_attack_surface_comprehensive(vulnerabilities: List[Dict[str, Any]], vulnerability_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive attack surface analysis"""
    total_vectors = len(vulnerabilities)
    high_risk_vectors = 0
    critical_vuln_types = []
    
    vuln_types = vulnerability_analysis.get("type_distribution", {})
    severity_dist = vulnerability_analysis.get("severity_distribution", {})
    
    # Count high risk vectors
    for vuln in vulnerabilities:
        if vuln.get("severity") in ["critical", "high"] and vuln.get("confidence", 0) >= 0.7:
            high_risk_vectors += 1
    
    # Identify critical vulnerability types
    critical_type_thresholds = {
        "sql_injection": 1,  # Any SQL injection is critical
        "xss": 2,           # 2+ XSS findings is critical
        "csrf": 1,           # CSRF is critical
        "ssl_tls": 1,        # SSL issues are critical
    }
    
    for vuln_type, threshold in critical_type_thresholds.items():
        if vuln_types.get(vuln_type, 0) >= threshold:
            critical_vuln_types.append(vuln_type)
    
    # Determine most critical type
    most_critical_type = None
    if vuln_types:
        risk_scores = {
            "sql_injection": 10,
            "xss": 9,
            "csrf": 8,
            "ssl_tls": 8,
            "open_redirect": 6,
            "headers": 4
        }
        most_critical_type = max(vuln_types.keys(), key=lambda x: risk_scores.get(x, 0) * vuln_types.get(x, 0))
    
    return {
        "total_vectors": total_vectors,
        "high_risk_vectors": high_risk_vectors,
        "vulnerability_distribution": vuln_types,
        "severity_distribution": severity_dist,
        "critical_vulnerability_types": critical_vuln_types,
        "most_critical_type": most_critical_type,
        "attack_complexity": assess_attack_complexity(vulnerabilities),
        "exploitability": assess_exploitability(vulnerabilities)
    }


def assess_attack_complexity(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Assess overall attack complexity"""
    if not vulnerabilities:
        return "NONE"
    
    # Simple complexity scoring
    complexity_score = 0
    for vuln in vulnerabilities:
        vuln_type = vuln.get("vulnerability_type", "unknown")
        confidence = vuln.get("confidence", 0)
        
        if vuln_type in ["sql_injection", "xss"]:
            complexity_score += confidence * 3
        elif vuln_type in ["csrf", "open_redirect"]:
            complexity_score += confidence * 2
        else:
            complexity_score += confidence
    
    if complexity_score >= 15:
        return "HIGH"
    elif complexity_score >= 8:
        return "MEDIUM"
    else:
        return "LOW"


def assess_exploitability(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Assess exploitability of vulnerabilities"""
    if not vulnerabilities:
        return "NONE"
    
    exploitability_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info")
        confidence = vuln.get("confidence", 0)
        
        severity_weight = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0.5
        }
        
        exploitability_score += severity_weight.get(severity, 0.5) * confidence
    
    if exploitability_score >= 10:
        return "HIGH"
    elif exploitability_score >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def assess_overall_risk_comprehensive(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Comprehensive risk assessment for all vulnerability types"""
    if not vulnerabilities:
        return "LOW"
    
    # Calculate comprehensive risk score
    risk_score = 0
    for vuln in vulnerabilities:
        vuln_type = vuln.get("vulnerability_type", "unknown")
        severity = vuln.get("severity", "info")
        confidence = vuln.get("confidence", 0)
        
        # Type-specific severity multipliers
        severity_multiplier = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 2,
            "info": 1
        }
        
        # Type-specific risk multipliers
        type_multiplier = {
            "sql_injection": 2.0,   # Very dangerous
            "xss": 1.8,           # Can steal sessions
            "csrf": 1.5,           # Cross-site attacks
            "ssl_tls": 1.6,        # Transport security
            "open_redirect": 1.2,   # Phishing risk
            "headers": 1.0          # Information disclosure
        }
        
        vuln_risk = (
            severity_multiplier.get(severity, 1) * 
            confidence * 
            type_multiplier.get(vuln_type, 1.0)
        )
        risk_score += vuln_risk
    
    # Determine overall risk
    if risk_score >= 25:
        return "CRITICAL"
    elif risk_score >= 15:
        return "HIGH"
    elif risk_score >= 8:
        return "MEDIUM"
    elif risk_score >= 3:
        return "LOW"
    else:
        return "INFO"


def prioritize_remediation_comprehensive(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Comprehensive remediation prioritization"""
    prioritized = []
    
    for vuln in vulnerabilities:
        # Calculate comprehensive priority score
        severity_weight = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        
        # Type-specific priority multipliers
        type_priority = {
            "sql_injection": 1.5,   # Database compromise
            "xss": 1.4,             # Client-side attacks
            "csrf": 1.3,             # Action forgery
            "ssl_tls": 1.35,         # Transport security
            "open_redirect": 1.1,     # Phishing risk
            "headers": 1.0            # Information disclosure
        }
        
        confidence_weight = vuln.get("confidence", 0) * 20
        
        priority_score = (
            severity_weight.get(vuln.get("severity", "info"), 10) *
            type_priority.get(vuln.get("vulnerability_type", "headers"), 1.0) +
            confidence_weight
        )
        
        prioritized.append({
            "vulnerability": vuln,
            "priority_score": priority_score,
            "urgency": determine_urgency_comprehensive(priority_score),
            "estimated_effort": estimate_remediation_effort_comprehensive(vuln),
            "business_impact": assess_business_impact_comprehensive(vuln),
            "affected_components": identify_affected_components(vuln)
        })
    
    # Sort by priority score (highest first)
    prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
    
    return prioritized[:10]  # Top 10 priorities


def determine_urgency_comprehensive(priority_score: float) -> str:
    """Determine urgency level based on comprehensive priority"""
    if priority_score >= 150:
        return "IMMEDIATE"
    elif priority_score >= 100:
        return "HIGH"
    elif priority_score >= 60:
        return "MEDIUM"
    else:
        return "LOW"


def estimate_remediation_effort_comprehensive(vuln: Dict[str, Any]) -> str:
    """Estimate remediation effort for different vulnerability types"""
    vuln_type = vuln.get("vulnerability_type", "unknown")
    
    effort_levels = {
        "sql_injection": "HIGH",      # Requires code changes, database review
        "xss": "MEDIUM",             # Input validation, output encoding
        "csrf": "MEDIUM",             # Token implementation
        "ssl_tls": "HIGH",            # Certificate, server configuration
        "open_redirect": "LOW",        # URL validation
        "headers": "LOW"              # Configuration changes
    }
    
    return effort_levels.get(vuln_type, "MEDIUM")


def assess_business_impact_comprehensive(vuln: Dict[str, Any]) -> str:
    """Assess business impact for different vulnerability types"""
    vuln_type = vuln.get("vulnerability_type", "unknown")
    severity = vuln.get("severity", "info")
    
    # Type-specific impact
    type_impact = {
        "sql_injection": "CRITICAL",   # Data breach
        "xss": "HIGH",               # Session hijacking
        "csrf": "HIGH",               # Unauthorized actions
        "ssl_tls": "HIGH",            # Data in transit risk
        "open_redirect": "MEDIUM",     # Phishing risk
        "headers": "LOW"              # Information disclosure
    }
    
    base_impact = type_impact.get(vuln_type, "MEDIUM")
    
    # Adjust based on severity
    if severity == "critical":
        return "CRITICAL"
    elif severity == "high" and base_impact != "CRITICAL":
        return "HIGH"
    elif severity == "medium" and base_impact == "LOW":
        return "MEDIUM"
    else:
        return base_impact


def identify_affected_components(vuln: Dict[str, Any]) -> List[str]:
    """Identify affected components based on vulnerability type and evidence"""
    vuln_type = vuln.get("vulnerability_type", "unknown")
    evidence = vuln.get("evidence", [])
    
    components = []
    
    # Type-specific component mapping
    if vuln_type == "xss":
        if isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, dict):
                    if item.get("parameter"):
                        components.append(f"URL Parameter: {item.get('parameter')}")
                    if item.get("field_name"):
                        components.append(f"Form Field: {item.get('field_name')}")
        components.append("Client-side JavaScript")
    
    elif vuln_type == "sql_injection":
        components.append("Database Layer")
        components.append("Input Validation")
        components.append("ORM/Database Access Layer")
    
    elif vuln_type == "csrf":
        components.append("Authentication/Authorization")
        components.append("Form Processing")
        components.append("Session Management")
    
    elif vuln_type == "ssl_tls":
        components.append("Network Layer")
        components.append("Web Server Configuration")
        components.append("Certificate Management")
    
    elif vuln_type == "open_redirect":
        components.append("URL Redirection")
        components.append("Input Validation")
    
    elif vuln_type == "headers":
        components.append("HTTP Response Headers")
        components.append("Web Server Configuration")
    
    return list(set(components))  # Remove duplicates


def generate_security_recommendations_comprehensive(vulnerabilities: List[Dict[str, Any]], vulnerability_analysis: Dict[str, Any]) -> List[str]:
    """Generate comprehensive security recommendations"""
    recommendations = []
    vuln_types = vulnerability_analysis.get("type_distribution", {})
    
    if not vulnerabilities:
        recommendations.append("Continue following secure coding practices and regular security testing.")
        return recommendations
    
    # Type-specific recommendations
    if vuln_types.get("sql_injection", 0) > 0:
        recommendations.extend([
            "Implement parameterized queries/prepared statements to prevent SQL injection.",
            "Use ORM frameworks with built-in SQL injection protection.",
            "Perform input validation and output encoding for all database operations."
        ])
    
    if vuln_types.get("xss", 0) > 0:
        xss_analysis = vulnerability_analysis.get("xss_analysis", {})
        if xss_analysis.get("execution_verified", 0) > 0:
            recommendations.append("Implement strict Content Security Policy (CSP) to prevent XSS execution.")
        recommendations.extend([
            "Implement output encoding based on context (HTML, JavaScript, CSS).",
            "Use security-focused templating engines with auto-escaping.",
            "Sanitize user input using established security libraries."
        ])
    
    if vuln_types.get("csrf", 0) > 0:
        recommendations.extend([
            "Implement anti-CSRF tokens for all state-changing operations.",
            "Validate referer headers and origin headers.",
            "Use SameSite cookies for additional CSRF protection."
        ])
    
    if vuln_types.get("ssl_tls", 0) > 0:
        recommendations.extend([
            "Update SSL/TLS configuration to use modern secure protocols (TLS 1.2+).",
            "Implement proper certificate management and monitoring.",
            "Disable weak ciphers and outdated SSL/TLS versions."
        ])
    
    if vuln_types.get("open_redirect", 0) > 0:
        recommendations.extend([
            "Validate all redirect URLs against allowlist of safe destinations.",
            "Avoid using user input directly in redirect operations.",
            "Implement safe URL parsing and validation mechanisms."
        ])
    
    if vuln_types.get("headers", 0) > 0:
        headers_analysis = vulnerability_analysis.get("headers_analysis", {})
        recommendations.extend([
            "Implement comprehensive security headers (CSP, HSTS, X-Frame-Options, etc.).",
            "Regularly review and update web server security configuration.",
            "Use security headers scanning tools to verify proper implementation."
        ])
    
    # General recommendations
    if len(vulnerabilities) > 5:
        recommendations.append("Consider implementing Web Application Firewall (WAF) for additional protection.")
    
    recommendations.extend([
        "Implement secure software development lifecycle (SSDLC) practices.",
        "Set up automated security testing in CI/CD pipeline.",
        "Provide regular security training for development team.",
        "Conduct periodic penetration testing and security audits.",
        "Establish incident response procedures for security breaches."
    ])
    
    return list(set(recommendations))  # Remove duplicates


def generate_ai_summary_comprehensive(vulnerabilities: List[Dict[str, Any]], risk_assessment: str, vulnerability_analysis: Dict[str, Any]) -> str:
    """Generate comprehensive AI-powered summary"""
    if not vulnerabilities:
        return "AI analysis confirms no vulnerabilities were detected. The application demonstrates strong security posture across all tested categories."
    
    vuln_types = vulnerability_analysis.get("type_distribution", {})
    severity_dist = vulnerability_analysis.get("severity_distribution", {})
    critical_count = severity_dist.get("critical", 0)
    high_count = severity_dist.get("high", 0)
    
    # Identify most concerning issues
    critical_types = [v_type for v_type, count in vuln_types.items() 
                     if v_type in ["sql_injection", "xss", "csrf"] and count > 0]
    
    if risk_assessment == "CRITICAL":
        return f"AI analysis indicates CRITICAL security risk with {len(vulnerabilities)} vulnerabilities across {len(vuln_types)} categories. Critical issues: {critical_count} critical, {high_count} high severity. Primary concerns: {', '.join(critical_types)}. Immediate comprehensive remediation required to prevent data breach and system compromise."
    elif risk_assessment == "HIGH":
        return f"AI analysis identifies HIGH security risk with {len(vulnerabilities)} vulnerabilities ({len(vuln_types)} categories). High severity: {high_count}. Main concerns: {', '.join(critical_types)}. Prompt remediation needed to address significant security gaps."
    elif risk_assessment == "MEDIUM":
        return f"AI analysis shows MODERATE security risk with {len(vulnerabilities)} vulnerabilities across {len(vuln_types)} categories. Systematic security improvements recommended to reduce attack surface and strengthen defenses."
    else:
        return f"AI analysis indicates LOW security risk with {len(vulnerabilities)} minor issues. Focus on implementing security best practices and continuous monitoring to maintain security posture."
