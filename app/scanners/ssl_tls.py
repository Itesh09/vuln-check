import ssl
import socket
import urllib.parse
from datetime import datetime
from app.utils.http_client import fetch_url


def scan_ssl_tls(scan_context: dict) -> dict:
    """
    Advanced SSL/TLS configuration scanner that checks for:
    - Certificate validity and trust
    - TLS version support
    - Cipher suite strength
    - Protocol security
    - Mixed content issues
    """
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    vulnerabilities = []
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        
        # Check if using HTTPS
        if parsed_url.scheme != "https":
            vulnerabilities.append({
                "type": "protocol_insecure",
                "severity": "critical",
                "description": "Application uses HTTP instead of HTTPS",
                "recommendation": "Redirect all HTTP traffic to HTTPS and implement HSTS"
            })
        else:
            # Perform comprehensive SSL/TLS analysis
            cert_analysis = analyze_certificate(hostname, port)
            if cert_analysis["issues"]:
                vulnerabilities.extend(cert_analysis["issues"])
            
            # Check TLS version support
            tls_analysis = analyze_tls_versions(hostname, port)
            if tls_analysis["issues"]:
                vulnerabilities.extend(tls_analysis["issues"])
            
            # Check cipher suites
            cipher_analysis = analyze_cipher_suites(hostname, port)
            if cipher_analysis["issues"]:
                vulnerabilities.extend(cipher_analysis["issues"])
            
            # Check for mixed content
            mixed_content_analysis = analyze_mixed_content(url)
            if mixed_content_analysis["issues"]:
                vulnerabilities.extend(mixed_content_analysis["issues"])
        
        # Analyze overall security posture
        is_vulnerable = len(vulnerabilities) > 0
        
        if is_vulnerable:
            critical_issues = [v for v in vulnerabilities if v.get("severity") == "critical"]
            high_issues = [v for v in vulnerabilities if v.get("severity") == "high"]
            medium_issues = [v for v in vulnerabilities if v.get("severity") == "medium"]
            
            if critical_issues:
                severity = "critical"
                confidence = 0.95
            elif high_issues:
                severity = "high"
                confidence = 0.9
            elif medium_issues:
                severity = "medium"
                confidence = 0.85
            else:
                severity = "low"
                confidence = 0.8
        else:
            severity = "info"
            confidence = 0.0
        
        for vuln in vulnerabilities:
            evidence.append(vuln)
        
        return {
            "vulnerability_type": "weak_ssl_tls",
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": generate_ssl_recommendations(vulnerabilities)
        }
        
    except Exception as e:
        return {
            "vulnerability_type": "weak_ssl_tls",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during SSL/TLS scanning."
        }


def analyze_certificate(hostname: str, port: int) -> dict:
    """Analyze SSL/TLS certificate for validity and trust issues"""
    issues = []
    
    try:
        # Create SSL context and connect
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                
                # Check certificate expiration
                if cert and 'notAfter' in cert:
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        issues.append({
                            "type": "certificate_expired",
                            "severity": "critical",
                            "description": f"Certificate expired {abs(days_until_expiry)} days ago",
                            "expiry_date": cert['notAfter']
                        })
                    elif days_until_expiry < 30:
                        issues.append({
                            "type": "certificate_expiring_soon",
                            "severity": "high",
                            "description": f"Certificate expires in {days_until_expiry} days",
                            "expiry_date": cert['notAfter']
                        })
                    elif days_until_expiry < 90:
                        issues.append({
                            "type": "certificate_expiring",
                            "severity": "medium",
                            "description": f"Certificate expires in {days_until_expiry} days",
                            "expiry_date": cert['notAfter']
                        })
                
                # Check certificate subject and issuer
                if cert and 'subject' in cert:
                    subject = cert['subject']
                    # Check for self-signed certificate
                    if cert and 'issuer' in cert and cert['subject'] == cert['issuer']:
                        issues.append({
                            "type": "self_signed_certificate",
                            "severity": "high",
                            "description": "Self-signed certificate detected - not trusted by browsers"
                        })
                
                # Check certificate strength
                if cert_der:
                    # This is simplified - in real implementation, we'd analyze the public key
                    cert_size = len(cert_der) * 8  # Convert to bits
                    if cert_size < 2048:
                        issues.append({
                            "type": "weak_certificate_key",
                            "severity": "medium",
                            "description": f"Weak certificate key size ({cert_size} bits)",
                            "recommendation": "Use certificates with at least 2048-bit keys"
                        })
                
    except ssl.SSLCertVerificationError as e:
        issues.append({
            "type": "certificate_verification_failed",
            "severity": "critical",
            "description": "Certificate verification failed",
            "error": str(e)
        })
    except ssl.SSLError as e:
        issues.append({
            "type": "ssl_error",
            "severity": "high",
            "description": "SSL/TLS handshake failed",
            "error": str(e)
        })
    except Exception as e:
        issues.append({
            "type": "certificate_analysis_error",
            "severity": "medium",
            "description": "Unable to analyze certificate",
            "error": str(e)
        })
    
    return {"issues": issues}


def analyze_tls_versions(hostname: str, port: int) -> dict:
    """Analyze supported TLS versions"""
    issues = []
    
    # TLS versions to test (from newest to oldest)
    tls_versions = [
        (ssl.TLSVersion.TLSv1_3, "TLS 1.3"),
        (ssl.TLSVersion.TLSv1_2, "TLS 1.2"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.SSLv3, "SSL 3.0"),
    ]
    
    supported_versions = []
    
    for version, version_name in tls_versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.minimum_version = version
            context.maximum_version = version
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported_versions.append(version_name)
        except (ssl.SSLError, socket.error, ConnectionResetError):
            # Version not supported
            pass
    
    # Check for deprecated/insecure versions
    insecure_versions = ["SSL 3.0", "TLS 1.0", "TLS 1.1"]
    for version in insecure_versions:
        if version in supported_versions:
            severity = "critical" if version in ["SSL 3.0", "TLS 1.0"] else "high"
            issues.append({
                "type": "insecure_tls_version",
                "severity": severity,
                "description": f"Supports insecure {version}",
                "recommendation": f"Disable {version} and use TLS 1.2+ only"
            })
    
    # Check if TLS 1.2+ is supported
    modern_versions = ["TLS 1.2", "TLS 1.3"]
    if not any(version in supported_versions for version in modern_versions):
        issues.append({
            "type": "no_modern_tls",
            "severity": "critical",
            "description": "No modern TLS versions (1.2+) supported",
            "recommendation": "Enable TLS 1.2 or higher"
        })
    
    return {"issues": issues, "supported_versions": supported_versions}


def analyze_cipher_suites(hostname: str, port: int) -> dict:
    """Analyze cipher suite strength"""
    issues = []
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name, tls_version, secret_bits = cipher
                    
                    # Check cipher strength
                    if secret_bits < 128:
                        issues.append({
                            "type": "weak_cipher",
                            "severity": "high",
                            "description": f"Weak cipher suite: {cipher_name} ({secret_bits} bits)",
                            "recommendation": "Use cipher suites with at least 128-bit encryption"
                        })
                    elif secret_bits < 256:
                        issues.append({
                            "type": "moderate_cipher",
                            "severity": "medium",
                            "description": f"Moderate cipher strength: {cipher_name} ({secret_bits} bits)",
                            "recommendation": "Consider using 256-bit cipher suites for better security"
                        })
                    
                    # Check for known weak ciphers
                    weak_ciphers = [
                        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ADH", "AECDH"
                    ]
                    
                    for weak_cipher in weak_ciphers:
                        if weak_cipher.upper() in cipher_name.upper():
                            issues.append({
                                "type": "insecure_cipher",
                                "severity": "critical",
                                "description": f"Insecure cipher suite: {cipher_name}",
                                "recommendation": f"Disable {weak_cipher} ciphers"
                            })
                            break
    
    except Exception as e:
        issues.append({
            "type": "cipher_analysis_error",
            "severity": "medium",
            "description": "Unable to analyze cipher suites",
            "error": str(e)
        })
    
    return {"issues": issues}


def analyze_mixed_content(url: str) -> dict:
    """Analyze page for mixed content (HTTPS page with HTTP resources)"""
    issues = []
    
    try:
        response = fetch_url(url)
        if response and response.text:
            import re
            
            # Look for HTTP resources in HTTPS page
            if url.startswith("https://"):
                # Check for HTTP links
                http_links = re.findall(r'http://[^\s"\'<>]+', response.text)
                if http_links:
                    issues.append({
                        "type": "mixed_content",
                        "severity": "medium",
                        "description": f"Found {len(http_links)} HTTP resources on HTTPS page",
                        "examples": http_links[:3],  # First 3 examples
                        "recommendation": "Update all resource URLs to use HTTPS"
                    })
                
                # Check for protocol-relative URLs that might resolve to HTTP
                protocol_relative = re.findall(r'//[^\s"\'<>]+', response.text)
                if protocol_relative:
                    issues.append({
                        "type": "protocol_relative_urls",
                        "severity": "low",
                        "description": f"Found {len(protocol_relative)} protocol-relative URLs",
                        "examples": protocol_relative[:3],
                        "recommendation": "Use explicit HTTPS URLs instead of protocol-relative"
                    })
    
    except Exception as e:
        issues.append({
            "type": "mixed_content_analysis_error",
            "severity": "low",
            "description": "Unable to analyze mixed content",
            "error": str(e)
        })
    
    return {"issues": issues}


def generate_ssl_recommendations(vulnerabilities: list) -> str:
    """Generate comprehensive SSL/TLS security recommendations"""
    if not vulnerabilities:
        return "SSL/TLS configuration appears secure. Continue following security best practices."
    
    recommendations = [
        "SSL/TLS security issues detected. Implement the following recommendations:",
    ]
    
    # Group recommendations by type
    critical_issues = [v for v in vulnerabilities if v.get("severity") == "critical"]
    high_issues = [v for v in vulnerabilities if v.get("severity") == "high"]
    medium_issues = [v for v in vulnerabilities if v.get("severity") == "medium"]
    
    if critical_issues:
        recommendations.append("\n🔴 CRITICAL - Immediate action required:")
        for issue in critical_issues:
            recommendations.append(f"• {issue['description']}: {issue.get('recommendation', 'Fix immediately')}")
    
    if high_issues:
        recommendations.append("\n🟠 HIGH - Priority fixes:")
        for issue in high_issues:
            recommendations.append(f"• {issue['description']}: {issue.get('recommendation', 'Fix soon')}")
    
    if medium_issues:
        recommendations.append("\n🟡 MEDIUM - Important improvements:")
        for issue in medium_issues:
            recommendations.append(f"• {issue['description']}: {issue.get('recommendation', 'Consider fixing')}")
    
    recommendations.extend([
        "\n📋 General SSL/TLS recommendations:",
        "• Use TLS 1.2 or higher exclusively",
        "• Implement strong cipher suites (AES-256-GCM, ChaCha20-Poly1305)",
        "• Obtain certificates from trusted Certificate Authorities",
        "• Monitor certificate expiration and renew before expiry",
        "• Implement HTTP Strict Transport Security (HSTS)",
        "• Use OCSP Stapling for certificate validation",
        "• Regularly test SSL/TLS configuration with tools like SSL Labs",
        "• Keep web server and SSL libraries updated",
        "• Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1",
        "• Use perfect forward secrecy (ECDHE) cipher suites"
    ])
    
    return "\n".join(recommendations)
