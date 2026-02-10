# 🛡️ VulnCheck - Advanced Web Vulnerability Scanner

A comprehensive vulnerability scanning tool that detects OWASP Top 10 security issues with AI-powered analysis and intelligent payload selection.

## ✨ Features

### 🔍 Multi-Vulnerability Detection
- **XSS Scanner**: Context-aware 2026 XSS payloads with execution verification
- **SQL Injection Scanner**: Union-based, Boolean-blind, Time-based, Error-based detection
- **Security Headers Scanner**: 10+ critical HTTP headers analysis
- **SSL/TLS Scanner**: Certificate validation, TLS version, cipher suite analysis
- **CSRF Scanner**: Form analysis, SameSite cookies, state-changing endpoints
- **Open Redirect Scanner**: URL parameter, form, JavaScript redirect analysis

### 🧠 AI-Powered Analysis
- **Dynamic Risk Assessment**: Type-specific vulnerability scoring
- **False Positive Reduction**: Intelligent filtering and validation
- **Attack Surface Mapping**: Comprehensive vulnerability distribution analysis
- **Priority-Based Remediation**: Business impact and urgency assessment
- **Context-Aware Recommendations**: Security guidance per vulnerability type

### 📊 Comprehensive Reporting
- **Risk Summary**: Overall risk level with severity breakdown
- **Detailed Evidence**: Technical details for each vulnerability
- **Actionable Insights**: Specific remediation recommendations
- **Human-Readable Output**: Terminal-friendly formatted reports

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.8+ required
python --version

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan a single website
python main.py -u https://example.com

# Run Flask API server
python main.py --run-server

# Custom server configuration
python main.py --run-server --host 0.0.0.0 --port 8080
```

### Docker Usage
```bash
# Build Docker image
docker build -t vulncheck .

# Run scan
docker run vulncheck python main.py -u https://example.com

# Run API server
docker run -p 8080:8080 vulncheck python main.py --run-server
```

## 📁 Project Structure

```
vuln-check/
├── main.py                    # CLI entry point
├── requirements.txt             # Python dependencies
├── .gitignore                # Git ignore file
├── README.md                  # This file
└── app/
    ├── __init__.py           # Flask app factory
    ├── scanners/              # Vulnerability scanners
    │   ├── xss.py          # XSS scanner with 2026 payloads
    │   ├── sql_injection.py # SQL injection detection
    │   ├── headers.py        # Security headers analysis
    │   ├── ssl_tls.py       # SSL/TLS configuration scanner
    │   ├── csrf.py          # CSRF vulnerability detection
    │   └── open_redirect.py  # Open redirect detection
    ├── services/              # Business logic layer
    │   ├── scan_orchestrator.py # Scan coordination
    │   ├── risk_scoring.py      # Risk assessment
    │   └── ai_analyzer.py       # AI analysis engine
    ├── utils/                 # Utility functions
    │   ├── http_client.py       # HTTP client with error handling
    │   ├── validators.py        # Input validation
    │   ├── logger.py           # Structured logging
    │   └── rate_limiter.py     # Rate limiting
    └── payloads/              # Vulnerability payloads
        └── xss_payloads.py   # 2026 XSS payload collection
```

## 🔬 Scanner Details

### XSS Scanner
- **2026 Payload Database**: 200+ modern XSS payloads
- **Context-Aware Selection**: Uses payloads based on page structure
- **Execution Verification**: Unique identifiers for confirmation
- **Dynamic Confidence Scoring**: Based on context and encoding
- **XSS Type Classification**: Reflected/Stored/DOM-based detection

### SQL Injection Scanner
- **Injection Types**: Union, Boolean-blind, Time-based, Error-based, Stacked queries
- **Database Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite patterns
- **Parameter Analysis**: URL and form field testing
- **Error Pattern Recognition**: Database-specific error detection

### Security Headers Scanner
- **Critical Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Additional Headers**: Referrer-Policy, Permissions-Policy, X-XSS-Protection
- **Configuration Validation**: Header value analysis and best practices
- **Information Disclosure**: Technology stack detection prevention

### SSL/TLS Scanner
- **Certificate Analysis**: Expiration, trust chain, key strength
- **TLS Version Support**: TLS 1.3, 1.2, legacy version detection
- **Cipher Suite Analysis**: Strength evaluation and weak cipher detection
- **Mixed Content Detection**: HTTP resources on HTTPS pages

### CSRF Scanner
- **Form Analysis**: CSRF token detection in multiple formats
- **Header Protection**: SameSite cookie and Origin/Referer validation
- **State-Changing Detection**: AJAX endpoint analysis for unprotected actions
- **Multi-Layer Protection**: Comprehensive CSRF defense analysis

### Open Redirect Scanner
- **URL Parameter Testing**: Multiple redirect payload types
- **Form-Based Testing**: POST/GET form submission analysis
- **JavaScript Analysis**: Client-side redirect detection
- **Domain Validation**: External vs internal redirect verification

## 🤖 AI Analysis Features

### Risk Assessment
- **Type-Specific Scoring**: Different weights per vulnerability category
- **Confidence Calculation**: Dynamic scoring based on evidence quality
- **Severity Classification**: Critical/High/Medium/Low/Info determination
- **Business Impact Analysis**: Potential damage assessment

### Attack Surface Analysis
- **Vulnerability Distribution**: Breakdown by type and severity
- **Critical Type Identification**: Most concerning vulnerability categories
- **Exploitability Assessment**: Attack complexity and difficulty
- **Component Mapping**: Affected system components

### Remediation Planning
- **Priority Scoring**: Risk-based vulnerability ranking
- **Urgency Classification**: Immediate/High/Medium/Low priority
- **Effort Estimation**: Fix complexity and resource requirements
- **Component-Specific Guidance**: Targeted remediation advice

## 📋 Example Reports



### Vulnerability Found
```
==================================================
SCAN REPORT FOR: https://example.com
Scan ID: c3349e6b-04f6-413a-b368-9a7cacd3acb6
Timestamp: 2026-02-06T08:53:23.930451
==================================================
--- Risk Summary ---
Overall Risk Level: CRITICAL
Total Risk Score: 240.0
Severity Breakdown:
  Critical: 1 findings
  High: 1 findings
Recommendation: Review high and critical vulnerabilities first.
--- Vulnerability Details ---
1. Vulnerability Type: SQL Injection
   Severity: Critical
   Confidence: 0.90
   Evidence: Union-based SQL injection detected in 'id' parameter
   Recommendation: Use parameterized queries/prepared statements.

2. Vulnerability Type: XSS
   Severity: High
   Confidence: 1.00
   Evidence: DOM-based XSS with execution verified
   Recommendation: Implement strict Content Security Policy.
--- AI Insights ---
Summary: AI analysis indicates CRITICAL security risk with multiple vulnerabilities.
==================================================
```

## 🔧 Configuration

### Environment Variables
```bash
# API Server Configuration
export FLASK_ENV=production
export FLASK_PORT=5000
export FLASK_HOST=127.0.0.1

# Scanner Configuration
export VULNCHECK_TIMEOUT=30
export VULNCHECK_RATE_LIMIT=10
export VULNCHECK_CONCURRENT=5
```

### Scan Customization
```python
# Custom configuration can be added to main.py
# Example: Change timeout, add custom headers, modify payload sets
```

## 🛡️ Security Considerations

### Ethical Usage
- **Read-Only**: No data modification or system changes
- **Rate Limiting**: Built-in protection against abuse
- **Safe Scanning**: Non-intrusive vulnerability detection
- **SSRF Prevention**: Private IP and metadata endpoint blocking

### Responsible Disclosure
- **Verification**: Manual confirmation before reporting
- **Impact Assessment**: Business and technical damage evaluation
- **Coordinated Reporting**: Through proper security channels

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone https://github.com/itesh19/vuln-check.git
cd vuln-check

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8
```

### Code Style
- **PEP 8**: Python code formatting
- **Type Hints**: Comprehensive type annotations
- **Documentation**: Docstrings for all functions
- **Testing**: Comprehensive test coverage

### Submitting Changes
1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m "Add feature description"`
4. Push to fork: `git push origin feature-name`
5. Create Pull Request

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP Top 10**: Security framework and testing methodology
- **2026 XSS Cheat Sheet**: Modern payload collection and techniques
- **Python Community**: Security testing libraries and tools
- **Security Researchers**: Vulnerability detection techniques and patterns

## 📞 Support

### Documentation
- [Usage Guide](docs/usage.md)
- [API Documentation](docs/api.md)
- [Development Guide](docs/development.md)

### Issues
- [Bug Reports](https://github.com/itesh19/vuln-check/issues)
- [Feature Requests](https://github.com/yourusername/vuln-check/issues)
- [Security Issues](https://github.com/yourusername/vuln-check/security)

### Community
- [Discussions](https://github.com/yourusername/vuln-check/discussions)
- [Wiki](https://github.com/yourusername/vuln-check/wiki)

---

**🔒 Security First, 🧠 Intelligence-Driven, 🚀 Production-Ready**
