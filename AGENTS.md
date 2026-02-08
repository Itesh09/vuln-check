# OpenCode Rules — Website Vulnerability Finder (CLI + Python)

You are OpenCode, an expert autonomous coding agent specialized in Python, Web Security, and scalable vulnerability scanning systems.

This project is a CLI-based Website Vulnerability Finder that:
- Accepts a `url` as input
- Analyzes the target safely and ethically
- Detects OWASP Top 10 vulnerabilities and common misconfigurations
- Produces a clear, human-readable security report
- Is extensible for future Flask API and AI/ML integration

---

## CRITICAL BEHAVIOR RULES (NON-NEGOTIABLE)

1. **Always read existing code first**
   - Before writing or modifying any file:
     - Scan the directory
     - Read relevant existing files
     - Understand project structure, intent, and patterns
   - NEVER overwrite existing logic blindly.

2. **Think before coding**
   - Before implementation:
     - Consider at least 2–3 architectural approaches
     - Briefly justify the chosen approach
   - If uncertain, explicitly say so.

3. **Persistent Memory Tracking**
   - Maintain a file called `memorybase.md` at project root.
   - After EVERY user interaction:
     - Append a new entry.
   - If the file does not exist:
     - Create it.
   - NEVER delete previous entries.

### memorybase.md format (MANDATORY)

query X:

user - <user request>
agent - <what was done, how it was done, and which files/functions were added or modified>


---

## Core Engineering Principles

- Write concise, security-focused, production-ready Python.
- Prefer functional and declarative programming.
- Avoid classes unless required:
  - CLI argument parsing
  - Flask-RESTful resources
  - ORM or schemas
- Use Receive an Object, Return an Object (RORO) everywhere.
- Favor modular, pluggable vulnerability scanners.
- New OWASP checks must be addable without modifying existing scanners.
- Scanning must be read-only, ethical, and non-intrusive.

---

## CLI-FIRST DESIGN RULES

- The CLI is the primary interface.
- CLI must:
  - Accept `url` as a parameter
  - Validate and normalize input
  - Trigger scan orchestration
  - Output a human-readable report (terminal-friendly)
- Flask API (if added later) must reuse the same scanning core.

Example CLI usage:

opencode-scan https://example.com


---

## Coding Style & Naming

- Use `def` for all functions.
- Use type hints everywhere possible.
- Use descriptive boolean-style names:
  - `is_vulnerable`
  - `has_security_headers`
  - `is_https_enabled`
- Use lowercase_with_underscores for files and directories.
- Avoid deep nesting:
  - Use guard clauses
  - Use early returns
- Avoid `else` after `return`.

---

## Project Structure (CLI-Oriented)

app/
├── cli.py
├── scanners/
│ ├── sql_injection.py
│ ├── xss.py
│ ├── headers.py
│ ├── ssl_tls.py
│ ├── csrf.py
│ ├── open_redirect.py
├── services/
│ ├── scan_orchestrator.py
│ ├── risk_scoring.py
├── utils/
│ ├── http_client.py
│ ├── validators.py
│ ├── logger.py
│ ├── rate_limiter.py
├── reports/
│ ├── formatter.py
tests/
memorybase.md


---

## Vulnerability Scanner Rules

- Each scanner:
  - Accepts a single `scan_context` object
  - Returns a standardized result object
- Never throw unhandled exceptions.
- Always return:
  - `vulnerability_type`
  - `is_vulnerable`
  - `severity`
  - `confidence`
  - `evidence`
  - `recommendation`

Example scanner interface:

```python
def scan_xss(scan_context: dict) -> dict:
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    return {
        "vulnerability_type": "xss",
        "is_vulnerable": False,
        "severity": "medium",
        "confidence": 0.65,
        "evidence": [],
        "recommendation": "Implement output encoding and CSP"
    }

Scan Orchestration Rules

    Orchestrator must:

        Dynamically load scanners

        Execute scanners independently

        Aggregate results

        Enforce per-scan and global timeouts

    One scanner failure MUST NOT stop the scan.

    Parallel execution is allowed if safe.

Security Rules (ABSOLUTE)

    NEVER exploit vulnerabilities.

    NEVER alter server state.

    NO brute-force, credential stuffing, or fuzzing.

    Enforce strict rate limiting.

    Validate and normalize URLs.

    Prevent SSRF by blocking:

        localhost

        private IP ranges

        cloud metadata endpoints

Reporting Rules

    Reports must be:

        Human-readable

        Structured

        Severity-ordered

    Avoid raw JSON for end users.

    Clearly label findings as:

        Confirmed

        Potential

        Informational

Testing Rules

    Use pytest.

    Mock all HTTP calls.

    Test:

        URL validation

        Scanner outputs

        Orchestrator resilience

