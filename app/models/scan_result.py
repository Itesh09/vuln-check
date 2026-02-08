from typing import Dict, Any, List

# In a more complex application with a database, this would typically be an SQLAlchemy ORM model.
# For now, we define a type hint for clarity and adhere to the "avoid classes unless required" principle.

ScanResult = Dict[str, Any]
"""
Represents a single scan result or a collection of aggregated results.
Expected keys might include:
- 'scan_id': str
- 'target_url': str
- 'timestamp': str (ISO format)
- 'vulnerabilities': List[Vulnerability]
- 'risk_score_summary': Dict[str, Any] (from risk_scoring.py)
- 'ai_insights': Dict[str, Any] (from ai_analyzer.py)
"""

# Example of what a stored scan result might look like
def create_empty_scan_result(scan_id: str, target_url: str) -> ScanResult:
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "timestamp": "", # Will be populated at time of creation
        "vulnerabilities": [],
        "risk_score_summary": {},
        "ai_insights": {}
    }

# Example of a vulnerability entry within the 'vulnerabilities' list
# This would correspond to the output of individual scanners.
Vulnerability = Dict[str, Any]
"""
Represents a single identified vulnerability.
Expected keys:
- 'vulnerability_type': str
- 'is_vulnerable': bool
- 'severity': str (e.g., 'critical', 'high', 'medium', 'low', 'info')
- 'confidence': float (0.0 to 1.0)
- 'evidence': Any (e.g., list of strings, dictionary)
- 'recommendation': str
"""
