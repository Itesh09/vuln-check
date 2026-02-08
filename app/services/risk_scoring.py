from typing import List, Dict, Any

def calculate_risk_score(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates a cumulative risk score based on the severity and confidence
    of identified vulnerabilities.

    Args:
        scan_results: A list of vulnerability scan results.

    Returns:
        A dictionary containing the total risk score and a breakdown.
    """
    total_score = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    severity_weights = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 0
    }

    for result in scan_results:
        severity = result.get("severity", "info").lower()
        confidence = result.get("confidence", 0.0)
        is_vulnerable = result.get("is_vulnerable", False)

        if is_vulnerable:
            score_contribution = severity_weights.get(severity, 0) * confidence
            total_score += score_contribution
            severity_counts[severity] += 1
            
    # Normalize or categorize the total_score if needed
    overall_risk_level = "info"
    if total_score > 150:
        overall_risk_level = "critical"
    elif total_score > 100:
        overall_risk_level = "high"
    elif total_score > 50:
        overall_risk_level = "medium"
    elif total_score > 0:
        overall_risk_level = "low"

    return {
        "total_risk_score": round(total_score, 2),
        "overall_risk_level": overall_risk_level,
        "severity_breakdown": severity_counts,
        "recommendation": "Review high and critical vulnerabilities first. Implement recommendations from individual scanners."
    }
