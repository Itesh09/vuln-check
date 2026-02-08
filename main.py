import argparse
import os
import uuid
from datetime import datetime
import json

from app import create_app
from app.utils.validators import is_processable_url
from app.services.scan_orchestrator import orchestrate_scan
from app.services.risk_scoring import calculate_risk_score
from app.services.ai_analyzer import ai_analyze_results
from app.models.scan_result import create_empty_scan_result, ScanResult, Vulnerability


def run_cli_scan(url: str):
    """
    Executes a vulnerability scan via CLI and prints a human-readable report.
    """
    print(f"Starting scan on {url}...")

    if not is_processable_url(url):
        print(f"Error: Cannot process URL: '{url}'. Please enter a valid and supported URL (http/https).")
        return

    scan_id = str(uuid.uuid4())
    scan_context = {"url": url, "scan_id": scan_id}
    
    # Orchestrate the scan
    raw_vulnerabilities: list[Vulnerability] = orchestrate_scan(scan_context)
    
    # Filter out non-vulnerabilities (e.g., info-level or disabled scanner messages)
    # and errors from the orchestrator
    actual_vulnerabilities = [
        v for v in raw_vulnerabilities 
        if v.get("is_vulnerable", False) and v.get("vulnerability_type") != "orchestrator_error"
    ]

    # Calculate risk score
    risk_summary = calculate_risk_score(actual_vulnerabilities)

    # Perform AI analysis (placeholder for now)
    ai_insights = ai_analyze_results(actual_vulnerabilities)

    # Aggregate results into a ScanResult object
    final_scan_result: ScanResult = create_empty_scan_result(scan_id, url)
    final_scan_result["timestamp"] = datetime.now().isoformat()
    final_scan_result["vulnerabilities"] = actual_vulnerabilities
    final_scan_result["risk_score_summary"] = risk_summary
    final_scan_result["ai_insights"] = ai_insights

    print("\n" + "="*50)
    print(f"SCAN REPORT FOR: {url}")
    print(f"Scan ID: {scan_id}")
    print(f"Timestamp: {final_scan_result['timestamp']}")
    print("="*50)

    print("\n--- Risk Summary ---")
    print(f"Overall Risk Level: {risk_summary['overall_risk_level'].upper()}")
    print(f"Total Risk Score: {risk_summary['total_risk_score']}")
    print("Severity Breakdown:")
    for severity, count in risk_summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count} findings")
    print(f"Recommendation: {risk_summary['recommendation']}")

    print("\n--- Vulnerability Details ---")
    if actual_vulnerabilities:
        for i, vuln in enumerate(actual_vulnerabilities):
            print(f"\n{i+1}. Vulnerability Type: {vuln.get('vulnerability_type', 'N/A').replace('_', ' ').title()}")
            print(f"   Severity: {vuln.get('severity', 'N/A').capitalize()}")
            print(f"   Confidence: {vuln.get('confidence', 'N/A'):.2f}")
            print(f"   Evidence: {json.dumps(vuln.get('evidence', 'N/A'), indent=2)}")
            print(f"   Recommendation: {vuln.get('recommendation', 'N/A')}")
            if vuln.get('scanner_name'):
                print(f"   Scanner: {vuln.get('scanner_name')}")
    else:
        print("No significant vulnerabilities detected.")
    
    print("\n--- AI Insights (Preliminary) ---")
    print(f"Summary: {ai_insights['summary']}")

    print("\n" + "="*50)
    print("SCAN COMPLETE.")
    print("="*50)


def main():
    parser = argparse.ArgumentParser(description="Website Vulnerability Finder CLI and Server.")
    parser.add_argument("-u", "--url", type=str, help="URL to scan for vulnerabilities.")
    parser.add_argument("--run-server", action="store_true", help="Run the Flask web server.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address for the Flask server.")
    parser.add_argument("--port", type=int, default=5000, help="Port for the Flask server.")

    args = parser.parse_args()

    if args.url:
        run_cli_scan(args.url)
    elif args.run_server:
        app = create_app()
        # Register blueprints
        from app.blueprints.scan_routes import scan_bp
        from app.blueprints.auth_routes import auth_bp
        from app.blueprints.report_routes import report_bp
        app.register_blueprint(scan_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(report_bp)

        print(f"Running Flask server on http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

