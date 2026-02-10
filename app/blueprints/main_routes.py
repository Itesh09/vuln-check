from flask import Blueprint, render_template, request, jsonify
import uuid
from datetime import datetime

from app.services.scan_orchestrator import orchestrate_scan
from app.services.risk_scoring import calculate_risk_score
from app.services.ai_analyzer import ai_analyze_results
from app.models.scan_result import create_empty_scan_result
from app.utils.validators import is_processable_url

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/scan')
def web_scan():
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    
    if not is_processable_url(url):
        return jsonify({"error": f"Invalid URL: {url}"}), 400
    
    try:
        scan_id = str(uuid.uuid4())
        scan_context = {"url": url, "scan_id": scan_id}
        
        raw_vulnerabilities = orchestrate_scan(scan_context)
        
        actual_vulnerabilities = [
            v for v in raw_vulnerabilities 
            if v.get("is_vulnerable", False) and v.get("vulnerability_type") != "orchestrator_error"
        ]
        
        risk_summary = calculate_risk_score(actual_vulnerabilities)
        ai_insights = ai_analyze_results(actual_vulnerabilities)
        
        final_scan_result = create_empty_scan_result(scan_id, url)
        final_scan_result["timestamp"] = datetime.now().isoformat()
        final_scan_result["vulnerabilities"] = actual_vulnerabilities
        final_scan_result["risk_score_summary"] = risk_summary
        final_scan_result["ai_insights"] = ai_insights
        
        return jsonify(final_scan_result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500