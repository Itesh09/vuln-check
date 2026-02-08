from flask import Blueprint, jsonify, request

scan_bp = Blueprint('scan', __name__, url_prefix='/scan')

@scan_bp.route('/', methods=['POST'])
def run_scan():
    # TODO: Implement scan orchestration
    return jsonify({"message": "Scan initiated (TODO)"}), 202

@scan_bp.route('/<scan_id>', methods=['GET'])
def get_scan_result(scan_id: str):
    # TODO: Implement fetching scan results
    return jsonify({"message": f"Fetching result for scan {scan_id} (TODO)"}), 200
