from marshmallow import Schema, fields, validate

class ScanRequestSchema(Schema):
    """
    Schema for validating incoming scan requests.
    """
    url = fields.URL(required=True, validate=validate.Length(min=5, max=2048))
    # Add other scan-related parameters as needed, e.g., scan_type, depth, etc.

class ScanResultSchema(Schema):
    """
    Schema for serializing outgoing scan results.
    """
    scan_id = fields.Str(required=True)
    target_url = fields.URL(required=True)
    timestamp = fields.DateTime(required=True)
    vulnerabilities = fields.List(fields.Nested("VulnerabilitySchema"), required=True) # Forward reference
    risk_score_summary = fields.Dict(required=True)
    ai_insights = fields.Dict(required=True)
