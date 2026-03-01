import logging
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class AuditLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.audit_file = self.log_dir / "audit.log"
        self.scan_file = self.log_dir / "scans.jsonl"

    def log_scan_start(self, scan_id: str, target_url: str, config: Dict[str, Any]):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "scan_start",
            "scan_id": scan_id,
            "target": target_url,
            "config": {k: v for k, v in config.items() if k != 'custom_user_agent'}
        }
        self._write_audit(entry)

    def log_scan_end(self, scan_id: str, findings_count: int, risk_level: str):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "scan_end",
            "scan_id": scan_id,
            "findings": findings_count,
            "risk_level": risk_level
        }
        self._write_audit(entry)

    def log_request(self, scan_id: str, method: str, url: str, status_code: int, duration_ms: float):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "http_request",
            "scan_id": scan_id,
            "method": method,
            "url": url,
            "status": status_code,
            "duration_ms": round(duration_ms, 2)
        }
        self._write_audit(entry)

    def log_finding(self, scan_id: str, vuln_type: str, severity: str, evidence: Dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "vulnerability_found",
            "scan_id": scan_id,
            "type": vuln_type,
            "severity": severity,
            "evidence": evidence
        }
        self._write_scan_log(entry)

    def log_rate_limit(self, scan_id: str, url: str, wait_time: int):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "rate_limited",
            "scan_id": scan_id,
            "url": url,
            "wait_seconds": wait_time
        }
        self._write_audit(entry)

    def log_error(self, scan_id: str, error_type: str, message: str):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "error",
            "scan_id": scan_id,
            "type": error_type,
            "message": message
        }
        self._write_audit(entry)

    def _write_audit(self, entry: Dict):
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def _write_scan_log(self, entry: Dict):
        with open(self.scan_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')


_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        log_dir = os.environ.get('VULNCHECK_LOG_DIR', 'logs')
        _audit_logger = AuditLogger(log_dir)
    return _audit_logger


def setup_logging(name: str = "vuln_check") -> logging.Logger:
    logger = logging.getLogger(name)
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    c_handler = logging.StreamHandler()
    c_handler.setFormatter(formatter)

    log_file = os.environ.get('VULNCHECK_LOG_FILE', 'vuln_check.log')
    f_handler = logging.FileHandler(log_file)
    f_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

    return logger


logger = setup_logging()
