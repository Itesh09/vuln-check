import importlib
import os
from typing import List, Dict, Any

from app.config.scan_modes import get_scanners_for_mode, apply_scan_mode_settings, get_scan_mode_config


def _load_scanners() -> Dict[str, Any]:
    """Dynamically loads scanner modules from the app/scanners directory."""
    scanners_dir = os.path.join(os.path.dirname(__file__), "..", "scanners")
    scanners = {}
    for filename in os.listdir(scanners_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = filename[:-3]
            try:
                module = importlib.import_module(f"app.scanners.{module_name}")
                scanner_function_name = f"scan_{module_name}"
                if hasattr(module, scanner_function_name):
                    scanners[module_name] = getattr(module, scanner_function_name)
                else:
                    print(f"Warning: Scanner function '{scanner_function_name}' not found in {filename}")
            except Exception as e:
                print(f"Error loading scanner {filename}: {e}")
    return scanners


_LOADED_SCANNERS = _load_scanners()


def orchestrate_scan(scan_context: Dict[str, Any], scan_mode: str = "fast") -> List[Dict[str, Any]]:
    """
    Orchestrates the execution of vulnerability scanners based on the specified scan mode.

    Args:
        scan_context: A dictionary containing context for the scan, e.g., {'url': 'http://example.com'}
        scan_mode: The scan mode - 'fast', 'stealth', or 'deep'

    Returns:
        A list of scan results from all executed scanners.
    """
    enabled_scanners = get_scanners_for_mode(scan_mode)
    mode_config = get_scan_mode_config(scan_mode)
    
    updated_context = apply_scan_mode_settings(scan_mode, dict(scan_context))
    updated_context["scan_mode"] = scan_mode
    updated_context["mode_config"] = mode_config
    
    print(f"\n[{scan_mode.upper()} SCAN MODE]")
    print(f"  Enabled scanners: {', '.join(enabled_scanners)}")
    print(f"  Timeout: {mode_config.timeout}s")
    print(f"  Max payloads: {mode_config.max_payloads}")
    print(f"  Delay: {mode_config.min_delay}-{mode_config.max_delay}s")
    print(f"  Stealth: {'enabled' if mode_config.stealth_enabled else 'disabled'}")
    print()
    
    all_results: List[Dict[str, Any]] = []

    for scanner_name, scanner_func in _LOADED_SCANNERS.items():
        if scanner_name not in enabled_scanners:
            continue
            
        try:
            result = scanner_func(updated_context)
            all_results.append(result)
        except Exception as e:
            error_result = {
                "vulnerability_type": "orchestrator_error",
                "scanner_name": scanner_name,
                "is_vulnerable": False,
                "severity": "critical",
                "confidence": 1.0,
                "evidence": f"Scanner failed with error: {e}",
                "recommendation": f"Investigate the '{scanner_name}' scanner for issues."
            }
            all_results.append(error_result)
            print(f"Error executing scanner {scanner_name}: {e}")
            
    return all_results

