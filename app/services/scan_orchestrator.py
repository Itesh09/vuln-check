import importlib
import os
from typing import List, Dict, Any

def _load_scanners() -> Dict[str, Any]:
    """Dynamically loads scanner modules from the app/scanners directory."""
    scanners_dir = os.path.join(os.path.dirname(__file__), "..", "scanners")
    scanners = {}
    for filename in os.listdir(scanners_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = filename[:-3]
            try:
                # Import the module
                module = importlib.import_module(f"app.scanners.{module_name}")
                # Assume scanner function is named 'scan_<module_name>'
                scanner_function_name = f"scan_{module_name}"
                if hasattr(module, scanner_function_name):
                    scanners[module_name] = getattr(module, scanner_function_name)
                else:
                    print(f"Warning: Scanner function '{scanner_function_name}' not found in {filename}")
            except Exception as e:
                print(f"Error loading scanner {filename}: {e}")
    return scanners

_LOADED_SCANNERS = _load_scanners()

def orchestrate_scan(scan_context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Orchestrates the execution of all registered vulnerability scanners.

    Args:
        scan_context: A dictionary containing context for the scan, e.g., {'url': 'http://example.com'}

    Returns:
        A list of scan results from all executed scanners.
    """
    all_results: List[Dict[str, Any]] = []

    for scanner_name, scanner_func in _LOADED_SCANNERS.items():
        try:
            # Each scanner should accept a single input object (scan_context)
            # and return a standardized result object.
            result = scanner_func(scan_context)
            all_results.append(result)
        except Exception as e:
            # Scanner failures must not stop the entire scan.
            # Log the error and continue with other scanners.
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

