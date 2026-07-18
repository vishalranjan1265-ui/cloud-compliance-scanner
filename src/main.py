import sys
import os
import logging
import yaml
from typing import Dict, Any

from utils import get_session
from scanner import ComplianceScannerOrchestrator
from compliance import ComplianceCrossMapper
from report import ReportCompiler

def load_runtime_configuration() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_path = os.path.join(base_dir, "config.yaml")
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {"global": {"output_dir": "reports", "compliance_framework": "CIS_V3.0"}}

def main() -> None:
    config = load_runtime_configuration()
    
    logging.basicConfig(
        level=config.get("global", {}).get("log_level", "INFO"),
        format='{"timestamp":"%(asctime)s", "module":"%(name)s", "level":"%(levelname)s", "message":"%(message)s"}',
        stream=sys.stdout
    )
    logger = logging.getLogger("CloudScanner.Main")
    logger.info("Initializing multi-region security orchestration execution flow...")

    try:
        session = get_session()
    except Exception as e:
        logger.critical(f"Aborting scanning operations. Standard credential token generation aborted: {str(e)}")
        sys.exit(1)

    # Execute Data Discovery Run Block
    orchestrator = ComplianceScannerOrchestrator(session, config)
    collected_findings = orchestrator.execute_global_scan()

    # Apply Structural Control Framework Mappings
    framework = config.get("global", {}).get("compliance_framework", "CIS_V3.0")
    mapper = ComplianceCrossMapper(framework)
    mapped_findings = [mapper.evaluate_finding(item) for item in collected_findings]

    # Export Structural Reports Outputs
    output_directory = config.get("global", {}).get("output_dir", "reports")
    logger.info(f"Scan complete. Passing data structures into compilation matrix outputs inside /{output_directory}...")
    
    ReportCompiler.generate_reports(mapped_findings, output_directory)
    logger.info("Compliance auditing run loop finalized successfully.")

if __name__ == "__main__":
    main()