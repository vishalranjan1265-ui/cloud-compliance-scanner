import logging
from typing import List, Dict, Any
import boto3

from utils import get_operational_regions
from iam import IAMScanner
from vpc import VPCScanner
from nacl import NACLScanner
from security_groups import SecurityGroupScanner
from aws_config import AWSConfigScanner
from guardduty import GuardDutyScanner
from security_hub import SecurityHubScanner

logger = logging.getLogger("CloudScanner.Core")

class ComplianceScannerOrchestrator:
    def __init__(self, session: boto3.Session, config: Dict[str, Any]) -> None:
        self.session = session
        self.config = config
        self.enabled_scanners = config.get("scanners", {})

    def execute_global_scan(self) -> List[Dict[str, Any]]:
        raw_findings: List[Dict[str, Any]] = []
        
        # 1. Identity Verification Domain (Global Context Execution)
        if self.enabled_scanners.get("iam", True):
            logger.info("Starting identity framework structural scan layer...")
            iam_driver = IAMScanner(self.session, self.config)
            raw_findings.extend(iam_driver.scan())

        # 2. Dynamic Discovery Partition Loops
        enable_multi = self.config.get("global", {}).get("enable_multi_region", True)
        regions = get_operational_regions(self.session) if enable_multi else ["us-east-1"]

        for region in regions:
            logger.info(f"==> Initiating infrastructure rules validations inside region: [{region}]")
            
            if self.enabled_scanners.get("vpc", True):
                raw_findings.extend(VPCScanner(self.session, region).scan())
            if self.enabled_scanners.get("nacl", True):
                raw_findings.extend(NACLScanner(self.session, region).scan())
            if self.enabled_scanners.get("security_groups", True):
                raw_findings.extend(SecurityGroupScanner(self.session, region).scan())
            if self.enabled_scanners.get("aws_config", True):
                raw_findings.extend(AWSConfigScanner(self.session, region).scan())
            if self.enabled_scanners.get("guardduty", True):
                raw_findings.extend(GuardDutyScanner(self.session, region).scan())
            if self.enabled_scanners.get("security_hub", True):
                raw_findings.extend(SecurityHubScanner(self.session, region).scan())

        return raw_findings