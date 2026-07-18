import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.GuardDuty")

class GuardDutyScanner:
    def __init__(self, session: Any, region: str) -> None:
        self.client = session.client("guardduty", region_name=region)
        self.region = region

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            detectors = self.client.list_detectors().get("DetectorIds", [])
            if not detectors:
                findings.append({
                    "Resource": f"GuardDuty [{self.region}]",
                    "Type": "GUARDDUTY",
                    "Severity": "CRITICAL",
                    "Description": f"Amazon GuardDuty threat detection is completely disabled in region '{self.region}'."
                })
        except ClientError as e:
            logger.error(f"GuardDuty evaluation failed in region {self.region}: {str(e)}")
        return findings