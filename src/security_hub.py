import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.SecurityHub")

class SecurityHubScanner:
    def __init__(self, session: Any, region: str) -> None:
        self.client = session.client("securityhub", region_name=region)
        self.region = region

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            self.client.get_enabled_standards()
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAccessException":
                findings.append({
                    "Resource": f"SecurityHub [{self.region}]",
                    "Type": "SECURITY_HUB",
                    "Severity": "MEDIUM",
                    "Description": f"AWS Security Hub is not activated or initialized within region '{self.region}'."
                })
            else:
                logger.error(f"Security Hub tracking check failed in region {self.region}: {str(e)}")
        return findings