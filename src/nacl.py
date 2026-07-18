import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.NACL")

class NACLScanner:
    def __init__(self, session: Any, region: str) -> None:
        self.client = session.client("ec2", region_name=region)
        self.region = region

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            nacls = self.client.describe_network_acls().get("NetworkAcls", [])
            for nacl in nacls:
                nacl_id: str = nacl["NetworkAclId"]
                for entry in nacl.get("Entries", []):
                    if entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("RuleAction") == "allow" and not entry.get("Egress", False):
                        findings.append({
                            "Resource": f"{nacl_id} [{self.region}]",
                            "Type": "NACL",
                            "Severity": "HIGH",
                            "Description": f"NACL '{nacl_id}' allows unrestricted inbound traffic (0.0.0.0/0) via rule {entry.get('RuleNumber')}."
                        })
        except ClientError as e:
            logger.error(f"NACL evaluation failed in region {self.region}: {str(e)}")
        return findings