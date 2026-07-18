import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.SecurityGroups")

class SecurityGroupScanner:
    def __init__(self, session: Any, region: str) -> None:
        self.client = session.client("ec2", region_name=region)
        self.region = region

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            groups = self.client.describe_security_groups().get("SecurityGroups", [])
            for sg in groups:
                sg_id: str = sg["GroupId"]
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            findings.append({
                                "Resource": f"{sg_id} ({sg.get('GroupName')}) [{self.region}]",
                                "Type": "SECURITY_GROUP",
                                "Severity": "HIGH",
                                "Description": f"Security Group '{sg_id}' allows public ingress (0.0.0.0/0) on port scope [{perm.get('FromPort')}-{perm.get('ToPort')}]."
                            })
        except ClientError as e:
            logger.error(f"Security Group check failed in region {self.region}: {str(e)}")
        return findings