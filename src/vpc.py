import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.VPC")

class VPCScanner:
    def __init__(self, session: Any, region: str) -> None:
        self.client = session.client("ec2", region_name=region)
        self.region = region

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            vpcs = self.client.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                vpc_id: str = vpc["VpcId"]
                if not self._has_flow_logs(vpc_id):
                    findings.append({
                        "Resource": f"{vpc_id} [{self.region}]",
                        "Type": "VPC",
                        "Severity": "MEDIUM",
                        "Description": f"VPC '{vpc_id}' in region '{self.region}' lacks active VPC Flow Logs configuration."
                    })
        except ClientError as e:
            logger.error(f"VPC sweep failed in region {self.region}: {str(e)}")
        return findings

    def _has_flow_logs(self, vpc_id: str) -> bool:
        try:
            logs = self.client.describe_flow_logs(
                Filter=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            ).get("FlowLogs", [])
            return len(logs) > 0
        except ClientError:
            return False