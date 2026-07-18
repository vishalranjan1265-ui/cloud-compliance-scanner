import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.AWSConfig")

class AWSConfigScanner:
    def __init__(self, session: Any, region: str) -> None:
        self.client = session.client("config", region_name=region)
        self.region = region

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            recorders = self.client.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                findings.append({
                    "Resource": f"AWS Config [{self.region}]",
                    "Type": "AWS_CONFIG",
                    "Severity": "HIGH",
                    "Description": f"AWS Config recorder is not enabled within region '{self.region}'."
                })
            else:
                for rec in recorders:
                    status = self.client.describe_configuration_recorder_status(
                        ConfigurationRecorderNames=[rec["name"]]
                    ).get("ConfigurationRecordersStatus", [])
                    if not status or not status[0].get("recording", False):
                        findings.append({
                            "Resource": f"{rec['name']} [{self.region}]",
                            "Type": "AWS_CONFIG",
                            "Severity": "HIGH",
                            "Description": f"AWS Config recorder '{rec['name']}' is present but not actively recording."
                        })
        except ClientError as e:
            logger.error(f"AWS Config validation failed in region {self.region}: {str(e)}")
        return findings