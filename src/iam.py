import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from utils import rate_limiter_fallback

logger = logging.getLogger("CloudScanner.IAM")

class IAMScanner:
    def __init__(self, session: Any, config: Dict[str, Any]) -> None:
        self.client = session.client("iam")
        self.threshold_days = config.get("thresholds", {}).get("stale_access_key_days", 90)

    @rate_limiter_fallback
    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username: str = user["UserName"]
                    user_arn: str = user["Arn"]
                    
                    if not self._is_mfa_enabled(username):
                        findings.append({
                            "Resource": user_arn,
                            "Type": "IAM_USER",
                            "Severity": "CRITICAL",
                            "Description": f"User '{username}' does not have Multi-Factor Authentication (MFA) enabled."
                        })
                    findings.extend(self._check_keys(username, user_arn))
        except ClientError as e:
            logger.error(f"Failed to scan IAM user directory: {str(e)}")
        return findings

    def _is_mfa_enabled(self, username: str) -> bool:
        try:
            mfa = self.client.list_mfa_devices(UserName=username)
            return len(mfa.get("MFADevices", [])) > 0
        except ClientError as e:
            logger.error(f"MFA validation failed for {username}: {str(e)}")
            return False

    def _check_keys(self, username: str, user_arn: str) -> List[Dict[str, Any]]:
        key_findings: List[Dict[str, Any]] = []
        try:
            keys = self.client.list_access_keys(UserName=username)
            now = datetime.now(timezone.utc)
            for metadata in keys.get("AccessKeyMetadata", []):
                if metadata["Status"] == "Active":
                    age = (now - metadata["CreateDate"]).days
                    if age > self.threshold_days:
                        key_findings.append({
                            "Resource": f"{user_arn}/accesskey/{metadata['AccessKeyId']}",
                            "Type": "IAM_USER",
                            "Severity": "HIGH",
                            "Description": f"Active access key {metadata['AccessKeyId']} is stale ({age} days old)."
                        })
        except ClientError as e:
            logger.error(f"Access key scan failed for {username}: {str(e)}")
        return key_findings