from typing import List, Dict, Any

class ComplianceCrossMapper:
    def __init__(self, framework: str) -> None:
        self.framework = framework

    def evaluate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Appends contextual regulatory control tags directly onto normalized structural records."""
        resource_type = finding.get("Type")
        description = finding.get("Description", "")
        
        control_id = "UNKNOWN-CONTROL"
        framework_reference = self.framework

        if resource_type == "IAM_USER":
            if "MFA" in description:
                control_id = "CIS-1.1"
            elif "Access Key" in description:
                control_id = "CIS-1.4"
        elif resource_type == "VPC":
            if "Flow Logs" in description:
                control_id = "CIS-3.9"
        elif resource_type == "NACL" or resource_type == "SECURITY_GROUP":
            if "0.0.0.0/0" in description:
                control_id = "CIS-4.1"
        elif resource_type == "AWS_CONFIG":
            control_id = "CIS-2.5"
        elif resource_type == "GUARDDUTY":
            control_id = "CIS-2.2"

        finding["ComplianceControl"] = control_id
        finding["Framework"] = framework_reference
        return finding