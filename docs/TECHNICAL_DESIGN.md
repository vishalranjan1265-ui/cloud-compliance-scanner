# Technical Design Document: Cloud Compliance Engine

## 1. Compliance Mapping Definition Strategy
Vulnerabilities map directly to internal identifiers tied to regulatory schemas:

| Sub-Module Reference | Audit Objective Context | Targeted Regulatory Control | Severity Target |
| :--- | :--- | :--- | :--- |
| `iam.py` | Access Key Decay & Missing MFA Constraints | CIS Control 1.1 - 1.14 | CRITICAL |
| `vpc.py` | Flow Log State Verification | CIS Control 3.9 / NIST AU-12 | MEDIUM |
| `nacl.py` | Ingress Perimeter Block Formats | CIS Control 4.1 / NIST SC-7 | HIGH |
| `security_groups.py` | Open Remote Administration Scopes | CIS Control 4.2 / NIST SC-7 | HIGH |
| `aws_config.py` | Global Recorder System Integrity | CIS Control 2.5 / NIST CM-2 | HIGH |
| `guardduty.py` | Intelligent Threat Detection Activation Status | CIS Control 2.2 / NIST SI-4 | CRITICAL |
| `security_hub.py` | Aggregator Ingress Integration State | CIS Control 2.3 / NIST SI-4 | MEDIUM |

## 2. Component Boundary Segregation
Network boundary scanners (`vpc.py`, `nacl.py`, `security_groups.py`) evaluate structural network paths concurrently. Governance and identity tools (`iam.py`, `aws_config.py`, `guardduty.py`, `security_hub.py`) assess the baseline orchestration profile. All findings normalize into an array of uniform dictionary data schemas passing into the core transformation engine layer.