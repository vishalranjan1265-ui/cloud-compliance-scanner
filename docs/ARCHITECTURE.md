# System Architecture: Cloud Compliance Scanner

## 1. Executive Summary
The Cloud Compliance Scanner is an enterprise utility designed to audit multi-region AWS footprints against established compliance frameworks (CIS AWS Foundations Benchmark v3.0, NIST 800-53). The engine operates as a stateless, containerized scanning utility capable of running locally, in ad-hoc staging instances, or integrated directly into standard execution pipeline architectures via GitHub Actions runners.

## 2. Core Architectural Principles
- **Stateless Execution:** The runner retains zero state across scans. State verification is performed live against target AWS provider configuration APIs.
- **Dynamic Module Loading:** The compliance evaluation matrix operates decoupled from resource collection strategies, enabling rules updates without breaking API aggregation layers.
- **Fail-Safe Token Consumption:** Invocations pass through an automated backoff decorator wrapper to eliminate API throttling risks across enterprise-scale accounts containing massive resource structures.

## 3. Structural Data & Flow Ingress
1. **Ingress Configuration Engine:** `main.py` parses configurations (`config.yaml`) into internal strongly typed dataclass matrices.
2. **Context Resolution:** `utils.py` creates explicit Boto3 provider contexts across dynamically discovered operational regions.
3. **Parallel Scanning:** `scanner.py` aggregates regional metrics from individual domain drivers (VPC, NACL, SG, AWS Config, GuardDuty, Security Hub, IAM).
4. **Compliance Cross-Mapping:** `compliance.py` evaluates resource states against specific regulatory metadata flags.
5. **Egress Multi-Report Compiler:** `report.py` emits unified structural artifacts (JSON, CSV, standalone static HTML dashboards) to the `/reports` partition.