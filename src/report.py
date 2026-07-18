import os
import csv
import json
from typing import List, Dict, Any

class ReportCompiler:
    @staticmethod
    def generate_reports(findings: List[Dict[str, Any]], output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. JSON Compilation
        with open(os.path.join(output_dir, "compliance_report.json"), "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        # 2. CSV Compilation
        fields = ["Resource", "Type", "Severity", "Description", "ComplianceControl", "Framework"]
        with open(os.path.join(output_dir, "compliance_report.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for finding in findings:
                writer.writerow({k: finding.get(k, "N/A") for k in fields})

        # 3. HTML Static Dashboard Matrix
        html_raw = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Cloud Compliance Report Matrix</title>
            <style>
                body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #121212; color: #FFFFFF; padding: 40px; }
                h1 { color: #00E676; font-size: 26px; border-bottom: 2px solid #1E1E1E; padding-bottom: 12px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #1E1E1E; border-radius: 8px; overflow: hidden; }
                th, td { padding: 14px 20px; text-align: left; border-bottom: 1px solid #121212; }
                th { background-color: #2E2E2E; color: #8E8E93; text-transform: uppercase; font-size: 13px; }
                .CRITICAL { color: #FF1744; font-weight: bold; }
                .HIGH { color: #FF9100; font-weight: bold; }
                .MEDIUM { color: #FFD600; font-weight: bold; }
                .empty { text-align: center; color: #8E8E93; padding: 40px; }
            </style>
        </head>
        <body>
            <h1>Cloud Compliance Scanner - Executive Metrics</h1>
            <table>
                <thead>
                    <tr>
                        <th>Resource Identifier</th>
                        <th>Domain Type</th>
                        <th>Severity</th>
                        <th>Control ID</th>
                        <th>Compliance Finding Context</th>
                    </tr>
                </thead>
                <tbody>
        """
        if not findings:
            html_raw += "<tr><td colspan='5' class='empty'>Fleet matches target policy specifications. Zero findings recorded.</td></tr>"
        else:
            for item in findings:
                html_raw += f"""
                <tr>
                    <td>{item['Resource']}</td>
                    <td>{item['Type']}</td>
                    <td class="{item['Severity']}">{item['Severity']}</td>
                    <td>{item['ComplianceControl']}</td>
                    <td>{item['Description']}</td>
                </tr>
                """
        html_raw += "</tbody></table></body></html>"
        
        with open(os.path.join(output_dir, "compliance_report.html"), "w", encoding="utf-8") as f:
            f.write(html_raw)