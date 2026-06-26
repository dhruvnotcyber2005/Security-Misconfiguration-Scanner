"""
Generate human-readable reports from SentinelScan scan results.
"""

from scanner.core.target import Target
from scanner.reporting.reporting_models import ScanResult

class ReportGenerator:
    """Generate formatted SentinelScan reports."""

    @staticmethod
    def generate(target:Target,results:list[ScanResult])->str:
        """Generate a formatted report from the scan results as string."""

        lines=[]
        lines.append("="*60)
        lines.append("SentinelScan Report")
        lines.append("="*60)
        lines.append("")
        lines.append(f"Target: {target.url}")
        lines.append(f"Modules Scanned: {len(results)}")
        lines.append("")

        for result in results:
            lines.append("-"*60)
            lines.append(f"Module: {result.module}")
            lines.append(f"Execution Time: {result.execution_time:.4f} seconds")
            lines.append("")

            if not result.findings:
                lines.append("No findings.")
                lines.append("")
            else:
                for finding in result.findings:
                    lines.append(f"Title: {finding.title}")
                    lines.append(f"Severity: {finding.severity}")
                    lines.append(f"Description: {finding.description}")
                    lines.append(f"Recommendation: {finding.recommendation}")
                    lines.append("")

        total_findings=0
        critical=0
        high=0
        medium=0
        low=0
        informational=0

        for result in results:
             for finding in result.findings:
                total_findings+=1
                
                if finding.severity=="Critical":
                    critical+=1
                elif finding.severity=="High":
                    high+=1 
                elif finding.severity=="Medium":
                    medium+=1 
                elif finding.severity=="Low":
                    low+=1 
                elif finding.severity=="Informational":
                    informational+=1 

        lines.append("=" * 60)
        lines.append("Summary")
        lines.append("=" * 60)
        lines.append(f"Modules Scanned: {len(results)}")
        lines.append(f"Total Findings: {total_findings}")
        lines.append("")
        lines.append(f"Critical: {critical}")
        lines.append(f"High: {high}")
        lines.append(f"Medium: {medium}")
        lines.append(f"Low: {low}")
        lines.append(f"Informational: {informational}")
        
        return "\n".join(lines)