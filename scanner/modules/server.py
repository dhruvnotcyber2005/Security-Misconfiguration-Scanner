"""
Scanner module for the server
"""

import time
import requests

from scanner.core.scanner import ScannerModule
from scanner.core.target import Target
from scanner.reporting.reporting_models import Finding,ScanResult
from scanner.utils.logger import logger

class ServerScanner(ScannerModule):
    """Scans a target website for exposed server banners."""
    SERVER_BANNER={
        "severity": "Low",
        "recommendation": (
            "Configure the web server to suppress or minimize "
            "the 'Server' HTTP response header in production."
        ),
    }

    @property
    def name(self)->str:
        return "Server Banner"
    
    def scan(self, target: Target)-> ScanResult:
        start_time=time.perf_counter()
        findings:list[Finding]=[]

        try:
            logger.info("Scanning %s for exposed server banner.",target.url)
            response=requests.get(target.url,timeout=10)

        except requests.exceptions.RequestException as error:
            logger.error("Failed to scan %s for server banner: %s",target.url,error)
            findings.append(
                Finding(
                    title="Server Banner Scan Failed",
                    severity="Informational",
                    description=str(error),
                    recommendation="Verify that the target URL is valid and reachable.",
                )
            )
        
        else:
                server_banner = response.headers.get("Server")

                if server_banner:
                    findings.append(
                        Finding(
                            title="Server Banner Exposed",
                            severity=self.SERVER_BANNER["severity"],
                            description=(
                                "The web server exposes its 'Server' HTTP response header. "
                                f"The reported server banner is: {server_banner}. "
                                "This information may assist attackers during reconnaissance."
                            ),
                            recommendation=self.SERVER_BANNER["recommendation"],
                        )
                    )

        end_time=time.perf_counter()
        return ScanResult(
            module=self.name,
            findings=findings,
            execution_time=end_time - start_time,
        )