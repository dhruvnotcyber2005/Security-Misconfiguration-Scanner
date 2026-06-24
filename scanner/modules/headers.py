"""
Scanner module for checking HTTP security headers
"""

import time
import requests

from scanner.core.scanner import ScannerModule
from scanner.core.target import Target

from scanner.reporting.reporting_models import Finding,ScanResult

from scanner.utils.logger import logger

class HeaderScanner(ScannerModule):
    """ Scans a target website for missing HTTP security headers """

    REQUIRED_HEADERS = {
        "Content-Security-Policy": "Implement a strong Content Security Policy.",
        "Strict-Transport-Security": "Enable HTTP Strict Transport Security (HSTS).",
        "X-Frame-Options": "Protect against clickjacking by setting X-Frame-Options.",
        "X-Content-Type-Options": "Prevent MIME type sniffing by setting X-Content-Type-Options to 'nosniff'.",
    }

    @property
    def name(self)->str:
        """Return the name of the scanner module"""
        return "HTTP Security Headers"
    
    def scan(self, target:Target)->ScanResult:
        """ Scan the target for missing HTTP security headers"""
        start_time=time.perf_counter()
        findings:list[Finding]=[]

        try:
            logger.info("Scanning HTTP Security Headers for %s",target.url)
            response=requests.get(target.url,timeout=10)

        except requests.exceptions.RequestException as error:
            logger.error("Header scan failed: %s",error)
            
            findings.append(
                Finding(
                    title="Header scan failed",
                    severity="Info",
                    description=str(error),
                    recommendation="Verify that the target URL is valid and reachable",
                )
            )
        
        else:
            headers=response.headers

            for header,recommendation in self.REQUIRED_HEADERS.items():
                if header not in headers:
                    findings.append(
                        Finding(
                            title=f"Missing: {header}",
                            severity="Medium",
                            description=f"{header} is missing",
                            recommendation=recommendation,
                        )
                    )

        end_time=time.perf_counter()
        return ScanResult(
            module=self.name,
            findings=findings,
            execution_time=end_time-start_time,
        )