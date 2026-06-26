"""
Scanner module for checking supported HTTP methods
"""

import time
import requests

from scanner.core.scanner import ScannerModule
from scanner.core.target import Target

from scanner.reporting.reporting_models import Finding, ScanResult
from scanner.utils.logger import logger

class MethodsScanner(ScannerModule):
    """Scans a target website for HTTP Methods."""

    RISKY_METHODS = {
    "PUT": {
        "severity": "Medium",
        "recommendation": "Disable PUT unless it is explicitly required.",
    },
    "DELETE": {
        "severity": "Medium",
        "recommendation": "Disable DELETE unless it is explicitly required.",
    },
    "TRACE": {
        "severity": "High",
        "recommendation": "Disable TRACE to mitigate Cross-Site Tracing (XST) attacks.",
    },
    "CONNECT": {
        "severity": "High",
        "recommendation": "Disable CONNECT unless the server is intended to function as an HTTP proxy.",
    },
}

    @property
    def name(self)->str:
        """Return the name of the scanner"""
        return "HTTP Methods"
    
    def scan(self, target:Target)->ScanResult:
        """Scan the target website's HTTP methods"""
        start_time=time.perf_counter()
        findings:list[Finding]=[]

        try:
            logger.info("Scanning HTTP methods for %s",target.url)
            response=requests.options(target.url,timeout=10)

        except requests.exceptions.RequestException as error:
            logger.error("HTTP methods scan failed: %s",error)

            findings.append(
                Finding(
                    title="HTTP Methods Scan failed",
                    severity="Informational",
                    description=str(error),
                    recommendation="Verify that the target URL is valid and reachable.",
                )
            )

        else:
            allowed_methods=response.headers.get("Allow","")
            allowed_methods={
                method.strip().upper()
                for method in allowed_methods.split(",")
                if method.strip()
            }

            for method,detail in self.RISKY_METHODS.items():
                if method in allowed_methods:
                    findings.append(
                        Finding(
                            title=f"{method} method enabled",
                            severity=detail["severity"],
                            description=f"The server allows the HTTP {method} method.",
                            recommendation=detail["recommendation"],
                        )
                    )

            

        end_time=time.perf_counter()

        return ScanResult(
            module=self.name,
            findings=findings,
            execution_time=end_time-start_time
        )