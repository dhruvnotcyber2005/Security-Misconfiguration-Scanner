#Scanner for HTTP Security Headers.

import time
import requests

from scanner.core.scanner import ScannerModule
from scanner.core.target import Target
from scanner.reporting.reporting_models import Finding,ScanResult
from scanner.utils.logger import logger

class HeaderScanner(ScannerModule):
    #Checks recommended headers
    REQUIRED_HEADERS={
        "Content-Security-Policy": "Implement a strong Content Security Policy.",
        "Strict-Transport-Security": "Enable HSTS.",
        "X-Frame-Options": "Prevent clickjacking using X-Frame-Options.",
        "X-Content-Type-Options": "Prevent MIME sniffing using nosniff.",
        "Referrer-Policy": "Configure an appropriate Referrer Policy.",
        "Permissions-Policy": "Restrict browser features."
    }

    @property
    def name(self)->str:
        return "Security Headers"
    
    def scan(self, target: Target) -> ScanResult:
        start_time = time.perf_counter()
        findings: list[Finding] = []

        try:
            logger.info("Scanning security headers for %s", target.url)

            response = requests.get(target.url, timeout=10)
            headers = response.headers

        except requests.exceptions.RequestException as error:
            logger.error("Header scan failed: %s", error)

            return ScanResult(
                module=self.name,
                findings=[
                    Finding(
                        title="Header Scan Failed",
                        severity="Info",
                        description=str(error),
                        recommendation="Verify that the target is reachable.",
                    )
                ],
                execution_time=time.perf_counter() - start_time,
            )

        for header, recommendation in self.REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        title=f"Missing {header}",
                        severity="Medium",
                        description=f"{header} header is not present.",
                        recommendation=recommendation,
                    )
                )

        return ScanResult(
            module=self.name,
            findings=findings,
            execution_time=time.perf_counter() - start_time,
        )