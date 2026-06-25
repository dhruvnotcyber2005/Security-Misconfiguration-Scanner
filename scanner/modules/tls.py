"""
Scanner module for checking TLS Certificate
"""

import socket
import ssl
import time

from datetime import datetime,timezone
from urllib.parse import urlparse
from cryptography import x509

from scanner.core.target import Target
from scanner.reporting.reporting_models import Finding,ScanResult
from scanner.core.scanner import ScannerModule
from scanner.utils.logger import logger

class TLSScanner(ScannerModule):
    """Scans a target website for TLS certificate misconfigurations."""
    
    EXPIRY_WARNING_DAYS = 30

    @property
    def name(self)->str:
        """Return the name of the scanner"""
        return "TLS Certificate"
    
    def scan(self, target:Target)->ScanResult:
        """Scan the target website's TLS certificate"""
        start_time=time.perf_counter()
        findings:list[Finding]=[]

        try:
            logger.info("Scanning TLS certificate for %s",target.url)

            parsed_url=urlparse(target.url)
            hostname=parsed_url.hostname
            port=parsed_url.port or 443

            # Disable automatic certificate verification so SentinelScan
            # can inspect expired, self-signed, and otherwise invalid
            # certificates instead of failing the TLS handshake.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE     

            with socket.create_connection((hostname,port),timeout=10) as socket_connection:
                with context.wrap_socket(
                    socket_connection,
                    server_hostname=hostname,
                ) as tls_connection:
                    certificate_bytes = tls_connection.getpeercert(binary_form=True)
                    certificate = x509.load_der_x509_certificate(certificate_bytes)

        except(
            socket.timeout,
            socket.gaierror,
            ConnectionRefusedError,
            ssl.SSLError,
            OSError
        ) as error:
            logger.error("TLS scan failed: %s",error)

            findings.append(
                Finding(
                    title="TLS Scan failed",
                    severity="High",
                    description=str(error),
                    recommendation="Verify that the target supports TLS and is reachable.",
                )
            )

        else:
            expiry_date = certificate.not_valid_after_utc

            current_time=datetime.now(timezone.utc)
            days_until_expiry=(expiry_date-current_time).days

            if days_until_expiry<0:
                findings.append(
                    Finding(
                        title="Expired TLS Certificate",
                        severity="High",
                        description=(
                            f"The TLS certificate expired on "
                            f"{expiry_date.strftime('%d-%m-%Y')}."
                        ),
                        recommendation="Renew and deploy a valid TLS certificate."
                    )
                )
            elif days_until_expiry<=self.EXPIRY_WARNING_DAYS:
                findings.append(
                    Finding(
                        title="TLS Certificate Expiring Soon",
                        severity="Medium",
                        description=(
                            f"The TLS certificate will expire in "
                            f"{days_until_expiry} day(s)."
                        ),
                        recommendation="Renew the TLS certificate before it expires."
                    )
                )

        end_time=time.perf_counter()

        return ScanResult(
            module=self.name,
            findings=findings,
            execution_time=end_time-start_time
        )