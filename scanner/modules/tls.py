#Scanner for TLS certificates.

import socket
import ssl
import time 

from scanner.core.scanner import ScannerModule
from scanner.core.target import Target
from scanner.reporting.reporting_models import Finding,ScanResult
from scanner.utils.logger import logger
from urllib.parse import urlparse
from pprint import pprint

class TLSScanner(ScannerModule):
    @property
    def name(self)->str:
        return "TLS Certificate"
    
    def _get_certificate(self,hostname:str):
        #Connect to the server and retrieve its certificate
        context=ssl.create_default_context()
        with socket.create_connection((hostname,443)) as sock:
            with context.wrap_socket(sock,server_hostname=hostname) as secure_socket:
                return secure_socket.getpeercert()

    def scan(self, target:Target)->ScanResult:
        #Execute TLS Scane
        start_time=time.perf_counter()
        findings:list[Finding]=[]
        logger.info("Scanning TLS certificate for %s", target.url)
        hostname=urlparse(target.url).hostname
        certificate=self._get_certificate(hostname)

        pprint(certificate)

        return ScanResult(
            module=self.name,
            findings=findings,
            execution_time=time.perf_counter() - start_time,
)