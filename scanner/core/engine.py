"""
Scan engine responsible for coordinating the execution of scanner modules.
"""

from scanner.core.target import Target
from scanner.core.scanner import ScannerModule
from scanner.reporting.reporting_models import ScanResult,Finding
from scanner.utils.logger import logger

import time

class ScanEngine:
    """Coordinates the execution of all scanner modules."""

    def __init__(self,scanners:list[ScannerModule]):
        """Initialise the scan engine with the scanner modules to execute"""
        self._scanners=scanners

    def run(self,target:Target)->list[ScanResult]:
        logger.info("Starting security scan.")
        results=[]

        for scanner in self._scanners:
            start_time=time.perf_counter()
            logger.info("Running %s.", scanner.name)
            try:
                scan_result=scanner.scan(target)
                results.append(scan_result)

            except Exception as error:
                execution_time=time.perf_counter()-start_time
                logger.exception("Unexpected error while running %s",scanner.name)
                results.append(
                    self._create_failure_result(scanner,error,execution_time)
                )

        logger.info("Security scan completed")

        return results
    
    def _create_failure_result(self,scanner:ScannerModule,error:Exception,execution_time:float)->ScanResult:
        """
        Create a ScanResult representing an unexpected scanner failure.
        """

        finding=Finding(
            title=f"{scanner.name} Execution Failed",
            severity="Informational",
            description=(
                f"The {scanner.name} encountered an unexpected internal "
                f"error while scanning the target.\n"
                f"Error: {error}"
            ),
            recommendation=(
                "Review the application logs for additional details "
                "about this internal error."
            )
        )
        return ScanResult(
            module=scanner.name,
            findings=[finding],
            execution_time=execution_time
        )