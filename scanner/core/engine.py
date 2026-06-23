# Scan engine for executing scanner modules.

from scanner.core.scanner import ScannerModule
from scanner.core.target import Target

class ScanEngine:
    #Coordinates execution of scanner modules.
    
    def __init__(self,scanners:list[ScannerModule]):
        # Initialise the scan engine
        self.scanners=scanners

    def run(self,target:Target):
        """
        Execute every scanner
        Returns a list containing results from every scanner
        """

        results=[]

        for scanner in self.scanners:
            result=scanner.scan(target)
            results.append(result)

        return results