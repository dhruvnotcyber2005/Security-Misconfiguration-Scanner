# Base scanner interface.

from abc import ABC, abstractmethod
from scanner.core.target import Target

class ScannerModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        #Human-readable scanner name
        pass

    @abstractmethod
    def scan(self,target:Target):
        """
        Execute the scan
        Returns the scan results
        """
        pass