"""
Target model for the Security Misconfiguration Scanner
Represents a web application to be scanned
"""

from dataclasses import dataclass

@dataclass
class Target:
    """
    Represents a scan target
    """
    url:str
    