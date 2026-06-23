#Data models used throughout the reporting system.

from dataclasses import dataclass,field

@dataclass
class Finding:
    #Represents a single security finding
    title:str
    severity:str
    description:str
    recommendation:str

@dataclass
class ScanResult:
    #Represents the result returned by one scanner module
    module:str
    findings:list[Finding]=field(default_factory=list)
    execution_time:float=0.0