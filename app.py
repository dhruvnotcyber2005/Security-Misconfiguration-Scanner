from scanner.core.target import Target
from scanner.core.engine import ScanEngine

from scanner.modules.headers import HeaderScanner
from scanner.modules.tls import TLSScanner
from scanner.modules.methods import MethodsScanner
from scanner.modules.server import ServerScanner

from scanner.reporting.report_generator import ReportGenerator

target=Target(url="https://boat-lifestyle.com")

scanners=[
    HeaderScanner(),
    TLSScanner(),
    MethodsScanner(),
    ServerScanner()
]

engine=ScanEngine(scanners)

results=engine.run(target)

report=ReportGenerator.generate(target, results)

print(report)

with open("report.txt","w",encoding="utf-8") as report_file:
    report_file.write(report)