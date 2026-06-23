from scanner.core.target import Target
from scanner.modules.headers import HeaderScanner

target = Target("https://example.com")

scanner = HeaderScanner()

result = scanner.scan(target)

print("=" * 70)
print(f"Module         : {result.module}")
print(f"Execution Time : {result.execution_time:.3f} seconds")
print(f"Findings       : {len(result.findings)}")
print("=" * 70)

if not result.findings:
    print("✅ No security header issues found.")
else:
    for i, finding in enumerate(result.findings, start=1):
        print(f"\n[{i}] {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"Description   : {finding.description}")
        print(f"Recommendation: {finding.recommendation}")
        print("-" * 70)