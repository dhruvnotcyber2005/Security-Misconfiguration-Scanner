from scanner.core.target import Target
from scanner.modules.tls import TLSScanner

scanner=TLSScanner()
target=Target("https://boat-lifestyle.com")
result=scanner.scan(target)
print(result)

