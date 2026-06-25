"""
Target model for the Security Misconfiguration Scanner
Represents a web application to be scanned
"""

from dataclasses import dataclass
from urllib.parse import urlparse,urlunparse

@dataclass
class Target:
    """
    Represents a scan target
    """
    url:str

    def __post_init__(self)->None:
        """
        Validate and normalise the target URL after initialisation
        """
        self.url=self._normalise_and_validate(self.url)

    def _normalise_and_validate(self,url:str)->str:
        """
        Validate and normalise the target URL
        """
        url=url.strip()

        if not url:
            raise ValueError("Target URL can't be empty")
        
        if "://" not in url:
            url=f"https://{url}"

        parsed=urlparse(url)

        if parsed.scheme.lower() not in ("http","https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported")
        
        if parsed.hostname is None:
            raise ValueError("Invalid URL: Hostname is missing")
        
        scheme=parsed.scheme.lower()
        hostname=parsed.hostname.lower()

        netloc=hostname

        if parsed.port:
            netloc+=f":{parsed.port}"

        path=parsed.path

        if path=="/":
            path=""
        
        normalised_url=urlunparse(
            (
                scheme,
                netloc,
                path,
                "",
                parsed.query,
                "",
            )
        )

        return normalised_url