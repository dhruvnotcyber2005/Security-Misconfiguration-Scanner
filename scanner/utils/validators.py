"""
Utitlity functions for validating and normalising URLs
"""

from urllib.parse import urlparse

def normalise_url(url:str)->str:
    """
        Normalising a user-given URL
        Return value=> a normalised URL
        Error=> If URL is invalid, raise ValueError
    """

    url=url.strip()

    if not url:
        raise ValueError("URL can't be empty")
    
    if not url.startswith(("http://","https://")):
        url=f"https://{url}"
    
    parsed=urlparse(url)

    if not parsed.netloc:
        raise ValueError("Invalid URL")
    
    normalised=parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower()
    ).geturl()

    if normalised.endswith("/") and parsed.path=="/":
        normalised=normalised[:-1]

    return normalised


