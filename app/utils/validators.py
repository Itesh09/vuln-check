from urllib.parse import urlparse

def is_processable_url(url: str) -> bool:
    """
    Checks if a URL is syntactically valid and can be processed.
    """
    try:
        result = urlparse(url)
        # A valid URL should have both a scheme (e.g., http, https) and a network location (e.g., www.example.com)
        # We also want to ensure the scheme is http or https
        if all([result.scheme, result.netloc]) and result.scheme in ["http", "https"]:
            return True
        return False
    except ValueError:
        return False
