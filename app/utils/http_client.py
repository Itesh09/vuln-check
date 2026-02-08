import requests
from requests.exceptions import RequestException
from typing import Dict, Any, Optional

def get_http_client() -> requests.Session:
    """
    Returns a configured requests Session for making HTTP requests.
    This allows for connection pooling and other session-specific configurations.
    """
    session = requests.Session()
    # Configure common headers, timeouts, retries etc.
    session.headers.update({
        "User-Agent": "VulnCheck-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    })
    # Consider adding retry logic with requests.adapters.HTTPAdapter
    return session

def fetch_url(url: str, method: str = "GET", params: Optional[Dict] = None, 
              data: Optional[Dict] = None, json: Optional[Dict] = None, 
              headers: Optional[Dict] = None, timeout: int = 10) -> Optional[requests.Response]:
    """
    Safely fetches a URL using the configured HTTP client.

    Args:
        url: The URL to fetch.
        method: HTTP method (GET, POST, etc.).
        params: Dictionary of URL query parameters.
        data: Dictionary, bytes, or file-like object to send in the body of the request.
        json: A JSON serializable dict to send in the body of the request.
        headers: Dictionary of HTTP headers to send.
        timeout: How many seconds to wait for the server to send data before giving up.

    Returns:
        The requests.Response object if successful, None otherwise.
    """
    session = get_http_client()
    try:
        response = session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            timeout=timeout,
            allow_redirects=True # Generally allow redirects, but scanners might want to control this
        )
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except RequestException as e:
        # Log the error safely without revealing sensitive info
        print(f"HTTP request failed for {url}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during HTTP request for {url}: {e}")
        return None