"""Brunata Online API Client"""

import logging

from libs.brunata.api import BrunataOnlineApiClient as ApiClient

TIMEOUT = 10
_LOGGER: logging.Logger = logging.getLogger(__package__)


class BrunataOnlineApiClient:
    """Brunata Online API Client."""

    def __init__(self, username: str, password: str, client: ApiClient) -> None:
        """Sample API Client."""
        self._username = username
        self._password = password
        self._session = client

    def async_get_data(self) -> dict:
        """Get data from the API."""
        url = "https://jsonplaceholder.typicode.com/posts/1"
        return url

    def async_set_title(self, value: str) -> None:
        """Get data from the API."""
        url = "https://jsonplaceholder.typicode.com/posts/1"
        return url
