""" Brunata Online API Client """

import base64
from datetime import datetime, timedelta
import hashlib
import logging
import os
import re
import urllib.parse

from requests import Session

from .const import (
    B2C_URL,
    BASE_URL,
    CLIENT_ID,
    HEADERS,
    OAUTH2_PROFILE,
    OAUTH2_URL,
    REDIRECT,
)

_LOGGER: logging.Logger = logging.getLogger(__package__)


class BrunataOnlineApiClient:
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._session = Session()
        self._power = False
        self._water = False
        self._heating = False
        self._tokens = {}
        self._session.headers.update(HEADERS)

    def get_new_tokens(self) -> None:
        # Check values
        if self._tokens:
            if datetime.fromtimestamp(self._tokens.get("expires_on")) > datetime.now():
                _LOGGER.debug(
                    "Token is not expired, expires in %d seconds",
                    self._tokens.get("expires_on") - int(datetime.now().timestamp()),
                )
            else:  # TODO: Stitch together some code to check expiry of refresh token
                _LOGGER.debug("Access Token is expired, continuing")
        # Initialize challenge values
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(code_challenge).decode("utf-8").replace("=", "")
        )
        # Initial authorization call
        req_code = self.api_wrapper(
            "GET",
            url=f"{BASE_URL.replace('webservice', 'auth-webservice')}/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT,
                "scope": f"{CLIENT_ID} offline_access",
                "response_type": "code",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        print(req_code)
        # Get CSRF Token & Transaction ID
        try:
            csrf_token = req_code.cookies.get("x-ms-cpim-csrf")
        except Exception as exception:
            _LOGGER.error("Error while retrieving CSRF Token: %s", exception)
            return
        match = re.search(r"var SETTINGS = (\{[^;]*\});", req_code.text)
        if match:  # Use a little magic to avoid proper JSON parsing ✨
            transId = [
                i for i in match.group(1).split('","') if i.startswith("transId")
            ][0][10:]
            _LOGGER.debug("Transaction ID: %s", transId)
        else:
            _LOGGER.error("Failed to get Transaction ID")
            return
        # Post credentials to B2C Endpoint
        req_auth = self.api_wrapper(
            "POST",
            url=f"{B2C_URL}/SelfAsserted",
            params={
                "tx": transId,
                "p": OAUTH2_PROFILE,
            },
            data={
                "request_type": "RESPONSE",
                "logonIdentifier": self._username,
                "password": self._password,
            },
            headers={
                "Referer": req_code.url,
                "X-Csrf-Token": csrf_token,
                "X-Requested-With": "XMLHttpRequest",
            },
            allow_redirects=False,
        )
        # Get authentication code
        req_auth = self.api_wrapper(
            "GET",
            url=f"{B2C_URL}/api/CombinedSigninAndSignup/confirmed",
            params={
                "rememberMe": False,
                "csrf_token": csrf_token,
                "tx": transId,
                "p": OAUTH2_PROFILE,
            },
            allow_redirects=False,
        )
        redirect = req_auth.headers["Location"]
        assert redirect.startswith(REDIRECT)
        auth_code = urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)[
            "code"
        ][0]
        # Get OAuth 2.0 token object
        result = self.api_wrapper(
            "POST",
            url=f"{OAUTH2_URL}/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT,
                "code": auth_code,
                "code_verifier": code_verifier,
            },
        ).json()
        # Add access token to session headers
        self._session.headers.update(
            {
                "Authorization": f"{result.get('token_type')} {result.get('access_token')}"
            }
        )
        self._tokens = result

    def renew_tokens(self) -> dict | None:
        # Check if token is expired
        if not self._tokens:
            _LOGGER.error("Attempted to renew tokens when no tokens are stored")
            return
        else:
            if datetime.fromtimestamp(self._tokens.get("expires_on")) > datetime.now():
                _LOGGER.debug(
                    "Access token is not expired, expires in %d seconds",
                    self._tokens.get("expires_on") - int(datetime.now().timestamp()),
                )
                return
            else:  # TODO: Implement check of refresh_token expiry
                _LOGGER.warn("Refresh token expiry check not implemented yet")
        # Get OAuth 2.0 token object
        tokens = self.api_wrapper(
            "POST",
            url=f"{OAUTH2_URL}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._tokens.get("refresh_token"),
                "CLIENT_ID": CLIENT_ID,
            },
        ).json()
        if tokens.get("access_token"):
            self._session.headers.update(
                {
                    "Authorization": f"{tokens.get('token_type')} {tokens.get('access_token')}",
                }
            )
            self._tokens = tokens
        return tokens or None

    def get_available_meters(self) -> dict:
        meters = self.api_wrapper(
            "GET",
            url=f"{BASE_URL}/consumer/superallocationunits",
            headers={
                "Referer": "https://online.brunata.com/consumption-overview",
            },
        ).json()
        units = meters[0].get("allocationUnits")
        _LOGGER.info("Meter info:\n%s", str(meters))
        _LOGGER.debug("allocationUnits: %s", str(units))
        # TODO: Check if these values are consistent with other users
        if "E" in units:
            _LOGGER.debug("Energy meter(s) found ⚡")
            self._power = True
        if "V" in units:
            _LOGGER.debug("Water meter(s) found 💧")
            self._water = True
        if "W" in units:
            _LOGGER.debug("Heating meter(s) found 🔥")
            self._heating = True
        return meters or {}

    def start_of_month(self) -> str:
        first_day = datetime.now().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        return f"{first_day.isoformat()}.000Z"

    def end_of_month(self) -> str:
        end = datetime.now().replace(day=28) + timedelta(days=4)
        end -= timedelta(days=end.day)
        end = end.replace(hour=23, minute=59, second=59, microsecond=0)
        return f"{end.isoformat()}.999Z"

    def get_monthly_energy(self) -> dict | None:
        if not self._power:
            _LOGGER.debug("No power meter was found 🌃")
            return
        energy = self.api_wrapper(
            "GET",
            url=f"{BASE_URL}/consumer/consumption",
            params={
                "startdate": self.start_of_month(),
                "enddate": self.end_of_month(),
                "interval": "D",
                "allocationunit": "E",
            },
            headers={
                "Referer": "https://online.brunata.com/consumption-overview/electricity",
            },
        ).json()
        _LOGGER.info("This month's daily energy consumption:")
        for e in energy["consumptionLines"][0]["consumptionValues"]:
            if e.get("consumption") is not None:
                _LOGGER.info("%s: %s kWh", e.get("fromDate")[:10], e.get("consumption"))
        return energy or {}

    def api_wrapper(self, method: str, **args) -> dict:
        """Get information from the API."""
        match method:
            case "GET":
                return self._session.get(**args)
            case "POST":
                return self._session.post(**args)
            case "PUT":
                return self._session.put(**args)
            case "PATCH":
                return self._session.patch(**args)
