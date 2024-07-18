""" Brunata Online API Client """

import base64
from datetime import datetime, timedelta
import hashlib
import logging
import os
import re
import urllib.parse

from requests import Session, Response

from .const import (
    B2C_URL,
    BASE_URL,
    CLIENT_ID,
    HEADERS,
    OAUTH2_PROFILE,
    OAUTH2_URL,
    REDIRECT,
    ConsumptionType,
    Interval,
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

    def get_tokens(self) -> None:
        # Check values
        if (
            self._tokens
            and datetime.fromtimestamp(self._tokens.get("refresh_token_expires_on"))
            > datetime.now()
        ):
            if datetime.fromtimestamp(self._tokens.get("expires_on")) > datetime.now():
                _LOGGER.debug(
                    "Token is not expired, expires in %d seconds",
                    self._tokens.get("expires_on") - int(datetime.now().timestamp()),
                )
                return
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
            if not tokens.get("access_token"):
                _LOGGER.error("Failed to renew existing tokens")
                self._tokens = {}
                return
        else:
            # Initialize challenge values
            code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
            code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
            code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            code_challenge = (
                base64.urlsafe_b64encode(code_challenge)
                .decode("utf-8")
                .replace("=", "")
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
            tokens = self.api_wrapper(
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
        if tokens.get("access_token"):
            # Add access token to session headers
            self._session.headers.update(
                {
                    "Authorization": f"{tokens.get('token_type')} {tokens.get('access_token')}",
                }
            )
            # Calculate refresh expiry
            if tokens.get("refresh_token") != self._tokens.get("refresh_token"):
                tokens.update(
                    {
                        "refresh_token_expires_on": int(
                            datetime.datetime.now().timestamp()
                        )
                        + tokens.get("refresh_token_expires_in")
                    }
                )
            self._tokens.update(tokens)
        else:
            _LOGGER.error("Failed to get tokens")
            self._tokens = {}

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
        if ConsumptionType.POWER in units:
            _LOGGER.debug("Energy meter(s) found ⚡")
            self._power = True
        if ConsumptionType.WATER in units:
            _LOGGER.debug("Water meter(s) found 💧")
            self._water = True
        if ConsumptionType.HEATING in units:
            _LOGGER.debug("Heating meter(s) found 🔥")
            self._heating = True
        return meters or {}

    def start_of_interval(self, interval: Interval) -> str:
        """Returns start of year if interval is "M", otherwise start of month"""
        start = datetime.now()
        if interval is Interval.MONTH:
            start.replace(month=1)
        start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return f"{start.isoformat()}.000Z"

    def end_of_interval(self, interval: Interval) -> str:
        """Returns end of year if interval is "M", otherwise end of month"""
        end = datetime.now()
        if interval is Interval.MONTH:
            end.replace(month=12)
        end.replace(day=28) + timedelta(days=4)
        end -= timedelta(days=end.day)
        end = end.replace(hour=23, minute=59, second=59, microsecond=0)
        return f"{end.isoformat()}.999Z"

    def get_consumption(self, unit: ConsumptionType, interval: Interval) -> dict | None:
        match (unit):
            case ConsumptionType.POWER:
                if not self._power:
                    _LOGGER.debug("No power meter was found 🌃")
                    return
            case ConsumptionType.WATER:
                if not self._water:
                    _LOGGER.debug("No water meter was found 🏜️")
                    return
            case ConsumptionType.HEATING:
                if not self._heating:
                    _LOGGER.debug("No heating meter was found ❄️")
                    return
        consumption = self.api_wrapper(
            "GET",
            url=f"{BASE_URL}/consumer/consumption",
            params={
                "startdate": self.start_of_interval(interval),
                "enddate": self.end_of_interval(interval),
                "interval": interval,
                "allocationunit": unit,
            },
            headers={
                "Referer": "https://online.brunata.com/consumption-overview",
            },
        ).json()
        _LOGGER.info("This month's daily energy consumption:")
        for e in consumption["consumptionLines"][0]["consumptionValues"]:
            if e.get("consumption") is not None:
                _LOGGER.info("%s: %s kWh", e.get("fromDate")[:10], e.get("consumption"))
        return consumption or {}

    def api_wrapper(self, method: str, **args) -> Response:
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
