"""Brunata Online API Client"""

import base64
from datetime import datetime, timedelta
import hashlib
import logging
import os
import re
import urllib.parse

from requests import Session, Response, HTTPError

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
        self._power = {}
        self._water = {}
        self._heating = {}
        self._tokens = {}
        self._session.headers.update(HEADERS)

    def _is_token_valid(self, token: str) -> bool:
        if not self._tokens:
            return False
        match token:
            case "access_token":
                ts = self._tokens.get("expires_on")
                if datetime.fromtimestamp(ts) < datetime.now():
                    return False
            case "refresh":
                ts = self._tokens.get("refresh_token_expires_on")
                if datetime.fromtimestamp(ts) < datetime.now():
                    return False
        return True

    def _renew_tokens(self) -> dict:
        if self._is_token_valid("access_token"):
            _LOGGER.debug(
                "Token is not expired, expires in %d seconds",
                self._tokens.get("expires_on") - int(datetime.now().timestamp()),
            )
            return self._tokens
        # Get OAuth 2.0 token object
        try:
            tokens = self.api_wrapper(
                method="POST",
                url=f"{OAUTH2_URL}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._tokens.get("refresh_token"),
                    "CLIENT_ID": CLIENT_ID,
                },
            )
        except HTTPError as error:
            _LOGGER.error("An error occurred while trying to renew tokens: %s", error)
            return {}
        return tokens.json()

    def _b2c_auth(self) -> dict:
        # Initialize challenge values
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(code_challenge).decode("utf-8").replace("=", "")
        )
        # Initial authorization call
        req_code = self.api_wrapper(
            method="GET",
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
            method="POST",
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
        try:
            req_auth = self.api_wrapper(
                method="GET",
                url=f"{B2C_URL}/api/CombinedSigninAndSignup/confirmed",
                params={
                    "rememberMe": False,
                    "csrf_token": csrf_token,
                    "tx": transId,
                    "p": OAUTH2_PROFILE,
                },
                allow_redirects=False,
            )
        except HTTPError as error:
            _LOGGER.error(
                "An error has occurred while attempting to authenticate: %s", error
            )
            return {}
        redirect = req_auth.headers["Location"]
        assert redirect.startswith(REDIRECT)
        auth_code = urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)[
            "code"
        ][0]
        # Get OAuth 2.0 token object
        tokens = self.api_wrapper(
            method="POST",
            url=f"{OAUTH2_URL}/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT,
                "code": auth_code,
                "code_verifier": code_verifier,
            },
        )
        return tokens.json()

    def get_tokens(self) -> None:
        """Get access/refresh tokens using credentials or refresh token."""
        # Check values
        if self._is_token_valid("refresh_token"):
            tokens = self._renew_tokens()
        else:
            tokens = self._b2c_auth()
        # Ensure validity of tokens
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
                        "refresh_token_expires_on": int(datetime.now().timestamp())
                        + tokens.get("refresh_token_expires_in")
                    }
                )
            self._tokens.update(tokens)
        else:
            self._tokens = {}
            _LOGGER.error("Failed to get tokens")
            raise Exception("Failed to get tokens")

    def get_meters(self) -> None:
        self.get_tokens()
        meters = self.api_wrapper(
            method="GET",
            url=f"{BASE_URL}/consumer/superallocationunits",
            headers={
                "Referer": "https://online.brunata.com/consumption-overview",
            },
        ).json()
        water_units = []
        heating_units = []
        power_units = []
        for meter in meters:
            match meter.get("superAllocationUnit"):
                case 1:  # Heating
                    heating_units += meter.get("allocationUnits")
                case 2:  # Water
                    water_units += meter.get("allocationUnits")
                case 3:  # Electricity
                    power_units += meter.get("allocationUnits")
        _LOGGER.info("Meter info: %s", str(meters))
        init = {"Meters": {"Day": {}, "Month": {}}}
        if heating_units:
            _LOGGER.debug("🔥 Heating meter(s) found")
            self._heating.update(init)
            self._heating.update({"Units": heating_units})
        if water_units:
            _LOGGER.debug("💧 Water meter(s) found")
            self._water.update(init)
            self._water.update({"Units": water_units})
        if power_units:
            _LOGGER.debug("⚡ Energy meter(s) found")
            self._power.update(init)
            self._power.update({"Units": power_units})

    def start_of_interval(self, interval: Interval) -> str:
        """Returns start of year if interval is "M", otherwise start of month"""
        start = datetime.now()
        if interval is Interval.MONTH:
            start = start.replace(month=1)
        start = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return f"{start.isoformat()}.000Z"

    def end_of_interval(self, interval: Interval) -> str:
        """Returns end of year if interval is "M", otherwise end of month"""
        end = datetime.now()
        if interval is Interval.MONTH:
            end = end.replace(month=12)
        end = end.replace(day=28) + timedelta(days=4)
        end -= timedelta(days=end.day)
        end = end.replace(hour=23, minute=59, second=59, microsecond=0)
        return f"{end.isoformat()}.999Z"

    def get_consumption(self, _type: ConsumptionType, interval: Interval) -> None:
        self.get_tokens()
        match _type:
            case ConsumptionType.ELECTRICITY:
                usage = self._power
            case ConsumptionType.WATER:
                usage = self._water
            case ConsumptionType.HEATING:
                usage = self._heating
        if not usage:
            _LOGGER.debug("No %s meter was found", _type.name.lower())
            return
        consumption = [
            self.api_wrapper(
                method="GET",
                url=f"{BASE_URL}/consumer/consumption",
                params={
                    "startdate": self.start_of_interval(interval),
                    "enddate": self.end_of_interval(interval),
                    "interval": interval.value,
                    "allocationunit": unit,
                },
                headers={
                    "Referer": f"https://online.brunata.com/consumption-overview/{_type.name.lower()}",
                },
            ).json()
            for unit in usage["Units"]
        ]
        # Add all metrics that are not None
        usage["Meters"][interval.name.capitalize()].update(
            {
                meter.get("meter").get("meterId")
                or index: {
                    "Name": meter.get("meter").get("placement") or index,
                    "Values": {
                        entry.get("fromDate")[
                            : 10 if interval is Interval.DAY else 7
                        ]: entry.get("consumption")
                        for entry in meter["consumptionValues"]
                        if entry.get("consumption") is not None
                    },
                }
                for lines in consumption
                for index, meter in enumerate(lines["consumptionLines"])
            }
        )

    def api_wrapper(self, **args) -> Response:
        """Get information from the API."""
        http = self._session.request(**args)
        http.raise_for_status()
        return http
