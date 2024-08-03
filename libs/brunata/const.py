"""Constants used by the Brunata API."""

from enum import Enum

# API Constants
BASE_URL = "https://online.brunata.com"
OAUTH2_PROFILE = "B2C_1_signin_username"
AUTHN_URL = f"https://brunatab2cprod.b2clogin.com/brunatab2cprod.onmicrosoft.com/{OAUTH2_PROFILE}"
API_URL = f"{BASE_URL}/online-webservice/v1/rest"

OAUTH2_URL = f"{AUTHN_URL}/oauth2/v2.0"
CLIENT_ID = "e1d10965-78dc-4051-a1e5-251483e74d03"
REDIRECT = f"{BASE_URL}/auth-response"

CONSUMPTION_URL = f"{BASE_URL}/consumption-overview"

# Default headers
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
        (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en",
    "Connection": "keep-alive",
}


class Consumption(Enum):
    """Enum for the different types of consumption."""

    HEATING = 1
    WATER = 2
    ELECTRICITY = 3


class Interval(Enum):
    """Enum for the different types of intervals."""

    DAY = "D"
    MONTH = "M"
