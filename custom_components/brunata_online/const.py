"""Constants for Brunata Online."""
# Base component constants
NAME = "Brunata Online"
DOMAIN = "brunata_online"
DOMAIN_DATA = f"{DOMAIN}_data"
VERSION = "0.9.0"

ATTRIBUTION = "Data provided by http://jsonplaceholder.typicode.com/"
ISSUE_URL = "https://github.com/YukiElectronics/brunata-online/issues"

# Icons
ICON = "mdi:format-quote-close"

# Device classes
BINARY_SENSOR_DEVICE_CLASS = "connectivity"

# Platforms
BINARY_SENSOR = "binary_sensor"
SENSOR = "sensor"
SWITCH = "switch"
PLATFORMS = [BINARY_SENSOR, SENSOR, SWITCH]

# API Constants
OAUTH2_PROFILE = "B2C_1_signin_username"
B2C_URL = f"https://brunatab2cprod.b2clogin.com/brunatab2cprod.onmicrosoft.com/{OAUTH2_PROFILE}"
BASE_URL = "https://online.brunata.com/online-webservice/v1/rest"

OAUTH2_URL = f"{B2C_URL}/oauth2/v2.0"
CLIENT_ID = "e1d10965-78dc-4051-a1e5-251483e74d03"
REDIRECT = "https://online.brunata.com/auth-response"

# Default headers
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en",
    "Connection": "keep-alive",
}

# Configuration and options
CONF_ENABLED = "enabled"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"

# Defaults
DEFAULT_NAME = DOMAIN


STARTUP_MESSAGE = f"""
-------------------------------------------------------------------
{NAME}
Version: {VERSION}
This is a custom integration!
If you have any issues with this you need to open an issue here:
{ISSUE_URL}
-------------------------------------------------------------------
"""
