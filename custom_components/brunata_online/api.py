''' Brunata Online API Client '''
import asyncio
import logging
import socket
import aiohttp
import async_timeout

import base64
import hashlib
import os
import re
import urllib.parse
from datetime import datetime, timedelta
from .const import (
	B2C_URL,
	BASE_URL,
	OAUTH2_URL,
	OAUTH2_PROFILE,
	CLIENT_ID,
	REDIRECT,
	HEADERS
)

TIMEOUT = 10
_LOGGER: logging.Logger = logging.getLogger(__package__)

class BrunataOnlineApiClient:
	def __init__(
		self, username: str, password: str, session: aiohttp.ClientSession
	) -> None:
		"""Sample API Client."""
		self._username = username
		self._password = password
		self._session = session
		self._power = False
		self._water = False
		self._heating = False
		self._tokens = {}
		self._session.headers.update(HEADERS)

	async def get_new_tokens(self) -> dict:
		# Check values
		if self._tokens:
			if datetime.fromtimestamp(self._tokens.get('expires_on')) > datetime.utcnow():
				_LOGGER.debug('Token is not expired, expires in %d seconds',
					self._tokens.get('expires_on') - int(datetime.utcnow().timestamp())
				)
			else:	# TODO: Stitch together some code to check expiry of refresh token
				_LOGGER.debug('Access Token is expired, continuing')
		# Initialize challenge values
		code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
		code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

		code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
		code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
		code_challenge = code_challenge.replace('=', '')

		# Initial authorization call
		req_code = self.api_wrapper('GET',
			url=f'{BASE_URL.replace("webservice","auth-webservice")}/authorize',
			params={
				'CLIENT_ID': CLIENT_ID,
				'REDIRECT_URL': REDIRECT,
				'scope': f'{CLIENT_ID} offline_access',
				'response_type': 'code',
				'code_challenge': code_challenge,
				'code_challenge_method': 'S256',
			},
		)
		# Get CSRF Token & Transaction ID
		csrf_token = req_code.cookies.get('x-ms-cpim-csrf')
		match = re.search(r'var SETTINGS = (\{[^;]*\});', req_code.text)
		if match:	# Use a little magic to avoid proper JSON parsing ✨
			transId = [i for i in match.group(1).split('","') if i.startswith('transId')][0][10:]
			_LOGGER.debug('Transaction ID: %s', transId)
			_LOGGER.debug('Transaction ID TEST: {}', transId)
		else:
			_LOGGER.error('Failed to get Transaction ID')
			return
		# Post credentials to B2C Endpoint
		self.api_wrapper('POST',
			url=f'{B2C_URL}/SelfAsserted',
			params={
				'tx': transId,
				'p': OAUTH2_PROFILE,
			},
			data={
				'request_type': 'RESPONSE',
				'logonIdentifier': self._username,
				'password': self._password,
			},
			headers={
				'Referer': req_code.url,
				'X-Csrf-Token': csrf_token,
				'X-Requested-With': 'XMLHttpRequest',
			},
			allow_redirects=False,
		)
		# Get authentication code
		req_auth = self.api_wrapper('GET',
			url=f'{B2C_URL}/api/CombinedSigninAndSignup/confirmed',
			params={
				'rememberMe': False,
				'csrf_token': csrf_token,
				'tx': transId,
				'p': OAUTH2_PROFILE,
			},
			allow_redirects=False,
		)
		redirect = req_auth.headers['Location']
		assert redirect.startswith(REDIRECT)
		auth_code = urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)['code'][0]
		# Get OAuth 2.0 token object
		result = await self.api_wrapper('POST',
			url=f'{OAUTH2_URL}/token',
			data={
				'grant_type': 'authorization_code',
				'CLIENT_ID': CLIENT_ID,
				'REDIRECT_URL': REDIRECT,
				'code': auth_code,
				'code_verifier': code_verifier,
			},
		).json()
		# Add access token to session headers
		self._session.headers.update({
			'Authorization': f'Bearer {result.get("access_token")}',
		})
		self._tokens = result
		return result

	async def renew_tokens(self) -> dict | None:
		# Check if token is expired
		if not self._tokens:
			_LOGGER.error('Attempted to renew tokens when no tokens are stored')
			return
		else:
			if datetime.fromtimestamp(self._tokens.get('expires_on')) > datetime.utcnow():
				_LOGGER.debug('Access token is not expired, expires in %d seconds',
					self._tokens.get('expires_on') - int(datetime.utcnow().timestamp())
				)
				return
			else:	# TODO: Implement check of refresh_token expiry
				_LOGGER.warn('Refresh token expiry check not implemented yet')
		# Get OAuth 2.0 token object
		tokens = await self.api_wrapper('POST',
			url=f'{OAUTH2_URL}/token',
			data={
				'grant_type': 'refresh_token',
				'refresh_token': self._tokens.get('refresh_token'),
				'CLIENT_ID': CLIENT_ID,
			},
		).json()
		if tokens.get("access_token"):
			self._session.headers.update({
				'Authorization': f'Bearer {tokens.get("access_token")}',
			})
			self._tokens = tokens
		return tokens or None

	async def get_available_meters(self) -> dict:
		meters = await self.api_wrapper('GET',
			url=f'{BASE_URL}/consumer/superallocationunits',
			headers={
				'Referer': 'https://online.brunata.com/consumption-overview',
			},
		).json()
		units = meters[0].get('allocationUnits')
		_LOGGER.info('Meter info:\n%s', str(meters))
		_LOGGER.debug('allocationUnits: %s', str(units))
		if 'E' in units:
			_LOGGER.debug('Energy meter(s) found ⚡')
			self._power = True
		if 'V' in units:
			_LOGGER.debug('Water meter(s) found 💧')
			self._water = True
		if 'W' in units:
			_LOGGER.debug('Heating meter(s) found 🔥')
			self._heating = True
		return meters or {}

	def start_of_month():
		first_day = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
		return f'{first_day.isoformat()}.000Z'

	def end_of_month() -> str:
		end = datetime.utcnow().replace(day=28) + timedelta(days=4)
		end -= timedelta(days=end.day)
		end = end.replace(hour=23, minute=59, second=59, microsecond=0)
		return f'{end.isoformat()}.999Z'

	async def get_monthly_energy(self) -> dict | None:
		if not self._power:
			_LOGGER.debug('No power meter was found 🌃')
			return
		energy = await self.api_wrapper('GET',
			url=f'{BASE_URL}/consumer/consumption',
			params={
				'startdate': self.start_of_month(),
				'enddate': self.end_of_month(),
				'interval': 'D',
				'allocationunit': 'E',
			},
			headers={
				'Referer': 'https://online.brunata.com/consumption-overview/electricity',
			},
		).json()
		_LOGGER.info("This month's energy consumption per day:")
		for e in energy['consumptionLines'][0]['consumptionValues']:
			if e.get('consumption') is not None:
				_LOGGER.info('%s: %s',
					datetime.fromisoformat(e.get('fromDate')).strftime('%B %d, %Y'),
					e.get('consumption')
				)
		return energy or {}

	async def api_wrapper(
		self, method: str, url: str, params: dict = {}, data: dict = {}, headers: dict = {}
	) -> dict:
		"""Get information from the API."""
		try:
			async with async_timeout.timeout(TIMEOUT, loop=asyncio.get_event_loop()):
				match method:
					case 'GET':
						return await self._session.get(url, headers=headers)
					case 'POST':
						return await self._session.post(url, headers=headers, data=data)
					case 'PUT':
						return await self._session.put(url, headers=headers, data=data)
					case 'PATCH':
						return await self._session.patch(url, headers=headers, data=data)

		except asyncio.TimeoutError as exception:
			_LOGGER.error(
				"Timeout error fetching information from %s - %s",
				url,
				exception,
			)

		except (KeyError, TypeError) as exception:
			_LOGGER.error(
				"Error parsing information from %s - %s",
				url,
				exception,
			)
		except (aiohttp.ClientError, socket.gaierror) as exception:
			_LOGGER.error(
				"Error fetching information from %s - %s",
				url,
				exception,
			)
		except Exception as exception:  # pylint: disable=broad-except
			_LOGGER.error("Something really wrong happened! - %s", exception)
