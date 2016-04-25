#!/usr/bin/python3

import requests, uuid, hashlib, urllib.parse, base64

class OprahProxy:
	''' Everybody gets a proxy! '''

	client_type = ''

	client_key = ''

	session = None

	device_id = ''

	device_id_hash = ''

	device_password = ''

	example_proxy = None


	def __init__(self, client_type, client_key):
		self.client_type = client_type
		self.client_key = client_key
		self.session = requests.Session()


	def post(self, url, data):
		headers = {
			'SE-Client-Type': self.client_type,
			'SE-Client-API-Key': self.client_key,
		}
		result = self.session.post('https://api.surfeasy.com%s' % url, data, headers = headers).json()
		code = list(result['return_code'].keys())[0]
		if (code != '0'):
			print('ERROR: %s' % result['return_code'][code])
			exit(1);
		return result


	def register_subscriber(self):
		print('DEBUG: Call register_subscriber')
		email_user = uuid.uuid4()
		email = '%s@mailinator.com' % email_user
		password = uuid.uuid4()
		password_hash = hashlib.sha1(str(password).encode('ascii')).hexdigest().upper()
		print('DEBUG: Your SurfEasy email: %s' % email)
		print('DEBUG: Your SurfEasy password: %s' % password)
		print('DEBUG: Your SurfEasy password hash: %s' % password_hash)
		print('DEBUG: Your mailbox: https://mailinator.com/inbox2.jsp?%s' % urllib.parse.urlencode({'public_to': email_user}))
		print('DEBUG: These are not the credentials you are looking for (you won\'t probably need these, ever)')

		data = {
			'email': email,
			'password': password_hash
		}
		result = self.post('/v2/register_subscriber', data)
		print('DEBUG: Subscriber registered')


	def you_get_a_proxy(self):
		print('++++++++++++++++++++++++++=======================~~~~~~~::::')
		print(',..,,,.,,...,,,.,,,,,,,,,,............,.....,.,,::::~~======')
		print(',,,,,:,,,,,,,,,,,,,,                    ,.,,,,,,,,,,,,,....~')
		print('~~~~~~~:::::::::::::  YOU GET A PROXY!  ,,,,,,,,,,,,,,,,,:~=')
		print('~~===~~~~::::::::::.                    ,,,,,,,,,,,,,,,~~~:~')
		print('::~:::::::::::::::,,...,~=::~=~:.....,,,,,,,,,,,,,,,:~:~:,::')
		print('??+=..,++++++++++=.....:===I+~=~....,,~~=~~~~~~~:~====~,,::~')
		print('::~....,...............~=~~~~:=~,...,.~~~======~==++=~:====+')
		print('::~...,:,,,,,,,,.......:==~+=:~:,.....,,,,,,,~~~====~,,,,,,,')
		print(':::~~~:,::,,::::,......+~~===~:,.....,,,,,,~~~~~==~,,,,....,')
		print('~:~:,,,,,:::::,..........~~::~,:....:~~~~~::::~:::::,,,,,,,,')
		print('~...~~~,,::~~::~:........~~~:~::.:,,:~::::::::::::::::::::::')
		print('+..???+?~,::::::::::::~:~::~~~:~::::::::::::::::~~=~~~~~~~~=')
		print('...?????+?,.:::::::::::~~:~~::~:::::::::::::::,~++++++++++++')
		print('?=??????+??~,::::::::~~~~~~~~~~::::::::::::::,=+++++++++++++')
		print('????????????::::::,::~~~~~~~~~~:::::::::::::,+++++++++++++++')
		print('??+??????????:,,::,:::~~~~~~~:::::::::::::,+++++++++++++++++')
		print('??????????????+,,,,:::~~,~~~~~:::=,:::::,?+?++++++++++++++++')
		print('????????????????+,:::~~:,~~~~~~~~:~::::=+??+?++?++++++++++++')
		print('??????????????????:::~~~~~~~~~~~:::::::???????++++++++++++++')
		print('??????????????????=:::~~~~~~~~~::::::::+??????+++++?+?++++++')
		print('=+==+====++++++++==:::~:,~~~~~:::,::::~====~~::::,,...,:~~=+')
		print('++++++++++++===++++::~:~~~~~~::::~::::=+++++++++++++========')
		print('=====+++++=====++++:~:~~~~~~::::::::::~++===================')
		print('+++==+======+++                           ==================')
		print('~~~~==========~  EVERYBODY GETS A PROXY!  ~~~~~~~~~~~~~~~~~~')
		print('~~~~~~~~~~~===~                           ~~~~~~~~~~~~~~~~~~')
		print('=============++===:::::::::::::::::::::~~~~~~~~~~~~~~~~~~~:~')
		print('https://github.com/spaze/oprah-proxy :::==~=~~~~~~~~=~~~~~~~')


	def register_device(self):
		print('DEBUG: Call register_device')
		data = {
			'client_type': self.client_type,
			'device_hash': '4BE7D6F1BD040DE45A371FD831167BC108554111',
			'device_name': 'Opera-Browser-Client'
		}
		result = self.post('/v2/register_device', data)
		self.device_id = result['data']['device_id']
		self.device_id_hash = hashlib.sha1(str(self.device_id).encode('ascii')).hexdigest().upper()
		self.device_password = result['data']['device_password']
		print('DEBUG: Device registered')


	def geo_list(self):
		print('DEBUG: Call geo_list')
		data = {
			'device_id': self.device_id_hash
		}
		result = self.post('/v2/geo_list', data)
		codes = []
		for geo in result['data']['geos']:
			codes.append(geo['country_code'])
			print('INFO: Supported country: %s %s' % (geo['country_code'], geo['country']))
		print('DEBUG: Geo list fetched')
		return codes


	def discover(self, country_code):
		print('DEBUG: Call discover %s' % country_code)
		data = {
			'serial_no': self.device_id_hash,
			'requested_geo': '"%s"' % country_code
		}
		result = self.post('/v2/discover', data)

		for ip in result['data']['ips']:
			for port in ip['ports']:
				if port == 443 and self.example_proxy is None:
					self.example_proxy = '%s:%s' % (ip['ip'], port)
				print('INFO: Proxy in %s %s:%s' % (ip['geo']['country_code'], ip['ip'], port))
		print('DEBUG: Proxies discovered')


	def everybody_gets_a_proxy(self):
		self.register_subscriber()
		self.register_device()
		for country_code in self.geo_list():
			self.discover(country_code)
		print('INFO: Pick a proxy from the list above and use these credentials:')
		print('INFO: Username: %s' % self.device_id_hash)
		print('INFO: Password: %s' % self.device_password)
		creds = ('%s:%s' % (self.device_id_hash, self.device_password)).encode('ascii')
		header = 'Proxy-Authorization: Basic %s' % base64.b64encode(creds).decode('ascii')
		print('INFO: HTTP header %s' % header)
		print('DEBUG: Example bash command: URL="http://www.opera.com" PROXY=%s HEADER="%s"; echo -e "GET $URL HTTP/1.0\\n$HEADER\\n\\n" | openssl s_client -connect $PROXY -ign_eof' % (self.example_proxy, header))
		print('DEBUG: For PAC-file for other browsers see https://github.com/spaze/oprah-proxy#usage-with-other-browsers')


you_get_a_proxy = OprahProxy('se0304', '3690AC1CE5B39E6DC67D9C2B46D3C79923C43F05527D4FFADCC860740E9E2B25')
you_get_a_proxy.you_get_a_proxy()
you_get_a_proxy.everybody_gets_a_proxy()
