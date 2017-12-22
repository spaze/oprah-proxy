#!/usr/bin/env python3

import base64
import hashlib
import uuid
import logging
import os
import re
import time
import hashlib
import threading
import warnings

from base64 import b64encode


try:
    from requests.auth import AuthBase
    from requests.compat import urlparse, str, basestring
    from requests.cookies import extract_cookies_to_jar
    from requests.utils import parse_dict_header
    import requests
except ImportError:
    logging.error('Cannot import requests')
    logging.debug('Please install Requests for Python 3, see '
                  'http://docs.python-requests.org/en/master/user/install/ or use your '
                  'favorite package manager (e.g. apt-get install python3-requests)')
    exit(2)
	
# HTTPDigestAuth class from requests library https://github.com/requests/requests
# Copyright 2017 Kenneth Reitz, licensed under Apache License 2.0
# extended to support SHA-256 digest (needed for surfeasy api)

class HTTPDigestAuth2(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = username
        self.password = password
        # Keep state in per-thread local storage
        self._thread_local = threading.local()

    def init_per_thread_state(self):
        # Ensure state is initialized just once per-thread
        if not hasattr(self._thread_local, 'init'):
            self._thread_local.init = True
            self._thread_local.last_nonce = ''
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    def build_digest_header(self, method, url):
        """
        :rtype: str
        """

        realm = self._thread_local.chal['realm']
        nonce = self._thread_local.chal['nonce']
        qop = self._thread_local.chal.get('qop')
        algorithm = self._thread_local.chal.get('algorithm')
        opaque = self._thread_local.chal.get('opaque')
        hash_utf8 = None

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8
        elif _algorithm == 'SHA-256':
            def sha256_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha256(x).hexdigest()
            hash_utf8 = sha256_utf8
        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = urlparse(url)
        #: path is request-uri defined in RFC 2616 which should not be empty
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += '?' + p_parsed.query

        A1 = '%s:%s:%s' % (self.username, realm, self.password)
        A2 = '%s:%s' % (method, path)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = '%08x' % self._thread_local.nonce_count
        s = str(self._thread_local.nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')
        s += os.urandom(8)

        cnonce = (hashlib.sha1(s).hexdigest()[:16])
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s' % (HA1, nonce, cnonce))

        if not qop:
            respdig = KD(HA1, "%s:%s" % (nonce, HA2))
        elif qop == 'auth' or 'auth' in qop.split(','):
            noncebit = "%s:%s:%s:%s:%s" % (
                nonce, ncvalue, cnonce, 'auth', HA2
            )
            respdig = KD(HA1, noncebit)
        else:
            # XXX handle auth-int.
            return None

        self._thread_local.last_nonce = nonce

        # XXX should the partial digests be encoded too?
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (self.username, realm, nonce, path, respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if entdig:
            base += ', digest="%s"' % entdig
        if qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)

    def handle_redirect(self, r, **kwargs):
        """Reset num_401_calls counter on redirects."""
        if False and r.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, r, **kwargs):
        """
        Takes the given response and tries digest-auth, if needed.
        :rtype: requests.Response
        """

        # If response is not 4xx, do not auth
        # See https://github.com/requests/requests/issues/3772
        if not 400 <= r.status_code < 500:
            self._thread_local.num_401_calls = 1
            return r

        if self._thread_local.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request.body.seek(self._thread_local.pos)
        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and self._thread_local.num_401_calls < 2:

            self._thread_local.num_401_calls += 1
            pat = re.compile(r'digest ', flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub('', s_auth, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Authorization'] = self.build_digest_header(
                prep.method, prep.url)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):
        # Initialize per-thread state, if needed
        self.init_per_thread_state()
        # If we have a saved nonce, skip the 401
        if self._thread_local.last_nonce:
            r.headers['Authorization'] = self.build_digest_header(r.method, r.url)
        try:
            self._thread_local.pos = r.body.tell()
        except AttributeError:
            # In the case of HTTPDigestAuth being reused and the body of
            # the previous request was a file-like object, pos has the
            # file position of the previous body. Ensure it's set to
            # None.
            self._thread_local.pos = None
        r.register_hook('response', self.handle_401)
        r.register_hook('response', self.handle_redirect)
        self._thread_local.num_401_calls = 1

        return r

    def __eq__(self, other):
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other
class OprahProxy:
    """ Everybody gets a proxy! """

    client_type = ''
    client_key = ''
    session = None
    device_id = ''
    device_id_hash = ''
    device_password = ''

    def __init__(self, client_type, client_key):
        self.client_type = client_type
        self.client_key = client_key
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = HTTPDigestAuth2(client_type, client_key)

    def post(self, url, data):
        headers = {'SE-Client-Type': self.client_type,
                   'SE-Client-API-Key': self.client_key,
                   'SE-Operating-System': 'Windows'}

        result = self.session.post('https://api.surfeasy.com%s' % url, data,
                                   headers=headers).json()
        
        code = list(result['return_code'].keys())[0]
        if code != '0':
            logging.debug('ERROR: %s' % result['return_code'][code])
            exit(1)
        return result

    def register_subscriber(self):
        logging.debug('Call register_subscriber')
        email = '%s@%s.surfeasy.vpn' % (uuid.uuid4(), self.client_type)
        password = uuid.uuid4()
        password_hash = hashlib.sha1(
            str(password).encode('ascii')).hexdigest().upper()
        logging.debug('Your SurfEasy email: %s' % email)
        logging.debug('Your SurfEasy password: %s' % password)
        logging.debug('Your SurfEasy password hash: %s' % password_hash)
        logging.debug("These are not the credentials you are looking for "
                      "(you won't probably need these, ever)")

        data = {'email': email,
                'password': password_hash}
        result = self.post('/v4/register_subscriber', data)
        logging.debug('Subscriber registered')
        return result

    def register_device(self):
        logging.debug('Call register_device')
        data = {'client_type': self.client_type,
                'device_hash': '4BE7D6F1BD040DE45A371FD831167BC108554111',
                'device_name': 'Opera-Browser-Client'}

        result = self.post('/v4/register_device', data)
        self.device_id = result['data']['device_id']
        logging.debug('Device id: %s' % self.device_id)
        self.device_id_hash = hashlib.sha1(
            str(self.device_id).encode('ascii')).hexdigest().upper()
        self.device_password = result['data']['device_password']
        logging.debug('Device registered')

    def geo_list(self):
        logging.debug('Call geo_list')
        data = {'device_id': self.device_id_hash}
        result = self.post('/v4/geo_list', data)
        codes = []
        for geo in result['data']['geos']:
            codes.append(geo['country_code'])
            logging.info('Supported country: %s %s' %
                         (geo['country_code'], geo['country']))
        logging.debug('Geo list fetched')
        return codes

    def discover(self, country_code):
        proxies = [{
            'hostname': '%s.opera-proxy.net' % country_code.lower(),
            'port': 443
        }]
        logging.info('Proxy in %s %s:%s' % (country_code, proxies[0]['hostname'], proxies[0]['port']))
        return proxies

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)-8s %(message)s'
    )

    logging.debug('++++++++++++++++++++++++++=======================~~~~~~~::::')
    logging.debug(',..,,,.,,...,,,.,,,,,,,,,,............,.....,.,,::::~~======')
    logging.debug(',,,,,:,,,,,,,,,,,,,,                    ,.,,,,,,,,,,,,,....~')
    logging.debug('~~~~~~~:::::::::::::  YOU GET A PROXY!  ,,,,,,,,,,,,,,,,,:~=')
    logging.debug('~~===~~~~::::::::::.                    ,,,,,,,,,,,,,,,~~~:~')
    logging.debug('::~:::::::::::::::,,...,~=::~=~:.....,,,,,,,,,,,,,,,:~:~:,::')
    logging.debug('??+=..,++++++++++=.....:===I+~=~....,,~~=~~~~~~~:~====~,,::~')
    logging.debug('::~....,...............~=~~~~:=~,...,.~~~======~==++=~:====+')
    logging.debug('::~...,:,,,,,,,,.......:==~+=:~:,.....,,,,,,,~~~====~,,,,,,,')
    logging.debug(':::~~~:,::,,::::,......+~~===~:,.....,,,,,,~~~~~==~,,,,....,')
    logging.debug('~:~:,,,,,:::::,..........~~::~,:....:~~~~~::::~:::::,,,,,,,,')
    logging.debug('~...~~~,,::~~::~:........~~~:~::.:,,:~::::::::::::::::::::::')
    logging.debug('+..???+?~,::::::::::::~:~::~~~:~::::::::::::::::~~=~~~~~~~~=')
    logging.debug('...?????+?,.:::::::::::~~:~~::~:::::::::::::::,~++++++++++++')
    logging.debug('?=??????+??~,::::::::~~~~~~~~~~::::::::::::::,=+++++++++++++')
    logging.debug('????????????::::::,::~~~~~~~~~~:::::::::::::,+++++++++++++++')
    logging.debug('??+??????????:,,::,:::~~~~~~~:::::::::::::,+++++++++++++++++')
    logging.debug('??????????????+,,,,:::~~,~~~~~:::=,:::::,?+?++++++++++++++++')
    logging.debug('????????????????+,:::~~:,~~~~~~~~:~::::=+??+?++?++++++++++++')
    logging.debug('??????????????????:::~~~~~~~~~~~:::::::???????++++++++++++++')
    logging.debug('??????????????????=:::~~~~~~~~~::::::::+??????+++++?+?++++++')
    logging.debug('=+==+====++++++++==:::~:,~~~~~:::,::::~====~~::::,,...,:~~=+')
    logging.debug('++++++++++++===++++::~:~~~~~~::::~::::=+++++++++++++========')
    logging.debug('=====+++++=====++++:~:~~~~~~::::::::::~++===================')
    logging.debug('+++==+======+++                           ==================')
    logging.debug('~~~~==========~  EVERYBODY GETS A PROXY!  ~~~~~~~~~~~~~~~~~~')
    logging.debug('~~~~~~~~~~~===~                           ~~~~~~~~~~~~~~~~~~')
    logging.debug('=============++===:::::::::::::::::::::~~~~~~~~~~~~~~~~~~~:~')
    logging.debug('https://github.com/spaze/oprah-proxy :::==~=~~~~~~~~=~~~~~~~')

    key = '94938A583190AF928BC4FA2279DC10AE8FABB5E9E21826C9092B404D24B949A0'
    client = 'se0316'
    op = OprahProxy(client, key)
    op.register_subscriber()
    op.register_device()
    example_proxy = None
    for country_code in op.geo_list():
        for item in op.discover(country_code):
            if not example_proxy and item['port'] == 443:
                example_proxy = '%s:%s' % (item['hostname'], item['port'])

    logging.info('Pick a proxy from the list above and use these credentials:')
    logging.info('Username: %s' % op.device_id_hash)
    logging.info('Password: %s' % op.device_password)
    creds = ('%s:%s' % (op.device_id_hash, op.device_password)).encode('ascii')
    header = 'Proxy-Authorization: Basic %s' % base64.b64encode(creds).decode('ascii')
    logging.info('HTTP header %s' % header)
    logging.debug('Example bash command: URL="http://www.opera.com" PROXY=%s '
                  'HEADER="%s"; echo -e "GET $URL HTTP/1.0\\n$HEADER\\n\\n" | '
                  'openssl s_client -connect $PROXY -ign_eof' %
                  (example_proxy, header))
    logging.debug('For PAC-file for other browsers see '
                  'https://github.com/spaze/oprah-proxy#usage-with-other-browsers')

