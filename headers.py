import argparse
import http.client
import re
import socket
import ssl
import sys
from urllib.parse import urlparse
import whois
import socket 
import sys


import utils
from constants import DEFAULT_URL_SCHEME, EVAL_WARN


class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass


class SecurityHeaders():
    DEFAULT_TIMEOUT = 10

    # Let's try to imitate a legit browser to avoid being blocked / flagged as web crawler
    REQUEST_HEADERS = {
        'Accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                   'application/signed-exchange;v=b3;q=0.9'),
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                       'Chrome/106.0.0.0 Safari/537.36'),
    }

    SECURITY_HEADERS_DICT = {
        'x-frame-options': {
            'recommended': True,
            'eval_func': utils.eval_x_frame_options,
        },
        'strict-transport-security': {
            'recommended': True,
            'eval_func': utils.eval_sts,
        },
        'content-security-policy': {
            'recommended': True,
            'eval_func': utils.eval_csp,
        },
        'x-content-type-options': {
            'recommended': True,
            'eval_func': utils.eval_content_type_options,
        },
        'x-xss-protection': {
            # X-XSS-Protection is deprecated; not supported anymore, and may be even dangerous in older browsers
            'recommended': False,
            'eval_func': utils.eval_x_xss_protection,
        },
        'referrer-policy': {
            'recommended': True,
            'eval_func': utils.eval_referrer_policy,
        },
        'permissions-policy': {
            'recommended': True,
            'eval_func': utils.eval_permissions_policy,
        },
        'content-type': {
            'recommended': True,
            'eval_func': utils.eval_content_type,
        },
        'set-cookie': {
            'recommended': True,
            'eval_func': utils.eval_set_cookie,
        },
        'access-control-allow-origin': {
            'recommended': True,
            'eval_func': utils.eval_access_control_allow_origin,
        },
        'cross-origin-opener-policy': {
            'recommended': True,
            'eval_func': utils.eval_cross_origin_opener_policy,
        },
        'cross-origin-embedder-policy': {
            'recommended': True,
            'eval_func': utils.eval_cross_origin_embedder_policy,
        },
        'cross-origin-resource-policy': {
            'recommended': True,
            'eval_func': utils.eval_cross_origin_resource_policy,
        },
        'server': {
            'recommended': True,
            'eval_func': utils.eval_server,
        },
        'x-powered-by': {
            'recommended': True,
            'eval_func': utils.eval_x_powered_by,
        },
        'x-dns-prefetch-control': {
            'recommended': True,
            'eval_func': utils.eval_x_dns_prefetch_control,
        },
        'public-key-pins': {
            'recommended': True,
            'eval_func': utils.eval_public_key_pins,
        },
        'x-aspnetmvc-version': {
            'recommended': True,
            'eval_func': utils.eval_x_aspnetmvc_version,
        },
        'x-aspnet-version': {
            'recommended': True,
            'eval_func': utils.eval_x_aspnet_version,
        },
    }

    SERVER_VERSION_HEADERS = [
        'x-powered-by',
        'server',
        'x-aspnet-version',
    ]

    def __init__(self, url, max_redirects=2, no_check_certificate=True):
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            url = "{}://{}".format(DEFAULT_URL_SCHEME, url)
            parsed = urlparse(url)
            if not parsed.scheme and not parsed.netloc:
                raise InvalidTargetURL("Unable to parse the URL")

        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.netloc
        self.path = parsed.path
        self.max_redirects = max_redirects
        self.target_url = None
        self.verify_ssl = False if no_check_certificate else True
        self.headers = None
        self.url = url
        self.domain = self.extract_domain(url)
        self.no_check_certificate = no_check_certificate

        if self.max_redirects:
            self.target_url = self._follow_redirect_until_response(url, self.max_redirects)
        else:
            self.target_url = parsed
    def extract_domain(self, url):
        return url.split("//")[-1].split("/")[0]

    def get_whois_details(self):
        try:
            domain_info = whois.whois(self.domain)
            return domain_info
        except Exception as e:
            return str(e)

    def get_raw_headers(self):
        # Fetch headers from the target site and store them into the class instance
        conn = self.open_connection(self.target_url)
        try:
            conn.request('GET', self.target_url.path, headers=self.REQUEST_HEADERS)
            res = conn.getresponse()
            headers = res.getheaders()
            self.headers = {x[0].lower(): x[1] for x in headers}
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            raise UnableToConnect("Connection failed {}".format(self.target_url.hostname)) from e

    def analyze_security_headers(self):
        try:
            self.fetch_headers()
            headers = self.check_headers()
            whois_details = self.get_whois_details()

        except SecurityHeadersException as e:
            return {'error': str(e)}

        result = {}

        # Populate result dictionary with security headers analysis
        result['security_headers'] = headers

        # Add HTTPS support and certificate validity information
        https = self.test_https()
        result['https'] = {
            'supported': https['supported'],
            'certvalid': https['certvalid'],
        }

        # Add HTTP to HTTPS redirect information
        result['http_to_https'] = self.test_http_to_https()

        # Add WHOIS details
        result['whois'] = whois_details

        # Add DNS details


        return result
    def test_https(self):
        conn = http.client.HTTPSConnection(self.hostname, context=ssl.create_default_context(),
                                           timeout=self.DEFAULT_TIMEOUT)
        try:
            conn.request('GET', '/')
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return {'supported': False, 'certvalid': False}
        except ssl.SSLError:
            return {'supported': True, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        temp_url = urlparse(url)
        while follow_redirects >= 0:
            if not temp_url.netloc:
                raise InvalidTargetURL("Invalid redirect URL")

            if temp_url.scheme == 'http':
                conn = http.client.HTTPConnection(temp_url.netloc, timeout=self.DEFAULT_TIMEOUT)
            elif temp_url.scheme == 'https':
                if self.verify_ssl:
                    ctx = ssl.create_default_context()
                else:
                    ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(temp_url.netloc, context=ctx, timeout=self.DEFAULT_TIMEOUT)
            else:
                raise InvalidTargetURL("Unsupported protocol scheme")

            try:
                conn.request('GET', temp_url.path, headers=self.REQUEST_HEADERS)
                res = conn.getresponse()
            except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
                raise UnableToConnect("Connection failed {}".format(temp_url.netloc)) from e
            except ssl.SSLError as e:
                raise UnableToConnect("SSL Error") from e
            

            if res.status >= 300 and res.status < 400:
                headers = res.getheaders()
                headers_dict = {x[0].lower(): x[1] for x in headers}
                if 'location' in headers_dict:
                    if re.match("^https?://", headers_dict['location']):
                        temp_url = urlparse(headers_dict['location'])
                    else:  # Probably relative path
                        temp_url = temp_url._replace(path=headers_dict['location'])
            else:
                return temp_url

            follow_redirects -= 1

        # More than x redirects, stop here
        return None

    def test_http_to_https(self, follow_redirects=5):
        url = "http://{}{}".format(self.hostname, self.path)
        target_url = self._follow_redirect_until_response(url)
        if target_url and target_url.scheme == 'https':
            return True

        return False

    def open_connection(self, target_url):
        if target_url.scheme == 'http':
            conn = http.client.HTTPConnection(target_url.hostname, timeout=self.DEFAULT_TIMEOUT)
        elif target_url.scheme == 'https':
            if self.verify_ssl:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(target_url.hostname, context=ctx, timeout=self.DEFAULT_TIMEOUT)
        else:
            raise InvalidTargetURL("Unsupported protocol scheme")

        return conn

    def fetch_headers(self):
        """ Fetch headers from the target site and store them into the class instance """

        conn = self.open_connection(self.target_url)
        try:
            conn.request('GET', self.target_url.path, headers=self.REQUEST_HEADERS)
            res = conn.getresponse()
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            raise UnableToConnect("Connection failed {}".format(self.target_url.hostname)) from e
        dns = socket.gethostbyname(self.target_url.hostname)
        ip = socket.gethostbyname_ex(self.target_url.hostname)

        # Retrieve raw headers
        raw_headers = res.msg._headers

        headers = res.getheaders()
        self.headers = {x[0].lower(): x[1] for x in headers}

        # Append DNS, IP, and raw headers to the headers dictionary
        self.headers['dns'] = dns
        self.headers['ip'] = ip  # Choosing the third element of the IP tuple, which contains all IP addresses
        self.headers['raw_headers'] = raw_headers


    def check_headers(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not fetched successfully")

        """ Loop through headers and evaluate the risk """
        for header in self.SECURITY_HEADERS_DICT:
            if header in self.headers:
                eval_func = self.SECURITY_HEADERS_DICT[header].get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException("No evaluation function found for header: {}".format(header))
                res, notes = eval_func(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

            else:
                warn = self.SECURITY_HEADERS_DICT[header].get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

        for header in self.SERVER_VERSION_HEADERS:
            if header in self.headers:
                res, notes = utils.eval_version_info(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

        return retval
    # def analyze_security_headers(self):
    #     try:
    #         self.fetch_headers()
    #         headers = self.check_headers()
    #     except SecurityHeadersException as e:
    #         return {'error': str(e)}

    #     result = {}
    #     for header, value in headers.items():
    #         result[header] = {
    #             'defined': value['defined'],
    #             'warn': value['warn'],
    #             'contents': value['contents'],
    #             'notes': value['notes'],
    #         }

    #     https = self.test_https()
    #     result['https'] = {
    #         'supported': https['supported'],
    #         'certvalid': https['certvalid'],
    #     }

    #     result['http_to_https'] = self.test_http_to_https()

    #     return result

if __name__ == "__main__":
    # Remove the argparse section and replace it with user input
    url = input("Enter the target URL: ")
    max_redirects = 2
    no_check_certificate = False

    try:
        header_check = SecurityHeaders(url)
        result = header_check.analyze_security_headers()
        
        security_headers = result['security_headers']
        whois_details = result['whois']
        # dns_details = result['dns']

        # Print security headers
        for header, value in security_headers.items():
            if value['warn']:
                if not value['defined']:
                    utils.print_warning("Header '{}' is missing".format(header))
                else:
                    utils.print_warning("Header '{}' contains value '{}".format(header, value['contents']))
                    for n in value['notes']:
                        print(" * {}".format(n))
            else:
                if not value['defined']:
                    utils.print_ok("Header '{}' is missing".format(header))
                else:
                    utils.print_ok("Header '{}' contains value".format(header))

        # Print HTTPS support and certificate validity
        https = result['https']
        if https['supported']:
            utils.print_ok("HTTPS supported")
        else:
            utils.print_warning("HTTPS supported")

        if https['certvalid']:
            utils.print_ok("HTTPS valid certificate")
        else:
            utils.print_warning("HTTPS valid certificate")

        # Print HTTP to HTTPS redirect
        if result['http_to_https']:
            utils.print_ok("HTTP -> HTTPS redirect")
        else:
            utils.print_warning("HTTP -> HTTPS redirect")

        # Print WHOIS details
        print("WHOIS Details:")
        print(whois_details)

        # Print DNS details
        print("IP: ", header_check.headers.get('ip'))

        # Print raw headers
        print("\nRaw Headers:")
        raw_headers = header_check.headers.get('raw_headers', [])
        for header in raw_headers:
            print(header[0], ": ", header[1])

    except SecurityHeadersException as e:
        print(e)
        sys.exit(1)
