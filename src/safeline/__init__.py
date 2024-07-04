import time

import pyotp
import requests
import requests.exceptions as req_exc


class SafeLineException(Exception):
    """
    General exception type for SafeLine-API-related failures.
    """
    pass


class TimeoutException(SafeLineException):
    pass


class LoginFailedException(SafeLineException):
    pass


class NotFoundException(SafeLineException):
    pass


class WrappedSession(requests.Session):
    """A wrapper for requests.Session to override 'verify' property, ignoring REQUESTS_CA_BUNDLE environment variable.

    This is a workaround for https://github.com/psf/requests/issues/3829 (will be fixed in requests 3.0.0)
    """

    def merge_environment_settings(self, url, proxies, stream, verify, *args,
                                   **kwargs):
        if self.verify is False:
            verify = False

        return super(WrappedSession, self).merge_environment_settings(url,
                                                                      proxies,
                                                                      stream,
                                                                      verify,
                                                                      *args,
                                                                      **kwargs)


class SafeLine:
    def __init__(self, base_url, username=None, password=None, otp_secret=None, timeout=None):
        self.jwt = None
        self.csrf_token = None
        self.base_url = base_url
        self.username = username
        self.password = password
        self.otp_secret = otp_secret
        self.timeout = timeout
        self._session = WrappedSession()

        self.certification = CertificationManager(self)
        self.ip_group = IpGroupManager(self)

    def _response_handler(self, response):
        """
        Handle response objects
        """

        # raise exceptions if occurred
        response.raise_for_status()

        # Response objects will automatically return unicode encoded
        # when accessing .text property
        return response

    def _request(self, req, stream=None):

        r = self._session.prepare_request(req)
        # requests.Session.send() does not honor env settings by design
        # see https://github.com/requests/requests/issues/2807
        _settings = self._session.merge_environment_settings(
            r.url, {}, stream, self._session.verify, None)
        _settings["timeout"] = self.timeout
        return self._session.send(r, **_settings)

    def get_passcode(self, otp_secret) -> str:
        try:
            totp = pyotp.TOTP(otp_secret)
            return totp.now()
        except Exception as err:
            if type(err).__name__ == 'Error' and err.args[0] == 'Incorrect padding':
                raise LoginFailedException("Wrong otp secret, please check your otp secret.")
            else:
                raise LoginFailedException(err)

    def get_csrf_token(self) -> str:
        response = self._session.get(f"{self.base_url}/api/open/auth/csrf")
        data = response.json()
        self.csrf_token = data['data']['csrf_token']
        return data['data']['csrf_token']

    def login(self, username, password, otp_secret):
        self.get_csrf_token()
        payload = {
            "username": username,
            "password": password,
            "csrf_token": self.csrf_token
        }
        response = self._session.post(f"{self.base_url}/api/open/auth/login", json=payload)
        try:
            _jwt = response.json()['data']['jwt']
        except KeyError:
            msg = response.json().get('msg', 'Login failed, check your username and password')
            raise LoginFailedException(msg)

        # the first jwt: _jwt is used for otp auth
        headers = {'authorization': 'Bearer ' + _jwt}
        self.get_csrf_token()
        final_payload = {
            "code": self.get_passcode(otp_secret),
            "timestamp": int(time.time() * 1000),
            "csrf_token": self.csrf_token
        }
        final_response = self._session.post(f"{self.base_url}/api/open/auth/tfa", headers=headers, json=final_payload)
        data = final_response.json()
        # print(data)
        try:
            self.jwt = data['data']['jwt']
        except KeyError:
            msg = response.json().get('msg', 'Login failed, check your otp code')
            raise LoginFailedException(msg)

    def safeline_request(self, req, stream=None):
        try:
            if self.jwt is None:
                self.login(self.username, self.password, self.otp_secret)
            req.headers["authorization"] = "Bearer " + self.jwt
            return self._response_handler(
                self._request(req, stream))

        except req_exc.HTTPError as e:
            if e.response.status_code in [401, 403, 500]:
                msg = 'Error in request. ' + \
                      'Possibly authentication failed [%s]: %s' % (
                          e.response.status_code, e.response.reason)
                if e.response.text:
                    msg += '\n' + e.response.text
                raise SafeLineException(msg)
            elif e.response.status_code == 404:
                raise NotFoundException('Requested item could not be found')
            else:
                raise

    def system_status(self) -> str:
        try:
            response = self.safeline_request(requests.Request('GET', self.base_url + "/api/open/system"))
            return response.text
        except req_exc.HTTPError as e:
            print(e.response.status_code)


class CertificationManager:
    def __init__(self, safeline):
        self.safeline = safeline

    def list(self):
        response = self.safeline.safeline_request(requests.Request('GET', f"{self.safeline.base_url}/api/open/cert"))
        return response.json()

    def create(self, crt, key):
        payload = {
            "manual": {
                "crt": crt,
                "key": key
            },
            "type": 2
        }
        response = self.safeline.safeline_request(
            requests.Request('POST', f"{self.safeline.base_url}/api/open/cert"), json=payload)
        return response.json()

    def delete(self, cert_id):
        response = self.safeline.safeline_request(
            requests.Request('DELETE', f"{self.safeline.base_url}/api/open/cert/{cert_id}"))
        return response.json()

    def update(self, cert_id, crt, key):
        payload = {
            "manual": {
                "crt": crt,
                "key": key
            },
            "type": 2,
            "id": cert_id
        }
        response = self.safeline.safeline_request(
            requests.Request('POST', f"{self.safeline.base_url}/api/open/cert",
                             json=payload))
        return response.json()

    def get(self, cert_id):
        response = self.safeline.safeline_request(
            requests.Request('GET', f"{self.safeline.base_url}/api/open/cert/{cert_id}"))
        return response.json()


class IpGroupManager:
    def __init__(self, safeline):
        self.safeline = safeline

    def list(self):
        response = self.safeline.safeline_request(requests.Request('GET', f"{self.safeline.base_url}/api/open/ipgroup"))
        return response.json()

    def create(self, ipgroup_name, ips_list=None, reference=None):
        payload = {
            "reference": reference,
            "comment": ipgroup_name,
            "ips": ips_list
        }
        response = self.safeline.safeline_request(
            requests.Request('POST', f"{self.safeline.base_url}/api/open/ipgroup", json=payload)
        )
        return response.json()

    def delete(self, ipgroup_id_list):
        payload = {
            "ids": ipgroup_id_list
        }
        response = self.safeline.safeline_request(
            requests.Request('DELETE', f"{self.safeline.base_url}/api/open/ipgroup", json=payload)
        )
        return response.json()

    def update(self, ipgroup_id, ipgroup_name, reference=None, ips_list=None):
        payload = {
            "id": ipgroup_id,
            "reference": reference,
            "ips": ips_list,
            "comment": ipgroup_name,
        }
        response = self.safeline.safeline_request(
            requests.Request('PUT', f"{self.safeline.base_url}/api/open/ipgroup", json=payload)
        )
        return response.json()

    def get(self, ipgroup_id):
        # TODO:  No RESTFul in safeline-ce 5.2.0
        pass
