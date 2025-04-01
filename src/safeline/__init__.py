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

class BadRequestException(SafeLineException):
    pass

class ForbiddenException(SafeLineException):
    pass

class WrappedSession(requests.Session):
    """A wrapper for requests.Session to override 'verify' property, ignoring REQUESTS_CA_BUNDLE environment variable.

    This is a workaround for https://github.com/psf/requests/issues/3829 (will be fixed in requests 3.0.0)
    """

    def merge_environment_settings(self, url, proxies, stream, verify, *args, **kwargs):
        if self.verify is False:
            verify = False

        return super(WrappedSession, self).merge_environment_settings(url, proxies, stream, verify, *args, **kwargs)

class SafeLine:
    def __init__(self, base_url: str, api_token: str = None, timeout: int = None):
        self.base_url = base_url
        self.api_token = api_token
        self.timeout = timeout
        self._session = WrappedSession()

        self.certification = CertificationManager(self)
        self.ip_group = IpGroupManager(self)

    def _response_handler(self, response: requests.Response) -> requests.Response:
        """Handle response objects and raise exceptions if errors occur."""
        response.raise_for_status()
        return response

    def _request(self, req: requests.Request, stream: bool = None) -> requests.Response:
        r = self._session.prepare_request(req)
        _settings = self._session.merge_environment_settings(
            r.url, {}, stream, self._session.verify, None)
        _settings["timeout"] = self.timeout
        return self._session.send(r, **_settings)

    def safeline_request(self, req: requests.Request, stream: bool = None) -> requests.Response:
        try:
            req.headers["X-SLCE-API-TOKEN"] = self.api_token
            return self._response_handler(self._request(req, stream))
        except req_exc.HTTPError as e:
            print(e)
            if e.response.status_code == 400:
                raise BadRequestException(f"Bad Request [{e.response.status_code}]: {e.response.reason}")
            elif e.response.status_code == 401:
                raise LoginFailedException(f"Unauthorized [{e.response.status_code}]: {e.response.reason}")
            elif e.response.status_code == 403:
                raise ForbiddenException(f"Forbidden [{e.response.status_code}]: {e.response.reason}")
            elif e.response.status_code == 404:
                raise NotFoundException("Requested item could not be found")
            elif e.response.status_code >= 500:
                msg = f"Server Error [{e.response.status_code}]: {e.response.reason}"
                if e.response.text:
                    msg += f'\n{e.response.text}'
                raise SafeLineException(msg)
            else:
                raise SafeLineException(f"Unhandled Error [{e.response.status_code}]: {e.response.reason}")

    def system_status(self) -> str:
        try:
            response = self.safeline_request(requests.Request('GET', self.base_url + "/api/open/system"))
            return response.text
        except req_exc.HTTPError as e:
            print(e.response.status_code)
            return ""

class CertificationManager:
    def __init__(self, safeline: SafeLine):
        self.safeline = safeline

    def list(self) -> dict:
        response = self.safeline.safeline_request(requests.Request('GET', f"{self.safeline.base_url}/api/open/cert"))
        return response.json()

    def create(self, crt: str, key: str) -> dict:
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

    def delete(self, cert_id: int) -> dict:
        response = self.safeline.safeline_request(
            requests.Request('DELETE', f"{self.safeline.base_url}/api/open/cert/{cert_id}"))
        return response.json()

    def update(self, cert_id: int, crt: str, key: str) -> dict:
        payload = {
            "manual": {
                "crt": crt,
                "key": key
            },
            "type": 2,
            "id": cert_id
        }
        response = self.safeline.safeline_request(
            requests.Request('POST', f"{self.safeline.base_url}/api/open/cert", json=payload))
        return response.json()

    def get(self, cert_id: int) -> dict:
        response = self.safeline.safeline_request(
            requests.Request('GET', f"{self.safeline.base_url}/api/open/cert/{cert_id}"))
        return response.json()

class IpGroupManager:
    def __init__(self, safeline: SafeLine):
        self.safeline = safeline

    def list(self) -> dict:
        response = self.safeline.safeline_request(requests.Request('GET', f"{self.safeline.base_url}/api/open/ipgroup"))
        return response.json()

    def create(self, ipgroup_name: str, ips_list: list = None, reference: str = None) -> dict:
        payload = {
            "reference": reference,
            "comment": ipgroup_name,
            "ips": ips_list
        }
        response = self.safeline.safeline_request(
            requests.Request('POST', f"{self.safeline.base_url}/api/open/ipgroup", json=payload))
        return response.json()

    def delete(self, ipgroup_id_list: list) -> dict:
        payload = {
            "ids": ipgroup_id_list
        }
        response = self.safeline.safeline_request(
            requests.Request('DELETE', f"{self.safeline.base_url}/api/open/ipgroup", json=payload))
        return response.json()

    def update(self, ipgroup_id: int, ipgroup_name: str, reference: str = None, ips_list: list = None) -> dict:
        payload = {
            "id": ipgroup_id,
            "reference": reference,
            "ips": ips_list,
            "comment": ipgroup_name,
        }
        response = self.safeline.safeline_request(
            requests.Request('PUT', f"{self.safeline.base_url}/api/open/ipgroup", json=payload))
        return response.json()

    def get(self, ipgroup_id: int) -> dict:
        response = self.safeline.safeline_request(
            requests.Request('GET', f"{self.safeline.base_url}/api/open/ipgroup/{ipgroup_id}"))
        return response.json()
