import socket
import urllib.request
from dataclasses import dataclass

from .auth import get_auth_passport
from .auth import login as auth_login
from .auth import make_auth_bytes
from .auth import get_mac_address
from .binarypack import (BinaryPack, BinaryPackLayoutV2, DataResponseV2, parameter_dictionary_to_binary_pack, parameter_dictionary_to_string, request_trend_v2, string_to_parameter_dictionary)
from .constants import DEFAULT_QSID
from .errors import AuthError, HevoError
from .salt import login_salt

class HevoClient:
    def __init__(self, host=None, port=None, username=None, password=None, http_get=None, http_post=None, transport=None, qsid=DEFAULT_QSID):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.http_get = http_get if http_get is not None else self._http_get
        self.http_post = http_post if http_post is not None else self._http_post
        self.transport = transport
        self.qsid = qsid
        self.auth = None
        self.auth_bytes = None
        self._auth_sent = False

    def _http_get(self, url):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return response.read()
        except Exception as exc:
            raise HevoError(str(exc))

    def _http_post(self, url, data, headers=None):
        try:
            request = urllib.request.Request(url, data=data, headers=headers or {})
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except Exception as exc:
            raise HevoError(str(exc))

    def login(self, username=None, password=None, mode="MD5"):
        username = username if username is not None else self.username
        password = password if password is not None else self.password
        if username is None or password is None:
            raise AuthError("missing credentials")
        if mode in ("Salt", "SaltTest", "SaltDebug"):
            session = login_salt(username, password, self.http_get, self.http_post, mode)
            passport = get_auth_passport(self.http_post, session, self.qsid)
            if passport is None or passport.is_bad:
                raise AuthError("bad auth passport")
            passport64 = passport.make_passport64_value()
            self.auth = {
                "session": session,
                "passport": passport,
                "passport64": passport64,
                "auth_bytes": make_auth_bytes(passport64, session.user_id, self.qsid, get_mac_address()),
            }
        else:
            self.auth = auth_login(username, password, self.http_get, self.http_post, self.qsid)
        self.auth_bytes = self.auth["auth_bytes"]
        self._auth_sent = False
        return self.auth

    def query_intraday(self, code, market="USHA", date="0", host=None, port=None):
        if self.auth is None and self.auth_bytes is None:
            raise AuthError("not logged in")
        request_string = request_trend_v2(207, market, code, date)
        params = string_to_parameter_dictionary(request_string)
        request_string = parameter_dictionary_to_string(params)
        pack = parameter_dictionary_to_binary_pack(params)
        request_bytes = pack.raw
        target_host = host if host is not None else self.host
        target_port = port if port is not None else self.port
        if self.transport is not None:
            if self.auth_bytes is not None and not self._auth_sent:
                self.transport(self.auth_bytes)
                self._auth_sent = True
            response_bytes = self.transport(request_bytes)
        elif target_host is not None and target_port is not None:
            if self.auth_bytes is not None and not self._auth_sent:
                self._send_socket(target_host, target_port, self.auth_bytes, read_response=False)
                self._auth_sent = True
            response_bytes = self._send_socket(target_host, target_port, request_bytes, read_response=True)
        else:
            raise HevoError("no transport or host/port")
        bp = BinaryPack.from_bytes(response_bytes)
        response = DataResponseV2(full_pack=bp)
        return response.as_list_dictionary()

    def _send_socket(self, host, port, data, read_response=True):
        with socket.create_connection((host, port), timeout=30) as sock:
            sock.sendall(data)
            if not read_response:
                return b""
            head = _recv_exact(sock, 13)
            body_length = int(head[4:12].decode("ascii"), 16)
            body = _recv_exact(sock, body_length)
            return head + body

def _recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass
class HevoCredentials:
    username: str
    password: str


HevoClient.Login = HevoClient.login
HevoClient.QueryIntraday = HevoClient.query_intraday
