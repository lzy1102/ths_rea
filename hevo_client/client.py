import socket
import urllib.request
from dataclasses import dataclass

from .auth import get_auth_passport
from .auth import login as auth_login
from .auth import make_auth_bytes
from .auth import get_mac_address
from .binarypack import (BinaryPack, BinaryPackLayoutV2, DataResponseV2, distribute_candle_fields, format_candle_time, get_real_period_id, merge_candle_responses, normalize_candle_fields, parameter_dictionary_to_binary_pack, parameter_dictionary_to_string, request_candle_v2, request_trend_v2, string_to_parameter_dictionary)
from .constants import CANDLE_FIELD_IDS, DEFAULT_QSID, INDEX_MARKETS
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
        self._sock = None

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

    def resolve_endpoint(self, version="V2"):
        passport = None
        if self.auth is not None:
            passport = self.auth.get("passport")
        if passport is None:
            raise HevoError("no passport for endpoint resolution")
        if version == "V3":
            groups = passport.server_groups_v3
        elif version == "V1":
            groups = passport.server_groups_v1
        else:
            groups = passport.server_groups_v2
        from .servers import select_main_quote_group
        group = select_main_quote_group(groups)
        if group is None:
            raise HevoError("no quote server group in passport")
        self.host = group.host_or_ip
        self.port = group.port
        return self.host, self.port

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
            response_bytes = self._send_socket(target_host, target_port, request_bytes)
        else:
            raise HevoError("no transport or host/port")
        bp = BinaryPack.from_bytes(response_bytes)
        response = DataResponseV2(full_pack=bp)
        return response.as_list_dictionary()

    def query_kline(self, code, market="USHA", period=5, count=100, end_time=None, start_time=None, fields=None, right="Forward", is_volume_exclude=False, host=None, port=None):
        if self.auth is None and self.auth_bytes is None:
            raise AuthError("not logged in")
        real_period = get_real_period_id(period)
        request_fields = normalize_candle_fields(fields)
        if market in INDEX_MARKETS:
            request_fields = [field_id for field_id in request_fields if field_id != CANDLE_FIELD_IDS["turnover_rate"]]
        buckets = distribute_candle_fields(request_fields)
        if not buckets:
            return []
        start = str(-int(count)) if start_time is None else format_candle_time(start_time, real_period)
        end = "0" if end_time is None else format_candle_time(end_time, real_period)
        target_host = host if host is not None else self.host
        target_port = port if port is not None else self.port
        if self.transport is None and (target_host is None or target_port is None):
            raise HevoError("no transport or host/port")
        responses = []
        for request_id, bucket_fields in buckets:
            request_string = request_candle_v2(request_id, market, code, start, end, bucket_fields, right, is_volume_exclude, real_period)
            params = string_to_parameter_dictionary(request_string)
            request_string = parameter_dictionary_to_string(params)
            pack = parameter_dictionary_to_binary_pack(params)
            request_bytes = pack.raw
            if self.transport is not None:
                if self.auth_bytes is not None and not self._auth_sent:
                    self.transport(self.auth_bytes)
                    self._auth_sent = True
                response_bytes = self.transport(request_bytes)
            else:
                response_bytes = self._send_socket(target_host, target_port, request_bytes)
            bp = BinaryPack.from_bytes(response_bytes)
            responses.append((request_id, DataResponseV2(full_pack=bp)))
        return merge_candle_responses(responses, real_period)

    def _send_socket(self, host, port, data):
        sock = self._get_socket(host, port)
        sock.sendall(data)
        head = _recv_exact(sock, 13)
        body_length = int(head[4:12].decode("ascii"), 16)
        body = _recv_exact(sock, body_length)
        return head + body

    def _get_socket(self, host, port):
        if self._sock is None:
            self._sock = socket.create_connection((host, port), timeout=30)
            if self.auth_bytes is not None and not self._auth_sent:
                self._sock.sendall(self.auth_bytes)
                self._auth_sent = True
        return self._sock

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._auth_sent = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

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
HevoClient.QueryKline = HevoClient.query_kline
