import base64
import json
import os

import pytest

from hevo_client.auth import AuthPublicKeyV1, get_auth_public_key
from hevo_client.crypto import hmac_sha256_hex, sha256_hex
from hevo_client.encoding import handle_xor
from hevo_client.salt import (AuthSaltResponse, SaltData, encrypt_password_width_salt,
                              get_salt_sign_headers, get_salt_sign_key)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
LIVE_CRND = "172339415169798594"
LIVE_ACCOUNT = "probe_test_account"


def _read(name):
    with open(os.path.join(FIXTURES, name), 'rb') as handle:
        return handle.read()


def test_live_public_key_response_parses_like_the_client():
    raw = _read('hevo_auth_pubkey.xml')
    key = AuthPublicKeyV1.load_from_response(raw.decode('gbk'))
    assert key.is_bad is False
    assert key.rsa_version == 'default_5'
    assert key.public_exponent == '10001'
    assert key.e == 65537
    assert key.n.bit_length() == 1024
    assert key.modulus == key.modulus.upper()
    assert key.public_key.startswith('-----BEGIN PUBLIC KEY-----')


def test_live_public_key_is_reachable_through_get_auth_public_key():
    def http_get(url):
        assert url.endswith('?reqtype=do_rsa&type=get_pubkey')
        return _read('hevo_auth_pubkey.xml')

    key = get_auth_public_key(http_get, 'http://auth.10jqka.com.cn/verify2?reqtype=do_rsa&type=get_pubkey')
    assert key.rsa_version == 'default_5'
    assert key.e == 65537


def test_live_salt_response_parses_like_the_client():
    with open(os.path.join(FIXTURES, 'hevo_salt.json'), encoding='utf-8') as handle:
        text = handle.read()
    response = AuthSaltResponse.load_from_response(text)
    assert response.code == '0'
    assert response.msg == 'success'
    assert len(response.result.dsk) == 64
    assert len(response.result.dsv) == 64
    assert base64.b64decode(response.result.ssv)


def test_live_salt_ssv_decodes_to_hmac_key_like_the_client():
    with open(os.path.join(FIXTURES, 'hevo_salt.json'), encoding='utf-8') as handle:
        response = AuthSaltResponse.load_from_response(handle.read())
    raw = base64.b64decode(response.result.ssv)
    key = sha256_hex(LIVE_CRND + response.result.dsk)
    message = handle_xor(raw.decode('ascii'), key)
    assert message.startswith('$hmac-hash256$key=')
    parts = [part for part in message.split('$') if part]
    assert parts[0] == 'hmac-hash256'
    assert parts[1].startswith('key=')
    text = parts[1].split('=')[1]
    assert text


def test_live_salt_wrong_crd_yields_no_hmac_key():
    with open(os.path.join(FIXTURES, 'hevo_salt.json'), encoding='utf-8') as handle:
        response = AuthSaltResponse.load_from_response(handle.read())
    raw = base64.b64decode(response.result.ssv)
    key = sha256_hex('000000000000000000' + response.result.dsk)
    message = handle_xor(raw.decode('ascii'), key)
    assert not message.startswith('$hmac-hash256$key=')


def test_sign_key_is_derived_from_the_shipped_encrypted_key():
    assert get_salt_sign_key('Salt') == 'TUALD74SBVO6KZQ0'
    assert get_salt_sign_key('SaltTest') == '2022021120720687'


def test_sign_headers_follow_the_client_message_layout():
    headers = get_salt_sign_headers('a=1&b=2', 'TUALD74SBVO6KZQ0',
                                    crnd=LIVE_CRND, timestamp=1700000000)
    arg = sha256_hex('a=1&b=2').upper()
    message = 'X-Auth-SignV3X-Auth-Time' + '1700000000' + arg
    assert headers['X-Auth-Sign'] == hmac_sha256_hex(message, 'TUALD74SBVO6KZQ0').upper()
    assert headers['X-Auth-SignV'] == '3'
    assert headers['X-Auth-Time'] == '1700000000'
    assert headers['X-Auth-Crnd'] == LIVE_CRND
    assert headers['X-Auth-Ext'] == LIVE_CRND
    assert headers['X-Auth-AppId'] == '2022021120720687'


def test_live_login_response_is_the_documented_second_login_challenge():
    import xml.etree.ElementTree as ET
    root = ET.fromstring(_read('hevo_salt_login.xml').decode('utf-8'))
    ret = root.find('ret')
    assert ret.get('code') == '-10002'
    item = root.find('item')
    assert item is not None
    assert len(item.get('dsk')) == 64
    assert len(item.get('dsv')) == 64


def test_live_second_login_response_reports_credential_failure():
    import xml.etree.ElementTree as ET
    root = ET.fromstring(_read('hevo_salt_login_again.xml').decode('utf-8'))
    ret = root.find('ret')
    assert ret.get('code') == '-3'
    assert ret.get('rcode') == '-10002'


def test_salt_password_chain_matches_the_live_server_challenge():
    with open(os.path.join(FIXTURES, 'hevo_salt.json'), encoding='utf-8') as handle:
        response = AuthSaltResponse.load_from_response(handle.read())
    raw = base64.b64decode(response.result.ssv)
    key = sha256_hex(LIVE_CRND + response.result.dsk)
    message = handle_xor(raw.decode('ascii'), key)
    text = [part for part in message.split('$') if part][1].split('=')[1]
    expected = hmac_sha256_hex('dummy_password', text)
    assert len(expected) == 64
    second = handle_xor(expected, sha256_hex(response.result.dsv))
    assert base64.b64encode(second.encode('ascii')).decode('ascii')


def test_handle_xor_rejects_non_latin1_like_the_client():
    with pytest.raises(ValueError):
        handle_xor('中文', '0123')
    with pytest.raises(ValueError):
        handle_xor('ABCD', 'AB')


def test_live_salt_data_shape():
    with open(os.path.join(FIXTURES, 'hevo_salt.json'), encoding='utf-8') as handle:
        obj = json.load(handle)
    assert set(obj) == {'code', 'msg', 'result'}
    assert set(obj['result']) == {'dsk', 'dsv', 'ssv'}


def test_salt_data_constructor_keeps_upstream_property_names():
    data = SaltData(dsk='a', dsv='b', ssv='c')
    assert data.Dsk == 'a'
    assert data.Dsv == 'b'
    assert data.Ssv == 'c'
    response = AuthSaltResponse(code='0', result=data)
    assert response.Code == '0'
    assert response.Result.Dsk == 'a'


def test_encrypt_password_width_salt_rejects_an_empty_salt_challenge():
    from hevo_client.auth import AuthPublicKeyV1
    from hevo_client.errors import AuthError
    key = AuthPublicKeyV1()
    key.modulus = 'CB' * 64
    key.public_exponent = '10001'
    response = AuthSaltResponse(code='0', result=SaltData(dsk='A' * 64, dsv='B' * 64, ssv=''))
    with pytest.raises(AuthError):
        encrypt_password_width_salt('pw', LIVE_CRND, response, key)
