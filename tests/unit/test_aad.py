import base64
import json
from datetime import datetime, timedelta
from copy import deepcopy

import mock
from dateutil.tz import tzlocal
import pytest
import requests


from aws_aad_creds.aad import DeviceCodeAuthenticator
from aws_aad_creds.aad import DeviceCodeCredentialsFetcher


@pytest.fixture
def mock_requests_session():
    return mock.Mock(spec=requests.Session)


@pytest.fixture
def aad_auth(prompter, mock_requests_session):
    return DeviceCodeAuthenticator(prompter, mock_requests_session)

@pytest.fixture
def generic_config():
    return {
            'role_arn': 'arn:aws:iam::123456789012:role/fakerole',
            'cli_client_id': '11111111-1111-1111-1111-111111111111',
            'aad_tenant': 'testtenant.obviouslyfake.mockdomain',
            'middleware_client_id': '22222222-2222-2222-2222-222222222222',
            'middleware_client_secret': 'notsosecret',
            'middleware_url': None,
            'authority_host_url': 'https://clearly.notmicrosoft.mockdomain'
        }

@pytest.fixture
def middleware_url_config():
    return {
            'role_arn': 'arn:aws:iam::123456789012:role/fakerole',
            'cli_client_id': '11111111-1111-1111-1111-111111111111',
            'aad_tenant': 'testtenant.obviouslyfake.mockdomain',
            'middleware_client_id': None,
            'middleware_client_secret': None,
            'middleware_url': 'https://middleware.obviouslyfake.mockdomain',
            'authority_host_url': 'https://clearly.notmicrosoft.mockdomain'
        }

@pytest.fixture
def mock_authenticator():
    return mock.Mock(spec=DeviceCodeAuthenticator)

@pytest.fixture
def cache():
    return {}


class TestDeviceCodeAuthenticator(object):

    @pytest.mark.xfail(reason="TODO: Cover with tests")
    def test_nothing_implemented_yet(self, aad_auth):
        assert aad_auth is None


class TestDeviceCodeCredentialsFetcher(object):

    @pytest.mark.xfail(reason="TODO: Cover with tests")
    def test_nothing_implemented_yet(self):
        assert True == False