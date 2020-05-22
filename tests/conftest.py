from datetime import datetime, timedelta
import copy
import logging
import mock

import pytest
from dateutil.tz import tzlocal


@pytest.fixture
def mock_botocore_client():
    return mock.Mock()


@pytest.fixture
def client_creator(mock_botocore_client):
    # Create a mock sts client that returns a specific response
    # for assume_role_with_saml.
    expiration = datetime.now(tzlocal()) + timedelta(days=1)
    mock_botocore_client.assume_role_with_saml.return_value = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': expiration
        },
    }
    return mock.Mock(return_value=mock_botocore_client)


@pytest.fixture(params=[
    {'reversed': False},
    {'reversed': True}
])
def assertion(request):
    provider_arn = 'arn:aws:iam::123456789012:saml-provider/fakeprovider'
    role_arn = 'arn:aws:iam::123456789012:role/fakerole'
    is_reversed = request.param.get('reversed', False)
    if not is_reversed:
        config_string = '%s,%s' % (provider_arn, role_arn)
    else:
        config_string = '%s,%s' % (role_arn, provider_arn)
    return create_assertion([config_string])



@pytest.fixture
def cache_dir(tmpdir):
    cache_directory = tmpdir.mkdir('awscreds-saml-cache')
    return '%s' % cache_directory
