import base64
import getpass
import logging
import xml.etree.cElementTree as ET
from hashlib import sha1
from copy import deepcopy

import six
import requests
import botocore
import adal
import uuid
import datetime

from botocore.client import Config
from botocore.compat import urlsplit
from botocore.compat import urljoin
from botocore.compat import json
from botocore.credentials import CachedCredentialFetcher
import botocore.session

import concurrent
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

import aws_aad_creds
from .compat import escape


_DEFAULT_EXPIRY_WINDOW = 60*15


class SAMLError(Exception):
    pass


logger = logging.getLogger(__name__)


def _role_selector(role_arn, roles):
    """ Select a role base on pre-configured role_arn and Idp roles list """
    chosen = [r for r in roles if r['RoleArn'] == role_arn]
    return chosen[0] if chosen else None


class DeviceCodeAuthenticator(object):

    def __init__(self, config):
        self._cli_client_id = config.get('cli_client_id')
        self._authority_host_url = config.get('authority_host_url')
        self._tenant = config.get('aad_tenant')
        self._middleware_client_id = config.get('middleware_client_id', None)
        self._middleware_client_secret = config.get('middleware_client_secret', None)
        self._middleware_url = config.get('middleware_url', None)
        self._upstream_resource = "https://signin.aws.amazon.com/saml"

        self._device_code = None

        self._authority_url = self._authority_host_url + '/' + self._tenant
        self._adal_context = adal.AuthenticationContext(self._authority_url)

    def _get_device_code_session(self):
        """ Connect to AzureAD and start a Device Code flow """
        device_code = self._adal_context.acquire_user_code(
                        self._middleware_client_id, self._cli_client_id)
        return device_code

    def _block_and_wait_for_signin(self, device_code):
        """ Waits for the user to sign in """
        # Block the thread, until we get confirmation that the token has
        # been claimed or we time out
        tpe = ThreadPoolExecutor(max_workers=1)
        futures = []

        # Add our poll job promise to the queue
        futures.append(tpe.submit(
            self._adal_context.acquire_token_with_device_code,
            self._middleware_client_id, device_code, self._cli_client_id
        ))

        # Store the result if we get one inside 10 seconds, otherwise bail
        # Blocking starts here...
        result = concurrent.futures.wait(futures, timeout=60)
        if len(result.done) == 1:
            token = result.done.pop().result()
        else:
            self._adal_context.cancel_request_to_get_token_with_device_code(device_code)
            raise Exception("Device token flow has timed out")
        return token

    def _send_oauth_token_to_middleware(self, token, middleware_url=None):

        resource = self._upstream_resource

        if middleware_url is None:
            # I'm the middleware, do this locally
            saml_token = self._process_middleware_locally(token, resource)
        else:
            raise NotImplemented

        return saml_token

    def _process_middleware_locally(self, token, resource,
                                    middleware_client_id=None,
                                    middleware_client_secret=None):

        oauth_url = f"{self._authority_url}/oauth2/token"

        middleware_client_id = self._middleware_client_id if None \
            else middleware_client_id
        middleware_client_secret = self._middleware_client_secret if None \
            else middleware_client_secret

        obo_payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": token["accessToken"],
            "client_id": self._middleware_client_id,
            "client_secret": self._middleware_client_secret,
            "resource": self._upstream_resource,
            "requested_token_use": "on_behalf_of",
            "requested_token_type": "urn:ietf:params:oauth:token-type:saml2"
        }
        response = requests.post(oauth_url, data=obo_payload)
        r = response.json()

        # Pull the saml token out of the response.
        saml_token = base64.urlsafe_b64decode(r['access_token'])
        if type(saml_token) == bytes:
            saml_token = saml_token.decode('utf-8')
        return saml_token

    def retrieve_saml_assertion(self, config):

        # Step 1 - start a device code session
        device_code = self._get_device_code_session()
        if device_code is not None:
            self._device_code = device_code

        #print("Logging in user using device token...")
        print(device_code['message'])

        # Step 2 - wait for the user to sign in, and retireve the token
        oauth_token = self._block_and_wait_for_signin(device_code)

        # Step 3 - send the token back to AAD using the middleware
        #          and exchange it for a SAML token against the AWS App
        saml_token = self._send_oauth_token_to_middleware(oauth_token)
        saml_response = self._transform_assertion_to_saml_response(saml_token)

        return base64.urlsafe_b64encode(saml_response.encode('utf-8')).decode('utf-8')

    def _transform_assertion_to_saml_response(self, saml_token):

        saml_response_tpl = """
        <samlp:Response ID="_{response_id}" Version="2.0" IssueInstant="{authn_instant}"
            Destination="https://signin.aws.amazon.com/saml" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
            <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</Issuer>
            <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
            {saml_assertion}
        </samlp:Response>
        """
        response_id = uuid.uuid4()
        authn_instant = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        issuer = self._parse_issuer(saml_token)

        saml_response = saml_response_tpl.format(response_id=response_id,
            authn_instant=authn_instant, issuer=issuer,
            saml_assertion=saml_token
        )

        return saml_response

    @staticmethod
    def _parse_issuer(saml_token):
        root = ET.fromstring(saml_token)
        issuer = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
        return issuer.text


class DeviceCodeCredentialsFetcher(CachedCredentialFetcher):

    def __init__(self, client_creator, provider_name, config,
                 role_selector=_role_selector, cache=None,
                 expiry_window_seconds=_DEFAULT_EXPIRY_WINDOW):

        self._client_creator = client_creator
        self._role_selector = role_selector
        self._provider_name = provider_name

        if cache is None:
            cache = {}
        self._cache = cache
        self._stored_cache_key = None

        self._config = config

        self._expiry_window_seconds = expiry_window_seconds

        self._assume_role_kwargs = None

        self._authenticator = DeviceCodeAuthenticator(config)

    @property
    def _cache_key(self):
        if self._stored_cache_key is None:
            self._stored_cache_key = self._create_cache_key()
        return self._stored_cache_key

    def _create_cache_key(self):
        cache_key_kwargs = {
            'provider_name': self._provider_name,
            'config': self._config
        }
        cache_key_kwargs = json.dumps(cache_key_kwargs, sort_keys=True)
        argument_hash = sha1(cache_key_kwargs.encode('utf-8')).hexdigest()
        return self._make_file_safe(argument_hash)

    def fetch_credentials(self):
        creds = super(DeviceCodeCredentialsFetcher, self).fetch_credentials()
        return {
            'AccessKeyId': creds['access_key'],
            'SecretAccessKey': creds['secret_key'],
            'SessionToken': creds['token'],
            'Expiration': creds['expiry_time']
        }

    def _get_credentials(self):
        kwargs = self._get_assume_role_kwargs()
        client = self._create_client()
        logger.info(
            'Retrieving credentials with STS.AssumeRoleWithSaml() using the '
            'following parameters: %s', kwargs
        )
        response = deepcopy(client.assume_role_with_saml(**kwargs))
        expiration = response['Credentials']['Expiration'].isoformat()
        response['Credentials']['Expiration'] = expiration
        return response

    def _create_client(self):
        return self._client_creator(
            'sts', config=Config(
                signature_version=botocore.UNSIGNED,
                user_agent_extra=(
                    'aws-aad-creds/%s' % aws_aad_creds.__version__
                )
            )
        )

    def _get_role_and_principal_arn(self, assertion):
        idp_roles = self._parse_roles(assertion)
        role_arn = self._role_selector(self._config.get('role_arn'), idp_roles)
        if not role_arn:
            role_arns = [r['RoleArn'] for r in idp_roles]
            raise Exception('Unable to choose role "%s" from %s' % (
                self._config.get('role_arn'), role_arns
            ))

        return role_arn

    def _get_assume_role_kwargs(self):
        if self._assume_role_kwargs is not None:
            return self._assume_role_kwargs

        config = {}
        assertion = self._authenticator.retrieve_saml_assertion(config)
        if not assertion:
            raise Exception(
                'Failed to login at %s' % config['saml_endpoint'])

        arns = self._get_role_and_principal_arn(assertion)

        self._assume_role_kwargs = {
            'PrincipalArn': arns['PrincipalArn'],
            'RoleArn': arns['RoleArn'],
            'SAMLAssertion': assertion
        }
        return self._assume_role_kwargs

    def _parse_roles(self, assertion):
        attribute = '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
        attr_value = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        awsroles = []
        root = ET.fromstring(base64.urlsafe_b64decode(assertion).decode('utf-8'))
        for attr in root.iter(attribute):
            if attr.get('Name') == \
                    'https://aws.amazon.com/SAML/Attributes/Role':
                for value in attr.iter(attr_value):
                    parts = [p.strip() for p in value.text.split(',')]
                    # Deals with "role_arn,pricipal_arn" or its reversed order
                    if 'saml-provider' in parts[0]:
                        role = {'PrincipalArn': parts[0], 'RoleArn': parts[1]}
                    else:
                        role = {'PrincipalArn': parts[1], 'RoleArn': parts[0]}
                    awsroles.append(role)
        return awsroles