from __future__ import print_function
import argparse
import json
import getpass
import sys
import logging
import base64
import xml.dom.minidom

import botocore.session

from .aad import DeviceCodeCredentialsFetcher
from .cache import JSONFileCache


def run(argv=None, prompter=getpass.getpass, client_creator=None,
         cache_dir=None):
    parser = argparse.ArgumentParser()
    middleware_group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        '-a', '--role-arn', required=True, help=(
            'The role arn you wish to assume. Your SAML provider must be '
            'configured to give you access to this arn.'
        )
    )
    parser.add_argument(
         '--cli-client-id', required=True, help=(
            'The Client ID of this AzureAD CLI Application'
        )
    )
    parser.add_argument(
         '--aad-tenant', required=True, help=(
            'The AzureAD Tenant, usually something.onmicrosoft.com or the TenantID'
        )
    )
    parser.add_argument(
         '--aad-auth-host', default="https://login.microsoftonline.com", required=False, help=(
            'The AzureAD login endpoint, defaults to https://login.microsoftonline.com'
        )
    )
    middleware_group.add_argument(
         '--middleware-url', required=False, help=(
            'The URL of a service acting as the middleware (optional, instead of client id and secret)'
            'WARNING: NOT YET IMPLEMENTED'
        )
    )
    middleware_group.add_argument(
         '--middleware-client-id', required=False, help=(
            'The Client ID of the AzureAD app used to call the AWS App on the users behalf'
        )
    )
    parser.add_argument(
         '--middleware-client-secret', required=False, help=(
            'The Client Secret of the AzureAD app used to call the AWS App on the users behalf, (required with middleware-client-id)'
        )
    )
    parser.add_argument(
        '--no-cache', action='store_false', default=True, dest='cache',
        help=(
            'Disables the storing and retrieving of credentials from the local file cache.'
        )
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', help=('Enables verbose mode.')
    )
    args = parser.parse_args(argv)

    if args.verbose:
        logger = logging.getLogger('aws_aad_creds')
        logger.setLevel(logging.INFO)
        handler = PrettyPrinterLogHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if client_creator is None:
        client_creator = botocore.session.Session().create_client

    cache = {}
    if args.cache:
        cache = JSONFileCache(cache_dir)

    if args.middleware_url is not None:
        print("ERROR: You need to specify a client id and secret", file=sys.stderr)
        parser.print_help()
        exit(1)

    fetcher = DeviceCodeCredentialsFetcher(
        client_creator=client_creator,
        provider_name='aws_aad_creds',
        config={
            'role_arn': args.role_arn,
            'cli_client_id': args.cli_client_id,
            'aad_tenant': args.aad_tenant,
            'middleware_client_id': args.middleware_client_id,
            'middleware_client_secret': args.middleware_client_secret,
            'middleware_url': args.middleware_url,
            'authority_host_url': args.aad_auth_host
        },
        cache=cache
    )
    creds = fetcher.fetch_credentials()
    creds['Version'] = 1
    print(json.dumps(creds) + '\n')


class PrettyPrinterLogHandler(logging.StreamHandler):
    def emit(self, record):
        self._pformat_record_args(record)
        super(PrettyPrinterLogHandler, self).emit(record)

    def _pformat_record_args(self, record):
        if isinstance(record.args, dict):
            record.args = self._pformat_dict(record.args)
        elif getattr(record, 'is_saml_assertion', False):
            formatted = self._pformat_saml_assertion(record.args[0])
            record.args = tuple([formatted])

    def _pformat_dict(self, args):
        return json.dumps(args, indent=4, sort_keys=True)

    def _pformat_saml_assertion(self, assertion):
        xml_string = base64.b64decode(assertion).decode('utf-8')
        return xml.dom.minidom.parseString(xml_string).toprettyxml()