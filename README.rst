===============================
AWS AzureAD Credential Provider
===============================

.. image:: https://github.com/elliotsegler/aws-aad-creds/workflows/Build/badge.svg?branch=master
   :target: https://github.com/elliotsegler/aws-aad-creds/actions

This is a process-based credential providers to be used with the AWS CLI
and related tools, heavily based on the existing `awsprocesscreds`_ provider from
AWS.

This is an experimental package, breaking changes may occur on any minor
version bump.

.. _awsprocesscreds: https://github.com/awslabs/awsprocesscreds

Installation
------------

The easiest way to install is to use pip::

    pip install aws_aad_creds

Requirements
~~~~~~~~~~~~

This package requires a version of python to be installed. Currently supported
python versions are:

* 3.8.x

In addition to python being installed, you'll need to:

- Have the ``Amazon Web Services (AWS)`` AzureAD Enterprise App deployed to your
  Azure AD Tenant

- Create two new AzureAD app registrations

  - One for this CLI application to use

  - One for a middleware component (which can be this script) to switch provide
    service chaining to call the AWS Enterprise App

Detailed `AzureAD Setup instructions`_ for the app registrations are provided below.

Azure AD Device Code Authentication
-----------------------------------

This provider connects to Azure AD using a device code flow.

The script has a number of required parameters:

**AWS Options:**

* ``-a / --role-arn`` - The role arn you wish to assume. This must be
  preconfigured in the AWS Enterprise App to give you access to this ARN.

**Azure AD Related Options:**

* ``--cli-client-id`` - The App Registration Client ID for this CLI app
  (see instructions)
* ``--aad-tenant`` - The AzureAD Tenant, usually something.onmicrosoft.com
  or the TenantID
* ``--middleware-client-id`` - The App Registration Client ID for the
  middleware app (see instructions)
* ``--middleware-client-secret`` - The App Registration Client Secret for the
  middleware app (see instructions)

This will cache your credentials by default, which will allow you to run
multiple commands without having to enter your password each time. You can
disable the cache by specifying ``--no-cache``.

Additionally, you can show logs by specifying ``-v`` or ``--verbose``.

To configure this provider, you need create a profile using the
``credential_process`` config variable. See the `AWS CLI Config docs`_
for more details on this config option.


Example configuration::

    [profile azuread]
    region = us-west-1
    credential_process = aws-aad-creds --role-arn arn:aws:iam::123456789012:role/myrole \
	                                   --cli-client-id 11111111-1111-1111-1111-111111111111 \
                                       --aad-tenant mytenant.onmicrosoft.com \
                                       --middleware-client-id 22222222-2222-2222-2222-222222222222 \
                                       --middleware-client-secret "secretpasswordhere"


.. _AWS CLI Config docs: http://docs.aws.amazon.com/cli/latest/topic/config-vars.html#cli-aws-help-config-vars


Custom Providers
----------------

The mechanism this package uses to provide credentials is generally available,
and not specific to this package. It can be used to implement any custom
credential provider that will work with the AWS CLI, boto3, and other SDKs as
they implement support.

A detailed breakdown of this mechanism along with a live demo of implementing a
credential provider that hooks into the macOS keychain can be seen on this
recorded talk from re:Invent 2017:
`AWS CLI: 2107 and Beyond <https://youtu.be/W8IyScUGuGI?t=1260>`_

The CLI will call the process provided as the value for ``credential_process``.
This process must return credentials on stdout in the following JSON form::

   {
      "Version": 1,
      "AccessKeyId": "string",
      "SecretAccessKey": "string",
      "SessionToken": "string",
      "Expiration": "2019-01-31T21:45:41+00:00"
   }

Where ``Expiration`` is an RFC 3339 compatible timestamp. As the expiration
time nears, the process will be called again to get a new set of credentials.
The ``Version`` denotes the version of this format, whose only current valid
value is ``1``. The remaining keys are the AWS credentials you wish to use.

==========================
AzureAD Setup Instructions
==========================

AWS Enterprise App
------------------

If you don't have an Azure AD Tenant, you'll need to
`create one <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-create-new-tenant>`_

You'll need to deploy the **Amazon Web Services (AWS)** Enterprise App. You
can see the instructions on how to do that
`here <https://docs.microsoft.com/en-us/azure/active-directory/saas-apps/aws-multi-accounts-tutorial>`_

CLI App Registration
--------------------

In addition to that, the CLI application in this package will require it's
own application. The application needs to be a public client application (not a web app).

**Step 1 - Register the app**

#. On the **App Registration** blade, click ``+ New Registration``
#. Give the application a **Name**. This will be displayed to users when the log in.
#. Select the appropriate **Account Type**. If you aren't sure, use the
   ``Accounts in this organizational directory only`` option.
#. Set the **Redirect URI Type** to ``Public Client``
#. Set the **Redirect URI** to ``https://login.microsoftonline.com/common/oauth2/nativeclient``
#. Click **Register**

**Step 2 - Set the authentication up correctly**

#. Open your new App, navigate to the **Authentication** tab
#. Ensure the **Implicit grant** flow is enabled with ``ID tokens``
#. Ensure the **Treat application as public client** option is set to ``Yes``

Finally, from the **Overview** tab on the App Registration, record the
``Application (client) ID``. This is used for the ``--cli-client-id`` option.


Middleware App Registration
---------------------------

The CLI application in this package will require a second application. This is used to call
the AWS Enterprise App, on-behalf-of the user. This also enables us to exchange an OAuth
token for a SAML2 Token.

Note: This could at some point in the future be run using a lambda or azure function,
reducing the need to be able to distribute the client secret to your users directly.

The application needs to be a public client application (not a web app).

**Step 1 - Register the app**

#. On the **App Registration** blade, click ``+ New Registration``
#. Give the application a **Name**. This will be displayed to users when the log in
   (although because it's a service to service app, users won't actually see it).
#. Select the appropriate **Account Type**. If you aren't sure, use the
   ``Accounts in this organizational directory only`` option.
#. Set the **Redirect URI Type** to ``Public Client``
#. Set the **Redirect URI** to ``https://login.microsoftonline.com/common/oauth2/nativeclient``
#. Click **Register**

**Step 2 - Set the authentication up correctly**

#. Open your new App, navigate to the **Authentication** tab
#. Ensure the **Implicit grant** flow is enabled with ``ID tokens`` and ``Access tokens``
#. Ensure the **Treat application as public client** option is set to ``Yes``

**Step 3 - Generate a client secret**

#. Navigate to the **Certificates and Secrets** tab.
#. Create a **New client secret**. Record this, it will only be displayed to
   you once. This is used for the ``--middleware-client-secret`` option.

**Step 4 - Add permissions for the AWS app**

#. Navigate to the **API permissions** tab
#. Click **+ Add a permission**
#. Select **APIs my organization uses**
#. Search for ``Amazon Web Services (AWS)``
#. Select **Delegated Permissions**
#. Ensure ``user_impersonation`` is checked
#. Click **Add permissions**

**Step 5 - Authorize the CLI App to call this app**

#. Navigate to the **Expose an API** tab
#. Under **Scopes defined by this API** click ``+ Add a scope``
#. Use the following settings:
    * **Name**: ``user_impersonation``
    * **Who can consent**: ``Admins and users``
    * **Admin consent display name**: Allow application to call to AWS on users behalf
    * **Admin consent description**: Allow application to call to AWS on users behalf
    * **User consent display name**: Allow application to call to AWS on users behalf
    * **User consent description**: Allow application to call to AWS on users behalf
    * **State**: ``Enabled``
#. Click **Add scope**
#. Under **Authorized client applications** click ``+ Add a client application``
#. Select the scope you just created
#. Enter the CLI Application Client ID
#. Click **Add application**

Finally, from the **Overview** tab on the App Registration, record the
``Application (client) ID``. This is used for the ``--middleware-client-id`` option.
