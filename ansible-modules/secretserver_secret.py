#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import uuid
from time import sleep, time
from string import Template

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url

DOCUMENTATION = r'''
---
module: get_bearer_token
short_description: Get Bearer token from a custom OAuth API and retrieve a secret from Password Vault
description:
  - This module registers an SDK client account using a rule and key, obtains a bearer token, and retrieves a secret from Password Vault using that token.
options:
  key:
    description: The onboarding key.
    required: true
    type: str
  rule:
    description: The rule name.
    required: true
    type: str
  secret_id:
    description: The ID of the secret to retrieve from the Password Vault.
    required: true
    type: str
author:
  - kostakoff
'''

EXAMPLES = r'''
- name: Get credentials from secretserver
  get_bearer_token:
    key: "my-onboarding-key"
    rule: "my-rule"
    secret_id: "123456"
  register: secret_credentials
  no_log: true
'''

RETURN = r'''
username:
  description: Username from retrieved secret.
  type: str
  returned: always
password:
  description: Password from retrieved secret.
  type: str
  returned: always
notes:
  description: Notes from retrieved secret.
  type: str
  returned: always
'''

SDK_API = "https://passwordvault.my.org/SecretServer/api/v1/sdk-client-accounts"
BEARER_TOKEN_URL = "https://passwordvault.my.org/SecretServer/oauth2/token"
API = "https://passwordvault.my.org/SecretServer/api/v1"

def get_bearer_token(module, key, rule, retry_count=3, retry_delay=1):
    start_time = time()

    for attempt in range(1, retry_count + 1):
        if attempt > 1:
            sleep(retry_delay)

        sdkClientParams = {
            'clientId': str(uuid.uuid4()),
            'clientName': uuid.uuid4().hex[:12],
            'ruleName': rule,
            'ruleKey': key
        }
        sdkClientTemplate = Template('{"ClientId":"${clientId}","Name":"${clientName}","Description":"Machine : ${clientName}, OS : X64 - .NET Core 4.6.27129.04 X64","RuleName":"${ruleName}","OnboardingKey":"${ruleKey}"}')
        sdkClientJson = sdkClientTemplate.substitute(sdkClientParams)
        sdkHeaders = {'Content-Type': 'application/json'}

        sdk_response, sdk_info = fetch_url(module, SDK_API, data=sdkClientJson, headers=sdkHeaders, method='POST')
        if sdk_info['status'] != 200:
            if attempt == retry_count:
                module.fail_json(msg=f"Failed to register SDK client after {retry_count} attempts. Status: {sdk_info['status']}")
            else:
                continue
        
        sdk_body = sdk_response.read()
        sdk_json = json.loads(sdk_body)
        client_secret = sdk_json['clientSecret']

        token_payload = {
            'grant_type': 'client_credentials',
            'client_id': f"sdk-client-{sdkClientParams.get('clientId')}",
            'client_secret': client_secret
        }
        token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        token_data = '&'.join([f"{k}={v}" for k,v in token_payload.items()])

        token_response, token_info = fetch_url(module, BEARER_TOKEN_URL, data=token_data, headers=token_headers, method='POST')
        if token_info['status'] != 200:
            if attempt == retry_count:
                module.fail_json(msg=f"Failed to get bearer token after {retry_count} attempts. Status: {token_info['status']}")
            else:
                continue

        token_body = token_response.read()
        token_json = json.loads(token_body)
        token = token_json['access_token']

        return token

    total_time = int(time() - start_time)
    module.fail_json(msg=f"Failed to generate bearer token in {retry_count} attempts over {total_time} seconds")

def secret_server_call(module, token, secret_id, retry_count=3, retry_delay=1):
    url = f"{API}/secrets/{secret_id}"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    for attempt in range(1, retry_count + 1):
        if attempt > 1:
            sleep(retry_delay)

        response, info = fetch_url(module, url, headers=headers, method='GET')
        
        if info['status'] not in (200, 304):
            if attempt == retry_count:
                body = response.read() if response else ''
                module.fail_json(msg=f"Error retrieving secret with ID {secret_id} after {retry_count} attempts.",
                                 status=info['status'], body=body)
            else:
                continue

        body = response.read()
        secret_data = json.loads(body)
        return secret_data

def credential_capability(module, token, secret_id):
    secret_data = secret_server_call(module, token, secret_id)
    username = ""
    password = ""
    notes = ""

    items = secret_data.get("items", [])
    for item in items:
        slug = item.get("slug", "").lower()
        if slug == "username":
            username = item.get("itemValue", "")
        elif slug == "password":
            password = item.get("itemValue", "")
        elif slug == "notes":
            notes = item.get("itemValue", "").replace('\n', ' ')

    return username, password, notes

def main():
    module = AnsibleModule(
        argument_spec=dict(
            key=dict(type='str', required=True),
            rule=dict(type='str', required=True),
            secret_id=dict(type='str', required=True),
        ),
        supports_check_mode=False
    )

    key = module.params['key']
    rule = module.params['rule']
    secret_id = module.params['secret_id']

    token = get_bearer_token(module, key, rule)

    username, password, notes = credential_capability(module, token, secret_id)

    module.exit_json(changed=False, username=username, password=password, notes=notes)


if __name__ == '__main__':
    main()
