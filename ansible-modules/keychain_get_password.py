#!/opt/homebrew/bin/python3
# -*- coding: utf-8 -*-

import os
import pwd
import platform
import subprocess
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: keychain_get_password
short_description: Retrieve password from macOS Keychain
description:
  - Retrieves a generic password entry from macOS Keychain.
version_added: "1.0.0"
options:
  service:
    description:
      - The service name of the password entry.
    required: true
    type: str
  account:
    description:
      - The account name associated with the password entry.
    required: true
    type: str
  keychain:
    description:
      - Which keychain to use.
      - 'default' uses the user's default login keychain.
      - 'system' uses the system keychain (/Library/Keychains/System.keychain).
    choices: [default, system]
    default: default
    type: str

author:
  - Your Name <you@example.com>
'''

EXAMPLES = r'''
- name: Get password from user default keychain
  keychain_get_password:
    service: "MyService"
    account: "myuser"
  register: result
- debug:
    msg: "Password is {{ result.password }}"

- name: Get password from system keychain
  become: true
  keychain_get_password:
    service: "MyServiceSystem"
    account: "adminuser"
    keychain: system
  register: result
- debug:
    msg: "System keychain password is {{ result.password }}"
'''

RETURN = r'''
password:
  description: Retrieved password or empty string if not found.
  type: str
  returned: always
changed:
  description: Whether something was changed.
  type: bool
  returned: always
message:
  description: Any message explaining result.
  type: str
  returned: on failure
'''

def run_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result

def find_password(service, account, keychain_path):
    cmd = [
        "security", "find-generic-password",
        "-a", account,
        "-s", service,
        "-w",
        keychain_path
    ]
    result = run_cmd(cmd)
    if result.returncode == 0:
        return result.stdout.strip()
    return None

def main():
    module = AnsibleModule(
        argument_spec={
            "service": {"type": "str", "required": True},
            "account": {"type": "str", "required": True},
            "keychain": {"type": "str", "choices": ["default","system"], "default": "default"}
        },
        supports_check_mode=True
    )

    # Проверяем ОС
    if platform.system() != "Darwin":
        module.fail_json(msg="This module can only run on macOS (Darwin). Current OS: {}".format(platform.system()))

    service = module.params['service']
    account = module.params['account']
    keychain_mode = module.params['keychain']

    # Определяем текущего пользователя
    current_user = pwd.getpwuid(os.getuid()).pw_name

    if keychain_mode == "system":
        if os.geteuid() != 0:
            module.fail_json(msg="This module must be run as root (become: true) when using system keychain. Current UID: {}".format(os.geteuid()))
        keychain_path = "/Library/Keychains/System.keychain"
    else:
        # Пользовательская связка ключей
        keychain_path = f"/Users/{current_user}/Library/Keychains/login.keychain-db"

    password = find_password(service, account, keychain_path)
    if password is not None:
        module.exit_json(changed=False, password=password)
    else:
        # Пароль не найден
        module.exit_json(changed=False, password="")

if __name__ == '__main__':
    main()
