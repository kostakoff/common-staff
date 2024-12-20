#!/opt/homebrew/bin/python3
# -*- coding: utf-8 -*-

import os
import pwd
import platform
import subprocess
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: macos_keychain_password
short_description: Manage passwords in macOS Keychain
description:
  - This module allows creating or removing a generic password entry in macOS Keychain.
  - If the password already exists and is different, it will be updated using the -U flag.
version_added: "1.0.0"
options:
  service:
    description:
      - The service name of the password entry.
    required: true
    type: str
  account:
    description:
      - The account name (username) associated with the password entry.
    required: true
    type: str
  password:
    description:
      - The password to set.
      - Required when state=create.
    required: false
    type: str
  state:
    description:
      - Desired state of the password entry.
    choices: [create, absent]
    default: create
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
- name: Create a password in user default keychain
  macos_keychain_password:
    service: "MyService"
    account: "myuser"
    password: "secret"
    state: create

- name: Update a password in user default keychain (if different it will be updated)
  macos_keychain_password:
    service: "MyService"
    account: "myuser"
    password: "newsecret"
    state: create

- name: Create a password in system keychain
  macos_keychain_password:
    service: "MyServiceSystem"
    account: "adminuser"
    password: "adminsecret"
    state: create
    keychain: system
    become: true

- name: Remove a password from default keychain
  macos_keychain_password:
    service: "MyService"
    account: "myuser"
    state: absent
'''

RETURN = r'''
changed:
  description: Whether the keychain entry was changed.
  type: bool
message:
  description: Human-readable message describing the outcome.
  type: str
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

def add_or_update_password(service, account, password, keychain_path):
    cmd = [
        "security", "add-generic-password",
        "-a", account,
        "-s", service,
        "-w", password,
        "-U",
        keychain_path
    ]
    return run_cmd(cmd)

def delete_password(service, account, keychain_path):
    cmd = [
        "security", "delete-generic-password",
        "-a", account,
        "-s", service,
        keychain_path
    ]
    return run_cmd(cmd)

def main():
    module = AnsibleModule(
        argument_spec={
            "service": {"type": "str", "required": True},
            "account": {"type": "str", "required": True},
            "password": {"type": "str", "no_log": True, "required": False},
            "state": {"type": "str", "choices": ["create", "absent"], "default": "create"},
            "keychain": {"type": "str", "choices": ["default","system"], "default": "default"}
        },
        supports_check_mode=True
    )

    # Проверяем ОС
    if platform.system() != "Darwin":
        module.fail_json(msg="This module can only run on macOS (Darwin). Current OS: {}".format(platform.system()))

    service = module.params['service']
    account = module.params['account']
    password = module.params['password']
    state = module.params['state']
    keychain_mode = module.params['keychain']

    # Определяем текущего пользователя
    current_user = pwd.getpwuid(os.getuid()).pw_name

    # Определяем путь к keychain
    if keychain_mode == "system":
        if os.geteuid() != 0:
            module.fail_json(msg="This module must be run as root (become: true) when using system keychain. Current UID: {}".format(os.geteuid()))
        keychain_path = "/Library/Keychains/System.keychain"
    else:
        # Используем явный путь к пользовательской login keychain
        keychain_path = f"/Users/{current_user}/Library/Keychains/login.keychain-db"

    existing_password = find_password(service, account, keychain_path)

    if state == "absent":
        if existing_password is not None:
            if module.check_mode:
                module.exit_json(changed=True, msg="Password would be deleted.")
            result = delete_password(service, account, keychain_path)
            if result.returncode == 0:
                module.exit_json(changed=True, msg="Password deleted.")
            else:
                module.fail_json(msg="Failed to delete password: {}".format(result.stderr))
        else:
            module.exit_json(changed=False, msg="Password not found, nothing to delete.")

    if state == "create":
        if password is None:
            module.fail_json(msg="Password is required when state=create")

        # Если пароль не существует - создаём
        if existing_password is None:
            if module.check_mode:
                module.exit_json(changed=True, msg="Password would be created.")
            res = add_or_update_password(service, account, password, keychain_path)
            if res.returncode == 0:
                module.exit_json(changed=True, msg="Password created.")
            else:
                module.fail_json(msg="Failed to create password: {}".format(res.stderr))
        else:
            # Пароль существует
            if existing_password == password:
                # Пароль совпадает — изменений нет
                module.exit_json(changed=False, msg="Password already exists and matches.")
            else:
                # Обновляем пароль с помощью -U
                if module.check_mode:
                    module.exit_json(changed=True, msg="Password would be updated.")
                res = add_or_update_password(service, account, password, keychain_path)
                if res.returncode == 0:
                    module.exit_json(changed=True, msg="Password updated.")
                else:
                    module.fail_json(msg="Failed to update password: {}".format(res.stderr))

if __name__ == '__main__':
    main()
