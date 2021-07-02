#!/usr/bin/python
# Apache License Version 2.0, January 2004 http://www.apache.org/licenses/

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = '''
---
module: isamadmin
short_description: This module will make calls to connection
description: This module will make calls to connection
author: Ram Sreerangam (@ram-ibm)
options:
    log:
        description:
            - level for log setting
        type: str
        required: False
        default: INFO
        choices:
            - DEBUG
            - INFO
            - ERROR
            - CRITICAL
    isamuser:
        description:
            - user name
        type: str
        required: False
    isampwd:
        description:
            - user password
        type: str
        required: True
    isamdomain:
        description:
            - domain name
        type: str
        required: False
        default: Default
    commands:
        description:
            - list of commands
        type: list
        elements: str
        required: True
'''

EXAMPLES = '''
- name: Configure access control attributes
  ibm.isam.isam:
    log:       "{{ log_level | default(omit) }}"
    force:     "{{ force | default(omit) }}"
    action: ibmsecurity.isam.aac.attributes.get
    isamapi: "{{ item }}"
  when: item is defined
  with_items: "{{ get_access_control_attributes }}"
  register: ret_obj
'''


__metaclass__ = type
import logging.config
import sys
from ansible.module_utils.basic import AnsibleModule
import datetime

from ansible_collections.ibm.isam.plugins.module_utils.isam import ISAMUtil

logger = logging.getLogger(sys.argv[0])


def main():
    module = AnsibleModule(
        argument_spec=dict(
            log=dict(required=False, default='INFO', choices=['DEBUG', 'INFO', 'ERROR', 'CRITICAL']),
            force=dict(required=False, default=False, type='bool'),
            isamuser=dict(required=False),
            isampwd=dict(required=True, no_log=True),
            isamdomain=dict(required=False, default='Default'),
            commands=dict(required=True, type='list', elements='str')
        ),
        supports_check_mode=False
    )

    module.debug('Started isam admin module')

    # Process all Arguments
    isamuser = module.params['isamuser']
    isampwd = module.params['isampwd']
    isamdomain = module.params['isamdomain']
    commands = module.params['commands']

    isam_util = ISAMUtil(module)

    # Execute isam admin commands (pdadmin)
    startd = datetime.datetime.now()

    ret_obj = isam_util.connection.call_isam_admin(isamdomain, isamuser, isampwd, commands)

    endd = datetime.datetime.now()
    delta = endd - startd

    ret_obj['stdout'] = isam_util.strlog.getvalue()
    ret_obj['stdout_lines'] = isam_util.strlog.getvalue().split('\n')
    ret_obj['start'] = str(startd)
    ret_obj['end'] = str(endd)
    ret_obj['delta'] = str(delta)
    ret_obj['cmd'] = "pdadmin execution using Domain: {0}, User: {1} and Commands: {2}".format(isamdomain, isamuser,
                                                                                               commands)

    module.exit_json(**ret_obj)


if __name__ == '__main__':
    main()
