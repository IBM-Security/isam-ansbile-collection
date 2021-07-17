from __future__ import (absolute_import, division, print_function)
import ibmsecurity.isam.web.runtime.pdadmin
from ibmsecurity.user.isamuser import ISAMUser

__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Security Automation Team <https://github.com/ansible-security>
connection: ibm.isam
short_description: Use ibmsecurity python library to connect to IBM ISAM appliances
description:
  - This connection plugin provides a connection to IBM ISAM devices
    via the C(ibmsecurity) python library.
version_added: "2.9"
options:
  host:
    type: str
    description:
      - Specifies the remote device FQDN or IP address of the IBM ISAM Appliance
        to establish a connection to.
    default: inventory_hostname
    vars:
      - name: ansible_host
  port:
    type: int
    description:
      - Specifies the port on the LMI Port that the IBM ISAM Appliance listens
        on.
    ini:
      - section: defaults
        key: remote_port
    env:
      - name: ANSIBLE_ISAM_PORT
    vars:
      - name: ansible_isam_port
  user:
    type: str
    description:
      - The username used to authenticate to the remote device when the API
        connection is first established.  If the remote_user is not specified,
        the connection will use the username of the logged in user.
      - Can be provided to the ansible CLI via the C(--user) or C(-u) options.
    ini:
      - section: defaults
        key: remote_user
    env:
      - name: ANSIBLE_ISAM_USER
    vars:
      - name: ansible_isam_user
      - name: ansible_isam_username
  password:
    type: str
    description:
      - Password used to authenticate to the IBM ISAM Appliance.
    vars:
      - name: ansible_password
      - name: ansible_isam_pass
      - name: ansible_isam_password
  persistent_connect_timeout:
    type: int
    description:
      - Configures, in seconds, the amount of time to wait when trying to
        initially establish a persistent connection.  If this value expires
        before the connection to the remote device is completed, the connection
        will fail.
    default: 30
    ini:
      - section: persistent_connection
        key: connect_timeout
    env:
      - name: ANSIBLE_PERSISTENT_CONNECT_TIMEOUT
    vars:
      - name: ansible_connect_timeout
  persistent_command_timeout:
    type: int
    description:
      - Configures, in seconds, the amount of time to wait for a command to
        return from the remote device.  If this timer is exceeded before the
        command returns, the connection plugin will raise an exception and
        close.
    default: 30
    ini:
      - section: persistent_connection
        key: command_timeout
    env:
      - name: ANSIBLE_PERSISTENT_COMMAND_TIMEOUT
    vars:
      - name: ansible_command_timeout
  persistent_log_messages:
    type: boolean
    description:
      - This flag will enable logging the command executed and response received from
        target device in the ansible log file. For this option to work 'log_path' ansible
        configuration option is required to be set to a file path with write access.
      - Be sure to fully understand the security implications of enabling this
        option as it could create a security vulnerability by logging sensitive information in log file.
    default: False
    ini:
      - section: persistent_connection
        key: log_messages
    env:
      - name: ANSIBLE_PERSISTENT_LOG_MESSAGES
    vars:
      - name: ansible_persistent_log_messages

"""
import importlib

from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.connection import NetworkConnectionBase

try:
    from ibmsecurity.appliance.isamappliance import ISAMAppliance
    from ibmsecurity.appliance.isamappliance_adminproxy import ISAMApplianceAdminProxy
    from ibmsecurity.appliance.ibmappliance import IBMError
    from ibmsecurity.user.applianceuser import ApplianceUser

    HAS_IBMSECURITY = True
except ImportError:
    HAS_IBMSECURITY = False


class Connection(NetworkConnectionBase):
    '''IBM ISAM via ibmsecurity library connection'''

    transport = 'isam'
    has_pipelining = False
    has_tty = False

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        self.isam_server = None
        if not HAS_IBMSECURITY:
            raise AnsibleConnectionFailure(
                "Error> ibmsecurity python module required for ibm.isam.isam connection plugin"
            )

    def _connect(self):
        if not self.connected:
            host = self.get_option('host')
            port = self.get_option('port') or 443
            user = self.get_option('user')
            passwd = self.get_option('password')

            self.queue_message(
                'vvv',
                "Connection to IBM ISAM Appliance established for user: {0} -> {1}".format(user,
                                                                                           'https://{0}:{1}'.format(
                                                                                               host, port)
                                                                                           )
            )
            # Create appliance object to be used for all calls
            if user == '' or user is None:
                u = ApplianceUser(password=passwd)
            else:
                u = ApplianceUser(username=user, password=passwd)

            # FIXME - add AdminProxy options and handle that here
            #
            # Create appliance object to be used for all calls
            # if adminProxy hostname is set, use the ISAMApplianceAdminProxy
            # if adminProxyHostname == '' or adminProxyHostname is None or omitAdminProxy:
            #    self.isam_server = ISAMAppliance(hostname=host, user=u, lmi_port=port)
            # else:
            #    self.isam_server = ISAMApplianceAdminProxy(adminProxyHostname=adminProxyHostname, user=u,
            #    hostname=appliance, adminProxyProtocol=adminProxyProtocol, adminProxyPort=adminProxyPort,
            #    adminProxyApplianceShortName=adminProxyApplianceShortName)
            #    pass
            self.isam_server = ISAMAppliance(hostname=host, user=u, lmi_port=port)
            self._sub_plugin = {'name': 'isam_server', 'obj': self.isam_server}

            self._connected = True

    def reset(self):
        self._connected = False
        self._connect()

    def call_isam_action(self, isam_module, options):
        """
        Imports a module and executes a target module dynamically using the
        persistent ISAMAppliance instance.

 :arg isam_module: str, the fully qualified module.method name to invoke
 :arg options: dict, the dict of options to pass to the API call

 :returns: dict, return value(s) from the api call
        """
        if not self.connected:
            self._connect()
        try:
            module_name, method_name = isam_module.rsplit('.', 1)
            self.queue_message('vvv', 'Action method to be imported from module: ' + module_name)
            self.queue_message('vvv', 'Action method name is: ' + method_name)
            mod = importlib.import_module(module_name)
            func_ptr = getattr(mod, method_name)  # Convert action to actual function pointer
            func_call = 'func_ptr(' + options + ')'

            # Execute requested 'action'
            ret_obj = eval(func_call)
            if ret_obj is None:
                ret_obj = {}
            ret_obj['ansible_facts'] = self.isam_server.facts
            return ret_obj
        except ImportError as e:
            raise AnsibleConnectionFailure('Error> action belongs to a module that is not found!', isam_module, e)
        except AttributeError as e:
            raise AnsibleConnectionFailure('Error> invalid action was specified, method not found in module!',
                                           isam_module, e)
        except TypeError as e:
            raise AnsibleConnectionFailure(
                'Error> action does not have the right set of arguments or there is a code bug! Options: ' + options,
                isam_module, e)
        except IBMError as e:
            raise AnsibleConnectionFailure("Error> IBMError, action: {0} Exception: {1}".format(isam_module, e), options,
                                           e)

    def call_isam_admin(self, adminDomain, isamuser, isampwd, commands, ignore_error):
        """
        Execute an ISAM Admin command, also know as pdadmin commands
        """
        if not self.connected:
            self._connect()
        try:
            if isamuser == '' or isamuser is None:
                iu = ISAMUser(password=isampwd)
            else:
                iu = ISAMUser(username=isamuser, password=isampwd)

            # Execute isam admin function
            ret_obj = ibmsecurity.isam.web.runtime.pdadmin.execute(isamAppliance=self.isam_server, isamUser=iu,
                                                                   admin_domain=adminDomain, commands=commands, ignore_error=ignore_error)
            ret_obj['ansible_facts'] = self.isam_server.facts
            return ret_obj
        except ImportError as e:
            raise AnsibleConnectionFailure('Error> Unable to Import pdadmin module!')
        except IBMError as e:
            raise AnsibleConnectionFailure("Error> IBMError", e)

    def close(self):
        '''
        Close the active session to the device
        '''
        # only close the connection if its connected.
        if self._connected:
            self.queue_message('vvv', "closing connection to IBM ISAM device")

        super(Connection, self).close()
