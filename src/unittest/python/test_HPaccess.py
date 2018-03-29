#!/usr/bin/env python
import logging
import os
import sys
import unittest

from mock import patch, mock_open, call, Mock

from HPaccess.hpaccess import add_ldap_group_access_vcm
from HPaccess.hpaccess import echo
from HPaccess.hpaccess import echo_dict
from HPaccess.hpaccess import echo_list
from HPaccess.hpaccess import eval_result
from HPaccess.hpaccess import get_args
from HPaccess.hpaccess import get_creds
from HPaccess.hpaccess import get_hpoa_client
from HPaccess.hpaccess import get_oa_role
from HPaccess.hpaccess import get_user_input
from HPaccess.hpaccess import get_vars
from HPaccess.hpaccess import parse_yaml
from HPaccess.hpaccess import init_logging
from HPaccess.hpaccess import log
from HPaccess.hpaccess import main
from HPaccess.hpaccess import read_yaml_file
from HPaccess.hpaccess import run
from HPaccess.hpaccess import update_all
from HPaccess.hpaccess import update_oa_ldap
from HPaccess.hpaccess import update_vcm_ldap

from HPaccess.hpaccess import MissingYamlValue
from HPaccess.hpaccess import UnknownOARole

from SDIutils import message_handler


logger = logging.getLogger(__name__)

consoleHandler = logging.StreamHandler(sys.stdout)
logFormatter = logging.Formatter(
    "%(asctime)s %(threadName)s %(name)s [%(funcName)s] %(levelname)s %(message)s")
consoleHandler.setFormatter(logFormatter)
rootLogger = logging.getLogger()
rootLogger.addHandler(consoleHandler)
rootLogger.setLevel(logging.DEBUG)


class TestHPaccess(unittest.TestCase):

    def setUp(self):
        """
        """
        self.yaml_config_raw_mock = (
            '---\nldap_groups:\n    - group1\n    - group2\n\noa_servers:\n    - server1\n    - server2')

        self.yaml_config_mock = {
            'ldap_groups': ['group1', 'group2'],
            'oa_servers': ['server1', 'server2']}

        self.incomplete_yaml_config_mock = {
            'ldap_groups': ['group1', 'group2']}

        self.user_creds_vars_mock = {
            'username': 'value',
            'password': 'value',
            'admin_pass': 'value'}

        self.all_vars_mock = {
            'ldap_groups': ['group1', 'group2'],
            'oa_servers': ['server1', 'server2'],
            'username': 'value',
            'password': 'value',
            'admin_pass': 'value'}

    def tearDown(self):
        """
        """
        pass

    @patch('HPaccess.hpaccess.argparse.ArgumentParser.parse_args')
    @patch('HPaccess.hpaccess.argparse.ArgumentParser.add_argument')
    def test__get_args_Calls_add_argument_And_parse_args(
            self, add_argument, parse_args, *patches):

        parse_args.return_value = 'parsed args'
        result = get_args()
        expected_result = 'parsed args'

        # only 2 add_arguments called, but parser init adds one more
        self.assertTrue(len(add_argument.mock_calls) == 2)
        self.assertEqual(result, expected_result)

    @patch('HPaccess.hpaccess.logging.Logger.info')
    @patch('HPaccess.hpaccess.logging.Logger.debug')
    def test__log_Calls_CorrectLogLevel(
            self, loggingDebug_mock, loggingInfo_mock, *patches):

        level = "info"
        msg = "rock and roll"
        log(msg, log_level=level)
        loggingInfo_mock.assert_called_with(msg)

        level = "debug"
        log(msg, log_level=level)
        loggingDebug_mock.assert_called_with(msg)

    @patch('os.path.isfile', return_value=True)
    @patch('yaml.safe_load')
    @patch('HPaccess.hpaccess.open', create=True)
    def test__read_yaml_file_ReadsFileIfPathIsValid(
            self, open_mock, safe_load_mock, *patches):

        open_mock.side_effect = [
            mock_open(read_data=self.yaml_config_raw_mock).return_value]
        safe_load_mock.return_value = self.yaml_config_mock

        result = read_yaml_file('path')
        self.assertEqual(result, self.yaml_config_mock)

    @patch('os.path.isfile', return_value=False)
    @patch('yaml.safe_load')
    @patch('HPaccess.hpaccess.get_user_input', return_value="path")
    @patch('HPaccess.hpaccess.open', create=True)
    def test__read_yaml_file_Calls_get_user_input_WhenPathIsIncorrect(
            self, open_mock, get_user_input_mock, safe_load_mock, *patches):

        open_mock.side_effect = [
            mock_open(read_data=self.yaml_config_raw_mock).return_value]
        safe_load_mock.return_value = self.yaml_config_mock

        result = read_yaml_file(None)

        get_user_input_mock.assert_called_with(
            "hpaccess_config",
            "Enter path to yaml configuration file: ")
        self.assertEqual(result, self.yaml_config_mock)

    @patch('SDIutils.set_logfile')
    @patch('HPaccess.hpaccess.logging')
    def test__init_logging_Sets_CorrectLogLevels(
            self, logging_mock, *patches):

        module_name = 'hpaccess'
        init_logging(module_name)

        getLogger_calls = [
            call("HPaccess.hpaccess"),
            call().setLevel(logging_mock.INFO),
            call("SSHclient"),
            call().setLevel(logging_mock.INFO),
            call("HPVCclient"),
            call().setLevel(logging_mock.INFO),
            call("HPOAclient"),
            call().setLevel(logging_mock.INFO),
            call("requests.packages.urllib3.connectionpool"),
            call().setLevel(logging_mock.CRITICAL),
            call("paramiko.transport"),
            call().setLevel(logging_mock.CRITICAL),
            call("urllib3.connectionpool"),
            call().setLevel(logging_mock.CRITICAL)]

        logging_mock.getLogger.assert_has_calls(getLogger_calls)

    @patch.dict(os.environ, {'test': 'value'})
    def test__get_user_input_Uses_os_environ_WhenVarIsInEnvironment(
            self, *patches):

        result = get_user_input("test", "prompt", secure=False)
        self.assertEqual(result, 'value')

    @patch.dict(os.environ, {'test1': 'value'})
    @patch('HPaccess.hpaccess.raw_input', return_value="plain")
    @patch('HPaccess.hpaccess.getpass.getpass', return_value="secret")
    def test__get_user_input_Calls_getpass_WhenVarNotInEnvironment(
            self, getpass_mock, raw_input_mock, *patches):

        result = get_user_input("test2", "prompt", secure=False)
        self.assertEqual(result, 'plain')
        raw_input_mock.assert_called()

        result = get_user_input("test2", "prompt", secure=True)
        self.assertEqual(result, 'secret')
        getpass_mock.assert_called()

    def test__parse_yaml_Returns_vars_WhenAllPresentInFile(
            self, *patches):

        result = parse_yaml(self.yaml_config_mock, self.yaml_config_mock.keys())
        self.assertEqual(result, self.yaml_config_mock)

    def test__parse_yaml_Raises_MissingYamlValue_WhenVarNotInFile(
            self, *patches):

        with self.assertRaises(MissingYamlValue):
            parse_yaml(self.incomplete_yaml_config_mock, self.yaml_config_mock.keys())

    @patch('HPaccess.hpaccess.echo_list')
    @patch('HPaccess.hpaccess.read_yaml_file')
    @patch('HPaccess.hpaccess.parse_yaml')
    @patch('HPaccess.hpaccess.get_creds')
    def test__get_vars_Returns_YamlAndCredentialVars(
            self, get_creds_mock, parse_yaml_mock, read_yaml_file_mock, echo_list_mock, *patches):
        get_creds_mock.return_value = self.user_creds_vars_mock
        parse_yaml_mock.return_value = self.yaml_config_mock
        read_yaml_file_mock.return_value = self.yaml_config_mock

        path = 'path'

        result = get_vars(path)

        read_yaml_file_mock.assert_called_with(path)
        get_creds_mock.assert_called()
        parse_yaml_mock.assert_called_with(
            self.yaml_config_mock, ['oa_servers', 'ldap_groups'])

        self.assertEqual(len(echo_list_mock.mock_calls), 2)
        self.assertEqual(result, self.all_vars_mock)

    @patch('HPaccess.hpaccess.echo')
    @patch('HPaccess.hpaccess.log')
    def test__echo_list_Calls_log_And_echo(
            self, log_mock, echo_mock, *patches):

        header = 'header'
        items = ['item1', 'item2']
        log_level = "info"

        echo_list(header, items, log_level=log_level)

        log_mock.assert_called_once_with(
            "{}: {}".format(header, items), log_level=log_level)

        self.assertEqual(len(echo_mock.mock_calls), 3)
        echo_mock.assert_any_call("{}:".format(header), log_level=None)
        for item in items:
            echo_mock.assert_any_call("  -{}".format(item), log_level=None)
            echo_mock.assert_any_call("  -{}".format(item), log_level=None)

    @patch('HPaccess.hpaccess.echo')
    @patch('HPaccess.hpaccess.log')
    def test__echo_dict_Calls_log_and_echo(
            self, log_mock, echo_mock, *patches):

        header = 'header'
        dictionary = {'key1': 'value1', 'key2': 'value2'}
        log_level = "info"

        echo_dict(header, dictionary, log_level=log_level)

        log_mock.assert_called_with(
            "{}: {}".format(header, dictionary), log_level=log_level)

        echo_mock.assert_any_call("{}:".format(header), log_level=None)
        for i in dictionary:
            echo_mock.assert_any_call("  -{}:  {}".format(i, dictionary[i]), log_level=None)
            echo_mock.assert_any_call("  -{}:  {}".format(i, dictionary[i]), log_level=None)

    @patch('HPaccess.hpaccess.get_user_input', return_value="value")
    def test__get_creds_Calls_get_user_input_WithCorrectValues(
            self, get_user_input_mock, *patches):

        results = get_creds()

        self.assertEqual(len(get_user_input_mock.mock_calls), 3)
        get_user_input_mock.assert_any_call(
            'hpaccess_username',
            "Enter username with access to these enclosures: ")
        get_user_input_mock.assert_any_call(
            'hpaccess_password',
            "Enter password for {}: ".format(results['username']),
            secure=True)
        get_user_input_mock.assert_any_call(
            'hpaccess_admin_pass',
            "Enter local administrator password to be set for these enclosures: ",
            secure=True)

        self.assertEqual(results, self.user_creds_vars_mock)

    @patch('HPOAclient.hpoaclient.HPOAclient.get_HPOAclient')
    def test__get_hpoa_client_CallsAndReturns_get_HPOAclient(
            self, get_HPOAclient_mock, *patches):

        client_mock = Mock()

        get_HPOAclient_mock.return_value = client_mock
        results = get_hpoa_client(
            "hostname", "username", "password")

        get_HPOAclient_mock.assert_called_once_with(
            hostname="hostname", username="username", password="password")

        client_mock.wrap_handler.assert_called_once_with(message_handler)

        self.assertEqual(results, client_mock)

    def test__update_oa_ldap_Calls_HPOAclient_add_ldap_group_access(
            self, *patches):

        hpoa_client_mock = Mock()
        ldap_groups = self.yaml_config_mock['ldap_groups']

        update_oa_ldap(hpoa_client_mock, ldap_groups)

        calls = [call(group) for group in ldap_groups]

        hpoa_client_mock.add_ldap_group_access.assert_has_calls(calls)

    def test__add_ldap_group_access_vcm_Calls_HPVCclientLdapCalls(
            self, *patches):

        hpvc_client = Mock()
        ldap_group = "group"

        add_ldap_group_access_vcm(ldap_group, hpvc_client)

        hpvc_client.add_ldap_group.assert_called_once_with(ldap_group=ldap_group)
        hpvc_client.set_ldap_group_permissions.assert_called_once_with(ldap_group=ldap_group)

    @patch('HPaccess.hpaccess.add_ldap_group_access_vcm')
    def test__update_vcm_ldap_Calls_add_ldap_group_access_vcm(
            self, add_ldap_group_access_vcm_mock, *patches):

        hpvc_client_mock = Mock()
        ldap_groups = self.yaml_config_mock['ldap_groups']

        update_vcm_ldap(hpvc_client_mock, ldap_groups)

        calls = [call(group, hpvc_client_mock) for group in ldap_groups]

        add_ldap_group_access_vcm_mock.assert_has_calls(calls)

    def test__get_oa_role_Returns_RoleIfValid(
            self, *patches):

        hpoa_client = Mock()

        for role in ['Active', "Standby"]:
            status = {'Role': role}
            hpoa_client.get_oa_status.return_value = status
            result = get_oa_role(hpoa_client)
            self.assertEqual(result, role)

    def test__get_oa_role_Raises_IfRoleNotValid(
            self, *patches):

        hpoa_client = Mock()

        with self.assertRaises(UnknownOARole):
            status = {'Role': 'Unknown'}
            hpoa_client.get_oa_status.return_value = status
            get_oa_role(hpoa_client)

    @patch('HPVCclient.hpvcclient.HPVCclient.get_HPVCclient')
    @patch('HPaccess.hpaccess.log')
    @patch('HPaccess.hpaccess.update_vcm_ldap')
    @patch('HPaccess.hpaccess.update_oa_ldap')
    @patch('HPaccess.hpaccess.get_oa_role')
    @patch('HPaccess.hpaccess.get_hpoa_client')
    def test__update_all_Returns_Success(
            self, get_hpoa_client_mock, get_oa_role_mock, update_oa_ldap_mock,
            update_vcm_ldap_mock, log_mock, get_HPVCclient_mock, *patches):

        hpoa_client = Mock()
        hpvc_client = Mock()

        ldap_groups = ['group1', 'group2']
        oa_server = 'oa_server'
        username = 'username'
        password = 'password'
        admin_user = 'Administrator'
        admin_pass = 'admin_pass'
        pvcip = '1.2.3.4'

        get_hpoa_client_mock.return_value = hpoa_client
        get_oa_role_mock.return_value = "Active"
        get_HPVCclient_mock.return_value = hpvc_client
        hpoa_client.get_primary_virtual_connect.return_value = pvcip

        result = update_all(oa_server, ldap_groups, username, password, admin_pass)
        self.assertEqual(result, 'Success')

        calls = [
            call(hostname=pvcip, password=password, username=username),
            call().reset_administrator_password(passwd=admin_pass),
            call(hostname=pvcip, password=admin_pass, username=admin_user)]
        get_HPVCclient_mock.assert_has_calls(calls)

        calls = [
            call(hostname=oa_server, username=username, password=password),
            call().reset_administrator_password(passwd=admin_pass),
            call(hostname=oa_server, username=admin_user, password=admin_pass),
            call().get_primary_virtual_connect()]
        get_hpoa_client_mock.assert_has_calls(calls)

        get_oa_role_mock.assert_called_once_with(hpoa_client)
        update_oa_ldap_mock.assert_called_once_with(hpoa_client, ldap_groups)
        update_vcm_ldap_mock.assert_called_once_with(hpvc_client, ldap_groups)

    @patch('HPaccess.hpaccess.log')
    @patch('HPaccess.hpaccess.get_oa_role')
    @patch('HPaccess.hpaccess.get_hpoa_client')
    def test__update_all_Returns_Standby(
            self, get_hpoa_client_mock, get_oa_role_mock, log_mock, *patches):

        hpoa_client = Mock()

        ldap_groups = ['group1', 'group2']
        oa_server = 'oa_server'
        username = 'username'
        password = 'password'
        admin_pass = 'admin_pass'

        get_hpoa_client_mock.return_value = hpoa_client
        get_oa_role_mock.return_value = "Standby"

        result = update_all(oa_server, ldap_groups, username, password, admin_pass)
        self.assertEqual(result, 'Standby')

        calls = [
            call(hostname=oa_server, username=username, password=password)]
        get_hpoa_client_mock.assert_has_calls(calls)

        get_oa_role_mock.assert_called_once_with(hpoa_client)

    @patch('HPaccess.hpaccess.echo')
    def test__eval_result_Calls_echo_AndReturnsResult(
            self, echo_mock, *patches):

        oa_server = 'oa_server'
        result = eval_result(oa_server, "Success")
        self.assertEqual(result, "Success")

        result = eval_result(oa_server, "Standby")
        self.assertEqual(result, "Skipped, OA in standby")

        result = eval_result(oa_server, "Error")
        self.assertEqual(result, "Error")

    @patch('HPaccess.hpaccess.log')
    @patch('HPaccess.hpaccess.print')
    def test__echo_Calls_print_WithCorrectColor_And_log_WithCorrectLogLevel(
            self, print_mock, log_mock, *patches):

        message = "test"
        echo(message, color="white", newline=True, log_level="info")
        echo(message, color="red", newline=False, log_level=None)

        log_calls = [
            call(message, log_level="info")]

        print_calls = [
            call('\033[1;37m{}\033[1;m'.format(message)),
            call('\033[1;31m{}\033[1;m'.format(message), end="")]

        log_mock.assert_has_calls(log_calls)
        print_mock.assert_has_calls(print_calls)

    @patch('HPaccess.hpaccess.echo')
    @patch('HPaccess.hpaccess.update_all')
    @patch('HPaccess.hpaccess.eval_result')
    def test__run_Calls_update_all_And_eval_result_ForAllServersPassed(
            self, eval_result_mock, update_all_mock, echo_mock, *patches):

        test_result = "result"
        expected_result = {}
        for oa_server in self.all_vars_mock['oa_servers']:
            expected_result[oa_server] = test_result

        eval_result_mock.return_value = test_result
        update_all_mock.return_value = test_result

        result = run(self.all_vars_mock)
        self.assertEquals(result, expected_result)

        eval_result_calls = []
        update_all_calls = []

        for oa_server in self.all_vars_mock['oa_servers']:
            eval_result_calls.append(call(oa_server, test_result))
            update_all_calls.append(
                call(
                    oa_server,
                    self.all_vars_mock['ldap_groups'],
                    self.all_vars_mock['username'],
                    self.all_vars_mock['password'],
                    self.all_vars_mock['admin_pass']))

        eval_result_mock.assert_has_calls(eval_result_calls)
        update_all_mock.assert_has_calls(update_all_calls)

    @patch('HPaccess.hpaccess.echo')
    @patch('HPaccess.hpaccess.echo_dict')
    @patch('HPaccess.hpaccess.run')
    @patch('HPaccess.hpaccess.get_vars')
    @patch('HPaccess.hpaccess.log_watermark')
    @patch('HPaccess.hpaccess.init_logging')
    @patch('HPaccess.hpaccess.get_args')
    def test__main_InitializesAndRunsHPaccess(
            self, get_args_mock, init_logging_mock, log_watermark_mock, get_vars_mock,
            run_mock, echo_dict_mock, echo_mock, *patches):

        module_name = 'hpaccess'
        args_mock = Mock()
        get_args_mock.return_value = args_mock
        get_vars_mock.return_value = self.all_vars_mock
        run_mock.return_value = "Result"

        main()

        get_args_mock.assert_called_once_with()
        init_logging_mock.assert_called_once_with(module_name)
        get_vars_mock.assert_called_once_with(args_mock.file)
        run_mock.assert_called_once_with(self.all_vars_mock)
