#!/usr/bin/env python
from __future__ import print_function

import argparse
import getpass
import logging
import os
import yaml

from HPVCclient import HPVCclient
from HPOAclient import HPOAclient
from SDIutils import set_logfile, log_watermark, message_handler

logger = logging.getLogger("HPaccess.hpaccess")


class MissingYamlValue(Exception):
    pass


class UnknownOARole(Exception):
    pass


class NoPrimaryVCMFound(Exception):
    pass


def read_yaml_file(path):
    """ Reading in yaml file from {}
    """
    if type(path) is str and path[0] == '~':
        home = os.path.expanduser("~")
        path = home + path[1:]

    if not path or not os.path.isfile(path):
        path = get_user_input(
            "hpaccess_config",
            "Enter path to yaml configuration file: ")

    with open(path) as yamlfile:
        return yaml.safe_load(yamlfile)


def get_user_input(var, prompt, secure=False):
    """ Prompting user for {}
    """
    if var in os.environ:
        return os.environ[var]

    try:
        if secure:
            return getpass.getpass(prompt='\033[1;37m{}\033[1;m'.format(prompt))
        else:
            return raw_input('\033[1;37m{}\033[1;m'.format(prompt))
    except KeyboardInterrupt as e:
        # Ctrl+c on a user prompt doesnt properly new line the next print.
        # This fixes that.
        print("")
        raise KeyboardInterrupt(e)


def parse_yaml(file, variables):
    """ Parsing yaml file
    """
    yaml_vars = {}

    for var in variables:
        yaml_vars[var] = file.get(var)
        if not yaml_vars[var]:
            raise MissingYamlValue(
                "No variable '{}' was found in the configuration file".format(var))

    return yaml_vars


def get_vars(path):
    """ Gathering all variables
    """
    yaml_file = read_yaml_file(path)
    yaml_vars = parse_yaml(yaml_file, ['oa_servers', 'ldap_groups'])

    echo_list("OA servers to be configured", yaml_vars['oa_servers'])
    echo_list("LDAP groups to be set", yaml_vars['ldap_groups'])

    creds = get_creds()
    yaml_vars.update(creds)

    return yaml_vars


def get_args():
    """ Parsing CLI arguments
    """
    parser = argparse.ArgumentParser(
        description='Manage Admin access on a HP enclosure')

    parser.add_argument(
        '-f', '--file',
        type=str,
        default='~/hpaccess_config.yaml')

    return parser.parse_args()


def log(msg, log_level="info"):
    """ Logging
    """
    function = getattr(logger, log_level.lower())
    function(msg)


def init_logging(module_name):
    """ Initializing logging
    """
    set_logfile(module_name)

    logging.getLogger("HPaccess.hpaccess").setLevel(logging.INFO)

    logging.getLogger('SSHclient').setLevel(logging.INFO)
    logging.getLogger('HPVCclient').setLevel(logging.INFO)
    logging.getLogger('HPOAclient').setLevel(logging.INFO)

    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.CRITICAL)
    logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.CRITICAL)


def echo_list(header, items, log_level="info"):
    if log_level:
        log("{}: {}".format(header, items), log_level=log_level)

    echo("{}:".format(header), log_level=None)
    for item in items:
        echo("  -{}".format(item), log_level=None)


def echo_dict(header, dictionary, log_level="info"):
    if log_level:
        log("{}: {}".format(header, dictionary), log_level=log_level)

    echo("{}:".format(header), log_level=None)
    for i in dictionary:
        echo("  -{}:  {}".format(i, dictionary[i]), log_level=None)


def echo(message, color="white", newline=True, log_level="info"):
    """ Print message with color
    """
    if log_level:
        log(message, log_level=log_level)

    color = color.lower()

    if color == "red":
        color = '31'
    elif color == "green":
        color = '32'
    elif color == "yellow":
        color = '33'
    elif color == "blue":
        color = '36'
    elif color == "white":
        color = '37'

    message = '\033[1;{}m{}\033[1;m'.format(color, message)

    if newline:
        print(message)
    else:
        print(message, end="")


def get_creds():
    """ Gathering credentials from user
    """
    creds = {}

    creds['username'] = get_user_input(
        'hpaccess_username',
        "Enter username with access to these enclosures: ")

    creds['password'] = get_user_input(
        'hpaccess_password',
        "Enter password for {}: ".format(creds['username']),
        secure=True)

    creds['admin_pass'] = get_user_input(
        'hpaccess_admin_pass',
        "Enter local administrator password to be set for these enclosures: ",
        secure=True)

    return creds


def get_hpoa_client(hostname, username, password):
    """ Grabbing HPOA client for {}
    """
    hpoa_client = HPOAclient.get_HPOAclient(
        hostname=hostname,
        username=username,
        password=password)
    hpoa_client.wrap_handler(message_handler)

    return hpoa_client


def update_oa_ldap(hpoa_client, ldap_groups):
    """ Updating OA LDAP groups
    """
    for ldap_group in ldap_groups:
        hpoa_client.add_ldap_group_access(ldap_group)


def add_ldap_group_access_vcm(ldap_group, hpvc_client):
    """ Configuring LDAP group {} on the VCM with full permissions
    """
    hpvc_client.add_ldap_group(ldap_group=ldap_group)
    hpvc_client.set_ldap_group_permissions(ldap_group=ldap_group)


def update_vcm_ldap(hpvc_client, ldap_groups):
    """ Updating VCM LDAP groups
    """
    for ldap_group in ldap_groups:
        add_ldap_group_access_vcm(ldap_group, hpvc_client)


def get_oa_role(hpoa_client):
    """ Getting OA role
    """
    status = hpoa_client.get_oa_status()

    if status['Role'] != "Standby" and status['Role'] != "Active":
        raise UnknownOARole("OA in unexpected role: '{}'".format(status['Role']))

    return status['Role']


def update_all(oa_server, ldap_groups, username, password, admin_pass):
    """ Updating {}
    """
    log("Getting HPOA client with user credentials")
    hpoa_client = get_hpoa_client(
        hostname=oa_server,
        username=username,
        password=password)

    log("Getting OA role")
    role = get_oa_role(hpoa_client)
    log("OA role: {}".format(role))
    if role != "Active":
        return role

    log("Setting OA administrator password")
    hpoa_client.reset_administrator_password(passwd=admin_pass)

    log("Getting HPOA client with administrator credentials")
    hpoa_client = get_hpoa_client(
        hostname=oa_server,
        username='Administrator',
        password=admin_pass)

    log("Setting OA LDAP access")
    update_oa_ldap(hpoa_client, ldap_groups)

    log("Getting primary VCM from OA")
    primary_vc_ip = hpoa_client.get_primary_virtual_connect()
    if not primary_vc_ip:
        raise NoPrimaryVCMFound("No primary VCM found.")

    log("Primary VCM: {}".format(primary_vc_ip))

    log("Getting HPVC client with user credentials")
    hpvc_client = HPVCclient.get_HPVCclient(
        hostname=primary_vc_ip,
        username=username,
        password=password)

    log("Setting VCM administrator password")
    hpvc_client.reset_administrator_password(passwd=admin_pass)

    log("Getting HPVC client with administrator credentials")
    hpvc_client = HPVCclient.get_HPVCclient(
        hostname=primary_vc_ip,
        username='Administrator',
        password=admin_pass)

    log("Setting VCM LDAP access")
    update_vcm_ldap(hpvc_client, ldap_groups)

    return "Success"


def eval_result(oa_server, result):
    """ Evaluating results
    """
    if result == "Success":
        echo(
            "Finished configuration of OA {}".format(oa_server),
            color="green")
    elif result == "Standby":
        result = "Skipped, OA in standby"
        echo(
            "Skipping configuration of OA {}, OA in standby".format(oa_server),
            color="yellow")
    else:
        echo(
            "Failed configuration of OA {} with: '{}'".format(oa_server, result),
            color="red",
            log_level="error")

    return result


def run(variables):
    """ Running update on all OA servers
    """
    results = {}
    for oa_server in variables['oa_servers']:
        echo("Starting configuration of OA {}".format(oa_server),
             color="White")
        try:
            result = update_all(
                oa_server,
                variables['ldap_groups'],
                variables['username'],
                variables['password'],
                variables['admin_pass'])
        except Exception as e:
            result = e.message
            log(e.message, log_level="exception")

        result = eval_result(oa_server, result)

        results[oa_server] = result

    return results


def main():
    """ Main program
    """
    module_name = 'hpaccess'

    try:
        args = get_args()

        init_logging(module_name)
        log_watermark(module_name)

        variables = get_vars(args.file)

        results = run(variables)

        echo_dict("Results", results)

    except Exception as e:
        echo(e.message, color="red", log_level="exception")
    except KeyboardInterrupt:
        echo("HPaccess script has been terminated prematurely.",
             color="red",
             log_level="error")
    finally:
        log_watermark(module_name, finish=True)


# HPVC client does not have wrap handler for output, doing it manually
HPVCclient.reset_administrator_password = message_handler(HPVCclient.reset_administrator_password)
# nor does it have a method for grouping ldap operations for clean output
add_ldap_group_access_vcm = message_handler(add_ldap_group_access_vcm)


if __name__ == '__main__':
    main()
