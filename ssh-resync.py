#!/usr/bin/env python3

import os
import sys
import argparse
import getpass
import platform
import paramiko
from paramiko import SFTPClient
import base64
import socket
from binascii import hexlify
import re
import uuid
import subprocess
import json
import time
from datetime import timezone
import datetime

class colors:
    '''Colors class:reset all colors with colors.reset; two
    sub classes fg for foreground
    and bg for background; use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.greenalso, the generic bold, disable,
    underline, reverse, strike through,
    and invisible work with the main class i.e. colors.bold'''

    reset='\x1b[0m'
    bold='\x1b[01m'
    disable='\x1b[02m'
    underline='\x1b[04m'
    reverse='\x1b[07m'
    strikethrough='\x1b[09m'
    invisible='\x1b[08m'

    class fg:
        black='\x1b[30m'
        red='\x1b[31m'
        green='\x1b[32m'
        orange='\x1b[33m'
        blue='\x1b[34m'
        magenta='\x1b[35m'
        cyan='\x1b[36m'
        white='\x1b[37m'
        grey='\x1b[90m'
        lightred='\x1b[91m'
        lightgreen='\x1b[92m'
        yellow='\x1b[93m'
        lightblue='\x1b[94m'
        pink='\x1b[95m'
        lightcyan='\x1b[96m'

    class bg:
        black='\x1b[40m'
        red='\x1b[41m'
        green='\x1b[42m'
        orange='\x1b[43m'
        blue='\x1b[44m'
        magenta='\x1b[45m'
        cyan='\x1b[46m'
        white='\x1b[47m'

class Utils:
    def list_object_items(self, object, return_dicts=False, prefix=''):
        items = []

        for item in vars(object):
            if not item.startswith('__'):
                item_content = getattr(object, item)
                is_object = False
                try:
                    vars(item_content)
                    is_object = True
                except Exception:
                    pass

                if is_object:
                    item_prefix='%s%s.' %(prefix, item)
                    sub_items = self.list_object_items(item_content, return_dicts, item_prefix)
                    if isinstance(sub_items, list):
                        items += sub_items
                else:
                    if return_dicts:
                        items.append({'key': prefix + item, 'val': item_content})
                    else:
                        items.append(prefix + item)

        return items

    def raw_print(self, text, target='stdout'):
        for item in self.list_object_items(colors, return_dicts=True):
            color_name = item['key']
            color_code = item['val']
            if color_name.startswith('fg.'):
                color_name = color_name.split('fg.')[1]
            elif color_name.startswith('bg.'):
                color_name = color_name.split('bg.')[1] + 'bg'

            text = item['val'].join(text.split('${%s}' %(color_name)))
            text = item['val'].join(text.split('{%s}' %(color_name)))

        if target == 'stderr':
            sys.stderr.write(text)
        else:
            sys.stdout.write(text)

    def print(self, text, target='stdout'):
        self.raw_print(text + "\n", target)

    def debug(self, text, level=0, timestamp=True):
        if not isinstance(text, str):
            text = str(text)

        if verbose_level >= level:
            leading_spaces = len(text) - len(text.lstrip())
            leading_str = ' ' * leading_spaces
            if timestamp:
                dt = datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                text = '%s%s: %s' %(leading_str, dt, text.lstrip())
            else:
                text = '%s%s' %(leading_str, text)
            self.print(text, 'stderr')

    def colored_msg(self, text, color, target='stdout'):
        self.print('{%s}%s{reset}' %(color, text), target)


class HostUnreachable(Exception):
    pass

class SSH:
    __default_users = ['debian', 'redhat', 'ubuntu', 'fedora', 'centos']
    __auth_methods = []
    __failed_auth_methods = []
    __auth_method = None
    __host = None
    __user = None
    __identity = None
    __password = None
    __conn = None
    __jump_hosts = None
    __resolves = {}
    __known_hosts = None
    __host_keys_filepath = None
    __host_keys_filepath_stats = None
    __host_keys_backup_filepath = None
    __host_keys = None
    __host_list_filepath = None

    def __init__(self):
        pass

    def parseHostsFile(self, hosts_filepath):
        result = False

        if self.__host_keys is not None and os.path.isfile(hosts_filepath):
            self.__host_list_filepath = hosts_filepath

            foundItems = []
            host_keys_changes = False

            with open(hosts_filepath, 'r') as f:
                utils.debug('Parsing hosts list file: %s' %(hosts_filepath), 2)
                for line in f.readlines():
                    fields = line.split()
                    for i in range(0, len(fields)):
                        hostnames = None

                        item = fields[i]
                        if item.startswith('#'):
                            break

                        if item not in foundItems:
                            utils.debug('Searching for %s in %s' %(item, self.__host_keys_filepath), 5)
                            hostnames = self.lookupKnownHosts(item)
                            if hostnames is not None:
                                utils.debug('Found item <{cyan}%s{reset}> in %s' %(item, self.__host_keys_filepath), 2)
                                foundItems.append(item)

                        if hostnames is not None:
                            for hostname in hostnames:
                                h = hostname['hostname']
                                if h in self.__known_hosts:
                                    if self.__known_hosts[h]['hashed'] and self.__known_hosts[h]['clear_name'] is None:
                                        hostnameInfo = self.getHostnameInfo(item)
                                        for key in ['clear_name', 'reachable', 'hostname', 'ip']:
                                            self.__known_hosts[h][key] = hostnameInfo[key]

                result = True

        return result

    def loadKnownHosts(self, known_hosts_filepath):
        if os.path.isfile(known_hosts_filepath):
            self.__host_keys_filepath = known_hosts_filepath
            try:
                self.__host_keys = paramiko.hostkeys.HostKeys(known_hosts_filepath)
            except Exception as e:
                utils.debug('{red}%s{reset}' %(e))
                sys.exit(1)

            if self.__host_keys is not None:
                self.__host_keys_filepath_stats = os.stat(self.__host_keys_filepath)

                if self.__known_hosts is None:
                    self.__known_hosts = {}
                    for lineno, hostname in enumerate(self.__host_keys.keys(), 1):
                        host = {'lineno': lineno, 'name': hostname, 'clear_name': None, 'reachable': False, 'jump_host': None, 'hostname': None, 'ip': None, 'port': None, 'hashed': False, 'key': None, 'replaced_key': None}
                        host['key'] = self.getHostKeyInfo(self.__host_keys[hostname])

                        hostnameInfo = self.getHostnameInfo(hostname)
                        for key in ['clear_name', 'reachable', 'hostname', 'ip', 'port', 'hashed']:
                            host[key] = hostnameInfo[key]

                        self.__known_hosts[hostname] = host

    def getHostKeyInfo(self, hostkey):
        result = None

        key = None
        keyType = None
        keyFingerPrint = None
        keyString = None

        for e in hostkey._entries:
            if e.valid:
                key = e.key

                if key is not None:
                    keyType = key.get_name()
                    keyString = key.get_base64()
                    keyFingerPrint = hexlify(key.get_fingerprint()).decode('utf-8')
                    result = {'key': key, 'key_type': keyType, 'key_string': keyString, 'finger_print': keyFingerPrint}

        return result

    def resolveHostname(self, hostname, jump_host=None):
        result = None

        oldDefaultTimeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.5)

        try:
            socket.inet_aton(hostname)
            result = hostname
        except Exception as e:
            pass

        if result is None:
            if hostname in self.__resolves:
                utils.debug('Taking <{cyan}%s{reset}> matching IP from previously resolved hostnames' %(hostname), 3)
                result = self.__resolves[hostname]
            else:
                try:
                    if jump_host is not None:
                        cmd = """
import socket
print(socket.gethostbyname('%s'))
""" %(hostname)

                        utils.debug('Trying to resolve {cyan}%s{reset} from jump host <{cyan}%s@%s:%s{reset}>' %(hostname, jump_host['user'], jump_host['host'], jump_host['port']), 3)
                        res = self.jumpExec(cmd, jump_host)
                        if res is not None:
                            for line in res:
                                line = line.strip()
                                try:
                                    socket.inet_aton(line)
                                    result = line
                                except Exception as e:
                                    pass
                                if result is not None:
                                    utils.debug('result: <%s>' %(result), 3)
                                    break
                    else:
                        utils.debug('Trying to resolve {cyan}%s{reset}' %(hostname), 3)
                        ip = socket.gethostbyname(hostname)
                        result = ip
                except Exception as e:
                    utils.debug('{red}Failed to resolve {cyan}%s{red}!{reset}' %(hostname), 2)

        if result is not None and hostname not in self.__resolves:
            self.__resolves[hostname] = result

        socket.setdefaulttimeout(oldDefaultTimeout)

        return result

    def getHostnameInfo(self, hostname, port=None, jump_host=None):
        if hostname is not None:
            hostname = hostname.strip()

        result = {'name': hostname, 'clear_name': None, 'reachable': False, 'jump_host': None, 'hostname': None, 'ip': None, 'port': port, 'hashed': False}

        if hostname is None or hostname == '':
            return result
        elif hostname.startswith('|1|'):
            result['hashed'] = True
            if port is None:
                result['port'] = 22
        else:
            clear_name = hostname
            if ':' in clear_name:
                clear_name = clear_name.split(':')
                if len(clear_name) > 1 and clear_name[1] != '' and clear_name[1].isnumeric() and port is None:
                    port = int(clear_name[1])
                hostname = clear_name[0]
            if port is None:
                port = 22

            result['clear_name'] = clear_name
            result['port'] = port

            try:
                socket.inet_aton(hostname)
                result['ip'] = hostname
            except Exception as e:
                pass

            if result['ip'] is None:
                result['hostname'] = hostname
                ip = self.resolveHostname(hostname, jump_host)
                if ip is not None:
                    result['ip'] = ip
                    if jump_host is not None:
                        result['jump_host'] = jump_host

            if result['ip'] is not None:
                if self.checkHost(result['ip'], port=port, timeout=0.1, jump_host=jump_host):
                    utils.debug('{green}Host IP check ok: <{cyan}%s{green}>{reset}' %(result['ip']), 2)
                    result['reachable'] = True
                else:
                    utils.debug('{red}Host IP check failed: <{cyan}%s{red}>!{reset}' %(result['ip']), 2)

        return result

    def saveKnownHosts(self, known_hosts_filepath):
        result = False

        if self.__host_keys is not None and known_hosts_filepath is not None and known_hosts_filepath != '':
            try:
                utils.debug('Replacing known_hosts file: %s' %(known_hosts_filepath), 1)
                tmp_known_hosts_filepath = '%s.tmp' %(known_hosts_filepath)
                if os.path.isfile(tmp_known_hosts_filepath):
                    os.unlink(tmp_known_hosts_filepath)
                self.__host_keys.save(tmp_known_hosts_filepath)
                if os.path.isfile(tmp_known_hosts_filepath):
                    try:
                        os.chmod(tmp_known_hosts_filepath, self.__host_keys_filepath_stats.st_mode)
                        if platform.system() != 'Windows':
                            os.chown(tmp_known_hosts_filepath, self.__host_keys_filepath_stats.st_uid, self.__host_keys_filepath_stats.st_gid)
                        if os.path.isfile(known_hosts_filepath):
                            os.unlink(known_hosts_filepath)
                        os.rename(tmp_known_hosts_filepath, known_hosts_filepath)
                        result = True
                    except Exception as e:
                        utils.debug('{red}saveKnownHosts: %s{reset}' %(e))
                    finally:
                        if os.path.isfile(tmp_known_hosts_filepath):
                            os.remove(tmp_known_hosts_filepath)
            except Exception as e:
                utils.debug('{red}saveKnownHosts: %s{reset}' %(e), 1)

        return result

    def lookupKnownHosts(self, hostname):
        result = []

        if self.__host_keys is not None:
            matches = self.__host_keys.lookup(hostname)
            if matches is not None:
                for e in matches._entries:
                    for h in e.hostnames:
                        h_dict = {'hostname': h, 'lineno': None}
                        for lineno, k in enumerate(self.__host_keys.keys(), 1):
                            if k == h:
                                h_dict['lineno'] = lineno
                                break
                        result.append(h_dict)

        if len(result) == 0:
            result = None

        return result

    def unhashKnownHosts(self, unhashed_known_hosts_filepath):
        result = False

        if self.__host_keys is not None and self.__known_hosts is not None:
            unhashed_host_keys = paramiko.hostkeys.HostKeys()

            for h in self.__host_keys.keys():
                if h in self.__known_hosts:
                    host = self.__known_hosts[h]

                    name = host['name']
                    keyType = None
                    key = None

                    if host['key'] is not None:
                        keyType = host['key']['key_type']
                        key = host['key']['key']

                        if host['clear_name'] is not None:
                            name = host['clear_name']

                        unhashed_host_keys.add(name, keyType, key)

            if len(unhashed_host_keys) > 0:
                utils.debug('Recording a unhashed (as much as possible with found hosts) version of the known_hosts file in %s' %(unhashed_known_hosts_filepath), 1)
                unhashed_host_keys.save(unhashed_known_hosts_filepath)
                result = True

        return result

    def listJumpHosts(self):
        result = ''

        if self.__jump_hosts is not None and len(self.__jump_hosts) > 0:
            for jump_host in self.__jump_hosts:
                if result != '':
                    result += '\n'
                result += '{magenta}%s{reset}: {cyan}%s@%s:%s{reset}' %(jump_host['jump_host_idx'] + 1, jump_host['user'], jump_host['host'], jump_host['port'])
                if jump_host['linked_jump_host_idx'] is not None:
                    linked_idx = jump_host['linked_jump_host_idx']
                    result += ' (linked to {magenta}%s{reset}: {cyan}%s@%s:%s{reset})' %(self.__jump_hosts[linked_idx]['jump_host_idx'] + 1, self.__jump_hosts[linked_idx]['user'], self.__jump_hosts[linked_idx]['host'], self.__jump_hosts[linked_idx]['port'])
        return result

    def getLinkedJumpHosts(self, jump_host):
        result = []

        if jump_host is not None and self.__jump_hosts is not None:
            result.append(jump_host)
            if jump_host['linked_jump_host_idx'] is not None:
                tmp_result = self.getLinkedJumpHosts(self.__jump_hosts[jump_host['linked_jump_host_idx']])
                for tmp_jump_host in tmp_result:
                    result.append(tmp_jump_host)

        return result

    def getJumpHostsStr(self, jump_host):
        result = ''

        if jump_host is not None:
            jump_host_list = self.getLinkedJumpHosts(jump_host)
            if isinstance(jump_host_list, list) and len(jump_host_list) > 0:
                jump_host_list.reverse()
                for tmp_jump_host in jump_host_list:
                    if result != '':
                        result += ' => '
                    result += '{magenta}%s@%s:%s{reset}' %(tmp_jump_host['user'], tmp_jump_host['host'], tmp_jump_host['port'])

        return result

    def createJumpHost(self, linked_jump_host=None):
        jump_host = None

        go_ahead = True

        sys.stdout.write('New Jump Host Hostname (:port)? ')
        host = input().lower()
        port = 22
        if ':' in host:
            host = host.split(':')
            if len(host) > 1 and host[1] != '22':
                port = int(host[1])
                host = host[0]
        hostInfos = self.getHostnameInfo(host, port, linked_jump_host)
        if hostInfos['ip'] is None:
            utils.debug('{red}The hostname <{cyan}%s{red}> is not resolvable!{reset}' %(host))
            go_ahead = False
        if go_ahead and not hostInfos['reachable']:
            utils.debug('{red}The hostname <{cyan}%s{red}> is not reachable!{reset}' %(host))
            go_ahead = False

        if go_ahead:
            sys.stdout.write('User: ')
            user = input()
            if user == '':
                utils.debug('{red}User name cannot be empty!{reset}')
                go_ahead = False

        if go_ahead:
            password = getpass.getpass(prompt='Password: ')
            if password == '':
                utils.debug('{red}Password cannot be empty!{reset}')
                go_ahead = False

        if go_ahead:
            jump_host = self.connectJump(host, user, password=password, port=port, jump_host=linked_jump_host)
            if jump_host is not None:
                utils.debug('{green}Successfully connected to {cyan}%s@%s:%s{reset}' %(jump_host['user'], jump_host['host'], jump_host['port']), 2)
            else:
                go_ahead = False

        return jump_host

    def autoCheckJumpHosts(self, target_host):
        jump_host = None

        hostInfos = None
        if target_host is not None:
            hostInfos = self.getHostnameInfo(target_host['clear_name'], target_host['port'])
            if not hostInfos['reachable'] and self.__jump_hosts is not None and len(self.__jump_hosts) > 0:
                for jump_host in self.__jump_hosts:
                    hostInfos = self.getHostnameInfo(target_host['clear_name'], target_host['port'], jump_host)
                    if hostInfos['reachable']:
                        break

            if not hostInfos['reachable']:
                jump_host = None

        return jump_host

    def configureJumpHosts(self, target_host=None):
        jump_host = None

        exit = False
        hostInfos = None
        if target_host is not None:
            hostInfos = self.getHostnameInfo(target_host['clear_name'], target_host['port'])
            if hostInfos['reachable']:
                exit = True
            else:
                tmp_jump_host = self.autoCheckJumpHosts(target_host)
                if tmp_jump_host is not None:
                    jump_host = tmp_jump_host
                    exit = True

        linked_jump_host = None
        go_ahead = True
        while not exit:
            host = None
            port = 22
            user = None
            password = None

            if go_ahead and not exit and linked_jump_host is None and jump_host is None:
                if self.__jump_hosts is not None and len(self.__jump_hosts) > 0:
                    sys.stdout.write('Do you want to use an existing pre-configured jump host [Y/n]? ')
                    response = input().lower()
                    if response != 'n':
                        jump_hosts_list_str = self.listJumpHosts()
                        if jump_hosts_list_str is not None:
                            utils.print(jump_hosts_list_str)
                        sys.stdout.write('Please enter the index number matching the pre-configured jump host you would like to use: ')
                        response = input()
                        if response.isnumeric():
                            response = int(response)
                            if response >= 1 and response <= len(self.__jump_hosts):
                                jump_host = self.__jump_hosts[response - 1]
                                if jump_host['linked_jump_host_idx'] is not None:
                                    linked_jump_host = self.__jump_hosts[jump_host['linked_jump_host_idx']]
                                if target_host is not None:
                                    hostInfos = self.getHostnameInfo(target_host['clear_name'], target_host['port'], jump_host)
                                    if hostInfos['reachable']:
                                        exit = True
                            else:
                                utils.debug('{red}Invalid choice!{reset}')
                                go_ahead = False
                        else:
                            utils.debug('{red}Invalid choice!{reset}')
                            go_ahead = False

            if go_ahead and not exit and jump_host is not None:
                if target_host is not None and not hostInfos['reachable']:
                    sys.stdout.write('The active jump host <%s@%s:%s> does not seem to be able to reach the targetted host <%s:%s>! Do you want to setup an additional jump host linked to the current one [Y/n]? ' %(jump_host['user'], jump_host['host'], jump_host['port'], target_host['clear_name'], target_host['port']))
                    response = input().lower()
                    if response == 'n':
                        jump_host = None
                        linked_jump_host = None
                        exit = True
                else:
                    sys.stdout.write('You can directly use this jump host (if you enter "n"), or create a new connection chain-linked (depending) to this one. Do you want to create a new connection [y/N]? ')
                    response = input().lower()
                    if response != 'y':
                        exit = True

            if go_ahead and not exit:
                tmp_jump_host = self.createJumpHost(jump_host)
                if tmp_jump_host is not None:
                    jump_host = tmp_jump_host
                    if jump_host['linked_jump_host_idx'] is not None:
                        linked_jump_host = self.__jump_hosts[jump_host['linked_jump_host_idx']]
                    if target_host is not None:
                        hostInfos = self.getHostnameInfo(target_host['clear_name'], target_host['port'], jump_host)
                        if hostInfos['reachable']:
                            exit = True

            if go_ahead and exit:
                if target_host is not None and not hostInfos['reachable']:
                    sys.stdout.write('Your current jump host configuration cannot reach the targetted host! Do you want to run the setup again [Y/n]? ')
                    response = input().lower()
                    if response != 'n':
                        exit = False

            if not go_ahead and not exit:
                sys.stdout.write('Failed to configure the jump host! Continue the jump hosts setup [Y/n]? ')
                response = input().lower()
                if response == 'n':
                    exit = True

        return jump_host

    def autoSyncKnownHosts(self, hosts_filepath, known_hosts_filepath=None, unhashed_known_hosts_filepath=None):
        result = False

        if self.__host_keys_filepath is None and os.path.isfile(known_hosts_filepath):
            utils.debug('Loading {cyan}%s{reset}, and checking the networking details and connectivity of every clear hostname host. This may take a while (if hostnames are not hashed)...' %(known_hosts_filepath))
            self.loadKnownHosts(known_hosts_filepath)
            if self.__known_hosts is not None:
                nb_known_hosts = len(self.__known_hosts)
                nb_hashed_known_hosts = 0
                nb_unhashed_known_hosts = 0
                nb_unresolvable_known_hosts = 0
                nb_reachable_known_hosts = 0
                nb_unreachable_known_hosts = 0
                for host_name in self.__known_hosts:
                    tmp_host = self.__known_hosts[host_name]
                    if tmp_host['hashed']:
                        nb_hashed_known_hosts += 1
                    else:
                        nb_unhashed_known_hosts += 1
                        if tmp_host['ip'] is None:
                            nb_unresolvable_known_hosts += 1
                        if tmp_host['reachable']:
                            nb_reachable_known_hosts += 1
                        else:
                            nb_unreachable_known_hosts += 1
                utils.debug('''  Total hosts: {magenta}%s{reset}
    Hashed names: {magenta}%s{reset} (we will need the host list file to find hosts behind their hash!)
    Unhashed (clear) names: {magenta}%s{reset}:
        Reachable: {magenta}%s{reset}
        Unreachable (will require jump hosts): {magenta}%s{reset}:
            Unresolvable (no DNS match): {magenta}%s{reset}''' %(nb_known_hosts, nb_hashed_known_hosts, nb_unhashed_known_hosts, nb_reachable_known_hosts, nb_unreachable_known_hosts, nb_unresolvable_known_hosts), timestamp=False)

        if self.__known_hosts is not None and os.path.isfile(hosts_filepath):
            utils.debug('Parsing hosts list file {cyan}%s{reset}, and checking the networking details and connectivity of every host which appears in {cyan}%s{reset}. This may take a while...' %(hosts_filepath, known_hosts_filepath))
            self.parseHostsFile(hosts_filepath)

        if self.__host_keys is not None and self.__known_hosts is not None:
            utils.debug('Checking server keys...')
            host_keys_changes = False

            if len(self.__known_hosts) > 0:
                for key_name in self.__host_keys.keys():
                    host = self.__known_hosts[key_name]

                    jump_host = None
                    fingerPrint = None

                    if host['key'] is not None:
                        fingerPrint = host['key']['finger_print']

                    if host['clear_name'] is not None and not host['reachable']:
                        tmp_jump_host = self.autoCheckJumpHosts(host)
                        if tmp_jump_host is not None:
                            jump_host = tmp_jump_host
                        else:
                            sys.stdout.write('The host <%s> is not (directly) reachable. Do you have access to a jump host that you want to configure here [y/N]? ' %(host['clear_name']))
                            response = input().lower()
                            if response == 'y':
                                try:
                                    jump_host = self.configureJumpHosts(host)
                                except Exception as e:
                                    pass

                        if jump_host is not None:
                            hostInfo = self.getHostnameInfo(host['clear_name'], host['port'], jump_host)
                            for key in 'clear_name', 'reachable', 'hostname', 'ip', 'port', 'jump_host':
                                host[key] = hostInfo[key]

                    if host['ip'] is not None and host['reachable']:
                        try:
                            self.fakeConnect(host['clear_name'], port=host['port'], jump_host=jump_host)
                        except paramiko.BadHostKeyException as e:
                            if self.__host_keys_backup_filepath is None:
                                self.__host_keys_backup_filepath = '%s.old' %(self.__host_keys_filepath)
                                utils.debug('Making known_hosts file backup copy: %s => %s' %(self.__host_keys_filepath, self.__host_keys_backup_filepath), 1)
                                with open(self.__host_keys_filepath, 'r') as oldfile, open(self.__host_keys_backup_filepath, 'w') as newfile:
                                    for line in oldfile:
                                        newfile.write(line)

                            current_key = e.expected_key
                            newKey = e.key
                            utils.debug('Bad host key for IP <{cyan}%s{reset}> (fingerprint <{cyan}%s{reset}>)!' %(host['ip'], fingerPrint), 4)

                            utils.debug('    Replacing fingerprint <{cyan}%s{reset}>, using the IP <{cyan}%s{reset}> to reach the host' %(fingerPrint, host['ip']), 2)
                            self.__known_hosts[key_name]['replaced_key'] = self.__known_hosts[key_name]['key']

                            newKeyType = newKey.get_name()
                            newFingerPrint = hexlify(newKey.get_fingerprint()).decode('utf-8')
                            newKeyString = newKey.get_base64()

                            msg = '    Saving new key (type {cyan}%s{reset}) for host <{cyan}%s{reset}> (IP <{cyan}%s{reset}>)' %(newKeyType, host['clear_name'], host['ip'])
                            if jump_host is not None:
                                msg += ', through jump hosts: %s' %(self.getJumpHostsStr(jump_host))
                            utils.debug(msg, 1)
                            self.__host_keys.add(key_name, newKeyType, newKey)
                            newKeyInfo = self.getHostKeyInfo(self.__host_keys[key_name])
                            self.__known_hosts[key_name]['key'] = newKeyInfo
                            host_keys_changes = True
                        except Exception as e:
                            pass

            if unhashed_known_hosts_filepath is not None:
                self.unhashKnownHosts(unhashed_known_hosts_filepath)

            if host_keys_changes:
                if self.__host_keys_filepath is not None:
                    #result = self.saveKnownHosts(self.__host_keys_filepath)
                    if result:
                        self.__host_keys = None
                        self.loadKnownHosts(self.__host_keys_filepath)
                        if self.__host_keys is None:
                            result = False

        return result

    def isPortOpen(self, ip, port=22, timeout=2, jump_host=None):
        isOpen = False


        if jump_host is not None:
            code = """
import socket
isOpen = False
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(%s)
try:
    s.connect(('%s', %s))
    s.shutdown(socket.SHUT_RDWR)
    isOpen = True
except:
    pass
finally:
    s.close()
print(isOpen)
""" %(timeout, ip, port)

            utils.debug('Checking if <%s:%s> is reachable from jump host <%s@%s:%s>' %(ip, port, jump_host['user'], jump_host['host'], jump_host['port']), 2)
            res = self.jumpExec(code, jump_host)
            if res is not None:
                for line in res:
                    line = line.strip()
                    utils.debug('result: <%s>' %(line), 2)
                    if line == 'True':
                        isOpen = True
                        break
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, int(port)))
                s.shutdown(socket.SHUT_RDWR)
                isOpen = True
            except:
                pass
            finally:
                s.close()

        return isOpen

    def checkHost(self, host, port=22, timeout=2, retries=3, delay=0.1, jump_host=None):
        isUp = False

        for i in range(retries):
            if self.isPortOpen(host, port=port, timeout=timeout, jump_host=jump_host):
                isUp = True
                break
            else:
                time.sleep(delay)

        return isUp

    def setDefaultUsers(self, default_users):
        result = False

        if isinstance(default_users, list):
            self.__default_users = default_users
            result = True

        return result

    def getDefaultUsers(self):
        return self.__default_users

    def __setIdentityFromFile(self, filePath):
        result = False

        if os.path.isfile(filePath):
            with open(filePath) as f:
                try:
                    import io
                    import paramiko
                    identity = io.StringIO()
                    k = paramiko.RSAKey.from_private_key_file(filePath)
                    k.write_private_key(identity)
                    self.__identity = identity
                    result = True
                except Exception as e:
                    utils.debug('{red}Exception while trying to write SSH Private Key as IOString: %s{reset}' %(e), 1)

        return result

    def setIdentity(self, identity):
        result = False

        if isinstance(identity, str):
            if os.path.isfile(identity):
                try:
                    import paramiko
                    k = paramiko.RSAKey.from_private_key_file(identity)
                    result = self.__setIdentityFromFile(identity)
                except Exception as e:
                    with open(identity) as f:
                        if 'OPENSSH' in f.readline():
                            tempFilename = ''
                            f.seek(0)
                            utils.debug('Trying to transform the OpenSSH identity to RSA...', 5)
                            try:
                                import tempfile
                                tempF = tempfile.NamedTemporaryFile(delete=False)
                                tempFilename = tempF.name
                                content = f.read()
                                tempF.write(content.encode('utf-8'))
                                tempF.close()
                                if os.path.isfile(tempFilename):
                                    res = os.system('ssh-keygen -p -f %s -m pem -P "" -N "" >/dev/null 2>&1' %(tempFilename))
                                    if res == 0:
                                        try:
                                            k = paramiko.RSAKey.from_private_key_file(tempFilename)
                                            result = self.__setIdentityFromFile(tempFilename)
                                        except Exception as exceptConnect:
                                            utils.debug('{red}SSH identity conversion exception: %s{reset}' %(exceptConnect), 1)
                            except Exception as exceptTempFile:
                                utils.debug('{red}SSH identity exception: %s{reset}' %(exceptTempFile), 1)
                            finally:
                                tempF.close()
                                if os.path.exists(tempFilename):
                                    os.remove(tempFilename)
        else:
            import io
            if isinstance(identity, io.StringIO):
                identity.seek(0)
                self.__identity = identity
                result = True

        return result

    def addAuthMethod(self, username=None, password=None, identity=None):
        result = False

        if username is not None:
            if password is not None:
                found = False
                for checkMethod in self.__auth_methods:
                    if checkMethod['method'] == 'creds' and checkMethod['username'] == username and checkMethod['password'] == password:
                        found = True
                        break
                if not found:
                    self.__auth_methods.append({'method': 'creds', 'username': username, 'password': password, 'identity': None, 'identityFilename': None})
                    result = True
            elif identity is not None:
                if os.path.isfile(identity):
                    idBak = self.getIdentity()
                    self.clearIdentity()
                    res = self.setIdentity(identity)
                    if res:
                        found = False
                        for checkMethod in self.__auth_methods:
                            if checkMethod['method'] == 'key' and checkMethod['username'] == username and checkMethod['identityFilename'] == identity:
                                found = True
                        if not found:
                            self.__auth_methods.append({'method': 'key', 'username': username, 'password': None, 'identity': self.getIdentity(), 'identityFilename': identity})
                            result = True
                    self.__identity = idBak
                elif os.path.isdir(identity):
                    self.findKeys(identity)
                    result = True
        elif identity is not None:
            if os.path.isfile(identity):
                idBak = self.getIdentity()
                self.clearIdentity()
                res = self.setIdentity(identity)
                if res:
                    for username in self.__default_users:
                        found = False
                        for checkMethod in self.__auth_methods:
                            if checkMethod['method'] == 'key' and checkMethod['username'] == username and checkMethod['identityFilename'] == identity:
                                found = True
                        if not found:
                            self.__auth_methods.append({'method': 'key', 'username': username, 'password': None, 'identity': self.getIdentity(), 'identityFilename': identity})
                            result = True
                self.__identity = idBak
            elif os.path.isdir(identity):
                self.findKeys(identity)
                result = True

        return result

    def findKeys(self, path='~/.ssh'):
        if path == '~/.ssh':
            path = os.path.expanduser(path)

        if os.path.exists(path):
            ssh_keys_dir = os.path.expanduser(path)
            for filename in os.listdir(ssh_keys_dir):
                if os.path.isfile(os.path.join(ssh_keys_dir, filename)) and not os.path.islink(os.path.join(ssh_keys_dir, filename)):
                    with open(os.path.join(ssh_keys_dir, filename)) as f:
                        if 'PRIVATE KEY' in f.readline():
                            ret = self.addAuthMethod(identity=os.path.join(ssh_keys_dir, filename))
                            if not ret:
                                utils.debug('{red}Failed to add "key" auth method: key <%s>!{reset}' %(os.path.join(ssh_keys_dir, filename)))

    def clearIdentity(self):
        self.__identity = None

    def isConnected(self):
        result = self.__conn is not None
        if not result:
            if self.__conn is not None:
                self.__conn.close()
            self.__conn = None
            self.__host = None
            self.__user = None
            self.__password = None

        return result

    def getIdentity(self):
        identity = None
        if self.__identity is not None:
            identity = self.__identity
            identity.seek(0)

        return identity

    def getAuthMethods(self):
        return self.__auth_methods

    def getFailedAuthMethods(self):
        return self.__failed_auth_methods

    def getAuthMethod(self):
        return self.__auth_method

    def connect(self, host, user, password=None, port=22, timeout=2, banner_timeout=200, auth_timeout=200, filename=None, sock=None):
        if host is not None and host != '' and user is not None and user != '':
            import paramiko
            import logging
            logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

            k = None
            if self.__identity is not None:
                try:
                    identity = self.getIdentity()
                    k = paramiko.RSAKey.from_private_key(identity)
                except Exception as e:
                    utils.debug('{red}Failed to load SSH identity: %s{reset}' %(e), 1)

            ssh = paramiko.SSHClient()
            if filename is not None and os.path.isfile(filename):
                ssh.load_system_host_keys(filename)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                if sock is not None or self.checkHost(host, port=port, timeout=timeout):
                    ssh.connect(host, port=port, username=user, password=password, pkey=k, timeout=timeout, banner_timeout=banner_timeout, auth_timeout=auth_timeout, sock=sock)
                    if ssh.get_transport() is not None:
                        if ssh.get_transport().is_active():
                            self.__conn = ssh
                            self.__host = host
                            self.__user = user
                            self.__password = password
            except Exception as e:
                utils.debug('{red}Failed to connect to <%s> with user <%s>: <<<%s>>>, type: %s{reset}' %(host, user, e, type(e)), 4)

        return self.isConnected()

    def createTransportChannelFromJumpHost(self, jump_host, target_host, target_port):
        result = None

        if jump_host is not None and target_host is not None:
            utils.debug('Attempting to prepare a transport channel from the jump host <{cyan}%s@%s:%s{reset}>' %(jump_host['user'], jump_host['host'], jump_host['port']), 4)

            jump_conn = None
            jump_transport = None
            jump_src_addr = None
            jump_dst_addr = None
            jump_channel = None

            jump_conn = jump_host['conn']
            if jump_conn is not None:
                try:
                    jump_transport = jump_conn.get_transport()
                    jump_src_addr = (jump_host['host'], jump_host['port'])
                    jump_dst_addr = (target_host, target_port)
                    jump_channel = jump_transport.open_channel('direct-tcpip', jump_dst_addr, jump_src_addr)
                    result = jump_channel
                    utils.debug('{green}Transport channel ready{reset}', 4)
                except Exception as e:
                    utils.debug('{red}Failed to prepare transport channel: %s{reset}' %(e))

        return result

    def fakeConnect(self, host, port=22, timeout=0.5, banner_timeout=None, auth_timeout=None, jump_host=None):
        result = False

        ssh = paramiko.SSHClient()
        ssh.load_host_keys(self.__host_keys_filepath)

        sock = None
        if jump_host is not None:
            sock = self.createTransportChannelFromJumpHost(jump_host, host, port)
            if sock is None:
                jump_host = None
                return result

        try:
            msg = 'fakeConnect: Checking the server key for <{cyan}%s:%s{reset}>' %(host, port)
            if jump_host is not None:
                msg += ', using jump host <{cyan}%s@%s:%s{reset}>' %(jump_host['user'], jump_host['host'], jump_host['port'])
            utils.debug(msg, 4)
            ssh.connect(host, port=port, timeout=timeout, banner_timeout=banner_timeout, auth_timeout=auth_timeout, look_for_keys=False, sock=sock)
            result = True
        except Exception as e:
            utils.debug('{red}fakeConnect: %s: %s{reset}' %(type(e), e), 5)
            raise e
        finally:
            ssh.close()

        return result

    def connectJump(self, host, user, password=None, port=22, timeout=2, banner_timeout=200, auth_timeout=200, filename=None, jump_host=None):
        result = None

        linked_jump_host_idx = None
        sock = None

        if self.__jump_hosts is not None and len(self.__jump_hosts) > 0:
            if '%s@%s:%s' %(user, host, port) in ['%s@%s:%s' %(d['user'], d['host'], d['port']) for d in self.__jump_hosts]:
                utils.debug('{red}connectJump: The combination <{cyan}%s@%s:%s{red}> already exist in the jump hosts!{reset}' %(user, host, port))
                return result

        if jump_host is not None:
            linked_jump_host_idx = jump_host['jump_host_idx']

            jump_channel = self.createTransportChannelFromJumpHost(jump_host, host, port)
            if jump_channel is not None:
                sock = jump_channel
            else:
                jump_host = None
                linked_jump_host_idx = None

            if sock is None:
                return result

        msg = 'Trying to connect <{cyan}%s@%s:%s{reset}>' %(user, host, port)
        if sock is not None:
            msg += ', using a transport channel prepared from jump host <{cyan}%s@%s:%s{reset}>' %(jump_host['user'], jump_host['host'], jump_host['port'])
        utils.debug(msg, 2)
        res = self.connect(host, user, password=password, port=port, timeout=timeout, banner_timeout=banner_timeout, auth_timeout=auth_timeout, filename=filename, sock=sock)
        if res:
            utils.debug('{green}Connection successful{reset}', 4)
            if self.__jump_hosts is None:
                self.__jump_hosts = []
            new_jump_host = {'conn': self.__conn, 'jump_host_idx': len(self.__jump_hosts), 'linked_jump_host_idx': linked_jump_host_idx, 'host': self.__host, 'port': port, 'user': self.__user, 'password': self.__password}
            self.__jump_hosts.append(new_jump_host)
            self.__conn = None
            self.isConnected()

            result = new_jump_host
        else:
            utils.debug('{red}Connection failed!{reset}', 2)

        return result

    def jumpExec(self, code, jump_host):
        result = None

        if jump_host is not None:
            codeEncodedString = base64.b64encode(code.encode()).decode()

            cmd = "python3 -c \"import base64; exec(base64.b64decode('%s').decode())\"" %(codeEncodedString)
            try:
                utils.debug('Executing code on jump host <%s@%s:%s>' %(jump_host['user'], jump_host['host'], jump_host['port']), 3)
                stdin, stdout, stderr = jump_host['conn'].exec_command(cmd)
                if stderr.read() == b'':
                    result = stdout.readlines()
                if proc.stderr != '':
                    utils.debug('{red}jumpExec: Error when executing the requested code: %s{reset}' %(proc.stderr))
                    raise Exception(proc.stderr)

                result = proc.stdout.strip()
            except Exception as e:
                pass

        return result

    def tryAuthMethods(self, host, port=22, skipMethods=None, timeout=2):
        connected = False

        if self.checkHost(host, port=port, timeout=timeout, retries=3, delay=0.1):
            self.__auth_method = None
            self.__failed_auth_methods = []
            for method in self.getAuthMethods():
                skip = False
                if skipMethods is not None:
                    for skipMethod in skipMethods:
                        if skipMethod['method'] == method['method'] and skipMethod['username'] == method['username'] and skipMethod['password'] == method['password'] and skipMethod['identityFilename'] == method['identityFilename']:
                            skip = True

                if not skip:
                    tries = 1
                    if method['method'] == 'creds':
                        tries = 3
                    while tries > 0 and not connected:
                        if method['method'] == 'creds':
                            try:
                                connected = self.connect(host, method['username'], method['password'], port=port, timeout=timeout)
                            except Exception as e:
                                utils.debug('{red}%s{reset}' %(e), 1)
                        elif method['method'] == 'key':
                            try:
                                identity = method['identity']
                                identity.seek(0)
                                ret = self.setIdentity(identity)
                                if not ret:
                                    utils.debug('{red}FAILED TO SET IDENTITY %s{reset}' %(method['identityFilename']))
                                connected = self.connect(host, method['username'], port=port, timeout=timeout)
                            except Exception as e:
                                utils.debug('{red}%s{reset}' %(e))

                        if not connected:
                            tries -= 1
                            if tries > 0:
                                time.sleep(0.1)

                    if connected:
                        self.__auth_method = method
                        break
                    else:
                        self.__failed_auth_methods.append(method)
                        utils.debug('{red}failed to connect to %s using user <%s> (key <%s>) with method <%s>{reset}' %(host, method['username'], method['identityFilename'], method['method']))
                        time.sleep(0.1)
        else:
            raise HostUnreachable('The TCP port <%s> is not open on host <%s>!' %(port, host))

        return connected

    def disconnect(self):
        if self.isConnected():
            self.__conn.close()
        self.__conn = None

        return self.isConnected()

    def command(self, cmd):
        result = None

        if self.isConnected():
            stdin, stdout, stderr = self.__conn.exec_command(cmd)
            result = stdout

        return result

    def listFilesInDir(self, dirPath):
        fileList = []

        if self.isConnected():
            try:
                sftpClient = self.__conn.open_sftp()
                for path in sftpClient.listdir(dirPath):
                    path = os.path.join(dirPath, path)
                    stats = sftpClient.lstat(path)
                    if stats.__str__().startswith('-'):
                        fileList.append(path)
                sftpClient.close()
            except Exception as e:
                fileList = None

        return fileList

    def createFile(self, filePath):
        result = False

        if self.isConnected():
            try:
                sftpClient = self.__conn.open_sftp()
                f = sftpClient.open(filePath, mode='wx')
                f.close()
                sftpClient.close()
                result = True
            except Exception as e:
                pass

        return result

    def deleteFile(self, filePath):
        result = False

        if self.isConnected():
            try:
                sftpClient = self.__conn.open_sftp()
                stats = sftpClient.lstat(filePath)
                if stats.__str__().startswith('-'):
                    sftpClient.unlink(filePath)
                    result = True
                sftpClient.close()
            except Exception as e:
                pass

        return result

    def filesystemTest(self):
        result = False

        if self.isConnected():
            import tempfile

            tempDir = '/tmp'
            fileList = None
            found = True
            while found:
                tempFilename = next(tempfile._get_candidate_names())
                if tempFilename != '':
                    tempFilename = os.path.join(tempDir, '.'.join(['cscs_checkfs', tempFilename]))
                    fileList = self.listFilesInDir(tempDir)
                    if fileList is None:
                        break
                    elif tempFilename not in self.listFilesInDir(tempDir):
                        found = False

            if not found:
                if self.createFile(tempFilename):
                    if self.deleteFile(tempFilename):
                        result = True

        return result

    def getHost(self):
        return self.__host

    def getUser(self):
        return self.__user

    def getConnection(self):
        return self.__conn

def check_path(path, mode='r', a_path=None):
    check_done = False
    mode_list = []

    if 'r' in mode:
        mode_list.append('r')
    if 'w' in mode:
        mode_list.append('w')

    if path != '':
        path = os.path.expanduser(path)
        path = os.path.realpath(path)
    else:
        path = None

    if path is None:
        print('The path cannot be empty!')
        return path

    old_path = path

    if a_path is None:  # first call: prepare an "accumulative" path for the terminal recursivity
        path_list = path.split(os.path.sep)
        a_path_list = []
        path = path_list[0]
        if path == '':
            path = os.path.sep
        if len(path_list) > 0:
            a_path = os.path.join(path, path_list[1])
    elif path == a_path:
        path_list = path.split(os.path.sep)
        a_path_list = a_path.split(os.path.sep)
        check_done = True
    else:
        path_list = path.split(os.path.sep)
        a_path_list = a_path.split(os.path.sep)
        path = a_path
        a_path = os.path.join(a_path, path_list[len(a_path_list)])

    path_type = None
    if not os.path.exists(path) and 'r' in mode_list:
        raise Exception('The path "%s" does not exist!' %(path))

    if os.path.isfile(path):
        path_type = 'file'
    elif os.path.isdir(path):
        path_type = 'directory'

    if not check_done and path_type == 'directory':
        if not os.access(path, os.X_OK):
            raise Exception('You don\'t have the required permissions to list the content of the %s "%s"!' %(path_type, path))

    if 'r' in mode_list and not os.access(path, os.R_OK):
        raise Exception('You don\'t have the required permissions to read the %s "%s"!' %(path_type, path))

    if 'w' in mode_list:
        if len(a_path_list) == len(path_list) - 1 and not os.access(path, os.W_OK):
            raise Exception('You don\'t have the required permissions to write in the %s "%s"!' %(path_type, path))
        if len(a_path_list) == len(path_list) and path_type is not None and not os.access(path, os.W_OK):
            raise Exception('You don\'t have the required permissions to write in the %s "%s"!' %(path_type, path))

    if not check_done:
        path = check_path(old_path, mode, a_path)

    return path

def is_valid_file(parser, filepath, mode='r'):
    try:
        check_path(filepath, mode)
    except Exception as e:
        parser.error(e)

    return filepath

def main():
    sys.exit()
    ssh = SSH()
    ssh.autoSyncKnownHosts(args.host_list, args.known_hosts, args.unhashed_known_hosts)

parser = argparse.ArgumentParser()
parser.add_argument('--host-list', dest='host_list', type=lambda f: is_valid_file(parser, f), required=True, help='host list filename')
parser.add_argument('--known-hosts', dest='known_hosts', type=lambda f: is_valid_file(parser, f), default='~/.ssh/known_hosts', help='known_hosts filename')
parser.add_argument('--unhashed-known-hosts', dest='unhashed_known_hosts', type=lambda f: is_valid_file(parser, f, 'w'), help='Unhashed known_hosts filename (found hosts will be extracted in clear text)')
parser.add_argument('--verbose-level', dest='verbose_level', type=int, default=1, help='Verbose level [default 1]')
args = parser.parse_args()

verbose_level = 0
if args.verbose_level is not None:
    verbose_level = args.verbose_level

utils = Utils()

if __name__ == '__main__':
    main()
