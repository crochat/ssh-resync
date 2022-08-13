#!/usr/bin/env python3

import os
import sys
import argparse
import paramiko
from paramiko import SFTPClient
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
    __resolves = {}
    __known_hosts = None
    __host_keys_filepath = None
    __host_keys_filepath_stats = None
    __host_keys_backup_filepath = None
    __host_keys = None
    __host_list_filepath = None
    __replaced_keys = None

    def __init__(self):
        pass

    def parseHostsFile(self, hosts_filepath):
        result = False

        if self.__host_keys is not None and os.path.isfile(hosts_filepath):
            self.__host_list_filepath = hosts_filepath

            foundItems = []
            host_keys_changes = False

            with open(hosts_filepath, 'r') as f:
                utils.debug('Parsing hosts list file: %s' %(hosts_filepath), 1)
                for line in f.readlines():
                    fields = line.split()
                    for i in range(0, len(fields)):
                        hostnames = None

                        item = fields[i]
                        if item.startswith('#'):
                            break

                        if item not in foundItems:
                            utils.debug('Searching for %s in %s' %(item, self.__host_keys_filepath), 4)
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
                        host = {'lineno': lineno, 'name': hostname, 'clear_name': None, 'reachable': False, 'hostname': None, 'ip': None, 'hashed': False, 'key': None, 'replaced_key': None}
                        host['key'] = self.getHostKeyInfo(self.__host_keys[hostname])

                        hostnameInfo = self.getHostnameInfo(hostname)
                        for key in ['clear_name', 'reachable', 'hostname', 'ip', 'hashed']:
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

    def getHostnameInfo(self, hostname):
        result = {'name': hostname, 'clear_name': None, 'reachable': False, 'hostname': None, 'ip': None, 'hashed': False}

        if hostname.startswith('|1|'):
            result['hashed'] = True
        else:
            result['clear_name'] = hostname

            oldDefaultTimeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.5)

            try:
                socket.inet_aton(hostname)
                result['ip'] = hostname
            except Exception as e:
                pass

            if result['ip'] is None:
                result['hostname'] = hostname

                if hostname in self.__resolves:
                    utils.debug('Taking <{cyan}%s{reset}> matching IP from previously resolved hostnames' %(hostname), 3)
                    result['ip'] = self.__resolves[hostname]
                else:
                    try:
                        utils.debug('Trying to resolve {cyan}%s{reset}' %(hostname), 3)
                        #python3 -c "import socket; print(socket.gethostbyname('mipintns1'))"
                        ip = socket.gethostbyname(hostname)
                        self.__resolves[hostname] = ip
                        result['ip'] = ip
                    except Exception as e:
                        utils.debug('{red}Failed to resolve {cyan}%s{red}!{reset}' %(hostname), 1)

            if result['ip'] is not None:
                if self.checkHost(result['ip'], timeout=0.1):
                    utils.debug('{green}Host IP check ok: <{cyan}%s{green}>{reset}' %(result['ip']), 2)
                    result['reachable'] = True
                else:
                    utils.debug('{red}Host IP check failed: <{cyan}%s{red}>!{reset}' %(result['ip']), 2)

            socket.setdefaulttimeout(oldDefaultTimeout)

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

    def unhashKnownHosts(self):
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
                unhashed_host_keys_filepath = '%s.unhashed' %(self.__host_keys_filepath)
                utils.debug('Recording a unhashed (as much as possible with found hosts) version of the known_hosts file in %s' %(unhashed_host_keys_filepath), 1)
                unhashed_host_keys.save(unhashed_host_keys_filepath)
                result = True

        return result

    def autoSyncKnownHosts(self, known_hosts_filepath=None, hosts_filepath=None):
        result = False

        if self.__host_keys_filepath is None and os.path.isfile(known_hosts_filepath):
            self.loadKnownHosts(known_hosts_filepath)

        if self.__known_hosts is not None and os.path.isfile(hosts_filepath):
            self.parseHostsFile(hosts_filepath)

        self.unhashKnownHosts()

        if self.__host_keys is not None and self.__known_hosts is not None:
            host_keys_changes = False

            if len(self.__known_hosts) > 0:
                for hostname in self.__host_keys.keys():
                    host = self.__known_hosts[hostname]

                    clear_name = None
                    ip = None
                    fingerPrint = None

                    if host['reachable'] and host['ip'] is not None:
                        clear_name = host['clear_name']
                        ip = host['ip']
                        fingerPrint = host['key']['finger_print']

                    if ip is not None:
                        try:
                            self.fakeConnect(clear_name)
                        except paramiko.BadHostKeyException as e:
                            if self.__host_keys_backup_filepath is None:
                                self.__host_keys_backup_filepath = '%s.old' %(self.__host_keys_filepath)
                                utils.debug('Making known_hosts file backup copy: %s => %s' %(self.__host_keys_filepath, self.__host_keys_backup_filepath), 1)
                                with open(self.__host_keys_filepath, 'r') as oldfile, open(self.__host_keys_backup_filepath, 'w') as newfile:
                                    for line in oldfile:
                                        newfile.write(line)

                            current_key = e.expected_key
                            newKey = e.key
                            utils.debug('Bad host key for IP <{cyan}%s{reset}> (fingerprint <{cyan}%s{reset}>)!' %(ip, fingerPrint), 4)

                            utils.debug('    Replacing fingerprint <{cyan}%s{reset}>, using the IP <{cyan}%s{reset}> to reach the host' %(fingerPrint, ip), 2)
                            self.__known_hosts[hostname]['replaced_key'] = self.__known_hosts[hostname]['key']

                            newKeyType = newKey.get_name()
                            newFingerPrint = hexlify(newKey.get_fingerprint()).decode('utf-8')
                            newKeyString = newKey.get_base64()

                            utils.debug('    Saving new key (type {cyan}%s{reset}) for host <{cyan}%s{reset}> (IP <{cyan}%s{reset}>)' %(newKeyType, clear_name, ip), 1)
                            self.__host_keys.add(hostname, newKeyType, newKey)
                            newKeyInfo = self.getHostKeyInfo(self.__host_keys[hostname])
                            self.__known_hosts[hostname]['key'] = newKeyInfo
                            host_keys_changes = True

            if host_keys_changes:
                if self.__host_keys_filepath is not None:
                    result = self.saveKnownHosts(self.__host_keys_filepath)
                    if result:
                        self.__host_keys = None
                        self.loadKnownHosts(self.__host_keys_filepath)
                        if self.__host_keys is None:
                            result = False

        return result

    def fakeConnect(self, host, port=22, timeout=0.5, banner_timeout=None, auth_timeout=None):
        ssh = paramiko.SSHClient()
        ssh.load_host_keys(self.__host_keys_filepath)

        try:
            utils.debug('    Attempting a SSH connection to <{cyan}%s{reset}>' %(host), 5)
            ssh.connect(host, port=port, timeout=timeout, banner_timeout=banner_timeout, auth_timeout=auth_timeout, look_for_keys=False)
        except paramiko.BadHostKeyException as e:
            raise e
        except Exception as e:
            utils.debug('fakeConnect: %s' %(e), 5)
        finally:
            ssh.close()

    def isPortOpen(self, ip, port=22, timeout=2):
        import socket

        isOpen = False

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

    def checkHost(self, host, port=22, timeout=2, retries=3, delay=0.1):
        isUp = False

        for i in range(retries):
            if self.isPortOpen(host, port=port, timeout=timeout):
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

    def connect(self, host, user, password=None, port=22, timeout=2, banner_timeout=200, auth_timeout=200, filename=None):
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
                if self.checkHost(host, port=port, timeout=timeout):
                    ssh.connect(host, port=port, username=user, password=password, pkey=k, timeout=timeout, banner_timeout=banner_timeout, auth_timeout=auth_timeout)
                    if ssh.get_transport() is not None:
                        if ssh.get_transport().is_active():
                            self.__conn = ssh
                            self.__host = host
                            self.__user = user
                            self.__password = password
            except Exception as e:
                utils.debug('{red}Failed to connect to <%s> with user <%s>: <<<%s>>>, type: %s{reset}' %(host, user, e, type(e)), 5)
                pass

        return self.isConnected()

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

def main():
    filedir = '.'
    knownHostsFilename = os.path.join(filedir, 'known_hosts')
    hostsFilename = os.path.join(filedir, 'hosts_list')

    ssh = SSH()
    ssh.autoSyncKnownHosts(knownHostsFilename, hostsFilename)

parser = argparse.ArgumentParser()
#parser.add_argument('--action', dest='action', type=str, choices=['storage-retype', 'finalize'], required=True, help='Action to execute')
#parser.add_argument('--cloud', dest='cloud', type=str, required=True, help='Cloud configuration name')
#parser.add_argument('--vm', dest='vm_name', type=str, required=True, help='VM name')
#parser.add_argument('--target-volume-type', dest='target_volume_type', type=str, choices=['NFS', 'NFS2', 'CEPH'], default='CEPH', help='Target volume type')
#parser.add_argument('--volume-id', dest='volume_id', type=str, help='Volume ID')
#parser.add_argument('--volume-snapshot-id', dest='snap_id', type=str, help='Volume snapshot ID')
#parser.add_argument('--new-volume-id', dest='newvol_id', type=str, help='New volume ID (generated from volume snapshot)')
#parser.add_argument('--image-id', dest='image_id', type=str, help='Image ID')
#parser.add_argument('--key-name', dest='key_name', type=str, help='Key name')
#parser.add_argument('--security-groups', dest='security_groups', type=str, help='Security groups (comma-separated)')
#parser.add_argument('--flavor-name', dest='flavor_name', type=str, help='Flavor name')
#parser.add_argument('--size', dest='vm_size', type=str, help='VM size (GiB)')
#parser.add_argument('--ips', dest='ips', type=str, help='VM IP addresses (comma-separated, must match subnet-names in the same order)')
#parser.add_argument('--keep', action='store_true', help='Keep temporary items')
parser.add_argument('--verbose-level', dest='verbose_level', type=int, default=1, help='Verbose level [default 1]')
args = parser.parse_args()

verbose_level = 0
if args.verbose_level is not None:
    verbose_level = args.verbose_level

utils = Utils()

if __name__ == '__main__':
    main()
