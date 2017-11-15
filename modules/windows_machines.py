from __future__ import generators
import os, sys
import socket
import win32com.client
import win32net

def main():
    try:
        domain_controller = win32net.NetGetDCName(None,None)
        domain_name = win32net.NetUserModalsGet(domain_controller, 2)['domain_name']
        adsi = win32com.client.Dispatch("ADsNameSpaces")
        nt = adsi.GetObject("","WinNT:")
        result = nt.OpenDSObject ("WinNT://%s" % domain_name, "", "", 0)
        result.Filter = ["computer"]
        return [machine for machine in result]
    except Exception as e:
        return "Machine enumeration returned error: {}".format(str(e))
    
if __name__ == '__main__':
    main()
