from __future__ import generators
import os, sys
import socket
import win32com.client
import win32net

def machines_in_domain(domain_name):
    adsi = win32com.client.Dispatch("ADsNameSpaces")
    nt = adsi.GetObject("","WinNT:")
    result = nt.OpenDSObject ("WinNT://%s" % domain_name, "", "", 0)
    result.Filter = ["computer"]
    for machine in result:
        yield machine.Name

domain_controller = win32net.NetGetDCName(None,None)
domain_name = win32net.NetUserModalsGet(domain_controller, 2)['domain_name']
print "Listing machines in", domain_name
for machine in machines_in_domain(domain_name):
    print machine
