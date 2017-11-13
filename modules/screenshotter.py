#!/usr/bin/python
# -*- coding: utf-8 -*-
import win32gui, win32ui, win32con, win32api
from os import path

def main():
    hdesktop = win32gui.GetDesktopWindow()
    width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN) * 2.5
    height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN) * 2.5
    left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
    top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
    desktop_dc = win32gui.GetWindowDC(hdesktop)
    img_dc = win32ui.CreateDCFromHandle(desktop_dc)
    mem_dc = img_dc.CreateCompatibleDC()
    screenshot = win32ui.CreateBitmap()
    screenshot.CreateCompatibleBitmap(img_dc, int(width), int(height))
    mem_dc.SelectObject(screenshot)
    mem_dc.BitBlt((0, 0), (int(width), int(height)), img_dc, (0, 0), win32con.SRCCOPY)
    tempdir  = path.expandvars('%TEMP%')
    tempfile = path.join(tempdir, 'screenshot.bmp')
    screenshot.SaveBitmapFile(mem_dc, tempfile)
    print tempfile
    return tempfile
    mem_dc.DeleteDC()
    win32gui.DeleteObject(screenshot.GetHandle())

if __name__ == '__main__':
    main()
