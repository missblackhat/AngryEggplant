#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys, os
from wx import App, Bitmap, MemoryDC, ScreenDC, BITMAP_TYPE_PNG
from random import randrange


def main(default=True):
    app = App() 
    screen = ScreenDC()
    size = screen.GetSize()
    if default:
        size = (round(size[0]*2.5), round(size[1]*2.5))
    bmp = Bitmap(size[0], size[1])
    mem = MemoryDC(bmp)
    mem.Blit(0, 0, size[0], size[1], screen, 0, 0)
    del mem
    name = '{}.png'.format(str(randrange(1000)))
    fname = os.path.join(os.getcwd(), name)
    bmp.SaveFile(fname, BITMAP_TYPE_PNG)
    print fname
    return fname


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print str(e)
        try:
            main(default=False)
        except Exception as x:
            print str(x)
