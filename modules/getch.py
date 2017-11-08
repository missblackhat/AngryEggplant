#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Cross-platform getch module"""

class _Getch:
    """Gets a single character from standard input.  Does not echo to the
    screen."""
    def __init__(self):
        if os.name is 'nt':
            self.impl = _GetchWindows()
        elif os.name is 'posix':
            self.impl = _GetchUnix()

    def __call__(self): return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys, termios

    def __call__(self):
        import sys, tty, termios
        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
        except: return raw_input('$ ')

class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        try:
            import msvcrt
            return msvcrt.getch()
        except: return raw_input('$ ')
