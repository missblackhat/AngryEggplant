#!/usr/bin/env python
# -*- encoding: utf-8 -*-

def run(*args, **kwargs):
    if 'win32net' not in globals():
        import win32net

    if 'win32netcon' not in globals():
        import win32netcon

    if 'os' not in globals():
        import os

    USER = "guest_account" if 'user' not in kwargs else kwargs.get('user')
    GROUP = "GuestAdministrators"
    PASWD = 'eggplant' if 'password' not in kwargs else kwargs.get('password')

    user_info = dict({
      'name': USER,
      'password': PASWD,
      'priv': win32netcon.USER_PRIV_USER,
      'home_dir': os.getenv('HOME'),
      'comment': None,
      'flags': win32netcon.UF_SCRIPT,
      'script_path': None
    })

    win32net.NetUserAdd(None, 1, user_info)
    group_info = dict({ 'name': GROUP })

    try:
      win32net.NetLocalGroupDel(None, GROUP)
    except win32net.error,(number, context, message):
      if number <> 2220:
        raise

    win32net.NetLocalGroupAdd(None, 0, group_info)
    user_group_info = dict({ 'domainandname': USER })
    win32net.NetLocalGroupAddMembers(None, GROUP, 3, [user_group_info])


if __name__ == '__main__':
    run(user='guest_account', password='eggplant')