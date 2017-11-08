import ftputil

ftp = ftputil.FTPHost('ftp.smarterasp.net','ftphost','ftpserver')
while True:
    cmd, _, action = raw_input('ftp> ').partition(' ')
    try:
	action = action.split(' ') if action else None
        res = getattr(ftp, cmd)(*action) if action else getattr(ftp, cmd)()
        if res:
            print res
    except Exception as e:
	print str(e)
