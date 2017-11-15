import os, sys
import win32api
import win32security
import ntsecuritycon as con

FILENAME = sys.argv[1] if len(sys.argv) > 1 else None

def show_cacls(filename):
    if os.path.isfile(filename):
        for line in os.popen("cacls %s" % filename).read().splitlines():
            print line

def main():
    try:
        everyone, domain, type = win32security.LookupAccountName("", "Everyone")
        admins, domain, type = win32security.LookupAccountName("", "Administrators")
        user, domain, type = win32security.LookupAccountName("", win32api.GetUserName())
        if os.path.isfile(FILENAME)
        open(FILENAME, "w").close()
        show_cacls(FILENAME)
        sd = win32security.GetFileSecurity(FILENAME, win32security.DACL_SECURITY_INFORMATION)
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ, everyone)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE, user)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, admins)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(FILENAME, win32security.DACL_SECURITY_INFORMATION, sd)
        show_cacls(FILENAME)
    except Exception as e:
        print "Error: {}".format(str(e))


if __name__ == '__main__':
    main()
