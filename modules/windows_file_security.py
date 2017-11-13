import os, sys
import win32api
import win32security
import ntsecuritycon as con

if len(sys.argv) < 2:
  print 'usage: {} <filename>'.format(os.path.basename(sys.argv[0]))
  sys.exit(0)

FILENAME = sys.argv[1]

def show_cacls (filename):
  print
  print
  for line in os.popen ("cacls %s" % filename).read ().splitlines ():
      print line

def main():
  everyone, domain, type = win32security.LookupAccountName ("", "Everyone")
  admins, domain, type = win32security.LookupAccountName ("", "Administrators")
  user, domain, type = win32security.LookupAccountName ("", win32api.GetUserName ())

  open(FILENAME, "w").close()
  show_cacls (FILENAME)

  #
  # Find the DACL part of the Security Descriptor for the file
  #
  sd = win32security.GetFileSecurity (FILENAME, win32security.DACL_SECURITY_INFORMATION)

  #
  # Create a blank DACL and add the three ACEs we want
  # We will completely replace the original DACL with
  # this. Obviously you might want to alter the original
  # instead.
  #
  dacl = win32security.ACL ()
  dacl.AddAccessAllowedAce (win32security.ACL_REVISION, con.FILE_GENERIC_READ, everyone)
  dacl.AddAccessAllowedAce (win32security.ACL_REVISION, con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE, user)
  dacl.AddAccessAllowedAce (win32security.ACL_REVISION, con.FILE_ALL_ACCESS, admins)

  #
  # Put our new DACL into the Security Descriptor,
  # update the file with the updated SD, and use
  # CACLS to show what's what.
  #
  sd.SetSecurityDescriptorDacl (1, dacl, 0)
  win32security.SetFileSecurity (FILENAME, win32security.DACL_SECURITY_INFORMATION, sd)
  show_cacls (FILENAME)

if __name__ == '__main__':
    main()
