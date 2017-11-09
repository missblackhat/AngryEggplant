import win32net
import win32netcon

USER = "user"
GROUP = "group"

#
# Create a new user with minimum privs.
# If it exists already, drop it first.
#
user_info = dict (
  name = USER,
  password = "Passw0rd",
  priv = win32netcon.USER_PRIV_USER,
  home_dir = None,
  comment = None,
  flags = win32netcon.UF_SCRIPT,
  script_path = None
)

try:
  win32net.NetUserDel (None, USER)
except win32net.error, (number, context, message):
  if number <> 2221:
    raise
win32net.NetUserAdd (None, 1, user_info)

#
# Create a new group
# If it exists already, drop it first.
#
group_info = dict (
  name = GROUP
)

try:
  win32net.NetLocalGroupDel (None, GROUP)
except win32net.error, (number, context, message):
  if number <> 2220:
    raise
win32net.NetLocalGroupAdd (None, 0, group_info)

#
# Add the new user to the new group
#
user_group_info = dict (
  domainandname = USER
)

win32net.NetLocalGroupAddMembers (None, GROUP, 3, [user_group_info])
