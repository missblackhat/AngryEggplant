from pygithub3 import Github

#declare variables
python = 0
cplusplus = 0
javascript = 0
ruby = 0
java = 0

#user input
username = raw_input("Please enter your Github username: ")
password = raw_input("Please enter your account password: ")

user = raw_input("Please enter the requested Github username: ")

#Connect to github
gh = Github(login=username, password = password)

get_user = gh.users.get(user)

repo = gh.repos.list(user = user).all()
print type(repo)

