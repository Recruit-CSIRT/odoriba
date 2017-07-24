#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is to collect malwares from you FireEye AX 

USER_AGENT = "Write your own" 
BASE64_LOGIN_USER = "Write your own" 
BASE64_LOGIN_PASS = "Write your own" 

import os
import subprocess
import re
import hashlib
import requests
import base64
from bs4 import BeautifulSoup

class Malwr(object):
    session = None
    logged = False
    verbose = False
    logger = None

    url = "https://malwr.com"
    headers = {
        'User-Agent': USER_AGENT
    }


    def __init__(self, verbose=False, username=None, password=None, logger=logger):
        self.verbose = verbose
        self.session = requests.session()
        self.logger = logger

        # Authenticate and store the session
        if username and password:
            soup = self.request_to_soup(self.url + '/account/login')
            csrf_input = soup.find(attrs=dict(name='csrfmiddlewaretoken'))
            csrf_token = csrf_input['value']
            payload = {
                'csrfmiddlewaretoken': csrf_token,
                'username': u'{0}'.format(username),
                'password': u'{0}'.format(password)
            }
            login_request = self.session.post("https://malwr.com/account/login/",
                                              data=payload, headers=self.headers)
            if login_request.status_code == 200:
                self.logged = True
                logger.debug("[malwr.com auth sucess] %s "%login_request)
            else:
                self.logged = False
                logger.debug("Not being able to log you")


    def request_to_soup(self, url=None):
        if not url: url = self.url
        req = self.session.get(url, headers=self.headers)
        soup = BeautifulSoup(req.content, "html.parser")
        return soup


    def display_message(self, s):
        if self.verbose:
            logger.debug('[verbose] %s' % s)


    def recent_analysis_list(self):
        data = []
        token_sha256_fdata = []
        soup = self.request_to_soup(self.url + '/analysis/')
        table = soup.find('table', attrs={'class':'table table-striped'})
        table_body = table.find('tbody')
        rows = table_body.find_all('tr')
        rSHA256 = re.compile(r'<th>SHA256</th>\n<td>([a-z0-9_]{64})</td>\n</tr>')
        i=0
        for row in rows:
            cols = row.find_all('td')
            token = str(row.find('a')).split('/')[2]
            each_analysis = self.request_to_soup(self.url + '/analysis/' + token + '/')
            try: sha256 = rSHA256.findall(str(each_analysis))[0]
            except: sha256 = "none"
            cols = [ele.text.strip() for ele in cols]
            data.append([ele for ele in cols])  
            token_sha256_fdata.append([token,sha256,data[i]])
            i+=1
        return token_sha256_fdata


    def download_sample(self,token,sha256,fdata,seedslist,logger):
        # Do nothing if not logged in
        if not self.logged:
            return []
        fname = fdata[2]
        dl_url = self.url + '/analysis/file/' + token + '/sample/' + sha256 + '/'
        logger.debug("\n[start][target_url] %s"%dl_url)
        with open('./seeds/%s'%fname,'wb') as f:
            req = self.session.get(dl_url, headers=self.headers)
            if req.status_code == 200:
                logger.debug("[stored] malware = %s,sha256 = %s"%(fname,sha256))
                f.write(req.content)
            else:
                logger.debug("[download_fail] because of status_code %s"%req.status_code)
        if self.sha256check(fname,sha256):
            logger.debug("[[sha256 hash check_ok]]")
            return "[complete!] downloaded samples %s"%fname
            seedslist.write(data[2],data[0],data[1],data[3])
        else:
            logger.debug("[[sha256 hash check_fail]]")
            return "[missing!] samples %s"%fname

    def sha256check(self,fname,sha256):
        output = subprocess.check_output(["shasum","-a","256","./seeds/%s"%fname])
        hash256 = output.split(" ")[0]
        if hash256 == sha256: 
            return True
        else: 
            proc = subprocess.Popen(["rm","-rf","./seeds/%s"%fname])   # hashが合わないものは削除
            out, err = proc.communicate()
            proc.wait()
            return False 




def main(logger):
    # phase 0: 認証突破
    username = base64.b64decode(BASE64_LOGIN_USER)
    password = base64.b64decode(BASE64_LOGIN_PASS)
    api_authenticated = Malwr(verbose=True, username=username, password=password,logger=logger)
        
    # phase 1 : collect malware list ,targets=[[token,sha256],[t,s]]
    targets = api_authenticated.recent_analysis_list()

    # phase 2:  malware download samples stored permission 644
    print os.getcwd()
    # malware collected seeds list 
    with open('./log/got_seedslist.csv','a') as sl:
        for tsf in targets:
            token,sha256,fdata = tsf
            print api_authenticated.download_sample(token,sha256,fdata,sl,logger)

# for stand alone ,
#logger = mylogfunc.mylog()            
#main(logger)

        


        
  