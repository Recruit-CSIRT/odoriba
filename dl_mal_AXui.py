#!/usr/bin/env python2.7
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is to collect malwares from you FireEye AX 
#  this module may not work well in case of your AX version. 


""" Main : 
 1. [selenium] GUI Connection to AX -> https certification 
 2. [selenium] get recent analysis md5list (it lets us know the download link.)
 3. [requests] Connection to AX -> https certification
 4. [requests] Archived Object Download
"""


AX_IP = "Write your own" 
USER_AGENT = "Write your own" 
MAX_PAGE = 7
BASE64_LOGIN_USER = "Write your own" 
BASE64_LOGIN_PASS = "Write your own" 

import base64
import sys,os,re
import subprocess,shlex
import requests
from selenium import webdriver
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time
import mylogfunc

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class AXConnect(object):
    session = None
    logged = False
    verbose = False
    logger = None

    url = "https://%s"%AX_IP
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest'
    }


    def __init__(self, verbose=False, username=None, password=None, logger=logger):
        self.verbose = verbose
        self.session = requests.session()
        self.logger = logger

        # Authenticate and store the session
        if username and password:
            soup = self.request_to_soup(self.url + '/login/login')
            csrf_input = soup.find(attrs=dict(name='csrf-token'))
            csrf_token = csrf_input['content']
            payload = {
                'csrf-token': csrf_token,
                'user[account]': u'{0}'.format(username),
                'user[password]': u'{0}'.format(password)
            }
            login_request = self.session.post(self.url + '/login/login',
                                              data=payload, headers=self.headers)
            if login_request.status_code == 200:
                self.logged = True
                logger.debug("[FireEye AX 5500 auth sucess via requests] %s "%login_request)
            else:
                self.logged = False
                logger.debug("Not being able to log you")


    def request_to_soup(self, url=None):
        if not url: url = self.url
        req = self.session.get(url, headers=self.headers, verify=False)
        soup = BeautifulSoup(req.content, "html.parser")
        return soup


    def download_sample(self,md5list,logger):
        # Do nothing if not logged in
        if not self.logged: return []

        for md5 in md5list:
            with open('./seeds/%s.zip'%md5,'wb') as f:
                dl_url = 'https://%s/event_stream/send_zip_file?zip_path=done/%s.zip'%(AX_IP,md5)
                logger.debug("\n[start][target_url] %s"%dl_url)
                req = self.session.get(dl_url, headers=self.headers)
                if req.status_code == 200: f.write(req.content)
                else: logger.debug("[download_fail] because of status_code %s"%req.status_code)

            # Check download fail?
            if subprocess.check_output(["file","./seeds/%s.zip"%md5]).find('Zip archive data,') == -1:
                logger.debug("[download_fail] because of Get DashBoard Page ,Not Zip. so remove now")
                # if download missed -> the content was html document.
                proc = subprocess.Popen(["rm","-rf","./seeds/%s.zip"%md5],stdout=subprocess.PIPE,stderr=subprocess.PIPE)   
                out, err = proc.communicate()
                proc.wait()
                # Retry put on gdone/： 
                with open('./seeds/%s.zip'%md5,'wb') as f:
                    dl_url = 'https://%s/event_stream/send_zip_file?zip_path=gdone/%s.zip'%(AX_IP,md5)
                    logger.debug("\n[start][target_url] %s"%dl_url)
                    req = self.session.get(dl_url, headers=self.headers)
                    if req.status_code == 200: f.write(req.content)
                    else: logger.debug("[download_fail] because of status_code %s"%req.status_code)

            # ReCheck download fail?
            if subprocess.check_output(["file","./seeds/%s.zip"%md5]).find('Zip archive data,') == -1:
                logger.debug("[download_fail] because of Get DashBoard Page ,Not Zip, so remove again")
                proc = subprocess.Popen(["rm","-rf","./seeds/%s.zip"%md5],stdout=subprocess.PIPE,stderr=subprocess.PIPE)   
                out, err = proc.communicate()
                proc.wait()
            else:
                # Zip Extraction
                if zip_extract(md5,logger):logger.debug("[[zip extract check_ok]][complete!] downloaded samples %s.zip"%md5)
                else:logger.debug("[[zip extract check_fail]][missing!] samples %s.zip"%md5)
                os.chdir("./..") ;print os.getcwd()


def zip_extract(md5,logger):
    os.chdir("./seeds");print os.getcwd()
    oldfile = md5 + ".zip"
    i=0
    while i < 3:
    	try: out = subprocess.check_output(["unzip","-o","-P","infected",oldfile])
    	except: out = "unzip error maybe already exist.."
        newfile=""
        if out.find("inflating:") != -1: 
            newfile = out.split("inflating: ")[-1].split(" ")[0]
            logger.debug("[success] unzip malware %s samples"%newfile)
            proc = subprocess.Popen(["rm","-rf",oldfile],stdout=subprocess.PIPE,stderr=subprocess.PIPE)  
            out, err = proc.communicate();proc.wait()
        print subprocess.check_output(["file",newfile])
        if subprocess.check_output(["file",newfile]).find('Zip archive data,') == -1: return True
        oldfile=newfile
        i+=1


def get_recent_analysis(username,password,logger): # selenium
	driver = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true']) # PhantomJS could't download files, so Chrome used


	"""  1. Login   """
	logger.debug("[FireEye AX auth sucess via selenium]")
	driver.get('https://%s/login/login'%AX_IP)
	loginid_form = driver.find_element_by_id('user_account')
	password_form = driver.find_element_by_id('user_password')
	loginid_form.send_keys(username)
	password_form.send_keys(password)
	driver.find_element_by_id('logInButton').click()
	time.sleep(3)

	"""  2. get 24h resent Analysis malware samples  """
	rmd5 = re.compile(r'<td title="([a-z0-9_]{32})"><div style="word-wrap: break-word;">')
	logger.debug("Get Resent Analysis page = 1")
	driver.get('https://%s/malware_analysis/analyses'%AX_IP)

	page = 1
	list_md5=[]
	while page < MAX_PAGE:
		alert = driver.page_source.split('<td class="first details" ')
		for md5 in rmd5.findall(driver.page_source):
			if md5 not in list_md5:
				list_md5.append(str(md5))
		page +=1 
		driver.find_element_by_link_text(str(page)).click()
		logger.debug("[Analysis] Get Resent Analysis page = %s, md5 counts = %s"%(page,len(list_md5)))
		time.sleep(3)

	driver.close()	

	return list_md5


def main(logger):
	username = base64.b64decode(BASE64_LOGIN_USER)
	password = base64.b64decode(BASE64_LOGIN_PASS)

	# 1. [selenium] GUI Connection to AX -> https certification 
	# 2. [selenium] get recent analysis md5list (it lets us know the download link.)
	logger.debug("-----  Ajax Parser for md5 list by selenium PhantomJS --------")
	list_md5 = get_recent_analysis(username,password,logger)
	print "\n\n"

	logger.debug("-----  Downloads Malwares by requests --------")
	# 3. [requests] Connection to AX -> https certification
	api_authenticated = AXConnect(verbose=True, username=username, password=password,logger=logger)
	# 4. [requests] Archived Object Download
	api_authenticated.download_sample(list_md5,logger=logger)


 
# for stand alone ,
#logger = mylogfunc.mylog()            
#main(logger)





    




