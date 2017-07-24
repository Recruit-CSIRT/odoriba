#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is Odoriba Launcher and add seeds automatically.
#            of cource, you can submit malware from cuckoo's Web UI

import signal
import os,sys
import glob
import time
import subprocess
import malwr_dl
import dl_mal_AXui
import mylogfunc


TIMEOUT = 600 # default 10 min for analysis, you can change the duration until next analysis start 


def exit(cuckoo,mongo,manage):
	cuckoo.terminate()
	mongo.terminate()
	manage.terminate()
	print "[odoriba.py's END] bye!"

def filetype_check(f):
	FLAG = True
	ft = subprocess.check_output(['file',f])
	# x64 exe -> remove
	# if file size == 0 empty
	logger.debug("[file_check] size %d byte"%os.path.getsize(file))
	if os.path.getsize(file) == 0: FLAG=False
	print ft
	if ft.find('x86-64')!=-1 or ft.find('32+')!=-1: FLAG=False

	# unsupported zip -> unzip
	elif ft.find('Zip archive') != -1:
		if ft.find('v1.0') == -1: 
			unzip = 'unzip -p %s | cat > %s'%(file,file[0:-4])
			try: subprocess.call(unzip,shell=True)
			except e: FLAG=False; return FLAG
			time.sleep(0.5)
			file_remove(file)
			mv = subprocess.Popen(["mv",file[0:-4],file],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			o,e = mv.communicate();mv.wait()
			if e!="": FLAG=False
	return FLAG

def file_remove(f):
	p2 = subprocess.Popen(["rm","-rf",file],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	o2,e2 = p2.communicate()
	p2.wait()
	if e2 == "":
		logger.debug("[removed] %s"%file.split('/')[-1])
	return 0


print "///////////////////////////////////////////////////////////////////////////////////\n\n\n"
print "                            Odoriba   ver 1.0                                      \n\n\n"
print "///////////////////////////////////////////////////////////////////////////////////\n"

logger = mylogfunc.mylog()

if len(sys.argv) != 4:
	logger.debug("usage error: python odoriba.py [vmware or virtualbox] [add or init or none] [malwr or ax or none]")
	sys.exit()

if sys.argv[2] == "init":
	if os.path.exists('./seeds')==False:
		os.mkdir("./seeds")
		print "[odoriba] Create ./seeds directory"
	if os.path.exists('./old_seeds')==False:
		os.mkdir("./old_seeds")
		print "[odoriba] Create ./old_seeds directory"
	# Odoriba Lancher cuckoo setup

	## bpf portfowarding  setting 
	logger.debug("sudo chmod +r /dev/bpf*")
	subprocess.Popen("sudo chmod +r /dev/bpf*",shell=True)
	time.sleep(1)
	subprocess.call(["sudo","sysctl","net.inet.ip.forwarding=1"])
	time.sleep(1)
	subprocess.call(["sudo","pfctl","-e"])
	if sys.argv[1] == "virtualbox":
		subprocess.call(["sudo","pfctl","-f","./pfrule_vboxnet0"])
	elif sys.argv[1] == "vmware":
		subprocess.call(["sudo","pfctl","-f","./pfrule_vmnet1"])
	else:
		logger.debug("[critical argument error] please [vmware or virtualbox] of argument1")
	logger.debug("[started] pfctl.... portforwarding")


	print "/////////////////////////////////////////////////////////////////////////////////////\n\n\n"
	# cuckoo launcher
	cuckoo = subprocess.Popen(["./cuckoo.py","-d"])
	logger.debug("[started] cucukoo -d")
	
	print "/////////////////////////////////////////////////////////////////////////////////////\n\n\n"
	time.sleep(5)
	# mongo lancher
	mongo = subprocess.Popen(["sudo","mongod"])
	logger.debug("[started] sudo mongod")
	print "/////////////////////////////////////////////////////////////////////////////////////\n\n\n"
	time.sleep(5)
	# web ui launcher , you can change the TCP port number of webui
	os.chdir("./web") 
	print os.getcwd()
	manage = subprocess.Popen(["./manage.py","runserver","127.0.0.1:8001"])
	logger.debug("[started] ./manage.py runserver 127.0.0.1:8001")
	print "/////////////////////////////////////////////////////////////////////////////////////\n\n\n"
	time.sleep(5)

	if os.path.exists('./static/json')==False:
		print "[odoriba] Create ./static/json directory"
		os.mkdir("./static/json")

	os.chdir("./..") 
	print os.getcwd()

elif sys.argv[2] == "add" or sys.argv[2] == "none" :
	print "/////////////////////////////////////////////////////////////////////////////////////\n\n\n"
	print "									Cuckoo Already started									"
	print "/////////////////////////////////////////////////////////////////////////////////////\n\n\n"



## old seeds move to ./old_seeds ?
old_files = glob.glob('./seeds/*') 
logger.debug("[move!] seeds to old_seeds")
for old_file in old_files:
	print ".",
	if os.path.isfile(old_file):
		old_move = subprocess.Popen(["mv", old_file, "./old_seeds"])
		out,err = old_move.communicate()
		old_move.wait()

# seeds download from Malwr
if sys.argv[3] == "malwr":
	logger.debug("[download malwares from Internet ... waiting..]\n\n ")
	malwr_dl.main(logger)
elif sys.argv[3] == "ax":
	logger.debug("[download malwares from FireEye AX last 24h ... waiting..]\n\n ")
	dl_mal_AXui.main(logger)
elif sys.argv[3] == "none":
	logger.debug("[ not download waiting... malware in ./seeds/* ]\n\n ")

print "///////////////////////////////////////////////////////////////////////////////////\n\n"
print "                     ~    Analysis   time   ~      submit to odoriba vm            \n\n"
print "///////////////////////////////////////////////////////////////////////////////////\n"

# seeds odoriba submitter 
while 1:
	logger.debug("[waiting seeds in ./seeds/* ]")
	files = glob.glob('./seeds/*')
	for file in files:
		if os.path.isfile(file) == True:
			if filetype_check(file) == True:
				try: out = subprocess.check_output(["unzip","-o","-P","infected",file])
				except: out = "unzip error maybe already exist.."
				logger.debug("[submit] %s"%file.split('/')[-1])
				try:
					p = subprocess.Popen(["./utils/submit.py",file])
					o,e = p.communicate()
					p.wait()
					while cnt <= TIMEOUT:
						time.sleep(1)
						cnt+=1
						# Child check
						cmd = 'ps | grep "child.py"'
						ps = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
						stdout_data, stderr_out = ps.communicate() 
						for proc in stdout_data.split('\n'):
							if proc.find("grep")==-1:
								pid = proc.split("tty")[0]
								pid = pid.strip(" ")
								if pid == "":
									break
					
					kill = subprocess.call(['python','%s/kill_children.py'%os.getcwd()])
					time.sleep(3)
					file_remove(file)
				except:
					logger.debug("[submit Error]  %s ---------------------------------------->>"%file)
				logger.debug("[Lets' go Next Seeds]---------------------------------------->>")
				logger.debug("[incialize] pfctl %s"%subprocess.check_output(["sudo","sysctl","net.inet.ip.forwarding=1"]))
			else:
				logger.debug("[warning] %s is not unsupported file."%file)
				file_remove(file)
		else:
			logger.debug("[notice] %s is not file."%file)
	if raw_input() == "EXIT": break

exit(cuckoo,mongo,manage)

