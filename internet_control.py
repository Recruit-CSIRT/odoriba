#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-

# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.
# [original] this module is to burn the malware outbound traffic

import os,sys
import subprocess
import time 
import shlex

VMWARE_GUEST_IP = "write your own"
VIRTUALBOX_GUEST_IP = "write your own"

def burn():
	# Halt Port fowardeing
	return subprocess.check_output(["sudo","sysctl","net.inet.ip.forwarding=0"])

# sys.argv[0] == "vmware" or "virtualbox"  
def check(hv,TIMEOUT,logger,BURN_LIMIT):
	s=0;FIN_flag=False
	if hv == "vmware":
		network = "vmnet1"
		srcip=VMWARE_GUEST_IP
	elif hv == "virtualbox": 
		network = "vboxnet0"
		srcip=VIRTUALBOX_GUEST_IP

	cmd_dump = 'tcpdump -i %s -c %s -nn src %s and \(dst port not 2042\) and \(src port not 8000\)'%(network,str(BURN_LIMIT),srcip)
	fd_dump = subprocess.Popen(shlex.split(cmd_dump),stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

	while True:
		s+=1
		logger.debug("[INTERNET_CONTROL]: analysis not completed yet (status=BURN_CHECK) (spent=%ds/%s)"%(s,TIMEOUT))
		time.sleep(1.0)
		if fd_dump.poll() is not None:
			if burn() == "net.inet.ip.forwarding: 1 -> 0\n":
				logger.debug("[burn] OFF!! internet access over %d ... filterd packets malware Scan or DoS"%BURN_LIMIT)
				break
		elif s==TIMEOUT:
			fd_dump.terminate() 
			break
		
		if subprocess.check_output(['ps']).find('child.py')==-1:
			FIN_flag = True
			fd_dump.terminate() 
			break

	return s,FIN_flag
