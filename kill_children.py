#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is to kill the child process when analysis will be finish.

import sys,subprocess

cmd = 'ps | grep "child.py"'
ps = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout_data, stderr_out = ps.communicate() 

kill_array = []
if len(sys.argv) > 1:
	kill = subprocess.call(['kill',sys.argv[1]])
	kill_array.append(sys.argv[1])
else:
	for proc in stdout_data.split('\n'):
		if proc.find("grep")==-1:
			pid = proc.split("tty")[0]
			pid = pid.strip(" ")
			if pid != "":
				kill = subprocess.call(['kill',pid])
				kill_array.append(pid)
print "###################################################\n kill child.py process : %s \n###################################################"%kill_array


