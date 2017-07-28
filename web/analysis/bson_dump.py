#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is the cuckoo behavior log analyzer via mongo bson files 
#            import 3 C&C reputation analyzer 

import sys,subprocess,time,os.path
import glob
import threading
import re
from collections import OrderedDict

# my own modules
import virustotal
import cymru
import http_access

def reputation(fqdn,rid):

	# web server check 
	hadn = threading.Thread(target=http_access.domain, args=(fqdn,rid,)) 
	hadn.start()

	# whois check
	cymrudn = threading.Thread(target=cymru.domain, args=(fqdn,rid,)) 
	cymrudn.start()

	# virustotal check
	vtdn = threading.Thread(target=virustotal.domain, args=(fqdn,rid,)) 
	vtdn.start()

	return 0

def behavior_intelligence(dict_bson): #[spt,tid,apiname,msg,category,success_flag]
	list_bson = []
	list_fqdns = []
	for idx,dict_v in dict_bson.items():
		#print dict_v
		success_flag = "no"
		msg = ""
		args_v = ""
		show_flag = True
		dict_process = {}
		dict_file = {}

		# ///////////   process intelligence 
		# success check
		if dict_v['args_keys'].find('is_success') and dict_v['args_value'].split(',')[0][-1] == "1":
			success_flag = "yes"

		# icchi intelligence
		if dict_v['apiname'] == "__process__" and dict_v['category'] == "__notification__":
			print "/////////   process start ///////// "
			msg += "Process Lanched！"
			try: 
				msg += dict_v['args_value'].split(',')[6].split('\\')[-1].rstrip('"')
				dict_process[str(dict_v['tid'])] = msg
			except: pass

		elif dict_v['category'] == "file" and dict_v['apiname'].find(u"CreateFile")!=-1:
			print "/////////   Create File //////////"	
			msg += "Create File"
			try: 
				msg += dict_v['args_value'].split(',')[-2]
				dict_file[str(dict_v['tid'])] = msg
			except: pass

		elif dict_v['category'] == "process" and dict_v['apiname'].find(u"TerminateProcess")!=-1:
			print "/////////   Terminate Process //////////"	
			msg += "Terminate Process"
			try:
				msg += dict_process[str(dict_v['tid'])]
			except: pass

		elif dict_v['category'] == "misc" and dict_v['apiname'].find(u"WriteConsole")!=-1:
			print "/////////    Write Console  //////////"	
			msg = dict_v['args_value'].split(',')[-1][2:-2]
			msg += "-> Write Console"

		# //////////////  traffic intelligence 
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"URLDownloadToFile")!=-1:
			print "/////////    URLDownloadToFile  //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += "-> Downloads"
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"HttpAddRequestHeaders")!=-1:
			print "/////////    HttpAddRequestHeaders  //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += "-> HTTP Connection prep"
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"HttpOpenRequest")!=-1:
			print "/////////    HttpOpenRequest  //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += "-> HTTP Open Request"
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"InternetReadFile")!=-1:
			print "/////////   InternetReadFile   //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += "-> File Read from Internet"
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"InternetOpen")!=-1:
			print "/////////    InternetOpen  //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += "-> Internet Connection prep"
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"InternetOpenUrl")!=-1:
			print "/////////    InternetOpenUrl  //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += expl_fqdn(dict_v['args_value'])
			msg += "-> Internet Connection prep"
		elif dict_v['category'] == "network" and dict_v['apiname'].find(u"InternetConnect")!=-1:
			print "/////////    InternetConnect  //////////"
			print dict_v['args_value']
			try: 
				fqdn = expl_fqdn(dict_v['args_value'])
				list_fqdns.append(fqdn)
				msg += fqdn
			except: pass
			msg += "-> Internet Connection"

		# SelfDeleting
		# under constructions
		#elif success_flag == 'yes' and dict_v['category'] == 'file' and ( dict_v['apiname'] == u'DeleteFileA' \
		#															or dict_v['apiname'] == u'DeleteFileW' \
		#															or dict_v['apiname'] == u'NtDeleteFile' ):
		#	print "/////////    Delete File  //////////"

		# storing
		if show_flag:
			try: tid = dict_v['tid']
			except: tid = "null"
			try: spt = dict_v['spent_time']
			except: spt = "null"
			try: apiname = dict_v['apiname']
			except: apiname = "null"
			try: category = dict_v['category']
			except: category = "null"
			args_v = msg # over write

			list_bson.append([spt,tid,apiname,args_v,category,success_flag])
		print [spt,tid,apiname,args_v,category,success_flag]

	list_bson.sort()
	return list_bson,list_fqdns



def expl_fqdn(args_value):
	# URLDownloadToFile , InternetOpen 
	fqdn = args_value.split('"')[1].split('/')[2]
	try:
		if fqdn.find(':') != -1: fqdn = fqdn.split(':')[0]
	except Exception, e:
		fqdn = "";print e

	print fqdn
	return fqdn





class MyThread(threading.Thread):
    def __init__(self,bson,dict_bindex,bsonid):
        threading.Thread.__init__(self)
        self.return_value = ""   # RETURN VALUE
        self.return_value =  dump_bson(bson, dict_bindex, bsonid)  # SET RETURN VALUE


def dump_bson(file,dict_bindex,bsonid):
	if dict_bindex.has_key(str(bsonid)) == False:
		dict_bindex[str(bsonid)] = 0
	cmd = 'bsondump %s'%file
	print cmd
	
	ps = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout_data, stderr_out = ps.communicate() 
	ps.wait()

	update = ""
	try:
		update = stdout_data[dict_bindex[str(bsonid)]:]
	except:
		update = stdout_data

	for row in update.split("\n"):
		if row =="": row = "[last log]"
		update += file.split("/")[-1] + "::" + row + "\n"
	if update != None:
		print "[[ BSON update logs : %s ]]"%update
	else:
		print "[[ BSON NO update ]]"
	
	dict_bindex[str(bsonid)] += len(update)
	#print "return main dict_bindex[%d] %s"%(i,dict_bindex)
	return update

def bson2dict(log):

    # Here's an api description object:
    # {
    #     "I"        : (string)<index in the API lookup table>,
    #     "name"     : (string)<API name>,
    #     "type"     : "info",
    #     "category" : (string)<an API category (e.g. "memory" or "network")>
    #     "args"     : [
    #         "is_success",
    #         "retval",
    #         (string)<description of the first argument>,
    #         (string)<description of the second argument>,
    #                       ...
    #         (string)<description of the n-th argument>,
    #     ]
    # }

	rbson = re.compile(r'.+bson::{ "I" : (.+), "name" : "(.+)", "type" : "(.+)", "category" : "(.+)", "args" : (.+) }')
	#if you install python3, use below instead of upper rbson
	#rbson = re.compile(r'.+bson::{"I":(.+),"name":"(.+)","type":"(.+)","category":"(.+)","args":(.+)}')

    # Here's an api object:
    # {
    #     "I"    : (int)<index in the API lookup table>,
    #     "T"    : (int)<caller thread id>,
    #     "t"    : (int)<time (in milliseconds) since a process launch>,
    #     "args" : [
    #         (int)<1 if this API call was successfull, 0 otherwise>,
    #         (int)<return value>,
    #         (any)<value the first argument>,
    #         (any)<value the second argument>,
    #                       ...
    #         (any)<value the n-th argument>,
    #     ]
    # }	

	rbson2 = re.compile(r'.+bson::{ "I" : (.+), "T" : (.+), "t" : (.+), "h" : (.+), "args" : (.+) }')
	#if you install python3, use below instead of upper rbson
	#rbson2 = re.compile(r'.+bson::{"I":(.+),"T":(.+),"t":(.+),"h":(.+),"args":(.+)}')



	list_bson = []
	dict_bson = OrderedDict()
	for raw in log.split('\n'):
		try:
			expl_raw = rbson.findall(raw)
			if len(expl_raw) == 0: # for api object
 				expl_raw = rbson2.findall(raw)[0]
				lookup_idx = expl_raw[0]
				dict_bson.has_key(lookup_idx)
				dict_bson[lookup_idx]['spent_time'] = float(float(expl_raw[2])/1000)
				dict_bson[lookup_idx]['tid'] = expl_raw[1]
				dict_bson[lookup_idx]['args_value'] = expl_raw[4]
			else: # for api description object
				expl_raw = expl_raw[0]
				lookup_idx = expl_raw[0]
				dict_bson[lookup_idx] = OrderedDict()
				dict_bson[lookup_idx]['apiname'] = expl_raw[1]
				dict_bson[lookup_idx]['category'] = expl_raw[3]
				dict_bson[lookup_idx]['args_keys'] = expl_raw[4]

		except Exception as e:
			print "[[bson regex parse error below]] ", e
			pass
	
	new_list_bson,list_fqdns = behavior_intelligence(dict_bson)
	list_bson.extend(new_list_bson)

	return list_bson,list_fqdns


def except_lsass_process(bson_files):
	min_process = 10000
	lsass_bson = ""
	for bson in bson_files:
		tmp_process = bson.split('/')[-1][:-5]
		print tmp_process
		if min_process > int(tmp_process):
			min_process = int(tmp_process)
			lsass_bson = bson
			print lsass_bson

	return lsass_bson


def main(rid,dict_bindex):
	try:
		home = os.path.expanduser('~')
		bson_files = glob.glob('%s/odoriba/storage/analyses/%s/logs/*'%(home,rid)) 
	except Exception as e:
		print e

	print "bson_dumping %s"%bson_files
	log = ""
	
	lsass_bson = except_lsass_process(bson_files)
	print "lsass_bson %s"%lsass_bson

	for bson in bson_files:
		if bson == lsass_bson:
			continue
		try:
			bsonid = bson.split('/')[-1][0:-5] #4776 etc; id only explore
		except Exception as e:
			print "bson expl error :%s"%e
		th = MyThread(bson,dict_bindex,bsonid)
		th.start()
		th.join()
		log += th.return_value

	
	list_bsons,list_fqdns = bson2dict(log)

	# emit  bson traffic intelligence
	list_fqdns = list(set(list_fqdns)) # unique
	print "fqdns:%s"%list_fqdns
	for fqdn in list_fqdns:
		reputation(fqdn,rid)

	return dict_bindex,list_bsons

#main("latest",{})