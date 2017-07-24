#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is DB writer for realtime behavior log and return data to views.py.

from django.conf import settings
import json
import bson_dump
import pcap_dump
from datetime import datetime
import time
import subprocess,os.path
from collections import OrderedDict

import pymongo

file_intel_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT).intel
file_collection = file_intel_db.collection
url_intel_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT).intel
url_collection = url_intel_db.collection

# realtime log storage
realtime_log_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT).real
realtime_log_collection = realtime_log_db.collection

def main(new,running,category):
	baiyo = []
	dict_real_db = {}
	# database collection
	data_real_db = realtime_log_collection.find_one({"id":str(running.id)})
	if data_real_db == None:
	    dict_bindex = {}
	    dict_pindex = {}
	    dict_pindex['past_pcaps'] = 0
	    list_bson_prev = [] 
	    list_pcap_prev = []
	    prev_bpage = 0
	    prev_ppage = 0
	else:
	    dict_bindex = data_real_db['dict_bindex']
	    dict_pindex = data_real_db['dict_pindex']
	    list_bson_prev = data_real_db['list_bson_prev']
	    list_pcap_prev = data_real_db['list_pcap_prev']
	    prev_bpage = data_real_db['prev_bpage']
	    prev_ppage = data_real_db['prev_ppage']

	## bsondump section
	result = bson_dump.main(running.id,dict_bindex)
	dict_bindex = result[0]
	list_bson = result[1]

	# bson time column adding
	i=0
	now_time = int(time.mktime(running.started_on.timetuple())) 
	while i < len(list_bson):
	    epoch = now_time + int(list_bson[i][0]) # spent second
	    clock = datetime(*time.localtime(epoch)[:6])
	    list_bson[i].append(str(clock))
	    i+=1


	# Debug check
	print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	print data_real_db
	print dict_bindex
	print dict_pindex
	print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	## pcapdump section
	pkts_index,list_pkts = pcap_dump.analyzer(running.id,dict_pindex)
	dict_pindex = pkts_index
	list_pcap = []
	for p in list_pkts:
	    if p != []:#list_pcap.append('pkt::'+str(p))
	        epoc = p[7] #float
	        spent = int(epoc) - now_time
	        p.pop(7)
	        p.insert(0,spent)
	        list_pcap.append(p)


	# json files creates
	print "======================================"
	print "\tJSON FILE Creating \n"

	home = os.path.expanduser('~')
	rid_path = '%s/odoriba/web/static/json/%s'%(home,str(running.id))
	bson_path = rid_path + '/bson'
	pcap_path = rid_path + '/pcap'
	
	if os.path.exists(rid_path) == False:
		subprocess.call(['mkdir',rid_path])
		print '[make folder] %s'%rid_path
	if os.path.exists(bson_path) == False:
		subprocess.call(['mkdir',bson_path])
		print '\t[make folder] %s'%bson_path
	if os.path.exists(pcap_path) == False:
		subprocess.call(['mkdir',pcap_path])
		print '\t[make folder] %s'%pcap_path
		
	bpage = len(os.listdir(bson_path))
	ppage = len(os.listdir(pcap_path))

	brow = 0
	while brow < len(list_bson):
		bpage += 1
		bjson = bson_path + '/bson_p%d.json'%bpage 
		dict_bpage = OrderedDict()
		with open(bjson,'w') as bj:
			print '\t\t[make json files] %s'%bjson
			for num in range(10):
				try: check_blistlength = list_bson[brow]
				except IndexError: break
				dict_brow = OrderedDict()
				dict_brow['Spent seconds'] = list_bson[brow][0]
				dict_brow['Thread id'] = list_bson[brow][1]
				dict_brow['Called APIname'] = list_bson[brow][2]
				dict_brow['Points'] = list_bson[brow][3]
				dict_brow['Category'] = list_bson[brow][4]
				dict_brow['Is Success ?'] = list_bson[brow][5]
				dict_brow['Time'] = list_bson[brow][6]
				dict_bpage[str(num+1)] = dict_brow
				brow += 1
			bj.write("%s\n"%json.dumps(dict_bpage, indent=4))
		

	prow = 0
	while prow < len(list_pcap):
		ppage += 1		
		pjson = pcap_path + '/pcap_p%d.json'%ppage 
		dict_ppage = OrderedDict()
		with open(pjson,'w') as pj:
			print '\t\t[make json files] %s'%pjson
			for num in range(10):
				try: check_plistlength = list_pcap[prow]
				except IndexError: break
				dict_prow = OrderedDict()
				dict_prow['Spent seconds'] = list_pcap[prow][0]
				dict_prow['DstIP'] = list_pcap[prow][1]
				dict_prow['DstPort'] = list_pcap[prow][2]
				dict_prow['SrcIP'] = list_pcap[prow][3]
				dict_prow['SrcPort'] = list_pcap[prow][4]
				dict_prow['Protocol'] = list_pcap[prow][5]
				dict_prow['Dump Top 128 byte'] = list_pcap[prow][6]
				dict_prow['Time'] = list_pcap[prow][7]
				dict_ppage[str(num+1)] = dict_prow
				prow += 1
			pj.write("%s\n"%json.dumps(dict_ppage, indent=4))
		

	#  database store
	if data_real_db == None:
	    # regist db
	    dict_real_db['id'] = str(running.id)
	    dict_real_db['list_bson_prev'] = list_bson
	    dict_real_db['list_pcap_prev'] = list_pcap
	    dict_real_db['dict_bindex'] = dict_bindex
	    dict_real_db['dict_pindex'] = dict_pindex
	    dict_real_db['prev_bpage'] = bpage
	    dict_real_db['prev_ppage'] = ppage
	    realtime_log_collection.insert_one(dict_real_db)
	else:
	    # add db (data_real_db)
	    data_real_db['list_bson_prev'].extend(list_bson)
	    data_real_db['list_pcap_prev'].extend(list_pcap)
	    data_real_db['dict_bindex'] = dict_bindex
	    data_real_db['dict_pindex'] = dict_pindex
	    data_real_db['prev_bpage'] = bpage
	    data_real_db['prev_ppage'] = ppage
	    realtime_log_collection.save(data_real_db)

	# storing rendering contena
	print "======================================"
	print "update bson row: %d"%len(list_bson)
	print "update pcap row: %d"%len(list_pcap)
	print " bson prev_bpage: %d"%prev_bpage
	print " pcap prev_ppage: %d"%prev_ppage
	print "======================================"

	new.update({"bson_maxpage": bpage})
	new.update({"pcap_maxpage": ppage})
	new.update({"prev_bpage": prev_bpage})
	new.update({"prev_ppage": prev_ppage})


	print "======================================"

	""" intelligence add-on """
	print " -------------   intelligence add-on   --------------------"
	list_intels = []
	if category == "file":
		list_collection = list(file_collection.find({'rid':str(running.id)}))
	elif category == "url":
		list_collection = list(url_collection.find({'rid':str(running.id)}))

	for l in list_collection:
	    l.pop("rid")
	    l.pop("_id")
	    list_intel = []
	    list_intel.append(l['ip'])
	    try:
	        list_intel.append(l['cc'])
	    except KeyError: 
	        list_intel.append('Not yet')
	    try:
	        list_intel.append(l['owner'])
	    except KeyError:
	        list_intel.append('Not yet')
	    try:
	        list_intel.append(l['response_code'])
	    except KeyError:
	        list_intel.append('Not yet')
	    try:
	        list_intel.append(l['webtitle'])
	    except KeyError:
	        list_intel.append('Not yet')
	    try:
	        list_intel.append(l['durl'])
	    except KeyError:
	        list_intel.append('Not yet')
	    try:
	        list_intel.append(l['dfile'])
	    except KeyError:
	        list_intel.append('Not yet')
	    list_intels.append(list_intel)

	new.update({"list_intel": list_intels})                   

	baiyo.append(new)

	return baiyo
