#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is virustotal reputation checker for C&C IP or FQDN

import sys #
import json
import urllib,urllib2
from pymongo import MongoClient

APIKEY = "Write your own apikey"

def parse_json(url,parameters):
	response = urllib2.urlopen('%s?%s' % (url, urllib.urlencode(parameters)),timeout=5).read()
	try:
		response_dict = json.loads(response)
	except Exception,e:
		#if e == "No JSON object could be decoded": 
		print "[Waiting 1 min for Virustotal's limit] %s"%e
		sys.exit(0)

	# inicialize
	dict_vt = {}

	# detected URLs
	total = "NULL"
	i = 0
	flag = False

	try:
		score = 0
		if len(response_dict[u'detected_urls']) > 1:
			while i < len(response_dict[u'detected_urls']):
				if i==0: total = response_dict[u'detected_urls'][i]["total"]
				if response_dict[u'detected_urls'][i]["positives"] != 0:
					score += response_dict[u'detected_urls'][i]["positives"]
					flag = True
				i+=1

			if flag != True:
				dict_vt['durl'] = "0/%s"%total
			else:
				avg = score/i
				dict_vt['durl'] = "%s/%s"%(avg,total)
		else:
			dict_vt['durl'] = "None"
	except KeyError:
		print "[INFO][Virustotal's result] durl isn't include key"
		dict_vt['durl'] = "None"


	# detected Files
	total = "NULL"
	i = 0
	flag = False

	if parameters.has_key('ip') == True:
		label = u'detected_downloaded_samples'
	elif parameters.has_key('domain') == True:
		label = u'detected_referrer_samples'

	try:
		score = 0
		while i < len(response_dict[label]):
			if i==0: total = response_dict[label][i]["total"]
			if response_dict[label][i]["positives"] != 0:
				score += response_dict[label][i]["positives"]
				flag = True
			i+=1

		if flag != True:
			dict_vt['dfile'] = "0/%s"%total
		else:
			avg = score/i
			rate = "%s/%s\t"%(avg,total)
			dict_vt['dfile'] = rate		
	except KeyError:
		print "[INFO][Virustotal's result] dfile isn't include key"
		dict_vt['dfile'] = "None"	

	#print dict_vt
	return dict_vt



def ipv4(ip,rid):
	# mongodb connect
	intel_db = MongoClient('127.0.0.1', 27017).intel
	collection = intel_db.collection

	print '#######  virustotal.ipv4  #######'
	if collection.find_one({'$and':[{"rid":str(rid)},{"ip":str(ip)},{"durl":"None"}]}) == None:
		print '\t#######  for new registration [%s]  #######'%str(ip)

		url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
		parameters = {'ip': ip, 'apikey': APIKEY}

		dict_vt = parse_json(url,parameters)

		ele = collection.find_one({'$and':[{"ip":str(ip)},{"rid":str(rid)}]})
		if ele == None:
			# regist db
			dict_vt['ip'] = str(ip)
			dict_vt['rid'] = str(rid)
			collection.insert_one(dict_vt)
		else:
			# add db
			ele["durl"] = dict_vt['durl']
			ele["dfile"] = dict_vt['dfile']
			collection.save(ele)

	else:
		print '\t#######  [virustotal.ipv4] already registed [%s]  #######'%str(ip)

def domain(fqdn,rid):
	# mongodb connect
	intel_db = MongoClient('127.0.0.1', 27017).intel
	collection = intel_db.collection

	print '#######  virustotal.domain  #######'
	if collection.find_one({'$and':[{"rid":str(rid)},{"fqdn":str(fqdn)},{"durl":"None"}]}) == None:
		print '\t#######  for new registration [%s]  #######'%str(fqdn)

		url = 'https://www.virustotal.com/vtapi/v2/domain/report'
		parameters = {'domain': fqdn, 'apikey': APIKEY}

		parse_json(url,parameters)

		dict_vt = parse_json(url,parameters)

		ele = collection.find_one({'$and':[{"fqdn":str(fqdn)},{"rid":str(rid)}]})
		if ele == None:
			# regist db
			dict_vt['fqdn'] = str(fqdn)
			dict_vt['rid'] = str(rid)
			collection.insert_one(dict_vt)
		else:
			# add db
			ele["durl"] = dict_vt['durl']
			ele["dfile"] = dict_vt['dfile']
			collection.save(ele)

	else:
		print '\t#######  [virustotal.domain] already registed [%s]  #######'%str(fqdn)
	

		
