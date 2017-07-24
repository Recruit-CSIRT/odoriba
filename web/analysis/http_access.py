#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is HTTP Access analyzer for C&C IP or FQDN

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient

USERAGENT = "Write your own"

def access(url):
	headers = {
			'User-Agent': USERAGENT,
	}
	session = requests.session()
	try:
		print url
		req = session.get(url, headers=headers,timeout=5)
		soup = BeautifulSoup(req.content, "html.parser")
		response_code = req.status_code
		title = soup.title
	except:
		print "%s -->>  requests.exceptions.ReadTimeout:!!!!!!!!!"%url
		response_code = 0
		contents = "NULL"

	return response_code,title


def ipv4(ip,rid):
	# mongodb connect
	intel_db = MongoClient('127.0.0.1', 27017).intel
	collection = intel_db.collection

	print '\t#######  http_access.ipv4  #######'
	if collection.find_one({'$and':[{"rid":str(rid)},{"ip":str(ip)},{"response_code":{"$exists":True}}]}) != None:
		print '\t#######  [http_access] already registed [%s]  #######'%str(ip)
	else:
		print '\t#######  for new registration [%s]  #######'%str(ip)
		url = "http://" + ip + ":80"
		
		response_code,title = access(url)

		ele = collection.find_one({'$and':[{"ip":str(ip)},{"rid":str(rid)}]})
		if ele == None:
			# regist db
			result = {"ip": str(ip), "response_code": str(response_code), "webtitle":str(title), "rid":str(rid)}
			collection.insert_one(result)
		else:
			# add db
			ele["response_code"] = str(response_code)
			ele["webtitle"] = str(title)
			collection.save(ele)


def domain(fqdn,rid):
	# mongodb connect
	intel_db = MongoClient('127.0.0.1', 27017).intel
	collection = intel_db.collection

	print '\t#######  http_access.fqdn  #######'
	if collection.find_one({'$and':[{"rid":str(rid)},{"fqdn":str(fqdn)},{"response_code":{"$exists":True}}]}) != None:
		print '\t#######  [http_access] already registed [%s]  #######'%str(fqdn)
	else:
		print '\t#######  for new registration [%s]  #######'%str(fqdn)
		url = "http://" + fqdn + ":80"
		
		response_code,title = access(url)

		ele = collection.find_one({'$and':[{"fqdn":str(fqdn)},{"rid":str(rid)}]})
		if ele == None:
			# regist db
			result = {"fqdn": str(fqdn), "response_code": str(response_code), "webtitle":str(title), "rid":str(rid)}
			collection.insert_one(result)
		else:
			# add db
			ele["response_code"] = str(response_code)
			ele["webtitle"] = str(title)
			collection.save(ele)



