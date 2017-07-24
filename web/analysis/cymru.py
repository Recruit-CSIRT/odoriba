#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is cymru whois analyzer for C&C IP or FQDN

import socket
from cymruwhois import Client
from pymongo import MongoClient

def ipv4(ip,rid):
	# mongodb connect
	intel_db = MongoClient('127.0.0.1', 27017).intel
	collection = intel_db.collection

	print '#######  cymru.ipv4  #######'
	if collection.find_one({'$and':[{"rid":str(rid)},{"ip":str(ip)},{"cc":{"$exists":True}}]}) != None:
		print '\t#######  [cymru.ipv4] already registed [%s]  #######'%str(ip)
	else:
		print '\t#######  for new registration [%s]  #######'%str(ip)	

		# cymru whois lookup
		c=Client()
		r=c.lookup(ip)

		ele = collection.find_one({'$and':[{"ip":str(ip)},{"rid":str(rid)}]})
		if ele == None:
			# regist db
			result = {"ip": str(ip), "owner": str(r.owner), "cc":str(r.cc),"rid":str(rid)}
			collection.insert_one(result)
		else:
			# add db
			ele["owner"] = str(r.owner)
			ele["cc"] = str(r.cc)
			collection.save(ele)

def domain(fqdn,rid):
	# mongodb connect
	intel_db = MongoClient('127.0.0.1', 27017).intel
	collection = intel_db.collection

	print '#######  cymru.ipv4  #######'
	if collection.find_one({'$and':[{"rid":str(rid)},{"fqdn":str(fqdn)},{"cc":{"$exists":True}}]}) != None:
		print '\t#######  [cymru.domain] already registed [%s]  #######'%str(fqdn)
	else:
		print '\t#######  for new registration [%s]  #######'%str(fqdn)	

		# cymru whois lookup
		ip = socket.gethostbyname(fqdn)
		c=Client()
		r=c.lookup(ip)

		ele = collection.find_one({'$and':[{"fqdn":str(fqdn)},{"rid":str(rid)}]})
		if ele == None:
			# regist db
			result = {"fqdn": str(fqdn), "ip": str(ip), "owner": str(r.owner), "cc":str(r.cc),"rid":str(rid)}
			collection.insert_one(result)
		else:
			# add db
			ele["owner"] = str(r.owner)
			ele["cc"] = str(r.cc)
			collection.save(ele)			



