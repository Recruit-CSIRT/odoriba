#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (C) 2016- Tatsuya Ichida Recruit Technologies.

# [original] this module is the pcap analyzer via pcap files
#            import 3 C&C reputation analyzer 

import dpkt,urllib
import socket,os.path
from datetime import datetime
from collections import OrderedDict
import ipaddress 
import threading

# my own modules
import virustotal
import cymru
import http_access

def reputation(ip,rid):
	# web server check 
	haip = threading.Thread(target=http_access.ipv4, args=(ip,rid,)) 
	haip.start()

	# whois check
	cymruip = threading.Thread(target=cymru.ipv4, args=(ip,rid,)) 
	cymruip.start()

	# virustotal check
	vtip = threading.Thread(target=virustotal.ipv4, args=(ip,rid,)) 
	vtip.start()

	return 0


def pcap_intelligence(list_pcap,rid):
	list_intel_pcap = []
	dict_repu = {}
	for p in list_pcap:
		# check ip address
		if len(p) == 8 and ipaddress.ip_address(p[0]).is_private == False: # p[0] = dst ip
			ip = p[0]
			if ip != "239.255.255.250": # M-SEARCH
				list_intel_pcap.append(p)
				proto = p[4]
				dstp = p[1]
				if isinstance(dstp, int):
					if proto == "HTTP Request":
						if dict_repu == {} or dict_repu.has_key(ip) == False:
							reputation(ip,rid)
					elif int(dstp) > 1024:
						if dict_repu == {} or dict_repu.has_key(ip) == False:
							reputation(ip,rid)


	return list_intel_pcap




def analyzer(rid,dict_pindex):
	try:
		home = os.path.expanduser('~')
		pcap_file = '%s/odoriba/storage/analyses/%s/dump.pcap'%(home,rid)
	except Exception as e:
		print e

	print pcap_file
	with open(pcap_file,'r') as f:
		pcap = dpkt.pcap.Reader(f)
		list_pcap = []
		counter = 0
		for ts, buf in pcap:
			counter += 1
			if counter <= dict_pindex['past_pcaps']: 
				continue
			dump = ""
			list_pkt = []
			try: eth = dpkt.ethernet.Ethernet(buf)
			except: break
			if not isinstance(eth.data, dpkt.ip.IP):
				dump = 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
			else:
				ip = eth.data
				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data
					list_pkt.append(socket.inet_ntoa(ip.dst))
					list_pkt.append(tcp.dport)
					list_pkt.append(socket.inet_ntoa(ip.src))
					list_pkt.append(tcp.sport)
					if len(tcp.data) > 0:
						if tcp.dport == 80:
							list_pkt.append('HTTP Request')
 							try: httpreq = dpkt.http.Request(tcp.data);dump += 'http://'+httpreq.headers['host']+httpreq.uri + ' | UA:' + httpreq.headers['user-agent']
 							except: dump += 'parse error' 
 						elif tcp.sport == 80:
							list_pkt.append('HTTP Response')
 							try: httpres = dpkt.http.Response(tcp.data);dump += httpres.status
 							except: dump += 'parse error' 
 						elif tcp.dport == 443 or tcp.sport == 443:
 							list_pkt.append('HTTPS')
							try: dump += tcp.data.encode('utf-8')[:128]
							except Exception as e:
								#print e
								dump += "<non utf-8>"
 						else:
 							list_pkt.append('tcp')
							try: dump += tcp.data.encode('utf-8')[:128]
							except Exception as e:
								#print e
								dump += "<non utf-8>"
	
					else: list_pkt.append('tcp');dump += "<body 0bytes>"
					list_pkt.append(dump)
				elif isinstance(ip.data, dpkt.udp.UDP):
					udp = ip.data
					list_pkt.append(socket.inet_ntoa(ip.dst))
					list_pkt.append(udp.dport)
					list_pkt.append(socket.inet_ntoa(ip.src))
					list_pkt.append(udp.sport)
					if len(udp.data) > 0:
						if udp.dport == 53:
							list_pkt.append('DNS Request')
							dns = dpkt.dns.DNS(udp.data)
							dump += dns.qd[0].name
						elif udp.sport == 53:
							list_pkt.append('DNS Response')
							dns = dpkt.dns.DNS(udp.data)
							for answer in dns.an:
								if answer.type == 5:
									dump += answer.name					
						else:
							list_pkt.append('udp')
							try: dump += udp.data.encode('utf-8')[:128]
							except Exception as e:
								#print e
								dump += "<non utf-8>"

					else: list_pkt.append('udp');dump += "<body 0bytes>"
					list_pkt.append(dump)
				elif isinstance(ip.data, dpkt.icmp.ICMP):
					icmp = ip.data
					list_pkt.append(socket.inet_ntoa(ip.dst))
					list_pkt.append("<no use>")
					list_pkt.append(socket.inet_ntoa(ip.src))
					list_pkt.append("<no use>")
					list_pkt.append('icmp')
					if len(icmp.data) > 0:
						try: dump += str(icmp.data).encode('utf-8')[:128]
						except Exception as e:
							#print e
							dump += "<non utf-8>"

					list_pkt.append(dump)
				else:
					#dict_pkt['proto'] = "<non tcp/udp/icmp>"
					#dict_pkt['dump'] = "<no use>"
					continue
				list_pkt.append(datetime.fromtimestamp(ts).strftime('%m/%d %H:%M:%S'))
				list_pkt.append(ts)
			list_pcap.append(list_pkt)

	dict_pindex['past_pcaps'] = counter
	
	if len(list_pcap) == 0:
		list_pcap.append("No packets!")

	list_pcap = pcap_intelligence(list_pcap,rid)

	return dict_pindex,list_pcap



#if __name__ == "__main__":
#	dump = analyzer(sys.argv[1])
#	print dump



