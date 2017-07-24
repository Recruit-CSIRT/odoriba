#!/usr/local/bin/env python
# -*- encoding: utf-8 -*-

# this module is logging function define

from logging import getLogger,StreamHandler,Formatter,DEBUG

def mylog():
	# create logger
	logger = getLogger(__name__)
	logger.setLevel(DEBUG)
	# create console handler and set level to debug
	ch = StreamHandler()
	ch.setLevel(DEBUG)
	# create formatter
	formatter = Formatter("%(asctime)s %(levelname)s %(message)s")
	# add formatter to ch
	ch.setFormatter(formatter)
	# add ch to logger
	logger.addHandler(ch)
	return logger