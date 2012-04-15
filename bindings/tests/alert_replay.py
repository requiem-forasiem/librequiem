#!/usr/bin/python

import os
import sys
sys.path.append('.')
sys.path.append('./.libs')

try:
	import RequiemEasy
except Exception,e:
	print "Import failed: ",e
	print "Try 'cd ./.libs && ln -s librequiem_python.so _RequiemEasy.so'"
	sys.exit(1)


src_dir = "alerts"
if len(sys.argv) > 1:
	src_dir = sys.argv[1]

if os.path.exists(src_dir) == 0:
	print "dir ",src_dir," does not exist"
	sys.exit(1)



def replay(alert):
	""" The real code goes here """
	print alert


for root, dirs, files in os.walk(src_dir):
	for name in files:
		if name.endswith(".idmef"):
			idmef = RequiemEasy.IDMEF()
			f = open( os.path.join(src_dir,name), "r")
			idmef >> f
			f.close()
			replay(idmef)


