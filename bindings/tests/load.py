#!/usr/bin/python

import sys
sys.path.append('.')
sys.path.append('./.libs')

try:
	import RequiemEasy
except Exception,e:
	print "Import failed: ",e
	print "Try 'cd ./.libs && ln -s librequiem_python.so _RequiemEasy.so'"
	sys.exit(1)

idmef = RequiemEasy.IDMEF()
idmef.ReadFromFile("foo.bin")
idmef.PrintToStdout()
