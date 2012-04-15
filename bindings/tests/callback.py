#!/usr/bin/python

import sys
sys.path.append('.')
sys.path.append('./.libs')

try:
	import RequiemEasy
except:
	print "Import failed"
	print "Try 'cd ./.libs && ln -s librequiem_python.so _RequiemEasy.so'"
	sys.exit(1)

def foo(id):
        print "callback: id = " + str(id)
	idmef = RequiemEasy._get_IDMEF(id)
        idmef.PrintToStdout()
        #print bar.Get("alert.classification.text") # XXX not yet implemented
        return 0

RequiemEasy.set_pymethod(foo)

RequiemEasy.test_fct()
