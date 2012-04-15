#!/usr/bin/python

import RequiemEasy

client = RequiemEasy.ClientEasy("PoolingTest", RequiemEasy.Client.IDMEF_READ)
client.Start()

while True:
    idmef = RequiemEasy.IDMEF()

    ret = client.RecvIDMEF(idmef)
    if ret:
	print idmef
