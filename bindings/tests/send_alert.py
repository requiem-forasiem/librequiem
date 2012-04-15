#!/usr/bin/python

import sys
import RequiemEasy

idmef = RequiemEasy.IDMEF()
idmef.Set("alert.classification.text", "Bar")

client = RequiemEasy.ClientEasy("MyTest")
client << idmef

