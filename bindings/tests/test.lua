#!/usr/bin/env lua

require("RequiemEasy")

function my_cb(level, log)
	io.write("log: " .. log)
end
RequiemEasy.Requiem.og_SetCallback(my_cb)

idmef = RequiemEasy.IDMEF()

print("*** IDMEF->Set() ***")
idmef:Set("alert.classification.text", "My Message")
idmef:Set("alert.source(0).node.address(0).address", "x.x.x.x")
idmef:Set("alert.source(0).node.address(1).address", "y.y.y.y")
idmef:Set("alert.target(0).node.address(0).address", "z.z.z.z")
print(idmef)


print("\n*** IDMEF->Get() ***")
print(idmef:Get("alert.classification.text"))

function print_list(x)
   for key,i in pairs(x) do
       if type(i) == "table" then 
	   print_list(i)
       else
	   print(i)
       end
   end
end

print_list(idmef:Get("alert.source(*).node.address(*).address"))

fd = io.open("foo.bin","w")
idmef:Write(fd)
fd:close()

fd2 = io.open("foo.bin","r")
idmef2 = RequiemEasy.IDMEF()
idmef2:Read(fd2)
fd2:close()
print(idmef2)


print("\n*** Client ***")
c = RequiemEasy.ClientEasy("requiem-lml")
c:Start()

c:SendIDMEF(idmef)
