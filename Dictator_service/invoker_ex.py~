"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to launch discovery process with gui mode .
Invoker_ex.py is actually responsible for calling driver_meta.py along with project_id and relevent 
switches which shall make the code driver_meta.py to run in execute mode and it will start vul scan.
A process will keep on running in the background which shall do the scanning and save the details in
the database table.
"""
import driver_meta as driver_exploits
import os
import ConfigParser
import time
import psutil
import subprocess
import sys
import threading

DriverObj=driver_exploits.Driver()

project_id=sys.argv[1]
continue_=sys.argv[2]
delete=sys.argv[3]
get_default_config=sys.argv[4]
threading_=sys.argv[5]


print "Inside Invoker_ex.py \n\n"
print "Recieved aurguments are :"
print(project_id,continue_,delete,get_default_config)
active_threads=threading.enumerate()
counter=len(active_threads)
print "Inside invoker_ex.The number of threads active  are :"+str(active_threads)+"\n"
if threading_ =="0":
	DriverObj.main('gui',project_id,True,False,False) #,continue_,delete,get_default_config
elif threading_=="1":
	DriverObj.main('gui',project_id,True,False,False,True)


