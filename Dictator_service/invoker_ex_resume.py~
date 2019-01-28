"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to resume the paused vulneribility scanning by invoking driver_meta.py with all relevent switches
"""

import driver_meta as driver_exploits
import os
import time
import psutil
import subprocess
import sys
import threading


DriverObj=driver_exploits.Driver()

project_id=sys.argv[1]



print "Inside Invoker_ex_resume.py \n\n"
print "Recieved aurguments are :"
print(project_id)
active_threads=threading.enumerate()
counter=len(active_threads)
print "Inside invoker_ex_resume.The number of threads active  are :"+str(active_threads)+"\n"

DriverObj.main('gui',project_id,True,False,False,False,False,'',True,True) 



