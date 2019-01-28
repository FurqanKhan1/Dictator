"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to stop an on going vulneraibility discovery scan
It will take the process id from the web service which would inturn get the id from the project id
and will then kill the process with recursively kiling all its child processes
"""

import main_class_based_backup as main
import os
import ConfigParser
import time
import psutil
import subprocess
import sys
import psutil
import threading
import IPexploits





def kill_processes(process_id):
	try:
		process = psutil.Process(process_id)
		print str(process)
		for proc in process.children(recursive=True):
			try:
				print( "Killing Process with id -->"+str(proc))
				proc.kill()
				print( "Killed Process with id -->"+str(proc))
			except Exception ,excep:
				print "Exception while killing but ignoring and continuing to kill "+str(excep)
			
		try:
			process = psutil.Process(process_id)
			if process:
				process.kill()
				thread=threading.current_thread()
				thread.join(10)
								#commands_executed.append('Process killed--.timeout')
		except:
			print("Parent Process already KIlled")
	except Exception ,ee:
		print("Exception caught in th-controllor--"+str(ee))



obj=IPexploits.IPexploits()
project_id=sys.argv[1]
concurrent=sys.argv[2]
print "Inside Stopper_ex.PY \n\n"
print (project_id,concurrent)
p_id=0

if concurrent=="0":
	p_id=obj.get_processId(project_id)
elif concurrent=="1":
	p_id=obj.get_processId(project_id,True)

if p_id:

	try:
		if concurrent=="0":
			process_id=int(p_id)
			kill_processes(process_id)
			obj.UpdatePid(project_id,'-100')
		else:
			processes=p_id.split(',')
			for proc in processes:
				kill_processes(int(proc))
			obj.UpdatePid(project_id,'-100',True)
		#return "1"
			
	except Exception ,ee:
		print("Exception2 caught in th-controllor--"+str(ee))
else:
	print "No process id associated with scan !!!"



	    



		

