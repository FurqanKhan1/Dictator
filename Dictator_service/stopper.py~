"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to stop an on going discover scan
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

NmapScanObj=main.NmapScan()

targethosts=sys.argv[1]
path=sys.argv[2]
targetports=sys.argv[3]
scan_type=sys.argv[4]
switch=sys.argv[5]
project_id=sys.argv[6]
mode=sys.argv[7]
assessment_id=sys.argv[8]
app_id=sys.argv[9]


print "Inside Stopper.PY \n\n"
print (targethosts,path,targetports,scan_type,switch,project_id,mode,assessment_id,app_id)

p_id=0
p_id=NmapScanObj.IPtable.get_processId(project_id)
process_id=int(p_id)

if process_id:

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
						#self.process.terminate()
		try:
			process = psutil.Process(process_id)
			if process:
				process.kill()
				thread=threading.current_thread()
				thread.join(60)
								#commands_executed.append('Process killed--.timeout')
		except:
			print("Parent Process already KIlled")
	    
	except Exception ,ee:
		print("Exception caught in th-controllor--"+str(ee))
else:
	print "No process id associated with scan !!!"







"""class Stopper():

	def __init__(targethosts,path,targetports,scan_type,switch,project_id,mode,assessment_id,app_id):
		self.NmapScanObj=main.NmapScan()		
		print "Inside Stopper.PY \n\n"


	def stop(self):
		p_id=self.NmapScanObj.IPtable.get_processId(project_id)
		process_id=int(p_id)

		if process_id:

			try:
				process = psutil.Process(process_id)
				print str(process)
				for proc in process.children(recursive=True):
					print( "Killing Process with id -->"+str(proc))
					proc.kill()
					print( "Killed Process with id -->"+str(proc))
						
								#self.process.terminate()
				try:
					process = psutil.Process(process_id)
					if process:
						process.kill()
						thread=threading.current_thread()
						thread.join(60)
										#commands_executed.append('Process killed--.timeout')
				except:
					print("Parent Process already KIlled")
			
			except Exception ,ee:
				print("Exception caught in th-controllor--"+str(ee))
		else:
			print "No process id associated with scan !!!"
"""







		

