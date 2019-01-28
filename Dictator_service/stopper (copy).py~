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
			obj.UpdatePid(project_id)
		else:
			processes=process_id.split(',')
			for proc in processes:
				kill_processes(int(proc))
			obj.UpdatePid(project_id)
			
	except Exception ,ee:
		print("Exception caught in th-controllor--"+str(ee))
else:
	print "No process id associated with scan !!!"


def kill_processes(process_id):
	try:
		process = psutil.Process(process_id)
		print str(process)
		for proc in process.children(recursive=True):
			print( "Killing Process with id -->"+str(proc))
			proc.kill()
			print( "Killed Process with id -->"+str(proc))
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

	    



		

