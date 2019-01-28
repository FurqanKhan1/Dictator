import main_class_based_backup as main
import os
import ConfigParser
import time
import psutil
import subprocess

class Gui_main():

	def __init__(self):
		self.NmapScanObj=main.NmapScan()

	def main (self,path='',targethosts='',targetports='',switch='',scan_type='',project_id='',assessment_id='',app_id=''):
		
		
		project_id=self.NmapScanObj.driver_main(targethosts,path,targetports,scan_type,switch,project_id,"g-init",assessment_id,app_id)

		print "Project id is :" +str(project_id)
		file_=os.path.join("project_logs","project_"+str(project_id)+".txt")
		log_file=open(file_,'w')
		#start sub process here 
		driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %('invoker.py',targethosts,path,targetports,scan_type,switch,project_id,'g-start',assessment_id,app_id),shell=True,stdout=log_file,stderr=log_file,stdin=subprocess.PIPE)
		print "\n\n\n\n"
		print "The driver process id is : "+str(driver_process.pid)

		#Update database table with process id and scan id/project id
		ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid)

		print "Return value of update Process id is : "+str(ret_val)
		
		

		#Finally return the project id to service
		return project_id
		


obj=Gui_main()
scan_id=obj.main('test_path','test-host','test-port','test-switch','1','test-project','test-assessment','1')
print "\n\n The scan id returned is : "+str(scan_id)+" \n\n"

