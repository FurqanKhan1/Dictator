import main_class_based_backup as main
import os
import ConfigParser
import time
import psutil
import subprocess
import driver_meta as driver
import multiprocessing
import IPexploits
import json
import collections

class Gui_main():

	def __init__(self):
		folder_dir=os.path.dirname(os.path.realpath(__file__))
		all_config_file=os.path.join(folder_dir,"all_commands.json")
		self.NmapScanObj=main.NmapScan()
		with open(all_config_file,"rb") as f:
			    jsonpredata = json.loads(f.read()) #--> all service types in master json 
		self.commandJson=jsonpredata
		self.commandsJson=jsonpredata
		self.IPexploit=IPexploits.IPexploits()


	def main_start (self,path='',targethosts='',targetports='',switch='',scan_type='',project_id='',assessment_id='',app_id='',concurrent=False):
		
		
		project_id=self.NmapScanObj.driver_main(targethosts,path,targetports,scan_type,switch,project_id,"g-init",assessment_id,app_id)

		print "Project id is :" +str(project_id)
		if not os.path.exists("project_logs"):
			os.makedirs("project_logs")
		file_=os.path.join("project_logs","project_"+str(project_id)+".txt")
		log_file=open(file_,'w')
		#start sub process here 
		folder_name=os.path.dirname(os.path.realpath(__file__))
		print ("folder name is : "+str(folder_name))
		exe_file=os.path.join(folder_name,'invoker.py')
		if concurrent==False:
			concr="0"
		else:
			concr="1"
		driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,targethosts,path,targetports,scan_type,switch,project_id,'g-start',assessment_id,app_id,concr),shell=True,stdout=log_file,stderr=log_file,stdin=subprocess.PIPE)
		print "\n\n\n\n"
		print "The driver process id is : "+str(driver_process.pid)

		#Update database table with process id and scan id/project id
		ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid)

		print "Return value of update Process id is : "+str(ret_val)
		
		

		#Finally return the project id to service
		return project_id
		

	def main_pause(self,project_id='',assessment_id='',app_id=''):
		try:
			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")
			file_=os.path.join("project_logs","project_pause"+str(project_id)+".txt")
			log_file=open(file_,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'stopper.py')
			driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,'','','','2','',project_id,'g-stop',assessment_id,app_id),shell=True,stdout=log_file,stderr=log_file,stdin=subprocess.PIPE)
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)
			status=self.NmapScanObj.IPtable.Update_status_to_paused(project_id)
			return status;
		except :
			return 0;


	def main_resume(self,project_id='',assessment_id='',app_id=''):
		try:
			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")
			file_=os.path.join("project_logs","project_resume"+str(project_id)+".txt")
			log_file=open(file_,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'invoker.py')
			driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,'','','','2','',project_id,'g-resume',assessment_id,app_id),shell=True,stdout=log_file,stderr=log_file,stdin=subprocess.PIPE)
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)
			ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid)
			print "Return value of update Process id is : "+str(ret_val)

			return project_id
		except :
			return 0;

	def Overwrite_and_GetDefaultConfiguration(self,project_id='',assessment_id='',app_id='',continue_=False,delete=False,get_update_config=False):
		try:
			driverObj=driver.Driver()
			return_val=driverObj.main('gui',project_id,continue_,delete,get_update_config)
			return return_val

		except Exception, ee:
			return_val={}
			return_val["status"]="failure"
			return_val["value"]="Exception : "+str(ee)
			print "Inside exception of get Default config !!" +str(ee)
			return 0;
			

	def getDefaultConfiguration(self,project_id='',assessment_id='',app_id='',proceed=False):
		try:
			
			driverObj=driver.Driver()
			if proceed==False:
				return_val=driverObj.main('gui',project_id,False,False)
			else:
				return_val=driverObj.main('gui',project_id,False,False,True)
			#print "Ret val is : "+str(return_val)
			return return_val
			#return project_id
		except Exception ,ee:
			return_val={}
			return_val["status"]="failure"
			return_val["value"]="Exception : "+str(ee)
			print "Inside exception of get Default config !!" +str(ee)
			return 0;

	def configure_response(self,default_config):
			print "IN configure response !"
			config_list=[]
			config_dict={}
			return_val=[]
			for config in default_config["value"]:
				print str(config)
				config_dict={}
				#print str(project[0])+ "   " +str(project[1])
				config_dict["id"]=config[0]
				config_dict["project_id"]=config[1]
				config_dict["host"]=config[2]
				config_dict["port"]=config[3]
				config_dict["service"]=config[4]
				config_dict["project_status"]=config[5]
				config_dict["Commands"]=config[6]
				config_dict["reconfig_service"]=False
				config_dict["reconfig_exploit"]=False
				config_list.append(config_dict)
			return_val.append(config_dict)
			return_val.append(config_list)
			return return_val

	def updateDefaultconfiguration(self,updated_config={},project_id='',assessment_id='',app_id=''):
		list_return_set=[]
		try:
			print "hello" +str(type(updated_config))
			print "\n\n---------------------------------------"
			
			for entry in updated_config: #list of dictionaries-->each entry is ord dict
				#print "woo-->"+str(type(entries))
				#if 
				print "<--->"+str(entry["reconfig_service"])
				return_set={}
				return_set["service"]=entry["service"]
				if entry.get("reconfig_service")==True and entry.get("reconfig_exploit")==True:
						print "Debug 1"
						
						return_set["status"]="failure"
						return_set["value"]="Cant reconfigure /update both service and exploits at 1 time "
						list_return_set.append(return_set)
				elif entry["reconfig_service"]==True or entry["reconfig_exploit"]==True:
						print "Debug2"
						new_service=entry["service"]
						result_set={}
						result_set["service"]=entry["service"]	
						return_set=self.validate_and_update_service(new_service,entry,entry["reconfig_service"],entry["reconfig_exploit"])
						#return_set["value"]="Updated successfully"

						list_return_set.append(return_set)
						#return_set["service"]=entry.get("service")
						print "Results obtaied are --> : " +str(return_set)
				else:
						print "Debug 3"
						return_set["status"]="no_update"
						return_set["value"]="For this service the configuration parameters did not point to any update"
						list_return_set.append(return_set)
						
				
			#return validation_results
			print "\n\n\n\nReched here \n and returning now "
			default_config=self.getDefaultConfiguration(project_id,'','',True)
			return_config=self.configure_response(default_config)
			return_list_2=[]
			if return_config:
				#config_dict=return_config[0]
				def_config={}
				def_config["status"]="success"
				def_config["value"]=return_config[1]
				return_list_2.append(def_config)
				
			else:
				def_config={}
				def_config["status"]="failure"
				def_config["value"]="Cant reterive Configuration for the services "
				list_return_set.append(def_config)
				return_list_2.append(def_config)
				#list_return_set.append("Cant reterive Configuration for the services )
			final_return_list=[]
			final_return_list.append(list_return_set)
			final_return_list.append(return_list_2)
			return final_return_list#list_return_set
		except Exception ,ee :
			print "Exception 000: "+str(ee)
			return_={}
			return_["status"]="exception"
			return_["value"]=str(ee)
			list_return_set.append(return_)
			final_return_list.append(list_return_set)
			return final_return_list



	def getTemplate(self,service,entry_=None,reconfig_service=False,reconfig_exploits=False):
		print "\n\nObtaining template for service --> "+str(service)+"\n\n "
		entries={}
		commands_and_exploits={}
		row=[]	
		#print "eNTRY ---> \n\n"
		#print str(entry_)
		print "\n\n\n"
		if reconfig_exploits and reconfig_service :
			return -1
		if reconfig_exploits:	#yin this case only the exploits would have been updated and not service
								#thus we can keep service same .But make sure that a user is not changing 									#both at 1 time --very importanat
			service_val=entry_
		elif reconfig_service:
			service_val=self.commandsJson.get(service)
		
		if(service_val):
				#print "Debug 3"
				all_commands=service_val.get('Commands')
				if all_commands:
					#print "Debug 4"
					for entry in all_commands :
						#print "Debug 5"
						#print str(entry)
						if entry:
							method_name=entry.get('method')
							#print method_name
							command_id=entry.get('id')
							if reconfig_exploits:
								print "In 1"
								include=entry.get('include')
								commands_and_exploits[command_id]=[include,"0","0"]
							else:
								print "In 2"
								commands_and_exploits[command_id]=[True,"0","0"]
						else:
							return -1
											
					entries["Entries"]=commands_and_exploits
					entries=json.dumps(entries)
					return entries
				else:
					return -1
			
		else :
			#if(reconfig==True):
			print r+"[*] Invalid choice Enter a valid service class as per master json "
			return -1
	

	def validate_and_update_service(self,service,entry,reconfig_service,reconfig_exploits):
		try:
			print "Service for which update is to be performed -->"+str(service)
			service_val=self.commandJson.get(service)
			print "service val is -->"+str(service_val)
			return_val={}
			#print "The service val is -->"+str(service_val)
			if (not service_val):
				return_val["status"]="failure"
				return_val["value"]="Invalid Service Choice "
				return_val["service"]=str(service)
				return return_val
			else:
				all_commands=service_val.get('Commands') #commands is  list of dictionaries
				is_custom=service_val.get('Custom')
			if(is_custom==False):
						json_template=self.getTemplate(service,entry,reconfig_service,reconfig_exploits) #this service would be added by user and 
						#print "obtained json template for service :"+str(service)+" is "+str(json_template)
						if (json_template ==-1):
							return_val["status"]="failure"
							return_val["value"]="Invalid Service Choice "
							return_val["service"]=str(service)
							return return_val
																
						else:
							self.IPexploit.Update_Reconfig(entry["id"],entry["project_id"],entry["host"],entry["port"],entry["service"],'existing',json_template)
							return_set={}
							return_set["status"]="success"
							return_set["service"]=entry["service"]
							return_set["value"]="Updated Successfully"
							return return_set

			elif((is_custom==True) and (all_commands)):
									insert_entries=[]
									made_insertion=False
									#parent_service =unknownservice_json.get(str(update_entry["id"]))
									#print r+"[+]Parent service to be updated is -->"+str(parent_service)+e
									for ent in all_commands : #each command entry will point to a service cls
										if (ent):
											json_template=self.getTemplate(ent,entry,reconfig_service,reconfig_exploits)
											if (json_template ==-1):
												return_val["status"]="failure"
												return_val["value"]="Invalid Service Choice Custom"
												return_val["service"]=ent
												return return_val
							
											else:
												row=(entry["project_id"],entry["host"],entry["port"],ent,'update',json_template,'existing')
												print "Obtained row is : "+str(row)
												self.IPexploit.insertIPexploits(row,True) #insrt single record ,thus true
												made_insertion=True
												#print "\n\n"+g+"[+]Record Updated!!"+e
									if(made_insertion):
										print "About to remove !! record with id -->"+str(entry["id"])
										self.IPexploit.removeIPexploit(int(entry["id"]))
										return_set={}
										return_set["status"]="success"
										return_set["service"]=entry["service"]
										return_set["value"]="Updated Successfully"		
										return return_set
							
			else:
							return_val["status"]="failure"
							return_val["value"]="Invalid Service Choice All commands not set"
							return_val["service"]=str(service)
							return return_val
											
			
		except Exception ,ee:
			return_val={}
			return_val["status"]="failure"
			return_val["value"]=str(ee)
			return return_val
							
			print "Exception in validation --> "+str(ee)



	def LaunchExploits(self,project_id,continue_,delete,get_default_config,threading_=False):
		try:

			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")

			file_=os.path.join("project_logs","project_exploits"+str(project_id)+".txt")
			log_file=open(file_,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'invoker_ex.py')
			if threading_:
				driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,project_id,continue_,delete,get_default_config,'1'),shell=True,stdout=log_file,stderr=log_file,stdin=subprocess.PIPE)
			
			else:
				driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,project_id,continue_,delete,get_default_config,'0'),shell=True,stdout=log_file,stderr=log_file,stdin=subprocess.PIPE)
			
			print "\n\n\n\n"
			ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid,True)
			if ret_val==1:
				return "Process id is :"+str(driver_process.pid) +"and details saved successfully"
			else:
				return "Process id is :"+str(driver_process.pid) +" but details not updated !"
			print "The driver process id is : "+str(driver_process.pid)
			
	
		except Exception ,ee:
			print "exception :"+str(ee)
			return_val={}
			return_val["status"]="failure"
			return_val["value"]=str(ee)
			return return_val
			
			




