"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to act as a driver stub for both discovery and vulnerability scanning phases.
Earlier we larnt that the discovery can be started as new scan ,paused and resumed.
In case of vulneraibility scanning we larnt that in case of gui the module can be invoked with various
switches:
	1)To get default configuration
	2)To update default configuration
	3)To start scanning with threading
	4)To start scanning without threading
	5)To start concurrent scanning
	6)To stop scanningn
	7)To resume scanning

All these functionalities are carried out with the help of this module.It takes the data from the web service and (to start,stop,resume) scan it starts a new process and passes on relevent parameters to the 
python code for actually carrying out the scan and stores the process id and returns response to the user
so that the gui does not freeze or keeps on waiting and the newly created process keeps on executing in the background.
"""

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
import IPtable
class Gui_main():
	"""
	
		Objective :
		This class has various methods to invoke the GUI based discovery and vulneribility scanning in 
		differnrt ways.
	"""
	def __init__(self):
		"""
		Objective :
		This is the constructor of the class and its purpose is to initialise varipus class variables
		"""

		folder_dir=os.path.dirname(os.path.realpath(__file__))
		all_config_file=os.path.join(folder_dir,"all_commands.json")
		self.NmapScanObj=main.NmapScan()
		self.cppath=os.path.join(folder_dir,"nmap.cfg")
 		self.SWITCH=""
		self.takescan="0"
		with open(all_config_file,"rb") as f:
			    jsonpredata = json.loads(f.read()) #--> all service types in master json 
		self.commandJson=jsonpredata
		self.commandsJson=jsonpredata
		self.IPexploit=IPexploits.IPexploits()
		self.record_id=[]
		self.project_obj=IPtable.Projects()
		self.folder_dir=os.path.dirname(os.path.realpath(__file__))
		self.results_path=os.path.join(self.folder_dir,"Results")
		#print "\n\nResult path is : "+str(results_path) 
		

	def scanbanner(self,switch):
		obj=IPtable.IPtable()
		my_switch=obj.getSwitch(switch)
		if my_switch["status"]=="success":
			self.SWITCH=my_switch["value"]["name"]
			print "Switch obtained :"+str(self.SWITCH)
			if my_switch["value"]["catagory"]=="general": #"top_ports"
				return 1;
			else:
				return 0;

		else:
			self.SWITCH='-T4 -A -n'
			return 1;

	
			
	def main_start (self,path='',targethosts='',targetports='',switch='',scan_type='',project_id='',profile='',assessment_id='',app_id='',concurrent=False):
		
		"""
	
		Objective :
		This is the method which would take the data from the web service method and would pass on the data 
		to main_class_based_backup.py with the mode switch as 'gui' and would initially go and register a
 		new project and thus would obtain the project id.Then it maps the obtained project_id with process
 		id in the database table.Once the project id is obtrained it will launch a
 		new process and the filename passed to that process is invoker.py.Invoker.py is actually
 		responsible for calling main_class_based_backip.py along with project_id and relevent details like 
		host ,port and switch etc.This would start the nmap discovery process and a process will keep on
 		running in the background which shall do the discovery and save the details in the database table.
		"""

		cat=self.scanbanner(switch)
		print "The switch for scanning is :"+str(self.SWITCH)+" and obtained profile is : "+str(profile)
		if cat==0:
			targetports="top_ports"
		project_id=self.NmapScanObj.driver_main(targethosts,path,targetports,scan_type,self.SWITCH,project_id,"g-init",assessment_id,app_id,False,profile)

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
		try:
			driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,targethosts,path,targetports,scan_type,self.SWITCH,project_id,'g-start',assessment_id,app_id,concr),shell=True,stdout=log_file,stderr=log_file)
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)

			#Update database table with process id and scan id/project id
			ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid)
		except Exception ,ec:
			print "Exception while starting the process "+str(ec)
			return -1

		print "Return value of update Process id is : "+str(ret_val)
		
		

		#Finally return the project id to service
		return project_id
		

	def main_pause(self,project_id='',assessment_id='',app_id=''):
		"""
	
		Objective :
		This is the method which would take the data from the web service method and is responsible for
		pausing an ongoing scan.Basically when a scan is started we map the project id with the process
		id .In order to stop scan ,this method will pull up the process id from the passed on project id.
		Then it passes on the control to stopper.py which actually kills the process recursively killing all
 		its child processes and the details of the processes and sub processes killed will be logged in a
 		log file
		"""

		try:
			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")
			file_=os.path.join("project_logs","project_pause"+str(project_id)+".txt")
			log_file=open(file_,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'stopper.py')
			driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,'','','','2','',project_id,'g-stop',assessment_id,app_id),shell=True,stdout=log_file,stderr=log_file)
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)
			driver_process.wait()
			status=self.NmapScanObj.IPtable.Update_status_to_paused_or_processing(project_id,'paused')
			return status;
		except :
			return 0;


	def main_resume(self,project_id='',assessment_id='',app_id='',concurrent=False,switch='1'):
		"""
	
		Objective :
		This is the method which would take the data from the web service method and would pass on the data 
		to main_class_based_backup.py with the mode switch as 'gui' and resume flag as set.The project id
 		is obtrained from the service and it will launch a new process and the filename passed to that
 		process is invoker.py.Invoker.py is actually responsible for calling main_class_based_backip.py
		along with project_id and and resume flag set as True .This would start the nmap
 		discovery process and a process will keep on running in the background which shall do the discovery
 		and save the details in the database table.
		"""

		try:
			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")
			file_=os.path.join("project_logs","project_resume"+str(project_id)+".txt")
			log_file=open(file_,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'invoker.py')
			self.scanbanner(switch)
			obj=IPtable.IPtable()
			ret_sw=obj.switch(project_id)
			if ret_sw != -1:
				self.SWITCH=ret_sw
			print "Obtained switch while resume :" +str(self.SWITCH)
			if concurrent==False:
				driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,'','','','2',self.SWITCH,project_id,'g-resume',assessment_id,app_id,'0'),shell=True,stdout=log_file,stderr=log_file)
			else:
				driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,'','','','2',self.SWITCH,project_id,'g-resume',assessment_id,app_id,'1'),shell=True,stdout=log_file,stderr=log_file)
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)
			ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid)
			print "Return value of update Process id is : "+str(ret_val)

			return project_id
		except :
			return -1;

	def Overwrite_and_GetDefaultConfiguration(self,project_id='',assessment_id='',app_id='',continue_=False,delete=False,get_update_config=False):
		"""
		Objective :
		THis method is used with vulneribility scanning.
		This is the method which would take the data from the web service method and would invoke 
		driver_meta.py with relevent switches in order to make driver_meta.py overwrite the configuration or
 		scan results earlier placed for the project id supplied by the service and then would return the
 		default configuration for project id that is passed to it.
		"""
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
			

	def getDefaultConfiguration(self,project_id='',assessment_id='',app_id='',proceed=False,concurrent=False,rec_list=[]):
		"""
		Objective :
		THis method is used with vulneribility scanning.
		This is the method which would take the data from the web service method and would invoke 
		driver_meta.py with relevent switches in order to make driver_meta.py return the default
 		configuration for project id that is passed to it.
		"""

		try:
			#print "\n\n Finally concurrent is :"+str(concurrent)
			driverObj=driver.Driver()
			if concurrent==False:
				if proceed==False:
					return_val=driverObj.main('gui',project_id,False,False)
				else:
					return_val=driverObj.main('gui',project_id,False,False,True)#third true means to get updated config
			#print "Ret val is : "+str(return_val)
				if return_val:
					return return_val
				else:
					return_set={}
					return_set["status"]="failure"
					return_set["value"]="Some error occured and could not fetch the configuration.See Logs"
					return return_set
			
			else:
				#return_val=driverObj.main('gui',project_id,False,False,True,False,True,rec_list,True)
				#The above switch will return the configuration for the records passed in list only
				print "Here i am dudes"
				return_val=driverObj.main('gui',project_id,False,False,True,False,False,'',True)
				#This witch will return the configuration for all records for the current scan,which is better with respect to gui and polling
				if return_val:
					return return_val
				else:
					return_set={}
					return_set["status"]="failure"
					return_set["value"]="Some error occured and could not fetch the configuration.See Logs"
					return return_set
			
			#return project_id
		except Exception ,ee:
			return_val={}
			return_val["status"]="failure"
			return_val["value"]="Exception : "+str(ee)
			print "Inside exception of get Default config !!" +str(ee)
			return 0;

	def configure_response(self,default_config):
			"""
			Objective :
			THis method is used with vulneribility scanning.
			This is the method which would reterive the configuration (default or updated) and would format
			it in a list of dictionaries such that the retuned structure is easy to consume and consistant.
			"""

			print "IN configure response !"
			config_list=[]
			config_dict={}
			return_val=[]
			for config in default_config["value"]:
				#print str(config)
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
				if len(config)> 7:
					config_dict["service_type"]=config[7]
				if len(config)>8:
					config_dict["state"]=config[8]
					config_dict["version"]=config[9]
				if len(config) >9:
					config_dict["test_case"]=config[10]
				
					
				
				config_list.append(config_dict)
			return_val.append(config_dict)
			return_val.append(config_list)
			return return_val

	def updateDefaultconfiguration(self,updated_config={},project_id='',assessment_id='',app_id='',concurrent=False):
		"""
		Objective :
		THis method is used with vulneribility scanning.
		This is the method which would take the data from the web service method and would invoke 
		driver_meta.py with relevent switches in order to update the default configuration for the 
		records that are passed in the list opf dictionaries updated_config={},to be updated.It makes use of
 		validate_and_update method which would actually validate details before updating them.IT must be
 		noted that either a service is updated (host ,port,service) or exploit is updated(include/exclude).
		
		To do :
		Kindly note right now we are adressing reconfigure service (it will reconfigure /update any of host
		/port/service for a given record.But we are not addressing the case of add new host,port,service
 		like we have in cli model.Add this feature 
	
		"""

		list_return_set=[]
		self.record_id=[]
		try:
			print "hello" +str(type(updated_config))
			print "\n\n---------------------------------------"
			
			for entry in updated_config: #list of dictionaries-->each entry is ord dict
				#<<<<<<< HEAD
				#=======
				#print "woo-->"+str(type(entries))
				#if 
				#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
				print "<--->"+str(entry["reconfig_service"])
				self.record_id.append(int(entry["id"]))
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
						return_set=self.validate_and_update_service(project_id,new_service,entry,entry["reconfig_service"],entry["reconfig_exploit"])
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
			print "Entries in Recor_id list are :"+str(self.record_id)
			if concurrent==False:
				
				default_config=self.getDefaultConfiguration(project_id,'','',True)
			else:
				default_config=self.getDefaultConfiguration(project_id,'','',True,True,self.record_id)
			
			return_config=[]
			if default_config["status"]!="failure":
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
				#list_return_set.append(def_config)
				return_list_2.append(def_config)
				#list_return_set.append("Cant reterive Configuration for the services )
			final_return_list=[]
			final_return_list.append(list_return_set)
			final_return_list.append(return_list_2)
			return final_return_list#list_return_set
		except Exception ,ee :
			print "Exception 000: "+str(ee)
			return_={}
			return_["status"]="failure"
			return_["value"]="Some error occured while fetching configuration "
			return_["errors"]=str(ee)
			if not list_return_set:
				list_return_set=[]
			if not final_return_list:
				final_return_list=[]
			list_return_set.append(return_)
			final_return_list.append(list_return_set)
			return final_return_list



	def getTemplate(self,project_id,service,entry_=None,reconfig_service=False,reconfig_exploits=False):

		"""
		Objective :
		THis method is used with vulneribility scanning.
		This is the method which would take the service from the updated_config list passed by the user and
 		would read the master json to fetch the service template if the provided service would be a relevent
 		1.If yes then the template(various vul scan checks along with command id's) is returned.
		"""

		print "\n\nObtaining template for service --> "+str(service)+"\n\n "
		entries={}
		commands_and_exploits={}
		row=[]	
		#print "eNTRY ---> \n\n"
		#print str(entry_)
		record_id=entry_["id"]
		print "\n\n\n"
		if reconfig_exploits and reconfig_service :
			return -1
		if reconfig_exploits:	#in this case only the exploits would have been updated and not service
								#thus we can keep service same .But make sure that a user is not changing 									#both at 1 time --very importanat (additional db check needed)
			
			result=self.IPexploit.return_service(project_id,record_id)
			if result["status"]=="success":
				obtained_service=result["value"]
				if obtained_service == service:
					service_val=entry_
				else:
					return -1
			else:
				print str(result["value"])
				return -1
			
		elif reconfig_service:
				service_val=self.commandsJson.get(service)
				id_list=[]
				profile_list=self.project_obj.getProfile(project_id)
				profile=profile_list[0]
			
				if profile== -1:
					profile="Mandatory"
				if profile=="Master":
					profile_file=os.path.join(self.folder_dir,"Master.json")
				elif profile=="Mandatory" or profile == "Custom_Mandatory":
					profile_file=os.path.join(self.folder_dir,"Mandatory.json")
				elif profile=="Analytical" or profile == "Custom_Analytical":
					profile_file=os.path.join(self.folder_dir,"Analytical.json")
				
				else: #For project specific and all custom ,always this will get executed
					profile_file=profile_list[1]
				
				with open(profile_file, 'r+') as infile:
					self.profileJson=json.loads(infile.read())

				profile_service=self.profileJson.get(service)
				id_list=profile_service.get('Test_cases')

		
		if(service_val and profile_service and id_list):
				#print "Debug 3"
				all_commands=service_val.get('Commands')
				if all_commands:
					for entry in all_commands :
						if entry:
							method_name=entry.get('method')
							command_id=entry.get('id')
							if command_id in id_list:
								if reconfig_exploits:
									include=entry.get('include')
									valid=[True,False]
									if include in valid:
										commands_and_exploits[command_id]=[include,"0","0"]
									else:
										return -1
								else:
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
	

	def validate_and_update_service(self,project_id,service,entry,reconfig_service,reconfig_exploits):
		"""
		Objective :
		THis method is used with vulneribility scanning.
		This is the method which would actually avlidate weather the provided service in the update_config{}
		is relevent or a registered service of nmap or not.If it is a register one as per master json ,then
		it shall fetch table and relevent commands from get_template() method and once the template is
 		obtained it would update the backend database with the updated configuration.
		"""

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
						json_template=self.getTemplate(project_id,service,entry,reconfig_service,reconfig_exploits) #this service would be added by user and 
						#print "obtained json template for service :"+str(service)+" is "+str(json_template)
						if (json_template ==-1):
							return_val["status"]="failure"
							return_val["value"]="Invalid Service Choice "
							return_val["service"]=str(service)
							return return_val
																
						else:
							#self.IPexploit.Update_Reconfig(entry["id"],entry["project_id"],entry["host"],entry["port"],entry["service"],'existing',json_template)
							self.IPexploit.Update_Reconfig(entry["id"],int(project_id),entry["host"],entry["port"],entry["service"],'existing',json_template)
							
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
									if reconfig_service:
										for ent in all_commands : #each command entry will point to a service cls
											if (ent):
												json_template=self.getTemplate(project_id,ent,entry,reconfig_service,reconfig_exploits)
												if (json_template ==-1):
													return_val["status"]="failure"
													return_val["value"]="Invalid Service Choice Custom"
													return_val["service"]=ent
													return return_val
							
												else:
													#row=(entry["project_id"],entry["host"],entry["port"],ent,'update',json_template,'existing')
													row=(int(project_id),entry["host"],entry["port"],ent,'init',json_template,'existing')
													print "Obtained row is : "+str(row)
													id_inserted=self.IPexploit.insertIPexploits(row,True) #insrt single record ,thus true
													if(id_inserted is not None):
														self.record_id.append(int(id_inserted))
													made_insertion=True
													#print "\n\n"+g+"[+]Record Updated!!"+e
										if(made_insertion):
											print "About to remove !! record with id -->"+str(entry["id"])
											#self.IPexploit.removeIPexploit(int(entry["id"]))
											self.IPexploit.removeIPexploit(int(entry["id"]),False,int(project_id))
											return_set={}
											return_set["status"]="success"
											return_set["service"]=entry["service"]
											return_set["value"]="Updated Successfully"		
											return return_set
										else:
											return_set={}
											return_set["status"]="failure"
											return_set["service"]=entry["service"]
											return_set["value"]="Not Updated"		
											return return_set

											
									else:
											return_set={}
											return_set["status"]="no_update"
											return_set["service"]=entry["service"]
											return_set["value"]="Cant Update the exploits of custom service.There is some configuration error.Update the service first to be of type custom and then update exploits at discrete level of returned services."
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


	
	def InsertDefaultconfiguration(self,updated_config={},project_id='',assessment_id='',app_id='',concurrent=False):
		list_return_set=[]
		self.record_id=[]
		try:
			for entry in updated_config: 
				self.record_id.append(int(entry["id"]))
				return_set={}
				return_set["service"]=entry["service"]
				
				if 1:
						
						new_service=entry["service"]
						result_set={}
						result_set["service"]=entry["service"]	
						return_set=self.validate_and_insert_service(project_id,new_service,entry)

						list_return_set.append(return_set)
						print "Results obtaied are --> : " +str(return_set)

			print "\n\n Now concurrent is :"+str(concurrent)
			if concurrent==False:
				
				default_config=self.getDefaultConfiguration(project_id,'','',True)
			else:
				default_config=self.getDefaultConfiguration(project_id,'','',True,True,self.record_id)
	
			#default_config=self.getDefaultConfiguration(project_id,'','',True)
			return_config=[]
			if default_config["status"]!="failure":
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
				
				return_list_2.append(def_config)
				
			final_return_list=[]
			final_return_list.append(list_return_set)
			final_return_list.append(return_list_2)
			return final_return_list#list_return_set
		except Exception ,ee :
			print "Exception 000: "+str(ee)
			return_={}
			return_["status"]="failure"
			return_["value"]="Some error occured while fetching configuration "
			return_["errors"]=str(ee)
			if not list_return_set:
				list_return_set=[]
			if not final_return_list:
				final_return_list=[]
			list_return_set.append(return_)
			final_return_list.append(list_return_set)
			return final_return_list

	def validate_and_insert_service(self,project_id,service,entry,reconfig_service=True,reconfig_exploits=False):
		try:
			service_val=self.commandJson.get(service)
			return_val={}
			if (not service_val):
				return_val["status"]="failure"
				return_val["value"]="Invalid Service Choice "
				return_val["service"]=str(service)
				return return_val
			else:
				all_commands=service_val.get('Commands') #commands is  list of dictionaries
				is_custom=service_val.get('Custom')
			if(is_custom==False):
						json_template=self.getTemplate(project_id,service,entry,reconfig_service,reconfig_exploits) #this service would be added by user and 
						#print "obtained json template for service :"+str(service)+" is "+str(json_template)
						if (json_template ==-1):
							return_val["status"]="failure"
							return_val["value"]="Invalid Service Choice "
							return_val["service"]=str(service)
							return return_val
																
						else:
							row=(int(project_id),entry["host"],entry["port"],entry["service"],'init',json_template,'existing')
							id_inserted=self.IPexploit.insertIPexploits(row,True) #insrt single record ,thus true
							if(id_inserted is not None):
								self.record_id.append(int(id_inserted))
								made_insertion=True
													
							if(made_insertion):
								#self.IPexploit.insertIPexploits(row,True)							
								return_set={}
								return_set["status"]="success"
								return_set["service"]=entry["service"]
								return_set["value"]="Inserted Successfully"
								return return_set
							else:
								return_set={}
								return_set["status"]="failure"
								return_set["service"]=entry["service"]
								return_set["value"]="Insert Failed"
								return return_set


			elif((is_custom==True) and (all_commands)):
									insert_entries=[]
									made_insertion=False
									if reconfig_service:
										for ent in all_commands : #each command entry will point to a service cls
											if (ent):
												json_template=self.getTemplate(project_id,ent,entry,reconfig_service,reconfig_exploits)
												if (json_template ==-1):
													return_val["status"]="failure"
													return_val["value"]="Invalid Service Choice Custom"
													return_val["service"]=ent
													return return_val
							
												else:
													
													row=(int(project_id),entry["host"],entry["port"],ent,'init',json_template,'existing')
													print "Obtained row is : "+str(row)
													id_inserted=self.IPexploit.insertIPexploits(row,True) #insrt single record ,thus true
													if(id_inserted is not None):
														self.record_id.append(int(id_inserted))
													made_insertion=True
													
										if(made_insertion):
											return_set={}
											return_set["status"]="success"
											return_set["service"]=entry["service"]
											return_set["value"]="Inserted Successfully"		
											return return_set
										else:
											return_set={}
											return_set["status"]="failure"
											return_set["service"]=entry["service"]
											return_set["value"]="Not Inserted"		
											return return_set

									else:
											return_set={}
											return_set["status"]="no_update"
											return_set["service"]=entry["service"]
											return_set["value"]="Cant Update the exploits of custom service.There is some configuration error.Update the service first"
											return return_set		
											
							
			else:
							return_val["status"]="failure"
							return_val["value"]="Invalid Service Choice @@"
							return_val["service"]=str(service)
							return return_val
											
			
		except Exception ,ee:
			return_val={}
			return_val["status"]="failure"
			return_val["value"]=str(ee)
			return return_val
							
			print "Exception in validation --> "+str(ee)


	def LaunchExploits(self,project_id,continue_,delete,get_default_config,threading_=False,concurrent=False,rec_list=[]):
		"""
		Objective :
		THis method is used with vulneribility scanning.
		This is the method which would take the data from the web service method which includes the project
 		id.Then it maps the obtained project_id with process id in the database table.Once the project id 
		is obtained it will launch a new process and the filename passed to that process is invoker_ex.py.
		Invoker_ex.py is actually responsible for calling driver_meta.py along with project_id and relevent 
 		switches which shall make the code driver_meta.py to run in execute mode and it will start vul scan.
		A process will keep on running in the background which shall do the scanning and save the details in
 		the database table.
		"""

		try:

			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")

			file_=os.path.join("project_logs","project_exploits"+str(project_id)+".txt")
			file_error=os.path.join("project_logs","project_exploits_error"+str(project_id)+".txt")
			file_conc=os.path.join("project_logs","project_exploits_conc"+str(project_id)+".txt")
			file_conc_error=os.path.join("project_logs","project_exploits_conc_error"+str(project_id)+".txt")
			log_file=open(file_,'w')
			log_file_error=open(file_error,'w')
			log_file_conc=open(file_conc,'a')
			log_file_conc_error=open(file_conc_error,'a')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'invoker_ex.py')
			exe_file_conc=os.path.join(folder_name,'invoker_ex_conc.py')
			#exe_file_conc_error=os.path.join(folder_name,'invoker_ex_conc_error.py')
			if threading_:
				driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,project_id,continue_,delete,get_default_config,'1'),shell=True,stdout=log_file,stderr=log_file_error)
			
			else:
				if concurrent==False:
					driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file,project_id,continue_,delete,get_default_config,'0'),shell=True,stdout=log_file,stderr=log_file_error)
				else:
					driver_process=subprocess.Popen('exec python "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s"' %(exe_file_conc,project_id,continue_,delete,get_default_config,'0','1',rec_list),shell=True,stdout=log_file_conc,stderr=log_file_conc_error)
		
			print "\n\n\n\n"
			
			ret_val=self.NmapScanObj.IPtable.update_Pid(project_id,driver_process.pid,True,concurrent)
			return_vall={}
			return_vall["status"]="success"
			
			
			if ret_val==1:
				return_vall["value"]="Vul scanning started and Details Updated and Process id is : "+ str(driver_process.pid)
				return return_vall
				#return "Process id is :"+str(driver_process.pid) +" and details saved successfully"
			else:
				return_vall["value"]="Vul scanning started ,but Details not Updated"
				return return_vall
				
				#return "Process id is :"+str(driver_process.pid) +" but details not updated !"
			print "The driver process id is : "+str(driver_process.pid)
			
	
		except Exception ,ee:
			print "exception :"+str(ee)
			return_val={}
			return_val["status"]="failure"
			return_val["value"]=str(ee)
			return return_val
			


	def exploits_pause(self,project_id='',concurrent=False):
		"""
	
		Objective :
		This is the method which would take the data from the web service method and is responsible for
		pausing an ongoing scan.Basically when a vul scan is started we map the project id with the process
		id .In order to stop scan ,this method will pull up the process id from the passed on project id.
		Then it passes on the control to stopper_ex.py which actually kills the process recursively killing
 		all its child processes and the details of the processes and sub processes killed will be logged in a
 		log file
		"""

		try:
			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")
			file_=os.path.join("project_logs","project_exploit_pause"+str(project_id)+".txt")
			log_file=open(file_,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			if concurrent==False:
				conc="0"
			else:
				conc="1"
			exe_file=os.path.join(folder_name,'stopper_ex.py')
			driver_process=subprocess.Popen('exec python "%s" "%s" "%s"' %(exe_file,project_id,conc),shell=True,stdout=log_file,stderr=log_file)
			driver_process.wait()
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)
			status=self.NmapScanObj.IPtable.Update_status_to_paused_or_processing(project_id,'paused',True)
			#<<<<<<< HEAD
			self.IPexploit.UpdateStatus('init','','',project_id,'',True)
			#=======
			#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
			#status=self.NmapScanObj.IPtable.Update_status_to_paused(project_id)
			return 1;
		except :
			return 0;

	
	def exploits_resume(self,project_id=''):
		"""
		Objective :
		This is the method which would take the data from the web service method and would pass on the data 
		to driver_meta.py with the mode switch as 'gui' and resume flag as set.The project id
 		is obtrained from the service and it will launch a new process and the filename passed to that
 		process is invoker_ex.py.Invoker_ex.py is actually responsible for calling driver_meta.py
		along with project_id and and resume flag set as True .This would start the vulnerability scanning
 		process and a process will keep on running in the background which shall do the vulnerability
 		scanning and save the details in the database table.
		"""

		try:
			if not os.path.exists("project_logs"):
				os.makedirs("project_logs")
			file_=os.path.join("project_logs","project_exploit_resume"+str(project_id)+".txt")
			file_error=os.path.join("project_logs","project_exploit_resume_error"+str(project_id)+".txt")
			log_file=open(file_,'w')
			log_file_error=open(file_error,'w')
			#start sub process here 
			folder_name=os.path.dirname(os.path.realpath(__file__))
			print ("folder name is : "+str(folder_name))
			exe_file=os.path.join(folder_name,'invoker_ex_resume.py')
			self.IPexploit.UpdateStatus('init','','',project_id,'',True)
			driver_process=subprocess.Popen('exec python "%s" "%s"' %(exe_file,project_id),shell=True,stdout=log_file,stderr=log_file_error)
			print "\n\n\n\n"
			print "The driver process id is : "+str(driver_process.pid)
			resp=self.IPexploit.UpdatePid(project_id,str(driver_process.pid))
			return_vall={}
			return_vall["status"]="success"
			
			
			if resp:
				return_vall["value"]="Vul scanning started and Details Updated"
				return return_vall
				#return "Process id is :"+str(driver_process.pid) +" and details saved successfully"
			else:
				return_vall["value"]="Vul scanning started ,but Details not Updated"
				return return_vall
			
			
		except :
			print "exception :"+str(ee)
			return_val={}
			return_val["status"]="failure"
			return_val["value"]=str(ee)
			return return_val

			




