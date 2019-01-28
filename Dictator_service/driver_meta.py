"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:12/30/2016

Objective :
The purpose of this file /module /Class is to read from master json ,reconfigure and to invoke the class which will actually run extarnal scripts for vulnerability scanniong .A more granular description is 
mentioned as under:

(1)	There would be a master json file which would be predefined which shall have exploits/test cases for each service discovered by Nmap (The master json file is prepared and tested based upon the latest PT-Database which serves as a guide line for pen testers which specifies what tests to conduct for what service).
(2)	The module Driver_meta.py would read the service, host, and port from the database table exploits for which test cases need to be launched. Based upon the service read it would then read the master json file to fetch the test cases which are meant to be checked/executed for the discovered service
(3)	The master json file can be found the bin folder of the tool by the name   all_commands.json.
(4)	The structure followed by master json file is : 
(5)	Key service name : value (A dictionary having a list of dictionaries)
(6) After the discovery phase would be over, all set of services and hosts would be identified and the next step is to launch exploits based upon the services found on the target host (s),for launching the exploits the master json file would be used/considered
(7)	But before launching the exploits, there would be an additional check that would prompt the user with all the details that have been identified in the discovery phase.(host, port, service, exploits to be launched (Default configuration)
(8)	For the CLI model this class will help in reconfiguration of the discovered services amnd for the GUI 		mode this class along with other classes will do reconfiguration .
(9)	Once the user has decided a final configuration and all the changes have been saved in the database, a scan would be launched as per user chosen configuration.
(10)The host, port and service class would be read from the database for the current project_id and then for current <host, port, service class >, the master json file would be read with the key being the service class. This would be done by the driver-stub )
(11)This stub would take the service-class from database as key and would read the master json file for external scripts /checks for the same key, if the 'custom' key would be set to true for the current service class, then driver stub would further read the classes that the custom class would be pointing to and would launch exploits/commands from the obtained indirection. If the custom flag would not be set then in that case the driver stub would simply read the exploits and would launch the exploits by invoking the auto_commands.py module with the chosen arguments. Note it replaces the host and port values read from the master json ,to actual host and port values read from the database and then finally passes control on to the appropriate method of the auto_commands.py module.
"""


import json
import time
import sys
import msfrpc
import auto_commands
import psutil
import MySQLdb
#import MySQLdb
import threading,multiprocessing
import subprocess
import logging
import logging.handlers
import threading
import Auto_logger
import json
import IPexploits
import commands,os
import texttable as tt
import csv
import os
import IPtable
import copy


r = '\033[31m' #red
b = '\033[34m' #blue
g = '\033[32m' #green
y = '\033[33m' #yellow
m = '\033[34m' #magenta
c = '\033[36m' #magenta
p = '\033[95m' #purple
e = '\033[0m' #end
lr= '\033[91m'#Light red


#print "Object created"


class Driver:
	"""
	Objective :
	This is the Driver class and has responsibility of mapping services discovered to master_json to fetch
	the external vulnerability scanning commands and also to reconfigure the default discovered services.
	"""
	
	def __init__(self):
		"""
		Objective :
		This is the constructor of the class and it initialises the various variables
		"""
	
		self.con=None
		self.cursor=None
		self.logger=None
		self.Log_file=None
		self.project_id="Default"
		self.lock = threading.Lock()
		self.Auto_logger=Auto_logger.Logger()
		self.commandObj=auto_commands.Commands()
		self.config={}
		self.config_file={}
		self.rows=[]
		self.method_id="INIT"
		self.processed_services=None
		self.commandsJson=None
		self.IPexploits=[]
		self.IPexploit=IPexploits.IPexploits()
		self.IPtable=IPtable.IPtable()
		self.missed_services=None
		self.new_and_unknown=[]
		self.data_path=""
		self.parent_folder="Results_and_Reports"
		self.folder_dir=os.path.dirname(os.path.realpath(__file__))
		self.results_path=os.path.join(self.folder_dir,"Results")
		#print "\n\nResult path is : "+str(results_path) 
		self.folder_name=os.path.join(self.results_path,"Data_")
		self.generate_report=False
		#<<<<<<< HEAD
		self.N=10
		self.active_processes=0
		#=======
		#self.N=10
		#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
		self.thread_count=1
		

	def init_connection(self):
		"""
		Objective :
		This method opens the database connection
		"""
	
		try:
			self.method_id="Init_connection()"
			self.con=MySQLdb.connect("localhost","<USER>","<PASSWORD>","nmapscan")
			self.cursor = self.con.cursor()
		except Exception,ee:
			self.print_Error("EXception in connection-->"+str(ee))

	def close_connection(self):
		"""
		Objective :
		This method closes the database connection
		"""
	
		try:
			self.method_id="Close_connection()"
			self.con.close()
		except Exception, ee:
			self.print_Error("EXception in connection-->"+str(ee))

	def parse_and_process(self,mode='c',continue_=False,concurrent=False): #note make an entry for service of type unknown in json file and its type would be custom
		"""
		Objective :
		The objective of this method is given as under :
		Once the discovery phase would be over the details of the discovered services are saved in the
 		IPtable (database table) as CSV in a single row for an ip and chunk of ports.This method actually
 		parses the csv based entries and then places them in seperate rows in the database table IPexploits.
		It also loads the default exploit template from the master json and places all these entries in the 
		IPexploits table under fields (project_id,host,port,service,exploits)
		 
		"""
	
		try:
			print "I am in parse and process"
			self.method_id="parse_and_process()"
			self.print_Log("Starting method --> "+self.method_id)
			self.rows=[]
			self.new_and_unknown=[]
			self.IPexploits=[]
			if (self.missed_services): #check is not none --it returns false for empty isits
				print "Missed services does contain data !!!"
				for k,v in self.missed_services.iteritems():
					entries={}
					entry={}
					service_status='unknown'
					#print "Missed service is "+str(k)
					if (k=='unknown'):
						service_status='unknown'
						entry["unknown"]=True
						entry["new"]=False
						#entry["echo"]=False
					elif(k !=""):
						service_status='new'
						entry["unknown"]=False
						entry["new"]=True
						#entry["echo"]=False
					if entry:
						entries["Entries"]=entry
						entries=json.dumps(entries)
					else:
						entries["Entries"]={"unknown":False,"new":False}
						entries=json.dumps(entries)
					for h_p in v:	
						#print "Appending -->Host-->"+str(h_p[0]) +"Port "+str(h_p[1]) +"Entries :" +str(entries)	
						self.rows.append((self.project_id,str(h_p[0]),str(h_p[1]),str(k),'init',entries,service_status,str(h_p[2]),str(h_p[3])))
						self.IPexploits.append(IPexploits.IPexploits(self.project_id,str(h_p[0]),str(h_p[1]),str(k),'init',entries,service_status))
					
			if (self.processed_services): #dict form of services that are discovered by nmap in dict fom
				#print "1000"
				#print "---->" +str(self.processed_services)
				for k,v in self.processed_services.iteritems():#would always have common services-May also contain custom services
					#print str(k)
					#print "bye"
					entries={}
					commands_and_exploits={}
					row=[]
					service_val=self.commandsJson.get(k) # k would be service and would act as key for commandsjson
					#all_commands=service_val.get('Commands') #commands is  list of dictionaries
					is_custom=service_val.get('Custom')
					#print "here reached"
					if(is_custom==False):
						entries=self.getTemplate(k)
						#print "entries are -->" +str(entries)
						if(entries != -1):
							#print "here reached also 1.2\n
							for h_p in v:	
								self.rows.append((self.project_id,str(h_p[0]),str(h_p[1]),str(k),'init',entries,'existing',str(h_p[2]),str(h_p[3])))
								self.IPexploits.append(IPexploits.IPexploits(self.project_id,str(h_p[0]),str(h_p[1]),str(k),'init',entries,'existing'))
								self.config[k]=row
						else:
							print "Error entry -1 for key -- Does not support recursive classes:"+str(k)
							self.print_Error("Entry error (returns -1) for key "+str(k))

					elif(is_custom==True):
						all_commands=service_val.get('Commands')
						if all_commands:
							for entry in all_commands : #each command entry will pint to a custom class
								if (entry):
									entries=self.getTemplate(entry)
									if(entries != -1):
										for h_p in v:	
											#self.rows.append((self.project_id,str(h_p[0]),str(h_p[1]),str(k),'init',entries,'existing'))
											self.rows.append((self.project_id,str(h_p[0]),str(h_p[1]),str(entry),'init',entries,'existing',str(h_p[2]),str(h_p[3])))
											self.IPexploits.append(IPexploits.IPexploits(self.project_id,str(h_p[0]),str(h_p[1]),str(entry),'init',entries,'existing'))
											self.config[k]=row
							

			if self.rows:
				#print "\n\n\nrows are \n\n"
				#print str(self.rows)
				#print "1"
				#self.makeBulkEntries(self.rows)
				self.IPexploit.insertIPexploits(self.rows)
				print "\n"
				#print r+"{+}______________Launching with selected configuration !!!__________________"+e
				if mode=='c':
					self.launchConfiguration()	
				else :
						if concurrent==True and continue_==False:
							return
						elif continue_== False and concurrent==False:
							return_val=self.launchConfiguration(False,'gui',False)
							return return_val
							#make_config=False,mode='c',choice='1',continue_=False):
						else: #no need for follwoing.It will be executed from main only
							val=self.launchConfiguration(True,'gui',True) #overwrite=true and continue=true
							if val==1:
								self.launchExploits()
							else:
								print "\n\n Some massive error occured --I am here !!"
							#self,make_config=False,mode='c',continue_=False)
			else :
				print "\n"+g+"No Common service and no unknown or new service discovered !!"+e
				return_set={}
				return_set["status"]="empty"
				return_set["value"]="No Common service and no unknown or new service discovered !!"
				return return_set
				#self.launchConfiguration()
				
		except Exception, ee:
			self.print_Error("EXception -->"+str(ee))
			return_set={}
			return_set["status"]="failure"
			return_set["value"]=str(ee)
			return return_set
	
	def DrawTable(self,records,header=[],col_width=[]):
		"""
		Objective :
		This method is used with the CLI version of the scripts and would display the discovered services
		for the current project id during the discovery phase ,so that the user can reconfigure any service 
		if he wishes.Note it works for CLI version.For GUI version there is a different method to handel
 		this
		"""
	
		tab = tt.Texttable()
		x = [[]]
		for row in records:
	   		x.append([str(row[0]),str(row[1]),str(row[2]),str(row[3]),str(row[4]),str(row[7])])
		tab.add_rows(x)
		tab.set_cols_align(['r','r','r','r','r','r'])
		if (header):
			tab.header(header)
		else:
			tab.header(['ID','PROJECT_Id','HOST','PORT','SERVICE','SERVICE TYPE'])
		if (col_width):
			tab.set_cols_width(col_width)
		print tab.draw()

	def getTemplate(self,service,reconfig=False):
		"""
		Objective :
		This is the method which will load the default template from master json for a given service.
		Suppose the service discovered by nmap is ssh ,now master json would be having 5-6 commands to be 
		executed for the given service ssh with id as (ssh1,ssh2,ssh3,ssh4,ssh5,ssh6) and this method first
 		checks weather the service exists in the master json ,if it does then its template in following 
		form is fetched entry[ssh1]:[True,0,0] ,entry[ssh2]:True,0,0] and so on
		The list  of dictionaris with value as [True ,0,0] actually maps to
 		['include_command,commands_executed,results_obtained]
		"""
	
		#print "\n\nObtaining template\n\n "
		entries={}
		commands_and_exploits={}
		row=[]		
		service_val=self.commandsJson.get(service)
		id_list=[]
		profile_service=self.profileJson.get(service)
		id_list=profile_service.get('Test_cases')
		if(service_val and profile_service):
				all_commands=service_val.get('Commands')
				if all_commands:
					for entry in all_commands :
						if entry:
							method_name=entry.get('method')
							command_id=entry.get('id')
							if command_id in id_list:
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
	
	def InsertAdditionalServices(self,unKnownServices,id_list):
		"""
		Objective :
		This method is used with CLI version and its purpose is to aid in reconfiguration.
		What it does is taht if any additional service records need to be added (host,port,service) assuming
		nmap missed something then that functionality in CLI mode is handeled by this method
		"""
	
		self.method_id="InsertAdditionalServices()"
		self.print_Log("Started method InsertAdditionalServices()")
		while (1):
				pass_check=True
				try:
					choice=raw_input( "\n\n"+y +">Press 1 to add additional test case and press 2 to proceed"+e)
					if (choice =="2"):
						break
					elif (choice=="1"):
						
						print b +"\n>Enter Host port and service in single line seperated by comma "+e
						print y +"[+] Eg: 192.168.179.136,80,ssh \n"+e
						entry=raw_input(y+">")
						line=entry.split(',')
						if (len(line) !=3):
							print "\n" +r+"[+] Invalid Choice "+e
							continue
						#(Pid,Host,Port,Service,Project_status,Exploits)
						ip=str(line[0])
						ip_chk=ip.split('.')
						if(len(ip_chk) < 2) :
							pass_check=False
							print "\n"+r+"[*]-Invalid Host "+e
							continue;
						if((str(line[1]).isdigit())==False):
							pass_check=False
							print "\n"+r+"[*]-Invalid PORT"+e
							continue
						service_val=self.commandsJson.get(str(line[2]))
						if (not service_val):
							print "\n"+r+"[*]--------Invalid SERVICE"+e
							continue
						all_commands=service_val.get('Commands')
						is_custom=service_val.get('Custom')
						if (is_custom==False):
							json_template=self.getTemplate(line[2],True)
							if (json_template ==-1):
								pass_check=False
								print "\n"+r+"[*]-Invalid SERVICE"+e
								continue
						
							if(pass_check==True):	
							
								print b+"json template--> " +str(json_template)
								if (json_template !=-1):
									row=(int(self.project_id),line[0],line[1],line[2],'init',json_template,'existing')
									self.IPexploit.insertIPexploits(row,True)
									print "\n"+y+"[+]The reconfiguration has been saved "+e
								else:
									print "\n"+r+"[*] Service class invalid "+e
							else:
								print "\n\n"+g+"[*]**********"+r+"Correct the errors and reenter"+g+"*********"+e+"\n\n"	
						elif (is_custom==True):
								if all_commands:
									for entry in all_commands : #each command entry will point to a custom class
										if (entry):
											json_template=self.getTemplate(entry,True)
											if (json_template ==-1):
												pass_check=False
												print "\n"+r+"[*]-Invalid SERVICE"+e
												continue
						
											if(pass_check==True):	
							
												print b+"json template--> " +str(json_template)
												if (json_template !=-1):
													row=(int(self.project_id),line[0],line[1],str(entry),'init',json_template,'existing')
													self.IPexploit.insertIPexploits(row,True)
													print "\n"+y+"[+]The reconfiguration has been saved "+e
												else:
													print "\n"+r+"[*] Service class invalid "+e
											else:
												print "\n\n"+g+"[*]**********"+r+"Correct the errors and reenter"+g+"*********"+e+"\n\n"
										else:
											print "\n\n"+g+"[*] **Some issue with master json..Contains no entry for this service for commands"+e
								else:
									print "\n\n"+g+"[*] **Some issue with master json..Commands key missing"+e
						else:
							print "\n\n"+g+"[*] **Some issue with master json..Custom flag not set"+e
										
				except Exception ,ee:
					print "Exception occured :" +str(ee)
					self.print_Error("Exception occured "+str(ee))
		self.method_id="InsertAdditionalServices()"
		self.print_Log("Stopped method InsertAdditionalServices()")


	def UpdateUnknownServices(self,unKnownServices,id_list,unknownservice_json):
		"""
		Objective :
		This method is used with the CLI version of the scripts and would give user the reconfiguration
		flexibility and would let the user to modify a given service or host or port and thus the
 		scanning would happen for the updated service/host/port rather than the one discovered by Nmap.
		For GUI version there is a different method to handle this
		"""
		self.method_id="UpdateUnknownServices()"
		self.print_Log("Started method UpdateUnknownServices")
		if (unKnownServices):
			update_entries=[]
			invalid=False
			while (1):
				try:	
					invalid=False
					reconfig=False
					choice=raw_input("\n"+b +">Press 1 to reconfigure press 2 to Launch Tests"+e)
					if (choice =="2"):
						break
					elif(choice=="1"):
						rec_id=raw_input( b +"Enter the Id of the record to reconfigure "+e)
						if rec_id in id_list:
							pass_check_=True
							reconfig=True
							update_entry={}
							update_entry["id"]=str(rec_id)
					
							inp=raw_input("Enter 1 to reconfigiure service and 2 to reconfigure all <host,port and service> ")

							if(inp=="1"):
								print y+"You may reffer to servics.txt file present in the parent folder to see the list of services currently supported"+e
								service_name=raw_input ("\n\n"+b +"Enter new service for the record id to be updated \n"+e)
								print "chosn service -->"+str(service_name)
								service_val=self.commandsJson.get(service_name) 
								print "service_val is :"+str(service_val)
								if (not service_val):
									print "\n"+r+"[*]-------Invalid SERVICE--------------"+e
									pass_check_=False
									continue
								all_commands=service_val.get('Commands') #commands is  list of dictionaries
								is_custom=service_val.get('Custom')
			
								if(is_custom==False):
										json_template=self.getTemplate(service_name,True) #this service would be added by user and 
										if (json_template ==-1):
											pass_check_=False
											print "\n"+r+"[*]-Invalid SERVICE"+e
											continue
										
						
										if( (pass_check_==True)):
											
											update_entry["service"]=service_name.lstrip().rstrip()
											update_entry["pid"]=str(self.project_id)
											print "\n\n[+]Updating the record!!"
											self.IPexploit.Update_Reconfig(update_entry["id"],update_entry["pid"],'','',update_entry["service"],'existing',json_template,True)
											print "\n\n"+g+"[+]Record Updated!!"+e


								elif((is_custom==True) and (all_commands)):
									print r+"\n\n[+]You have selected a custom class option.A custom class can be configured by selecting <configure all> option from the last menu.KIndly set custom service from there "+e
									continue
				
									
							elif(inp=="2"):
								print b +"Enter host port and service in single line seperated by comma "+e
								print y +"Eg: 192.168.179.136,80,ssh "+e
								entry=raw_input(y+">")
								line=entry.split(',')
								if (len(line) !=3):
									print "\n" +r+"[+] Invalid Choice "+e
									continue
								ip=str(line[0])
								ip_chk=ip.split('.')
								if(len(ip_chk) < 2) :
									pass_check_=False
									print "\n"+r+"[*]-Invalid Host "+e
									continue
								if((str(line[1]).isdigit())==False):
									pass_check_=False
									print "\n"+r+"[*]-Invalid PORT"+e
									continue
								service_val=self.commandsJson.get(str(line[2])) 
								print "The service val is -->"+str(service_val)
								if (not service_val):
									print "\n"+r+"[*]-------Invalid SERVICE--------------"+e
									pass_check=False
									continue
								all_commands=service_val.get('Commands') #commands is  list of dictionaries
								is_custom=service_val.get('Custom')
			
								if(is_custom==False):
										json_template=self.getTemplate(line[2],True) #this service would be added by user and 
										if (json_template ==-1):
											pass_check_=False
											print "\n"+r+"[*]-Invalid SERVICE"+e
											continue
										
						
										if((reconfig) and (not invalid) and (pass_check_==True)):
											update_entry["host"]=str(line[0]).lstrip().rstrip()
											update_entry["port"]=str(line[1]).lstrip().rstrip()
											#check weather the service added is there in the  master json
											update_entry["service"]=str(line[2]).lstrip().rstrip()
											update_entry["pid"]=str(self.project_id)
											print "\n\n[+]Updating the record!!"
											self.IPexploit.Update_Reconfig(update_entry["id"],update_entry["pid"],update_entry["host"],update_entry["port"],update_entry["service"],'existing',json_template)
											print "\n\n"+g+"[+]Record Updated!!"+e


								elif((is_custom==True) and (all_commands)):
									insert_entries=[]
									made_insertion=False
									parent_service =unknownservice_json.get(str(update_entry["id"]))
									print r+"[+]Parent service to be updated is -->"+str(parent_service)+e
									for entry in all_commands : #each command entry will point to a custom class
										if (entry):
											json_template=self.getTemplate(entry,True)
											if (json_template ==-1):
												pass_check_=False
												print "\n"+r+"[*]-Invalid SERVICE"+e
												continue
											
											if((reconfig) and (not invalid) and (pass_check_==True)):
												update_entry["host"]=str(line[0]).lstrip().rstrip()
												update_entry["port"]=str(line[1]).lstrip().rstrip()
												#check weather the service added is there in the  master json
												#update_entry["service"]=parent_service
												update_entry["service"]=entry
												update_entry["pid"]=str(self.project_id)
							
												print "\n\n[+]Updating the record!!"
												row=(int(self.project_id),update_entry["host"],update_entry["port"],update_entry["service"],'update',json_template,'existing')
												self.IPexploit.insertIPexploits(row,True)
												made_insertion=True
												print "\n\n"+g+"[+]Record Updated!!"+e
									if(made_insertion):
										self.IPexploit.removeIPexploit(int(update_entry["id"]))
										self.print_Log("Details updated for custom added service !!")
										print "\n\n"+g+"[+] Details updated Successfully for current service "	+e
							
							else:
								print r+"\n[+] INvalid choice \n"+e
								continue	
						else:
							print r +"[*][*]In valid Id-->Enter a valid ID\n" +e
							#invalid=True
							continue

				except Exception ,ee:
					self.print_Error("Exception in Update unknown services --" +str(ee))
					print ("Exception in update unknown services --"+str(ee))
							
		else :
			print g+"\n[+] No UNknown services were detected"+e

		self.method_id="UpdateUnknownServices()"
		self.print_Log("Stopped method UpdateUnknownServices")


	def reConfigure(self,mode='c'):
		"""
		Objective :
		This method is used with the CLI version of the scripts and would actually invoke the two flavours 
		of reconfiguration at run time (add additional records,modify existing records).This method would 
		also display all the unknown services on console (By unknown services we mean the services that do
		not have mapping created in the master json)
		"""
		try:
			self.method_id="Reconfigure()"
			self.print_Log("Started method Reconfigure")
			unKnownServices=self.IPexploit.getUnknownServices(self.project_id)
			id_list=[]
			
			repeat=1
			unknownservice_json={}
			if unKnownServices:
				print "found unknown services !!!"
				for entry in unKnownServices:
					id_list.append(str(entry[0])) #the one's having service type as unknown
					unknownservice_json[str(entry[0])]=str(entry[4])
				print y +"[+]" + "Discovered some unknown and new  services--Configure them or exploits woould not be launched against them" +e
				print "\n"
				self.DrawTable(unKnownServices)
				return_set={}
				return_set["services"]=unKnownServices
				if mode=="c":
					self.UpdateUnknownServices(unKnownServices,id_list,unknownservice_json)
				#else:
					

			self.InsertAdditionalServices(unKnownServices,id_list)
	
			#print "Press 1 to launch exploits and 2 change master file and  exit :"
			choice="0"
			while(1):
				choice=raw_input("\n"+g+"[+]Press 1 see the updated configuration and launch exploits and 2 change master file and  exit :\n"+e)
				if((choice=="1") or(choice=="2")):
					break
				else:
					print "\n"+r+"[*] Choice invalid \n"+e
			self.method_id="Reconfigure()"
			self.print_Log("Ending method Reconfigure()")
			if (choice =="1"):
				self.launchConfiguration(True)
				#self.launchExploits()
				#self.print_Log("Ended method Reconfigure")
			else :
				return


		except Exception,ee:
			self.print_Error("Error occured !!:" +str(ee))
	
	def makeConfigurationFile(self):
		"""
		Objective :
		This method is used wll actually save the final configuration for which the sacn is to be conducted 
		in a config file in json format
		"""
		
		config_file=str(self.project_id)+"Config.json"
		config_file_path = os.path.join(self.data_path, config_file)
		with open(config_file_path, 'w') as outfile:
     			json.dump(self.config_file, outfile, indent = 2,ensure_ascii=False)


	def launchConfiguration(self,make_config=False,mode='c',continue_=False,concurrent=False,record_list=[]):
		"""
		Objective :
		This method is used with the CLI version of the scripts and would actually display the default
 		configuration  for the services that would be discovered by Nmap .Essentially it would get executed 
		before any reconfiguration and would give user an option to choose weather to san with the default
		configuration or weather user may wish to update the configuration
		"""
		
		try:
			print "\n"+g+"[+] Launching configuration ...."+e
			#self.init_connection()
			self.method_id="launchConfiguration()"
			self.print_Log("Starting method --> "+self.method_id +"Project id --> "+self.project_id)
			id_=int(self.project_id)
			if concurrent==False:
				IPexploits=self.IPexploit.getIpExploits(self.project_id)
			else:
				IPexploits=self.IPexploit.getIpExploit(self.project_id,record_list)
			IPexploits_and_commands=[]
			list_row=[]
			config_list=[]
			tab_draw=[]
			for row in IPexploits: #row is of type tuple whic is read only
				
				#print str(row[4])
				#print "Row found with all elements as :"+str(row[0]) +str(row[1]) +str(row[2])+str(row[3])+str(row[4])
	   			commands=self.getCommands(row[4],row[2],row[3])#x.append([str(row[0]),str(row[1])])
				#print" commands got are :" +str(commands)
				list_row.append((row[0],row[1],row[2],row[3],row[4],row[5],commands,row[7],row[10],row[11],row[12]))
				tab_draw.append((row[0],row[1],row[2],row[3],row[4],row[5],'',commands))
			#note list row will have all the details required to be returned
	
			#print tab.draw()
			header=[]
			header=['ID','PROJECT_Id','HOST','PORT','SERVICE','Commands']
			col_width=[5,5,15,5,7,40]
			#self.DrawTable(tab_draw,header,col_width)
			return_set={}
			

			if mode !='c' and continue_== False:
				if concurrent==False:
					all_exploits=self.IPexploit.getUnknownServicesOnly(self.project_id)
				else:
					all_exploits=self.IPexploit.getUnknownServicesOnly(self.project_id,True,record_list)
				for row in all_exploits: #row is of type tuple whic is read only
					print "Row found UNknown also with 0th element as :"+str(row[0])
					empty_dict={}
					empty_dict["status"]="empty"
					list_row.append((row[0],row[1],row[2],row[3],row[4],row[5],empty_dict,row[7],row[10],row[11],row[12]))

				print "\n\nAbout to return now !!!"
				return_set["status"]="reconfig"
				return_set["value"]=list_row
				return return_set

			for row in list_row:
				config_entry={}
				print "\n"+ lr +"######################################################################################"+e
				#print str(row)
				#if mode =='c':
				if mode =='c':
					print ("\n"+g+"[+]Project id : "+y+str(row[1])+g+" [+] Host : "+y+ str(row[2])+g+" [+] Port : "+y+str(row[3]) +g+" [+] Service : "+y+str(row[4])+e)
				#print "Commands :"
				command_data=row[6]
				config_entry["id"]=str(row[0])
				config_entry["Project_id"]=str(row[1])
				config_entry["Host"]=str(row[2])
				config_entry["Port"]=str(row[3])
				config_entry["Service"]=str(row[4])
				config_entry["IsCustom"]=False
				config_entry["IsModified"]=False
				command_list=[]
				print "\n"
				for k in command_data:
					id_=k.get("id")
					command_list.append(id_)
					args=k.get('args')
					if mode =='c':
						print b+"*************************************************"+e
						print r+"Command id :-->"+y+str(id_)+e
						print r+"Commands :"+e
					for aur in args:
						if isinstance(aur, basestring):
							aur=aur.replace('\n','')
						if mode =='c':
							print str(aur)
					if mode =='c':
						print b+"*************************************************"+e
				#print "\n"
				if mode =='c':	
					print "\n"+ lr +"######################################################################################"+e
				config_entry["Commands"]=command_list
				config_list.append(config_entry)
			self.config_file["Records"]=config_list

			if mode !='c' and continue_==True and make_config==True:
				self.makeConfigurationFile()
				return 1

			if(make_config==True):
				self.makeConfigurationFile()
			
			print y+"\n\n[+] The above configuration has been selected :Press 1 tolaunch the tests ,2 to reconfigure !!!"+e
			choice="0"
			if mode=='c':
				while (1):
					choice =raw_input(b+"\n>Please enter your choice\n "+e)
					if((choice=="1") or (choice=="2")):
						break;
					else:
						print "\n" + r +"[+] Invalid choice " +e

				if (choice =="1"):
				
					self.launchExploits()
				else :
					self.reConfigure()
			else:
					print "Some error occured with flow.This should not be executed !!"
					#self.reConfigure("gui")
					

		except Exception ,ee:
			self.print_Error("EXception 11-->"+str(ee))
			print "Exception 11"+str(ee)

	def getCommands(self,k,host,port):
		"""
		Objective :
		This method is used to replace the command <host><Port> literals by actual host and port
		for which exploits need to be launched
		"""
		
		try:
			# "In get commands"
			#print str(k)
			service_val=self.commandsJson.get(k)
			#print "Got commands"
			#print str(service_val)
			all_commands=service_val.get('Commands')
			#print "here"
			arg_list=[]
			#arg_list.append(1)
			for arg in all_commands :
				#print str(args)
				if isinstance(arg, basestring):
						arg=arg.replace("<host>",host)
						arg=arg.replace("<port>",port)
				arg_list.append(arg)


			return arg_list

		except Exception, ee:
			self.print_Error("EXception -22->"+str(ee))
			return -1
	
		



	def set_log_file(self):
		"""
		Objective :
		This method is used to set the log file where all the log messages would be logged while execution.
		
		"""
		
		self.Log_file=str(self.project_id) +str("_Log_file_info.txt")
		print "\n\n\nData path is -->"+str(self.data_path) 
		self.Log_file_path = os.path.join(self.data_path, self.Log_file)
		print "Log file is --> " +str(self.Log_file)+"and log file path is : "+str(self.Log_file_path)
		print "\n@@@@\n"
		#self.Log_file=str(self.project_id) +str("_Log_file_info")
		self.logger=self.Auto_logger.configureLoggerInfo(self.method_id,self.Log_file_path)	
		self.print_Log("\n\nStarting \n\n")
		time.sleep(3)
		print "hello !!!  Logger is set"

	def init_project_directory(self):
		"""
		Objective :
		This method is used with to create a directory /folder with the name as same of the project id 
		and all the project related data would be found in this specific folder.It shall have all
		reports ,log files ,pcap files and configuration files specific to the project
		"""
		
		print "Initialising parent directory "
		try:
			if not os.path.exists(self.folder_name+str(self.project_id)):
				os.mkdir(self.folder_name+str(self.project_id))
				s_path=os.path.join(self.results_path,'bk')
				os.system("cp -r "+s_path+ " "+ self.folder_name+str(self.project_id)+"/")
				
			self.data_path=self.folder_name+str(self.project_id)
			return 1;
		except Exception ,ee:
			#self.print_Error("Error while creating directory !!"+str(ee))
			print "EX "+str(ee)
			return -1
	

	#def main_gui(self,project_id=''):
			
	def main(self,mode='c',project_id_='',continue_=False,delete=False,get_updated_config=False,threading_=False,concurrent=False,record_list=[],skip_init_check=False,resume=False):
		"""
		Objective :
		Note :Important method and switches
		This method is used from where the execution of this module/class begins.This is very important
 		method and is the starting point of both CLI mode and GUI mode.If invoked with mode flag as ='C' 
		(default) the code will run in CLI mode and when invoked with mode flag ='gui' the code will run
		in gui mode.
	
		There are various flags with which this module method could be invoked are gives as under :
	
		(1) main('c',100)	--> This will start the code in CLI mode for project with ID=100

		(2) main('gui',100) --> This will invoke the code in GUI mode and will return the Default 
			configuration for the project id 100.By default configuration we mean the default services
 			(discovered by nmap) and their checks from master json.

		(3) main('gui',100,False,True) --> This flag combination is essentialy used for rescanning in GUI
 			mode .Suppose for project id 100,earlier the scanning would have completed and all the results
			would be saved in the database table .If we wish to overwrite the earlier obtained results with
			default configuration and then scan /rescan again we invoke the main method with this switch.

		(4) main('gui',100,False,False,True) --> This flag configuration will return the updated 
			configuration for project id 100 ,when operated in GUI mode.
			Note:In order to save the details /updated configuration there is a different module that would
			handle that and would sent updated configuration to server to save it

		(5) main('gui',100,True,False,False) --> This flag combination will go ahead and would launch
 			vulnerability scanning for the project id 100 ,with the configuration that might be present in
			the database at that instance

		(6) main('gui',100,True,False,False,True) --> This flag combination will go ahead and would launch
 			vulnerability scanning for the project id 100 ,with the configuration that might be present in
			the database at that instance and in this case the vulnerability would be launched with
		 	threading enabled .Thus on the target machine parllely payload packets would be sent for
			vulneraibility assessment.This is a faster way to scan the target but note that the system 
			resources utilized with this kind of scan are relatively higher.
		
		(7) main('gui',100,False,False,False,False,True,[100,201])--> This will invoke the code in GUI mode
 			and will return the Default configuration for the project id 100 and only for the records
 			specified in the record_list and the concurrent flag should be set to true.By default
 			conf we mean the default services (discovered by nmap) and their checks from master json.
			So when concurrent flag is set ,instead of reading from IPtable_history the code reads from
 			IPexploits table for records in (rec_list[]) and perses the results to store them into 
			IPexploits table and finally returns the default configuration.

		(8) main('gui',100,False,False,True,False,True,[100,201])--> This will invoke the code in GUI mode
 			and will return the Updated configuration for the project id 100 and only for the records
 			specified in the record_list and the concurrent flag should be set to true.

			Note :In order to update the configuration ,there is a seperate module and the list of
 			dictionaries having updated configuration would be passed on to that module.

		(9) main('gui',100,True,False,False,False,True,[100,201])--> This flag combination will go ahead
 			and would launch vulnerability scanning for the project id 100 for the records in the
 			record list only and this actually represents the concurrent mode with concurrent flag set 
			to true,and the scanning would be done against  the configuration that might be present in the
 			database at that instance for the records specified in the record list.
		"""
		

		print "INVOKED Driver meta main with record_list : "+str(record_list) +" and  concurrent status : "+str(concurrent) +" and skip_init_check status as :"+str(skip_init_check) +" and continue ="+str(continue_)
		try:
			return_set={}
			self.method_id="Main()"
			
			tab = tt.Texttable()
			x = [[]]
			#self.init_connection()
			self.project_obj=IPtable.Projects()
			#result = self.cursor.execute("SELECT id, projects from project where project_status='complete'")
			#result=self.cursor.fetchall()
			if mode =='c':
				result=self.project_obj.completed_projects()
			else:
				result=self.project_obj.completed_projects(project_id_,'',True)
			#print "Result is :"+str(result)
			valid_projects=[]
			for row in result:
	   			x.append([str(row[0]),str(row[1])])
				valid_projects.append(str(row[0]))

			tab.add_rows(x)
			tab.set_cols_align(['r','r'])
			tab.header(['IDs','PROJECT_NAME'])
			#if mode =='c':
			#print "Valid projects :":
			#for v in valid_projects:
					#print v

				#print "\n"
			if mode=='c':
				print r+"List of Project with IDs"+e +"\n"
				print tab.draw()
				while 1:
					id = raw_input(b+"[+]Enter The Project Id For Scanning :\n>"+e)
					reenter=False
					if id in valid_projects:
						#print "yes"
						check_status=self.IPexploit.Exists(id)
						#print "here"
						print check_status
						if (check_status ==1):
							print y+"[+] It seems ,you have alreday launched exploits for this project .\n[+]Proceeding further would overwrie old logs."+e	
							while(1):
								ch=raw_input(b+"[+]Press 1 to Proceed 2 to Re enter.\n"+e)
								if ch=="1":
									self.IPexploit.removeIPexploit(id,all_=True)
									break
								elif ch=="2":
									reenter=True
									break
						if (reenter==False):		
							break
					else:
						print r+"[+] Invalid project id.Please select an id from the provided list "+e
						print "\n"
			else:
				id=str(project_id_)
				print "\n\n Project id is :	"+str(id)+"\n\n" 
				print "valid projects are " +str(valid_projects)
				if concurrent==False: 
					idd=str(id)
					if idd in valid_projects:
							#print "yes"
							check_status=self.IPexploit.Exists(id)
							print "here#@@"
							print check_status
							if (check_status ==1):
								if (concurrent==False):
									if(get_updated_config==False) and (continue_==False):
										proj_status=self.project_obj.fetch_project_status(id)
										status_flag=False
										if proj_status["status"]=="success":
											ps=proj_status["value"]["project_status"]
											pes=proj_status["value"]["project_exploits_status"]
											if pes=="incomplete":
												delete=True
										if(delete==False) :
											return_set["status"]="exists"
											return_set["value"]="It seems ,you have already launched exploits for this project .Proceeding further would overwrie old logs.Do you wish to continue"
											return return_set;
										elif(delete==True) and (continue_==False) and (concurrent==False): #launching get req second time
											print "About to remove entries even when status =false !!"
											self.IPexploit.removeIPexploit(id,all_=True)
							#else:
								#return_set["status"]="failure"
								#return_set["value"]="No service detected for this project"
								#return return_set

								
					else:
							print "\n\n\n\n Noops "
							return_set["status"]="failure"
							return_set["value"]="Invalid project id.Please select an id from the provided list"
							print r+"[+] Invalid project id.Please select an id from the provided list "+e
							print "\n"
							return return_set

			self.project_id=id
			#print "Removed !!"
			#print "-1"
			status=self.init_project_directory()
			print "INitialised"
			if (status==-1):
				return_set["status"]="failure"
				return_set["value"]="some error occured while creating the directory--Exiting..."
				print("some error occured while creating the directory\nExiting...")
				if mode !='c':
					return return_set
				else:
					return
			all_config_file=os.path.join(self.folder_dir,"all_commands.json")
			with open(all_config_file,"rb") as f:
					jsonpredata = json.loads(f.read()) #--> all service types in master json 
			self.commandsJson=jsonpredata
			profile_list=self.project_obj.getProfile(self.project_id)
			profile=profile_list[0]
			if 1:
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


			
			#self.print_Log("\n\n\nWelcome  STARTING MAIN METHOD OF DRIVER FILE FOR PROJECT ID --> " +str(id))
			lst1 = []
			
			id_=int(id)
			if skip_init_check==False: #Must exe for both exploit launching and def config
				if concurrent==False:
					result=self.IPtable.getServicesDetected(id_)
				else:
					result=self.IPtable.getServicesDetected(id_,True,record_list)#useful for specific insertion and also for specific configuration during getconfiguration
				#self.close_connection()
				#result_=self.cursor.fetchall()
				result_=result
				empty=True
				for rw in result:
					if rw[0] is not None:
						empty=False
						
				print "Hello"
				#print "Reult obtained is :"+str(result_)
				if (result_==0) or (not result_) or (empty==True):
					#return_set["status"]="failure"
					#return_set["value"]="some error occured while creating the directory--Exiting..."

					print "Some exception occured as result is empty !--"+str(result_)
					resp_stat={}
					resp_stat["status"]="failure"
					resp_stat["value"]="No service was detected for this scan."
	
					return resp_stat
				for row in result_:
					if row[0] is not None:
						string = str(row[0])
						s = string.split("\n")
						for k in s:
							t = str(k).split(";")
							lst1.append(t)
				#print "List 1 -->"+ str(lst1)
				lst = {}

				for i in lst1:
					if len(i) is not 1:
					 #print i[0]
					 temp={i[3]:[i[0],i[2],i[4],i[8]]}
                     
					 if cmp(lst.keys(), temp):
						lst.setdefault(i[3], []).append([i[0],i[2],i[4],i[8]])
					 else:
						lst.update(temp)

				lst.pop("name") #-->All service and val disc by nmap  {ssh:[[h1,p1],[h2,p2]],ftp--}
				all_config_file=os.path.join(self.folder_dir,"all_commands.json")
				with open(all_config_file,"rb") as f:
					jsonpredata = json.loads(f.read()) #--> all service types in master json 

				lst_pre = jsonpredata.keys()
				lst_temp = lst.keys()
				ss = set(lst_temp).intersection(set(lst_pre)) #-->All services common to what is discovered by nmap and what is there in master json-->it will skip the use case if nmap identifies a service that our master json would not have.Thus it would be good to do a set difference as well suc that all the services that are discovered by nmap and are not there in master json would be fetched
				ms=list(set(lst_temp) - set(lst_pre))

				#print "ss is " +str(ss) +" and lst is "+str(lst) +"and lst1 is :"+str(lst1)
				dic = {}
				for i in ss:
					for k in lst.get(i):
						dic.setdefault(i, []).append(k)#thus all refined data would be in dic.All services and host,ports that ar discovered by the nmap scan placed like {ssh:[[h1,p1],[h2,p2]],ftp--}
					#dic.update({i:k for k in lst.get(i)})
				ms_dic={}
				for i in ms:
					for k in lst.get(i):
						ms_dic.setdefault(i, []).append(k)
				print "here reached "
				self.processed_services=dic #--Processed services would now contain relevent json 
				self.commandsJson=jsonpredata #all data from json file is in commandsjson
				self.missed_services=ms_dic
				
			if mode=='c':
				self.set_log_file()
				self.IPexploit.data_path=self.data_path
				self.IPexploit.logger=self.logger
				self.commandObj.project_id=self.project_id
				self.commandObj.data_path=self.data_path
				self.commandObj.set_log_file()
				self.commandObj.logger_info=self.logger
			
				self.parse_and_process()
			else:
				#print "value of continue is :"+continue_
				#bool_=False
				#print "bool value :"+bool_
				if continue_==False and get_updated_config==False:#Initial run to get default config
					return_val=self.parse_and_process(mode,continue_,concurrent)
					return_set={}
					return_set["status"]="success"
					return_set["value"]=return_val
					return return_val
				elif continue_==False and get_updated_config==True:
					if concurrent==False:
						return_val=self.launchConfiguration(False,'gui',False)
					else:
						print "In else of concurrent and get updated config :"
						return_val=self.launchConfiguration(False,'gui',False,True,record_list)
						#print "Finished and now returning ----->:"+str(return_val)
						#print "\n\n\n\n\n"
					return return_val
				elif continue_==True and get_updated_config==False:#when -->for launching exploits
					print "\n\nLaunching config \n\n"
					#if concurrent==False:
					self.set_log_file()
					self.IPexploit.data_path=self.data_path
					self.IPexploit.logger=self.logger
					self.commandObj.project_id=self.project_id
					self.commandObj.data_path=self.data_path
					self.commandObj.set_log_file()
					self.commandObj.logger_info=self.logger
			
					val=self.launchConfiguration(True,'gui',True) #To mk config file overwrite=true and continue=true (self,make_config=False,mode='c',continue_=False):
					print "Val ret is :"+str(val)
					if val==1:
						print "Now Launching exploits !"
						if threading_==False:
							if concurrent==False:
								if resume==False:
									self.launchExploits()
								else:
									self.launchExploits(False,'',True)
							else:
								self.launchExploits(True,record_list)
							print "Launched Exploits !"
						else:
							print "Threading obtained is true !!!"
							active_threads=threading.enumerate()
							counter=len(active_threads)
							print "\n---\nMain At the begining --1---- the active threads are :---"+str(active_threads)+"\n---\n\n"
							self.thread_count=counter
							print "\n---\nMain At the begining the active threads are :---"+str(active_threads)+"\n---\n\n"
							#<<<<<<< HEAD

							self.IPexploit.UpdateStatus('init','','',self.project_id,'',True)
							self.startProcessing(self.N)
							
							
							#=======
							#self.startProcessing(self.N)
							
							#self.IPexploit.UpdateStatus('init','','',self.project_id,'',True)
							#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
							time.sleep(100)
							# "**Pooling started **\n"
							active_threads=threading.enumerate()
							counter=len(active_threads)
							
							#self.thread_count=counter
							self.method_id="Main()"
							#<<<<<<< HEAD
							self.print_Log("**Polling started :**")
							#=======
							#self.print_Log("**Pooling started :**")
							#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
							self.start_Polling()
						if threading_==True:
							self.check_final_status()
						else:

							self.IPexploit.UpdateProjectStatus('complete',self.project_id,concurrent)	
						return_val={}
						return_val["status"]="success"
						return_val["value"]="Project execution finished"
						#return return_val
					else:
						return_val={}
						return_val["status"]="failure"
						return_val["value"]="Some error occured.It occured while Launching configuration."
						return return_val
						print "\n\n Some massive error occured --I am here !!"

					
			print "Reached here !!"
			if(self.generate_report==True):
				if mode=='c':
					while (1):
						inp=raw_input("\n" + g +"[+] Press 1 to generate the report and 2 to exit \n")
						if (inp=="1"):
							self.IPexploit.generate_report(self.project_id)
							break
						elif(inp=="2"):
							break
				else:
					self.IPexploit.generate_report(self.project_id)
			
			if skip_init_check==False:
						
				temp_file=str(id) + "_result_data.txt"
				data_file=os.path.join(self.data_path,temp_file)
				json.dump(dic,open(data_file,"wb"))
				data = json.load(open(data_file,"rb"))

				data_temp = []
				for j in data:
					data_temp.append(j) #all keys of json file go in data_temp
	
		except Exception ,ee:
			print str(ee)
			self.print_Error("Error occured in Main method "+str(ee))
			return_set={}
			return_set["status"]="failure"
			return_set["value"]="Exception occured :"+str(ee)
			return return_set
		

	def check_final_status(self):
				"""
				Objective :
					This method is used with threading switch enabled and the purpose of this method is to 
					check weather there are any records in the database table with status marked as 
					incomplete.Actually this method is invoked when the scan would be about to finish and
					the number of threads would be reduced to 1 .
					Just to be completly sure we check if there is any record with status as incomplete.
					If yes then we do not terminate the process immidiately but infact wait for some time 
					till the status is marked as complete or error-complete and then safely exit.
				"""

				th_count=threading.enumerate() 
				print "# of threads Alive are :"+str(len(th_count))
				#while (1) :
				if 1:
					if (1):
						print "\nNow stopping and saving Global Project Id : "+ str(self.project_id)+"\n";	
						#global self.CURRENT_PROJECT_ID
						if 1:#((self.CURRE != "") and (self.CURRENT_PROJECT_ID is not None)):
							status=self.IPexploit.checkStatus(self.project_id)
							if(status):
								processing_status=status[0]
								pause_status=status[1]
								if((processing_status) and (not (pause_status))):#will just check once
										print "Still left with some hosts that display status as processing !!!"
										time.sleep(10)#the reason for this delay is suppose some thread is fired but not scheduled yet and thus the status would show as incomplete and if we immidiately statprocessing,then 2 threads might point to 1 record
										self.startProcessing(self.N)
										print "Main Thread--->Again Starting pooling in 50 sec :"
										time.sleep(50)
										print "Polling started-->again :"
										self.start_Polling()
										#xx=2
								if ((not(processing_status))  and (not(pause_status))): #to update status from incompl to comp								
									print "Launching clear logs and finally closing !!!"
									self.IPexploit.UpdateProjectStatus('complete',self.project_id)
									#self.IPtable.clearLogs(self.CURRENT_PROJECT_ID,'complete')
								#else :
									#clearLogs(self.CURRENT_PROJECT_ID,'complete')
				#end_time = time.time()
				#print "Time taken in seconds : "+str(end_time-start)


	def print_Log(self,message):
		"""
				Objective :
					This method is used to print log messages to the log file 
		"""
		if self.logger is not None:
			print message+"\n"
			try:
				print "Printing to log "
				self.lock.acquire()
				self.logger.debug(message)
				self.lock.release()	
				print "Printed to log"
			except Exception ,ee:
				self.lock.acquire()
				self.logger.critical(message +"--Exception :  --"+str(ee))
				self.lock.release()
				

	def print_Error(self,message):
		"""
				Objective :
					This method is used to print Error/Exception messages to the log file 
		"""

		if self.logger is not None:
			try:
				self.lock.acquire()
				self.logger.error(message)
				self.lock.release()
			except Exception ,ee:
				self.lock.acquire()
				self.logger.error(message +"--Exception :  --"+str(ee))
				self.lock.release()
			print message+"\n"
	
	
	def startProcessing(self,n):
	 """
		Objective :
		This method is used with threading switch enabled and acts as a thread schedular.
		It fetches teh number of unscanned IP's from database table and passes control to
		thread_starting method which launches n 'number' of threads based upon 'n' number of 
		IP's fetched from the database table where scan_status=unscanned'
	 """

	 try :
			active_threads=threading.enumerate()
			counter=len(active_threads)
			print "\n---\nB4 start processing --  the active threads are :---"+str(active_threads)+"\n---\n\n"
							#self.thread_count=counter

			self.method_id="LaunchExploits() with Threading"
			self.print_Log("Started method LaunchExploits()")
			self.generate_report=True
			All_services_and_hosts=self.IPexploit.getIpExploits(self.project_id,n)
			if (All_services_and_hosts):
				self.StartThreads(All_services_and_hosts)			
			else :
				return;
	 except Exception ,ee :
		print "Exception 12 " +str(ee)	

	def getPausedStatus(self,project_id):
		"""
				Objective :
				This method is used to check if the current project is under paused state or not
		"""

		try :
			status=self.IPexploit.getStatus(project_id)
			return status
		except Exception ,ee:
			print "Exception getstatus " +str(ee)
			return 0

	def check_dummy_status_only(self,active_threads):
		try:
			valid_counter=0;
			for th in active_threads:
				if th.getName().startswith('Dummy')==False:
					valid_counter = valid_counter +1
				else:
					print "Obtained dummy thread "+str(th)

			if valid_counter > 1:
				return False
			else:
				return True
		except Exception ,eex:
			
			print "Exception in iterating over dummy threads :"+str(eex)
			return False


	def start_Polling(self):
		"""
			Objective :
			This method would run infinitely in the background and would poll on active threads .
			Any time the active threads drop the thrashHold ((4) currently),this method will select
			(thrashhold-len(curr_threads)) number of IP addresses /records from table and would launch
			(thrashhold-len(curr_threads)) number of threads in parllal to scan the remaining hosts.
		"""

		try:
			stop_db_poll=False #use this logic to stop unnecessary db poll when all hosts finish
			#global N
			while 1:
				time.sleep(5)
				active_threads=threading.enumerate()
				counter=len(active_threads)
				#=1
				#print "Parent thread count oreginally was :"+str(self.thread_count)
				#<<<<<<< HEAD
				#print "Polling --> Threads remaining are :"+str(len(active_threads))+str(active_threads)+"\n"
				#=======
				#print "Polling --> Threads remaining are :"+str(active_threads)+"\n"
				#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
				ret_val=self.IPexploit.checkPollingStatus(self.N,self.project_id)
				print "Polling status of ret value is : "+str(ret_val["status"])
				if(ret_val["status"]=="complete"):
						print "Left with dummy threads ponly :"
						status=self.IPexploit.checkStatus(self.project_id)
						if(status):
							processing_status=status[0]
							pause_status=status[1]
							if((processing_status) and (not (pause_status))):#will just check once
									print "Still left with some records that display status as processing or incomplete "
									time.sleep(10)
									self.startProcessing(self.N)
									time.sleep(50)
							else:		
									
								print "Active Threads are only 1 --Scan about to finish --Threads remaining are :"+str(active_threads)
								self.print_Log("Active Threads are only 1 --Scan about to finish --Threads remaining are :"+str(active_threads))
								break;

				#elif(counter <=(self.N+1)):
				elif(ret_val["status"]=="pull"):
					if(not(self.getPausedStatus(self.project_id))):
						#limit=(self.N+1)-counter
						limit=int(ret_val["value"])
						if(limit != 0): 
							left_hosts=self.startProcessing(limit) 
							time.sleep(1)	
						else: #some thread is being executed
							time.sleep(2) #All threads are running ,just wait for 1 sec and then pool again	
							
					else:
						time.sleep(10) #status --> pause then it would get terminated on its own by kill
				elif(ret_val["status"]=="pass"):
					print "Active processes running are equal to max val :"
					time.sleep(10)
				elif (ret_val["status"]=="error") :
					print "\n------FATEL ERROR-------\n"
					print str(ret_val["value"])
					break;			
		except Exception ,ee:
			print "Exception caught 15" +str(ee)
			#break


	def getNonDummyCount(self,active_threads):
		try:
			dummy_counter=0;
			valid_counter=0
			for th in active_threads:
				if th.getName().startswith('Dummy')==False:
					valid_counter=valid_counter +1
				else:
					dummy_counter = dummy_counter +1
					
					print "Obtained dummy thread "+str(th)
			return valid_counter
			
		except Exception ,eex:
			
			print "Exception in iterating over dummy threads :"+str(eex)
			return len(active_threads)

	def StartThreads(self,IPexploits_data):
		"""
			Objective :
			This method would actually take data from polling and start_processing method and would be 
			responsible for actually launching 'n' threads in parllal each pointing to a record.
		"""

		try:
			self.method_id="Start Threads"
			threads=[]
			self.print_Log("Starting : "+str(len(IPexploits_data)) +"Threads for services :" )
			for exploit in IPexploits_data:
						current_record_id=exploit[0]
						service=str(exploit[4])
						host=exploit[2]
						port=exploit[3]
						#self.print_Log("Service,Host,port  is -->"+str(service)+"  " +str(host)+"  "+str(port))
						entry=self.commandsJson.get(service)
						meta=entry.get('Commands') 
						lk= threading.enumerate()
						#if len(lk)<(self.N+1) :	
						if (int(self.getNonDummyCount(lk)) < (self.N+1) ):
							print "Copying object !"
							obj=Driver()
							obj.con=self.con#=None
							obj.cursor=self.cursor#=None
							obj.logger=self.logger#=None
							obj.Log_file=self.Log_file#=None
							obj.project_id=self.project_id#="Default"
							obj.lock=self.lock #= threading.Lock()
							obj.Auto_logger=self.Auto_logger#=Auto_logger.Logger()
							obj.commandObj=auto_commands.Commands()#=THis line causes the bug /issue 
							obj.commandObj.project_id=self.project_id
							obj.commandObj.data_path=self.data_path
							obj.commandObj.set_log_file()
							obj.commandObj.logger_info=self.logger
							obj.config=self.config#={}
							obj.config_file=self.config_file#={}
							obj.rows=self.rows#=[]
							obj.method_id=self.method_id#="INIT"
							obj.processed_services=self.processed_services#=None
							obj.commandsJson=self.commandsJson#=None
							obj.IPexploits=self.IPexploits#=[]
							obj.IPexploit=self.IPexploit#=IPexploits.IPexploits()
							obj.IPtable=self.IPtable#=IPtable.IPtable()
							obj.missed_services=self.missed_services#=None
							obj.new_and_unknown=self.new_and_unknown#=[]
							obj.data_path=self.data_path#=""
							obj.parent_folder=self.parent_folder#="Results_and_Reports"
							obj.folder_dir=self.folder_dir#=os.path.dirname(os.path.realpath(__file__))
							#obj.results_path=results_path=os.path.join(self.folder_dir,"Results")
							#print "\n\nResult path is : "+str(results_path) 
							obj.folder_name=self.folder_name
							obj.profileJson=self.profileJson
					
							obj.N=self.N
							

							#obj=copy.deepcopy(self)	
							print "Object copied !"
							print "New object instance is :"+str(obj) +" and the main object instance is :"+str(self)	
							
							t = multiprocessing.Process(target=obj.launchThread,args=(meta,host,port,service,current_record_id,self)) 
							try :
								self.IPexploit.UpdateStatus('processing',host,port,int(self.project_id),int(current_record_id))
							except Exception, ee:
								print "EXception while updating status : " +str(ee)				
							#threads.append(t)
							t.start()
							obj.print_Log("\nStarted thread --"+str(t)+"--- for IP :"+str(host) + " Port : "+  str(port)+" and service : "+str(service))
							self.active_processes=self.active_processes +1
							print "Active processes : "+str(self.active_processes)
							#<<<<<<< HEAD
							time.sleep(1)
							#=======
							#time.sleep(3)
							#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
		except Exception ,ee:
			print ("Inside exception of start Threads ! " +str(ee))


	def launchThread(self,meta,host,port,service,current_record_id,parent_obj=None,params_key="Default"):
					"""
					Objective :
					Each thread will actually invoke the file auto_commands.py with appropriate commands
					and method in order for the method to launch vulnerability scanning with external
					scripts .This method does the same with threading enabled.
					"""

					try :
						profile_service=self.profileJson.get(service)
						id_list=profile_service.get('Test_cases')
		
						print "The thread is invoked with innstance :"+str(self)
						#print "The process count from parent is : " +str(project_obj.active_processes)
						params_config_file=os.path.join(self.folder_dir,"Project_params.json")
						with open(params_config_file,"rb") as f:
							all_params_data = json.loads(f.read()) #--> all service types in master json 
						param_data=all_params_data.get(params_key,None)
						user=''
						password=''
						domain=''
						user_sid=''
						if param_data != None:
							user=param_data.get("User","")
							password=param_data.get("Password","")
							domain=param_data.get("Domain","")
							user_sid=param_data.get("User_sid","")
							
						for entries in meta :
						  if entries.get('id') in id_list:	
							method_name=entries.get('method')
							args=entries.get('args')
							self.commandObj.method_id=method_name
							self.commandObj.command_id=entries.get('id')
							self.commandObj.current_record_id=current_record_id
							self.commandObj.current_host=host
							self.commandObj.current_port=port
							self.commandObj.data_path=self.data_path
							final_args=[]
							for arg in args:
								if isinstance(arg, basestring):
									arg=arg.replace("<host>",host)
									arg=arg.replace("<port>",port)
									arg=arg.replace("<user>",user)
									arg=arg.replace("<password>",password)
									arg=arg.replace("<domain>",domain)
									arg=arg.replace("<user_sid>",user_sid)
								final_args.append(arg)
							if ((method_name)):
								func = getattr(self.commandObj,method_name)
								print "Invoking !!! with instance -->"+str(self)
								is_interactive=entries.get('interactive')
								self.commandObj.print_Log_info("\n\n\n STARTING EXPLOITS  FOR PROJECT ID --> " +str(self.project_id)+" with object instance --"+str(self))
								print "Logged"
								#<<<<<<< HEAD
								try:
									if((is_interactive !=None ) and (is_interactive =="1")):
										print "Launching General interactive mode !!-->Method->"+method_name
									
										func(final_args,True)
									else:
										print "Launching without interactive mode !!--->"+method_name
										grep= entries.get("grep",None)
										if grep != None:
												grep_commands=entries.get("grep_commands")
												func(final_args,grep_commands)
										else:
												func(final_args)	
										#func(final_args)
									self.IPexploit.TestCaseStatus('true',host,port,int(self.project_id),int(current_record_id))
								except Exception ,ees:
									print "EXception occured while executing test case :"+str(ees)
								
					
						self.IPexploit.UpdateStatus('complete',host,port,int(self.project_id),int(current_record_id))
						
						if parent_obj.active_processes > 0:
							parent_obj.active_processes=parent_obj.active_processes -1
					except Exception, ee:
							self.IPexploit.UpdateStatus('error-complete',host,port,int(self.project_id),int(current_record_id))
							print "EXception while executing exploits !: " +str(ee)
				
				
		
	def launchExploits(self,concurrent=False,record_list=[],resume=False,params_key="Default"):
		"""
			Objective :
			This mehod will actually invoke the file auto_commands.py with appropriate commands
			and method in order for the method to launch vulnerability scanning with external
			scripts .This method does the same with threading disabled.
		"""
		try:
			self.method_id="LaunchExploits()"
			self.print_Log("Started method LaunchExploits()")
			if concurrent==False:
				self.generate_report=True
			if concurrent==False:
				if resume==False:
					IPexploits_data=self.IPexploit.getIpExploits(self.project_id)
				else:
					IPexploits_data=self.IPexploit.getIpExploits(self.project_id,None,True)
					print "Now sleeping for 20 sec !!"
					time.sleep(20)
			else:
				IPexploits_data=self.IPexploit.getIpExploit(self.project_id,record_list)
				if((IPexploits_data !=-1 ) and (IPexploits_data is not None)):
					try:
						for exploit in IPexploits_data:
								current_record_id=exploit[0]
								service=str(exploit[4])
								host=exploit[2]
								port=exploit[3]
								self.IPexploit.UpdateStatus('processing',host,port,int(self.project_id),int(current_record_id))
					except Exception ,exce:
						print "Exception occured while updating the record status :"+str(exce)
					
			
			if((IPexploits_data !=-1 ) and (IPexploits_data is not None )):
				
				for exploit in IPexploits_data:
					try:
						current_record_id=exploit[0]
						service=str(exploit[4])
						host=exploit[2]
						port=exploit[3]
						self.print_Log("Service,Host,port  is -->"+str(service)+"  " +str(host)+"  "+str(port))
						entry=self.commandsJson.get(service)
						print "read"
						meta=entry.get('Commands') #check weather the obtained service is custom or not.If yes then the following code will throw exception and needs to be modified a little
						self.IPexploit.UpdateStatus('processing',host,port,int(self.project_id),int(current_record_id))
						profile_service=self.profileJson.get(service)
						id_list=profile_service.get('Test_cases')
						execute=True
						params_config_file=os.path.join(self.folder_dir,"Project_params.json")
						with open(params_config_file,"rb") as f:
							all_params_data = json.loads(f.read()) #--> all service types in master json 
						param_data=all_params_data.get(params_key,None)
						user=''
						password=''
						domain=''
						user_sid=''
						if param_data != None:
							user=param_data.get("User","")
							password=param_data.get("Password","")
							domain=param_data.get("Domain","")
							user_sid=param_data.get("User_sid","")

						for entries in meta :
							execute=entries.get("execute",True)
							print "For command : "+str(entries.get("id")) +" execute is : "+str(execute)
							if entries.get('id') in id_list and execute ==True:
								method_name=entries.get('method')
								args=entries.get('args')
								self.commandObj.method_id=method_name
								self.commandObj.command_id=entries.get('id')
								self.commandObj.current_record_id=current_record_id
								self.commandObj.current_host=host
								self.commandObj.current_port=port
								self.commandObj.data_path=self.data_path
								final_args=[]
								for arg in args:
									if isinstance(arg, basestring):
										arg=arg.replace("<host>",host)
										arg=arg.replace("<port>",port)
										arg=arg.replace("<user>",user)
										arg=arg.replace("<password>",password)
										arg=arg.replace("<domain>",domain)
										arg=arg.replace("<user_sid>",user_sid)
									final_args.append(arg)
								if ((method_name)):
									func = getattr(self.commandObj,method_name)
									print "Invoking !!!"
									is_interactive=entries.get('interactive')
									self.commandObj.print_Log_info("\n\n\n STARTING EXPLOITS  FOR PROJECT ID --> " +str(self.project_id))
									print "Logged"
									try:
									
										if((is_interactive !=None ) and (is_interactive =="1")):
											print "Launching General interactive mode !!-->Method->"+method_name
											func(final_args,True)
										else:
											print "Launching without interactive mode !!--->"+method_name
											grep= entries.get("grep",None)
											if grep != None:
												grep_commands=entries.get("grep_commands")
												func(final_args,grep_commands)
											else:
												func(final_args)
										self.IPexploit.TestCaseStatus('true',host,port,int(self.project_id),int(current_record_id))
									
									except Exception ,ee:
										print "Exception occured while executing exploits for command id :"+str(entries.get("id"))
										

						self.IPexploit.UpdateStatus('complete',host,port,int(self.project_id),int(current_record_id))
					except Exception ,exccc:
						print "Exception ---> "+str(exccc)
						self.IPexploit.UpdateStatus('error-complete',host,port,int(self.project_id),int(current_record_id))
				
				


			
				
		except Exception ,ee:
			self.print_Error("Inside exception of launch exoloits :"+str(ee))

	


