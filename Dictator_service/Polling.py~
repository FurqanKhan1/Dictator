"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to provide the pololing details to the webservice which can inturn
pass the details to the application that might have requested it.
This module basically returns the intermediate status of records with respect to both discovery and vulnerability scanning.
"""

import IPtable
import IPexploits
import os
import json

class PollingExploits:
	"""
	Objective :
	The class PollingExploits provides the intermediate results with respect to vulnerability scanning
	"""

	def __init__(self,project_id):
		"""
		Objective :
		This is the constructor and would initialize the various class variables 
		"""

		self.project_id=project_id
		self.IPexploit=IPexploits.IPexploits()
		self.commandsJson=self.setCommandsJson()
		

	def setCommandsJson(self):
		"""
		Objective :
		This method will load the master json file in an instance variabl;e and the utility being that
		it would be used for generating the data that is returned to the application
		"""

		folder_dir=os.path.dirname(os.path.realpath(__file__))
		all_config_file=os.path.join(folder_dir,"all_commands.json")
		with open(all_config_file,"rb") as f:
			    jsonpredata = json.loads(f.read()) #--> all service types in master json 
		return jsonpredata
	



	def getCommands(self,k,host,port):
		"""
		Objective :
		The method would parse the masterjson and would extract various commands based upon the service key
 		and place the commands in the list of dictionaries to be returned .
		"""

		try:
			service_val=self.commandsJson.get(k)
			all_commands=service_val.get('Commands')
			arg_list=[]
			for arg in all_commands :
				if isinstance(arg, basestring):
						arg=arg.replace("<host>",host)
						arg=arg.replace("<port>",port)
				arg_list.append(arg)
			return arg_list

		except Exception, ee:
			print("Exception Polling - getCommands()->"+str(ee))
			return -1
	

	def getConfiguration(self):
		"""
		Objective :
		The method would get the configuration for the current project id
		"""

		try:
			print " Launching Polling for getconfiguration ...."
			return_set={}
			id_=int(self.project_id)
			return_val=self.IPexploit.getIpExploitPolling(self.project_id,'false')
			IPexploits_and_commands=[]
			list_row=[]
			config_list=[]
			tab_draw=[]
			
			if return_val["status"]=="success":
				IPexploits=return_val["value"]
				for row in IPexploits:
		   			commands=self.getCommands(row[4],row[2],row[3])#x.append([str(row[0]),str(row[1])])
					list_row.append((row[0],row[1],row[2],row[3],row[4],row[5],commands))
						
			return_val=self.IPexploit.getUnknownServicesOnlyPolling(self.project_id,'false')
			if return_val["status"]=="success":
				all_exploits=return_val["value"]
				for row in all_exploits: #row is of type tuple whic is read only
						empty_dict={}
						empty_dict["status"]="empty"
						list_row.append((row[0],row[1],row[2],row[3],row[4],row[5],empty_dict))
			if (len(list_row) >0):
				return_set["status"]="reconfig"
				return_set["value"]=list_row
			else:
				return_set["status"]=return_val["status"]
				return_set["value"]=return_val["value"]
			return return_set

		except Exception ,ee:
			print "Inside polling exception :"+str(ee)
			return_set["status"]="failure"
			return_set["value"]=str(ee)
			return return_set


	def UpdateStatus(self,record_list):
		"""
		Objective :
		The method would update the status of the records which are read by the application as read and
		would return success if update is successful and failure if update fails
		"""

		try:
			return_value={}
			ret_val=self.IPexploit.UpdatePollingStatus(self.project_id,record_list)
			if ret_val==1:
				return_value["status"]="success"
				return_value["value"]="Data updated"
			else:
				return_value["status"]="failure"
				return_value["value"]="Not updated"
			return return_value
		except Exception, ee:
			print("Exception Polling Update status- getCommands()->"+str(ee))
			return_value["status"]="failure"
			return_value["value"]=str(ee)
			return return_value


	def ExploitPoll(self):
		"""
		Objective :
		The method would actually poll the IPexpoloits table and would return data when ever new data is
		inserted and when there is not new data then it returns status as no data
		"""

		try:
			print " Launching Polling for getconfiguration ...."
			return_set={}
			id_=int(self.project_id)
			list_row=[]
			return_val=self.IPexploit.getIpExploitPollingResult(self.project_id,'false')
			if return_val["status"]=="success":
				IPexploits=return_val["value"]
				for row in IPexploits:
		   			commands=row[6]#self.getCommands(row[4],row[2],row[3])#x.append([str(row[0]),str(row[1])])
					list_row.append((row[0],row[1],row[2],row[3],row[4],row[5],commands))
			if (len(list_row) >0):
				return_set["status"]="success"
				return_set["value"]=list_row
			else:
				return_set["status"]=return_val["status"]
				return_set["value"]=return_val["value"]
			return return_set

		except Exception ,ee:
			ret_status={}
			ret_status["status"]="failure"
			ret_status["value"]=str(ee)
			return ret_status
	
	def UpdateStatusExploit(self,record_list,all_=False):
		"""
		Objective :
		The method would update exploit status and would set it as read when the records are read
		"""

		try:
			return_value={}
			if all_==False:
				ret_val=self.IPexploit.UpdatePollingStatusExploit(self.project_id,record_list)
			else:
				ret_val=self.IPexploit.UpdatePollingStatusExploit(self.project_id,'',True,'false')
			if ret_val==1:
				return_value["status"]="success"
				return_value["value"]="Data updated"
			else:
				return_value["status"]="failure"
				return_value["value"]="Not updated"
			return return_value
		except Exception, ee:
			print("Exception Polling Update status- getCommands()->"+str(ee))
			return_value["status"]="failure"
			return_value["value"]=str(ee)
			return return_value

	def UpdateStatusInit(self):
		"""
		Objective :
		The method would update exploit status and would set it as read when the records are read
		"""

		try:
			return_value={}
			ret_val=self.IPexploit.UpdatePollingStatusinit(self.project_id,'',True,'false')
			if ret_val==1:
				return_value["status"]="success"
				return_value["value"]="Data updated"
			else:
				return_value["status"]="failure"
				return_value["value"]="Not updated"
			return return_value
		except Exception, ee:
			print("Exception Polling Update status->"+str(ee))
			return_value["status"]="failure"
			return_value["value"]=str(ee)
			return return_value

			
		




































