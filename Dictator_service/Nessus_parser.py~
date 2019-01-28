"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to parse the nessus XML report.
It works in two modes :(1) Store (2) Retun

1) When this code is invoked wirh store flag as set ,then it will go ahead and parse the nessus report as a 
list  and finally will store /bulk insert all the rows of the list in the backend database table.This table would be later on used for report integration with mannual test cases

2) When invoked with return flag as set then this code will parse the nessus report and will return a list of dictionaries.This list of dictionary would be later on used and traversed to do cve to exploit mapping and make the final report in (html,xml,json or csv format)
"""
from libnessus.parser import NessusParser
from libnessus.plugins.backendpluginFactory import BackendPluginFactory
import sys
import Report_Generator
import json

class Nessus_Parser:
	"""
	Objective :
	The following class Nessus_Parser is to parse the nessus xml report as mentioned above 
	"""

	def __init__(self):
		"""
		Objective :
		This method is the constructor of the class and initializes instance variables 
		"""

		self.rg=Report_Generator.ReportGenerator()

	def demo_print(self,nessus_obj_list):
		"""
		Objective :
		This method is used to print the parsed report on the console 
		"""

		docu = {}
		for i in nessus_obj_list.hosts:
			
				docu['scantime'] = nessus_obj_list.endtime

				docu['host_ip'] = i.ip
				docu['host_name'] = i.name
				docu['host-fqdn'] = i.get_host_property('host-fqdn')
				docu['operating-system'] = i.get_host_property('operating-system')
				docu['system-type'] = i.get_host_property('system-type')
				print "--------------------------------------------------------------------------------------"
				print "Host : "+i.ip+"	Host Name : "+i.name +"	OS : "+i.get_host_property('operating-system')#+"	System Type : "+i.get_host_property('system-type')
				print "---------------------------------------------------------------------------------------"
				 
				for v in i.get_report_items:
					#print str(v.get_vuln_info)
					print "---------------------------------------------------------"
					print str("Plugin id :"+str(v.plugin_id))
					print str("Plugin name : "+str(v.plugin_name))
					print "Sevirity : "+str(v.severity)
					#if v.plugin_id=="54615":
					print str("Service name :"+str(v.service))		

					#print str("Service name :"+str(v.svc_name))
					print str("Protocol :"+str(v.protocol))
					print str("Port : "+str(v.port))
					print "Synopsis :"+str(v.synopsis)+"\n"
					print "Description : "+str(v.description)+"\n"
				
					print "Risk vectors :"+str(v.get_vuln_risk)+"\n"
					
					print "External references :"+str(v.get_vuln_xref)+"\n"
					print "Solution :"+str(v.solution)
					print "---------------------------------------------------------"

					print "\n\n"
		
	def return_results(self,nessus_obj_list,project_id,action="store"):
		"""
		Objective :
		This method is used to traverse through the parsed report report and either save the parsed report
 		in the database table or return the parsed report as a list of dictionaries 
		"""

		ret_list=[]
		return_value={}
		Bulk_list=[]
		Bulk_list_details=[]
		obj=Report_Generator.ReportGenerator()
		try:
			for i in nessus_obj_list.hosts:	
					#print "11-->"+str(i.ip)
				
					docu={}
					ret_dict={}
					ret_host_info={}
					ret_dict["host"]=i.ip
					docu['scantime'] = str(nessus_obj_list.endtime)
					docu['host_ip'] = i.ip
					docu['host_name'] = i.name
					docu['host-fqdn'] = i.get_host_property('host-fqdn')
					docu['operating-system'] = i.get_host_property('operating-system')
					docu['os'] = i.get_host_property('operating-system')
					docu['system-type'] = i.get_host_property('system-type')
					ret_dict["host_info"]=docu
					ret_dict["host"]=i.ip
					ret_dict["status"]="nessus_only"
					report_item_list=[]
					Bulk_list.append((int(project_id),i.ip,'nessus'))
					"""insert into report_details 									(Pid,Host,Port,Service,host_name,os,system_type,plugin_id,plugin_name,severity,protocol,\
synopsis,description,ref,risk_vec,solution,Source"""

					for v in i.get_report_items:
						#print str(v.service)
						report_prop={}
						report_prop["plugin_id"]=str(v.plugin_id)
						report_prop["plugin_name"]=str(v.plugin_name)
						report_prop["sevirity"]=str(v.severity)
						report_prop["service"]=str(v.service)
						report_prop["port"]=str(v.port)
						report_prop["protocol"]=str(v.protocol)
						report_prop["synopsis"]=str(v.synopsis)
						report_prop["description"]=str(v.description)
						report_prop["ref"]=v.get_vuln_xref
						report_prop["risk_vec"]=v.get_vuln_risk
						report_prop["solution"]=str(v.solution)
						report_prop["os"]=docu["os"]
						report_prop["system-type"]=docu['system-type']
						report_prop["host_name"]=docu['host_name']
						report_prop["exploits"]=''
						if report_prop["ref"] and len (report_prop["ref"]) > 0:
							report_prop["exploits"]=self.rg.getExploits(report_prop["ref"],False,"outside")
						report_item_list.append(report_prop)
						
						#print len(report_item_list)
						Bulk_list_details.append((int(project_id),i.ip,v.port,v.service,i.name,docu['operating-system'],docu['system-type'],v.plugin_id,v.plugin_name,str(v.severity),v.protocol,v.synopsis,v.description,json.dumps(report_prop["ref"]),json.dumps(report_prop["risk_vec"]),str(report_prop["solution"]),'nessus'))

					ret_dict["value"]=report_item_list
					ret_list.append(ret_dict)
			
			
			if len(ret_list) > 0:
					if action=="store":
						print "action is store"
						resp=obj.Store_parsed_report(Bulk_list,Bulk_list_details,'','nessus')
						return resp
					
					elif action=="return":
						print "action is return "
						return_value["status"]="success"
						return_value["value"]=ret_list
						return return_value
					
			else:
					return_value["status"]="empty"
					return_value["value"]="0"
					return return_value
		except Exception ,ex:
			print "Exception -->:"+str(ex)
			return_value["status"]="failure"
			return_value["value"]=str(ex)
			return return_value

			
	def parse(self,file_=None,p_id=None,mode=None,action="store"):
		"""
		Objective :
		This method is actually responsible for parsing the report from xml format into a class
		object list where each object/instance would represent a nessus report item /host.
		It would further invoke return_results method passing the nessus object list to it
		"""

		print "In side parse :"
		try:
			try:
				#print "arg is :"+str(sys.argv[0])
				nessus_obj_list = NessusParser.parse_fromfile(file_)
			except Exception ,eee:
				print("file cannot be imported : %s" % file)
				print "Exception 1 :"+str(eee)
				return #continue
			docu = {}
			if mode=="demo":
				self.demo_print(nessus_obj_list)
			else:
				if p_id !=None:
					
					return_val=self.return_results(nessus_obj_list,int(p_id),action)
				else:
					return_val=self.return_results(nessus_obj_list,0,action)
				return return_val
				#print return_val		
		except Exception ,ee:
			print "Exception 2:"+str(ee)
			ret_val={}
			ret_val["status"]="failure"
			ret_val["value"]=str(ee)
			return ret_val


#obj=Nessus_Parser()	
#print str(obj.parse('m.nessus','0','',"return"))
