"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to pass on the data to the database table.
It acts as a model class for the table report_details and report_mapping.
This class will take final data from nessus and qualys parser (if mode =store) and will actually store
the bulk list (data) in the database table
"""
import MySQLdb
import Auto_logger
import json
import os
class ReportGenerator:
	"""
	Objective :
	The class would aid in report generation by putting data and obtaining data from the backend 
	database tables.

	Note:
	This class actually aids in report generation of mannual vulnerability scanning merged with
	qualys and nessus findings.
	Thus the objective is to obtained 1 integrated report that would combine all the findings
	of mannual + nessus + qualys and would also have cve-exploit mapping.
	Thus this module would always depend upon the project id of the mannual vulnerability scanning.
	The details obtained by parsing the nessus /qualys report would also have the mannual project 
	id added to them before being saved in the database table.
	"""


	def __init__(self):
		"""
		Objective :
		The method is the constructor of the class
		"""

		self.con=None
		self.cursor=None
		

	def init_connection(self):
		"""
		Objective :
		The method will initialize the database connection
		"""
		try:
			self.method_id="Init_connection()"
			self.folder_dir=os.path.dirname(os.path.realpath(__file__))
			user=''
			password=''
			try:
				db_file=os.path.join(self.folder_dir,"db_file.txt")
				with open(db_file ,"r+") as db:	
					user_pass=db.read()
					user_pass=user_pass.replace("\n","").replace("\r\n","").replace("\r","")
					user_pass=user_pass.split(":")
					user=user_pass[0]
					password=user_pass[1]
					
			except Exception ,eex:
				print "EXception ! " +str(eex)

			self.con=MySQLdb.connect("localhost",user,password,"nmapscan")
			self.cursor = self.con.cursor()
		except Exception,ee:
			print("EXception in connection-->"+str(ee))

	def close_connection(self):
		"""
		Objective :
		The method will close the database connection
		"""

		try:
			self.method_id="Close_connection()"
			self.con.close()
		except Exception, ee:
			print("EXception in connection-->"+str(ee))



	def delete_if_exists(self,Bulk_list_mapping):
		"""
		Objective :
		The current arcitecture suggests taht suppose a nessus or qualys report for a scan /project
		is splitted into multiple small segemants each having few hosts and discovered services,
		then each shall have the same project id as that of mannual vul scanning report.
		So the idea adapted here to avoid redundant records in teh database table is that
		a project_id + host + source-(nessus/qualys) must remain unique in the database table report_mpping
		.No duplicates are allowed there.AS we assume that if we are breaking the report into small
 		segements each segement may contain different hosts.
		Thus for each host in teh Bulk list it is chacked weather the combination already exists in the 
		mapping table.If it does then the old records are deleted forst before inserting the new ones.
		THis method would do that task
		"""

		try:
			for rec in Bulk_list_mapping:
				#print "Reached -->"+str(rec)
				self.cursor.execute("select count(*) from report_mapping where Pid =%s and Host=%s and Source=%s",(int(rec[0]),rec[1],rec[2]))
				result=self.cursor.fetchone();
				if (result[0]>=1):
					print "Record exists ,Now Deleting :"+str(rec)
					self.cursor.execute("delete from report_mapping where Pid =%s and Host=%s and Source=%s",(int(rec[0]),rec[1],rec[2])) #should cascade delete from report_details table too
			print "Now inserting bulk1"
			self.cursor.executemany("insert into report_mapping (Pid,Host,Source) values (%s,%s,%s)",Bulk_list_mapping)
			return 1
				
		
		except Exception ,ee:
			print "Exception while deleting :"+str(ee)
			return str(ee)

	def Store_parsed_report(self,Bulk_list_mapping,Bulk_list_nessus,Bulk_list_qualys,source=None):
		"""
		Objective :
		The method will store the final parsed report as a bulk list in the database table.
		"""

		try:
			#all_exploits=[]
			return_resp={}
			return_resp["status"]="success"
			return_resp["value"]="Report inserted and parsed"

			self.init_connection()
			
			if source =='nessus':
				resp=self.delete_if_exists(Bulk_list_mapping);
				if resp ==1:
					print "Now inserting bulk2"
					self.cursor.executemany("insert into report_details (Pid,Host,Port,Service,host_name,os,system_type,plugin_id,plugin_name,severity,protocol,\
synopsis,description,ref,risk_vec,solution,Source) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",Bulk_list_nessus)
					self.con.commit()
					self.close_connection()
				else:
					return_resp["status"]="failure"
					return_resp["value"]=str(resp)
			
			elif source=='qualys':
				resp=self.delete_if_exists(Bulk_list_mapping);
				if resp ==1:
					print "Now inserting bulk2"
					self.cursor.executemany("insert into report_details (Pid,Host,Port,severity,protocol,\
title,cvss,ref,result,dignosis,solution,Source,sub_type) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",Bulk_list_qualys)
					self.con.commit()
					self.close_connection()
				else:
					return_resp["status"]="failure"
					return_resp["value"]=str(resp)
			
			elif source=='both':
				resp=self.delete_if_exists(Bulk_list_mapping);
				if resp == 1:
					self.cursor.executemany("insert into report_details (Pid,Host,Port,Service,host_name,os,system_type,plugin_id,plugin_name,severity,protocol,\
synopsis,description,ref,risk_vec,solution,Source) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",Bulk_list_nessus)
					self.cursor.executemany("insert into report_details (Pid,Host,Port,severity,protocol,\
title,cvss,ref,result,dignosis,solution,Source,sub_type) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",Bulk_list_qualys)
					self.con.commit()
					self.close_connection()
				else:
					return_resp["status"]="failure"
					return_resp["value"]=str(resp)
			
			
			return return_resp

		except Exception ,ee:
			print "Exception closing !!!"+str(ee)
			self.con.rollback()
			self.close_connection()
			return_resp["status"]="failure"
			return_resp["value"]=str(ee)
			
			return return_resp


	def unfold(self,v,prepend):
		"""
		Objective :
		The method combine the CVE /BID in propar format as recongnised
		by qualys and metasploit repository to help in the lookup process.
		For example CVE:2000-1922 will be transformed to CVE-2000-1922 .
		"""

		exploit_ids=[]
		try:
			if isinstance(v,list):
				#print "1"
				for val in v:
					#print "2"
					exploit_ids.append(str(prepend)+str(val))
			elif isinstance(v,basestring):
					#print "Exploit id is base string :"+str(v)
					exploit_ids.append(str(prepend)+str(v))

			return exploit_ids
		except Exception ,ee:
			print "Exception @@ "+str(ee)
			return exploit_ids
		
	def getExploits(self,ref,return_val=False,action="internal"):
		"""
		Objective :
		The method will read the metasploit and qualys repository and would obtain 
		the exploits based upon CVE's, BID's Osvdb id's and etc
		"""

		try:
			
			if action=="outside":
				self.init_connection()
				print "Connection initialized"
			is_cve=False
			exploit_modules=[]
			if len(ref) >0:
				exploit_ids=[]
				if isinstance(ref,dict):
					print "Dict instance "					
					for k,v in ref.iteritems():
						if k=='cve':
							exploit_ids.extend(self.unfold(v,''))
							is_cve=True
						elif k=='bid':
							exploit_ids.extend(self.unfold(v,'BID-'))
						elif k=='osvdb':
							exploit_ids.extend(self.unfold(v,'OSVDB-'))						
						elif k=='edb-id':
							exploit_ids.extend(self.unfold(v,'EDB-'))	
				elif isinstance(ref,list):
					print "List instance"
					is_cve=True
					exploit_ids.extend(self.unfold(ref,''))					
				elif isinstance(ref,basestring):
					print "String obtained--"+str(ref)
				if return_val==True:
					if action=="outside":
						self.close_connection()

					return exploit_ids
				if len(exploit_ids) >0:
					#print "\n\n"
					#print "---------------------------------------------"
					#print "Obtained exploit id's are :"+str(exploit_ids)
					#print "---------------------------------------------"
					#print "\n\n"
					format_strings=','.join(['%s'] * len(exploit_ids))
					sql_query="select distinct fullname from exploit_mapping_metasploit where name in (%s)"% format_strings
					#print "Sql query is :"+sql_query
					args=exploit_ids
					self.cursor.execute(sql_query,args)
					exploits=self.cursor.fetchall()
					if(len(exploits) >0):
						#print "\n\nObtained exploits from Metasploit db !"
						
						for exploit in exploits:
							#print "Exploit ---> "+str(exploit[0])
							exploit_modules.append(exploit[0])
						
					#else:
						#print "\nNo Metasploit exploits obtained for this data "
					if (is_cve):
						sql_query="select distinct concat(Exploit_desc,concat(' URL-',Exploit_link)) as d from exploit_cve_mapping where Exploit_ref in (%s) and EXPLOIT_SRC_NAME <> 'Metasploit'"% format_strings
						args=exploit_ids
						self.cursor.execute(sql_query,args)
						exploits=self.cursor.fetchall()
						if(len(exploits) >0):
							#print "\n\nObtained exploits from Qualys db !"
						
							for exploit in exploits:
								#print "Exploit ---> "+str(exploit[0])
								exploit_modules.append(exploit[0])
							
						#else:
							#print "\nNo Other exploits obtained for this data "
					if action=="outside":
						self.close_connection()

					return exploit_modules

				else:
					if action=="outside":
						self.close_connection()

					return exploit_modules
						
			else:
				if action=="outside":
						self.close_connection()

				return exploit_modules

		except Exception ,ee:
			if action=="outside":
						self.close_connection()
			print "Exception :"+str(ee)
			return exploit_modules
	


	def get_missed_mannual_ports(self,project_id,host,source):
		"""
		Objective :
		There could be occassions that for a particular host there might be some ports /services/findings
		that could be missed by mannual n-map scanning but both nessus and qualys or either of nessus or
 		qualys woulod have discovered them.This method searches those findings from database table.
		"""

		try:
			self.init_connection()
			item_list=[]
			ret_resp={}

			if source=='nessus':
					self.cursor.execute("select IFnull(Service,'') as Service,IFnull(host_name,'') as host_name,IFnull(os,'') as os,IFnull(system_type,'') as system_type,IFnull(plugin_id,'') as plugin_id,IFnull(plugin_name,'')as plugin_name,IFnull(severity,'') as severity,IFnull(protocol,'') as protocol\
,IFnull(synopsis,'') as synopsis,IFnull(description,'') as description,IFnull(ref,'[]') as ref,IFnull(risk_vec,'[]') as risk_vec,IFnull(solution,'') as solution,IFnull(Port,'') as Port from report_details where Pid=%s and Host=%s and Source='nessus' and Port not in (select distinct Port from IPexploits where Pid = %s and Host= %s union select distinct Port from report_details where Pid=%s and Host=%s and Source='qualys')",(int(project_id),host,int(project_id),host,int(project_id),host))
					results=self.cursor.fetchall()
					if len(results) > 0:
						for v in results :
							report_prop={}
							report_prop["plugin_id"]=str(v[4])
							report_prop["plugin_name"]=str(v[5])
							report_prop["sevirity"]=str(v[6])
							report_prop["service"]=str(v[0])
							report_prop["host_name"]=str(v[1])
							report_prop["os"]=str(v[2])
							report_prop["system-type"]=str(v[3])
							report_prop["protocol"]=str(v[7])
							report_prop["synopsis"]=str(v[8])
							report_prop["description"]=str(v[9])
							report_prop["ref"]=json.loads(str(v[10]))
							report_prop["exploits"]=self.getExploits(report_prop["ref"])
							report_prop["risk_vec"]=json.loads(str(v[11]))
							report_prop["solution"]=str(v[12])
							report_prop["port"]=str(v[13])
							#print "Found Port --> "+str(v[13])
							#print "Found plugin_id" +str(v[4])
							item_list.append(report_prop)
						ret_resp["status"]="success"
						ret_resp["value"]=item_list
					else:
						ret_resp["status"]="empty"
						ret_resp["value"]="0"
			elif(source =="qualys"):
					self.cursor.execute("select severity,protocol,\
IFnull(title,'') as title,IFnull(cvss,'[]') as cvss,IFnull(ref,'[]') as ref,IFnull(result,'') as result,IFnull(dignosis,'') as dignosis,IFnull(solution,'') as solution,sub_type,IFnull(Port,'') as Port from report_details where Pid=%s and Host=%s and Source='qualys' and Port not in (select distinct Port from IPexploits where Pid = %s and Host= %s union select distinct Port from report_details where Pid=%s and Host=%s and Source='nessus')",(int(project_id),host,int(project_id),host,int(project_id),host))
					results=self.cursor.fetchall()
					if len(results)>0:
						for v in results :
							report_prop={}
							report_prop["sevirity"]=str(v[0])
							report_prop["title"]=str(v[2])
							report_prop["cvss"]=json.loads(str(v[3]))
							report_prop["protocol"]=str(v[1])
							report_prop["ref"]=json.loads(str(v[4]))
							report_prop["exploits"]=self.getExploits(report_prop["ref"])
							report_prop["result"]=str(v[5])
							report_prop["dignosis"]=str(v[6])
							report_prop["solution"]=str(v[7])
							report_prop["sub_type"]=str(v[8])
							report_prop["port"]=str(v[9])
							#print "Qualys port found -->"+str(v[9])
							#print "Qualys Title :"+str(v[2])
							item_list.append(report_prop)
						ret_resp["status"]="success"
						ret_resp["value"]=item_list	
					else:
						ret_resp["status"]="empty"
						ret_resp["value"]="0"

			elif(source=="both"):
					self.cursor.execute("select Service,host_name,os,system_type,plugin_id,plugin_name,severity,protocol,\
IFnull(synopsis,'') as synopsis,IFnull(description,'') as description,IFnull(ref,'[]') as ref ,IFnull(risk_vec,'[]') as risk_vec,IFnull(solution,'') as solution,IFnull(Port,'') as Port from report_details where Pid=%s and Host=%s  and Source='nessus' and Port in (select distinct T.Port as Port from ((select distinct R1.Port from report_details R1 join report_details R2 on R1.Port=R2.Port and R1.Pid=%s and R1.Host=%s and R1.Source='qualys' and R2.Pid=%s and R2.Host=%s and R2.Source='nessus') T left join IPexploits on IPexploits.Port=T.Port and IPexploits.Pid=%s and IPexploits.Host=%s) where IPexploits.Port is null)",(int(project_id),host,int(project_id),host,int(project_id),host,int(project_id),host))
					results=self.cursor.fetchall()
					if len(results) > 0:
						for v in results :
							#print "\n\nBoth Port --> "+str(v[13])
							#print "Found plugin_id" +str(v[4])+"\n\n"
							report_prop={}
							report_prop["plugin_id"]=str(v[4])
							report_prop["plugin_name"]=str(v[5])
							report_prop["sevirity"]=str(v[6])
							report_prop["service"]=str(v[0])
							report_prop["host_name"]=str(v[1])
							report_prop["os"]=str(v[2])
							report_prop["system-type"]=str(v[3])
							report_prop["protocol"]=str(v[7])
							report_prop["synopsis"]=str(v[8])
							report_prop["description"]=str(v[9])
							report_prop["ref"]=json.loads(str(v[10]))
							report_prop["exploits"]=self.getExploits(report_prop["ref"])
							report_prop["risk_vec"]=json.loads(str(v[11]))
							report_prop["solution"]=str(v[12])
							report_prop["port"]=str(v[13])
							#print "Both Port --> "+str(v[13])
							#print "Found plugin_id" +str(v[4])
							item_list.append(report_prop)
						ret_resp["status"]="success"
						ret_resp["value"]=item_list
					else:
						ret_resp["status"]="empty"
						ret_resp["value"]="0"

				
				
			else:
				ret_resp["status"]="failure"
				ret_resp["value"]="Invalid choice"
			self.close_connection()
			return ret_resp

		except Exception ,ee:
			print "Exception exc :"+str(ee)
			self.close_connection()
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ee)
			return ret_resp




	def get_missed_hosts(self,project_id,source):
		"""
		Objective :
		There could be occassions that for a particular network there might be some hosts that could be
		missed by mannual n-map scanning but both nessus and qualys or either of nessus or
 		qualys woulod have discovered them.This method searches those findings from database table.
		"""

		try:
			self.init_connection()
			item_list=[]
			ret_resp={}

			if source=='nessus':
					self.cursor.execute("select distinct Host from report_details where Pid=%s and Source='nessus' and Host not in (select distinct Host from IPexploits where Pid = %s union select distinct Host from report_details where Pid=%s and Source='qualys')",(int(project_id),int(project_id),int(project_id)))
					results=self.cursor.fetchall()
					if len(results) > 0:
						for v in results :
							#print "Nessus only :"+str(v[0])
							item_list.append(str(v[0]))
						ret_resp["status"]="success"
						ret_resp["value"]=item_list
					else:
						ret_resp["status"]="empty"
						ret_resp["value"]="0"
			elif(source =="qualys"):
					self.cursor.execute("select distinct Host from report_details where Pid=%s and Source='qualys' and Host not in (select distinct Host from IPexploits where Pid = %s  union select distinct Host from report_details where Pid=%s and Source='nessus')",(int(project_id),int(project_id),int(project_id)))
					results=self.cursor.fetchall()
					if len(results) >0:
						for v in results :
							#print "Qualys only :"+str(v[0])
							item_list.append(str(v[0]))
						ret_resp["status"]="success"
						ret_resp["value"]=item_list	
					else:
						ret_resp["status"]="empty"
						ret_resp["value"]="0"
			elif(source=="both"):
					self.cursor.execute("select distinct Host from report_details where Pid=%s and Host in (select distinct T.Host as Host from ((select distinct R1.Host from report_details R1 join report_details R2 on R1.Host=R2.Host and R1.Pid=%s and R1.Source='qualys' and R2.Pid=%s and R2.Source='nessus') T left join IPexploits on IPexploits.Host=T.Host and IPexploits.Pid=%s) where IPexploits.Host is null)",(int(project_id),int(project_id),int(project_id),int(project_id)))
					results=self.cursor.fetchall()
					if len(results) > 0:
						for v in results :
							#print "Host Both Port --> "+str(v[0])
							item_list.append(str(v[0]))
						ret_resp["status"]="success"
						ret_resp["value"]=item_list
					else:
						ret_resp["status"]="empty"
						ret_resp["value"]="0"
			else:
				ret_resp["status"]="failure"
				ret_resp["value"]="Invalid choice"
			self.close_connection()
			return ret_resp

		except Exception ,ee:
			print "Exception exc :"+str(ee)
			self.close_connection()
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ee)
			return ret_resp

	def get_details(self,project_id,host,port,source):
		"""
		Objective :
		This method would actually fetch all the mannual findings for a host (all services of hosts)
		combined with common services for the same host discovered by both nessus and qualys
		THus this is an integration of common(mannual + qualys +nessus) + (mannual -(qualys+nessus))
		"""

		try:
			self.init_connection()
			item_list=[]
			ret_resp={}
			
			self.cursor.execute("select count(*) from report_details where Pid=%s and Host=%s and Port=%s and Source=%s",(int(project_id),host,port,source))
			count=self.cursor.fetchone()
			#print "count is :"+str(count)
			if count[0] > 0:
				if source=='nessus':
					self.cursor.execute("select Service,host_name,os,system_type,plugin_id,plugin_name,severity,protocol,\
synopsis,description,ref,risk_vec,solution,Port from report_details where Pid=%s and Host=%s and Port=%s and Source=%s",(int(project_id),host,port,source))
					results=self.cursor.fetchall()
					for v in results :
						report_prop={}
						report_prop["plugin_id"]=str(v[4])
						report_prop["plugin_name"]=str(v[5])
						report_prop["sevirity"]=str(v[6])
						report_prop["service"]=str(v[0])
						report_prop["host_name"]=str(v[1])
						report_prop["os"]=str(v[2])
						report_prop["system-type"]=str(v[3])
						report_prop["protocol"]=str(v[7])
						report_prop["synopsis"]=str(v[8])
						report_prop["description"]=str(v[9])
						report_prop["ref"]=json.loads(str(v[10]))
						report_prop["exploits"]=self.getExploits(report_prop["ref"])
						report_prop["risk_vec"]=json.loads(str(v[11]))
						report_prop["solution"]=str(v[12])
						report_prop["port"]=str(v[13])
						item_list.append(report_prop)

					ret_resp["status"]="success"
					ret_resp["value"]=item_list
					
	
				elif source =='qualys':
					self.cursor.execute("select severity,protocol,\
title,cvss,ref,result,dignosis,solution,sub_type,Port from report_details where Pid=%s and Host=%s and Port=%s and Source=%s",(int(project_id),host,port,source))
					results=self.cursor.fetchall()
					for v in results :
						report_prop={}
						report_prop["sevirity"]=str(v[0])
						report_prop["title"]=str(v[2])
						report_prop["cvss"]=json.loads(str(v[3]))
						report_prop["protocol"]=str(v[1])
						report_prop["ref"]=json.loads(str(v[4]))
						report_prop["exploits"]=self.getExploits(report_prop["ref"])
						report_prop["result"]=str(v[5])
						report_prop["dignosis"]=str(v[6])
						report_prop["solution"]=str(v[7])
						report_prop["sub_type"]=str(v[8])
						report_prop["port"]=str(v[9])
						item_list.append(report_prop)

					ret_resp["status"]="success"
					ret_resp["value"]=item_list	

				else:
					ret_resp["status"]="failure"
					ret_resp["value"]="Invalid choice,Need to provide some value "
				
			else:
				ret_resp["status"]="empty"
				ret_resp["value"]="0"
			
			self.close_connection()
			return ret_resp
		

		except Exception ,ee:
			print "Exception caught -->:"+str(ee)
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ee)
			self.close_connection()
			return ret_resp




