"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to call the backend database table IPtable , Projects and Application_auth and pass the details to it.It will save update ,delete and reterive details from IPtable, Projects and Application_auth table and thus acts like a model class for the database table IPtabl,Projects and Application_auth.
"""

import MySQLdb
import Auto_logger
import threading
import time
import os

class IPtable:
	"""
		Objective :
		The purpose of this class is to pass the details to the backend IPtable table .
		It acts like a model class which just communicates with the database layer
	"""
	
	def __init__(self,Pid=None,Hosts=None,Ports=None,Service=None,Project_status=None,Exploits=None,Command_id=None):
		"""
			Objective :
			This method would initialise the class variables
		"""
		
		self.id=None
		self.Project=Pid
		self.IPs=Hosts
		self.PORTs=Ports
		self.Sevices_detected=Service
		self.status=Project_status
		self.con=None
		self.cursor=None
		self.logger=None
		self.lock = threading.Lock()
		self.Auto_logger=Auto_logger.Logger()
		self.method_id="INIT"
		self.conn=None
		

	def init_connection(self):
		"""
			Objective :
			This method would initialise the database connection
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
			self.conn=MySQLdb.connect("localhost",user,password,"nmapscan")
			self.cursor = self.conn.cursor()
			self.cur=self.conn.cursor()
		except Exception,ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def close_connection(self):
		"""
			Objective :
			This method would close the database connection
		"""
		
		try:
			self.method_id="Close_connection()"
			if self.conn.open:
				self.conn.close()
		except Exception, ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def print_Log(self,message):
		"""
			Objective :
			This method would print details  to log and console
		"""
		
		print message

	def print_Error(self,message):
		"""
			Objective :
			This method would print error messages to the log file
		"""
		
		print message
	
	def update_Pid(self,project_id,process_id,exploit_pid=False,concurrent=False):
		"""
			Objective :
			This method would actually update the process id and wil map it aginst the current project
			id which helps in stoppinga nd pausing the scan
		"""
		
		try:
			print "Inside update --Obtained process id is ->"+str(process_id)+"  and project_id is : "+str(project_id)
			self.method_id="Update Process Id Mapping"
			#self.print_Log("Started")
			self.init_connection()
			if exploit_pid==False:
				self.cursor.execute("update project set process_id=%s where id =%s",(str(process_id),int(project_id)))
			else:
				if concurrent==False:
					print "Concurrent is false and updating with above values"
					self.cursor.execute("update project set exploits_process_id=%s , project_status_exploits='incomplete' where id =%s",(str(process_id),int(project_id)))
				else:
					process_id_=","+str(process_id)
					self.cursor.execute("update project set exploit_process_id_list=concat(IFNULL(exploit_process_id_list,'-100'),%s) where id=%s",(str(process_id_),int(project_id)))

			self.conn.commit();
			self.close_connection()
			self.print_Log("ended")
			return 1
		
		except Exception ,ee:
			print "Exception in update process id :" +str(ee)
			self.conn.rollback()
			self.close_connection()
			return 0;

	def get_processId(self,project_id):
		"""
			Objective :
			This method would return the process id for the current project id and wil be used for 
			pausing the scan
		"""
		
		try:
			print "Project id is :" +str(project_id)
			self.init_connection()	
			self.cur.execute("SELECT process_id from project where id=%s",(int(project_id),))
			cursor=self.cur.fetchone()
			self.close_connection()
			print str(cursor[0])
			if cursor :
				return str(cursor[0])
			else:
				return 0

		except Exception ,ee:
			self.print_Log("Exception in getprocess_id "+str(ee))
			self.close_connection()
			

	def update_mapping(self,app_id,project_id,assessment_id):
		"""
			Objective :
			This method would map the project id and the assessement id
		"""
		
		try:
				self.method_id="Update Mapping"
				#self.print_Log("Started")
				self.init_connection()
				self.cursor.execute("insert into mapping_table (app_id,project_id,assessment_id) values (%s,%s,%s)",(app_id,project_id,assessment_id))
				self.conn.commit();
				self.close_connection()
				self.print_Log("ended")
				return 1
		except Exception ,ee :
				print "EXception in insert all "+str(ee)
				self.conn.rollback()
				self.close_connection()
				return 0;
			
		

	def DistinctHosts(self,CURRENT_PROJECT_ID,n):
		"""
			Objective :
			This method would reterive all distinct hosts from iptable for current project id
		"""
		
		try:
			self.method_id="DistinctHosts()"
			self.print_Log("Started DH")
			iplist=[]
			self.init_connection()
			self.cursor.execute("select distinct IPs from IPtable where project = %s and status='incomplete' limit %s ",(int(CURRENT_PROJECT_ID),int(n)))
			rows=self.cursor.fetchall();
			#print "Rows are :" +str(rows) 
			if(len(rows)>0):
				for ip in rows :
					iplist.append(ip[0])				
				self.close_connection()
				self.print_Log("Ended DH")
				return iplist
			else:
				self.print_Log("Ended DH")
				return 0
		except Exception ,ee:
			self.print_Error("Exception in distinctHosts : "+str(ee))
			self.close_connection()
			return 0


	def getHostPort(self,project_id):
		"""
			Objective :
			This method would reterive the given ip and port range for the current project
		"""
		
		try:
			project_data=[]
			self.init_connection()
			self.cur.execute("select IPrange,port_range from project where id=%s",(int(project_id),))
			data=self.cur.fetchone()
			if(data):
				project_data.append(str(data[0]))
				project_data.append(str(data[1]))
				self.close_connection()
				return project_data
			else:
				self.close_connection()
				return 0

		except Exception ,ee:
			self.print_Error("Exception getHostPort-ip-"+str(ee))
			self.close_connection()
			return 0


	def getServicesDetected(self,project_id,concurrent=False,rec_id=[]):
		"""
			Objective :
			This method would select the services detected for the currenyt project_id for all hosts
		"""
		
		try:
			self.init_connection()
			if concurrent ==False:
				self.cur.execute("SELECT Sevices_detected from IPtable_history where project=%s and Sevices_detected is not null",(int(project_id),))
			else:
				format_strings=','.join(['%s'] * len(rec_id))
				sql_query="SELECT Sevices_detected from IPtable where id in (%s) and Sevices_detected is not null and project=%%s" % format_strings
				print "SQL QUERY IS :" +str(sql_query)
				args=rec_id +[int(project_id)]
				self.cur.execute(sql_query,args)

			cursor=self.cur.fetchall()
			self.close_connection()
			return cursor

		except Exception ,ee:
			self.print_Log("Exception in get Services Detected() "+str(ee))
			self.close_connection()
			return 0
			


	def getPausedScans(self):
		"""
			Objective :
			This method would return id's of all projects where status=paused
		"""
		self.IPtable=IPtable.IPtable()
		try:
			self.init_connection()	
			self.cur.execute("SELECT id, projects from project where project_status='incomplete' or project_Status='paused'")
			cursor=self.cur.fetchall()
			self.close_connection()
			return cursor
		except Exception ,ee:
			self.print_Log("Exception in getPausedScans() "+str(ee))

			
	def getStatus(self,project_id):
		"""
			Objective :
			This method wouldget the status of the current projecta nd would determine weather the project 
			is complete/incomplete or paused
		"""
		
		try:
			self.init_connection()
			self.cursor.execute("select project_status from project where  id=%s",(int(project_id),))
			status=self.cursor.fetchone()
			if status :
				if(str(status[0])=='paused'):
					self.close_connection()
					return 1;
				else:
					self.close_connection()
					return 0;
			else :
				self.close_connection()
				return 0;

		except Exception, ee:
			self.print_Error("Exception get status "+str(ee))
			self.close_connection()
			return 0


	def MakeUpdate(self,project_id):
		"""
			Objective :
			This method would be useful when resuming a paused scan.
			This method is invoked at the start and would make the status as incpomplete
			where the status would have been paused
		"""
		
		try:
			self.method_id="MakeUpdate()"
			self.print_Log("Started")
			self.init_connection()
			self.cur.execute("select project_status from project where id=%s",(int(project_id),))
			stat=self.cur.fetchone()
			print "The current status is : "+str(stat[0])
			if (stat[0]=="complete"):
				return 3;
			self.cur.execute("select count(id) from IPtable where project=%s",(int(project_id),))
			data=self.cur.fetchone()
			print "Data status is :"+str(data[0])
			if(int(data[0]) > 0):
				self.cur.execute("update IPtable set status='incomplete' where status='processing' and project=%s",(int(project_id),))
				self.conn.commit()
				self.close_connection()
				self.print_Log("Updated status to incomplete !!Ended")
				return 1
			else:
				self.close_connection()
				self.print_Log("Ended")
				return 2	
		except Exception ,ee:
			print "Exception Make Update()" +str(ee)
			self.print_Error( "Exception Make Update()" +str(ee))
			self.conn.rollback()
			self.close_connection()
			return 0;


			
	def InsertAll(self,BulkList):
			"""
			Objective :
			This method would make the insertions inside the IPtable.
			Thus the given ip range in CIDR or comma seperated notation is converted into bulk list as rows
			all the rows are passed to this method and insertion is made in the database table
			"""
		
			try:
				self.method_id="InsertAll"
				self.print_Log("Started")
				self.init_connection()
				self.cursor.executemany("insert into IPtable (project,IPs,PORTs,status) values (%s,%s,%s,%s)",BulkList)
				self.conn.commit();
				self.close_connection()
				self.print_Log("ended")
				return 1
			except Exception ,ee :
				print "EXception in insert all "+str(ee)
				self.print_Error("EXception in insert all "+str(ee))
				#print "EXception Update "+str(ee)
				self.conn.rollback();
				self.close_connection()
				return -1
		


	def switch(self,project_id):
		try :
				self.init_connection()
				self.cursor.execute("select switch from project where id=%s",(int(project_id),))

				#CURRENT_PROJECT_ID
				sw=self.cursor.fetchone()
				self.close_connection()
				#time.sleep(10)
				return sw[0]
		except Exception ,ee :
				print "Exception 0 "+str(ee)
				#self.print_Error("EXception in switch get"+str(ee))		
				#self.conn.rollback()
				self.close_connection()
				return -1

	def getSwitch(self,switch_id=None):
		try :
				ret_resp={}
				switch_list=[]
				self.init_connection()
				if switch_id!=None:
					self.cursor.execute("select switch_id,switch,switch_catagory from switches where switch_id=%s",(int(switch_id),))
					
					
					sw=self.cursor.fetchone()
					sw_d={}
					sw_d["id"]=str(sw[0])
					sw_d["name"]=str(sw[1])
					sw_d["catagory"]=str(sw[2])
					ret_resp["status"]="success"
					ret_resp["value"]=sw_d

				else:
					self.cursor.execute("select switch_id,concat(switch_name,' : ',switch),switch_catagory from switches")

					sw=self.cursor.fetchall()
					for s in sw:
						sw_d={}
						sw_d["id"]=str(s[0])
						sw_d["name"]=str(s[1])
						sw_d["catagory"]=str(s[2])
						switch_list.append(sw_d)
				
					ret_resp["status"]="success"
					ret_resp["value"]=switch_list
	
				
				self.close_connection()
				#time.sleep(10)
				return ret_resp
		except Exception ,ee :
				print "Exception 0 "+str(ee)
				#self.print_Error("EXception in switch get"+str(ee))		
				#self.conn.rollback()
				self.close_connection()
				ret_resp={}
				ret_resp["status"]="failure"
				ret_resp["value"]=str(ee)
	
				return -1

		
		
	def Insert(self,projectname_db,IP_range,Port_range,switch="-T4 -A -n",profile=2): #  Store the project name and return the auto generated id
			"""
			Objective :
			This method would make the insertions inside the project table for new project and would return
			the newly created project id.
			"""

			self.init_connection()
			print "p-name is "+str(projectname_db)
			print "Profile obtained is : " +str(profile)
		        
			try :
				self.cursor.execute("insert into project (projects,IPrange,port_range,switch,profile_id) values (%s,%s,%s,%s,%s)",(str(projectname_db),str(IP_range),str(Port_range),str(switch),int(profile)))

				#CURRENT_PROJECT_ID
				CURRENT_PROJECT_ID=self.cursor.lastrowid
		        	print "The id of the new project is : "+str(CURRENT_PROJECT_ID)
				
				self.conn.commit();
				self.close_connection()
				#time.sleep(10)
				return CURRENT_PROJECT_ID
			except Exception ,ee :
				print "Exception 0 "+str(ee)
				self.print_Error("EXception in insert "+str(ee))		
				self.conn.rollback()
				self.close_connection()
				return -1

	def getPorts(self,ipl,CURRENT_PROJECT_ID):
		
		"""
			Objective :
			This method would return the ports from the table where the host is given and status is 
			incomplete.
		"""

		try:
			self.method_id="getPorts()"
			self.print_Log("Started")
			self.init_connection()
			self.cursor.execute("select PORTs,id from IPtable where IPs=%s and status='incomplete' and project=%s" ,(str(ipl),int(CURRENT_PROJECT_ID)))
			port_list=self.cursor.fetchall()
			self.close_connection()
			self.print_Log("Ended")
			return port_list

		except Exception ,ee:
			self.print_Log("Inside exception getPorts():"+str(ee))
			self.close_connection()
			return -1

	#"update IPtable set status= 'processing' where PORTs='%s' AND IPs='%s' AND project=%d"%(fport,ipl,int(self.CURRENT_PROJECT_ID)))
	
	def UpdateStatus(self,status,ipx,portx,project_id):
		"""
			Objective :
			This method would update the status of the records for ehich discovery would be over and
			would mark the status as complete
		"""

		try:
			self.init_connection()
			self.cursor.execute("UPDATE IPtable SET status = %s WHERE IPs=%s AND PORTs=%s AND project=%s",(status,ipx,portx,int(project_id))) 			
			self.conn.commit()		
			
		except Exception ,ee:
			self.print_Log("Inside exception update status "+str(ee))
			self.conn.rollback()
			self.close_connection()
			


	def Update_status_to_paused_or_processing(self,project_id,status,exploits_status=False,both=False):
		"""
			Objective :
			This method would update the project status as paused and would place the details in the
 			project table
		"""

		try:
			self.method_id="Update to pause"
			#self.print_Log("Started")
			self.init_connection()
			if both==False:
				if exploits_status==False:
					self.cursor.execute("UPDATE project SET project_status = %s WHERE id =%s",(status,int(project_id)))
				else:
					self.cursor.execute("UPDATE project SET project_status_exploits = %s WHERE id =%s",(status,int(project_id)))
			else:
				self.cursor.execute("UPDATE project SET project_status = %s ,project_status_exploits= %s WHERE id =%s",(status,status,int(project_id)))

			self.conn.commit()
			self.close_connection()
			self.print_Log("Stopped")
			return 1
			#conn.close()

		except Exception ,ee:
			self.print_Error("Exception in Update() to pause"+str(ee))
			self.conn.rollback()
			self.close_connection()
			return 0

	def Update(self,sd,portx,ipx,project_id):
		"""
			Objective :
			This method would update the record for which the discovery would be over and the obtained
			services in csv form are placed in teh serviced_detected column
		"""

		try:
			self.method_id="Update"
			self.print_Log("Started")
			self.init_connection()
			self.cursor.execute("UPDATE IPtable SET Sevices_detected = %s WHERE PORTs=%s AND IPs=%s AND project=%s",(sd,portx,ipx,int(project_id)))
			self.conn.commit();
			self.close_connection()
			self.print_Log("Stopped")
			#conn.close()

		except Exception ,ee:
			self.print_Error("Exception in Update()"+str(ee))
			self.conn.rollback()
			self.close_connection()
			
					
		

	def clearLogs(self,project_id,status,concurrent=False):
			"""
			Objective :
			This method would remove all the records from IPtable to IPtable_history once the scan is over.
			The reason for doing that is to spped up the polling process for the nest scans to start.
			"""

			#get_hello()
			print "Clearing old logs !!!!! with status -->"+str(status)
			self.method_id="clearLogs"
			try :
				if(project_id):
					self.init_connection()
					print "\n\nThe logs are not clear :\n\n Clearing them Now ..................\n\n"
					self.print_Log("Clearing Logs now inside clear logs !!")
					self.cursor.execute("select count(*) from IPtable where project=%s",(int(project_id),))
					val=self.cursor.fetchone()
					if (int(val[0]) > 0):
						self.cursor.execute("delete from IPtable_history where project=%s",(int(project_id),))#back up ipbackup
						self.cursor.execute("insert into IPtable_history select * from IPtable where project=%s",(int(project_id),))
						self.cursor.execute ("delete from IPtable where project=%s",(int(project_id),))#delete from current table
						self.cursor.execute("UPDATE project SET project_status = %s WHERE id =%s",(status,int(project_id)))
					if concurrent==True:
						print "hello" #self.cursor.execute("UPDATE project SET project_status_exploits = %s WHERE id =%s",(status,int(project_id)))
					self.conn.commit()
					self.close_connection()#conn.close()
					self.print_Log("Cleared all logs !!")
					print "The logs are finally cleared !!!"
			except Exception ,ee:
				print "Exception 15 " +str(ee) 	
				self.print_Error("Exception in clearing logs :: "+str(ee))
				self.conn.rollback()
				self.close_connection()


	def checkStatus(self,project_id):
		#print "Checking processing status !!! !!!!! for project "+str(project_id)
		"""
			Objective :
			This method would return the count of records where the status is 
			incomplete or processing.This aids in deciding weather any records are left unscanned
			before terminating the discovery process
		"""

		self.method_id="CheckStatus()"
		self.print_Log("Started")
		all_status=[]
		try :
			if(project_id):
				self.init_connection()
				self.cursor.execute("select count(project) from IPtable where  project=%s and (status='processing' or status='incomplete')",(int(project_id),))
				status=self.cursor.fetchone()
				if(int(status[0])):
					#conn.close()
					all_status.append(1)
					#return 1;
				else:
					#conn.close()
					all_status.append(0)
					#return 0;
				self.close_connection()
				all_status.append(self.getStatus(project_id))
				
				self.print_Log("Ended")
				return all_status
		
		except Exception ,ee:
			print "Exception 16 " +str(ee) 
			self.print_Error("Exception checkStatus" +str(ee) )
			self.close_connection()
			return all_status

class Projects:
	"""
		Objective :
		The purpose of this class is to pass the details to the backend Projects table .
		It acts like a model class which just communicates with the database layer
	"""
	
	def init_connection(self):
		"""
		Objective :
		The purpose of this method is to initialize the database connection
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
			self.conn=MySQLdb.connect("localhost",user,password,"nmapscan")

			self.cursor = self.conn.cursor()
			self.cur=self.conn.cursor()
		except Exception,ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def close_connection(self):
		"""
		Objective :
		The purpose of this method is to close the database connection
		"""
	
		try:
			self.method_id="Close_connection()"
			if self.conn.open:
				self.conn.close()
		except Exception, ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def print_Log(self,message):
		"""
		Objective :
		The purpose of this method is to print the details to file
		"""
	
		print message

	def getProfile(self,project_id):
		try:
			ret_list=[]
			self.init_connection()
			self.cursor.execute("select p_name,p_path from Scan_Profiles where p_id in (select profile_id from project where id=%s)",(int(project_id),))
			profile_name=self.cursor.fetchone()
			if profile_name :
				self.close_connection()
				ret_list.append(profile_name[0])
				ret_list.append(profile_name[1])
				return ret_list
			else:
				self.close_connection()
				ret_list.append(-1)
				return ret_list

		except Exception, ee:
			print "Exception -"+str(ee)
			self.close_connection()
			ret_list.append(-1)
			return ret_list
	
	def Profile(self,p_id,all_=False,profile_ids=[]):
		try:
			ret_list=[]
			ret_dict={}
			self.init_connection()
			if all_==False:
				self.cursor.execute("select p_name,p_path,p_id from Scan_Profiles where p_id =%s",(int(p_id),))
				profile_name=self.cursor.fetchone()
				if profile_name :
					self.close_connection()
					ret_list.append(profile_name[0])
					ret_list.append(profile_name[1])
					ret_list.append(profile_name[2])
					return ret_list
				else:
					self.close_connection()
					ret_list.append(-1)
					return ret_list
			else:
				try:
					if len(profile_ids) ==0:
						profile_ids.append(-1)
					format_strings=','.join(['%s'] * len(profile_ids))
					sql_query="select distinct p_id,p_name,p_path from Scan_Profiles where p_catagory <>'Project_Specific' and  (p_catagory ='Shared' or p_id in (%s))" % format_strings
					self.cursor.execute(sql_query,tuple(profile_ids))
					profile_name=self.cursor.fetchall()
					if profile_name :
						self.close_connection()
						for profile in profile_name :
							profile_={}
							profile_["id"]=profile[0]
							profile_["name"]=profile[1]
							profile_["path"]=profile[2]						
							ret_list.append(profile_)
						ret_dict["status"]="success"
						ret_dict["value"]=ret_list
						
					else:
						self.close_connection()
						ret_dict["status"]="failure"
						ret_dict["value"]=-1

					return ret_dict

				except Exception, eex:
					print "Exception -"+str(eex)
					self.close_connection()
					ret_dict["status"]="failure"
					ret_dict["value"]=str(eex)
					return ret_dict

		except Exception, ee:
			print "Exception -"+str(ee)
			self.close_connection()
			ret_list.append(-1)
			return ret_list

	def SaveProfile(self,p_path,u_id,p_name,p_catagory):
		try:
			ret_val={}
			self.init_connection()
			self.cursor.execute("insert into Scan_Profiles (u_id,p_name,p_catagory,p_path)values(%s,%s,%s,%s)",(u_id,p_name,p_catagory,p_path))
			profile_id=self.cursor.lastrowid
			self.conn.commit()
			self.close_connection()
			
			ret_val["status"]="success"
			ret_val["value"]=str(profile_id)
			return ret_val
		except Exception ,ee:
			print("Exception in Save Profile()"+str(ee))
			self.conn.rollback()
			self.close_connection()
			ret_val["status"]="failure"
			ret_val["value"]=str(ee)
			return ret_val
			
	def fetch_project_status(self,project_id):
		try:
			resp_text={}
			resp_val={}
			self.init_connection()
			self.cursor.execute("select project_status,project_status_exploits,mode from project where id=%s",(int(project_id),))
			status=self.cursor.fetchone()
			if status :
				resp_val["project_status"]=status[0]
				resp_val["project_exploits_status"]=status[1]
				resp_val["mode"]=status[2]
				resp_text["status"]="success"
				resp_text["value"]=resp_val
				self.close_connection()
				return resp_text
			else :
				resp_text["status"]="failure"
				resp_text["value"]="No status is stored for this project"

				self.close_connection()

				return resp_text;

		except Exception, ee:
			print "Exception -"+str(ee)
			resp_text["status"]="failure"
			resp_text["value"]="Exception is : "+str(ee)
			self.close_connection()
			return resp_text;



		

	def print_Error(self,message):
		"""
		Objective :
		The purpose of this method is to print the error to the file
		"""
	
		print message

	def Update_mode(self,project_id,mode):
		"""
			Objective :
			This method update the scan mode
		"""

		try:
			self.init_connection()
			self.cursor.execute("UPDATE project set mode=%s where id=%s",(mode,int(project_id)))
			self.conn.commit();
			self.close_connection()
			
		except Exception ,ee:
			print("Exception in Update()"+str(ee))
			self.conn.rollback()
			self.close_connection()

	def ShareProfile(self,profile_id):
		"""
			Objective :
			This method update the Profile and Share it across
		"""

		try:
			ret_resp={}
			if int(profile_id) not in [1,2,3,4,5]:
				self.init_connection()
				self.cursor.execute("UPDATE Scan_Profiles set p_catagory='Shared' where p_id=%s",(int(profile_id),))
				self.conn.commit();
				self.close_connection()
				#ret_resp={}
				ret_resp["status"]="success"
				ret_resp["value"]="Scan Profile Shared Successfully"
			else:
				
				ret_resp["status"]="failure"
				ret_resp["value"]="Cant Share the chosen Scan Profile"

			return ret_resp
		except Exception ,ee:
			print("Exception in Update() Scan Profile_id"+str(ee))
			self.conn.rollback()
			self.close_connection()
			ret_resp={}
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ee)
			return ret_resp


	def UpdateProjectProfile(self,project_id,profile_id):
		"""
			Objective :
			This method update the scan Profile
		"""

		try:
			self.init_connection()
			self.cursor.execute("UPDATE project set profile_id=%s where id=%s",(int(profile_id),int(project_id)))
			self.conn.commit();
			self.close_connection()
			
		except Exception ,ee:
			print("Exception in Update() Profile_id"+str(ee))
			self.conn.rollback()
			self.close_connection()


	def completed_projects(self,project_id=None,paused=False,single=False):
			"""
			Objective :
			The purpose of this method is to return the list of projects where status is complete
			"""	
			try:
				print "\n\n\n\n\nP_id ---> "+str(project_id)
				self.init_connection()
				if single==False:
					if project_id ==None:
						if paused==False:
							print "@@##here@@##"
							self.cursor.execute("SELECT id, projects ,project_status,project_status_exploits ,mode,Date,IPrange,Port_range,switch from project order by id desc")
						else:
							self.cursor.execute("SELECT id, projects,project_status,project_status_exploits ,mode,Date,IPrange,Port_range,switch from project where project_status='paused' or project_status_exploits='paused' order by id desc")
						result=self.cursor.fetchall()
					else:
						result = self.cursor.execute("SELECT count(*) from project where project_status='complete' and id=%s",(int(project_id),))
						result=self.cursor.fetchone()
				else:
					self.cursor.execute("SELECT id, projects ,project_status,project_status_exploits ,mode,Date,IPrange,Port_range,switch from project where id=%s",(int(project_id),))
					result=self.cursor.fetchall()
				self.close_connection()
				return result
			except Exception,ee:
				self.print_Error("EXception in fetching completed projects "+str(ee))
				self.close_connection()
				return 0

	def Poll(self,project_id,source):
		"""
		Objective :
		The purpose of this method is to poll the IPtable and IPexploits table and it
		returns the percentage of records that have been scanned relative to the total 
		number of inserted records
		"""
	
		try:
				self.init_connection()
				if source =="discovery":
					self.cursor.execute("select count(*) from IPtable_history  where project=%s",(int(project_id),))
					result=self.cursor.fetchone()
					if(result[0] >0):
							ret_list=[]
							ret_list.append('100')
							self.close_connection()
							return ret_list
					
					self.cursor.execute("select  ifnull(((select count(*) from IPtable where project=%s and (status='complete' or status='error-complete' or status='host-down')) / (select count(*) from IPtable where project=%s) * 100),0) as percent",(int(project_id),int(project_id)))
					result=self.cursor.fetchone()
				elif source=="scan":
					self.cursor.execute("select  ifnull(((select count(*) from IPexploits where Pid=%s and service_type='existing' and (project_status='complete' or project_status='error_complete' )) / (select count(*) from IPexploits where Pid=%s and service_type='existing') * 100),0) as percent",(int(project_id),int(project_id)))
					result=self.cursor.fetchone()
				else :
					result= -1

				self.close_connection()

				return result


		except Exception ,ee:
				self.print_Error("EXception in polling at db "+str(ee))
				self.close_connection()
				return -1

			

			
	
	
class Application_auth:
	"""
		Objective :
		The purpose of this class is to pass the details to the backend Application_auth table and 
		authenticate the incomming app request to deduce weather the source is valid or not.
		It acts like a model class which just communicates with the database layer
	"""
	
	def __init__(self,app_id=None,app_key=None,app_type=None):
			"""
				Objective :
				Class constructor
			"""
	
			self.app_id=app_id
			self.app_key=app_key
			self.app_type=app_type

	def init_connection(self):
		"""
				Objective :
				Initializes the db connection
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

			self.conn=MySQLdb.connect("localhost",user,password,"nmapscan")
			self.cursor = self.conn.cursor()
			self.cur=self.conn.cursor()
		except Exception,ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def close_connection(self):
		"""
				Objective :
				Closes the db connection
		"""

		try:
			self.method_id="Close_connection()"
			if self.conn.open:
				self.conn.close()
		except Exception, ee:
			print "Exception in closing connection :"+str(ee)
			self.print_Error("EXception in connection-->"+str(ee))


	def print_Log(self,message):
		"""
				Objective :
				Prints the details to log file
		"""

		print message

	def print_Error(self,message):
		print message
	

	def authenticate(self,app_key):
			"""
				Objective :
				Authenticates the incomming ap request and validates weather the app key is valid 
				or not.
			"""

			try:
				self.init_connection()
				self.cursor.execute("select app_key from application_auth where  app_key=%s",(str(app_key),))
				status=self.cursor.fetchone()
				if status :
					if(str(status[0])==app_key):
						self.close_connection()
						return 1;
					else:
						self.close_connection()
						return 0;
				else :
					self.close_connection()
					return 0;

			except Exception, ee:
				print("Exception authentication "+str(ee))
				self.close_connection()
				return 0


			

		
			

	
