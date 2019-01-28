import MySQLdb
import Auto_logger
import threading
import time

class IPtable:
	def __init__(self,Pid=None,Hosts=None,Ports=None,Service=None,Project_status=None,Exploits=None,Command_id=None):
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
		try:
			self.method_id="Init_connection()"
			self.conn=MySQLdb.connect("localhost","<USER>","<PASSWORD>","nmapscan")
			self.cursor = self.conn.cursor()
			self.cur=self.conn.cursor()
		except Exception,ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def close_connection(self):
		try:
			self.method_id="Close_connection()"
			if self.conn.open:
				self.conn.close()
		except Exception, ee:
			self.print_Error("EXception in connection-->"+str(ee))


	def print_Log(self,message):
		print message

	def print_Error(self,message):
		print message
	
	def update_Pid(self,project_id,process_id):
		try:
			self.method_id="Update Process Id Mapping"
			#self.print_Log("Started")
			self.init_connection()
			self.cursor.execute("update project set process_id=%s where id =%s",(str(process_id),int(project_id)))
			self.conn.commit();
			self.close_connection()
			self.print_Log("ended")
			return 1
		
		except Exception ,ee:
			print "Exception in uodate process id :" +str(ee)
			self.conn.rollback()
			self.close_connection()
			return 0;


	def update_mapping(self,app_id,project_id,assessment_id):
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



	def getPausedScans(self):
		try:
			self.init_connection()	
			self.cur.execute("SELECT id, projects from project where project_status='incomplete' or project_Status='paused'")
			cursor=self.cur.fetchall()
			self.close_connection()
			return cursor
		except Exception ,ee:
			self.print_Log("Exception in getPausedScans() "+str(ee))

			
	def getStatus(self,project_id):
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
			self.print_Error("Exception get status "+str(e))
			self.close_connection()
			return 0


	def MakeUpdate(self,project_id):
		try:
			self.method_id="MakeUpdate()"
			self.print_Log("Started")
			self.init_connection()
			self.cur.execute("select count(id) from IPtable where project=%s",(int(project_id),))
			data=self.cur.fetchone()
			if(int(data[0]) > 0):
				self.cur.execute("update IPtable set status='incomplete' where status='processing' and project=%s",(int(project_id),))
				self.conn.commit()
				self.close_connection()
				self.print_Log("Ended")
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
		


	def Insert(self,projectname_db,IP_range,Port_range): #  Store the project name and return the auto generated id
			self.init_connection()
		        print "p-name is "+str(projectname_db)
		        
			try :
				self.cursor.execute("insert into project (projects,IPrange,port_range) values (%s,%s,%s)",(str(projectname_db),str(IP_range),str(Port_range)))

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
		try:
			self.method_id="getPorts()"
			self.print_Log("Started")
			self.init_connection()
			self.cursor.execute("select PORTs from IPtable where IPs=%s and status='incomplete' and project=%s" ,(str(ipl),int(CURRENT_PROJECT_ID)))
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
		try:
			self.init_connection()
			self.cursor.execute("UPDATE IPtable SET status = %s WHERE IPs=%s AND PORTs=%s AND project=%s",(status,ipx,portx,int(project_id))) 			
			self.conn.commit()		
			
		except Exception ,ee:
			self.print_Log("Inside exception update status "+str(ee))
			self.conn.rollback()
			self.close_connection()
			


	def Update(self,sd,portx,ipx,project_id):
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
			
					
		

	def clearLogs(self,project_id,status):
			#get_hello()
			print "Clearing old logs !!!!! with status -->"+str(status)
			self.method_id="clearLogs"
			try :
				if(project_id):
					self.init_connection()
					print "\n\nThe logs are not clear :\n\n Clearing them Now ..................\n\n"
					self.print_Log("Clearing Logs now inside clear logs !!")
					self.cursor.execute("delete from IPtable_history where project=%s",(int(project_id),))#back up ipbackup
					self.cursor.execute("insert into IPtable_history select * from IPtable where project=%s",(int(project_id),))
					self.cursor.execute ("delete from IPtable where project=%s",(int(project_id),))#delete from current table
					self.cursor.execute("UPDATE project SET project_status = %s WHERE id =%s",(status,int(project_id)))
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

		
			

	
