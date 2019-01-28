#!/usr/bin/python



import time
import threading
import time
import nmap
import multiprocessing
import os
import sys
import ConfigParser
#import mysql.connector
import MySQLdb
import atexit
import IPtable
import texttable as tt
import Simple_Logger




r = '\033[31m' #red
b = '\033[34m' #blue
g = '\033[32m' #green
y = '\033[33m' #yellow
m = '\033[34m' #magenta
c = '\033[36m' #magenta
e = '\033[0m' #end


def test():
  print "\n\n\n Exiting Bye Bye !!!"

atexit.register(test)


class NmapScan:
	def __init__(self):
		self.IP=""
		self.PORT=None
		self.SWITCH=""
		self.CURRENT_PROJECT_ID=""
		self.takescan=""
		self.N=4
		self.Port_Divisior=7500
		self.Pause_Flag=False
		self.Stop_Flag=False
		self.ipcount=0
		self.IPtable=IPtable.IPtable()
		self.method_id="INIT"
		self.Thread_pool=[]
		self.retry_count=0
		self.max_retries=3
		self.simple_logger=Simple_Logger.SimpleLogger()
		self.lock=threading.Lock()
		self.folder_name=os.path.join("Results","Data_")

	def generate_Error_log(status,ipx,portx,pid):
		try:
			print "Logged exception"
			'''self.data_path=self.folder_name+str(self.pid)
			error_file=str(project_id)+"_error.txt"
			error_file_path = os.path.join(self.data_path, error_file)
			self.lock.acquire()
			simple_logger.log(error_file_path,"Error -->,Status:Error Complete,Host :"+str(ipx)+",Port:"+str(portx)+",Project id :"+str(pid)+"\n")
			self.lock.release()'''
			
		except Exception ,ee:
			print "Exception while writing to error file :"+str(ee)
			
	def portscanner(self,ipx,portx): #switch,current_project_id
	
		nm=nmap.PortScanner() 
		try:
			if portx=="top_ports":	
				nm.scan(ipx,None,self.SWITCH) 
			else:
				nm.scan(ipx,portx,self.SWITCH) 
		except Exception ,ex:
			self.seperator()
			print r+"\n\nEXCEPTION in nmap built in utiliry--> "+str(ex) +e 
			self.seperator()
			self.seperator()
			print g+"\n\nRe-attempts made on this record :"+str(self.retry_count)+e
			self.seperator()
			self.retry_count =self.retry_count+1
			if (self.retry_count < self.max_retries):
				print g+"\n\nRe-attemting for the failed record"+e
				self.IPtable.UpdateStatus('incomplete',ipx,portx,int(self.CURRENT_PROJECT_ID))
			else:
				print g+"\n\nMax re attempts exceeded - Updating status to ERror-complete"+e
				print r+"\n\nPlease see the error log for further details.IT would mention the host for which the nmap module failed"+e
				self.IPtable.UpdateStatus('error-complete',ipx,portx,int(self.CURRENT_PROJECT_ID))
				self.generate_Error_log('error-complete',ipx,portx,int(self.CURRENT_PROJECT_ID))
			return 0
		try:
			
			temp=nm.scanstats()['uphosts'] 
			if (int(temp) != 0):
				host=ipx 
			
				if 'tcp' in nm[host].all_protocols(): 
					self.seperator()    
						             
					print "Result for IP : " + host   
					print('Protocol : TCP' )
					for kk in nm[host]['tcp'].keys():
						if (nm[host]['tcp'][kk]['name'])=='':
							nm[host]['tcp'][kk]['name']='unknown'

					lport = nm[ipx]['tcp'].keys() 
					lport.sort()
					for port in lport:
						print b+'port : ' +y+str(port) + ' \t ' +  g+ nm[host]['tcp'][port]['state']  +' \t' +r +'' + nm[host]['tcp'][port]['name'] +e
				  
					self.seperator()
					sd=nm.csv() 

			
					#print "Reached at update point "
					try :
						self.IPtable.Update(sd,portx,ipx,int(self.CURRENT_PROJECT_ID))
					
					except Exception ,ee :
						self.print_Log("Exception in update "+str(ee))
						print "EXception Update main "+str(ee)
				
					

				if 'udp' in nm[host].all_protocols():
					self.seperator()
					#self.IPtable.Update(sd,portx,ipx,int(self.CURRENT_PROJECT_ID))
					print "Result for IP : " + host
					print('Protocol : UDP' )

					lport = nm[ipx]['udp'].keys()
					lport.sort()
					for kk in nm[host]['tcp'].keys():
						if (nm[host]['udp'][kk]['name'])=='':
							nm[host]['tcp'][kk]['name']='unknown'

					for port in lport:
						print b+'port : ' +y+str(port) + ' \t ' +  g+ nm[host]['udp'][port]['state']  +' \t' +r +'' + nm[host]['udp'][port]['name'] +e
		 			self.seperator()
					sd=nm.csv() 
			
					try :
						self.IPtable.Update(sd,portx,ipx,int(self.CURRENT_PROJECT_ID))
					except Exception ,ee :
						print "EXception Update main "+str(ee)
						self.print_Log("Exception in update "+str(ee))

				status="complete"

				#print "\n\n\n!!!Completed!!! Ip : "+ipx+"\n\n\n -Protocols ---> "+str(nm[host].all_protocols())+"\n\n"
				try :
					self.IPtable.UpdateStatus(status,ipx,portx,int(self.CURRENT_PROJECT_ID))
				except Exception ,ee :
					self.print_Log("Exception in update status "+str(ee))
			else:
			  	statuss="host-down"
				try :
					self.IPtable.UpdateStatus(statuss,ipx,portx,int(self.CURRENT_PROJECT_ID))
				except Exception ,ee :
					self.print_Log("Exception in update status host-down "+str(ee))
		except Exception,exc:
			self.print_Log("Parent exception : "+str(exc))


	def ThreadEnd(self,ipl):
		print "\n\nThread ended with host ip -"+str(ipl)+"\n\n"
		#startProcessing(1)

	def simplescanner(self,ipl): 
		

		self.method_id="Simple scanner"
		self.print_Log("Started Simple acanner")

		stport=0
		lsport=0
		port_list=[]
		process_list=[]
		try :
			port_list=self.IPtable.getPorts(str(ipl),self.CURRENT_PROJECT_ID)
			if(port_list):
				for port in port_list:
					fport=str(port[0]) #fport=1 -5001
					#print "\n\nFport is :"+fport +" IP :" +str(ipl) +"id :" +str(self.CURRENT_PROJECT_ID)
					time.sleep(10)
					try :
						self.IPtable.UpdateStatus('processing',ipl,fport,int(self.CURRENT_PROJECT_ID))
					except Exception, ee:
						print "EXception 13.01 : " +str(ee)
				
					tp=multiprocessing.Process(target=self.portscanner,args=(ipl,fport)) #
					process_list.append(tp)				
					tp.start()
					#print "\n\nStarted subprocess for ip " +str(ipl) +" and port "+ str(port) +" and Process : "+str(tp)

				for process_ in process_list:
					process_.join()	
					print "\n\n Finished subprocess for ip " +str(ipl) +" and Process : "+str(process_)				
					
			else:
				#print "The current ip address has all its ports scanned -->Must have not been there" +str(ipl)
				self.print_Log("Some exception-->The current ip address has all its ports scanned -->Must have not been there" +str(ipl))
		
			self.print_Log("Ended Simple acanner")

		except Exception ,ee:
			print "EXception 11" +str(ee)
			self.print_Log("Exception inSimpleScanner-->"+str(ee))

		self.ThreadEnd(ipl)


	def topport_scan(self,ipls,portl): #this would be invoked if the given port list would be empty such that only the top ports would be scanned

		tp=multiprocessing.Process(target=portscanner,args=(ipls,"top_ports")) 

		tp.start() 
		tp.join() 


	def getBulkInsertList_(self,start,end,iplist):
		#print "About to make bulk enteries - #Ip:"+ str(len(iplist) )
		BulkList=[]
		counter=1
		#global P
		for ip in iplist:
			x=int(start)
			pnum=end-start+1 #First port number in the sequence say 1-10023 is the range ->pnum =10023
			r=pnum%self.Port_Divisior  #r = 10023 % 5000 --> r=23
			q=pnum//self.Port_Divisior # Floor division ->q=quetient= 10023/5000 => 2.004 ,since floor ,thus q=2
			check=q*self.Port_Divisior #check =2*5000 =>10,000
			#x=int(start) #x=1
			ip_list=[]
			while check>0: #(1) check=10000 >0 (2) check=5000 > 0

		
				for tport in range(x,x+self.Port_Divisior,self.Port_Divisior): 
					fport=str(tport)+'-' +str(tport+self.Port_Divisior) #fport=1 -5001
					BulkList.append((self.CURRENT_PROJECT_ID,ip,fport,'incomplete'))
					x=x+self.Port_Divisior			
					check=check-self.Port_Divisior # (A) 1 --> check=5000  , (B) 1 --> check =0
					counter=counter+1

		    #By this time 1-10,000 ports would be scanned .The idea is to scan 5000 ports at 1 time.
		    #The number of ports left are 23

			check=q*self.Port_Divisior  #check =10,000
			#print "\n\n\n\n check is "+str(check )+" Pnum is "+str(pnum)+"\n\n\n\n"
			if check < end :
				if pnum!=0 : #pnum=10023
					print "Scanning remaining ports"
					prange=str(start+check)+"-"+str(start+check+r-1) #prange= (100001-10,0023) -->Thus the remaining 23 ports are ranged out
					print "Range is :"+ prange+"\n\n\n"
					BulkList.append((self.CURRENT_PROJECT_ID,ip,prange,'incomplete'))
					
		print "\n\nLoop executed : "+str(counter)
		return BulkList;

	def getBulkInsertList(self,all_ports,iplist):
		print "(1)--About to make bulk enteries - #Ip:"+ str(len(iplist))
		BulkList=[]
		if (all_ports == None) :
			print "in if(1)"
			all_Ports_="top_ports"
			for ip in iplist:
				BulkList.append((self.CURRENT_PROJECT_ID,ip,all_Ports_,'incomplete'))			
		elif "-" in all_ports:	
			print "in elif(1)"
			tlist=all_ports.split('-') #Split them and the list would be stored in variable named tlist
			stport=int(tlist[0]) #First port
			lsport=int(tlist[1]) 
			if ((lsport-stport)< 5000):
				for ip in iplist:
					BulkList.append((self.CURRENT_PROJECT_ID,ip,all_ports,'incomplete'))			
			else :
				BulkList=self.getBulkInsertList_(stport,lsport,iplist)

		else :
				print "in else"
				for ip in iplist:
					BulkList.append((self.CURRENT_PROJECT_ID,ip,all_ports,'incomplete'))
		#print "\n\nBulk List is \n\n"
		#print BulkList
		return BulkList	
	

	def multiscan(self,start,end,ipls): #This would be invokd when the number of ports per host to be scanned exceed 5000

		pnum=end-start+1 #First port number in the sequence say 1-10023 is the range ->pnum =10023
		r=pnum%5000  #r = 10023 % 5000 --> r=23
		q=pnum//5000 # Floor division ->q=quetient= 10023/5000 => 2.004 ,since floor ,thus q=2

		check=q*5000 #check =2*5000 =>10,000



		x=int(start) #x=1
		while check>0: #(1) check=10000 >0 (2) check=5000 > 0

	
			for tport in range(x,x+5000,5000): 
				fport=str(tport)+'-' +str(tport+5000) #fport=1 -5001
				tp=multiprocessing.Process(target=portscanner,args=(ipls,fport)) 
				tp.start()
				#tp.join()
				x=x+5000 # (A) 1 --> x=5001 -->It will break from this loop (B) 1 --> x=10,001 -->it shall break the loop
			#	print "Scan from " + str(tport) + " till " + str(tport+5000)+ " Done"
				check=check-5000 # (A) 1 --> check=5000  , (B) 1 --> check =0

	    #By this time 1-10,000 ports would be scanned .The idea is to scan 5000 ports at 1 time.
	    #The number of ports left are 23

		check=q*5000  #check =10,000
		if pnum!=0: #pnum=10023
		#	print "Scanning remaining ports"
			prange=str(start+check)+"-"+str(start+check+r-1) #prange= (100001-10,0023) -->Thus the remaining 23 ports are ranged out
		#	print prange
			tp=multiprocessing.Process(target=portscanner,args=(ipls,prange)) #Finally invoking the cpode portscanner for remaining 23 ports with range (10,001 -10,023)
			tp.start()
			#tp.join()

	def singlescan(self,start,end,ipls):
		#print "Single Scan"
		prange=str(start)+"-"+str(end)
		tp=multiprocessing.Process(target=portscanner,args=(ipls,prange)) 
		tp.start() 
		tp.join() 

	def numofips(self,iprange): #Converts CIDR notation as simple list
		scanner=nmap.PortScanner() 
		IPlist=scanner.listscan(iprange) 

		return IPlist #Thus this wosuld be a list of IP addres


	def banner(self,):
		print g+" ################################################################# "+e
		print g+" ###"+r+"     __                                                    "+g+"### "+e
		print g+" ###"+r+"  /\ \ \_ __ ___   __ _ _ __                               "+g+"### "+e
		print g+" ###"+r+" /  \/ / '_ ` _ \ / _` | '_ \                              "+g+"### "+e
		print g+" ###"+r+"/ /\  /| | | | | | (_| | |_) |                             "+g+"### "+e
		print g+" ###"+r+"\_\ \/ |_| |_| |_|\__,_| .__/                              "+g+"### "+e
		print g+" ###"+r+"                       |_|                                 "+g+"### "+e
		print g+" ###"+r+"   _         _                                             "+g+"### "+e
		print g+" ###"+r+"  /_\  _   _| |_ ___  _ __ ___   __ _| |_(_) ___  _ __     "+g+"### "+e
		print g+" ###"+r+" //_\\| | | | __/ _ \| '_ ` _ \ / _` | __| |/ _ \| '_ \     "+g+"### "+e
		print g+" ###"+r+"/  _  \ |_| | || (_) | | | | | | (_| | |_| | (_) | | | |   "+g+"### "+e
		print g+" ###"+r+"\_/ \_/\__,_|\__\___/|_| |_| |_|\__,_|\__|_|\___/|_| |_|   "+g+"### "+e
		print g+" ###"+r+"                                                           "+g+"### "+e
		print g+" ###"+r+" __           _       _                                    "+g+"### "+e
		print g+" ###"+r+"/ _\ ___ _ __(_)_ __ | |_                                  "+g+"### "+e
		print g+" ###"+r+"\ \ / __| '__| | '_ \| __|                                 "+g+"### "+e
		print g+" ###"+r+"_\ \ (__| |  | | |_) | |_                                  "+g+"### "+e
		print g+" ###"+r+"\__/\___|_|  |_| .__/ \__|                                 "+g+"### "+e
		print g+" ###"+r+"               |_|                                         "+g+"### "+e
		print g+" ###"+b+"                                       Written by: M$P@T3L "+g+"### "+e
		print g+" ################################################################# "+e


	def seperator(self):
		print r+ "----------------------------------------------" +e


	def create_schema(self):
	    with open(schema_file, 'rt') as f:
	    	schema = f.read()
		conn.executescript(schema)


	def prompt_project(self):
		projectname=raw_input(b+"What is your Project name(no white spaces)? \n>"+y)
		return projectname

	def prompt_ips(self):
		ips=raw_input(b+"Type the IP range: \n>"+y)
		IP=ips
		return ips

	def prompt_ports(self):
		ports=raw_input(b+"Enter the Port number or Ports range: \n>"+y)
		#global PORT
		if ports == "":
			self.PORT=None
		elif(ports=="*"):
			self.PORT="1-65535"
		else:
			self.PORT=ports


		return self.PORT

	def print_Log(self,message):
		print str(message)

	def print_Error(self,message):
		print str(message)


	def db_projectname(self,projectname_db,IP_range,Port_range): #  Store the project name and return the auto generated id
			self.method_id="db_projectname"
			self.print_Log("Method started")
			print "Hello"
			time.sleep(10)
			try :
				pid=self.IPtable.Insert(projectname_db,IP_range,Port_range)

				if (pid !=-1):
					self.CURRENT_PROJECT_ID=pid
				else:
					self.print_Log("Some error occured while storing !!" +str(pid))

				self.print_Log("Method ended")
				
		
			except Exception ,ee :
				self.print_Error( "Exception in db_projectname "+str(ee))
		      
				

			#print self.CURRENT_PROJECT_ID
			#print cursor.lastrowid

	def scanbanner(self):
		cp=ConfigParser.RawConfigParser() #parses config files
		cppath="nmap.cfg" #This is the config file to be read.The config file would have various sections.Each section would be in [sq] beakets.each section would be having key/val pairs as conf setting options
		cp.read(cppath) #Read the current file nmap.cfg.The file has got only 1 section given as :[Scantype]
		#global self.SWITCH
		#global self.takescan

		print b+"SELECT THE TYPE OF SCAN: "
		self.seperator()
		print y+"1).  Intense Scan"
		print "2).  Intense + UDP Scan"
		print "3).  Intense + TCP full Scan"
		print "4).  Intense + No Ping Scan"
		print "5).  TCP Ping Scan"
		print "6).  PCI Ping Sweep"
		print "7).  PCI full ports TCP"
		print "8).  PCI Top 200 UDP"
		print "9).  PCI Top 100 UDP"
		print "10). PCI Top 1000 TCP"

		self.takescan=raw_input(b+"Select the type of Scan:\n>"+y)
		if self.takescan=="1":
			self.SWITCH=cp.get('Scantype','Intense') 

		elif self.takescan == "2":
			self.SWITCH=cp.get('Scantype','Intense_UDP')  #-sU -T4 -A -n

		elif self.takescan == "3":
			self.SWITCH=cp.get('Scantype','Intense_TCPall') #-sS -T4 -A -n--max-rtt-timeout 500ms

		elif self.takescan == "4":
			self.SWITCH=cp.get('Scantype','Intense_NoPing') #T4 -A -v -Pn -n

		elif self.takescan == "5":
			self.SWITCH=cp.get('Scantype','Ping') #-PS

		elif self.takescan == "6":
			self.SWITCH=cp.get('Scantype','PCI_Ping_Sweep') #-PE -n -oA


		elif self.takescan == "7":
			self.SWITCH=cp.get('Scantype','PCI_Full_ports_TCP') #-Pn -sS -sV -n --max-retries 3 --max-rtt-timeout 1000ms --top-ports 1000

		elif self.takescan == "8":
			self.SWITCH=cp.get('Scantype','PCI_Top_200_UDP') #-Pn -sU -sV -n --max-retries 3 --max-rtt-timeout 100ms --top-ports 200

		elif self.takescan == "9":
			self.SWITCH=cp.get('Scantype','PCI_Top_100_UDP') #-Pn -sU -sV -n --max-retries 3 --max-rtt-timeout 100ms --top-ports 100

		elif self.takescan == "10":
			self.SWITCH=cp.get('Scantype','PCI_Top_1000_TCP') #-Pn -sS -sV -n --max-retries 3 --max-rtt-timeout 500ms


		else:
			print "Invalid value supplied"
			print "Using Default(1)"
			self.SWITCH=cp.get('Scantype','Intense')

	def prompt_ProjectID(self): #would prompt the user with paused projects -->status=incomplete or paused in projects table
	   	print "\n"
		tab = tt.Texttable()
		x = [[]] #multi dimension array
		cursor=self.IPtable.getPausedScans()
		if cursor:
			print r+"List of Project with IDs"+e +"\n"
			for row in cursor:
		   		x.append([str(row[0]),str(row[1])]) #Place details in the array to display later

			tab.add_rows(x) #thus the table would have all rows and 2 columns
			tab.set_cols_align(['r','r']) 
			tab.header(['IDs','PROJECT_NAME']) #setting heder details for col
			print tab.draw() #this would draw the table on the console

			print "\n"
			id_ = raw_input(b+"Enter The Project Id For Scanning :"+e)
			try :
				if(int(id_)):
					return id_
			except :
				print "Exception 6-->Invalid Value"
				return ""
		else:
			print "\n\nNo incomplete Projects\n\n";
			time.sleep(1);
			self.main()



	 	
	def prompt_ScanType(self):
		scanType=raw_input(b+"Enter Your choice: \n"+y +"\n(1) For Launching New Scan \n(2) For Launching Paused Scans\n "+e)
		try:
			if((int(scanType)<1)or(int(scanType) >2)):
				return 1;
			else :
				return scanType;
		except :
			return 1;

	
		

	def getHostPort(self,project_id):
		try:
			self.method_id="getHostPort()-->main"
			self.print_Log("Started")
			project_data=[]
			project_data=self.IPtable.getHostPort(project_id)
			self.method_id="getHostPort()-->main"
			self.print_Log("Ended")
			return project_data
		except Exception ,ee:
			print "Exception 14" +str(ee)
			self.print_Error("Exception --getHostPort--"+str(ee))
			return 0;


	def launch_PausedScan(self,project_id):
		print "Reached Here in Launch Paused Scan !!!\n";
		self.method_id="LaunchPausedScan()"
		self.print_Log( "Started Launch Paused ")
		success=self.IPtable.MakeUpdate(project_id)
		if(success==1):
			self.startProcessing(self.N)
		elif(success==2): #when its paused b4 making bulk entries
			port_host=self.getHostPort(project_id)
			if(port_host):
				ip_range=port_host[0]
				port_range=port_host[1]
				listip=self.numofips(ip_range) 
				BulkEntries=self.makeBulkEnteries(listip,port_range)
				#global N
				self.startProcessing(self.N)
			else:
				print "The given project id is not present in Database :-->Kindly recheck "
				self.print_Log("The given project id is not present in Database :-->Kindly recheck ")
		
		else:
			print "\n\nThe update method for status= incomplete has exception \n\n"
			self.print_Log("The update method for status= incomplete has exception ")
		 	
	def stop_all(self):
		os._exit()

	def makeBulkEnteries(self,all_hosts,all_ports):
		#print "In here !!1"
		self.method_id="makeBulkEntries()"
		self.print_Log("Started")
		BulkList=[]
		if 1:
			

			BulkList=self.getBulkInsertList(all_ports,all_hosts) 
			self.method_id="makeBulkEntries()"
			self.method_id="makeBulkEntries"
			try:
				status=self.IPtable.InsertAll(BulkList)
				self.method_id="makeBulkEntries()"
				if (status != 1):
					print "Some error occured while bulk insertion"
										
			except Exception ,ee :
				print "EXception 9 "+str(ee)
				self.print_Error("EXception make Bulk entries --> "+str(ee))

			self.print_Log("Ended")
			return BulkList;

	
	def getAllDistinctHosts(self,n):
		try :
			self.method_id="getAllDistinctHost()"
			self.print_Log("started")
			iplist=[]
			iplist=self.IPtable.DistinctHosts(self.CURRENT_PROJECT_ID,int(n))
			self.method_id="getAllDistinctHost()"
			self.print_Log("Ended")
			return iplist
		except Exception ,ee :
			print "Exception 10 " +str (ee)	
			self.print_Error("Exception "+str(ee))
			
			return 0

	def start_Polling(self):
		try:
			stop_db_poll=False #use this logic to stop unnecessary db poll when all hosts finish
			#global N
			while 1:
				time.sleep(5)
				active_threads=threading.enumerate()
				counter=len(active_threads)
				print self.seperator()
				print "Polling \n Threads remaining are :"+str(active_threads)+"\n"
				print self.seperator()
				#if some thread might die-->processing or lets say that initially all rec have status as incomplete and the parent thread would be the polling thread.The status is changed to be processing by the threads that are started by the parent thread.Say for some reason the parent thread would start a thread ,but it might not be scheduled by the scheduler ,and the polling thread would be running asynchronously,the polling thread would immidiately detect the thread count to be =1 as the child threads would have not been scheduled yet ,thus the status would also not be as processing...it would show to be of type incomplete--->thus keeping this condition at head its importent to check herethat if the thread count =1-->main thread only then there should be no record with status as incomplete or processing.Now lets say a person has intentionally paused the scan ,then in that case the project-table would show the status as paused and iptable might contain both entries as processing and incomplete.That use case would be ignored and the scan would come to end
				if(counter==1):
						status=self.IPtable.checkStatus(self.CURRENT_PROJECT_ID)
						if(status):
							processing_status=status[0]
							pause_status=status[1]
							if((processing_status) and (not (pause_status))):#will just check once
									print "Still left with some hosts that display status as processing or incomplete "
									time.sleep(10)#the reason for this delay is suppose some thread is fired but not scheduled yet and thus the status would show as incomplete and if we immidiately statprocessing,then 2 threads might point to 1 record
									self.startProcessing(self.N)
									#print "Main Thread--->Again Starting pooling in 50 sec :"
									time.sleep(50)
							else:		
									
								print "Active Threads are only 1 --Scan about to finish --Threads remaining are :"+str(active_threads)
								self.print_Log("Active Threads are only 1 --Scan about to finish --Threads remaining are :"+str(active_threads))
								break;

				#include logic to stop unnecessary polling see count (*) where status=p if that=limit then dont poll

				elif(counter <=(self.N+1)):
					if(not(self.getPausedStatus(self.CURRENT_PROJECT_ID))):
						limit=(self.N+1)-counter
						if(limit != 0): 
							#print "\n\nLaunching :"+str(limit)+" Threads for  hosts"
							
							left_hosts=self.startProcessing(limit) #chk if its 0 then break or dont poll till current th fn
							#print "Making main thread sleep for 1 seconds"
							time.sleep(1)	
							#print "Waking main thread awake after 1 seconds"
						else:
							#print "Making main thread sleep for 1 seconds"
							time.sleep(1)	
							#print "Waking main thread awake after 1 seconds"
					else:
						time.sleep(10)
				else :
					print "\n\n\n\n------FATEL ERROR-------\n\n\n"
					print "Number of threads cant exceed : "+str(self.N+1)
							
			
		except Exception ,ee:
			print "Exception caught 15" +str(ee)
	

	def StartThreads(self,hosts):
		#print "\n In start thread method !!! \n"
		self.method_id="Start THreads"
		threads=[]
		#print "Starting : "+str(len(hosts)) +"Threads for "+ str(hosts) +"Hosts :" 
		print "\n"
		print self.seperator()
		self.print_Log("Starting : "+str(len(hosts)) +"Threads for "+ str(hosts) +"Hosts" )
		print self.seperator()
		print "\n"
		for host in hosts: 
				#print "host is "+str(host)
				lk= threading.enumerate()
				#print "\n Current thread count : "+str(len(lk))
				#print "\n\nThe threads enumerate returned are : " +str(lk) +"\n\n"
				self.print_Log(g+"******************************************************************************************************************************************\n"+e+"Current thread count : "+str(len(lk)))
				self.print_Log("The threads enumerate returned are : " +str(lk)+g+"\n******************************************************************************************************************************************"+e)
				if len(lk)<(self.N+1) :											
					currentIP= str(host)
					obj=NmapScan()
					obj.IP=self.IP
					obj.PORT=self.PORT
					obj.SWITCH=self.SWITCH
					obj.CURRENT_PROJECT_ID=self.CURRENT_PROJECT_ID
					obj.takescan=self.takescan
					obj.N=self.N
					obj.Port_Divisior=self.Port_Divisior
					obj.Pause_Flag=self.Pause_Flag
					obj.Stop_Flag=self.Stop_Flag
					obj.ipcount=self.ipcount
					obj.IPtable=IPtable.IPtable()
					obj.simple_logger=self.simple_logger
					#self.method_id="INIT"
					t = threading.Thread(target=obj.simplescanner, args=([currentIP])) 
					threads.append(t)
					#print "Starting thread for IP :"+str(host)
					#self.print_Log("Starting thread for IP :"+str(host))
					t.start()
					
					self.Thread_pool.append(t)
					#print "\n\n\nStarted thread for IP :"+str(host) + " --> Thread is : "+  str(t)
					self.print_Log( "\nStarted thread for IP :"+str(host) + " --> Thread is : "+  str(t))
					time.sleep(3)

					
		

					
	
	def startProcessing(self,n):
	 try :
		
			All_hosts=self.getAllDistinctHosts(n)
			#print "Hosts to be given to thread : "+str(All_hosts)
			if (All_hosts):
				self.StartThreads(All_hosts)
			
			else :
				return;
				
		
	 except Exception ,ee :
		print "Exception 12 " +str(ee)	



	

	

	def getPausedStatus(self,project_id):
		try :
		
			status=self.IPtable.getStatus(project_id)
			return status
		except Exception ,ee:
			print "Exception getstatus " +str(ee)
			return 0


	
		


	def pause_scan(self):
		global Pause
		Pause =1
		stop_all();
	
	def main(self,path='',targethosts='',targetports='',switch='',scan_type='',mode="c",project_id='',assessment_id='',app_id=''):
		if (scan_type=="1"):
			
			self.SWITCH=switch
			self.PORT=targetports
			print "The mode recieved is :" +str(mode)
			if(mode=="c"):
				self.db_projectname(path,targethosts,self.PORT) 
				self.seperator()
			elif mode =="g-init":
				if assessment_id =='':
					return;
				else:
					self.db_projectname(path,targethosts,self.PORT) 
					self.IPtable.update_mapping(app_id,self.CURRENT_PROJECT_ID,assessment_id)
					return self.CURRENT_PROJECT_ID
			elif mode=="g-start":
				self.CURRENT_PROJECT_ID=int(project_id)
				x=333#gui mode

			print b +"[+]" + "Starting SCAN" +e
			#targethosts=['10.0.1.39','10.0.1.39','10.0.1.39','10.0.1.39']

			ipcount=len(self.numofips(targethosts)) 
			if (',' in targethosts):
				listip=targethosts.split(',')
			else:
				listip=self.numofips(targethosts) 
		
		
			BulkEntries=self.makeBulkEnteries(listip,self.PORT)
			#global N
			self.startProcessing(self.N) #this is the part wher the prompt input finishes
			#print "Main Thread Starting pooling in 50 sec :"
			time.sleep(100)
			# "**Pooling started **\n"
			self.method_id="Main()"
			self.print_Log("**Pooling started :**")
			self.start_Polling()
			#print "\n\n\n\n\nScan Finished\n\n\n\n\n "
		
		else:
			#global self.CURRENT_PROJECT_ID
			if (mode=="c"):
				self.CURRENT_PROJECT_ID=self.prompt_ProjectID()
			else:
				self.CURRENT_PROJECT_ID=int(project_id)

			if (self.CURRENT_PROJECT_ID != ""):
				self.launch_PausedScan(self.CURRENT_PROJECT_ID)
				print "\n\nMain thread starting Polling .........\n\n"
				print "Main Thread Starting pooling in 10 sec :"
				time.sleep(100)
				print "Pooling started :"
				self.start_Polling()
		
		

	def driver_main(self,ips='',project_name='',port='',scan_type='',switch='',project_id='',mode="c",assessment_id="",app_id=""):
		try:
			print ("("+ips,project_name,port,scan_type,switch,project_id,mode,assessment_id,app_id+")")
			print "\n\n Hello world \n\n"
			time.sleep(10)
			start = time.time()
			os.system('cls' if os.name == 'nt' else 'clear')
			db_filename="nmapscan"
			start = time.time()
			#self.main()
			#mode="c"path='',targethosts='',targetports='',switch='',scan_type='',mode="c",project_id=''):
			self.main(project_name,ips,port,switch,scan_type,mode,project_id,assessment_id,app_id)
			print "Reached here as well !!!"
			if mode != "g-init" :	
				th_count=threading.enumerate() 
				print "# of threads Alive are :"+str(len(th_count))
				#while (1) :
				if 1:
					if (len(th_count)==1):
						print "\nNow stopping and saving Global Project Id : "+ str(self.CURRENT_PROJECT_ID)+"\n";	
						#global self.CURRENT_PROJECT_ID
						if ((self.CURRENT_PROJECT_ID != "") and (self.CURRENT_PROJECT_ID is not None)):
							status=self.IPtable.checkStatus(self.CURRENT_PROJECT_ID)#if some thread might die-->processing or lets say that initially all rec have status as incomplete and the parent thread would be the polling thread.The status is changed to be processing by the threads that are started by the parent thread.Say for some reason the parent thread would start a thread ,but it might not be scheduled by the scheduler ,and the polling thread would be running asynchronously,the polling thread would immidiately detect the thread count to be =1 as the child threads would have not been scheduled yet ,thus the status would also not be as processing...it would show to be of type incomplete--->thus keeping this condition at head its importent to check herethat if the thread count =1-->main thread only then there should be no record with status as incomplete or processing.Now lets say a person has intentionally paused the scan ,then in that case the project-table would show the status as paused and iptable might contain both entries as processing and incomplete.That use case would be ignored and the scan would come to end
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
									print "Launching clear logs !!!"
									self.IPtable.clearLogs(self.CURRENT_PROJECT_ID,'complete')
								#else :
									#clearLogs(self.CURRENT_PROJECT_ID,'complete')
				end_time = time.time()
				print "Time taken in seconds : "+str(end_time-start)

			elif mode =="g-init":
				print "\n\nPROPER\n\n"
				return self.CURRENT_PROJECT_ID	

		except KeyboardInterrupt:
			print c+"\n[*]"+g+" Scan is Aborted"+e
			print c+"[*]"+g+" Stopping"+e
			self.print_Log("\n[*]"+g+" Scan is Aborted")
			time.sleep(1)
			pass
		except Exception ,ee:
			self.print_Log("Exception in driver() "+str(ee))



#NmapScanObj=NmapScan()
#NmapScanObj.driver_main()

