"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:12/30/2016			
			

Objective :
The purpose of this file /module /Class is to actually execute the external scripts for vulnerability assessment and scanning.It runs metasploit modules ,external python ,ruby,bash,shell,java class files and some perl as well as NSE scripts.This file is invoked from driver_meta.py and it invokes appropriate method at 1 time depending upon the type of service and checks to be carried.
Thus there are various method catagories like :

(1) Single line  :For the scripts that only require to be invoked and they return data after completion of execution .
(2) Interactive :This catagory of methods create a virtual terminal to execute the commands in interactive manner ,where the next input given to virtual terminal depends upon the output produced from the preceeding command.
(3) Sniffing :This catagory generates triffic sniffing files for the service /port being testes
(4) Metasploit :This catagory will invoke the metasploit modules and would execute them and collect data from the execution
(5) Single line timeout :THis catagory comes with a timeout parameter which will wait for external script to finish its execution for some specified time

"""
import shlex
import sys
import msfrpc
import time
import pyshark
import pexpect
from subprocess import Popen, PIPE, STDOUT
import commands
import urllib2
import requests
import threading
import subprocess
import psutil
import logging
import logging.handlers
import threading
import Auto_logger
import IPexploits
import time
import unicodedata
import chardet 
import os
import json

"""
Objective :
The following class Commands has got all the catagories of methods discussed above 
"""
class Commands:
	"""
	Objective :
	The following class Commands has got all the catagories of methods discussed above 
	"""

	def __init__(self):
		print "Inside INIT"
		self.project_id=004
		self.method_id="INIT"
		self.command_id=None
		self.Log_file=str(self.project_id) +str("_Log_file")
		self.lock = threading.Lock()
		self.logger =None
		self.logger_info=None
		self.Log_file_info=None
		self.exploit_results=None
		self.con=None
		self.cursor=None
		self.Auto_logger=Auto_logger.Logger()
		self.IPexploitObj=IPexploits.IPexploits()
		self.current_record_id=None
		self.general_op=""
		self.current_host=''
		self.current_port=''
		self.data_path=''
		self.general_op=""
		self.Kill=False
		
	

	def set_log_file(self):
		"""
		Objective :
		When invoked from the GUI the whole code executes in the background and in order to track the 
		details of execution we log the debugging messages that help us track the execution flow.This 			method initilizes the logger class and sets a logger file for the current project (scanning phase 			only)
		""" 
		#print "Inside set Log file  " 
		
		self.Log_file=str(self.project_id) +str("_Log_file")
		self.Log_file_path = os.path.join(self.data_path, self.Log_file)
		#self.Log_file_info=str(self.project_id) +str("_Log_file_info")
		print "Log file is : " +str(self.Log_file)
		self.logger=self.Auto_logger.configureLogger(self.method_id,self.Log_file_path)
		#self.logger_info=self.Auto_logger.configureLoggerInfo(self.method_id,self.Log_file_info)
		time.sleep(3)

	def init_connection(self):
		"""
		Objective :
		This method would initialize the database connection 
		"""
		try:
			self.con=MySQLdb.connect("localhost","<USER>",<PASSWORD>","nmapscan")
			self.cursor = self.con.cursor()
		except Exception, e:
			self.print_Error("EXception in connection-->"+str(e))

	def print_Log(self,message):
		"""
		Objective :
		This method would log the command id and message (obtained results) to the log file
		"""
		message="Command Logger --->Command id --> "+str(self.command_id) +"  Message --> :" +str(message)
		try:
			self.lock.acquire()
			self.logger.debug(message)
			self.lock.release()	
		except Exception ,e:
			self.lock.acquire()
			self.logger.critical(message +"--Exception :  --"+str(e))
			self.lock.release()
			print "Log exception :"+str(e)
		print message+"\n"

	def print_Error(self,message):
		"""
		Objective :
		This method log any exception or error to the logger with the flag info as ERROR
		"""

		print "Error Logger Command fro file -->"+str(self.Log_file)
		#self.logger=self.Auto_logger.configureLogger(self.method_id,self.Log_file)
		
		message="Error -->Command id --> "+str(self.command_id) +"  Message --> :" +str(message)
		print message
		try:
			self.lock.acquire()
			self.logger.error(message)
			self.lock.release()
		except Exception ,e:
			self.lock.acquire()
			self.logger.error(message +"--Exception :  --"+str(e))
			self.lock.release()

	def print_Log_info(self,message):
		"""
		Objective :
		This method would log the execution flow to the different log file (info) .The purpose of this log 			is to do debugging and track execution flow of commands 
		"""

		message="Command id --> "+str(self.command_id) +"  Message --> :" +str(message)
		message=message.replace("\n","")
		message=message.replace("\\n","")
		"""print "-----------------------------------------------------------------------------------------"
		print "Logger Info for file -->"+str(self.Log_file_info) 
		#print "Inside print log !!--Log file is "+str(self.Log_file)
		
		print "Message is " +str(message)
		print "-----------------------------------------------------------------------------------------"
		"""
		#self.logger_info=self.Auto_logger.configureLoggerInfo(self.method_id,self.Log_file_info)
		#print "\n\n\n"		#print "logger is -->"+str(self.logger)
		
		
		try:
			self.lock.acquire()
			self.logger_info.debug(message)
			self.lock.release()	
		except Exception ,e:
			self.lock.acquire()
			self.logger_info.critical(message +"--Exception :  --"+str(e))
			self.lock.release()
			print "Log exception :"+str(e)
		print message+"\n"

	def print_Error_info(self,message):
		"""
		Objective :
		This method would log errors pertaining to execution flow with flag set as 'Error'
		"""

		#self.logger_info=self.Auto_logger.configureLoggerInfo(self.method_id,self.Log_file_info)
		message="Command id --> "+str(self.command_id) +"  Message --> :" +str(message)
		print message
		try:
			self.lock.acquire()
			self.logger_info.error(message)
			self.lock.release()
		except Exception ,e:
			self.lock.acquire()
			self.logger_info.error(message +"--Exception :  --"+str(e))
			self.lock.release()
		

	def cleanUp(self):
		"""
		Objective :
		This method would clean up the virtual console 
		"""

		#a = client.call('console.write', [console_id, "workspace\n"])
		#time.sleep(1)
		#self.print_Log( "\n\n"+str(a)+"--->Written<----\n\n"
		cleanup = self.client.call('console.destroy',[self.console_id])
		time.sleep(1)
		self.print_Log( "Clean up :"+str(cleanup))
	    	self.print_Log( "Cleanup result: %s" %cleanup['result'])

	def exit_child(self,child):
		"""
		Objective :
		This method would gracefully exit the msfconsole when all metasploit commands are ececuted
		"""

		try:
			self.print_Log_info("\nExiting  from msfconsole !!!\n")
			self.print_Log("\nExiting  from msfconsole !!!\n")
			child.sendline('exit')
			time.sleep(2)
			j=child.expect(['[$/#]',pexpect.EOF,pexpect.TIMEOUT],timeout=60)
			print "j is "+str(j)
			if(j==1):
				self.print_Log("Exited from msfconsole !!!")
				self.Display_msg(child)
			else :
				self.print_Log("\n\nSome Error Occured while Exiting\n\n")
				self.Display_msg(child)	

		except Exception ,e:
			self.print_Error_info("\n\nException in Exit Child "+str(e))
			self.print_Error("\n\nException in Exit Child "+str(e))
			self.Display_msg(child)	

	def SaveDetails(self,commands,result):
		"""
		Objective :
		This method is commonly shared amongst all catagories of methods
		(singleline ,interactive ,metasploit ,sniffing and etc) which are responsible for invoking 
		the external scripts as well as the metasploit modules .Actually when ever the methods execute the 
		external scripts teh recived data from external scripts is passed on to this method and it saves the
 		findings inside the databse table
		"""

		#print "\n\n\n\n"
		self.print_Log("Saving details :")
		self.print_Log_info("Saving details :")
		print "\n\n Here :Commands Executed for Record id -> " +str(self.current_record_id) +" and Command Id : -->"+str(self.command_id )+" and Method id -->"+self.method_id
		print str(commands)
		print ("\n\n\n\n")
		print "\n\nResults for Record id  -> " +str(self.current_record_id) +" and Command Id : -->"+str(self.command_id) +" and Method id -->"+self.method_id
		print str(result)
		#print str(result) 
		status=1
		self.IPexploitObj.logger=self.logger
		status=self.IPexploitObj.Update(self.project_id,self.current_record_id,self.command_id,commands,result,False)
		if (status==1):
			self.print_Log_info( "Details Updated successfully")
			#self.print_Log( "Details Update Failed")
			print "Details Updated successfully"
		else:
			self.print_Log_info( "Details Update Failed")
			self.print_Log( "Details Update Failed")
			print "Details Update Failed"
		#print str(result)+"\n\n\n"
		x=1


	def custom_meta(self,commands):
		"""
		Objective :
		This method would take the list of commands as aurgument and would invoke metasploit as a subprocess
		in virtual console and would execute the commands and would collect the resukts and finally would
		pass the findings to savedetails method to save the results
		"""

		try:
			exploit_result=''
			commands_launched=[]
			self.method_id="Custom meta"
			self.print_Log_info("Inside command_meta")
			self.print_Log("Inside command_meta")
			#child=pexpect.spawn("msfconsole")
			child = pexpect.spawn('msfconsole -q')
			commands_launched.append('>msfconsole \n')
			print "Console created "
			
			#print str(child)
			#child = pexpect.spawn(args[0])
			i=child.expect(['.*> ',pexpect.EOF,pexpect.TIMEOUT],timeout=480)
			run=True
			if (i==0):
				self.print_Log(str(child.after))
				commands_launched.append(str(child.after))
				self.print_Log(str(i))
				for command in commands:
					command=command.replace("\n","")
					child.sendline(command)
					#commands_launched.append(command+"\n")
					time.sleep(3)
					j=child.expect(['.*> ',pexpect.EOF,pexpect.TIMEOUT],timeout=280)
					if(j==0):
						self.print_Log(str(child.after))
						commands_launched.append(str(child.after)+"\n")
						continue
					elif(j==1):
						self.print_Log("EOF reached-->Not launching the run command")
						self.Display_msg(child)
						commands_launched.append(str(child.after)+"\n")
						run=False
						break
					else:
						self.print_Log("Time out exceeded in child check ->Not launching the run command")
						self.Display_msg(child)
						commands_launched.append(str(child.after)+"\n")
						run=False
						break

			elif(i==1):
					print "Reache1"
																													
					self.print_Log("EOF reached Outer Expect-->Not launching the run command")
					run=False
					self.Display_msg(child)
					commands_launched.append("EOF->"+str(child.after)+"\n")
					
			else:
					print "Reache2"
					self.print_Log("Time out exceeded in parent check ->Not launching the run command")
					run=False
					self.Display_msg(child)
					commands_launched.append("Time out exceeded "+str(child.after)+"")
				
			if(run==True):
					print "Reache3"
					self.print_Log("\n\nEverything Fine till now-->Launching run command\n\n")
					self.print_Log_info("\nEverything Fine till now-->Launching run command\n")
					child.sendline('run')
					#commands_launched.append('>run')
					time.sleep(3)
					k=child.expect(['.*>.*',pexpect.EOF,pexpect.TIMEOUT],timeout=1500)
					time.sleep(2)
					if(k==0):
						self.print_Log("\n\nModule Execution completed\n\n")
						self.print_Log_info("\nModule Execution completed\n")
						self.Display_msg(child)
						commands_launched.append(''+str(child.after)+'\n')
						exploit_result=exploit_result+"Command Executed :"+commands_launched[0]
						exploit_result="\n"+exploit_result+"\nResult :\n"+str(child.after)
						#exploit_result=str(child.after)
						self.print_Log("\n\nNow exiting !!!\n\n")
						self.exit_child(child)
						self.print_Log("Closing the child pipe !!!")
						child.close(force=True)	
					else:
						
						self.print_Log("some error occured while running the aux module !!")
						self.print_Log_info("some error occured while running the aux module !!")
						self.print_Log_Error("some error occured while running the aux module !!")
						self.print_Log("The value of expect here is :" +str(k))
						self.Display_msg(child)
						commands_launched.append('<Finished-T/O or EOF>'+str(child.after)+'')
						exploit_result=exploit_result+"Command Executed :"+commands_launched[0]
						exploit_result="\n"+exploit_result+"\nResult :\n"+str(child.after)
						#exploit_result=str(child.after)
						self.print_Log("\n\nNow exiting !!!\n\n")
						self.exit_child(child)
						self.print_Log("Closing the child pipe !!!")
						child.close(force=True)
			else:
				self.print_Log("Run Flag is Not true !!")
				self.print_Log_info("Run Flag is Not true !!")
				self.print_Log("Closing the child pipe !!!")
				child.sendline('exit')
				child.close(force=True)
				exploit_result="Command msf console failed to load the console or timeout occured "
				exploit_result=exploit_result+"Command Executed :"+commands_launched[0]
				exploit_result="\n"+exploit_result+"\nResult :\n"+commands_launched[len(commands_launched)-1]
				
			#self.SaveDetails(''.join(commands_launched),exploit_result)
			self.SaveDetails(str(commands_launched),exploit_result)
			self.print_Log_info("Exiting custom_meta !!")
		except Exception ,e:
			self.print_Error(str(child.after))
			self.print_Error("Custom MetaSploit module has exception :" +str(e))
			self.print_Error_info("Custom MetaSploit module has exception :" +str(e))
			#self.Display_msg("Closing the child pipe !!!")
			child.close(force=True)


	def meta_commands(self,commands):
		"""
			Objective :
			This method is obselete and is not used in final draft of code.Its purpose was to use github
			version of code for metasploit modules execution ,but due to its unstable nature we adapted 
			our own custom methodology using Python's pexpect
		"""

		try:
				
			
			self.print_Log( "Console id is :"+str(self.console_id))			
			for command in commands:
		    		a = self.client.call('console.write', [self.console_id, command])
				time.sleep(1)
			a = self.client.call('console.write', [self.console_id, "run\n"])
		    	time.sleep(5)
			self.print_Log( str(a))
			while True:
				self.res = self.client.call('console.read',[self.console_id])
				if len(self.res['data']) > 1:
					self.print_Log( "Result :" + self.res['data'])
				if self.res['busy'] == True:
					self.print_Log( "Console is busy :")
					time.sleep(1)
					continue
				break
	    		
		except Exception,e:
			print "Exception meta_commands-->"+str(e)
			self.print_Error( "EXception Meta "+str(e))
	

	def start_wireshark(self,args):
		"""
		Objective :
		This method would start python version of wireshark called as pyshark for traffic sniffing
		"""

		self.print_Log( "\n\nStarting wireshark for 50 sec\n\n")
		self.print_Log_info( "\n\nStarting wireshark for 50 sec\n\n")
		try:
			capture = pyshark.LiveCapture(interface=args[0],bpf_filter=args[1])
			capture.sniff(timeout=50)#will mae the pyshark to capture packets for next 50 seconds
			for packet in capture.sniff_continuously(packet_count=5):
		    		self.print_Log( 'Just arrived:'+str( packet))
		except Exception ,ee:
			self.print_Error( "EXception Wireshark-old "+str(ee))
			self.print_Error_info( "EXception Wireshark-old "+str(ee))
			return


	def Display_msg(self,child):
		"""
		Objective :
		This method would pass the debugging messages to print_Log method to keep track of execution flow
		"""

		try:
			self.print_Log( "Before : \n"+ str(child.before) + "After : \n"+ str(child.after))
		except Exception, ee:
			self.print_Error("Error in Display_msg methos --> : "+str(ee))
			self.print_Error_info("Error in Display_msg methos --> : "+str(ee))

	def Nfs_Mount_intaractive(self,args):
		"""
		Objective :
		Nfs mount is used for service NFS and this check will attempt to mount directories of remote system 		to local machine .The method is interacive and is customizd only for this purpose.

		Todo :
		For now we are hard coding-->assuming root permission -->later try to parse the directories which
		have permission and mount them only.It assumes /temp/ directory is created already

		"""

		try:  #For now we are hard coding-->assuming root permission -->later try to parse the directories which have permission and mount them only.It assumes /temp/ directory is created already
			self.print_Log( "\n\nStarting Mount  all retive\n\n")
			self.print_Log_info( "\n\nStarting Mount  all retive\n\n")
			print ("Launching command--> "+str(args[0]))
			commands_executed=[]
			commands_executed.append(">"+str(args[0])+"\n")
			exploit_result=''
			child = pexpect.spawn(args[0])
			print "Launched"
			i=child.expect([pexpect.TIMEOUT, '[#\$]','.*access denied.*',pexpect.EOF],timeout=25)
			if ((i==1)or(i==3)):
				print "here"
				self.print_Log(str(child.after))
				commands_executed.append(">"+str(child.after))
				self.print_Log( str(i))
				for counter in range (1,len(args)):
					child.sendline(args[counter])
					commands_executed.append(args[counter]+"\n")
					time.sleep(2)
					j=child.expect([pexpect.TIMEOUT, '[#\$] ',pexpect.EOF],timeout=15)
					time.sleep(2)
					commands_executed.append(str(child.after))
					if((j==1)or (j==2)):
						self.print_Log(str(child.after))
						continue
					else :
						self.print_Log("Some Error occured--During command launching")
						self.print_Log_info("Some Error occured--During command launching")
						self.Display_msg(child)
						break
				exploit_result="Command Executed :"+commands_executed[0]
				exploit_result="\n"+exploit_result+"Result:\n"+commands_executed[len(commands_executed)-1]
				self.print_Log("Closing Child now !!")
				self.print_Log_info("Closing Child now !!")
				child.close(force=True)	
			elif (i==2):
				commands_executed.append(str(child.after))
				exploit_result="Command Executed :"+commands_executed[0]
				exploit_result="\n"+exploit_result+"Result:\n"+commands_executed[len(commands_executed)-1]
				self.print_Log("Closing Child now !!")
				self.print_Log_info("Closing Child now !!")
				child.close(force=True)	
	
			else:
				self.print_Log("Either timeout or End of file "+str(i))
				self.print_Log_info("Either timeout or End of file "+str(i))
				self.print_Log("Closing Child now !!")
				exploit_result="Command Executed :"+commands_executed[0]
				exploit_result="\n"+exploit_result+"\nResult:\n"+commands_executed[len(commands_executed)-1]
				child.close(force=True)	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Exiting mathos Nfs interactive  now !!")
		except Exception,e:
			child.close(force=True)	
			self.print_Error("Exception in mount interactive "+str(e))
			self.print_Error_info("Exception in mount interactive "+str(e))
			#self.print_Error("Closing Child now !!")
			

	def ftp_interactive(self,args): #Note never execute it as a sinle line command as the console gets stuck
		"""
			Objective :
			The purpose of this method is to check weather anonymous login is allowed on ftp service
			on the given remote host.Altough the same task could be achived by passing appropriate
			aurguments to General_interactive catagory of methos ,but this method was developed before
 			developemt of General_interactive and thus is customized only for anonymous FTP check using
	 		interactive mode with virtual console
		"""		
		try :
			
			commands_executed=[]
			exploit_result=''
			self.method_id="Ftp_interactive ()"
			self.print_Log( "\n\nStarting FTP Login --Anonmous\n\n")
			self.print_Log_info( "\n\nStarting FTP Login --Anonmous\n\n")
			child = pexpect.spawn(args[0])
			i=child.expect(['Permission denied', 'Name .*:','.* Connection refused',pexpect.TIMEOUT, '[#\$] '],timeout=25)
			commands_executed.append(args[0]+"\n")
			commands_executed.append(str(child.after)+"\n")
			if (i==1):
				self.print_Log(str(child.before) +"  " +str(child.after))
				commands_executed.append(str(child.after))
				#self.print_Log( str(i))
				child.sendline('anonymous')
				commands_executed.append('anonymous'+"\n")
				time.sleep(3)
				j=child.expect(['.*Password:',pexpect.TIMEOUT],timeout=25)
				if(j==0):
					self.print_Log( "Before : "+ str(child.before) + "After : "+ str(child.after))
					commands_executed.append(str(child.after)+"\n")
					child.sendline('noah@example.com')
					time.sleep(3)
					commands_executed.append('noah@example.com'+"\n")
					k=child.expect(['.*ftp> ',pexpect.TIMEOUT],15)
					commands_executed.append(str(child.after)+"\n")
					if(k==0):
						exploit_result="Login SuccesFul --> "+str(child.after)
						self.print_Log( "Login Successful")
						self.print_Log_info( "Login Successful")
						self.print_Log( "Before : "+ str(child.before) + "After : "+ str(child.after))
						
					else:
						exploit_result="Login Not SuccesFul --> "+str(child.after)
						self.print_Log( "Login Not Successful")
						self.print_Log_info( "Login Not Successful")
						self.Display_msg(child)
				else:
					commands_executed.append(str(child.after)+"\n")
					self.Display_msg(child)

			elif ((i==2)or (i==3)):
				
				self.print_Log( "Host seems to be down or service is turned off : ")
				self.print_Log_info( "Host seems to be down or service is turned off- or connection Timed out : ")
				self.Display_msg(child)
			
			elif (i==4):
				self.print_Log( "Host has very less security as it permits ftp login without any password: ")
				self.print_Log_info( "Host has very less security as it permits ftp login without any password: ")
				self.Display_msg(child)
			else :
				self.print_Log( "\n\nPermission Denied\n\n")
				self.print_Log_info( "\n\nPermission Denied\n\n")
				self.Display_msg(child)

			self.print_Log("Closing Child now !!")
			
			child.close(force=True)
			exploit_result=exploit_result+"Command Executed :"+commands_executed[0]
			exploit_result="\n"+exploit_result+"\nResult :\n"+str(child.after)
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Exiting method Ftp interactive !!")	
	
		except Exception,e:
			self.print_Error("Closing Child now !!")
			child.close(force=True)	
			self.print_Error( "Exception ftp_intaractive "+str(e))
			self.print_Error_info( "Exception ftp_intaractive "+str(e))

	def ssh_check_execution(self,child,commands_executed):
		"""This method works in conjuction with ssh_root_login check/ssh_interactive"""
		exploit_result=""
		try:
			print "In here"
			i=child.expect(['.*Permission denied.*', 'root@.* password:.*','.* Connection refused',pexpect.TIMEOUT,'[#\$]',pexpect.EOF],timeout=15)
			time.sleep(2)
			print "got something-->"+str(i)
			commands_executed.append(str(child.after)+"\n")
			print "i is -->"+str(i)
			if ((i==1)):
					
				self.print_Log( "Root is expecting a pssword--supplying default password")
				self.print_Log_info( "Root is expecting a pssword--supplying default password")
				#self.print_Log( str(i))
				child.sendline('root')
				commands_executed.append('root'+"\n")
				time.sleep(2)
				j=child.expect(['root@.* password:.*' ,'[#\$] ','Permission denied'],timeout=15)
				commands_executed.append(str(child.after)+"\n")
				#commands_executed.append('root'+"\n")
				#time.sleep(2)
				exploit_result=str(child.after)+"\n"
				if(j==1):	
					
					self.print_Log( "Login Successful with password root")
					self.print_Log_info( "Login Successful with password root")
					self.print_Log( "Before : "+ str(child.before) + "After : "+ str(child.after))
				else:
					#exploit_result ="Before -: "+str(child.before) + "After - :" +str(child.after)
					self.print_Log("No login with pw root-Cant guess weather root login is enabled.Need to brute force\n" +str(j)) 
					self.print_Log_info("No login with pw root-Cant guess weather root login is enabled.Need to brute force")
					self.Display_msg(child)
			elif (i==4):
				self.print_Log( "Login successful ..Root is set to weak privlages it permits login without password:")
				self.print_Log_info( "Login successful ..Root is set to weak privlages it permits login without password:")
				self.Display_msg(child)
			elif (i==2):
				self.print_Log( "Connection refused-->Service not running on host")
				self.print_Log_info( "Connection refused-->Service not running on host")
				self.Display_msg(child)
			elif (i==3) or (i==5):
				self.print_Log( "TimeOut occcured or EOF")
				self.print_Log_info( "Connection Timed out !!!")
				self.Display_msg(child)
			else :
				self.print_Log( "Permission Denied at inception for root--Good ")
				self.print_Log_info( "Permission Denied at inception for root--Good ")
				self.Display_msg(child)

			#exploit_result ="Before -: "+str(child.before) + "After - :" +str(child.after)
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])
			self.print_Log("Closing Child now !!")
			child.close(force=True)	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Exiting method ssh interactive!!")
		except Exception,e:
			self.print_Error("Closing Child now !!")
			child.close(force=True)	
			self.print_Error( "Exception ssh_intaractive "+str(e))
			self.print_Error_info( "Exception ssh_intaractive "+str(e))


	def ssh_interactive(self,args): #Note never execute it as a sinle line command as the console gets stuck
		"""
			Objective :
			The purpose of this method is to check weather root login is allowed on ssh service
			on the given remote host.Altough the same task could be achived by passing appropriate
			aurguments to General_interactive catagory of methods ,but this method was developed before
 			developemt of General_interactive and thus is customized only for SSH root login check using
	 		interactive mode with virtual console
		"""
		try:
			print "In ssh interactive !!!!!"
			commands_executed=[]
			exploit_result=""
			self.method_id="ssh_interactive()"
			self.print_Log( "\n\nStarting ssh--INteractive\n\n")
			self.print_Log_info( "\n\nStarting ssh--INteractive\n\n")
			child = pexpect.spawn(args[0]) #root@192.168.179.136's password:
			commands_executed.append(args[0]+"\n")
			check_list=['.*Permission denied.*', 'root@.* password:.*','.* Connection refused','.*(yes/no).*','[#\$] ',pexpect.TIMEOUT,pexpect.EOF]
			i=child.expect(['.*Permission denied.*', 'root@.* password:.*','.* Connection refused','.*(yes/no).*',pexpect.TIMEOUT,'[#\$]',pexpect.EOF],timeout=15)
			print "THe value oof i is "+str(i)
			if(i==3):
				print "Hre-yes/no"
				child.sendline('yes')
				time.sleep(3)
				self.ssh_check_execution(child,commands_executed)
			else:
				print "here -->other--->" +str(i)
				self.print_Log_info( "Root is expecting a pssword--supplying default password")
				#self.print_Log( str(i))
				commands_executed.append(str(child.after)+"\n")
				child.sendline('root')
				commands_executed.append('root'+"\n")
				self.ssh_check_execution(child,commands_executed)

		except Exception,e:
			self.print_Error("Closing Child now !!")
			child.close(force=True)	
			self.print_Error( "Exception ssh_intaractive "+str(e))
			self.print_Error_info( "Exception ssh_intaractive "+str(e))
	
	def domain_interactive(self,args):
		"""
			Objective :
			The purpose of this method is to check /conduct various checks related to domain server /DNS
			service like (zone transfers ,guessing subdomains and etc).Altough the same task could be
 			achived by passing appropriate aurguments to General_interactive catagory of methods ,but this
 			method was developed before developemt of General_interactive and thus is customized only for
 			Domain server checks using interactive mode with virtual console
		"""
		try:
			self.method_id="Domain_interactive()"
			self.print_Log("Launching Domain Interactive ::<--- Command :--->"+str(args[0]))
			self.print_Log_info("Launching Domain Interactive ::<--- Command :--->"+str(args[0]))
			child = pexpect.spawn(args[0]) #root@192.168.179.136's password:
			commands_executed=[]
			exploits_result=''
			commands_executed.append(args[0]+"\n")
			i=child.expect(['.*>.*'],timeout=55)#note > is kept with purposefully here,* is not there as it does something like xx->
			time.sleep(2)
			if (i==0):
				self.print_Log( "$"+str(args[1])+"\n" )
				#self.print_Log( str(i))
				self.Display_msg(child)
				child.sendline(args[1])
				#commands_executed.append(args[1])
				time.sleep(2)
				j=child.expect(['Address: .*#.*> ' ,"nslookup: couldn't get.*",".*>.*"],timeout=35) #note this case will work only when the given <host> is in 192.x.x.x notation
				commands_executed.append(str(child.after)+"\n")
				if(j==0) or (j==2):	
					#self.print_Log( "Dns lookup Address changed successfully-->"+str(child.before)+str(child.after))
					self.Display_msg(child)
					commands_executed.append(str(child.before) +"   " +str(child.after))
					child.sendline(str(args[2]))
					commands_executed.append(args[2]+"\n")
					time.sleep(2)
					k=child.expect(['.*>.*' ,".* SERVFAIL",".*no servers could be reached.*"],timeout=20)
					commands_executed.append(str(child.after)+"\n")
					exploit_result=str(child.after)+"\n"
					
				else:
					exploit_result=str(child.after)+"\n"
					self.print_Log("Invalid host address given \n" +str(j)) 
					self.print_Log_info("Invalid host address given \n" +str(args[2])+" J is --> " +str(j))
					self.Display_msg(child)
			
			exploit_result=exploit_result+"\n\n""Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"Result:\n"+str(commands_executed[len(commands_executed)-1])
			self.print_Log("Closing Child now !!")
			child.close(force=True)	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log("Closing Child now !!")
			child.close(force=True)	
			self.print_Log("Exiting Domain interactive !!")
			
		
		except Exception ,e:
			self.print_Error( "Exception Domain Intaractive " +str(e))
			self.print_Error_info( "Exception Domain Intaractive " +str(e))
			self.print_Error(self.Display_msg(child))
			self.print_Error("Closing Child now !!")
			child.close(force=True)	

	def imap_interactive(self,args):
		"""
			Objective :
			The purpose of this method is to check /conduct various checks related to Imap service.

			To do :
			Right now teh username and password passed to this module are (msfadmin,msfadmin).Add additional
			aurguments to the master json file for this service to take username password from master json
 			or name list to brute force login attempt.
		"""
		
		try:
			commands_executed=[]
			self.method_id="Imap_interactive"
			exploit_result=''
			self.print_Log("Launching Imap Interactive ::Command-->" +str(args[0]))
			self.print_Log_info("Launching Imap Interactive ::Command-->" +str(args[0]))
			child = pexpect.spawn(args[0]) #Telnet <IP> 143: Connection refused
			commands_executed.append(args[0])
			i=child.expect(['.*: No route to host', '.* login:','.*: Connection refused', '[#\$] ',pexpect.TIMEOUT],timeout=25)
			#self.print_Log(str(i))
			commands_executed.append(str(child.after)+"\n")
			if (i==1):
				self.print_Log( "Telnet is expecting Username -- supplying default Username")
				self.print_Log_info( "Telnet is expecting Username -- supplying default Username")
				#self.print_Log( str(i)
				child.sendline('msfadmin')
				commands_executed.append('msfadmin'+"\n")
				time.sleep(2)
				
				j=child.expect(['.*Password:' ,'[#\$] ','Last login',pexpect.TIMEOUT],timeout=15)
				commands_executed.append(str(child.after))
				if(j==0):
					self.print_Log( "Telnet is expecting Password-- supplying default Password")
					self.print_Log_info( "Telnet is expecting Password-- supplying default Password")
					child.sendline('msfadmin')
					commands_executed.append('msfadmin'+"\n")
					time.sleep(2)	
					k=child.expect(['.* login:' ,'[#\$] ','Last login:',pexpect.TIMEOUT],timeout=15)
					commands_executed.append(str(child.after)+"\n")
					if(k==2):
						self.print_Log( "Login Successful with password root "+str(k))
						self.print_Log_info( "Login Successful with password root "+str(k))
						self.Display_msg(child)
					else:
						self.print_Log( "Login Failed with default username and password  "+str(k))
						self.print_Log_info( "Login Failed with default username and password  "+str(k))
						self.Display_msg(child)
				else:
					self.print_Log( "Weak login -->Only default username was sufficient -- \n" +str(j) )
					self.print_Log_info( "Weak login -->Only default username was sufficient -- \n" +str(j) )
					self.Display_msg(child)
			elif(i==0):
				self.print_Log( "There is no route to host--The host is not up and running !!")
				self.print_Log_info( "There is no route to host--The host is not up and running !!")
				self.Display_msg(child)
			elif(i==2):
				self.print_Log( "The remote host has no service running on the supplied port :"+str(args[0]))
				self.print_Log_info( "The remote host has no service running on the supplied port :"+str(args[0]))
				self.Display_msg(child)
			else:
				self.print_Log( "Week security !!--Telnet can be logged in without any username and password -command :"+str(args[0]))
				self.print_Log_info( "Week security !!--Telnet can be logged in without any username and password -command :"+str(args[0]))
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])
			self.print_Log("Closing Child now !!")
			child.close(force=True)	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log("Closing Child now !!")
			self.print_Log_info("Exiting Imap interactive!!")
			child.close(force=True)	
			
		except Exception ,e:
			#
			self.print_Error( "Exception Imap_intaractive " +str(e))
			self.print_Error_info( "Exception Imap_intaractive " +str(e))
			self.print_Error(self.Display_msg(child))
			self.print_Error("Closing Child now !!")
			child.close(force=True)	
		



	def time_out_command(self,arg,timeout):
		"""
			Objective :
			The purpose of this method is to accomdate execution of all scripts that can be invoked with a
		 	single command along with host and port info and do not require any further interaction with
 			the user.The timeout parameter asks the controllor thread to wait for "n" units of time and
			even then if the external script does not finish execution then abort the execution of external
 			script such that other services and scriptsare not starved for execution.
		"""
		
		try:
		    print "Command is---> ::" +str(cmd)
		    print "hello world !!1"
		    #cmd ="nslookup google.com"
		    commands_executed=[]
		    exploit_result=''
		    self.print_Log( 'Thread started --with command '+str(cmd))
		    self.print_Log_info( 'Thread started --with command '+str(cmd))
		    commands_executed.append(cmd+"\n")		  
		    self.process=subprocess.Popen(cmd,shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)#best way to implement -->gives o/p in variable
		    
		    (output, err)=self.process.communicate() #seunicode characters.sends ouput continuesly.Thus we may not know in which chunk of o/p we would recieve unicode character.Its better to convert all output into utf-8 and then back to ascii with ignoring special characters/unicode characters
		    result = chardet.detect(output)
		    charenc = result['encoding']
		    print "Encoding used is --> : "+str(charenc)
		    if (charenc is not None):
		    		output=output.decode(charenc).encode('ascii','replace')
		    		err=err.decode(charenc).encode('ascii','replace')

		    self.print_Log_info( 'Thread finished')
		    self.general_op=(str(output)+"\n"+str(err)+"\n")
		    #return (str(output)+"\n"+str(err)+"\n")
		except Exception ,ee:
			self.print_Error("Exception in gneral :"+str(ee))
			self.general_op= "0" +str(ee)
			
		
			    
		    
	def threadControllor(self,cmd,timeout=100):
			"""
			Objective :
			The purpose of this method is to start a new thread which will inturn launch a new subprocess 
			and that subprocess will actually execute the external script.Further more the thread will wait 
			for the subprocess to complete its execution for the time specified in timeout parameter 
			(in secconds) ,and if teh sub process dors not finish within that time ,the thread kills the
			subprocess and recursively kills all its children processes(external scripts)
			"""
		
			thread = threading.Thread(target=self.execute_singleLine,args=(cmd,True))
			thread.start()
			timeout=100
			timeout_=int(timeout)
			print "Joined and waiting !!!\n\n"
			thread.join(timeout_)
			print "Timeout\n\n\n"
			#self.method_id="Dns_Ferice_Check()"
			if thread.is_alive():
				self.print_Log( 'Terminating process')
				self.print_Log_info( 'Terminating process')
				try:
					process = psutil.Process(self.process.pid)
					for proc in process.children(recursive=True):
							self.print_Log_info( "Killing Process with id -->"+str(proc))
							try:
								proc.kill()
							except Exception ,ew:
								self.print_Error("Exception while killing :"+str(ew))
							self.print_Log_info("Killed Process with id -->"+str(proc))
						
					
					try:
						process = psutil.Process(self.process.pid)
						if process:
							self.process.kill()
							thread.join(60)
							#commands_executed.append('Process killed--.timeout')
					except:
						self.print_Log("Parent Process already KIlled")	    
				except Exception ,ee:
					self.print_Error("Exception caught in th-controllor"+str(ee))
	    

	def Dns_FierceCheck(self,args):#Aur are send seperately cuz we need to do a reverse dns lookup also
		"""
			Objective :
			The purpose of this method is to check /conduct various checks related to DNS.
			It does dns fierce check for the host and also then for reverse dns of the host.
		"""
		
		try:
			commands_executed=[]
			exploit_result=''
			self.method_id="Dns_Ferice_Check()"
			
			self.print_Log("Launching FierceCheck with the given host --> "+str(args[1]))
			self.print_Log_info("Launching FierceCheck with the given host --> "+str(args[1]))
			cmd=str(args[0])+str(args[1])+str(args[2])
			print "command is " +cmd
			commands_executed.append(cmd+"\n")
		
		
			self.threadControllor(cmd,100)
			time.sleep(50)
			print "Not executed till thread is killed"
			#p = commands.getoutput(cmd)
			p=self.general_op
			print "Output ### is -->" +str(p)+"\n\n\n"
			self.print_Log(str(p))
			commands_executed.append(str(p) +"\n")
			host=self.getReverseDns(str(args[1]))
			self.method_id="Dns_Ferice_Check()"
			commands_executed.append("Result --> "+str(host))
			if(host!=-1):
				self.print_Log("Launching reverse DNS FierceCheck")
				self.print_Log_info("Launching reverse DNS FierceCheck")	
				cmd=str(args[0])+str(host)+str(args[2])
				commands_executed.append(cmd)
				self.threadControllor(cmd,100)
				p=self.general_op
				#p = commands.getoutput(cmd)
				commands_executed.append(str(p))
				self.print_Log( str(p))
			else:
				self.print_Log("There is no reverse dns resolution for ip :"+args[1])
				self.print_Log_info("There is no reverse dns resolution for ip :"+args[1])
				commands_executed.append("No reverse dns for ip -->" +args[1])
			
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])
		
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Exiting Dns_Ferice_check()")

		except Exception ,e:
			self.print_Error("Exception in Dns_FierceCheck "+str(e))
			self.print_Error_info("Exception in Dns_FierceCheck "+str(e))



	def Dns_ReconCheck(self,args):
		"""
			Objective :
			The purpose of this method is to check /conduct various checks related to DNS.
			It does dns_recon check for the host and also then for reverse dns of the host.
		"""
		
		try:
			commands_executed=[]
			exploit_results=''
			host=str(args[0])
			self.method_id="DNS_Recon_check()"
			self.print_Log("In Dns_recon check")
			self.print_Log_info("In Dns_recon check")
			commands_executed.append("Dns check : "+str(args[0]))
			rev_host=self.getReverseDns(host)
			commands_executed.append("Res:"+str(rev_host))
			print "Length of args : "+str(len(args))
			for i in range (1,len(args)):
				#print args[i]
				if (("<reversehost>" in args[i])):
					self.print_Log_info( "Comamnd to be launched -->" +str(args[i]))
					self.print_Log( "Comamnd to be launched -->" +str(args[i]))
					if((rev_host !=-1)):						
						cmd=args[i].replace("<reversehost>",rev_host)
						commands_executed.append(cmd+"\n")
						print "Updated command --> " +str(cmd)
						p = commands.getoutput(cmd)
						commands_executed.append(str(p)+"\n")
						self.print_Log( str(p)+"\n\n")
				else:
					cmd=args[i]
					commands_executed.append(cmd+"\n")
					self.print_Log("Launching Command --> :"+str(cmd))
					p = commands.getoutput(cmd)
					commands_executed.append(str(p)+"\n")
					self.print_Log( str(p)+"\n\n")

			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult :\n"+str(commands_executed[len(commands_executed)-1])	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Exiting Dns_recon check")
			
					#
		except Exception ,e:
			
			#child.close(force=True)	
			self.print_Error("Exception dns recon " +str(e))
			self.print_Error_info("Exception dns recon " +str(e))
			#.print_Error("Closing Child now !!")


	def start_sniffing(self,interface,timeout):
		"""
			Objective :
			The purpose of this method is to sniff network packets for various services using 
			terminal version of wireshark called as Tshark.This method would start the sniffer on 
			given interface.
			
			Todo:
			Right now the interface name is hardcoded to 'eth0' ,add additional aurguments to master json
			to accomdate this flexibility
		"""

		try:
			self.print_Log("IN Start_sniffing() method")
			self.print_Log_info("IN Start_sniffing() method")
			cmd="tshark -f 'port "+ str(self.current_port) +" and host "+ str(self.current_host) + "' -i "+str(interface)+" -a duration:"+str(timeout)+" -w "+ os.path.join(self.data_path,str(self.project_id)+"_"+str(self.current_host)+"_"+str(self.current_port)+"_capture-output.pcap")
			commands_executed=[]
			exploit_result=''
			commands_executed.append(cmd+"\n")
			self.print_Log("sniffing command is --> "+str(cmd))
			self.process_sniff=subprocess.Popen(cmd,shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
			(output, err)=self.process_sniff.communicate()
			commands_executed.append(str(output)+"\n"+str(err)+"\n")
			#commands_executed.append()
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			print "output is " +str(output) + "Error is " +str(err)
			self.print_Log_info("Exiting Start_sniffing() method")
		except 	Exception ,e:
			self.print_Log("Exception while sniffing !!"+str(e))
			self.print_Log_info("Exception while sniffing !!"+str(e))



	def execute_singleLine(self,cmd,result_=False,grep_commands=None):#A good thing is that even when a process is killed the thread resumes and details are saved
		"""
			Objective :
			The purpose of this method is to execute scripts that can be invoked by single line command
			and no timeout parameter is used here.
		"""

		try:
		    print "Command is---> ::" +str(cmd)
		    print "hello world !!1"
		    #cmd ="nslookup google.com"
		    commands_executed=[]
		    exploit_result=''
		    self.print_Log( 'Thread started --with command '+str(cmd))
		    self.print_Log_info( 'Thread started --with command '+str(cmd))
		    commands_executed.append(cmd+"")		  
		    polling_elements=[]
		    elements={}
		    output=''
		    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)) ,"polling_TC.json")
		    with open(file_path,"r+") as f:
		         elements=json.loads(f.read())
		         e=elements["entries"]
		         for item in e:
		            polling_elements.append(item)
		    print "Entries Read :" +str(polling_elements)
		    if self.command_id in polling_elements:
		            out_file=open(str(self.project_id)+"_"+str(self.command_id)+"_output.txt","w")
		            err_file=open(str(self.project_id)+"_"+str(self.command_id)+"_error.txt","w")
		            in_file=open(str(self.project_id)+"_"+str(self.command_id)+"_input.txt","w")
		            in_file.write('n')	
		            self.process=subprocess.Popen(cmd,shell=True,stderr=err_file,stdout=out_file,stdin=in_file)
		            err=''
		            try:
		                (output, err)=self.process.communicate()
		                out_file.close()
		                err_file.close()
		                in_file.close()
		                f=open(str(self.project_id)+"_"+str(self.command_id)+"_output.txt","r")
		                e=open(str(self.project_id)+"_"+str(self.command_id)+"_error.txt","r")
		                output=f.read()
		                err=e.read()
		                f.close()
		                e.close()
		                os.remove(str(self.project_id)+"_"+str(self.command_id)+"_error.txt")
		                os.remove(str(self.project_id)+"_"+str(self.command_id)+"_output.txt")
		                os.remove(str(self.project_id)+"_"+str(self.command_id)+"_input.txt")
		                if self.Kill:
		                     self.Kill=False
		                     err=err+"Killed@"
		            except Exception ,exx:
		                 if self.Kill:
		                    self.Kill=False
		                    err=err+"Killed@"
		    else:
		        self.process=subprocess.Popen(cmd,shell=True,stderr=subprocess.STDOUT,stdout=subprocess.PIPE)#best way to implement -->gives o/p in variable
		    	(output, err)=self.process.communicate() #seunicode characters.sends ouput continuesly.Thus we may not know in which chunk of o/p we would recieve unicode character.Its better to convert all output into utf-8 and then back to ascii with ignoring special characters/unicode characters
		    result = chardet.detect(output)
		    charenc = result['encoding']
		    #print "Encoding used is --> : "+str(charenc)
		    if (charenc is not None):
		            output=output.decode(charenc).encode('ascii','replace')
		            if err is not None:		
		    		     err=err.decode(charenc).encode('ascii','replace')
		            else:
		                 err=''
		                 if self.Kill:
		                     self.Kill=False
		                     err=err+"Killed@"
		    commands_executed.append(str(output)+"\n"+str(err)+"\n")	
		    parent_output=str(output)
		    exploit_result="Command Executed :"+commands_executed[0]+"\n"
		    exploit_result=exploit_result+"\nResult"+str(commands_executed[len(commands_executed)-1])
		    commands_executed[len(commands_executed)-1]="\nEnd"
		    self.print_Log( 'Thread finished')
		    self.print_Log_info( 'Thread finished')
		    if(result_==False):
				#print "Execution result : "+str(exploit_result)
				#print "Hello"
				self.SaveDetails((str(commands_executed)),exploit_result)
				var=0
				if grep_commands !=None :
					for dic in grep_commands:
						if var <1:
							#var =1
							try:#for kk ,vv in dic.iteritems():
								#var=1
								kk=dic["id"]
								vv=dic["grep_string"]
								commands_executed=[]
								self.command_id=kk
								command=cmd +" | "+ str(vv)
								commands_executed.append(command+"\n")
								to_execute="echo "+"'"+str(parent_output) +"'" +"|" +str(vv)
								split_output=parent_output.split("\n")
								counter_var=0
								result="None"
								output=''
								for op in split_output:
									
									if vv in op:
										#print "Found at counter val :"+str(counter_var)
										output=op
										after_val=int(dic["after"])
										before_val=int(dic["before"])
										grep_before=''
										if before_val !=0:	
											before_counter=counter_var-before_val
											#print "Before counter is : "+str(before_counter)
											for i in range(before_counter,counter_var):	
												grep_before=grep_before +"\n"+split_output[i] 
										grep_after=''	
										if after_val !=0:	
											after_counter=counter_var+after_val
											for i in range(counter_var +1 ,after_counter):	
												grep_after=grep_after +"\n"+split_output[i] 
										output=grep_before +"\n"+ output +"\n"+ grep_after
										break
									counter_var=counter_var + 1
								result=chardet.detect(output)
								charenc = result['encoding']
								if (charenc is not None):
										output=output.decode(charenc).encode('ascii','replace')
										if err is not None:		
											 err=err.decode(charenc).encode('ascii','replace')
										else:
											 err=''
											 if self.Kill:
												 self.Kill=False
												 err=err+"Killed@"
								if err==None:
									err=""
								commands_executed.append(str(output)+"\n"+str(err)+"\n")	
								exploit_result="Command Executed :"+commands_executed[0]+"\n"
								exploit_result=exploit_result+"\nResult\n"+str(commands_executed[len(commands_executed)-1])
								commands_executed[len(commands_executed)-1]="\nEnd"
								self.SaveDetails((str(commands_executed)),exploit_result)
							except Exception ,exc:
								print "INternal Exception " +str(exc)
								self.print_Error( "Inner Exception - " +str(exc))
								self.print_Error_info( "Inner Exception" +str(exc))
						
						
		    else:
				self.general_op=(str(output)+"\n"+str(err)+"\n")
			#return str(str(output)+"\n"+str(err)+"\n")	 
		    
		   
		    
		
		except Exception ,e :
			print "EXception " +str(e)
			self.print_Error( "Exception in thread " +str(e))
			self.print_Error_info( "Exception in thread " +str(e))
	
	def test_ssl(self,args):
		"""
			Objective :
			The purpose of this method is to execute test_ssl.py script .The script detects various ciphers
 			used and is only customized for this purpose.It could have not been accomdated in
 			General_interactive catagory and thus we had to write custom code for this
		"""

		try:
			
			self.method_id="Test_ssl"
			self.print_Log_info("Starting Test ssl")
			cmd=args[1]
			to=args[0]
			print( 'Thread started --with command '+str(cmd))		   	
			commands_executed=[]
			exploit_result=''
			commands_executed.append(cmd+"\n")
			child = pexpect.spawn(cmd)
			i=child.expect(['.*Proceed ?.*','.* Unable to open a socket to .*',pexpect.TIMEOUT,pexpect.EOF],timeout=int(to))
			if (i==0):
				print "\n\nReached at here"+str(child.after)				
				child.sendline('yes')
				#commands_executed.append('yes')
				j=child.expect(['.*Proceed ?.*','.* Unable to open a socket to .*',pexpect.TIMEOUT,pexpect.EOF],timeout=int(to))
				print "J is --" +str(j)+"\n\n\n\n"+str(child.before)+"   "+str(child.after)+"\n\n\n\n\n"
				commands_executed.append(str(child.before)+str(child.after))	
			if(i==2):
				commands_executed.append(str(child.after)+"Time out -It seems host is down")	
			if(i==3):
				commands_executed.append(str(child.before)+str(child.after)+"End of file -")			
		   		

			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult\n"+str(commands_executed[len(commands_executed)-1])	
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Stopping Test ssl")
			child.close(force=True)
		except Exception ,e :
			
			self.print_Error("Exception general interactive " +str(e))
			self.print_Error_info("Exception general interactive " +str(e))
			self.print_Error("Closing Child now !!")
			child.close(force=True)

	def general_interactive_special_char(self,args):
		"""
			Objective :
			The purpose of this method is to execute teh interactive scripts or kali tools which 
			return various special charactes which need to be decoded first to interpret meaning from them
			before passing the next command of interaction
		"""

		try:
			self.method_id="general_interactive_special_char()"
			self.print_Log("Starting Special char-Interactive Session with command --> "+str(args[1]) +" and timeout " +str(args[0]))
			cmd=args[1]
			timeout=args[0]
			child=pexpect.spawn(cmd)
			commands_executed=[]
			commands_executed.append(cmd+"\n")
			exploit_result=''
			
			self.print_Log_info("Starting Special char-Interactive Session with command --> "+str(args[1]) +" and timeout " +str(args[0]))
			for i in range(2,len(args),2):
				#print "Commands are --" +str(args[i]) +   "   " +str(args[i+1])
				#child.sendline(args[i])
				#time.sleep(2)
				arg_list=[]
				check_list=[]
				#<<<<<<< HEAD
				arg_list=list(args[i])
				#=======
				#arg_list=args[i]
				#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
				check_list=arg_list.pop(0).split(',')
				count=len(arg_list)-1
				arg_list.append(pexpect.TIMEOUT)
				check_list.append(str(count+1))
				arg_list.append(pexpect.EOF)
				check_list.append(str(count+2))
				self.print_Log("Arg list is --> "+str(arg_list))
				commands_executed.append(str(arg_list))
				self.print_Log("check list is --> "+str(check_list))
				print "Waiting for 60 sec"
				#<<<<<<< HEAD
				j=child.expect(arg_list,120)
				#=======
				#j=child.expect(arg_list,60)
				#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
				print "The value of j is :"+str(j)
				print str(child.after)+"\n\n"+str(child.before)
				#commands_executed.append(str(child.after)+"\n")
				commands_executed.append("\n"+str(child.before)+"\n"+str(child.after))
				time.sleep(2)
				print "J is "+str(j) +"\n and i is " +str(i)
				if(str(j) in check_list):
					self.print_Log("Before :"+str(child.before) + "\n" + "After : "+str(child.after)+" j is "+str(j) )
					if((i+1)<len(args)): # i can never be == len (args) as i is an even number and len args wil always be odd
						child.send(args[i+1])
						child.send('\r')
						commands_executed.append(args[i+1]+"\n")
						self.print_Log("Just sent command -->  "+str(args[i+1]))
						time.sleep(2)
					continue;
				else:
					self.print_Log("Results not as expected --> see aurguments " +str(j) +"\n"+str(child.before) + "  " + str(child.after))
					self.print_Log_info("Results not as expected --> see aurguments ")
					break
			#self.print_Log("Closing Child !")
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log("Before : "+str(child.before)+"After : "+str(child.after))
			self.print_Log("Closing Child now !!")
			child.sendcontrol('z')
			child.sendcontrol('c')
			child.close(force=True)	
			self.print_Log_info("Exiting general Interactive with special char()")
					
		except Exception ,e:
			self.print_Error("Exception general interactive " +str(e))
			self.print_Error_info("Exception general interactive " +str(e))
			self.print_Error("Closing Child now !!")
			child.close(force=True)
			


	def general_interactive(self,args):
		"""
			Objective :
			This is a generic and important method and the purpose of this method is to accomdate most of
 			the interactive commands /tools that require user interaction.It automates the whole process
			and there are various scripts that are executed using this method by passing appripriate
			script aurguments to this method.
		"""

		try:
			print "Inside general interactive"
			self.method_id="General_Interactive()"
			self.print_Log("Starting Interactive Session with command --> "+str(args[1]) +" and timeout " +str(args[0]))
			self.print_Log_info("Starting Interactive Session with command --> "+str(args[1]) +" and timeout " +str(args[0]))
			cmd=args[1]
			timeout=args[0]
			child=pexpect.spawn(cmd)
			commands_executed=[]
			commands_executed.append(cmd+"\n")
			exploit_result=''
			print "here"
			for i in range(2,len(args),2):
				#print "Commands are --" +str(args[i]) +   "   " +str(args[i+1])
				#child.sendline(args[i])
				#time.sleep(2)
				arg_list=[]
				check_list=[]
				#<<<<<<< HEAD
				arg_list=list(args[i])
				#print "Initial arg list is ;"+str(arg_list) 
				check_list=arg_list.pop(0).split(',')
				#print "Initial check list is :::: " +str(check_list)
				#=======
				#arg_list=args[i]
				#check_list=arg_list.pop(0).split(',')
				#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
				count=len(arg_list)-1
				arg_list.append(pexpect.TIMEOUT)
				check_list.append(str(count+1))
				arg_list.append(pexpect.EOF)
				check_list.append(str(count+2))
				self.print_Log("Arg list is --> "+str(arg_list))
				#<<<<<<< HEAD
				#commands_executed.append("\nThe console would produce a pattern similar to following :\n "+str(arg_list)+"\n")
				self.print_Log("check list is --> "+str(check_list))
				print "Waiting for 60 sec"
				j=child.expect(arg_list,120)
				commands_executed.append(str(str(child.before)+"\n\nConsole is Now expecting :"+str(arg_list[j])+"\n\n\nActual Output by console \n:"+str(child.after)+"\n\n").replace("<class 'pexpect.EOF'>","Console Ended").replace("<class 'pexpect.exceptions.TIMEOUT'>","Time out").replace("<class 'pexpect.exceptions.EOF'>","Console Ended"))#
				#=======
				#commands_executed.append("\nThe console would produce a pattern similar to following :\n "+str(arg_list)+"\n")
				#self.print_Log("check list is --> "+str(check_list))
				#print "Waiting for 60 sec"
				#j=child.expect(arg_list,120)
				#commands_executed.append(str("\nThe index of item that console produced is :"+str(j)+"\n\n"+str(child.before)+"\n:"+str(child.after)+"\n\n").replace("<class 'pexpect.EOF'>","Console Ended").replace("<class 'pexpect.TIMEOUT'>","Time out"))
				#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
				time.sleep(4)
				print "J is "+str(j) +"\n and i is " +str(i)
				if(str(j) in check_list):
					self.print_Log("Before :"+str(child.before) + "\n" + "After : "+str(child.after)+" j is "+str(j) )
					if((i+1)<len(args)): # i can never be == len (args) as i is an even number and len args wil always be odd
						child.sendline(args[i+1])
						#<<<<<<< HEAD
						commands_executed.append("Writing on console : "+args[i+1]+"\n")
						#=======
						#commands_executed.append(args[i+1]+"\n")
						#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
						self.print_Log("Just sent command -->  "+str(args[i+1]))
						time.sleep(2)
					continue;
				else:
					#<<<<<<< HEAD
					self.print_Log("Results not as expected --> see aurguments " +str(j) +str(arg_list[j]) +"\n"+str(child.before) + "  " + str(child.after))
					#=======
					#self.print_Log("Results not as expected --> see aurguments " +str(j) +"\n"+str(child.before) + "  " + str(child.after))
					#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
					self.print_Log_info("Results not as expected --> see aurguments ")
					break
			#self.print_Log("Closing Child !")
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nOutput\n"+str(commands_executed[len(commands_executed)-1])	
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log("Before : "+str(child.before)+"After : "+str(child.after))
			self.print_Log("Closing Child now !!")
			child.sendcontrol('z')
			child.sendcontrol('c')
			child.close(force=True)	
			self.print_Log_info("Exiting General_interactive()")
					
		except Exception ,e:
			self.print_Error("Exception general interactive " +str(e))
			self.print_Error_info("Exception general interactive " +str(e))
			self.print_Error("Closing Child now !!")
			child.close(force=True)	

	
	def generalCommands_Tout_Sniff(self,arg,interactive=False): #note see the methods which inoke other methods
		"""
			Objective :
			The purpose of this method is to start a traffic sniffer and immidiately after that execute the
 			external script which would do vulnerability scanning on given service and the sniffer would
 			capture traffic in the background.The moment the external script would finish execution the 
			method would stop the sniffer.Important point is thet ,the external script is executed with
			timeout value.If the script does not complete within given time frame both sniffer and external 			process would be stopped
		"""

		try:
			commands_executed=[]
			exploit_result=''
			self.method_id="General_Commands_Timeout_sniff()"
			self.print_Log("Starting single line + Sniff")
			self.print_Log_info("Starting single line + Sniff")
			commands_executed.append('starting sniffing')
			#<<<<<<< HEAD
			thread = threading.Thread(target=self.start_sniffing,args=("eth0","200",))
			#=======
			#thread = threading.Thread(target=self.start_sniffing,args=("eth0","100",))
			#>>>>>>> b6b8e9ee72399e3d683c7808a85d7f1c8ce3cbf6
			thread.start()
			time.sleep(3)
			if (interactive==False):
				self.singleLineCommands_Timeout(arg) #this will act as join here and next line will execute after packets are sent
			else:
				self.general_interactive(arg)
			self.method_id="General_Commands_Timeout_sniff()"
			if thread.is_alive():
				self.print_Log('Terminating Sniffing process')
				self.print_Log_info('Terminating Sniffing process')
				try:
					process = psutil.Process(self.process_sniff.pid)
					for proc in process.children(recursive=True):
							print "Killing Process with id -->"+str(proc)
							try:
								proc.kill()
							except Exception ,ew:
								print "Exception while killing :"+str(ew)

					#self.process.terminate()
					try:
						process = psutil.Process(self.process_sniff.pid)
						if process:
							self.process_sniff.kill()
							thread.join(60) #wait only for 1 minute
							print "Kill result is --> "+str(self.process_sniff.returncode)
					except:
						self.print_Log("Parent process already killed:")
					commands_executed.append('Finished  sniffing-->Details are in pcap file')
					exploit_result="Command Executed :"+commands_executed[0]+"\n"
					exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])
					#self.SaveDetails(''.join(commands_executed),exploit_result)
					
				except Exception ,ee:
					self.print_Error("Exception in killing process --> "+str(self.process_sniff.returncode) +str(ee))
					self.print_Error_info( "Exception in killing process --> "+str(self.process_sniff.returncode) +str(ee))
			
			self.print_Log_info("Exiting general_commands_tout_sniff()")
		except Exception ,e:
			self.print_Error("Exception in SingleLineCommands_Tout" +str(e))
			self.print_Error_info("Exception in SingleLineCommands_Tout" +str(e))	
	

	def singleLineCommands_Timeout(self,arg,grep_commands=None):   #see in this case its not necessaer to update result since it would be uodated by the other mrth	
			"""
			Objective :
			The purpose of this method is to execute scripts that can be invoked with single line command
 			and it internally invokes the earlier discussed single_line command method.
			"""
		
			self.method_id="Execute_Single_line_timeout()"
			self.print_Log("In method SingleLineCommands_Timeout()")
			self.print_Log_info("In method SingleLineCommands_Timeout()")
			commands_executed=[]
			commands_executed.append(arg[1])
			if grep_commands ==None:
				thread = threading.Thread(target=self.execute_singleLine,args=(arg[1],))
			else:
				print "In else with grep as true "
				thread = threading.Thread(target=self.execute_singleLine,args=(arg[1],False,grep_commands))
			thread.start()
			timeout=int(arg[0])
			thread.join(timeout)
			self.method_id="Execute_Single_line_timeout()"
			if thread.is_alive():
				self.print_Log( 'Terminating process')
				self.print_Log_info( 'Terminating process')
				try:
					process = psutil.Process(self.process.pid)
					for proc in process.children(recursive=True):
							self.print_Log_info( "Killing Process with id -->"+str(proc))
							try:
								self.Kill=True
								proc.kill()
								time.sleep(1)
								
								
							except Exception ,ew:
								print "Exception while killing :"+str(ew)

							
							self.print_Log_info( "Killed Process with id -->"+str(proc))
						
					#self.process.terminate()
					try:
						process = psutil.Process(self.process.pid)
						if process:
							self.Kill=True
							self.process.kill()
							
							thread.join(60)#wait for 1 minute ,if we dont set limit here the remaining code would halt
							commands_executed.append('Process killed--.timeout')
					except:
						self.print_Log("Parent Process already KIlled")
					
					self.print_Log( "Kill result is --> "+str(self.process.returncode))
					self.print_Log_info( "Kill result is --> "+str(self.process.returncode))
					exploit_result="Command Executed :"+commands_executed[0]+"\n"
					exploit_result=exploit_result+"\nResult:\n"+str(commands_executed[len(commands_executed)-1])
					
					#self.SaveDetails(''.join(commands_executed),exploit_result)	
				except Exception ,ee:
					self.print_Error( "Exception in killing process --> "+str(self.process.returncode) +str(ee))
					self.print_Error_info( "Exception in killing process --> "+str(self.process.returncode) +str(ee))
			
		

	def getHost(self,result): #no need to put results here--its intermediate results
		"""
			Objective :
			The purpose of this method is to parse the output from nslookup and return host from ip.
		"""

		index=result.find("name =")
		
		if(index !=-1):
			index=index+6
			actual_host=result[index:]
			actual_host=actual_host.lstrip()
			index_last=actual_host.find("\n")
			if(index_last!=-1):
				actual_host=actual_host.replace("\n","")
				actual_host=actual_host[:index_last-2]
				actual_host.rstrip()
				
				print "Actual host is "+actual_host
				return actual_host
			else:
				print "Actual host is "+actual_host
				return actual_host
		else:
			print "Name not found !!"
			print str(result)
			return -1

	def getReverseDns(self,host):#ret again intermediate results
		"""
			Objective :
			The purpose of this method is to use nslookup to transform ip->domain name"
		"""

		try:
			#host='google.com'
			self.method_id="getReverseDns()"
			self.print_Log( "Dns reverse lookup")
			self.print_Log_info( "Dns reverse lookup")
			commands_executed=[]
			exploit_result=''
			self.print_Log_info("Recieved host is : "+str(host))
			child = pexpect.spawn("nslookup "+str(host))
			commands_executed.append('nslookup ' +str(host))
			i=child.expect(['Address: .*',".* server can't find .*",".* name = .*",pexpect.EOF,pexpect.TIMEOUT],timeout=15)
			commands_executed.append(str(child.after))
			self.print_Log(str(i))
			if (i==0):
				self.print_Log( "Reverse dns successful")
				self.print_Log_info( "Reverse dns successful")
				self.Display_msg(child)
				result=str(child.after)
				index=result.find(":")
				index=index+1
				actual_host=result[index:]
				actual_host=actual_host.lstrip()
				self.print_Log("Actual host is "+actual_host)
				self.print_Log_info("Actual host is "+actual_host)
				self.print_Log("Closing Child now !!")
				self.print_Log_info( "Exiting getReverseDns()")
				child.close(force=True)
				return actual_host
				#self.print_Log( str(i)
			elif (i==2):
				self.print_Log( "Reverse dns partially successful")
				self.print_Log_info( "Reverse dns partially successful")
				self.print_Log_info( "Exiting getReverseDns()")
				result=str(child.after)
				actual_host=self.getHost(result)
				self.print_Log("Closing Child now !!")
				child.close(force=True)
				return actual_host
					
			elif(i==3):
				self.print_Log( " (2)-->Reverse dns Timed out")
				self.print_Log_info( " (2)-->Reverse dns Timed out")
				result=str(child.before)
				actual_host=self.getHost(result)
				self.print_Log_info( "Exiting getReverseDns()")
				self.print_Log("Closing Child now !!")
				child.close(force=True)
				return actual_host

			else:
				self.print_Log( "Reverse dns Failed")
				self.print_Log_info( "Reverse dns Failed")
				self.print_Log_info( "Exiting getReverseDns()")
				self.Display_msg(child)
				self.print_Log("Closing Child now !!")
				child.close(force=True)
				return -1
		

		except pexpect.TIMEOUT,e:
			self.print_Error("Time out exception in pexpect !!"+str(e))
			self.print_Error_info("Time out exception in pexpect !!"+str(e))
			self.print_Error("Closing Child now !!")
			child.close(force=True)
			return -1
            		#pass
        	except pexpect.EOF,e:
           		self.print_Error("EOF exception in pexpect !!" +str(e))
			self.print_Error_info("EOF exception in pexpect !!" +str(e))
			self.print_Error("Closing Child now !!")
			child.close(force=True)
			return -1
		except Exception ,e:
			self.print_Error("Exception in Reverse Dns !!"+str(e))
			self.print_Error_info("Exception in Reverse Dns !!"+str(e))
			self.print_Error(self.Display_msg(child))
			self.print_Log("Closing Child now !!")
			child.close(force=True)
			return -1

	def singleLineCommands(self,args):
		"""
			Objective :
			The purpose of this method is to execute scripts that can be invoked with single line command
 			and it internally invokes the earlier discussed single_line command method without timeout.
		"""

		try:
			commands_executed=[]
			exploit_result=''
			self.method_id="SingleLineCommands()"
			self.print_Log( "\nInvoking Single line command -->Title-->" +str(args[0])+"\n")
			self.print_Log_info( "\nInvoking Single line command -->Title-->" +str(args[0])+"\n")
			cmd=args[0]
			commands_executed.append(cmd+"\n")
			p = commands.getoutput(cmd)
			commands_executed.append(str(p))
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult\n"+str(commands_executed[len(commands_executed)-1])
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)	
			self.print_Log( str(p))
			self.print_Log( "\nExiting Single line command -->Title-->" +str(args[0])+"\n")
			
		except Exception ,e:
			self.print_Error( "Exception single Line   "+ str(e))
			self.print_Error_info( "Exception single Line   "+ str(e))

	def http_based(self,args):
		"""
			Objective :
			The purpose of this method is to execute http based checks that request external urls using
 			python get request to fetch data.
		"""

		try:
			commands_executed=[]
			exploit_result=''
			self.method_id="Http_based()"
			self.print_Log("Inside HttpBased()")
			self.print_Log_info("Inside HttpBased()")
			self.print_Log("Args are : "+str(args[0]))
			commands_executed.append('requests.get('+str(args[0])+')')	
			response = requests.get(str(args[0]))
			
			self.print_Log( "Status code is : "+str(response.status_code))
			self.print_Log_info( "Status code is : "+str(response.status_code))
			html = response.text
			commands_executed.append("http-response" +str(html))
			file_ = open('response.html', 'w+')
			file_.write(html.encode('utf8'))
			file_.close()
			exploit_result="Command Executed :"+commands_executed[0]+"\n"
			exploit_result=exploit_result+"\nResult\n"+str(commands_executed[len(commands_executed)-1])
			#exploit_result="\nResult"+exploit_result+str(commands_executed[len(commands_executed)-1])
			#self.SaveDetails(''.join(commands_executed),exploit_result)
			self.SaveDetails(str(commands_executed),exploit_result)
			self.print_Log_info("Exiting  HttpBased()")
			
		except Exception ,ee:
			self.print_Error( "Exception Http_based " +str(ee))
			self.print_Error_info( "Exception Http_based " +str(ee))

	

