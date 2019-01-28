"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:12/30/2016

Objective :
The purpose of this file /module /Class is to take data from the user to initiate discovery process of a new scan.Basically this class is used with the CLI model of code and it takes the user inputs like host-range,
Port range ,Project name ,scan type and etc and then finally invokes the class main_class_based_backup.py in order to start the scan with the chosen user settings and configuration.Thus this class is a seperation between the logic that collects user input fpr starting new scan or resuming paused scan ,and once the user 
input is collected ,at that time the process of discovery starts with invoking the mentioned class (main_class_based_backup.py)


"""

import main_class_based_backup as main
import os
import ConfigParser
import time

r = '\033[31m' #red
b = '\033[34m' #blue
g = '\033[32m' #green
y = '\033[33m' #yellow
m = '\033[34m' #magenta
c = '\033[36m' #magenta
e = '\033[0m' #end
#obj=main()
class Driver_main():
	"""
	Objective :
	This is the class which only takes user input for CLI mode and verifies weather the supplied input
	is proper and if yes then control is passed onto the main processing class.
	"""
	
	def __init__(self):
		"""
		Objective :
		This is the constructor of the class and it creates instance of main processing class :
		main_class_based_backup.py
		"""
	
		self.NmapScanObj=main.NmapScan()

	def prompt_ScanType(self):
		"""
		Objective :
		This method takes user choice of weather user wants to launch a new scan or wants to launch an
 		earlier paused scan.

		"""

		while 1:
			scanType=raw_input(b+"Enter Your choice: \n"+y +"\n(1) For Launching New Scan \n(2) For Launching Paused Scans\n "+e)
			try:
				if(((scanType)=="1")or((scanType) =="2")):
					break
					
				else :
					print "Invalid Choice"
					#return scanType;
			except :
				return "1";
		return scanType;

	def seperator(self):
		print r+ "----------------------------------------------" +e


	def create_schema(self):
		"""
		Objective :
		This is an obselete method and was used earlier when the code was using sqllite in the backend .
		With this method the schema of backend tables can be created at run time.Kept for backward
 		compatibility
		"""

		with open(schema_file, 'rt') as f:
			schema = f.read()
		conn.executescript(schema)


	def prompt_project(self):
		"""
		Objective :
		This mathod takes project name from the user and returns it
		"""

		projectname=raw_input(b+"What is your Project name(no white spaces)? \n>"+y)
		return projectname

	def prompt_ips(self):
		"""
		Objective :
		This method takes the IP range from the user and reurns it
		"""

		ips=raw_input(b+"Type the IP range: \n>"+y)
		IP=ips
		return ips

	def prompt_ports(self):
		"""
		Objective :
		This method takes the Port range from the user and returns it
		"""

		ports=raw_input(b+"Enter the Port number or Ports range: \n>"+y)
		#global PORT
		if ports == "":
			self.PORT=None
		elif(ports=="*"):
			self.PORT="1-65535"
		else:
			self.PORT=ports

		return self.PORT

	def scanbanner(self):
		"""
		Objective :
		This method would print the scan banner and would show the mapping between the user choice and 
		scan prefernces.For example it displays a message that choose (1) for intense scan 
		(2) For full udp scan and etc.
		"""

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

	def banner(self,):
		"""
		Objective :
		This method prints the nmap scan banner on console 
		"""

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
		print g+" ###"+b+"                                                           "+g+"### "+e
		print g+" ################################################################# "+e

	def start(self):
		"""
		Objective :
		This is the start method and would initiate the process of collection ofscan information from
		the user and once all the information is gathered it shall go ahead and start the scan by invoking
		main class -->main_class_based_backup.py
		"""

		self.method_id="Main"
		self.banner()

		if os.geteuid() != 0:
			exit( r+ "\n You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting."+e)
		#clearLogs()
		scan_type=self.prompt_ScanType();
		print "Scan type chosen is :"+str(scan_type)
		self.seperator()
		if (scan_type=="1"):
			targethosts=self.prompt_ips() 
			
			self.seperator()
			self.scanbanner()
			print "self.SWITCH: " + g+ self.SWITCH +e
			self.seperator()

			if int(self.takescan)>7:
				targetports=None
			else:
				targetports=self.prompt_ports() 

			#print self.PORT
			self.seperator()

			path=self.prompt_project()
			path=''.join(path.split()).lower()
			self.NmapScanObj.driver_main(targethosts,path,targetports,scan_type,self.SWITCH,'',mode="c")

		elif(scan_type=="2"):
			self.scanbanner()
			print "self.SWITCH: " + g+ self.SWITCH +e
			self.NmapScanObj.driver_main('','','',scan_type,self.SWITCH,'',mode="c")



obj=Driver_main()
obj.start()
			
