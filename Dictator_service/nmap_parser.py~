"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to parse the nmap xml report.
On parsing the report the details are saved in the database table such that
the same details could be used in order to perform vulneraibility scanning on the generated project id.
"""

from libnmap.parser import NmapParser
import IPtable

IPtable=IPtable.IPtable()

def Import(mode='c',report_name='',project_name='',pid=''):
	"""
	Objective :
	The method Import takes the nmap file as input if the mode of operation is gui 
	and if mode is CLI then it prompts the user to provide the path of the nessus file.
	Once the user provides the path ,this method would start parsing the report and would
	save the parsed report in the database table and would return the project id of the newly registered 
	project.The user can reffer this project id in order to start vulnerability scanning.
	"""

	try:
		return_val={}
		if mode=='c':
			report_name=raw_input("Enter name of report with extention")
			project_name=raw_input("Enter name of project you wish to save report with :")

		if report_name == None or report_name =="" or project_name == None or project_name =="" :
			return
	
		
		if mode=='c':
			pid=IPtable.Insert(project_name,'import','import')
			print "Kindly note the project id is : "+str(pid) 
			print "You can use the above generated project id for launching scans !! "

		BulkList=[]
		BulkList.append((pid,'import','import','incomplete'))
		status=IPtable.InsertAll(BulkList)
		print "Parsing the report ....."
		bulk_list=''
		bulk_list+='host;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe'
		bulk_list+='\n'
		if (report_name):
			report=NmapParser.parse_fromfile(report_name)
			#print "Scan summary : {0} ".format(report.summary)
			hosts=report.hosts
			for host in hosts:
				#print str(host)
				if host.is_up():
					portso=host.get_open_ports()
					for port in portso:
						service =host.get_service(port[0],port[1])
						bulk_list+=str(host.address)+";"+str(port[1])+";" +str(port[0])+";"+service.service+";"+service.state+";"+";"+";"+";"+";"+";"
						bulk_list+='\n'
					
		print "\n\n\n"
		IPtable.Update(bulk_list,'import','import',int(pid))
		status='complete'
		IPtable.UpdateStatus(status,'import','import',int(pid))
		print "Clearing logs and about to complete..."
		IPtable.clearLogs(pid,'complete')
		print "Cleared logs"

		print "Please go and launch exploits for the current project id : "+str(pid)
		return_val["status"]="success"
		return_val["value"]="1"

		print "\n\n\n\n"
		print str(bulk_list)
		return return_val

	except Exception ,ee:
		return_val={}
		return_val["status"]="failure"
		return_val["value"]=str(ee)
		return return_val

#Import()
