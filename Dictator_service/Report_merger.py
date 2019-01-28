import Qualys_parser
import Nessus_parser
import IPexploits
import itertools
class Report_merger:
	def __init__(self,Nessus_report=None,Qualys_report=None):
		self.Nessus_report=None
		self.Qualys_report=None
		self.nessus_all_hosts=[]
		self.mannual_all_hosts=[]	
		self.qualys_all_hosts=[]
		self.nessus_extra_hosts=[]
		self.qualys_extra_hosts=[]
		self.mannual_extra_hosts=[]
		self.mannual_host_port=[]
		self.nessus_host_port=[]
		self.qualys_host_port=[]
		self.mannual_extra_port_per_host=[]
		self.nessus_extra_port_per_host=[]
		self.qualys_extra_port_per_host=[]
			
		if Nessus_report:
			self.Nessus_report=Nessus_report
		if Qualys_report:
			self.Qualys_report=Qualys_report

	def generate_report(self,project_id):
		try:
			mannual_results=None
			mannual=IPexploits.IPexploits()
			mannual_results=mannual.generate_report_GUI(project_id)
			nessus=Nessus_parser.Nessus_Parser()
			qualys=Qualys_parser.QualysParser()
			nessus_results=None
			qualys_results=None
			if (self.Nessus_report):
				nessus_results=nessus.parse(self.Nessus_report)
			if (self.Qualys_report):
				qualys_results=qualys.parse(self.Qualys_report)
			self.start_merging(mannual_results,nessus_results,qualys_results)
		except Exception,ee:
			print "Exception caught :"+str(ee)

	def start_merging(self,mannual_results=None,nessus_results=None,qualys_results=None):
		try:
			if (mannual_results and nessus_results and qualys_results ):
					self.merge_all(mannual_results,nessus_results,qualys_results)
			elif (mannual_results and nessus_results):
					self.merge_mn(mannual_results,nessus_results)
			elif (mannual_results and qualys_results):
					self.merge_mq(mannual_results,qualys_results)
			elif (mannual_results):
					self.merge_m(mannual_results)
			elif (nessus_results and qualys_results):
					self.merge_nq(nessus_results,qualys_results)						
		except Exception ,ee:
			print "Exception while generating report :"+str(ee)
	

	def merge_mq(self,mannual_results,qualys_results):
			print "In merge mq"

	def merge_m(self,mannual_results):
		print "Inside merge mannual only "

	def get_nessus_details(self,nessus_results,host,port):
		try:
			items_=[]
			for hosts in nessus_results:
					if hosts["host"].strip() ==host:
						details_nessus=hosts["value"]
						for items in details_nessus:
								if items["port"].strip()==port:
									items_.append(items)
									#return items
						return items_	
						#returnturn found
			
		except Exception ,ee:
			print "Exception get nessus details : "+str(ee)


	def get_qualys_details(self,qualys_result,host,port):
		try:
			qualys_results={}
			#print "hello here "+str(qualys_results)
			for hosts in qualys_result:
					#print str(hosts)
					if hosts["host"].strip() ==host:
						#print "Reached 11"
						details_q=hosts["vulns"]
						items_=[]
						for items in details_q:
								
								if items["port"].strip()==port:
									items_.append(items)
						qualys_results["vulns"]=items_


						items_=[]
						details_q=hosts["infos"]
						for items in details_q:
								
								if items["port"].strip()==port:
									items_.append(items)
						qualys_results["infos"]=items_

						items_=[]
						details_q=hosts["services"]
						for items in details_q:
								
								if items["port"].strip()==port:
									items_.append(items)
						qualys_results["services"]=items_

						
						return qualys_results				#return items
								
						#return found
			
		except Exception ,ee:
			print "Exception get nessus details : "+str(ee)


	def init_port_host(self,mode,mannual_results=None,nessus_results=None,qualys_results=None):
		try:
			if mode=='all':
				
				for ent in mannual_results:
					h_p={}
					host_ports=[]
					for e in ent["value"]:
						#print str(e)
						#print "000--->"+str(e["port"])
						host_ports.append(e["port"])
					#print "1"
					host_ports=list(set(host_ports))
					h_p[ent["host"]]=host_ports
					
					self.mannual_host_port.append(h_p)
					#print str(self.mannual_host_port)
				
				for ent in nessus_results:
					h_p={}
					host_ports=[]
					for e in ent["value"]:
						host_ports.append(e["port"])
					host_ports=list(set(host_ports))
					h_p[ent["host"]]=host_ports
					self.nessus_host_port.append(h_p)


				for ent in qualys_results:
					h_p={}
					host_ports=[]
					try:
						for e in ent["vulns"]:
							host_ports.append(e["port"])
						for e in ent["infos"]:
							host_ports.append(e["port"])
						for e in ent["services"]:
							host_ports.append(e["port"])

					except Exception ,eex:
						print "Append exception : "+str(eex)

					host_ports=list(set(host_ports))
					h_p[ent["host"]]=host_ports
					self.qualys_host_port.append(h_p)

						
				print "Mapping mannual :" +str(self.mannual_host_port)
				print "Mapping nussys :" +str(self.nessus_host_port)
				print "Mapping qualys :" +str(self.qualys_host_port)

				print "\n\n\n"
				#print "Mapping manual only :"+str(self.mannual_extra_port_per_host)
		except Exception ,ee:
				print "Exception !! :"+str(ee)

	def init_hosts(self,mode,mannual_results=None,nessus_results=None,qualys_results=None):
		try:
			if mode=='all':
				for ent in mannual_results:
					self.mannual_all_hosts.append(ent["host"].strip())

				for ent in nessus_results:
					self.nessus_all_hosts.append(ent["host"].strip())

				for ent in qualys_results:
					#print "Inside qualys host --:"+str(ent["host"])
					
					self.qualys_all_hosts.append(ent["host"].strip())

				self.mannual_extra_hosts=list(set(self.mannual_all_hosts)-set(self.nessus_all_hosts))
				self.mannual_extra_hosts=list(set(self.mannual_extra_hosts)-set(self.qualys_all_hosts))
				print "EXtra Mannual:"+str(self.mannual_extra_hosts)
				print "\n\n\n"

				self.nessus_extra_hosts=list(set(self.nessus_all_hosts)-set(self.mannual_all_hosts))
				self.nessus_extra_hosts=list(set(self.nessus_extra_hosts)-set(self.qualys_all_hosts))
				print "EXtra Nessus:"+str(self.nessus_extra_hosts)
				print "\n\n\n"


				self.qualys_extra_hosts=list(set(self.qualys_all_hosts)-set(self.mannual_all_hosts))
				self.qualys_extra_hosts=list(set(self.qualys_extra_hosts)-set(self.nessus_all_hosts))
				print "EXtra Qualys:"+str(self.qualys_extra_hosts)
				print "\n\n\n"


				
				
		except Exception ,ee:
				print "Exception !! :"+str(ee)


	def merge_all(self,mannual_results,nessus_results,qualys_results):
		try:
			report_template=[]
			
			parent_dict_mannual=mannual_results["value"]
			parent_dict_nessus=nessus_results["value"]
			parent_dict_qualys=qualys_results["value"]
			service_count_matched=0
			self.init_hosts('all',mannual_results["value"],nessus_results["value"],qualys_results["value"])
			self.init_port_host('all',mannual_results["value"],nessus_results["value"],qualys_results["value"])
			if parent_dict_mannual:
				print "\n\n"
				#print str(parent_dict_mannual)
				for host_items in parent_dict_mannual:
						report_item={}
				
						print "1"
						print str(host_items["host"])
						host=host_items["host"]
						report_item["host"]=host
						
						#is_host_in_nessus=is_host_present_nessus(host,nessus_results)
						if 1: #host not in (self.mannual_extra_hosts): #it would mean host is in m and either of (n and q)
							details_mannual=host_items["value"]
							
							if details_mannual: 
								print "3"
								findings=[]
								for items in details_mannual:
										found_item={}
										port=items["port"]
										service_nmap=items["service"]
										found_item["port"]=port
										found_item["service_nmap"]=service_nmap
										found_item["nessus"]=''
										found_item["qualys_vuln"]=''
										found_item["qualys_info"]=''
										found_item['qualys_services']=''
										#found_item['mannual']=items['exploits']
										
										details_nessus=self.get_nessus_details(nessus_results["value"],host,port)
										if details_nessus:
											found_item["nessus"]=details_nessus
											service_count_matched=service_count_matched+1
											
										details_qualys=self.get_qualys_details(qualys_results["value"],host,port)
										if details_qualys:
											#print "Qualys details :"+str(details_qualys)
											found_item['qualys_vulns']=details_qualys['vulns']
											found_item['qualys_info']=details_qualys['infos']
											found_item['qualys_services']=details_qualys['services']
				
										findings.append(found_item)

								report_item["value"]=findings
								report_template.append(report_item)

			#print "The total number of services for host under test:"+str(ser)
			print "The service count matched with nessus :"+str(service_count_matched)
			print "\n\n\n\n\nReport template :\n\n\n\n"
			print str(report_template)
		except Exception ,ee:
				print "Exception caught --> "+str(ee)



obj=Report_merger('m.nessus','metasploit.xml')
obj.generate_report('246')









