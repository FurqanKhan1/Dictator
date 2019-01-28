"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to print the report in the format specified by the user and finally return a zipped folder containing the printed report.
"""
import itertools
from ansi2html import Ansi2HTMLConverter
from ansi2html_ import ansi2html
import json
import HTML_Template
import os
import datetime
import ast
import csv
import dicttoxml
from xml.dom.minidom import parseString
import re
import zipfile

class Report_printer:
	"""
	Objective :
	This class has various methods to print the report in the format specified by user.
	Each method would correspond to report format like generate_html,generate_csv,generate_xml
	"""
	

	def __init__(self,action="default"):
		"""
		Objective :
		This is the constructor and would initialize various class level variables.
		"""
	
		self.html_obj=HTML_Template.Html_template()
		self.folder_dir=os.path.dirname(os.path.realpath(__file__))
		if action=="default":
			self.results_path=os.path.join(self.folder_dir,"Results")
		elif action=="parse_only":
			self.results_path=os.path.join(self.folder_dir,"Results_mapping")
		#print "\n\nResult path is : "+str(results_path) 
		self.folder_name=os.path.join(self.results_path,"Data_")

	def init_project_directory(self,project_id):
		"""
		Objective :
		This is the method which will create and initialize the project directory
		"""
	
		print "Initialising parent directory "
		try:
			if not os.path.exists(self.folder_name+str(project_id)):
				os.mkdir(self.folder_name+str(project_id))
				s_path=os.path.join(self.results_path,'bk')
				#d_path=os.path.join(self.results_path,'bk')	
				
				os.system("cp -r "+s_path+ " "+ self.folder_name+str(project_id)+"/")
			self.data_path=self.folder_name+str(project_id)
			return 1;
		except Exception ,ee:
			#self.print_Error("Error while creating directory !!"+str(ee))
			print "EX "+str(ee)
			return -1

		
	def generate_html(self,report_content,project_id):
		"""
		Objective :
		This is the method which will generate the report in HTML format
		"""
	
		try:
			stat=self.init_project_directory(project_id)
			if stat==-1:
				ret_resp={}
				ret_resp["status"]="failure"	
				ret_resp["value"]="Some error occured while initializing project directory"
				return ret_resp
				
			self.data_path=self.folder_name+str(project_id)
			html=[]
			host_counter=0
			service_counter=0
			e_counter=0
			all_exploits=0
			
			for item in report_content:
				#print "Item is --"+str(item)
				if "host" in item:
					host=item["host"]
					
					if item["status"]=="all":
						html.append(self.html_obj.get_header(host)) #open host div (1 div)
						html.append(self.html_obj.get_host_wrap(host_counter)) #open host (1 div)
						host_counter=host_counter+1
						report_item=item["value"]
						for ri in report_item:
							if ri["status"]=="all":
								port=ri["port"]
								service=ri["service_nmap"]
								mannual=ri["mannual"] #open service div in next __init (1 div)
								html.append(self.html_obj.get_init_table(service_counter,host,port,service))
								service_counter=service_counter +1
								template_message="Mannual findings for service :"+str(service)
								html.append(self.html_obj.get_exploit_template(e_counter,template_message))
								#open exploits div and exploits result div (2 divs)
								e_counter=e_counter+1
								exploit_data=mannual
								self.process_and_append_mannual_findings(exploit_data,html)
								
								html.append(self.html_obj.close_divs_item())
								#3 divs closed (exploits ,exploit_results and service)
								#updated to 2 now
								nessus=ri["nessus"]
								template_message="Nessus Findings for Service :"+str(service)
								#print "nessus is :"+str(nessus)
								#2 divs in next opened
								html.append(self.html_obj.get_exploit_template(e_counter,template_message))
								e_counter=e_counter+1
								self.process_and_append_nessus_findings(nessus,html,host,port)
								html.append(self.html_obj.close_divs_item())
								#2 divs closed
								
								qualys=ri["qualys"]
								template_message="Qualys Findings for Service :"+str(service)
								html.append(self.html_obj.get_exploit_template(e_counter,template_message))
								e_counter=e_counter+1
								self.process_and_append_qualys_findings(qualys,html,host,port)
								html.append(self.html_obj.close_divs_item())
								e_counter=e_counter+1
								html.append("</div>")#close service div
								#html.append(self.html_obj.close_parents())
							elif ri["status"]=="nessus_only":
								print "N only"	
								#print "\n\n\n"
								#print str
								message="Nessus Discoverd Some additional Services"
								html.append(self.html_obj.get_init_table_add(service_counter,host,message))
								service_counter=service_counter +1
								e_counter=e_counter+1
								nessus=ri["value"]
								template_message="Additional Nessus Findings for host :"+str(host)
								html.append(self.html_obj.get_exploit_template(e_counter,template_message))
								e_counter=e_counter+1
								self.process_and_append_nessus_findings(nessus,html,host,'')
								html.append(self.html_obj.close_divs_item())
								html.append("</div>")
						
												
							elif ri["status"]=="qualys_only":
								print "Q only"	
								message="Qualys Discoverd Some additional Services "
								html.append(self.html_obj.get_init_table_add(service_counter,host,message))
								service_counter=service_counter +1
								e_counter=e_counter+1
								qualys=ri["value"]
								template_message="Additional Qualys Findings for host :"+str(host)
								html.append(self.html_obj.get_exploit_template(e_counter,template_message))
								e_counter=e_counter+1
								self.process_and_append_qualys_findings(qualys,html,host,'')
								html.append(self.html_obj.close_divs_item())
								html.append("</div>")
								#html.append(self.html_obj.close_parents())

							elif ri["status"]=="both":
								print "Both only"
								message="Both Nessus Qualys Discoverd Some additional Services "
								html.append(self.html_obj.get_init_table_add(service_counter,host,message))
								service_counter=service_counter +1	
								e_counter=e_counter+1
								nessus=ri["value"]
								template_message="Common Findings of Both Nessus and Qualys for host :"+str(host)
								html.append(self.html_obj.get_exploit_template(e_counter,template_message))
								e_counter=e_counter+1
								self.process_and_append_nessus_findings(nessus,html,host,'')
								html.append(self.html_obj.close_divs_item())
								html.append("</div>")

						html.append(self.html_obj.close_parents())


					elif item["status"]=="nessus_only":
						print "N Host only"
						html.append(self.html_obj.get_header(host))
						html.append(self.html_obj.get_host_wrap(host_counter))
						host_counter=host_counter+1
						message="The above host discovered was an additional finding of Nessus"
						html.append(self.html_obj.get_init_table_add(service_counter,host,message))
						service_counter=service_counter +1
						e_counter=e_counter+1
						nessus=item["value"]
						template_message="Additional Nessus Host Findings - Host :"+str(host)
						html.append(self.html_obj.get_exploit_template(e_counter,template_message))
						e_counter=e_counter+1
						self.process_and_append_nessus_findings(nessus,html,host,'')
						html.append(self.html_obj.close_divs_item())
						html.append("</div>")
						html.append(self.html_obj.close_parents())
												
					elif item["status"]=="qualys_only":
						print "Q Host only"	
						html.append(self.html_obj.get_header(host))
						html.append(self.html_obj.get_host_wrap(host_counter))
						host_counter=host_counter+1
						message="The above host discovered was an additional finding of Qualys"
						html.append(self.html_obj.get_init_table_add(service_counter,host,message))
						service_counter=service_counter +1
						
						e_counter=e_counter+1
						qualys=item["value"]
						#print str(qualys)
						template_message="Additional Qualys Host Findings - Host :"+str(host)
						html.append(self.html_obj.get_exploit_template(e_counter,template_message))
						e_counter=e_counter+1
						self.process_and_append_qualys_findings(qualys,html,host,'')
						html.append(self.html_obj.close_divs_item())
						html.append("</div>")
						html.append(self.html_obj.close_parents())

					elif item["status"]=="both":
						print "B Host only"	
						html.append(self.html_obj.get_header(host))
						html.append(self.html_obj.get_host_wrap(host_counter))
						host_counter=host_counter+1
						message="The above host discovered was an additional finding of Both Nessus and Qualys"
						html.append(self.html_obj.get_init_table_add(service_counter,host,message))
						service_counter=service_counter +1
						
						e_counter=e_counter+1
						nessus=item["value"]
						template_message="Common Host Findings of Both Nessus and Qualys - Host :"+str(host)
						html.append(self.html_obj.get_exploit_template(e_counter,template_message))
						e_counter=e_counter+1
						self.process_and_append_nessus_findings(nessus,html,host,'')
						html.append(self.html_obj.close_divs_item())
						html.append("</div>")
						html.append(self.html_obj.close_parents())


					#close host div	
			if len(html) >0:
				stat=self.print_report(html,project_id,host_counter,e_counter)
				return stat
										
		except Exception ,ee:
			print "Exception while generating report "+str(ee)
			ret_resp={}
			ret_resp["status"]="failure"	
			ret_resp["value"]=str(ee)
			return ret_resp

	def generate_xml(self,report_content,project_id):
		"""
		Objective :
		This is the method which will generate the report in XML format
		"""
	
		try:
			print "In xml:"
			stat=self.init_project_directory(project_id)
			if stat==-1:
				ret_resp={}
				ret_resp["status"]="failure"	
				ret_resp["value"]="Some error occured while initializing project directory"
				return ret_resp

			self.data_path=self.folder_name+str(project_id)
			xml_result=dicttoxml.dicttoxml(report_content)
			RE_XML_ILLEGAL = u'([\u0000-\u0008\u000b-\u000c\u000e-\u001f\ufffe-\uffff])' + \
                 u'|' + \
                 u'([%s-%s][^%s-%s])|([^%s-%s][%s-%s])|([%s-%s]$)|(^[%s-%s])' % \
                  (unichr(0xd800),unichr(0xdbff),unichr(0xdc00),unichr(0xdfff),
                   unichr(0xd800),unichr(0xdbff),unichr(0xdc00),unichr(0xdfff),
                   unichr(0xd800),unichr(0xdbff),unichr(0xdc00),unichr(0xdfff))
			#x = u"<foo>text\u001a</foo>"
			x = re.sub(RE_XML_ILLEGAL, "?", xml_result)
			dom = parseString(x.encode("utf-8"))

			#dom=parseString(str(xml_result.encode("utf-8")))
			
			report_file=str(project_id)+"__report.xml"
			first_report=report_file
			report_file_path = os.path.join(self.data_path, report_file)
			output = open(report_file_path,"w") #create a html report file and open it
			#output = open('test.csv',"w")
			output.write(dom.toprettyxml())
			output.close()
			report_file=str(project_id)+"__report_unformatted.xml"
			report_file_path = os.path.join(self.data_path, report_file)
			output = open(report_file_path,"w") #create a html report file and open it
			#output = open('test.csv',"w")
			output.write(xml_result.encode("utf-8"))
			output.close()
			
			zip_folder_name="Data_xml_"+str(project_id)+".zip"
			zip_folder_creation_path=os.path.join(self.results_path,zip_folder_name)
			zip_folder_path=self.data_path #file to be zipped
			zipf=zipfile.ZipFile(zip_folder_creation_path,'w',zipfile.ZIP_DEFLATED)
			self.zipdir(zip_folder_path,zipf,report_file,"xml",first_report)
			zipf.close()
			ret_resp={}
			ret_resp["status"]="success"
			ret_resp["value"]=zip_folder_creation_path
			return ret_resp
	
			
		except Exception ,ee:
			print "Exception while generating xml report "+str(ee)
			ret_resp={}
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ee)
			return ret_resp


	def get_nessus_findings(self,item_,csv_n,writer):
		"""
		Objective :
		This method will name the nessus findings in proper naming convention and order for csv writing.
		"""
	
		#nes_protocol=item["protocol"]
		
		print "1@@"
		#print str(item_)
		for item in item_:
			csv_n['n_service']=item["service"]
			csv_n['n_pl_id']=item["plugin_id"]
			csv_n['n_pl_nm']=item["plugin_name"]
			csv_n['n_sevirity']=item["sevirity"]
			csv_n['n_synop']=item["synopsis"]
			csv_n['n_description']=item["description"]
			csv_n['n_ref']=str(item["ref"])
			csv_n['n_exploits']=str(item["exploits"])
			csv_n['n_risk_vec']=str(item["risk_vec"])
			csv_n['n_solution']=str(item["solution"])
			writer.writerow(csv_n)

	def get_qualys_findings(self,item_,csv_n,writer):
		"""
		Objective :
		This method will name the qualys findings in proper order for csv writing.
		"""

		for item in item_:
			csv_n['q_sevirity']=item["sevirity"]
			csv_n['q_title']=item["title"]
			csv_n['q_cvss']=item["cvss"]
			csv_n['q_protocol']=item["protocol"]
			csv_n['q_result']=item["result"]
			csv_n['q_dignosis']=item["dignosis"]
			csv_n['q_ref']=str(item["ref"])
			csv_n['q_exploits']=str(item["exploits"])
			csv_n['q_sub_type']=item["sub_type"]
			csv_n['q_solution']=item["solution"]
			writer.writerow(csv_n)

								#for item in nessus:
								
								
	def generate_csv(self,report_content,project_id):
		"""
		Objective :
		This method will generate the report in csv format.
		"""

		try:
			print "inside csv !!"
			stat=self.init_project_directory(project_id)
			if stat==-1:
				ret_resp={}
				ret_resp["status"]="failure"	
				ret_resp["value"]="Some error occured while initializing project directory"
				return ret_resp

			self.data_path=self.folder_name+str(project_id)
			html=[]
			host_counter=0
			service_counter=0
			e_counter=0
			all_exploits=0
			host_status=''
			fields=['project_id','host_status','service_status','host','port','service_mannual']
			fields.extend(['mannual_commands','mannual_results','n_service','n_pl_id','n_pl_nm','n_sevirity'])
			fields.extend(['n_synop','n_description','n_ref','n_exploits','n_risk_vec','n_solution'])
			fields.extend(['q_sevirity','q_title','q_cvss','q_protocol','q_result','q_dignosis','q_ref',])
			fields.extend(['q_exploits','q_sub_type','q_solution'])
			report_file=str(project_id)+"__report.csv"
			report_file_path = os.path.join(self.data_path, report_file)
			output = open(report_file_path,"w") #create a html report file and open it
			#output = open('test.csv',"w")
			writer=csv.DictWriter(output,fieldnames=fields)
			writer.writeheader()
			for item_ in report_content:
				if "host" in item_:
					host=item_["host"]
					host_status="mannual"
					if item_["status"]=="all":
						report_item=item_["value"]						
						for ri in report_item:
							if ri["status"]=="all":
								csv_r={}
								service_status="mannual"
								port=ri["port"]
								service=ri["service_nmap"]
								mannual=ri["mannual"] #open service div in next __init (1 div)
								m_res=self.get_mannual_results(mannual)
								comm=''
								res=''
								try:
									if m_res and (len(m_res) > 0):
										comm=m_res[0]
										res=m_res[1]
								except Exception ,ee:
									print "EXcept :"+str(ee)
								print "111222333"
								master_list=[]
								nessus=ri["nessus"]
								item=nessus
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=port
								csv_r['service_mannual']=service
								csv_r['mannual_commands']=comm
								csv_r['mannual_results']=str(m_res)
								writer.writerow(csv_r)
								if len(nessus) >0 and nessus !='':
									service_status=service_status + " and nessus"
								
									csv_r={}
									csv_r["project_id"]=project_id
									csv_r['host_status']=host_status
									csv_r['service_status']=service_status
									csv_r['host']=host
									csv_r['port']=port
									self.get_nessus_findings(item,csv_r,writer)
					
								item=ri['qualys']
								if len(item) >0 and item !='':
									service_status=service_status +" and qualys"
									csv_r={}
									csv_r["project_id"]=project_id
									csv_r['host_status']=host_status
									csv_r['service_status']=service_status
									csv_r['host']=host
									csv_r['port']=port
									self.get_qualys_findings(item,csv_r,writer)
									#writer.writerow(csv_r)
								
							elif ri["status"]=="nessus_only":
								csv_r={}
								service_status="nessus"
								nessus=ri["value"]
								item=nessus
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=''
								csv_r['service_mannual']=''
								csv_r['mannual_commands']=''
								csv_r['mannual_results']=''
								self.get_nessus_findings(item,csv_r,writer)
								#writer.writerow(csv_r)
												
							elif ri["status"]=="qualys_only":
								csv_r={}
								service_status="qualys"
								item=ri["value"]
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=''
								csv_r['service_mannual']=''
								csv_r['mannual_commands']=''
								csv_r['mannual_results']=''
								self.get_qualys_findings(item,csv_r,writer)
								#writer.writerow(csv_r)
								
							elif ri["status"]=="both":
								csv_r={}
								service_status="both"
								nessus=ri["value"]
								item=nessus
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=''
								csv_r['service_mannual']=''
								csv_r['mannual_commands']=''
								csv_r['mannual_results']=''
								self.get_nessus_findings(item,csv_r,writer)
								#writer.writerow(csv_r)
								

					elif item_["status"]=="nessus_only":
								#host_status="nessus"
								csv_r={}
								host_status="nessus"
								service_status="nessus"
								nessus=item_["value"]
								item=nessus
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=''
								csv_r['service_mannual']=''
								csv_r['mannual_commands']=''
								csv_r['mannual_results']=''
								self.get_nessus_findings(item,csv_r,writer)
								#writer.writerow(csv_r)
												
					elif item_["status"]=="qualys_only":
								csv_r={}
								host_status="qualys"
								service_status="qualys"
								item=item_["value"]
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=''
								csv_r['service_mannual']=''
								csv_r['mannual_commands']=''
								csv_r['mannual_results']=''
								self.get_qualys_findings(item,csv_r,writer)
								
					elif item_["status"]=="both":
								csv_r={}
								host_status="both nessus and qualys"
								service_status="both nessus and qualys"
								nessus=item_["value"]
								item=nessus
								csv_r["project_id"]=project_id
								csv_r['host_status']=host_status
								csv_r['service_status']=service_status
								csv_r['host']=host
								csv_r['port']=''
								csv_r['service_mannual']=''
								csv_r['mannual_commands']=''
								csv_r['mannual_results']=''
								self.get_nessus_findings(item,csv_r,writer)
								#writer.writerow(csv_r)
								

					#close host div	
		
			output.close()
			zip_folder_name="Data_csv_"+str(project_id)+".zip"
			zip_folder_creation_path=os.path.join(self.results_path,zip_folder_name)
			zip_folder_path=self.data_path #file to be zipped
			zipf=zipfile.ZipFile(zip_folder_creation_path,'w',zipfile.ZIP_DEFLATED)
			self.zipdir(zip_folder_path,zipf,report_file,"csv")
			zipf.close()
			ret_resp={}
			ret_resp["status"]="success"
			ret_resp["value"]=zip_folder_creation_path
	
			print "In csv and closing !!!"
			return ret_resp
			
		except Exception ,ee:
			print "Exception while generating csv report "+str(ee)
			ret_resp={}
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ee)
			return ret_resp
	

	def zipdir(self,path,ziph,report_file,format_="html",add_file=''):
		"""
		Objective :
		This method will zip the final report in a zipped directory and wilol return that directory.
		"""

		for dirname,subdirs,files in os.walk(path):
			abs_path_dir=dirname
			rel_path_dir=abs_path_dir[len(path)+len(os.sep):]
			print "ADd dir is :"+str(rel_path_dir)
			for file_ in files:
				#print "File is : "+str(file_) 
				if (file_==report_file) or (file_==add_file and format_=='xml') or ((rel_path_dir=='bk') and format_=="html"):
					abs_path=os.path.join(dirname,file_)
					rel_path=abs_path[len(path)+len(os.sep):]
					ziph.write(abs_path,rel_path)
					
						
	def print_report(self,html,project_id,host_counter,e_counter):
			#self.folder_name=os.path.join("Results","Data_")
		try:
			ret_resp={}
			print "Printing started"
			report_file=str(project_id)+"__report.html"
			report_file_path = os.path.join(self.data_path, report_file)
			bootstrap=self.html_obj.get_header_bs()
			nav_bar=self.html_obj.get_nav_bar()
			html_body=self.html_obj.get_html_body(bootstrap,nav_bar,host_counter,e_counter)
			html_final=ansi2html(str(''.join(html)))
			output = open(report_file_path,"wb") #create a html report file and open it
			output.write(html_body)
			output.write(html_final)
			output.write(str("</div></div>"))
			output.close()
			print "Printed Successfully"
			zip_folder_name="Data_html_"+str(project_id)+".zip"
			zip_folder_creation_path=os.path.join(self.results_path,zip_folder_name)
			zip_folder_path=self.data_path #file to be zipped
			zipf=zipfile.ZipFile(zip_folder_creation_path,'w',zipfile.ZIP_DEFLATED)
			self.zipdir(zip_folder_path,zipf,report_file)
			zipf.close()
			ret_resp["status"]="success"
			ret_resp["value"]=zip_folder_creation_path
	
			
			return ret_resp
		except Exception ,ex:
			print "Exception @1@" +str(ex)
			ret_resp["status"]="failure"
			ret_resp["value"]=str(ex)
			return ret_resp
			
			
	def process_and_append_nessus_findings(self,nessus_data,html,host,port):
		"""
		Objective :
		This method will put the nessus findings in proper order for html writing.
		"""

		try:
			if nessus_data:
				for item in nessus_data:
					try:
						html.append(self.html_obj.get_nessus_header(host,port,item["os"],item["protocol"],item["service"]))
						html.append(self.html_obj.get_nessus_body(item["plugin_id"],item["plugin_name"],item["sevirity"],item["synopsis"],item["description"],item["ref"],item["exploits"],item["risk_vec"],item["solution"],item["port"]))
					except Exception ,ex:
						print "Exception ! nessus "+str(ex) +"\n\n"+str(nessus_data)
				
		except Exception ,ee:
			print "Exception caught while nessus findings "+str(ee)


	def process_and_append_qualys_findings(self,qualys_data,html,host,port):
		"""
		Objective :
		This method will put the qualys findings in proper order for html writing.
		"""

		try:
			if qualys_data:
				for item in qualys_data:
					try:
						html.append(self.html_obj.get_qualys_header(host,port))
						html.append(self.html_obj.get_qualys_body(item["sevirity"],item["title"],item["cvss"],item["protocol"],item["result"],item["dignosis"],item["ref"],item["exploits"],item["sub_type"],item["solution"],item["port"]))
					except Exception ,ex:
						print "Exception ! Qualys "+str(ex)
				
		except Exception ,ee:
			print "Exception caught while nessus findings "+str(ee)

	def get_mannual_results(self,exploit_data):
		"""
		Objective :
		This method will apply transformation to mannual results to make it more readable.
		"""

		try:
								all_commands=[]
								all_results=[]
								return_list=[]
								entries=exploit_data.get("Entries")
								if(entries):
									for k,v in entries.iteritems():
										#print "key is "+str(k)
										if(v):
											command_id=str(k)
											commands = v[1] if v[1] else "Nil"								
											result=v[2] if v[2] else "No Results"
											final_commands=[]
									
											if(commands !="Nil"):
												try:
													cmd = ast.literal_eval(commands)
													if (isinstance(cmd,list)):
														for c in cmd:
															final_commands.append(c)
													else:
														final_commands.append(str(cmd))
												
													commands=''.join(final_commands)
													#all_exploits=all_exploits+1
													all_commands.append(commands)
													all_results.append(result)
												except Exception ,exc:
													print "Exception while transforming :"+str(exc)

									return_list.append(all_commands)
									return_list.append(all_results)
									return return_list
												
		except Exception,ee:
			print "exception @@"+str(ee)
			return "0"+str(ee)

	def process_and_append_mannual_findings(self,exploit_data,html):
		"""
		Objective :
		This method will put the mannual findings in proper order for html writing.
		"""

		try:
			if(isinstance(exploit_data,basestring)):
							exploit_data=json.loads(exploit_data)
			if exploit_data:
								entries=exploit_data.get("Entries")
								if(entries):
									for k,v in entries.iteritems():
										#print "key is "+str(k)
										if(v):
											command_id=str(k)
											html.append(self.html_obj.get_command_template(command_id))
											commands = v[1] if v[1] else "Nil"								
											result=v[2] if v[2] else "No Results"
											final_commands=[]
									
											if(commands !="Nil"):
												try:
													cmd = ast.literal_eval(commands)
													if (isinstance(cmd,list)):
														for c in cmd:
															final_commands.append(c)
													else:
														final_commands.append(str(cmd))
												
													commands=''.join(final_commands)
													#all_exploits=all_exploits+1
													html.append(self.html_obj.get_exploit_body_commands(commands)) #(div open and close -->0 div)
													html.append(self.html_obj.get_exploit_body_results(result)) #(div open and close -->0 div)
													
												except Exception ,ee:
													print "Exc lit eval "+str(ee)


		except Exception ,ee:
			print "Exception while process and append of mannual data :"

