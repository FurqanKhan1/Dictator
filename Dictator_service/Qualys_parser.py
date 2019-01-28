#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to parse the Qualys XML report.
It works in two modes :(1) Store (2) Retun

1) When this code is invoked wirh store flag as set ,then it will go ahead and parse the Qualys report as a 
list  and finally will store /bulk insert all the rows of the list in the backend database table.This table would be later on used for report integration with mannual test cases

2) When invoked with return flag as set then this code will parse the Qualys report and will return a list of dictionaries.This list of dictionary would be later on used and traversed to do cve to exploit mapping and make the final report in (html,xml,json or csv format)
"""

from __future__ import with_statement
#from plugins import core
import re
import os
import sys
import json
import Report_Generator

try:

    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION

except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION



current_path = os.path.abspath(os.getcwd())



def cleaner_unicode(string):
	"""
		Objective :
		This method is used to clean the special characters from the report string and
		place ascii characters in place of them
	"""

	if string is not None:
		return string.encode('ascii', errors='backslashreplace')
	else:
		return string


def cleaner_results(string):
    """
		Objective :
		This method is used to replace the html tags with plain text.
		So that the browser does not render the html ,but should display it. 
    """

    try:
        result = string.replace('<P>', '').replace('<UL>', ''). \
            replace('<LI>', '').replace('<BR>', ''). \
            replace('<A HREF="', '').replace('</A>', ' '). \
            replace('" TARGET="_blank">', ' ').replace('&quot;', '"')
        return result

    except:
        return ''


class QualysguardXmlParser():
    """
	Objective :
	The classQualysguardXmlParser will parse the Qualys xml report as mentioned above 
    """

    
    def __init__(self, xml_output):
        """
		Objective :
		This method is the constructor of the class and initializes instance variables
        """


        tree, type_report = self.parse_xml(xml_output)

        if not tree or type_report is None:
            self.items = []
            return

        if type_report is 'ASSET_DATA_REPORT':
            self.items = [data for data in self.get_items_asset_report(tree)]
        elif type_report is 'SCAN':
            
            self.items = [data for data in self.get_items_scan_report(tree)] #data is in for loop it will automatically call the next() method of generator/iterator and thus will return instance of ItemScan report class placed in list data[]->items

    def parse_xml(self, xml_output):
        """
		Objective :
		This method is actually responsible for parsing the report from xml format into a class
		object list where each object/instance would represent a Qualys report item or host.
		
        """

        
        asset_data_report = '<!DOCTYPE ASSET_DATA_REPORT SYSTEM'
        scan_report = '<!DOCTYPE SCAN SYSTEM'

        try:
            #tree = ET.fromstring(xml_output)
            tree=ET.parse(xml_output).getroot()
            #tree1=ET.parse(xml_output)
            #print str(tree1)
            xml_output=ET.tostring(tree,encoding='utf8',method='xml')
            #whole_doc=ET.tostring(tree1,encoding='utf8',method='xml')
            tree = ET.fromstring(xml_output)
            #print "no exception"
            # xml_output
            #print tree.tag
            if asset_data_report in xml_output:
                type_report = 'ASSET_DATA_REPORT'
            elif scan_report in xml_output:
                type_report = 'SCAN'
            else:
                type_report = None
            type_report = 'SCAN'
            #return None ,None

        except SyntaxError, err:
            print('SyntaxError: %s. %s' % (err, xml_output))
            return None, None

        return tree, type_report

    def get_items_scan_report(self, tree):
        """
		Objective:
        @return items A list of Host instances
        """
        for node in tree.findall('IP'):
            yield ItemScanReport(node) #yield will make a list and then retiurn the list togeather

    def get_items_asset_report(self, tree):
        """
		Objective:
        @return items A list of Host instances
        """
        for node in tree.find('HOST_LIST').findall('HOST'):
            yield ItemAssetReport(node, tree)


class ItemAssetReport():
    """
	Objective :
	The Qualys report is generally of two formats (Item scan report) and (Item Asset report) .
	This calss will handle Item Asset report 
    """

    def __init__(self, item_node, tree):

        self.node = item_node
        self.ip = self.get_text_from_subnode('IP')

        self.os = self.get_text_from_subnode('OPERATING_SYSTEM')
        self.vulns = self.getResults(tree)

    def getResults(self, tree):
        
        glossary = tree.find('GLOSSARY/VULN_DETAILS_LIST')

        for self.issue in self.node.find('VULN_INFO_LIST'):
            yield ResultsAssetReport(self.issue, glossary)

    def get_text_from_subnode(self, subnode_xpath_expr):
        """
        Finds a subnode in the host node and the retrieves a value from it.

        @return An attribute value
        """
        sub_node = self.node.find(subnode_xpath_expr)
        if sub_node is not None:
            return sub_node.text

        return None


class ResultsAssetReport():
    
    def __init__(self, issue_node, glossary):

        # VULN_INFO ElementTree
        self.node = issue_node
        self.port = self.get_text_from_subnode(self.node, 'PORT')
        self.protocol = self.get_text_from_subnode(self.node, 'PROTOCOL')
        self.name = self.get_text_from_subnode(self.node, 'QID')
        self.result = self.get_text_from_subnode(self.node, 'RESULT')

        self.severity_dict = {
            '1': 'info',
            '2': 'low',
            '3': 'med',
            '4': 'high',
            '5': 'critical'}

        # GLOSSARY TAG
        self.glossary = glossary
        self.severity = self.severity_dict.get(
            self.get_text_from_glossary('SEVERITY'), 'info')
        self.title = self.get_text_from_glossary('TITLE')
        self.cvss = self.get_text_from_glossary('CVSS_SCORE/CVSS_BASE')
        self.pci = self.get_text_from_glossary('PCI_FLAG')
        self.solution = self.get_text_from_glossary('SOLUTION')
        self.impact = self.get_text_from_glossary('IMPACT')

        # Description
        self.desc = cleaner_results(self.get_text_from_glossary('THREAT'))
        if not self.desc:
            self.desc = ''
        if self.result:
            self.desc += '\n\nResult: ' + cleaner_results(self.result)
        if self.impact:
            self.desc += '\n\nImpact: ' + cleaner_results(self.impact)
        if self.result:
            self.desc += '\n\nSolution: ' + cleaner_results(self.solution)

        # References
        self.ref = []
        self.ref.append(self.get_text_from_glossary('CVE_ID_LIST/CVE_ID/ID'))

        if self.cvss:
            self.ref.append('CVSS SCORE: ' + self.cvss)

        if self.pci:
            self.ref.append('PCI: ' + self.pci)

    def get_text_from_glossary(self, tag):
        
        for vuln_detail in self.glossary:

            id_act = vuln_detail.get('id').strip('qid_')
            if id_act == self.name:

                text = vuln_detail.find(tag)
                if text is not None:
                    return cleaner_unicode(text.text)
                else:
                    return None

    def get_text_from_subnode(self, node, subnode_xpath_expr):
        
        sub_node = node.find(subnode_xpath_expr)
        if sub_node is not None:
            return cleaner_unicode(sub_node.text)

        return None


class ItemScanReport():
    """
	Objective :
	The Qualys report is generally of two formats (Item scan report) and (Item Asset report) .
	This calss will handle Item scan report 
    """

    
    def __init__(self, item_node): #item node points to an IP
        """
			Objective :
			This method is the constructor of the class 
        """

        self.node = item_node
        self.ip = item_node.get('value')
        self.os = self.get_text_from_subnode('OS')
        # "os is "+str(self.os) +" and itemnode is :"+str(item_node)
        self.vulns = self.getResults(item_node,0)
        self.infos=self.getResults(item_node,1)
        self.services=self.getResults(item_node,2)
        #print "Not executed this :"

    def getResults(self,tree,code):
		"""
		Objective :
		The qualys item report has 3 sub catagories :
		1)Vulnerabilities
		2)Info findings
		3)Services
		Each of the catagory is represnted by a list of instances of class ResultScanReport
		This method would integrate the different ctagories as a list of dictionaries ,where the 	
		key would be item catagory (1,2,3) and the value would be a list.Each list holding list of 
		ReesultScanReport 
		"""

		if code==0:
			for self.issues in tree.findall('VULNS/CAT'): #each issue --> vul parent node <vulns cat=tcp>...
				for v in self.issues.findall('VULN'): #each v will piint to a vuln inside current catagory
					yield ResultsScanReport(v, self.issues)
		elif code==1:
			for self.issues in tree.findall('INFOS/CAT'):
				for v in self.issues.findall('INFO'):
					yield ResultsScanReport(v, self.issues)
		elif code==2:
			for self.issues in tree.findall('SERVICES/CAT'):
				for v in self.issues.findall('SERVICE'):
					yield ResultsScanReport(v, self.issues)


    def get_text_from_subnode(self, subnode_xpath_expr):
		"""
		Objective :
		The method will actually get the data/text content from the node and shall return that
		"""        
		sub_node = self.node.find(subnode_xpath_expr)
		if sub_node is not None:
			return sub_node.text

		return None


class ResultsScanReport():
    """
	Objective :
	The class ResultScanReport will actually genearte a class instance that replicates the report item 
	of the qualys xml report .Thus each report item of xml report will finally be represented as instance of
	this class.  
    """


    def __init__(self, issue_node, parent): #issue_node has vul node and parent holds the <cat> node
      """
		Objective :
		The method/constructor will initialize all the instance variables of this class
	  """

      try:
        self.node = issue_node
        self.port = parent.get('port')
        #print "PORT is "+str(self.port)
        self.protocol = parent.get('protocol')
        self.name = self.node.get('number')
        self.severity = self.node.get('severity')
        self.title = self.get_text_from_subnode('TITLE')
        self.cvss = self.get_text_from_subnode('CVSS_BASE')
        self.pci = self.get_text_from_subnode('PCI_FLAG')
        self.diagnosis = self.get_text_from_subnode('DIAGNOSIS')
        self.solution = self.get_text_from_subnode('SOLUTION')
        self.result = self.get_text_from_subnode('RESULT')
        

        self.desc = cleaner_results(self.diagnosis)
        if self.result:
            self.desc += '\nResult: ' + cleaner_results(self.result)
            #print str(self.desc)
        else:
            self.desc += ''

        self.ref = [] #this list shall hold the cve id's and bugtrack-id's 
        for r in issue_node.findall('CVE_ID_LIST/CVE_ID'):
            self.node = r #  rnow points towards the node <cveid>
            self.ref.append(self.get_text_from_subnode('ID')) #The list shall hold the cve id now
        for r in issue_node.findall('BUGTRAQ_ID_LIST/BUGTRAQ_ID'):
            self.node = r
            self.ref.append('bid-' + self.get_text_from_subnode('ID')) #the bugtrack id's will have text as bid-<id>
      except Exception ,ee:
			print "eXception :"+str(ee)

    def get_text_from_subnode(self, subnode_xpath_expr):
        """
		Objective :
        Finds a subnode in the host node and the retrieves a value from it.

        @return An attribute value
        """
        sub_node = self.node.find(subnode_xpath_expr) #returns result like :<Element 'TITLE' at 0x7fa586b62150> for a search key like :title

        if sub_node is not None:
            #print "Search Key is : "+str(subnode_xpath_expr) +" and value is :" +str(sub_node)
            return cleaner_results(cleaner_unicode(sub_node.text))
           

        return None


class QualysguardPlugin(): #core.PluginBase
    
   
    def __init__(self):

        #core.PluginBase.__init__(self)
        self.id = 'Qualysguard'
        self.name = 'Qualysguard XML Output Plugin'
        self.plugin_version = '0.0.2'
        self.version = 'Qualysguard 2016 March '
        self.framework_version = '1.0.0'
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(
            r'^(sudo qualysguard|\.\/qualysguard).*?')

        global current_path
        self._output_file_path = os.path.join(
            self.data_path,
            'qualysguard_output-%s.xml' % self._rid)

    def parseOutputString(self, output, debug=False):

        parser = QualysguardXmlParser(output)

        for item in parser.items:

            h_id = self.createAndAddHost(
                item.ip,
                item.os)

            i_id = self.createAndAddInterface(
                h_id,
                item.ip,
                ipv4_address=item.ip,
                hostname_resolution=item.ip)

            for v in item.vulns:

                if v.port is None:
                    self.createAndAddVulnToHost(
                        h_id,
                        v.title if v.title else v.name,
                        ref=v.ref,
                        severity=v.severity,
                        resolution=v.solution if v.solution else '',
                        desc=v.desc)

                else:

                    web = False
                    s_id = self.createAndAddServiceToInterface(
                        h_id,
                        i_id,
                        v.port,
                        v.protocol,
                        ports=[str(v.port)],
                        status='open')

                    if v.port in ['80', '443'] or re.search('ssl|http', v.name):
                        web = True
                    else:
                        web = False

                    if web:
                        self.createAndAddVulnWebToService(
                            h_id,
                            s_id,
                            v.title if v.title else v.name,
                            ref=v.ref,
                            website=item.ip,
                            severity=v.severity,
                            desc=v.desc,
                            resolution=v.solution if v.solution else '')

                        n_id = self.createAndAddNoteToService(
                            h_id,
                            s_id,
                            'website',
                            '')

                        self.createAndAddNoteToNote(
                            h_id,
                            s_id,
                            n_id,
                            item.ip,
                            '')

                    else:
                        self.createAndAddVulnToService(
                            h_id,
                            s_id,
                            v.title if v.title else v.name,
                            ref=v.ref,
                            severity=v.severity,
                            desc=v.desc,
                            resolution=v.solution if v.solution else '')

        del parser

    def processCommandString(self, username, current_path, command_string):
        return None

    def setHost(self):
        pass


class Results:
	"""
	Objective :
	Now we know that all the results of the parsed report will be reprsented as Instances of the class 
	ResultScanReport and what this class does is that ,it will traverse through each instance and would
	finally represent each instance as a dictionary and would append each disctioanry to a list.
	The final list so produced will be holding many dictionaries and each dictionary holding a report item.
	Depending upon the flag with which the  parser code would be invoked ,the final results can either be 
	stored in the database table ,thereby providing aid in integration of mannual nessus and qualys report.
	If the flag would be return then in that case the list of dictionaries would be returned back mapping
	cve's to exploit mapping.Finally the report can be downloaded in xml,csv,json or html format
	"""

	def __init__(self):
		"""
		Objective :
		The method is the constructor of the class and it initialises the instance variables 
		"""

		self.rg=Report_Generator.ReportGenerator()

	def print_results(self,result,sub_type,host,p_id,action="store"):
			"""
			Objective :
			The method would save the details of the parsed report either in the database table
			or would actually return back the results depending upon weather the action flag is 
			store or return
			"""

			try:
				#print "-----------------------------------------------------------------------\n\n"
				#print print_message
				#ret_rec={}
				rec_list=[]
				Bulk_list=[]
				Bulk_list_details=[]
				for vul in result: #item.vulns holds the generator which inturn is the list of inatances of ResultScanReport
				#	print str("----------------------------------------------------------------")
				#	print print_message
					result_scan=vul
					ret_rec={}
				#	print "Title :" +str(result_scan.title)
				#	print "Port :"+str(result_scan.port)
				#	print "Protocol :"+str(result_scan.protocol)
				#	print "Sevirity :" +str(result_scan.severity)
				#	print "Cvss :"+str(result_scan.cvss)
				#	print "References :"+str(result_scan.ref)
				#	print "Result :" +str(result_scan.result)
				#	print "Dignosis :"+str(result_scan.diagnosis)
				#	print "Solution :" +str(result_scan.solution)
				#	print "--------------------------------------------------------------------"
				#(Pid,Host,Port,severity,protocol,title,cvss,ref,result,dignosis,solution,Source,sub_type)
					if action =="return":
						ret_rec["title"]=str(result_scan.title)
						ret_rec["port"]=str(result_scan.port)
						ret_rec["protocol"]=str(result_scan.protocol)
						ret_rec["sevirity"]=str(result_scan.severity)
						ret_rec["cvss"]=str(result_scan.cvss)
						#print "Type of ref is :"+str(type(result_scan.ref))
						ret_rec["ref"]=result_scan.ref
						#print "Now Type of ref is :"+str(type(ret_rec["ref"]))
						ret_rec["result"]=str(result_scan.result)
						ret_rec["dignosis"]=str(result_scan.diagnosis)
						ret_rec["solution"]=str(result_scan.solution)
						ret_rec["exploits"]=''
						if result_scan.ref and len (result_scan.ref) > 0:
							ret_rec["exploits"]=self.rg.getExploits(result_scan.ref,False,"outside")
						ret_rec["sub_type"]=sub_type
						rec_list.append(ret_rec)
					Bulk_list_details.append((int(p_id),host,str(result_scan.port),str(result_scan.severity),str(result_scan.protocol),str(result_scan.title),json.dumps(result_scan.cvss),json.dumps(result_scan.ref),str(result_scan.result),str(result_scan.diagnosis),str(result_scan.solution),'qualys',sub_type))

				if action =="store":
					return Bulk_list_details
				elif action=="return":
					return rec_list
			except Exception ,ee:
				print "Exception qual :"+str(ee)
				empty_list=[]
				return empty_list
			

def createPlugin():
    return QualysguardPlugin()

class QualysParser:
	"""
	Objective :
	The class QualysParser will be the start of the execution flow and would invpoke the class
 	QualysGuardParser passing the obtained qualys file to it.
	"""

	def parse(self,xml_file,project_id,action="store"):
		"""
		Objective :
		The method would invoke the QualysguardXmlParser class and would pass the xml file to it 
		and thus all the instances /list of instances would be returned to it.
		IT would then pass the list of instances to print_results() method of Results class which
		will finally convert the list instances as list of dictionatries and depending upon action flag
 		(store.return) it will either store details in database table or return results to the calling
 		method 
		"""


		return_response={}
		objj=Report_Generator.ReportGenerator()
		
			
		try:
			parser = QualysguardXmlParser(xml_file) 
		except Exception ,ex:
			print "Exception no file passed"
			return_response["status"]="failure"
			return_response["value"]=str(ex)
			return return_response
		try:
			obj=Results()
			return_list=[]
			Bulk_list=[]
			Bulk_list_details=[]
			
			for item in parser.items: #iterating over the generators
					#print "----------------------------------------------------------------------------"
					#print "Host discovered is : "+str(item.ip)
					#print "----------------------------------------------------------------------------"
					qualys_list=[]
					ret_record={}
					ret_record["host"]=str(item.ip)
					if action=="return":
						ret_record["status"]="qualys_only"
						ret_record["value"]=[]
					Bulk_list.append((int(project_id),str(item.ip),'qualys'))


					if action=="store":
						ret_record["vulns"]=obj.print_results(item.vulns,"vulns",item.ip,int(project_id))
						Bulk_list_details.extend(ret_record["vulns"])
					elif action =="return":
						a=''
						a=obj.print_results(item.vulns,"vulns",item.ip,0,"return")
						#print "obtained a --->"+str(a)
						qualys_list.extend(a)
						ret_record["value"].extend(a)
					print "\n\n"
					try:
						if item.infos:
							if action=="store":
								ret_record["infos"]=obj.print_results(item.infos,"infos",item.ip,int(project_id))
								Bulk_list_details.extend(ret_record["infos"])
							elif action =="return":
								a=''
								a=obj.print_results(item.infos,"infos",item.ip,0,"return")
								qualys_list.extend(a)
								ret_record["value"].extend(a)
								
					#		print "\n\n"
							if action =="store":
								ret_record["services"]=obj.print_results(item.services,"services",item.ip,int(project_id))
								Bulk_list_details.extend(ret_record["services"])
							elif action=="return":
								a=''
								a=obj.print_results(item.services,"services",item.ip,0,"return")
								qualys_list.extend(a)
								ret_record["value"].extend(a)

						if action=="store":
							return_list.append(ret_record)
						elif action=="return":
							return_list.append(ret_record)
					except Exception ,ee:
						print str(ee) 

			
			if len(return_list)>0:
				if action=="store":
					resp=objj.Store_parsed_report(Bulk_list,'',Bulk_list_details,'qualys')
				return_response["status"]="success"
				return_response["value"]=return_list
				if action =="store":
					return resp
				elif action=="return":
					return return_response
				else:
					return_response["status"]="empty"
					return_response["value"]="The action value is in correct"
					return return_resp
		
			else:
				return_response["status"]="empty"
				return_response["value"]="0"
				return return_resp
		
		

		except Exception ,exc:
			print "Exception caught @@@ " +str(exc)
			return_response["status"]="failure"
			return_response["value"]=str(exc)
			return return_response
		

#obj=QualysParser()
#rss=obj.parse('metasploit.xml','0',"return")
#print "Final returnrd vales !!"""
#print rss









				
