import json
import sys
import re
class Extract_Convert():
	def __init__(self):
		self.json_file=sys.argv[1]
	def process(self):
		with open(self.json_file,"r+") as json_data:
			my_dict=json.loads(json_data.read())
		output_file=open("output.html","w+")
		output_file.write("<html><head></head><body><table border='1px'>")
		
		for k ,v in my_dict.iteritems():
			service=k
			custom=v["Custom"]
			output_file.write("<tr><td>Service : "+str(service)+"</td>")
			#output_file.write("Service : "+str(service)+"")
			if custom==False:
				print "Service : "+str(service)
				output_file.write("<td>")
				for test_case in v["Commands"]:						
						args=test_case["args"]
						#output_file.write("Method : " +str(test_case["method"])+"\n")
						
						if test_case["method"] in ["singleLineCommands_Timeout","general_interactive_special_char","test_ssl","general_interactive","generalCommands_Tout_Sniff"]:
							command=args[1]
							output_file.write(str(command).replace("<","&lt").replace(">","&gt"))
							output_file.write("<br>")
						elif test_case["method"] in ["custom_meta"]:
							not_found=True
							for arg in args:
								found=re.search(r'.*use auxiliary/.*',arg,re.M|re.I)
								if found is not None:
									#print "Found Buddy !!"
									command=found.group()
									output_file.write(command)
									output_file.write("<br>")
									not_found=False
									break
								elif re.search(r'.*use scanner/.*',arg,re.M|re.I) is not None :
									found=re.search(r'.*use scanner/.*',arg,re.M|re.I)
									command=found.group()
									output_file.write(command)
									output_file.write("<br>")
									not_found=False
									break
								elif re.search(r'.*use voip/.*',arg,re.M|re.I) is not None :
									found=re.search(r'.*use voip/.*',arg,re.M|re.I)
									command=found.group()
									output_file.write(command)
									output_file.write("<br>")
									not_found=False
									break
								elif re.search(r'.*use admin/.*',arg,re.M|re.I) is not None :
									found=re.search(r'.*use admin/.*',arg,re.M|re.I)
									command=found.group()
									output_file.write(command)
									output_file.write("<br>")
									not_found=False
									break
							if not_found:#else:
									command="Not found meta for id : "+str(test_case["id"])
									output_file.write(command)
									output_file.write("<br>")
								
						else:
							command=args[0]
							output_file.write(command)
							output_file.write("<br>")
						print "Command is : "+str(command) +" and command id is "+str(test_case["id"])
				output_file.write("</td></tr>")	
				print "\n\n"
			else:
				print "Service : "+str(service)
				output_file.write("<td>")
				for custom_cases in v["Commands"]:
					
					command="Test cases for service "+str(custom_cases)
					print command
					output_file.write(command)
					output_file.write("<br>")
					print "\n"
				output_file.write("</td></tr>")
		output_file.write("</table></body></html>")
		output_file.close()
obj=Extract_Convert()
obj.process()
