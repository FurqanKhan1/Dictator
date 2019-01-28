import json
import sys
import re
class Extract_Convert():
	def __init__(self):
		self.json_file=sys.argv[1]
	def process(self):
		with open(self.json_file,"r+") as json_data:
			my_dict=json.loads(json_data.read())
		parent_dict={}
		for k ,v in my_dict.iteritems():
			service=k
			custom=v["Custom"]
			if custom==False:
				print "Service : "+str(service)
				
				for test_case in v["Commands"]:						
						args=test_case["args"]
						
						if test_case["method"] in ["singleLineCommands_Timeout","general_interactive_special_char","test_ssl","general_interactive","generalCommands_Tout_Sniff"]:
							command=args[1]
							parent_dict[test_case["id"]]=command
						elif test_case["method"] in ["custom_meta"]:
							not_found=True
							for arg in args:
								found=re.search(r'.*use auxiliary/.*',arg,re.M|re.I)
								if found is not None:
									#print "Found Buddy !!"
									command=found.group()
									
									not_found=False
									break
								elif re.search(r'.*use scanner/.*',arg,re.M|re.I) is not None :
									found=re.search(r'.*use scanner/.*',arg,re.M|re.I)
									command=found.group()
									
									not_found=False
									break
								elif re.search(r'.*use voip/.*',arg,re.M|re.I) is not None :
									found=re.search(r'.*use voip/.*',arg,re.M|re.I)
									command=found.group()
									
									not_found=False
									break
								elif re.search(r'.*use admin/.*',arg,re.M|re.I) is not None :
									found=re.search(r'.*use admin/.*',arg,re.M|re.I)
									command=found.group()
									
									not_found=False
									break
							if not_found:#else:
									command="Not found meta for id : "+str(test_case["id"])
									
							parent_dict[test_case["id"]]=command	
						else:
							command=args[0]
							parent_dict[test_case["id"]]=command

		with open(sys.argv[2],"w+") as output:
			output.write(json.dumps(parent_dict,ensure_ascii=False,indent=4,sort_keys=True))	
		print "Data written"
obj=Extract_Convert()
obj.process()
