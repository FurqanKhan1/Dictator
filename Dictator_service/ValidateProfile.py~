import json
import os
import IPtable
class Profile():

	def __init__(self):
		self.folder_dir=os.path.dirname(os.path.realpath(__file__))

	def CreateCustom(self,data_path,profile_json,scan_id,profile_id,assessment_id):#project specific profile
		try:
			ret_val={}
			profile_list=IPtable.Projects().Profile(profile_id)
			profile=profile_list[0]
			ret_val["status"]="failure"
			if profile ==-1:
					ret_val["value"]= "The profile does not exist"
					return ret_val
			if profile=="Master":
				custom_file=os.path.join(data_path,"Custom_Master_"+str(scan_id)+".json")
			
			elif profile=="Custom_Mandatory" or profile=="Mandatory":
				custom_file=os.path.join(data_path,"Custom_Mandatory_"+str(scan_id)+".json")
			elif profile=="Custom_Analytical" or profile=="Analytical":
				custom_file=os.path.join(data_path,"Custom_Analytical_"+str(scan_id)+".json")
			else:
				custom_file=os.path.join(data_path,"Custom_"+str(scan_id)+".json")
			save_p=IPtable.Projects().SaveProfile(custom_file,assessment_id,str(scan_id),"Project_Specific")
			if save_p["status"]=="success":
				with open (custom_file,"w+") as custom:
					custom.write(json.dumps(profile_json,indent=4))

				return save_p
			else:
				return save_p
		except Exception ,ex:
			ret_val["status"]="failure"
			ret_val["value"]= str(ex)
			return ret_val

	def validateProfile(self,profile_id,profile_json): #only needed when edit option is enabled
		try:
				profile_list=IPtable.Projects().Profile(profile_id)
				profile=profile_list[0]
				print "Output is : "+str(profile) +str(profile_list)
				if profile ==-1:
					return -2
				if profile=="Master":
					profile_file=os.path.join(self.folder_dir,"Master.json")
				elif profile=="Custom_Mandatory" or profile=="Mandatory":
					profile_file=os.path.join(self.folder_dir,"Mandatory.json")
				elif profile=="Custom_Analytical" or profile=="Analytical":
					profile_file=os.path.join(self.folder_dir,"Analytical.json")
				else:
					profile_file=profile_list[1]
				
				with open(profile_file, 'r+') as infile:
					profileJson=json.loads(infile.read())
				
				is_valid=True

				for k,v in profile_json.iteritems():
					parent_test_cases=profileJson[k]["Test_cases"]
					for tc in v["Test_cases"]:
						if tc not in parent_test_cases:
							is_valid=False
							break
					if is_valid==False:
						break

				if is_valid==True:
					return 1
				else:
					return -1
		except Exception ,ex:
			print "EXception : " +str(ex)
			return str(ex)
