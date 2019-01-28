import json
with open ("all_commands.json","rb") as f:
		json_commands=json.loads(f.read())

updated_json={}


for k,v in json_commands.iteritems(): #k=theservice value is dictionary which is list of dict
	#print str(k)
	updated_command={}
	for ky,vl in v.iteritems():  #as we know that value is dict _>list of dict under commands key
		command =str(ky)
		value=vl
		
		#print "Key is : "+str(ky) +" and value is : "+str(vl)
		if command=="Commands":  #command is a list of dictionaries
			
			my_dict_List=[]
			for each_val in value: #itt over list of dict
				print type(each_val)
				if isinstance(each_val, dict):
					my_dict={}
					my_dict=each_val.copy() #thus dict goes to my_dict
					my_dict["include"]=True
					my_dict_List.append(my_dict)
				elif isinstance(each_val,basestring):
					my_dict_List.append(each_val)
					
			updated_command[command]=my_dict_List
		else:
			updated_command[ky]=vl
			
		#print str(updated_command)
			
		#print str(my_dict_List)
		
		#print str(updated_command)
	updated_json[k]=updated_command


print "Final updated json is : " +str(updated_json)	


with open('updated.json','w') as f:
		json.dump(updated_json,f,sort_keys=True,indent=2,ensure_ascii=False)	
		#commands=val["Commands"]
		#print str(commands)
