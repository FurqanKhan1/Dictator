import json

print "Hello\n\n\n"
with open("all_commands.json","rb") as f:
    	json_commands = json.loads(f.read()) 


#with open("data.json","rb") as f:
#	json_nse=json.loads(f.read())

#json_nse_keys=json_nse.keys()
json_command_keys=json_commands.keys()



updated_json={}
counter=0
print "\n\nFollowing are the keys not found in json-nse but are there in commands.json\n\n"
for k,v in json_commands.iteritems():
	print "\n\nCurrent key is --> "+str(k)
	append=False
	commands=[]
	dict_list={}
	service_commands=[]
	service_commands=v.get("Commands")
	is_custom=v.get("Custom")
	if (is_custom==False):
		c=0
		
		#print "Key is :"+str(k) +"\n\n"
		#print "Value is : "+str(v)
		counter_=1
		counter=1
		mod_service_commands=[]	
		#cc={}
		#cc["id"]=00
		#cc["id"]=22
		#print str(cc)
		for command in service_commands:
			id_=command.get("id")
			if(id_):
				print "Got id :" +str(id_)
			else:
				print "Missed id for service -->"+str(k)

	else:
		print "Is custom is true"#commands.append(service_commands)
	
	#dict_list["Commands"]=service_commands
	#dict_list['Custom']=False
	#updated_json[k]=dict_list
	




#The foll commented out is the best method so far --tested and verified
#with open('all_commands.json', 'w') as outfile:
#     json.dump(updated_json, outfile, sort_keys = True, indent = 2,ensure_ascii=False)

"""with open('Merged_commands.json', 'w') as outfile:
     json.dump(updated_json, outfile, indent = 2,
ensure_ascii=False)"""



"""with open('formatted_commands.json', 'w') as outfile:
     json.dump(json_commands, outfile, sort_keys = True, indent = 2,
ensure_ascii=False)"""

"""print "\n\nFollowing are the key found in json-nse but are not there in commands.json--The result set must be ideally empty \n\n"
for k,v in json_nse.iteritems():
	#print "Current key is --> "+str(k)
	if k in json_command_keys:
		#print "Found --Ky :" +str(k)
		found=True
	else:
		print "Not Found key : "+str(k)
"""
