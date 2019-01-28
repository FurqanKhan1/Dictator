import json

with open ("all_commands.json","r+") as my_json:
	my_data=json.loads(my_json.read())

i=0;

with open ("services.txt","w+") as output:
	for k in my_data:
		output.write(str(k)+"\n")
		#print str(k)
	#i=i+1


