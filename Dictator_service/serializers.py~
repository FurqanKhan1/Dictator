"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/3/2017

Objective :
The purpose of this file /module /Class is to validate weathe the posted data to the service method is in the
format that is expected or not.
Actually Each serialiser points towards a class ,and would validate weather the supplied data is in json format or not.It also has the capability to transform json to python objects/instances

An important feature of this file is to validate teh content and type and aurguments of the data that are passed.
Suppose the input expected is 3 integer variables and 2 list variables ,then instead of validating content mannualy ,we map it to a serializer class having 3 integer variables and 2 list variables.If the supplied 
data is valid then the instance of that class is returned and the data can be accessed as the instance vcariables.

"""

from __future__ import unicode_literals
from django.core.validators import RegexValidator

from rest_framework import serializers
# Create your models here.

class Validators:
	"""
	Objective :
	This class has various regular expressions and is used for whitelisting the obtained input
	"""

	def __init__(self):
		"""
		Objective :
		This method actually is the constructor and it initialises varioys regular expressions that will
		be used against data to be validated
		"""

		self.IP=RegexValidator(r'^[0-9a-zA-Z.,/-]*$','The given IP address /Range is in invalid format')
		self.decimal=RegexValidator(r'^[0-9]*$','Invalid value')
		self.Port=RegexValidator(r'^[0-9a-zA-Z_-]*$','Invalid value')
		self.alpha_num=RegexValidator(r'^[0-9A-Za-z]*$','Invalid value')
		self.Project=RegexValidator(r'^[0-9A-Za-z_]*$','Invalid value ,only special character allowed is "_"')
		self.alpha_num_sp=RegexValidator(r'^[0-9A-Za-z_?.-]*$','Invalid value.Only special character allowed is "_" , "?", "-","_",":"')
		self.alpha_only=RegexValidator(r'^[a-zA-Z]*$','Invalid Value Supplied')
		#self.valid_json=

class UserSerializer(serializers.Serializer):
	"""
	Objective :
	This class is only for testing purpose.Does not serve any purpose related to code
	"""

	id=serializers.IntegerField()
	name=serializers.CharField(required=False,allow_blank=True,max_length=100)


class ProfileAttributes(serializers.Serializer):
	profile_name=serializers.CharField(required=True,allow_blank=False,max_length=100,validators=[Validators().Project])
	profile_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_num])
	assessment_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_num_sp])
	profile_json=serializers.CharField(required=True,allow_blank=False)



class ScanAttributes(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the scan attributes/inputs which are needed to begin a new scan
	"""

	project_name=serializers.CharField(required=True,allow_blank=False,max_length=100,validators=[Validators().Project])
	IP_range=serializers.CharField(required=True,allow_blank=False,validators=[Validators().IP])
	Port_range=serializers.CharField(required=True,allow_blank=False,validators=[Validators().Port])
	switch=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	#scan_type=serializers.IntegerField()
	#project_id=serializers.CharField(required=True,allow_blank=False)
	assessment_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_num_sp])
	app_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_num_sp])
	mode=serializers.CharField(required=True,allow_blank=False,validators=[Validators().Project])
	profile=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	edit_profile=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	profile_json=serializers.CharField(required=True,allow_blank=False)

	#'test_path','test-host','test-port','test-switch','1','test-project','test-assessment','1'

class General(serializers.Serializer):
	project_id=serializers.CharField(required=True,allow_blank=False,max_length=100,validators=[Validators().decimal])
	assessment_id=serializers.CharField(required=False,allow_blank=True,validators=[Validators().alpha_num_sp])
	app_id=serializers.CharField(required=False,allow_blank=True,validators=[Validators().alpha_num_sp])


class ProjectSerializer(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the project attributes which have project id and project name
	"""

	id=serializers.CharField(required=True,allow_blank=False,max_length=1000,validators=[Validators().decimal])
	name=serializers.CharField(required=True,allow_blank=True,max_length=100,validators=[Validators().Project])

class Configuration(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the configuration attributes which are needed to 
	get updated configuration for changing config in vulnerability scanning phase
	"""

	id=serializers.CharField(required=True,allow_blank=False,max_length=1000,validators=[Validators().decimal])
	project_id=serializers.CharField(required=True,allow_blank=False,max_length=1000,validators=[Validators().decimal])
	host=serializers.CharField(required=True,allow_blank=False,validators=[Validators().IP])
	port=serializers.CharField(required=True,allow_blank=False,validators=[Validators().Port])
	service=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_num_sp])
	project_status=serializers.CharField(required=False,allow_blank=True,validators=[Validators().alpha_only]) #no need to share this field
	project_test_data=serializers.CharField(default="hello!!")
	Commands=serializers.ListField(child=serializers.DictField())
	reconfig_service=serializers.BooleanField(default=False,validators=[Validators().alpha_only])
	reconfig_exploit=serializers.BooleanField(default=False,validators=[Validators().alpha_only])
	

class test_multi(serializers.Serializer):
	"""
	Objective :
	This class validates weather input supplied has both id and app_key
	"""

	id=serializers.CharField(required=True,allow_blank=False,max_length=1000,validators=[Validators().decimal])
	name=serializers.CharField(required=True,allow_blank=True,max_length=100,validators=[Validators().alpha_num_sp])
	app_key=serializers.CharField(required=True,allow_blank=True,max_length=100,validators=[Validators().alpha_num_sp])

class Exploits(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the Vulnerability scan attributes which are needed to begin a new
 	vulnerability scan
	"""
	project_id=serializers.CharField(required=True,allow_blank=False,max_length=100,validators=[Validators().decimal])
	threading=serializers.BooleanField(default=False,validators=[Validators().alpha_only])

class ExploitsConcurrent(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the Vulnerability scan attributes which are needed to begin a new
 	vulnerability scan in conurrent mode
	"""
	project_id=serializers.CharField(required=True,allow_blank=False,max_length=100,validators=[Validators().decimal])
	threading=serializers.BooleanField(default=False,validators=[Validators().alpha_only])
	record_list=serializers.ListField(child=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal]))

class UploadXml(serializers.Serializer):
	"""
	Objective :
	This class validates attributes to upload xml report(nessus,qualys,nmap)
	"""
	
	project_name=serializers.CharField(required=True,allow_blank=False,validators=[Validators().Project])
	filename=serializers.FileField(required=True,allow_empty_file=False)



class UploadXmlNmap(serializers.Serializer):
	"""
	Objective :
	This class validates attributes to upload xml report(nessus,qualys,nmap)
	"""
	
	project_name=serializers.CharField(required=True,allow_blank=False,validators=[Validators().Project])
	filename=serializers.FileField(required=True,allow_empty_file=False)
	assessment_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_num_sp])
	#profile=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	app_id=serializers.CharField(required=False,allow_blank=False,validators=[Validators().alpha_num_sp])



class Polling_(serializers.Serializer):
	"""
	Objective :
	This class validates attributes required for updating polling results
	which include project id and record_list for which the read status would be updated to True
	"""
	project_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	record_list=serializers.ListField(child=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal]))

class Merge_reports(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the Merge_report functionality attributes
	"""
	
	project_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	report_format=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_only])

class OnFly(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the attributes that are needed to map qualys-exploit mapping
	or nessus-exploit mapping on the fly-without saving details in teh database.By just parsing
	the report and merging it with exploits data
	"""
	
	report_format=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_only])
	filename=serializers.FileField(required=True,allow_empty_file=False)
	source=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_only])

class Poll_me(serializers.Serializer):
	"""
	Objective :
	This class validates and transforms the attributes needed to update polling status of discovery
	""" 
	
	alpha=RegexValidator(r'^[0-9a-zA-Z/]*$','Only alpha numeric characters allowed')
	project_id=serializers.CharField(required=True,allow_blank=False,validators=[Validators().decimal])
	source=serializers.CharField(required=True,allow_blank=False,validators=[Validators().alpha_only])
	


	



	
	



