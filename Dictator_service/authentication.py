"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:12/30/2016

Objective :
The purpose of this file /module /Class is to authenticate the incomming request.
Any time any service url is requested ,the first hit will come to this class where it is verified 
weather the incomming request has the api key or not.If the api key is not present of is invalid the request is dropped

"""
from __future__ import unicode_literals
from rest_framework import authentication
from rest_framework import exceptions
from django.contrib.auth.models import User
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.parsers import JSONParser
import IPtable
# Create your models here.


class AppAuthentication(authentication.BaseAuthentication):
	"""
	Objective :
	This class will do the Custom authentication and would verify the auth-key with mysql database 
	"""

	def authenticate(self,request):
		"""Objective :
		This method would actually obtain the API key from the rest requst and would validate the key
		against the database for registered apps and the key matches valid record the request is forwarded to 			intended url /method or else the request is dropped and Authentication exception is raised
		"""
		print "Hello world reached here "
		self.auth=IPtable.Application_auth()
	
		data_=request.data
		try:
			print str(data_)
			for k,v in data_.iteritems():
				print "key :"+str(k)
				print "Val" +str(v)
			app_key=data_["app_key"]
			#print "key is : "+str(app_key)
		except :
			raise exceptions.AuthenticationFailed('No API Key Supplied ')

		if not app_key:
			#print "going to return none "
			raise exceptions.AuthenticationFailed('No API Key Supplied ')
		try:
			#print "Not executed !!!"
			app=self.auth.authenticate(app_key)
			#print "app is : "+str(app)
			if app:
				print "Authenticated"
				request.session["app_id"]=str(app_key)
				app_user=User(username=app_key)
			else:
				print "Not Authenticated"
				raise exceptions.AuthenticationFailed('in valid app trying to access API')
				
		except Exception ,ee:
			print "Exception "+str(ee)
			raise exceptions.AuthenticationFailed('in valid app trying to access API')
		return (app_user,None)
	
