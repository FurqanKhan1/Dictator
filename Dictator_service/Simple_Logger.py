"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to log the execution flow in a text file in unformatted way
"""
import time
class SimpleLogger:
	def __init__(self):
		self.logger=None
		self.Log_file=None
		self.loggerInfo=None
	
	def log(file_path,message):
		try:
			output = open(file_path,"a") #create a html report file and open it
			output.write(message)
			output.close()
		except Exception ,ee:
			print "EXception while logging at simple logger"
			

