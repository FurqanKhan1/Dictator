"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:12/30/2016

Objective :
The purpose of this file /module /Class is to take data from various other classes /methods and log
it into a file for debugging and execution flow information.
This class makes use of generic python logging module which serves as a global logger 
for the whole scope of the project .But note that we make use of this logger only for vulnerability 
scanning phase.For discovery phase we make use of simple text based log files to log the details and 
execution flow

"""

import logging
import logging.handlers
import time
class Logger:
	"""
	Objective :
	This is the logger class which will log messages to text file
	"""
	def __init__(self):
		"""
		Objective :
		This is the init method of logger where looger variables are initialized
		"""
	
		self.logger=None
		self.Log_file=None
		self.loggerInfo=None
		
	def configureLogger(self,method_id,Log_file_name):
		"""
		Objective :
		This is the method which will actually configure the logger and would invoke the constructor
		of the python logger module passing the logger name as aurgument and also the default logger
		file size as aurgument.The logger configured here will log the commands executed and the results
		produced by the executed commands
		"""
	
		self.logger=None
		#self.Log_file=None
		#print "->Log file passed is " +str(Log_file_name)
		self.logger = logging.getLogger("Commands Logger")
		self.logger.setLevel(logging.DEBUG)
		handler = logging.handlers.RotatingFileHandler(Log_file_name, maxBytes=(1048576*10), backupCount=7)
		formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
		handler.setFormatter(formatter)
		self.logger.addHandler(handler)
		return self.logger

	def configureLoggerInfo(self,method_id,Log_file_name):
		"""
		Objective :
		This is the method which will actually configure the logger and would invoke the constructor
		of the python logger module passing the logger name as aurgument and also the default logger
		file size as aurgument.The logger configured here will log the execution flow of the code as in
		when method starts execution and when it ends.This shall help in debugging issues if any
		
		"""
	
		self.loggerInfo=None
		#self.Log_file=None
		print "hello@@"
		print "->\n\n\nLog file passed is " +str(Log_file_name)
		time.sleep(5)
		self.loggerInfo = logging.getLogger("Info Logger")
		self.loggerInfo.setLevel(logging.DEBUG)
		handler = logging.handlers.RotatingFileHandler(Log_file_name, maxBytes=(1048576*10), backupCount=7)
		formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
		handler.setFormatter(formatter)
		self.loggerInfo.addHandler(handler)
		return self.loggerInfo
