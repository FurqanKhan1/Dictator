import logging
import logging.handlers
import time
class Logger:
	def __init__(self):
		self.logger=None
		self.Log_file=None
		self.loggerInfo=None
		
	def configureLogger(self,method_id,Log_file_name):
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
