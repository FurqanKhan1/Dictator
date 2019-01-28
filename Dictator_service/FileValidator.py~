"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to validate weather the file passes to it is of type xml pr not.If 
the type and content of the file matches with xml format then it returns true else false.
"""
import magic
class FileValidator():
		"""
	
		Objective :
		This is the FileValidator class and has responsibility validating type and content of incomming file
		"""

		def validateXML(self,XMLfile):
			"""
			Objective :
			This is the method which validates weather the content of the passed file is of type xml or
 			not.If yes then it returns true else returns false.
			"""

			file_type=magic.from_buffer(XMLfile.read())
			if not "XML" in file_type:
				return 0
			else:
				return 1
			
