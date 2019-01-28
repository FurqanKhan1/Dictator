"""

	[H]ttp [OP]tions Checker in [PY]thon

	hoppy - a (dirty) python script to test webserver methods: 
	 		it gets options then tests all known methods not just those returned by options
	 		basic parsing is emplloyed to see if the server told us anything of interest
	 			 		
	hopclass.py is the class file for this project	
	
	Copyright (C) 14/03/2007 - deanx <RID[at]portcullis-secuirty.com>
	
	Version 1.8.1
	
	* This program is free software; you can redistribute it and/or modify
	* it under the terms of the GNU General Public License as published by
 	* the Free Software Foundation; either version 2 of the License, or
	* (at your option) any later version.
	*
 	* This program is distributed in the hope that it will be useful,
 	* but WITHOUT ANY WARRANTY; without even the implied warranty of
 	* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 	* GNU General Public License for more details.
 	*
 	* You should have received a copy of the GNU General Public License
 	* along with this program; if not, write to the Free Software
 	* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.	

"""


import socket, re, base64, os, sys

six = 1
try:
	import ssl
except ImportError, e:
	six = 0



exclusion = [ "gif", "jpeg", "jpg", "jpe", "png", "vis", "tif", "tiff", "psd", "bmp", "ief", "wbmp", "ras", "pnm", "pbm", "pgm", "ppm", "rgb", "xbm", "xpm", "xwd", "djv", "djvu", "iw4", "iw44", "fif", "ifs", "dwg", "svf", "wi", "uff", "mpg", "mov", "mpeg", "mpeg2", "avi", "asf", "asx", "wmv", "qt", "movie", "ice", "viv", "vivo", "fvi", "tar", "tgz", "gz", "zip", "jar", "cab", "hqx", "arj", "rar", "rpm", "ace", "wav", "vox", "ra", "rm", "ram", "wma", "au", "snd", "mid", "midi", "kar", "mpga", "mp2", "mp3", "mp4", "aif", "aiff", "aifc", "es", "esl", "pac", "pae", "a3c", "pdf", "doc", "xls", "ppt", "mp", "msi", "rmf", "smi", "bin", "ps", "eps", "exe"] # array conating those extensions that we shoud not get when spidering

def higlightip(message): # function to highlight IP addresses
	messageip = regex.ip2.search(message).group()
	message = message.replace(messageip, '\033[31m' + messageip + '\033[0;0m')
	return message

def highlightpath(message): # function to highlight internal paths
	if regex.pathl.search(message): # are we linux
		path = regex.pathl
	else:
		path = regex.pathw # or are we windows
	messagepath = path.search(message).group()
	message = message.replace(messagepath, '\033[34m' + messagepath + '\033[0;0m')
	if len(message) > 130: # truncate if line is too long
		char = message.lower().find(messagepath.lower())
		beg = char - 65
		if beg < 0:
			beg = 0
		end = beg + 130
		return message[beg:end]
	return message

def highlightkey(message, key):
	#print message
	char = message.lower().find(key.lower())
	char2 = len(key)
	if len(message) > 130: # truncate if length of line is too long
		beg = char - 65
		if beg < 0:
			beg = 0
		end = beg + 130
		messageh = message[beg:char] + '\033[32m' + message[char:char+char2] + '\033[0;0m' + message[char+char2:end]
	else:
			messageh = message[:char] + '\033[32m' + message[char:char+char2] + '\033[0;0m' + message[char+char2:]
	return messageh
 	


nothreading = 0
try:
	import threading
	from threading import Thread
except ImportError, e:
	nothreading = 1

if not nothreading: # set up the thread class
	class testit(Thread):
		def __init__ (self,testhost,test, path):
			Thread.__init__(self)
			self.testhost = testhost 
			self.test = test
			self.path = path
		
		def run(self):

			self.testhost.send(self.test)
			self.test.getLinks()
			#self.test.export(sys.stdout, 3)
			self.testhost.disk.acquire() #only write to disk/screen and run processing on out own
			try:
				self.testhost.parseLinks(self.test.links, self.path)
				if self.testhost.savespider:
					self.test.export(self.testhost.savespider,3)
					for p in self.test.links:
						if p[0] == "/":
							self.testhost.savespider.write('\n\t\t' + p)
						else:
							self.testhost.savespider.write('\n\t\t' + self.path + p)
					self.testhost.savespider.flush()
			finally:
   				self.testhost.disk.release() # release lock, no matter what				
			self.testhost.pool_sema.release()   



class connection: 
	"Server Object"
	def __init__(self):
		self.port = ''
		self.ssl = 0
		self.file = 'dummy.txt'
		self.location = '/images'
		self.timeout = 10
		self.errors = 0
		self.proxyon = 0
		self.noproxy = 0
		self.b64auth = ''
		self.connection = ''
		self.host = ''
		self.hostname = ''
		self.nossl = 0
		self.errors = 0
		self.tests = []
		self.leak = []
		self.pathleak = []
		self.ipleak = []
		self.auth = []
		self.authmethods = []
		self.extract = []
		self.locations = ["/"]
		self.dirs = ["/"]
		self.save = ''
		self.actualfiles = {} # dictionary of parsed links
		self.cookie = ''
		self.savespider = ''
		self.savesummary = ''
		self.depth = 10
		
	def __finished(self, data, got, length): # check to see if we should wait for anymore data, return 0 on finish else length, -2 if chunked
		header = 0
		if got > 500000: # drop out if we fetch more than 500K
			return 0
		if data.lower().find('transfer-encoding: chunked') >= 0 or length == -2: # Dirty!
			try:
				if data.splitlines()[-2] == '0': # Dirtier but speeds things up! finds the last line of chunk decoded data
					return 0
			except IndexError: 
				pass
   			return -2
		elif length < 0 and data and data.splitlines()[0].lower().find('http') == 0: # Get Content Length
			header = len(data.split('\r\n\r\n')[0]) # remove header length from caalculation
			for content in data.splitlines(): # process a line at a time
				if content.lower().find('content-length') == 0:
					hhh = content.split(':')
					try:
						length = header + int(hhh[1]) # assign the content length
					except ValueError: # need this but not sure why had an error during testing but clause never met, thinks it a thread thing
						pass
                                        except IndexError: # need this but not sure why had an error during testing but clause never met, thinks it a thread thing
                                                pass
					#print 'found length ' + str(length) + ' got so far ' + str(got) 
					break
				elif data.find('\r\n\r\n') < 0: # have we got the whol header
					length = -3 # content length not in header
		if (length > 0 and got < length): # detect if we have downloaded less than the content length
			return length			
		if not data or (len(data[header-1:].splitlines()[-1]) == 0 and (header+4) < len(data)) or (length > 0 and got > length): # have we finished then?
			return 0
		return length
	
	def print2(self, text): # write to screen and disk
		print text,
		if self.save:
			self.save.write(text)
			self.save.flush()
			self.savesummary.write(text)
			self.savesummary.flush()
	
	def parseLinks(self, links, path): # check for unique links 
		for link in links:
			if link[-1] == '/' and len(link) > 1: # are we a directory?
				end = '/'
			else:
				end = ''
				
			if link[0] == '/': # are we relative?
				link = os.path.normpath(link) + end
			else:
				#print path + " ! " + link
				link = os.path.normpath(path + link) + end
			if link.count('/') > int(self.depth) + 1:# self.depth:
				continue			
			l =  link.split('?')[0] # make sure we are not recursivly getting session based gets
			if link != l: 
				num = self.actualfiles.get(l, 0)
				if num > 15: # break if we have seen this link alot
					break
				self.actualfiles.update({l:num+1}) # update the score
					
			if link not in self.locations:# and link != '//':
				if link.split(".")[-1].lower() not in exclusion: # check extension
					self.locations.append(link)
				linkpath = os.path.dirname(link.split('?')[0]) # extract dir less the get information
				if linkpath not in self.dirs: # and len(linkpath) >1:
					comp = linkpath.split('/')
					compbuild = ''
					for part in comp[1:]: # only use part to remove excess /'s, recursivly build directory tree so we set it all
						compbuild = compbuild + '/' + part
						if compbuild not in self.dirs:
							self.dirs.append(compbuild)
							self.print2("\n\t\t" + compbuild + "/")
						if compbuild + "/" not in self.locations:
							self.locations.append(compbuild + "/")
								
	def spider(self, threads): # spider method on server
		
		if self.savespider:
			self.savespider.write('\n[+] Spider Beggining for ' + self.host + ':'  + self.port + ' with a Virtual Host of ' + self.hostname + '\n')
			self.savespider.write("\n\t[+] Start points are  '/' and '" + self.location + "/" + self.file + "'\n")
		if self.proxyon and not self.ssl:
			gent = 'GET http://(realhost):(port)(location) HTTP/1.1\r\nHost: (host)\r\n(cookie)\r\n(auth)\r\n\r\n'
		else:
			gent = 'GET (location) HTTP/1.1\r\nHost: (host)\r\n(cookie)\r\n(auth)\r\n\r\n'

		# parse the output and get out all links
		# add full file + path to location and dirs to dirs if not it etc...
		# loop around the locations stack to get all files and parse out locations
		# lets not get jpg, pdf, tiff etc but hey
		# also recursive loop gets need to be fixed!
		# print out new dirs when found
		# do we thread this bit?
		
		self.locations.append(self.location + "/" + self.file) # add spider start
		try:		
			if threads == 1: # non threaded run
				visited = 0
				for loc in self.locations:
					if len(self.locations) > 1000: # or we have toooo many links anyhow
						break
					path = os.path.dirname(loc) + "/"
					if path == '//':
						path = '/'
					req = gent.replace('(location)',loc)
					reqo = test('GET','X', req)
					self.send(reqo)
					reqo.getLinks()
					self.parseLinks(reqo.links, path)
					if self.savespider:
						reqo.export(self.savespider,3)
						for p in reqo.links:
							if path[0] == "/":
								self.savespider.write('\n\t\t' + p)
							else:
								self.savespider.write('\n\t\t' + path + p)
						self.savespider.flush()

			else: # we are threaded
				self.disk = threading.Lock()
				self.pool_sema = threading.BoundedSemaphore(threads)
				visited = 0
				while len(self.locations) > visited: # need to wait till all threads are done before we decide if we have finished
					if len(self.locations) > 10000: # or we have toooo many links anyhow
						while (threading.activeCount() > 1):
							pass	
						break
					for loc in self.locations[visited:]:			# test methods from file
						path = os.path.dirname(loc) + "/"
						if path == '//':
							path = '/'
						req = gent.replace('(location)',loc) # build new request
						reqo = test('GET','X', req)
						self.pool_sema.acquire() # block till we have a new thread
						current = testit(self, reqo, path)
						#current.setDaemon()
						current.start() # non blocking start to threads
						visited += 1
					while (threading.activeCount() > 1):
						pass							
			if len(self.dirs) > 0:
				self.print2("\n\n\t[+] Spider Completed :-)")
				self.print2("\n\n\t[+] Found " + str(len(self.dirs)-1) + " directories for testing\n")
			else:
				self.print2("\n\t[+] Spider Completed :-)\n")
				self.print2("\n\t[!] Nothing Found, sorry\n")
							
		except KeyboardInterrupt:	
			self.print2('\n\n\t[!] Waiting for Threads to Finish ;-)\n')
			try:
				while (threading.activeCount() > 1): # wait for all the threads to finish
					pass
			except KeyboardInterrupt:
				pass
			if len(self.dirs) > 0:
				self.print2("\n\n\t[!] Premature End to the spider")
				self.print2("\n\n\t[+] Found " + str(len(self.dirs)-1) + " directories for testing\n")
			else:
				self.print2("\n\t[+] Premature End to the spider\n")
				self.print2("\n\t[!] Nothing Found, sorry\n")
		return
				
	def exportSummary(self, file, fof): # print the summary 
		file.write('\n\n[+] Summary of Findings\n')
		types = []
		ignorecodes = [404, 100, 000, 301, 400]
		interesting = []		

		for check in self.tests:
			for rescode in check.resline:
				if (check.name + ',' + rescode[1]) not in types: # check for duplicates
					if not (ignorecodes.count(rescode[0]) or check.name[:4] == "Info") or fof: # are we -4 or not ignoring it
						#sys.stdout.flush()
						types.append(check.name + ',' + rescode[1])
					if str(rescode[0]) == check.interesting:
						interesting.append(check.name + ',' + rescode[1])
						
		types.sort()
		interesting.sort()
		if len(types) > 0:
			file.write('\n\t[+] Method Responses:\n')
			for data in types:
				name, got = data.split(',', 1)
				file.write('\n\t\t%-25s -\t %s' % (name, got))
		if len(interesting) > 0:
			file.write('\n\n\t[+] Interesting Method Responses:\n')
			for data in interesting:
				name, got = data.split(',', 1)
				file.write('\n\t\t%-25s -\t %s' % (name, got))
		if len(self.leak) > 0: # print infrmation leakage
			file.write('\n\n\t[+] Information Leakage:\n')	
			for data in self.leak:
				file.write('\n\t\t' + data)
		if len(self.ipleak) > 0: # print IP leakage
			file.write('\n\n\t[+] IP Leakage:\n')	
			for data in self.ipleak:
				iph = higlightip(regex.ips.search(data).group()) # highlight IP address
				file.write('\n\t\t' + iph)
		if len(self.pathleak) > 0: # print path leakage
			file.write('\n\n\t[+] PATH Leakage:\n')	
			for data in self.pathleak:
				pathh = highlightpath(data)
				file.write('\n\t\t' + pathh)
		if len(self.authmethods) > 0: # print auth leakage
			file.write('\n\n\t[+] Avaliable Auth Methods:\n\n\t\t' + str(self.authmethods))
		if len(self.auth) > 0: 
			file.write('\n\n\t[+] AUTH Leakage:\n')	
			for data in self.auth:
				file.write('\n\t\t' + data)
		if len(self.extract) > 0: # print extracted data
			file.write('\n\n\t[+] Extracted Data:\n')	
			for data in self.extract:
				file.write('\n\t\t' + data)
		file.write('\n\n')
				
	def summary(self): # summarise all the tests we performed
		for job in self.tests:
			for resp in job.summary:
				resp = resp.strip()	# Find all matching headers and print once
				authed = 0 
				if resp.lower().find('www-authenticate') == 0 or resp.lower().find('proxy-authenticate') == 0: # bas64decode the NTLM header
					authed = 1
					authmeth = resp.split()[1]
					if authmeth not in self.authmethods: 
						if authmeth == 'Negotiate' and 'NTLM' not in self.authmethods: # only add one
							self.authmethods.append('NTLM')
						elif authmeth.lower() == 'basic' or authmeth.lower() == 'digest':
							try:
								self.authmethods.append(authmeth)
								realm = authmeth + ' Auth Realm = "' + resp.split('"')[1] + '"'
								if realm not in self.auth:
									self.auth.append(realm)
							except IndexError:
								pass	
						elif authmeth != 'Negotiate':	# add all others
							self.authmethods.append(authmeth)
					try:
						all = resp.split()[2] # try to extract machine/domain data
						machine = unicode(base64.b64decode(all)[56:], 'utf-8', 'replace') # only get a bit of the string
						machine = 'NTLM Info "' + machine.encode('ascii', 'replace') + '"'
						if machine not in self.auth and all[:5] == "TlRMT": # we got a good decode
							self.auth.append(machine)			 # Append leak text
					except TypeError:
						pass
					except IndexError:
						pass
				if resp.find('{extract}') == 0: # detect and append extracted data
					resp = resp.replace('{extract}', '')
					if resp not in self.extract:
						self.extract.append(resp)
					continue
				if resp not in self.pathleak and (regex.pathl.search(resp) or regex.pathw.search(resp)): # append path leakage
					self.pathleak.append(resp)
				if resp not in self.ipleak and regex.matchip(resp): # append ip leakage
					self.ipleak.append(resp)
				if not authed and resp not in self.leak and resp not in self.ipleak and resp not in self.pathleak and resp not in self.extract and resp not in self.auth:
					self.leak.append(resp) # append other stuff
		self.leak.sort()	
	
	def addAuth(self, auth): # create and add basic auth
		print '\n\t[+] Adding Basic Auth of "' + auth + '"'
		self.b64auth = base64.encodestring(auth)
	
	def removessl(self): # nossl
		self.nossl = 1
		
	def removeproxy(self):
		self.noproxy = 1
		
	def checkConfig(self):
		h = regex.host.match(self.host) # extract the information from the passed -h flag
		protocol = h.group(1)
		auth = h.group(3)
		host = h.group(4)
		port = h.group(6)
		location = h.group(8)
		file = h.group(9)
		if auth:
			self.addAuth(auth)	
		if protocol and protocol.lower() == 'https://':
			if not self.nossl:
				self.ssl = 1
			if not self.port:
				self.port = '443'	
		if port:
			self.port = port
		if location:
			self.location = location
		if file:
			self.file = file
			if not location:
				self.location = '/'	
		self.host = host
				
		if self.port == str(443) and not self.nossl:
			self.ssl = 1
		if not self.hostname:
			self.hostname = self.host
		if not self.port:
			if self.ssl:
				self.port = '443'
			else:	
				self.port = '80'	
		
	def send(self, test): # send the test
		timedout = 0
		returnbuff = []
		text = test.method
		connecthead = 'CONNECT ' + self.host + ':' + self.port + ' HTTP/1.0\r\nHost: ' + self.hostname + '\r\n\r\n'
		#connecthead = 'CONNECT ' + test.name + ' HTTP/1.1\r\nHost: ' + test.name + '\r\n\r\n'
		text = text.replace('(host)',self.hostname) # replace the place holders
		text = text.replace('(realhost)',self.host)
		text = text.replace('(port)',self.port)
		text = text.replace('\\n','\r\n')
		if self.b64auth:
			text = text.replace('(auth)\r\n','Authorization: Basic ' + self.b64auth)
		else:
			text = text.replace('(auth)\r\n','')
		if self.cookie:
			text = text.replace('(cookie)','Cookie: ' + self.cookie)
		else:
			text = text.replace('(cookie)\r\n','')

		split = text.split('(wait)')
		test.sent = split
		data = ''
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # open the socket
		length = 0
		try:
			s.connect(self.connection)
			if self.ssl: # do it over ssl
				if self.proxyon:
					s.send(connecthead)
					data = s.recv(8192)
				if six:
					ssl_sock = ssl.wrap_socket(s)
				else :
					ssl_sock = socket.ssl(s) #, certfile="cert.pem", keyfile="key.pem")
				for line in split: # if we a re multi stage request then send all of them
					ssl_sock.write(line)
					s.settimeout(self.timeout)
					total_data = []
					length = -1
					while True: # keep looping till timeout or finished
						try:
							data = ssl_sock.read()
						except socket.error:
							timedout = 1
							break
						except socket.sslerror:
							break
						total_data.append(data)
						if length == -3:
							length = self.__finished(''.join(total_data), len(''.join(total_data)), length) # detect a finished connection
						else:
							length = self.__finished(data, len(''.join(total_data)), length) # detect a finished connection
						#print length
						if not length:
							break
					returnbuff.append(''.join(total_data)) # add the data to the buffer
				del ssl_sock # remove ssl socket
			else: # do it over plain http
				for line in split: # if we a re multi stage request then send all of them
					timedout = 0
					s.send(line)
					total_data = []
					s.settimeout(self.timeout)
					length = -1
					while True: # keep looping till timeout or finished
						try:
							data = s.recv(8192)
						except socket.error,e:
							timedout = 1
							break
						total_data.append(data)					
						if length == -3:
							length = self.__finished(''.join(total_data), len(''.join(total_data)), length) # detect a finished connection
						else:
							length = self.__finished(data, len(''.join(total_data)), length) # detect a finished connection
						#print length
						if not data or not length:
							break
					returnbuff.append(''.join(total_data))
			if timedout:
				test.result = '!' # we timed out rather than completed
			else:
				test.result = '.' # good we did it
					
		except socket.error, e: # oh dear something went wrong
			(num, name) = e
			test.result = name
		s.close()
	 	test.recieved = returnbuff # tell the caller what happended
		
	#sys.exit(2)

class test: # test class

	def __init__(self, name, interesting, method): 
		self.name = name
		self.method	= method
		self.recieved = ''
		self.sent = ''
		self.result = ''
		self.resline = []
		self.summary = []
		self.links = []
		self.interesting = interesting
	
	
	def summarise(self, keywords): # parse the repsonce and extract the data we want
		authmatch = ["-Authenticate","TlRMTVNTUAA"]
		if self.recieved:
			for line in self.recieved:
				allow = line.splitlines()
				if allow:
					match = regex.p.search(allow[0])	# match a server code 
					if match:			# Append Server Response
						code = int(match.group())
					else:
						code = 888
					self.resline.append([code, allow[0]])
					for x in allow:			# print intersting lines from server response and saves to a list
						x = x.lstrip().rstrip()
						if regex.matchip(x) or regex.pathw.search(x) or regex.pathl.search(x) and x not in self.summary:	# match an ip address and add
							self.summary.append(x)
						else:
							for y in authmatch:
								n = x.lower()[:20].find(y.lower())
								if n >= 0 and x not in self.summary: # n <10 cause for some reason we 
									self.summary.append(x)
									break
							for y in keywords:	# try matching keywords from file 
								name, method = y.split(',', 1)
								if ((x.lower().find(name.lstrip().rstrip().lower()) >= 0 and int(method)) or x.lower().find(name.lstrip().rstrip().lower()) == 0) and x not in self.summary:
									if (int(method) == 2):
										self.summary.append('{extract}' + self.name + ':\t\t ' + highlightkey(x, name))
									else:
										self.summary.append(highlightkey(x, name))
				else: # we got no data back so something went wrong!
					self.resline.append([000,'HTTP/1.1 000 This Test Falied!'])
			return 1
		return 0
		

	def export(self, file, verbose): # put the test data to screen and/or disk
		
		i = 0
		if verbose >= 2: # print the sent and recievned if we are in verbose mdoe.
			for line in self.sent: # print the test data
				if verbose > 2:
					file.write('\n\nWe Sent:\n\n' + line + '\n')
					if len(self.recieved) > i:
						file.write('\nServer Responded:\n\n' + self.recieved[i]  + '\n')
					i = i + 1
		if verbose:
			file.write('\n\t[+] Parsed Response:' + '\n')
			for res in self.resline:
				file.write('\n\t\t' + self.name + ': ' + res[1] + '\n')
			for sum in self.summary:
				sum = sum.replace('{extract}', '')
				file.write('\n\t\t\t' + sum + '\n')
		elif len(self.result) == 1:
			file.write(self.result)
		else:
			file.write('\n\t[!] ' + self.result)
		file.flush()

	def getLinks(self): # parse out the links from a repoonse 
		if self.recieved:
			for line in self.recieved:
				if (line):
					h = regex.link.findall(line) # find all links in page
					for l in h:
						link = ''
						if l[3]:
							link = regex.host2.match(l[3])
						if not link:
							link=regex.host2.match(l[2])
						if link:
							self.links.append(link.group(3))
		#for a in self.links:
		#	print "Link: " + str(a)			
		return		
		

class Callable:
    def __init__(self, anycallable):
    	self.__call__ = anycallable	

class regex:

	p = re.compile(' \d\d\d ')											# regex for matching server responce code
	ip = re.compile('(\d{1,}\.){3}\d{1,}')								# regex to match ip addresses
	ip2 = re.compile('(\d{1,3}\.){3}\d{1,3}')							# regex to match ip addresses
	ips = re.compile('.{0,60}(\d{1,3}\.){3}\d{1,3}.{0,60}') 			# regex to isoloate IP address
	pathw = re.compile('[A-z]:\\\\([^\\\\]+\\\\){0,10}')				# regex to match windows filename
	pathl = re.compile('/([^/]*/){0,10}(www|web)root/([^/]*/){0,10}')	# regex to match linux filename		
	host = re.compile('^(https?://)?((\S+:\S+)@)?([A-z0-9.-]+)(:(\d+))?((/\S*)?/(\S*))?', re.I)
	host2 = re.compile('^((ftp|http|news)s?://[^/]+)?(/?[^:[*#\s>]+)', re.I)
	dir2 = re.compile('^((/\S*)/)')
	link = re.compile('([\s|;](src|href|action|location|url)\s*=\s*[\'"]?\s*([^>\'"]*)\s*[\'"]?)|\slocation:\s(\S*)', re.I)


	def matchip(IP):
		
		if (regex.ip.search(IP)):
			octets = regex.ip.search(IP).group().split('.')
			if (int(octets[0]) == 0) or (int(octets[3]) == 0):
				return 0
			for i in octets:
				if (int(i) > 255):
					return 0
			return 1
		return 0
	
	matchip = Callable(matchip) 			
		
		
		
