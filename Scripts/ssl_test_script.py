import threading
import psutil
import subprocess
import time
import pexpect

class SSL_check():
	def __init__(self):
		self.current_host=''
		self.limit=10

	def launch(self):
		print "Launching all threads in parllel :"
		thread = threading.Thread(target=self.fire_threads)
		thread.start()
		thread.join()
		
	def fire_threads(self):
		data=[]
		with open("hosts.txt","r")as file:
			data = file.readlines()
    			#do something with data
		
		
		active_=len(data)
		i=0
		while i < len(data):
			lk=threading.enumerate()
			if(len(lk)< self.limit-2):
				cmd="bash testssl.sh -B -A -F -p -J -f "
				#bash testssl.sh -B -A -F -p -J -f  192.168.179.136:80-->Fast and quick
				cmd=cmd+data[i]
				print "command is "+cmd
				time.sleep(5)
				obj=SSL_check()
				obj.current_host=data[i]
				thread = threading.Thread(target=obj.execute_singleLine_interactive,args=(cmd,))
				thread.start()
				i=i+1
			else:
				print "sleeping for 10 sec"
				time.sleep(10)
				

		
	def SaveDetails(self,commands_executed,exploit_result):
		print  "Commands : "+commands_executed +"\n\nResult : "+exploit_result+"\n\n\n"
		data= "Commands : "+commands_executed +"\n\nResult : "+exploit_result+"\n\n\n"
		with open(self.current_host+"ssl_hosts.txt","w")as file:
			file.write(data)

	def execute_singleLine_interactive(self,cmd):#A good thing is that even when a process is killed the thread resumes and details are saved
		try:
		    print( 'Thread started --with command '+str(cmd))
		    print "Command is---> ::" +str(cmd)
		    print "hello world !!1"
		    #cmd ="nslookup google.com"
		    commands_executed=[]
		    exploit_result=''
		    commands_executed.append(cmd+"\n")
		    child = pexpect.spawn(cmd)
		    i=child.expect(['.*Proceed ?.*','.* Unable to open a socket to .*',pexpect.TIMEOUT,pexpect.EOF, '[#\$] '],timeout=3000)
		    if (i==0):
				print "Reached at here"+str(child.after)
				child.sendline('yes')
				commands_executed.append('yes')
				i=child.expect(['.*Proceed ?.*','.* Unable to open a socket to .*',pexpect.TIMEOUT,pexpect.EOF, '[#\$] '],timeout=3000)
		   		self.SaveDetails(str(commands_executed),(str(child.before)+"\n"+str(child.after))+"i is "+str(i))
		    else:
				self.SaveDetails((str(commands_executed)),(str(child.before)+"\n"+str(child.after))+"i is "+str(i))
		    
		    """"commands_executed.append(cmd+"\n")
		    self.process=subprocess.Popen(cmd,shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)#best way to implement -->gives o/p in variable
		    (output, err)=self.process.communicate()
		    commands_executed.append(str(output)+"\n"+str(err)+"\n")
		    exploit_result="Command Executed :"+commands_executed[0]+"\n"
		    exploit_result=exploit_result+"\nResult"+str(commands_executed[len(commands_executed)-1])"""
		    
		    print "Finished subprocess "
		   
		except Exception ,e :
			print "EXception " +str(e)



obj=SSL_check()
obj.launch()
			
			
