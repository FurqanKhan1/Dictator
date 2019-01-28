#!/usr/bin/env python
# MSF-RPC - A  Python library to facilitate MSG-RPC communication with Metasploit
# Ryan Linn  - RLinn@trustwave.com
# Copyright (C) 2011 Trustwave
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import msfrpc
import time

if __name__ == '__main__':
  
  # Create a new instance of the Msfrpc client with the default options
  client = msfrpc.Msfrpc({})
  # print str(client)

  # Login to the msfmsg server using the password "abc123"
  client.login('msf','toor')
  ress = client.call('console.create')
  console_id = ress['id']
  #print "res: %s" %ress

  RHOST='10.0.1.39'

  commands = "use auxiliary/scanner/http/dir_listing set RHOSTS "+RHOST
  print (commands)
  
	
  print "[+] Exploiting ftp banner on: "+RHOST
  x= client.call('console.write',[console_id,commands])
  time.sleep(1)
  a = client.call('console.write', [console_id, "run\n"])
  time.sleep(1)
  res = client.call('console.read',[console_id])
  #print "\n\nres: %s" %res
  result = res['data'].split('\n')
  #print str(result)
  for r in result :
     print str(r)
  """for a in x :
	print str(a)	
  print str(x)
  print "\n\n\nprinting list\n\n\n"
  while True:
        res = client.call('console.read',[console_id])
        if len(res['data']) > 1:
            print res['data'],

        if res['busy'] == True:
            time.sleep(1)
            continue

        break"""

  cleanup = client.call('console.destroy',[console_id])
  print "Cleanup result: %s" %cleanup['result']

 

