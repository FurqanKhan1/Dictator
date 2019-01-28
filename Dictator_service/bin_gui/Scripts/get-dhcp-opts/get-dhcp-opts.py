#!/usr/bin/env python
#
# get-dhcp-opts.py: Discover DHCP/BOOTP servers and display the offered DHCP/BOOTP options.
#                   For example to get BOOTP filenames or other options like VoIP specific...
#
#   usage:
#      get-dhcp-opts.py <interface>
#
#
# Copyright (C) 2012 Pablo Catalina
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at pcg@portcullis-security.com
#


##########################
####   CONFIG OPTIONS ####
##########################

interface = 'eth0'   # Network interface where you want to discover DHCP options
verbose   = False    # Verbose mode (True or False)
timeout   = 5        # Timeout when waiting for a DHCP Offer
retries   = 3        # Number of retries
rogue     = True     # Detect multiple DHCP servers at the same LAN (Rogue DHCP Servers)

####### END CONFIG #######

version = '0.8'
import sys, string, socket, binascii

try:
    from scapy.all import *
except:
    print "Please, install scapy"
    sys.exit(2)

if len(sys.argv) == 2:
    interface = sys.argv[1]


conf.checkIPaddr = False
conf.iface = interface

fam,hw = get_if_raw_hwaddr(conf.iface)

dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])

while retries>0:
    wans=False
    if rogue:
        print "\n\n[?] Waiting for multiple DHCP Offers (%d secs). Rogue DHCP Server detection\n" % timeout
        ans, unans = srp(dhcp_discover,timeout=timeout, multi=True)
    else:
        print "\n\n[?] Waiting for a DHCP Offer (%d secs)\n" % timeout
        ans, unans = srp(dhcp_discover,timeout=timeout)

    try:
        if ans[0]:
            ans.summary()
            wans = True
    except:
	wans = False

    if wans and ((rogue and (ans[0] and len(ans) > 1)) or (not rogue and ans[0])):
        break
    else:
        retries -= 1

if not wans:
    print "\n\n[!] No DHCP Offers found, check if there is a DHCP server and/or try again\n"
    sys.exit(3)


if rogue:
    if len(ans) > 1:
        print "\n\n[!] Multiple DHCP server: Maybe you have a Rogue DHCP Server on your network. Check it."
    else:
        print "\n\n[*] Single DHCP server."

rep=0
for an in ans:
    rep+=1
    dhcpoffer = an[1]

    if verbose:
        print dhcpoffer.display()
    
    print ""
    if len(ans) > 1:
        print "  [ OFFER: %d ]" % rep
    print "==================="
    print "  DHCP OFFER INFO  "
    print "==================="
    print ""
    print "SERVER INFO:"
    print "  MAC:                      %s" % dhcpoffer["Ethernet"].src
    print "  IP:                       %s" % dhcpoffer["IP"].src
    print ""
    print "BOOTP INFO:"
    print "  Your IP Address:          %s" % dhcpoffer["BOOTP"].yiaddr
    print "  DHCP Server IP Address:   %s" % dhcpoffer["BOOTP"].siaddr
    print "  Gateway IP Address:       %s" % dhcpoffer["BOOTP"].giaddr
    print "  Server Name:              %s" % dhcpoffer["BOOTP"].sname.replace('\x00',' ').strip()
    print "  File Name:                %s" % dhcpoffer["BOOTP"].file.replace('\x00',' ').strip()
    print ""
    print "DHCP OPTIONS:"
    keys={}
    for i in dhcpoffer['DHCP options'].options:
        if type(i) == tuple or type(i) == list:
            if len(i) > 1:
                arr = []
                for s in i[1:]:
                    if type(s) == str and not all(c in string.printable for c in s):
                        mys = []
                        try:
                            stringval      = str(s)
                            mys.append("%s" % stringval)
                        except:
                            stringval      = None
                        try:
                            hexval         = str(binascii.hexlify(s))
                            mys.append("hex: %s" % hexval)
                        except:
                            hexval         = None
                        try:
                            formatstring   = str(repr(s))
                            mys.append("formatstring: %s" % formatstring)
                        except:
                            formatstring   = None
                        try:
                            decval         = str(int(binascii.hexlify(s), 16))
                            mys.append("decimal: %s" % decval)
                        except:
                            decval         = None
                        try:
                            ipval          = str(socket.inet_ntoa(s))
                            mys.append("ip: %s" % ipval)
                        except:
                            ipval          = None
                        s = '\n                              |=> '.join(mys)
                    arr.append(str(s))
                print "  %s:%s%s" % (i[0],' '*(25-len(str(i[0]))),', '.join(arr))
            else:
                print "  %s" % i[0]
    
    
    
                if all(c in string.printable for c in i[0]):
                    print "  %s" % i[0]
                else:
                    
                    dec = None
                    ip  = None
                    try:
                        dec = int(binascii.hexlify(i[0]), 16)
                    except:
                        # Not decimal value
                        pass
                    try:
                        ip = socket.inet_ntoa(d)
                    except:
                        # Not IP
                        pass
                    print "  %s (Hex: %s)(Decimal: %s) (IP: %s)" % i[0],dec,
                    
        else:
            print "  %s" % i
