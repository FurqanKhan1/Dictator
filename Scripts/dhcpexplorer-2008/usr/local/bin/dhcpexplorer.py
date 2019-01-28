#!/usr/bin/python

#    This file is part of Dhcpexplorer.
#
#    Dhcpexplorer is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Dhcpexplorer is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Maildispatcher.  If not, see <http://www.gnu.org/licenses/>.
#
#    Copyright 2008 Yuri Lya


"""
DHCP explorer. Finds all DHCP servers in local network
"""


import socket
import array
import struct
import threading
import sys
import ctypes
from optparse import OptionParser
if sys.platform != "win32":
    import fcntl


OPORT = 67
IPORT = 68
SIOCGIFCONF = 0x8912
SIOCGIFHWADDR = 0x8927    # /usr/include/bits/ioctls.h


class Mibifrow(ctypes.Structure):
    """
        C structure for windows API
    """
    _fields_ = [("wszName", ctypes.c_wchar * 256)
                , ("dwIndex", ctypes.c_ulong)
                , ("dwType", ctypes.c_ulong)
                , ("dwMtu", ctypes.c_ulong)
                , ("dwSpeed", ctypes.c_ulong)
                , ("dwPhysAddrLen", ctypes.c_ulong)
                , ("bPhysAddr", ctypes.c_ubyte * 8)
                , ("dwAdminStatus", ctypes.c_ulong)
                , ("dwOperStatus", ctypes.c_ulong)
                , ("dwLastChange", ctypes.c_ulong)
                , ("dwInOctets", ctypes.c_ulong)
                , ("dwInUcastPkts", ctypes.c_ulong)
                , ("dwInNUcastPkts", ctypes.c_ulong)
                , ("dwInDiscards", ctypes.c_ulong)
                , ("dwInErrors", ctypes.c_ulong)
                , ("dwInUnknownProtos", ctypes.c_ulong)
                , ("dwOutOctets", ctypes.c_ulong)
                , ("dwOutUcastPkts", ctypes.c_ulong)
                , ("dwOutNUcastPkts", ctypes.c_ulong)
                , ("dwOutDiscards", ctypes.c_ulong)
                , ("dwOutErrors", ctypes.c_ulong)
                , ("dwOutQLen", ctypes.c_ulong)
                , ("dwDescrLen", ctypes.c_ulong)
                , ("bDescr", ctypes.c_ubyte * 256)]


class Mibiftable(ctypes.Structure):
    """
        C structure for windows API
    """
    _fields_ = [("dwNumEntries", ctypes.c_ulong)
                , ("table", Mibifrow * 16)]


def get_iface_list():
    """
        Returns list of all network interfaces in nix system
    """
    max_possible = 128    # arbitrary. raise if needed.
    bytes = max_possible * 32
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    info = fcntl.ioctl(soc.fileno(), SIOCGIFCONF
                       , struct.pack('iL', bytes, names.buffer_info()[0]))
    outbytes = struct.unpack('iL', info)[0]
    namestr = names.tostring()
    soc.close()
    
    ret_f = lambda i: namestr[i: i + 32].split('\0', 1)[0]
    return [ret_f(i) for i in range(0, outbytes, 32)]


def get_mac_address_list_nix():
    """
        Returns all MAC addresses as list in nix system
    """
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    all_hwaddrs = []
    all_ifaces = get_iface_list()
    for iface in all_ifaces:
        info = fcntl.ioctl(soc.fileno(), SIOCGIFHWADDR
                           , struct.pack('32s', iface))
        if info[18:24] == "\0\0\0\0\0\0":
            continue
        else:
            all_hwaddrs.append(info[18:24])
    soc.close()
    
    return all_hwaddrs


def construct_correct_hwlist(mibift):
    """
        It is used by get_mac_address_list_win function
    """
    all_hwaddrs = []
    for i in range(mibift.dwNumEntries):
        hwaddr = []
        for j in range(mibift.table[i].dwPhysAddrLen):
            hwaddr.append(chr(mibift.table[i].bPhysAddr[j]))
        if len(hwaddr) != 0:
            all_hwaddrs.append("".join(hwaddr))
    
    return all_hwaddrs


def get_mac_address_list_win():
    """
        Returns all MAC addresses as list in win system
    """
    get_if_table = ctypes.windll.Iphlpapi.GetIfTable
    
    all_hwaddrs = []
    mibift = Mibiftable()
    wdsiz = ctypes.c_ulong(ctypes.sizeof(mibift))
    if get_if_table(ctypes.byref(mibift), ctypes.byref(wdsiz), 1) == 0:
        all_hwaddrs = construct_correct_hwlist(mibift)
    
    return all_hwaddrs


def get_mac_address_list():
    """
        Returns MAC address list of all network interfaces in system
    """
    if sys.platform == "win32":
        return get_mac_address_list_win()
    else:
        return get_mac_address_list_nix()


def construct_message(hwaddr):
    """
        It returns DHCP message string of type DHCPDISCOVER
    """
    mess = [chr(0x01)    # op \
            , chr(0x01)    # htype \
            , chr(0x06)    # hlen \
            , chr(0x00)    # hops \
            , hwaddr[2:]    #xid \
            , chr(0x00) * 2    # secs \
            , chr(0x80) + chr(0x00)    # flags \
            , chr(0x00) * 4    # ciaddr \
            , chr(0x00) * 4    # yiaddr \
            , chr(0x00) * 4    # siaddr \
            , chr(0x00) * 4    # giaddr \
            , hwaddr + chr(0x00) * 10    # chaddr \
            , chr(0x00) * 64    # sname \
            , chr(0x00) * 128    # file \
            , chr(99) + chr(130) + chr(83) + chr(99)    # magic cockie \
            , chr(53) + chr(1) + chr(1)]    # option 53
    
    return "".join(mess)


def exit_func():
    """
        Sends broadcast "exit" message to port 68
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto("exit", ("<broadcast>", IPORT))
    sock.close()


def prepare_out_socket():
    """
        Prepare socket on 67 (out) port
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    return sock


def prepare_in_socket():
    """
        Prepare socket on 68 (in) socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", IPORT))
    
    return sock


def send_dhcpdiscover_packets(sock):
    """
        Sends DHCPDISCOVER packets over all network interfaces
    """
    all_hwaddrs = get_mac_address_list()
    for hwaddr in all_hwaddrs:
        mess = construct_message(hwaddr)
        sock.sendto(mess, ("<broadcast>", OPORT))


def receive_all_answers(sock):
    """
        Receives answer packets from all DHCP servers
    """
    ipaddr_list = []
    while 1:
        (msg, addr) = sock.recvfrom(1024)
        if msg == "exit":
            break
        ipaddr_list.append(addr[0])
    
    host_list = []
    for ipaddr in set(ipaddr_list):
        try:
            hostname = socket.gethostbyaddr(ipaddr)
            host_list.append(hostname[0] + ' ' + ipaddr)
        except(socket.error):
            hostname = "Unknown host"
            host_list.append(hostname + ' ' + ipaddr)
    
    return host_list


def main():
    """
        Entry point
    """
    
    # Parsing command line
    parser = OptionParser()
    parser.add_option("-t", "--timeout", type = "float", dest = "timeout"
                      , default = 0.1
                      , help="timeout in seconds for waiting answers"
                      , metavar = "TIME")
    (options, args) = parser.parse_args()
    
    
    outsock = prepare_out_socket()
    insock = prepare_in_socket()
    
    tim = threading.Timer(options.timeout, exit_func)
    tim.start()
    
    send_dhcpdiscover_packets(outsock)
    host_list = receive_all_answers(insock)
    
    for host in host_list:
        print host
    
    # Clean up
    outsock.close()
    insock.close()


main()
