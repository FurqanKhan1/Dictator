#!/usr/bin/env python
import socket
from json import dumps
import string
from random import choice
from ssl import wrap_socket
from sys import exit, exc_info
from random import random
import logging
import time
import threading
import traceback
import struct
import os
import ctypes
import datetime

version = "0.9"


def print_help():
    global version
    print("usage: ircsnapshot.py [-h] [options] server [port]")
    print("")
    print(("IRCSnapshot v" + version))
    print("Gathering information from IRC servers")
    print("By Brian Wallace (@botnet_hunter)")
    print("")
    print("Options:")
    print("  -n --nick NICK                Set nick of bot")
    print("  -u --user USER                Set user of bot")
    print("  -r --real REAL                Set real name of bot")
    print("  -x --ssl                      SSL connection")
    print("  -p --password PASS            Server password")
    print("  -c --channels #chan1,#chan2   Additional channels to check")
    print("  --proxy SERVER[:PORT]         SOCKS4 proxy to connect through")
    print("  -o --output Directory         Output directory (default .)")
    print("  -t --throttle 1.0             Seconds to sleep before sending messages (default 1)")
    print("  -L --no-list                  Do not request server wide lists (channels, links, names)")
    print("                                Random values between 0 and this value are chosen each time")
    print("")
    print("  -h --help                     Print this message")
    print("")


def id_generator(size=6, chars=string.ascii_uppercase + string.ascii_lowercase):
    return ''.join(choice(chars) for x in range(size))


def is_ipv6(ip):
    try:
        if os.name == "nt":
            class sockaddr(ctypes.Structure):
                _fields_ = [("sa_family", ctypes.c_short),
                            ("__pad1", ctypes.c_ushort),
                            ("ipv4_addr", ctypes.c_byte * 4),
                            ("ipv6_addr", ctypes.c_byte * 16),
                            ("__pad2", ctypes.c_ulong)]

            WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
            addr = sockaddr()
            addr.sa_family = socket.AF_INET6
            addr_size = ctypes.c_int(ctypes.sizeof(addr))
            if WSAStringToAddressA(ip, socket.AF_INET6, None, ctypes.byref(addr), ctypes.byref(addr_size)) != 0:
                raise socket.error(ctypes.FormatError())
            return ctypes.string_at(addr.ipv6_addr, 16)
        else:
            return socket.inet_pton(socket.AF_INET6, ip)
    except:
        return False


def is_ipv4(ip):
    try:
        return socket.inet_aton(ip)
    except:
        return False


class QueuedTask(object):
    def __init__(self, verb, data, other=None):
        self.verb = verb
        self.data = data
        self.other = other

    def __str__(self):
        return "%s %s" % (self.verb, self.data)

    def __eq__(self, other):
        return self.verb == other.verb and self.data == other.data


class IrcBotControl:
    def __init__(self, config):
        self.config = config

        self.nick = config["nick"]
        self.user = config["user"]
        self.real = config["real"]

        self.queue_lock = threading.Lock()
        self.to_process_queue = []
        self.is_processing = []

        self.channels = {}
        self.users = {}
        self.userList = {}
        self.linkList = {}
        self.userDetails = {}

        self.links = []

        self.listDone = False

        self.hasListed = False

        self.whoisDataCodes = ["307", "308", "309", "310", "311", "312", "313",
            "316", "317", "319", "320", "330", "335", "338", "378", "379",
            "615", "616", "617", "671", "689", "690", ]
        self.channelJoinCodes = {"366", "470", "471", "473", "474", "475", "476", "477", "479", "519", "520"}

        self.bot = IRCBot(self.config, self)

        self.died = False
        self.max_processing_items = 10

        self.bot.log(dumps({'config': self.config, 'nick': self.nick,
            'user': self.user, 'real': self.real}))

        self.last_return = datetime.datetime.now()

        self.timer = threading.Timer(self.get_throttle_time(), self.process_queue_item)
        self.timer.start()

    def get_throttle_time(self):
        return float(self.config['throttleLevel']) + (float(self.config['throttleLevel']) * random())

    def add_to_processing_queue(self, item):
        self.queue_lock.acquire()
        if item not in self.to_process_queue and item not in self.is_processing:
            self.to_process_queue.append(item)
        self.queue_lock.release()

    def process_queue_item(self):
        self.queue_lock.acquire()
        if self.died:
            if len(self.to_process_queue) == 0 and len(self.is_processing) == 0:
                self.queue_lock.release()
                logging.info("finished")
                return
            else:
                self.queue_lock.release()
                logging.info("finished with items remaining")
                return
        if not self.listDone:
            self.timer = threading.Timer(self.get_throttle_time(), self.process_queue_item)
            self.timer.start()
            self.queue_lock.release()
            return
        if len(self.to_process_queue) > 0:
            item = choice(self.to_process_queue)
            self.to_process_queue.remove(item)
            self.last_return = datetime.datetime.now()
            if item.verb == "join":
                self.is_processing.append(item)
                if item.other is not None:
                    self.bot.join("%s %s" % (item.data, item.other))
                else:
                    self.bot.join(item.data)
            if item.verb == "whois":
                self.is_processing.append(item)
                self.bot.whois(item.data)
            if item.verb == "part":
                self.is_processing.append(item)
                self.bot.part(item.data)
            if item.verb == "quit":
                self.bot.quit()
                self.queue_lock.release()
                return
        elif len(self.is_processing) == 0:
            self.bot.quit()
            self.queue_lock.release()
            return
        else:
            diff = datetime.datetime.now() - self.last_return
            if diff.total_seconds() > 600:
                self.bot.quit()
                self.queue_lock.release()
                return
        self.timer = threading.Timer(self.get_throttle_time(), self.process_queue_item)
        self.timer.start()
        self.queue_lock.release()

    def remove_finished_item(self, item):
        self.queue_lock.acquire()
        if item in self.is_processing:
            self.is_processing.remove(item)
        else:
            logging.info("%s not found in is_processing" % str(item))
            logging.info(str(self.is_processing))
        self.queue_lock.release()

    def start(self):
        try:
            self.bot.start()
        except:
            self.died = True
            raise
        self.died = True

    # Start Parsers
    def parse_ping(self, line):
        if line[:6] == "PING :":
            self.bot.send("PONG :" + line[6:], True)
            return True
        return False

    def parse_support(self, line, cmd):
        if cmd[1] == "005":
            for c in cmd:
                if c.startswith('MAXCHANNELS='):
                    print c['MAXCHANNELS='.__len__():]

    def parse_nick_in_use(self, line, cmd):
        if cmd[1] == "433":
            self.bot.set_nick(self.nick)
            return True
        return False

    def parse_end_of_motd(self, line, cmd):
        if cmd[1] == "422" or cmd[1] == "376":
            # can start scanning
            if self.config['listDelay'] is None:
                self.start_scanning()
            else:
                threading.Timer(float(self.config['listDelay']), self.start_scanning).start()
            return True
        return False

    def start_scanning(self):
        if self.hasListed is False:
            self.hasListed = True
            self.parse_list_end("", ["", "323"])
            if not self.config['nolist']:
                self.bot.list()
                self.bot.send("LINKS")
                self.bot.send("NAMES")
            else:
                # decided to get a channel list, so we force a list end call
                self.parse_list_end(None, [None, "323"])

    def parse_list_entry(self, line, cmd):
        if cmd[1] == "322":
            chanDesc = {"name": unicode(cmd[3], errors='ignore'), "usercount": cmd[4], "topic": unicode(line[line.find(":", 1) + 1:], errors='ignore')}
            self.channels[chanDesc['name']] = chanDesc
            if chanDesc['name'] != "*":
                item = QueuedTask("join", chanDesc['name'])
                self.add_to_processing_queue(item)
            return True
        return False

    def parse_link_entry(self, line, cmd):
        if cmd[1] == "364":
            linkDesc = {"mask": unicode(cmd[3], errors='ignore'), "server": unicode(cmd[4], errors='ignore'), "hopcount": unicode(cmd[5][1:], errors='ignore'), "info": line[line.find(' ', line.find(":", 1)) + 1:]}
            self.links.append(linkDesc)
            return True
        return False

    def parse_list_end(self, line, cmd):
        if cmd[1] == "323":
            if self.config['channelstocheck'] is not None:
                # Add all mandatory join channels
                for chan in self.config['channelstocheck']:
                    if chan.find(' ') != -1:
                        item = QueuedTask("join", unicode(chan[:chan.find(' ')], errors='ignore'), unicode(chan[chan.find(' ') + 1:]))
                        self.add_to_processing_queue(item)
                    else:
                        item = QueuedTask("join", unicode(chan[:chan.find(' ')], errors='ignore'))
                        self.add_to_processing_queue(item)
            # Start timer here?
            self.listDone = True
            return True
        return False

    def parse_names_reply(self, line, cmd):
        if cmd[1] == "353":
            if cmd[4] not in self.userList:
                self.userList[cmd[4]] = []
            for nick in string.split(string.split(line, ":")[2],
                " "):
                if nick == "" or nick == " ":
                    continue
                if nick[0] == "@" or nick[0] == "~" or nick[0] == "%" or nick[0] == "+" or nick[0] == "&":
                    nick = nick[1:]
                if nick not in self.userList[cmd[4]] and nick != self.nick:
                    self.userList[cmd[4]].append(unicode(nick, errors='ignore'))
                    if nick not in self.users:
                        item = QueuedTask("whois", nick)
                        self.add_to_processing_queue(item)
            return True
        return False

    def parse_join_codes(self, line, cmd):
        if cmd[1] in self.channelJoinCodes:
            j_item = QueuedTask("join", cmd[3])
            self.remove_finished_item(j_item)
            self.bot.part(cmd[3])
            return True
        return False

    def parse_whois_codes(self, line, cmd):
        if cmd[1] in self.whoisDataCodes:
            item = QueuedTask("whois", cmd[3])
            if cmd[3] != self.nick:
                if cmd[3] not in self.users:
                    self.users[cmd[3]] = []
                if cmd[3] not in self.userDetails:
                    self.userDetails[cmd[3]] = {'nick': '', 'user': '', 'host': '', 'real': '', 'identified': False, 'oper': False}
                if cmd[1] == "311":
                    self.userDetails[cmd[3]]['nick'] = unicode(cmd[3], errors='ignore')
                    self.userDetails[cmd[3]]['user'] = unicode(cmd[4], errors='ignore')
                    self.userDetails[cmd[3]]['host'] = unicode(cmd[5], errors='ignore')
                    self.userDetails[cmd[3]]['real'] = unicode(line[line.find(':', 1) + 1:], errors='ignore')
                if cmd[1] == "307" or cmd[1] == "330":
                    self.userDetails[cmd[3]]['identified'] = True
                if cmd[1] == "313":
                    self.userDetails[cmd[3]]['oper'] = True
                if cmd[1] == "312" and len(cmd) > 4:
                    #contains server location
                    if cmd[4] not in self.linkList:
                        self.linkList[cmd[4]] = []
                    if cmd[3] not in self.linkList[cmd[4]]:
                        self.linkList[cmd[4]].append(cmd[3])
                if unicode(line, errors='ignore') not in self.users[cmd[3]]:
                    self.users[cmd[3]].append(unicode(line, errors='ignore'))
            return True
        return False

    def parse_whois_end(self, line, cmd):
        if cmd[1] == "318":
            item = QueuedTask("whois", cmd[3])
            self.remove_finished_item(item)
            return True
        return False
    # End Parsers


class ProxyWrapper:
    def __init__(self, ipv6):
        self.type = None
        self.ip = None
        self.port = None
        if ipv6:
            self.inner = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            self.inner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.user = None
        self.password = None
        self.proxy_type = "socks5"

    def set_proxy_address(self, host, port):
        self.ip = host
        self.port = port

    def set_proxy_auth(self, user, password):
        self.user = user
        self.password = password

    def set_proxy_type(self, type):
        self.proxy_type = type

    def __getattr__(self, name):
        ret = getattr(self.inner, name)
        return ret

    def _generate_connect_packet_socks4a(self, host, port):
        packet = "\x04\x01"
        packet += struct.pack("!H", port)
        packet += "\x00\x00\x00\x11"
        if self.user is not None:
            packet += self.user
        packet += "\x00"
        packet += host + "\x00"
        return packet

    @staticmethod
    def _generate_connect_packet_socks5():
        # For now, no authentication supported
        packet = "\x05\x01\x00"
        return packet

    @staticmethod
    def _generate_connect_packet_socks5_2_domain(host, port):
        packet = "\x05\x01\x00\x03"
        packet += struct.pack('B', host.__len__())
        packet += host
        packet += struct.pack("!H", port)
        return packet

    @staticmethod
    def _generate_connect_packet_socks5_2_ipv6(ip, port):
        packet = "\x05\x01\x00\x04"
        packet += ip
        packet += struct.pack("!H", port)
        return packet

    @staticmethod
    def _generate_connect_packet_socks5_2_ipv4(ip, port):
        packet = "\x05\x01\x00\x01"
        packet += ip
        packet += struct.pack("!H", port)
        return packet

    def connect(self, endpoint):
        (host, port) = endpoint
        if self.proxy_type == "socks4a":
            packet = self._generate_connect_packet_socks4a(host, port)
            self.inner.connect((self.ip, self.port))
            self.inner.send(packet)
            resp = self.inner.recv(4096)
            if resp.__len__() == 0 or ord(resp[1]) != 0x5a:
                self.inner.close()
                raise Exception("Proxy refused to connect to target (code: " + str(ord(resp[1])) + ")")
        elif self.proxy_type == "socks5":
            packet = self._generate_connect_packet_socks5()
            self.inner.connect((self.ip, self.port))
            self.inner.send(packet)
            resp = self.inner.recv(4096)
            if ord(resp[1]) == 0x00:
                if is_ipv6(host) is not False:
                    ip = is_ipv6(host)
                    packet = self._generate_connect_packet_socks5_2_ipv6(ip, port)
                elif is_ipv4(host) is not False:
                    ip = is_ipv4(host)
                    packet = self._generate_connect_packet_socks5_2_ipv4(ip, port)
                else:
                    packet = self._generate_connect_packet_socks5_2_domain(host, port)
                self.inner.send(packet)
                resp = self.inner.recv(4096)
                if resp.__len__() == 0 or ord(resp[1]) != 0x00:
                    self.inner.close()
                    raise Exception("Proxy refused to connect to target (code: " + str(ord(resp[1])) + ")")
            else:
                self.inner.close()
                raise Exception("Invalid authentication type")

        else:
            raise Exception("Invalid proxy type")


class IRCBot:
    def __init__(self, config, parser):
        self.config = config

        self.nick = config["nick"]
        self.user = config["user"]
        self.real = config["real"]

        self.parser = parser

        self.send_lock = threading.Lock()
        self.sock = None
        self.ipv6 = is_ipv6(self.config['server']) is not False
        self.first_packet = True

    def log(self, message):
        try:
            message = unicode(message)
            message = message.encode("utf-8")
        except:
            message = message
        logging.info(message)

    def send(self, message, overrideThrottle=False):
        self.send_lock.acquire()
        self.log(message)
        self.sock.sendall(message + "\r\n")
        self.send_lock.release()

    def set_nick(self, nick):
        self.send("NICK " + nick, True)

    def privmsg(self, to, msg):
        self.send("PRIVMSG " + to + " :" + msg)

    def join(self, channel, key=None):
        if key is not None:
            self.send("JOIN " + channel + " " + key)
        else:
            self.send("JOIN " + channel)

    def part(self, channel):
        self.send("PART " + channel)

    def whois(self, nick):
        self.send("WHOIS " + nick + " " + nick)

    def quit(self):
        self.send("QUIT :")

    def list(self):
        self.send("LIST")

    def start(self):
        self.server = self.config['server']
        self.port = int(self.config['port'])
        if self.config['proxyhost'] is None:
            if self.ipv6:
                self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = ProxyWrapper(is_ipv6(self.config['proxyhost']))
            self.sock.set_proxy_address(self.config['proxyhost'], self.config['proxyport'])
        self.sock.connect((self.server, self.port))

        if self.config['ssl'] is True:
            self.sock = wrap_socket(self.sock)

        #send pass
        if self.config["pass"] is not None:
            self.send("PASS " + self.config["pass"], True)

        self.send("USER " + self.user + " 127.0.0.1 " + self.server + " :" + self.real, True)
        self.set_nick(self.nick)
        self.main()

    def main(self):
        data = ""
        f = self.sock.makefile()
        while True:
            data = ""
            data = f.readline()
            if not data:
                self.log("Disconnected")
                break
            if self.first_packet:
                self.first_packet = False
                if data[0] != ":" and data[0] != "N" and data[0] != "P":
                    raise Exception("Does not appear to be an IRC server: {0}".format(data))
            for line in [data]:
                line = line[:-2]
                self.log(line)

                # handle pings
                self.parser.parse_ping(line)

                cmd = string.split(line, " ")
                if len(cmd) > 1:
                    self.parser.parse_support(line, cmd)
                    self.parser.parse_nick_in_use(line, cmd)
                    self.parser.parse_end_of_motd(line, cmd)
                    self.parser.parse_list_entry(line, cmd)
                    self.parser.parse_link_entry(line, cmd)
                    self.parser.parse_list_end(line, cmd)
                    self.parser.parse_names_reply(line, cmd)
                    self.parser.parse_join_codes(line, cmd)
                    self.parser.parse_whois_codes(line, cmd)
                    if self.parser.parse_whois_end(line, cmd):
                        break

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(add_help=False)
    parser.add_argument('server', metavar='server', type=str, nargs='?', default=None)
    parser.add_argument('port', metavar='port', type=str, nargs='?', default="6667")
    parser.add_argument('-p', '--password', metavar='password', type=str, nargs='?', default=None)
    parser.add_argument('-c', '--channels', metavar='channels', type=str, nargs='?', default=None)
    parser.add_argument('-o', '--output', metavar='output', type=str, nargs='?', default='.')
    parser.add_argument('-t', '--throttle', metavar='throttle', type=float, nargs='?', default='1')
    parser.add_argument('-l', '--listdelay', metavar='listdelay', type=float, nargs='?', default=None)

    parser.add_argument('-n', '--nick', metavar='nick', type=str, nargs='?', default=id_generator(10))
    parser.add_argument('-r', '--real', metavar='real', type=str, nargs='?', default=id_generator(10))
    parser.add_argument('-u', '--user', metavar='user', type=str, nargs='?', default=id_generator(10))

    parser.add_argument('--proxy', metavar='proxy', type=str, nargs='?', default=None)
    parser.add_argument('-x', '--ssl', default=False, required=False, action='store_true')
    parser.add_argument('-L', '--no-list', required=False, action='store_true', default=False)

    parser.add_argument('-h', '--help', default=False, required=False, action='store_true')

    args = parser.parse_args()
    print args

    if args.help or args.server is None:
        print_help()
        exit()

    server = args.server
    port = args.port
    password = args.password

    proxyhost = args.proxy
    proxyport = 9050

    channels = None
    if args.channels is not None:
        channels = args.channels.split(',')

    if proxyhost is not None:
        if proxyhost.find(":") != -1:
            proxyport = proxyhost[proxyhost.find(":") + 1:]
            proxyhost = proxyhost[:proxyhost.find(":")]

    if not os.path.exists(args.output):
        os.makedirs(args.output)

    logFormatter = logging.Formatter("[%(asctime)s] %(message)s")
    logFormatter.converter = time.gmtime
    rootLogger = logging.getLogger()

    fileHandler = logging.FileHandler("{0}/{1}.log".format(args.output, server.replace(":", ".")))
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)
    rootLogger.setLevel(0)
    logging.info("Logger initiated")

    config = {
        'server': server,
        'port': port,
        'pass': password,
        'ssl': args.ssl,
        'channelstocheck': channels,
        'proxyhost': proxyhost,
        'proxyport': int(proxyport),
        'nick': args.nick,
        'user': args.user,
        'real': args.real,
        'outputdir': args.output,
        'throttleLevel': args.throttle,
        'listDelay': args.listdelay,
        'nolist': args.no_list,
    }

    bot = IrcBotControl(config)

    test = False

    if not test:
        try:
            bot.start()
        except:
            logging.info("An error occurred while connected to the IRC server")
            logging.info("Still going to write out the results")
            logging.info((exc_info()[0]))
            logging.info((exc_info()[1]))
            logging.info(traceback.format_tb(exc_info()[2]))
    else:
        bot.start()

    results = {'channels': bot.channels, 'userList': bot.userList,
               'users': bot.users, 'links': bot.links, 'linkList': bot.linkList,
               'userDetails': bot.userDetails}

    with open(args.output + "/" + config['server'].replace(":", ".") + ".json", "a") as myfile:
        myfile.write(dumps(results, sort_keys=True, indent=4, separators=(',', ': ')))
