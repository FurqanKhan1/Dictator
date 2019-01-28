#!/usr/bin/env python
from json import loads
import string
import socket
from argparse import ArgumentParser
from sys import exit

version = "0.1"


def PrintHelp():
    global version
    print("usage: to.gexf.py [-h] [options] conversion input")
    print("")
    print(("to.gexf v" + version))
    print("Convert IRCSnapShot output to Gephi compatible format")
    print("Gexf output is to STDOUT")
    print("By Brian Wallace (@botnet_hunter)")
    print("")
    print("Conversion Types:")
    print("  UserToLink                    Show relation between users and links")
    print("  UserToChannel                 Show relation between users and channels")
    print("")
    print("GPS:")
    print("  -m MaxMind Location           Location of Maxmind database files (default .)")
    print("")
    print("  -h --help                     Print this message")
    print("")
    print("You can get Maxmind databases from Maxmind.com.")
    print("Free database: http://geolite.maxmind.com/download/geoip/database/GeoLiteCity_CSV/GeoLiteCity-latest.zip")
    print("")


blocks = []
locations = {}


def IPtoInt(address):
    (o1, o2, o3, o4) = address.split('.')
    return (16777216 * int(o1)) + (65536 * int(o2)) + (256 * int(o3)) + int(o4)


def LoadBlocks(path):
    global blocks
    with open(path) as f:
        count = 0
        for line in f:
            count += 1
            if count < 3:
                continue
            blocks.append(ParseCSVLine(line))
    blocks = sorted(blocks, key=lambda it: int(it[0]))


def GetLocationID(address):
    global blocks
    ip = IPtoInt(address)

    for (startip, endip, locID) in blocks:
        startip = int(startip.strip().strip('"'))
        endip = int(endip.strip().strip('"'))
        locID = int(locID.strip().strip('"'))
        if startip <= ip:
            if endip >= ip:
                return locID
    return False


def ParseCSVLine(line):
    line = line.strip()
    values = []
    while line.__len__() > 0:
        if string.count(line, ',') > 0:
            if line[0] == '"':
                line = line[1:]
                values.append(line[:string.find(line, '"')])
                line = line[string.find(line, '"') + 1:]
                line = line[1:]
                if line.__len__() == 0:
                    values.append("")
            else:
                values.append(line[:string.find(line, ',')])
                line = line[string.find(line, ',') + 1:]
                if line.__len__() == 0:
                    values.append("")
        else:
            values.append(line)
            line = ""
    return values


def LoadLocations(path):
    global locations
    with open(path) as f:
        count = 0
        for line in f:
            count += 1
            if count < 3:
                continue
            (locId, country, region, city, postalCode, latitude, longitude,
            metroCode, areaCode) = ParseCSVLine(line)
            locations[int(locId)] = {"country": country, "region": region,
                "city": city, "postalCode": postalCode, "latitude": latitude,
                "longitude": longitude, "metroCode": metroCode,
                "areaCode": areaCode}


def GetLocationInformation(address):
    global locations
    location_id = GetLocationID(address)
    if location_id in locations:
        return locations[location_id]

''' TODOs
    Command line parsing
        Make Maxmind database locations configurable
        Clear any cache files/databases
        Input for output options (coords)
    Maxmind
        Cache results
        Increase speed of lookups
        Increase speed of initial reading
    Treat users without GPS coordinates with a different mod
    Backwards listing of links inferred by users
'''

parser = ArgumentParser(add_help=False)
parser.add_argument('conversion', metavar='conversion', type=str, nargs='?',
    default=None)
parser.add_argument('input', metavar='input', type=str, nargs='?',
    default=None)
parser.add_argument('-m', metavar='maxmind', type=str, nargs='?',
    default='.')
parser.add_argument('-h', '--help', default=False, required=False,
    action='store_true')

args = parser.parse_args()

if args.help or args.input is None or args.conversion is None or (args.conversion != "UserToLink" and args.conversion != "UserToChannel"):
    PrintHelp()
    exit()


LoadBlocks(args.m + '/GeoLiteCity-Blocks.csv')
LoadLocations(args.m + '/GeoLiteCity-Location.csv')

in_results = {}
with open(args.input, 'r') as content_file:
    in_results = loads(content_file.read())

linkList = in_results['linkList']
links = in_results['links']
users = in_results['users']
channels = in_results['channels']
channelList = in_results['userList']


highestnode = -1
nodes = {}
connections = []

if args.conversion == "UserToLink":
    for link in links:
        highestnode += 1
        node = {"id": highestnode, "label": link['mask'], "mod": 0}
        try:
            node['ip'] = socket.gethostbyname(link['mask'])
            if node['ip'] == '92.242.140.2':
                node['ip'] = "0.0.0.0"
        except:
            node['ip'] = "0.0.0.0"
        if node['ip'] != "0.0.0.0":
            loc = GetLocationInformation(node['ip'])
            node['label'] += " (" + node['ip'] + ")"
            if loc:
                node['lat'] = loc['latitude']
                node['lng'] = loc['longitude']
        nodes[link['mask']] = node

    for name, node in list(nodes.items()):
        connections.append([node['id'], nodes[link['server']]['id']])

    for link, userList in list(linkList.items()):
        for user in userList:
            if user in users:
                for line in users[user]:
                    if line.count(" 311 ") > 0:
                        highestnode += 1
                        t = line[string.find(line, " 311 ") + 5:]
                        node = {"id": highestnode, "label": str(user) + " (" +
                        t.split(' ')[3] + ")",
                        "host": t.split(' ')[3], "mod": 1}
                        try:
                            node['ip'] = socket.gethostbyname(node['host'])
                            if node['ip'] == '92.242.140.2':
                                node['ip'] = "0.0.0.0"
                        except:
                            node['ip'] = "0.0.0.0"
                        if node['ip'] != "0.0.0.0":
                            loc = GetLocationInformation(node['ip'])
                            if loc:
                                node['lat'] = loc['latitude']
                                node['lng'] = loc['longitude']
                        nodes[user] = node
                    if line.count(" 312 ") > 0:
                        t = line[string.find(line, " 312 ") + 5:]
                        if t.split(' ')[2] not in nodes:
                            highestnode += 1
                            node = {"id": highestnode, "label": t.split(' ')[2], "mod": 0}
                            try:
                                node['ip'] = socket.gethostbyname(node['label'])
                                if node['ip'] == '92.242.140.2':
                                    node['ip'] = "0.0.0.0"
                            except:
                                node['ip'] = "0.0.0.0"
                            if node['ip'] != "0.0.0.0":
                                loc = GetLocationInformation(node['ip'])
                                node['label'] += " (" + node['ip'] + ")"
                                if loc:
                                    node['lat'] = loc['latitude']
                                    node['lng'] = loc['longitude']
                            nodes[t.split(' ')[2]] = node
                        connections.append([nodes[user]['id'],
                            nodes[t.split(' ')[2]]['id']])
elif args.conversion == "UserToChannel":
    for channel, userList in list(channelList.items()):
        highestnode += 1
        if channel not in nodes:
            i = {"id": highestnode, "label": channel, "mod": 0}
            nodes[channel] = i
        for user in userList:
            if user in users:
                if user not in nodes:
                    for line in users[user]:
                        if line.count(" 311 ") > 0:
                            highestnode += 1
                            t = line[string.find(line, " 311 ") + 5:]
                            node = {"id": highestnode, "label": str(user) + " (" +
                            t.split(' ')[3] + ")",
                            "host": t.split(' ')[3], "mod": 1}
                            try:
                                node['ip'] = socket.gethostbyname(node['host'])
                                if node['ip'] == '92.242.140.2':
                                    node['ip'] = "0.0.0.0"
                            except:
                                node['ip'] = "0.0.0.0"
                            if node['ip'] != "0.0.0.0":
                                loc = GetLocationInformation(node['ip'])
                                if loc:
                                    node['lat'] = loc['latitude']
                                    node['lng'] = loc['longitude']
                            nodes[user] = node
                connections.append([nodes[user]['id'], nodes[channel]['id']])

print('<?xml version="1.0" encoding="UTF-8"?>')
print('<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">')
print('    <meta lastmodifieddate="2009-03-20">')
print(('        <creator>' + "bwall" + '</creator>'))
print('        <description></description>')
print('    </meta>')
print('    <graph mode="static" defaultedgetype="directed">')
print('    <attributes class="node" mode="static">')
print('      <attribute id="modularity_class" title="Modularity Class" type="integer"></attribute>')
print('      <attribute id="lat" title="lat" type="double"></attribute>')
print('      <attribute id="lng" title="lng" type="double"></attribute>')
print('    </attributes>')
print('        <nodes>')
for name, node in list(nodes.items()):
    if 'lat' in node:
        print(('            <node id="' + str(node['id']) + '" label="' +
            node['label'] + '">'))
        print('                <attvalues>')
        print(('                    <attvalue for="modularity_class" value="' +
            str(node['mod']) + '"></attvalue>'))
        print('                     <attvalue for="lat" value="' + str(node['lat']) + '"></attvalue>')
        print('                     <attvalue for="lng" value="' + str(node['lng']) + '"></attvalue>')
        print('                </attvalues>')
        print('            </node>')
    else:
        print(('            <node id="' + str(node['id']) + '" label="' +
            node['label'] + '">'))
        print('                <attvalues>')
        print(('                    <attvalue for="modularity_class" value="' +
            str(node['mod']) + '"></attvalue>'))
        print('                     <attvalue for="lat" value="0"></attvalue>')
        print('                     <attvalue for="lng" value="0"></attvalue>')
        print('                </attvalues>')
        print('            </node>')
print('        </nodes>')
print('        <edges>')
count = 0
for node in connections:
    print(('            <edge id="' + str(count) + '" source="' + str(node[0]) +
         '" target="' + str(node[1]) + '" />'))
    count += 1
print('        </edges>')
print('    </graph>')
print('</gexf>')

