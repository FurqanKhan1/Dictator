__author__ = 'bwall'
import json
import os
import time
import ExtractHosts
import base64


def create_command_to_run(pbot, output_folder=None, proxy=None):
	if proxy is None:
		proxy = ""
	else:
		proxy = "--proxy {0}".format(proxy)

	password = ""
	if 'pass' in pbot['information']:
		password = "-p '{0}'".format(pbot['information']['pass'])

	server = ""
	if 'server' in pbot['information']:
		server = pbot['information']['server']
		if ExtractHosts.extract_domain(server) is None and ExtractHosts.extract_ipv4(
				server) is None and ExtractHosts.extract_ipv6(server) is None:
			try:
				server = base64.b64decode(server)
			except:
				pass
	else:
		return None

	port = ""
	if 'port' in pbot['information']:
		port = pbot['information']['port']

	if output_folder is None:
		output_folder = ""
	else:
		output_folder = "-o {0}".format(output_folder)

	return "python ircsnapshot.py {0} {4} {1} {2} {3}".format(proxy, password, server, port, output_folder)


with open("dump.json", "r") as f:
	doc = json.load(f)
	cmds = []
	for key in doc.keys():
		cmd = create_command_to_run(doc[key], "fbi2")
		if cmd is not None and cmd not in cmds:
			print cmd
			cmds.append(cmd)
			os.system(cmd)