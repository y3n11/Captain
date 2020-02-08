import sys
import json
import os

from ruamel.yaml import YAML
import optparse


class Function:
	def __init__(self, name):
		self.func_name = name
		self.arg_dict = {}
		self.match = False


class Signature:
	def __init__(self, name):
		self.sig_name = name
		self.proc_name = ''
		self.func_list = []




class Event:
	def __init__(self):
		self.event_name = ''
		self.proc_name = ''
		self.proc_id = 0
		self.event_time = ''
		self.func_name = ''
		self.arg_dict = {}

def parse_signature(sig_file):

	yaml = YAML()
	yaml.allow_duplicate_keys = True
	with open(sig_file) as _sig_file:
		signature = _sig_file.read()

	sigs = yaml.load(signature)
	for sig in sigs:
		__sig = Signature(sig['name'])
		if 'proc_name' in sig.keys():
			__sig.proc_name = sig['proc_name']
		for func in sig['functions']:
			__func = Function(func['func_name'])
			for key,value in func['arguments'].items():
				__func.arg_dict[key] = value
			__sig.func_list.append(__func)

	return __sig


def parse_event(event_str):
	
	event = Event()
	event.event_time = event_str['event_time']
	event.proc_name = event_str['proc_name']
	event.proc_id = event_str['proc_id']
	event.func_name = event_str['function']['func_name']
	for key,value in event_str['function']['arguments'].items():
		event.arg_dict[key] = value

	return event


def print_event(event):
	
	print('Event : ', event.event_name)
	print('Event time : ', event.event_time)
	print('Processus name : ', event.proc_name)
	print('Processus ID : ', event.proc_id)
	print('Event function name : ', event.func_name)
	for key,value in event.arg_dict.items():
		print('\t', key, ' : ', value)

def apply_signature(_sig_file, _event_file):


	signature = parse_signature(_sig_file)
	events_json = [json.loads(line) for line in open(_event_file, 'r')]

	if signature.proc_name != None:
		for entry in events_json:
			event = parse_event(entry)
			if event.proc_name.split('\\')[-1].lower() != signature.proc_name.split('\\')[-1].lower():
				events_json.remove(entry)

	valid_events_groups = {}



	for func in signature.func_list:
		for entry in events_json:
			event = parse_event(entry)
			event.event_name = signature.sig_name
			if(event.func_name == func.func_name) :
				for key,value in func.arg_dict.items():
					if value == event.arg_dict[key]:
						if event.proc_id in valid_events_groups.keys():
							if event not in valid_events_groups[event.proc_id]:
								valid_events_groups[event.proc_id].append(event)
						else :
							valid_events_groups[event.proc_id] = []
							valid_events_groups[event.proc_id].append(event)
					else :

						if event.proc_id in valid_events_groups.keys():
							if event in valid_events_groups[event.proc_id]:
								valid_events_groups[event.proc_id].remove(event)


	match = False


	clean_valid_events_groups = valid_events_groups.copy()



	for key,value in valid_events_groups.items():
		for func in signature.func_list:
			match == False
			for ev in valid_events_groups[key]:
				match = False
				if ev.func_name == func.func_name:
					match = True
					break

			if match == False:
				del clean_valid_events_groups[key]


	for key,value in clean_valid_events_groups.items():
		for ev in value:
			print("[+] Malicious event spotted \n")
			print_event(ev)
			print('\n')


if __name__ == '__main__':

	parser = optparse.OptionParser("usage: %prog [options] ")
	parser.add_option("-s", "--signature", dest="sig_file", type="string", help="Specify a signature file to apply")
	parser.add_option("-S", "--signatures", dest="sig_dir", type="string", help="Specify a directory of signatures to apply")
	parser.add_option("-e", "--event", dest="ev_file", type="string", help="Specify an event file to analyze")
	parser.add_option("-E", "--events", dest="ev_dir", type="string", help="Specify a directory of events to analyze")

	(options, args) = parser.parse_args()

	if (options.sig_file == None and options.sig_dir == None):
		parser.error("please provide at least a signature to apply")

	if (options.ev_file == None and options.ev_dir == None):
		parser.error("please provide at least an event file to analyze")

	if(options.sig_dir != None):
		if(options.ev_dir != None):
			for s_file in os.listdir(options.sig_dir):
				for e_file in os.listdir(options.ev_dir):
					apply_signature(s_file, e_file)
		else:
			for s_file in os.listdir(options.sig_dir):
				apply_signature(s_file, options.ev_file)

	else:
		if(options.ev_dir != None):
			for e_file in os.listdir(options.ev_dir):
				apply_signature(options.sig_file, e_file)
		else:
				apply_signature(options.sig_file, options.ev_file)


