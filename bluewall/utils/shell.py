import subprocess
import os

class Interact(object):

	def run_command(self, cmd, VERBOSE=0, DEBUG=False):
		if VERBOSE < 2:
			cmd += " 2>/dev/null"
		if DEBUG or VERBOSE > 1:
			print "$ " + cmd
		output = subprocess.check_output(cmd, shell=True)
		if DEBUG or VERBOSE > 1:
			print output
		return output

	def run_commands(self, cmd_list, VERBOSE=0, DEBUG=False):
		# Takes a list of commands to run
		for cmd in cmd_list:
			self.run_command(cmd, VERBOSE=VERBOSE, DEBUG=DEBUG)
		return

	def demand_input(self, prompt):
		response = ""
		while response is "":
			response = raw_input(prompt).strip()
		return response

	def root_check(self, debug=False):
		if debug:
			print 'UID: '+ str(os.getuid())
		if os.getuid() != 0:
			print("[-] Program MUST be run as sudo or root!\nUsage: sudo bw <options>")
			exit()
		return

class bcolors:
	HEADERS = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = 	'\033[91m'
	ENDC = 	'\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'