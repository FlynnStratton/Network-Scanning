import pyfiglet
import sys
import socket
from datetime import datetime
from colorama import Fore
import socket
import sys
import subprocess
from subprocess import Popen, PIPE
import os
import uuid
import platform



ops = platform.system().lower()



def start():
	print(Fore.BLUE, f'''
		        ▒▒▓▓                                ▒▒▓▓░░      
		        ▓▓░░▓▓                              ▓▓░░▓▓      
		        ▓▓  ▓▓                              ▓▓  ▓▓      
		        ▓▓  ▓▓                              ▓▓  ▓▓      
		        ▓▓  ▓▓                              ▓▓  ▓▓      
		        ▓▓  ▓▓          ▓▓▓▓▓▓▓▓▒▒          ▓▓  ▓▓      
		        ▓▓  ▓▓      ▒▒▓▓▒▒      ▒▒▓▓░░      ▓▓  ▓▓      
		        ▓▓  ▓▓    ▓▓▒▒    ▓▓▓▓▓▓    ▓▓▒▒    ▓▓  ▓▓      
		        ▓▓  ▓▓        ▓▓▒▒      ▒▒▓▓        ▓▓  ▓▓      
		        ▓▓  ▓▓      ▓▓    ▓▓▓▓▓▓  ░░░░      ▓▓  ▓▓      
		        ▓▓  ▓▓          ▓▓▓    ▓░░          ▓▓  ▓▓      
		        ▓▓  ▓▓              ▓░              ▓▓  ▓▓      
		        ██  ▓▓                              ▓▓  ▓▓      
		        ▓▓  ▓▓                              ▓▓  ▓▓      
		  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
		  ▓▓                                                  ▓▓
		  ▓▓▓▓  ▓▓▓▓▓▓  ▓▓▓▓  ▓▓▓▓▓▓  ▓▓▓▓▒▒▒▒▓▓▓▓  ▓▓▓▓▓▓  ▓▓▓▓
		  ▓▓                                                  ▓▓
		  ▓▓                                                  ▓▓
		  ▓▓                                                  ▓▓
		  ▓▓                                                  ▓▓
		  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
		        ▓▓    ▓▓                          ▓▓    ▓▓      
		        ▓▓▓▓▓▓▓▓                          ▓▓▓▓▓▓▓▓      
		''')
	print(Fore.YELLOW)
	a = str(f'''
Github Profile: https://github.com/FlynnStratton/
		{print('Your MAC address :',':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
								for ele in range(0, 8 * 6, 8)][::-1]))}
	''')

	a = a.replace('None', '')
	print(a)

	import re



	def port_scanner():
		ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

		port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

		port_min = 0
		port_max = 65535
		open_ports = []

		while True:
			ip_add_entered = input("Enter IP to scan : ")
			if ip_add_pattern.search(ip_add_entered):
				print(Fore.GREEN, f"{ip_add_entered} is a valid ip address")
				break
			else:
				print(Fore.RED, 'IP entered is not valid')
				break

		while True:

			port_range = input('Enter port range eg. (10-80) : ')
			port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
			if port_range_valid:
				port_min = int(port_range_valid.group(1))
				port_max = int(port_range_valid.group(2))
				break

		for port in range(port_min, port_max + 1):
			# Connect to socket of target machine. We need the ip address and the port number we want to connect to.
			try:

				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

					s.settimeout(0.5)

					s.connect((ip_add_entered, port))
					print(Fore.GREEN, f"\nPort {port} is open on {ip_add_entered}.")
					open_ports.append(port)

			except:
				print(Fore.RED, f'Port {port} | Not open')
				pass

		for port in open_ports:
			print(Fore.GREEN, f"Port {port} is open on {ip_add_entered}.")

		

	def net_scan():
		if 'windows' in ops:
			print(Fore.RED,'')
			try:
				network = subprocess.check_output(['netsh', 'wlan', 'show', 'network'])
				networks = network.decode('ascii')
				print(networks)
			except:
				a = (Fore.RED,'[+] There is no wireless interface on the system. Or an error has been found with it')

		else:
			print(Fore.RED, '[+] Your operating system does not support this tool')




	def lan_scan():
		if 'linux' or 'parrot' or 'windows' in ops:
			print(Fore.GREEN)
			data = "arp -a"
			cmd = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE,
								   stderr=subprocess.PIPE)
			output_byte = cmd.stdout.read() + cmd.stderr.read()
			print(str(output_byte, "utf-8"))

		else:
			print(Fore.RED, '[+]This tool will not be able to run on your system')

		data = f"getmac"
		if 'windows' or 'mac' in ops:
			cmd = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
			output_byte = cmd.stdout.read() + cmd.stderr.read()
			print(str(output_byte, "utf-8"))


		


	def menu():
		print(Fore.GREEN,'''
             --help  |    Show this menu

  Port scanner 
		-ps  |    Port scanner eg. python NAT.py -ps (or --portscanner)

  LAN scan
		-lS  |    LAN (local area network) scan eg. (python NAT.py -ls)
			
  Network scanner
		-ns  |    Network scanner
		''')


	try:
		command = sys.argv[1]


		if command == '-ps':
			port_scanner()

		elif command == '--help':
			menu()

		elif command == '-ns':
			net_scan()

		elif command == '-ls':
			lan_scan()


		else:
			menu()

	except IndexError:
		menu()





if 'linux' in ops:
	os.system('clear')
	start()

elif 'windows' in ops:
	os.system('cls')
	print(Fore.RED, f'Some tools may not be available due to your operating system | OS - {ops}')
	start()

elif 'parrot' in ops:
	os.system('clear')
	print(Fore.RED, f'Some tools may not be available due to your operating system | OS - {ops}')
	start()

else:
	print(Fore.RED, f'Operating System - {ops} is not usable')


print(Fore.RESET)



