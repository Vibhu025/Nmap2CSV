import xml.etree.ElementTree as ET
import pandas as pd
import sys

def nmap_parser():
	list=[]
	try:
		#  Taking input
		xml_file = sys.argv[1]
		
		#  Checking for xml extension
		if xml_file.split(".")[-1] != "xml":
			print("Please provide an xml file only")
			exit()

		tree = ET.parse(xml_file)
		root = tree.getroot()
	
	#  Handling absence of files in command lines
	except IndexError as e:
		print("Usage: python nmap_parser.py <xml file name>")
		exit()

	#  Handling improper structured xml file
	except ET.ParseError as e:
		print("Could not parse the given XML file, please check the format")
		exit()

	for host in root.findall('host'):
		ip_address = host.find('address').get('addr')
		
		if host.find('hostnames') is not None:
			if host.find('hostnames').find('hostname') is not None:
				hostname = host.find('hostnames').find('hostname').get('name')

		for port in host.find('ports').findall('port'):

			#Getting Protocol
			protocol = port.get('protocol')
			if protocol is None:
				protocol = "Unknown"

			# Getting Port Number
			portnumber = port.get('portid')
			if portnumber is None:
				portnumber = "Unknown"

			# CHecking Port State
			if port.find('state') is not None:
				if port.find('state').get('state') is not None:
					state = port.find('state').get('state')
				elif port.find('state').get('state') is None:
					state = "Unknown"

			if port.find('service') is not None:
				if port.find('service').get('name') is not None:
					service = port.find('service').get('name')

			#Checking Product Info
			if port.find('service') is not None:

				if port.find('service').get('product') is not None:
					product = port.find('service').get('product')
					details = product.replace("", "")

				elif port.find('service').get('product') is None:
					details = "Unknown"

				
				if port.find('service').get('version') is not None:
					version = port.find('service').get('version')
					details = details + '(' + version + ')'

				elif port.find('service').get('version') and port.find('service').get('product') is None:
					details = "Unknown"

				if port.find('service').get('extrainfo') is not None:
					extrainfo = port.find('service').get('extrainfo')
					details = details  + extrainfo  

				elif port.find('service').get('version') and port.find('service').get('product') and port.find('service').get('extrainfo') is None:
					details = "Unknown"

			list.append((ip_address,portnumber,protocol,state,service,details))

		df=pd.DataFrame(list,columns=['IP','Port Number','Protocol','State','Service','Details'])
		df.to_csv('nmap_parser_output.csv')

	message = "Report created Successfully"
	return message


if __name__=='__main__':

	result = nmap_parser()
	print(result)