import xml.etree.ElementTree as ET

def create_raw_nmap_output_root_from_file(filename):
	'''
	load the nmap.xml file into an element tree
	'''
	tree = ET.parse(filename)
	return tree.getroot()

def add_rich_text_to_node(node, content=None):
	'''
	Add a <rich_text> subnode with content to the given parent node
	returns the new rich text node
	'''
	rich_text = ET.SubElement(node,'rich_text')		# make the node
	if (content == None):
		content = ''
	rich_text.text = str(content)					# set the inner text
	return rich_text								# return the new rich text node


def create_blank_cherrytree_nmap_root():
	'''
	Returns a tuple containing the root of the new tree and the blank scan results node
	'''
	cherrytree = ET.Element('cherrytree')
	scan_results = ET.SubElement(cherrytree,'node',attrib={'prog_lang':"custom-colors",'name':"Scan Result"})
	return (cherrytree, scan_results)

def extract_scan_type_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.find('scaninfo').get('type')
	except:
		return None

def extract_scan_protocol_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.find('scaninfo').get('protocol')
	except:
		return None

def extract_scan_num_services_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.find('scaninfo').get('numservices')
	except:
		return None

def extract_scan_services_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.find('scaninfo').get('services')
	except:
		return None

def extract_scan_start_time_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.getroot().get('startstr')
	except:
		return None

def extract_scan_end_time_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.find('runstats').find('finished').get('timestr')
	except:
		return None

def extract_scan_args_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.getroot().get('args')
	except:
		return None

def extract_scan_summary_from_raw_nmap_tree(raw_nmap_tree):
	try:
		return raw_nmap_tree.find('runstats').find('finished').get('summary')
	except:
		return None

def extract_scan_metadata_from_raw_nmap_tree(raw_nmap_tree):
	return {
		'type':			extract_scan_type_from_raw_nmap_tree(raw_nmap_tree),
		'protocol':		extract_scan_protocol_from_raw_nmap_tree(raw_nmap_tree),
		'num_services': extract_scan_num_services_from_raw_nmap_tree(raw_nmap_tree),
		'services':		extract_scan_services_from_raw_nmap_tree(raw_nmap_tree),
		'start_time':	extract_scan_start_time_from_raw_nmap_tree(raw_nmap_tree),
		'end_time':		extract_scan_end_time_from_raw_nmap_tree(raw_nmap_tree),
		'args':			extract_scan_args_from_raw_nmap_tree(raw_nmap_tree),
		'summary':		extract_scan_summary_from_raw_nmap_tree(raw_nmap_tree)
	}


def extract_hosts_from_raw_nmap_tree(raw_nmap_tree):
	return raw_nmap_tree.findall('host')

def extract_ip_addr_from_host(host):
	try:
		return host.find("address[@addrtype='ipv4']").get('addr')
	except:
		return None

def extract_mac_addr_from_host(host):
	try:
		return host.find("address[@addrtype='mac']").get('addr')
	except:
		return None

def extract_up_reason_from_host(host):
	try:
		return host.find("status").get('reason')
	except:
		return None

def extract_hostname_from_host(host):
	try:
		return host.find("hostnames").find('hostname').text
	except:
		return None

def extract_host_metadata_from_host(host):
		return {
			'ip_addr' :	extract_ip_addr_from_host(host),
		#	'mac_addr':	extract_mac_addr_from_host(host),
			'up_reason': extract_up_reason_from_host(host),
		#	'hostnames': extract_hostname_from_host(host)
		}

def run():
	'''
	When invoked on the CLI, do the following:
	1. get scan metadata from nmap.xml
	2. get hosts and for each host
	3. get ports and the respective services, and script output
	4. format extracted data into a cherrytree
	5. write the resulting cherrytree to a file
	'''

	# 1. get scan metadata from nmap.xml
	raw_nmap_tree = create_raw_nmap_output_root_from_file(filename="test_nmap_output.xml")


	# 2. get hosts and for each host
	# 3. get ports and the respective services, and script output
	# 4. format extracted data into a cherrytree
	# 5. write the resulting cherrytree to a file
	nmap_root = create_blank_cherrytree_nmap_root()
	scan_metadata = extract_scan_metadata_from_raw_nmap_tree(raw_nmap_tree)
	hosts = get_hosts()
	for host in hosts:
		host_metadata = extract_host_metadata_from_host(host)
	#	 ports = # get state @state=open
		# for each port: 
			# if state/@state=='open'
				# <node prog_lang="custom-colors" custom_icon_id="1" name="{portid PROTOCOL i.e. 80 TCP'}">
			# if state/@state=='filtered'
				# <node prog_lang="custom-colors" custom_icon_id="2" name="{$portid $protocol.toUpper)}">
			# state = value of state/@state + ( + state/@reason + )
			# service = Name + (method), Product + version, extrainfo, cpe.text <service name="http" product="Microsoft IIS httpd" version="10.0" ostype="Windows" method="probed" conf="10">
			# script = ID > Output: <script id="fingerprint-strings" output="&#xa;	DNSVersionBindReqTCP: &#xa;    version&#xa;    bind">
	#						 <node prog_lang="custom-colors" name="{@id}">
	#							 <rich_text>
	#								 <xsl:value-of select="@output" />
	#							 </rich_text>
	#						 </node>
	#						 <xsl:if test="service">
	#							 <rich_text>

if __name__ == "__main__":
	run()
