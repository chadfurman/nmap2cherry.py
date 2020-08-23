import unittest
import xml.etree.ElementTree as ET

import nmap2cherry as test_subject
						

class TestNmap2Cherry(unittest.TestCase):

	def test_create_raw_nmap_output_root_from_file(self):
		# 1. setup
		# specify filename 
		filename = "test_nmap_output.xml"

		# 2. execute
		nmap_output_tree = test_subject.create_raw_nmap_output_root_from_file(filename)

		# 3. assert
		self.assertEquals(nmap_output_tree.tag, "nmaprun", msg="Error: test XML not loaded as expected")



	def test_add_rich_text_node(self):
		# 1. setup
		# create parent node
		parent_node = ET.Element('parent_node')

		# set content string
		content_string = "content string for rich text"

		# 2. exectue
		new_rich_text_node = test_subject.add_rich_text_to_node(parent_node, content_string)

		# 3. assert 
		self.assertIn(new_rich_text_node, parent_node, msg = "Error: wrong parent on rich text node")
		self.assertEquals(new_rich_text_node.text, content_string, msg = "Error: wrong content in rich text node")


	def test_create_blank_cherrytree_nmap_root(self):
		# 1. setup
		# none

		# 2. execute
		(cherrytree, results) = test_subject.create_blank_cherrytree_nmap_root()

		# 3. assert
		self.assertEquals(cherrytree.tag, "cherrytree", msg = "Error: new nmap node must be nested in <cherrytree>")

		child_count = 0
		for child in cherrytree:
			child_count += 1
			self.assertEquals(child.tag, "node", msg = "Error: new nmap xml entity should be <node>")
			self.assertEquals(child.get('name'), "Scan Result", msg = "Error: new nmap node missing expected name attribute")
			self.assertEquals(child.get('prog_lang'), "custom-colors", msg = "Error: new nmap node missing expected prog_lang attribute")

		self.assertEquals(child_count, 1, msg = "Error: only <cherrytree><node name='Scan Results' ...></...>")


	def test_parse_scan_metadata(self):
		# 1. setup
		# load in test XML file
		tree = ET.ElementTree(file="test_nmap_output.xml")

		# 2. execute
		scan_metadata = test_subject.extract_scan_metadata_from_raw_nmap_tree(tree)

		# 3. assert
		self.assertEquals(scan_metadata['type'], 'syn', msg = "Error: metadata failed to successfully parse type")
		self.assertEquals(scan_metadata['protocol'], 'tcp', msg = "Error: metadata failed to successfully parse protocol")
		self.assertEquals(scan_metadata['num_services'], '65536', msg = "Error: metadata failed to successfully parse num_services")
		self.assertEquals(scan_metadata['services'], '0-65535', msg = "Error: metadata failed to successfully parse services")
		self.assertEquals(scan_metadata['start_time'], 'Sun Aug 16 14:30:14 2020', msg = "Error: metadata failed to successfully parse start_time")
		self.assertEquals(scan_metadata['end_time'], 'Sun Aug 16 15:03:26 2020', msg = "Error: metadata failed to successfully parse end_time")
		self.assertEquals(scan_metadata['args'], 'nmap -p0- -v -A -T4 -oN nmap_output.nmap -oG nmap_output.grep -oX nmap_output.xml 10.10.10.179,180,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,203', msg = "Error: metadata failed to successfully parse args")
		self.assertEquals(scan_metadata['summary'], 'Nmap done at Sun Aug 16 15:03:26 2020; 20 IP addresses (20 hosts up) scanned in 1992.83 seconds', msg = "Error: metadata failed to successfully parse summary")


	def test_get_hosts(self):
		# 1. setup
		# load in test xml file
		tree = ET.ElementTree(file="test_nmap_output.xml")

		# 2. execute
		hosts = test_subject.extract_hosts_from_raw_nmap_tree(tree)

		# 3. assert
		self.assertEquals(len(hosts), 20, msg = "Error: Incorrect number of hosts")


#	def test_(self):
#		# 1. setup
#		# 
#
#		# 2. execute
#		pass
#
#		# 3. assert
#		self.assertEquals(, msg = "Error: ")


if __name__ == '__main__':
	unittest.main()
