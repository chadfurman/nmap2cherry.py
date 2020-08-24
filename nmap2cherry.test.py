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



    def test_add_rich_text_node_to_node(self):
        # 1. setup
        # create parent node
        parent_node = ET.Element('parent_node')

        # set icon id
        icon_id = 1

        # set name
        name = "name"

        # set content string
        content_string = "content string for rich text"

        # 2. exectue
        (new_rich_text_node, new_rich_text) = test_subject.add_rich_text_node_to_node(parent_node, content = content_string, custom_icon_id = icon_id, name = name)

        # 3. assert 
        self.assertIn(new_rich_text_node, parent_node, msg = "Error: wrong parent on rich text node")
        self.assertEquals(new_rich_text_node.tag, 'node', msg = 'Error: wrong tag type on rich text node')
        self.assertEquals(new_rich_text_node.get('prog_lang'), 'custom_colors', msg = 'Error: wrong prog_lang on rich text node')
        self.assertEquals(new_rich_text_node.get('custom_icon_id'), icon_id, msg = 'Error: wrong icon id on rich text node')
        self.assertEquals(new_rich_text_node.get('name'), name, msg = 'Error: wrong icon id on rich text node')

        self.assertEquals(new_rich_text.tag, 'rich_text', msg = 'Error: wrong tag type on rich text')
        self.assertIn(new_rich_text, new_rich_text_node, msg = "Error: wrong parent on rich text")
        self.assertEquals(new_rich_text.text, content_string, msg = "Error: wrong content in rich text")


    def test_create_blank_cherrytree_nmap_root(self):
        # 1. setup
        # none

        # 2. execute
        (cherrytree, results) = test_subject.create_blank_cherrytree_nmap_root()

        # 3. assert
        self.assertEquals(cherrytree.getroot().tag, "cherrytree", msg = "Error: new nmap node must be nested in <cherrytree>")

        child_count = 0
        for child in cherrytree.getroot():
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
        self.assertEquals(scan_metadata['type'], 'syn', msg = "Error: scan metadata failed to successfully parse type")
        self.assertEquals(scan_metadata['protocol'], 'tcp', msg = "Error: scan metadata failed to successfully parse protocol")
        self.assertEquals(scan_metadata['num_services'], '65536', msg = "Error: scan metadata failed to successfully parse num_services")
        self.assertEquals(scan_metadata['services'], '0-65535', msg = "Error: scan metadata failed to successfully parse services")
        self.assertEquals(scan_metadata['start_time'], 'Sun Aug 16 14:30:14 2020', msg = "Error: scan metadata failed to successfully parse start_time")
        self.assertEquals(scan_metadata['end_time'], 'Sun Aug 16 15:03:26 2020', msg = "Error: scan metadata failed to successfully parse end_time")
        self.assertEquals(scan_metadata['args'], 'nmap -p0- -v -A -T4 -oN nmap_output.nmap -oG nmap_output.grep -oX nmap_output.xml 10.10.10.179,180,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,203', msg = "Error: scan metadata failed to successfully parse args")
        self.assertEquals(scan_metadata['summary'], 'Nmap done at Sun Aug 16 15:03:26 2020; 20 IP addresses (20 hosts up) scanned in 1992.83 seconds', msg = "Error: scan metadata failed to successfully parse summary")


    def test_get_hosts(self):
        # 1. setup
        # load in test xml file
        tree = ET.ElementTree(file="test_nmap_output.xml")

        # 2. execute
        hosts = test_subject.extract_hosts_from_raw_nmap_tree(tree)

        # 3. assert
        self.assertEquals(len(hosts), 20, msg = "Error: Incorrect number of hosts")

    def test_extract_host_metadata(self):
        # 1. setup
        # pull a host from the tree
        host = ET.ElementTree(file="test_nmap_output.xml").findall('host')[0]

        # 2. execute
        host_metadata = test_subject.extract_host_metadata_from_host(host)

        # 3. assert
        self.assertEquals(host_metadata['ip_addr'], '10.10.10.179', msg = "Error: host metadata failed to successfully parse ip_addr")
        #self.assertEquals(host_metadata['mac_addr'], None, msg = "Error: host metadata failed to successfully parse mac_addr")
        self.assertEquals(host_metadata['up_reason'], 'echo-reply', msg = "Error: host metadata failed to successfully parse up_reason")
        #self.assertEquals(host_metadata['hostnames'], None, msg = "Error: host metadata failed to successfully parse hostnames")

    def test_extract_ports_from_host(self):
        # 1. setup
        # pull a host from the tree
        host = ET.ElementTree(file="test_nmap_output.xml").findall('host')[0]

        # 2. execute
        ports = test_subject.extract_ports_from_host(host)

        # 3. assert
        self.assertEquals(len(ports), 22, msg = "Error: unexpected number of extracted ports")

    def test_extract_scripts_from_ports(self):
        # 1. setup
        # pull a port from the tree
        port = ET.ElementTree(file="test_nmap_output.xml").findall('host')[0].find('ports').findall('port')[1]

        # 2. execute
        scripts = test_subject.extract_scripts_from_port(port)

        # 3. assert
        self.assertEquals(len(scripts), 4, msg = "Error: unexpected number of extracted scripts")

    def test_extract_script_metadata(self):
        # 1. setup
        # pull a script from the tree
        script = ET.ElementTree(file="test_nmap_output.xml").findall('host')[0].find('ports').findall('port')[1].findall('script')[0]

        # 2. execute
        script_metadata = test_subject.extract_script_metadata_from_script(script)

        # 3. assert
        self.assertEquals(script_metadata['id'], 'http-favicon', msg = "Error: host metadata failed to successfully parse id")
        self.assertEquals(script_metadata['output'], 'Unknown favicon MD5: 6944F7C42798BE78E1465F1C49B5BF04', msg = "Error: host metadata failed to successfully parse output")

    def test_extract_port_metadata(self):
        # 1. setup
        # pull a port from the tree
        port = ET.ElementTree(file="test_nmap_output.xml").findall('host')[0].find('ports').findall('port')[1]

        # 2. execute
        port_metadata = test_subject.extract_port_metadata_from_port(port)

        # 3. assert
        self.assertEquals(port_metadata['portid'], '80', msg = "Error: host metadata failed to successfully parse portid")
        self.assertEquals(port_metadata['protocol'], 'tcp', msg = "Error: host metadata failed to successfully parse protocol")
        self.assertEquals(port_metadata['state'], 'open', msg = "Error: host metadata failed to successfully parse state")
        self.assertEquals(port_metadata['service'], 'Microsoft IIS httpd', msg = "Error: host metadata failed to successfully parse service")

#       def test_(self):
#               # 1. setup
#               # 
#
#               # 2. execute
#               pass
#
#               # 3. assert
#               self.assertEquals(, msg = "Error: ")


if __name__ == '__main__':
    unittest.main()
