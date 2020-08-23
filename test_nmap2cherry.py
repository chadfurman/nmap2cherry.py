import unittest
import xml.etree.ElementTree as ET

import nmap2cherry as test_subject
                        

class TestNmap2Cherry(unittest.TestCase):

    def test_load_nmap_scan(self):
        # 1. setup
        # load in test nmap xml
        # specify filename 
        # 

        # 2. execute


        # 3. assert



    def test_add_rich_text_node(self):
        # 1. setup
        # create parent node
        parent_node = ET.element('parent_node')

        # set content string
        content_string = "content string for rich text"

        # 2. exectue
        new_rich_text_node = test_subject.add_rich_text_to_node(parent_node, content_string)

        # 3. assert 
        self.assertTrue(new_rich_text_node.parent == parent_node, "Error: wrong parent on rich text node")
        self.assertTrue(new_rich_text_node.text == content_string, "Error: wrong content in rich text node")

    def test_create_nmap_root(self):
        # 1. setup
        # none

        # 2. execute
        (cherrytree, results) = test_subject.create_new_nmap_root()

        # 3. assert
        self.assertTrue(cherrytree.tag == "cherrytree", "Error: new nmap node must be nested in <cherrytree>")

        child_count = 0
        for child in cherrytree:
            child_count += 1
            self.assertTrue(child.tag == "node", "Error: new nmap xml entity should be <node>")
            self.assertTrue(child.get('name') == "Scan Result", "Error: new nmap node missing expected name attribute")
            self.assertTrue(child.get('prog_lang') == "custom-colors", "Error: new nmap node missing expected prog_lang attribute")

        self.assertTrue(child_count == 1, "Error: only <cherrytree><node name='Scan Results' ...></...>")


    def test_parse_scan_metadata(self):
        pass

    def get_hosts(self):
        pass

    # test host, post, service, and script

if __name__ == '__main__':
    unittest.main()
