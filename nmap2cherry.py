import xml.etree.ElementTree as ET
import sys


def create_raw_nmap_output_root_from_file(filename):
    '''
    load the nmap.xml file into an element tree
    '''
    tree = ET.parse(filename)
    return tree.getroot()


def add_rich_text_node_to_node(
        node,
        name,
        content=None,
        prog_lang='custom_colors',
        custom_icon_id=None):
    '''
    Add a <rich_text> subnode with content to the given parent node
    returns the new rich text node
    '''
    rich_text_node = ET.SubElement(node, 'node')     # make the node
    rich_text_node.set('name', name)
    rich_text_node.set('prog_lang', prog_lang)

    if custom_icon_id:
        rich_text_node.set('custom_icon_id', custom_icon_id)

    rich_text = ET.SubElement(rich_text_node, 'rich_text')
    rich_text.text = str(content) if content else ''  # set the inner text
    return rich_text_node, rich_text  # return the new rich text node


def create_blank_cherrytree_nmap_root():
    '''
    Returns a tuple containing the root of the new tree 
    and the blank scan results node
    '''
    cherrytree = ET.Element('cherrytree')
    tree = ET.ElementTree(cherrytree)
    scan_results = ET.SubElement(cherrytree, 'node', attrib={
        'prog_lang': "custom-colors",
        'name': "Scan Result"
    })
    return (tree, scan_results)


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
        'type': extract_scan_type_from_raw_nmap_tree(raw_nmap_tree),
        'protocol': extract_scan_protocol_from_raw_nmap_tree(raw_nmap_tree),
        'num_services': extract_scan_num_services_from_raw_nmap_tree(raw_nmap_tree),
        'services': extract_scan_services_from_raw_nmap_tree(raw_nmap_tree),
        'start_time': extract_scan_start_time_from_raw_nmap_tree(raw_nmap_tree),
        'end_time': extract_scan_end_time_from_raw_nmap_tree(raw_nmap_tree),
        'args': extract_scan_args_from_raw_nmap_tree(raw_nmap_tree),
        'summary': extract_scan_summary_from_raw_nmap_tree(raw_nmap_tree)
    }


def extract_hosts_from_raw_nmap_tree(raw_nmap_tree):
    try:
        return raw_nmap_tree.findall('host')
    except:
        return None


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
        'ip_addr' :     extract_ip_addr_from_host(host),
        'up_reason': extract_up_reason_from_host(host),
    }


def extract_ports_from_host(host):
    try:
        return host.find('ports').findall('port')
    except:
        return None


def extract_portid_from_port(port):
    try:
        return port.get('portid')
    except:
        return None


def extract_protocol_from_port(port):
    try:
        return port.get('protocol')
    except:
        return None


def extract_state_from_port(port):
    try:
        return port.find('state').get('state')
    except:
        return None


def extract_service_from_port(port):
    try:
        return port.find('service').get('product')
    except:
        return None


def extract_port_metadata_from_port(port):
    return {
        'portid': extract_portid_from_port(port),
        'protocol': extract_protocol_from_port(port),
        'state': extract_state_from_port(port),
        'service': extract_service_from_port(port),
    }


def extract_scripts_from_port(port):
    try:
        return port.findall('script')
    except:
        return None


def extract_id_from_script(script):
    try:
        return script.get('id')
    except:
        return None


def extract_output_from_script(script):
    try:
        return script.get('output')
    except:
        return None


def extract_script_metadata_from_script(script):
    return {
        'id': extract_id_from_script(script),
        'output': extract_output_from_script(script)
    }


def run(filename):
    '''
    When invoked on the CLI, do the following:
        1. get scan metadata from nmap.xml
        2. get hosts and for each host
        3. get ports and the respective services, and script output
        4. format extracted data into a cherrytree
        5. write the resulting cherrytree to a file
    '''
    (cherrytree, nmap_node) = create_blank_cherrytree_nmap_root()

    # 1. get scan metadata from nmap.xml
    raw_nmap_tree = create_raw_nmap_output_root_from_file(filename=filename)
    add_rich_text_node_to_node(nmap_node, name='Metadata', content=extract_scan_metadata_from_raw_nmap_tree(raw_nmap_tree))

    # 2. build a cherrytree from all information about the hosts that we care about
    hosts = extract_hosts_from_raw_nmap_tree(raw_nmap_tree)
    (hosts_node, leaf) = add_rich_text_node_to_node(nmap_node, name='Hosts')
    for host in hosts: 
        # each host's metadata
        host_metadata = extract_host_metadata_from_host(host)
        (host_node, leaf) = add_rich_text_node_to_node(hosts_node, name='Host: '+host_metadata['ip_addr'])

        ports = extract_ports_from_host(host)
        (ports_node, leaf) = add_rich_text_node_to_node(host_node, name='Ports')
        for port in ports:
            # each port's metadata
            port_metadata = extract_port_metadata_from_port(port)
            custom_icon_id = '2' if port_metadata['state'] == 'open' else '1'
            (port_node, leaf) = add_rich_text_node_to_node(ports_node, custom_icon_id = custom_icon_id, name='%s %s' % (port_metadata['portid'],port_metadata['protocol']))
            scripts = extract_scripts_from_port(port)
            (scripts_node, leaf) = add_rich_text_node_to_node(port_node, name='Scripts')
            for script in scripts:
                # each script's metadata
                script_metadata = extract_script_metadata_from_script(script)
                (script_node, leaf) = add_rich_text_node_to_node(scripts_node,content = script_metadata['output'], name='%s' % (script_metadata['id']))

        cherrytree.write('new_cherrytree.ctd')


if __name__ == "__main__":
    run(sys.argv[1])
