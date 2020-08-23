import xml.etree.ElementTree as ET
tree = ET.ElementTree(file='host.xml')

root = tree.getroot()
printRecur(root)

def add_rich_text(node, content=None):
    '''
    Add a <rich_text> subnode with content to the given parent node
    returns the new rich text node
    '''
    rich_text = ET.Subelement(node,'rich_text')     # make the node
    if (content == None):
        content = ''
    rich_text.text = str(content)                   # set the inner text
    return rich_text                                # return the new rich text node


def create_new_nmap_root():
    cherrytree = ET.element('cherrytree')
    scan_results = ET.Subelement(cherrytree,'node',attrib={prog_lang:"custom-colors",name:"Scan Result"})
    return (cherrytree, scan_results)

nmap_root = create_nmap_root()
scan_metadata = {
    type: None,
    protocol: None,
    num_services: None,
    services: None,
    start_time: None, # from nmaprun
    end_time:  None, # from runstats/finished 
    args: None, # get from nmaprun
    summary: None # get from runstats
}
#hosts = get_hosts()
#
#for host in hosts:
#    ip_addr = # get ip addr from parse
#    mac_addr = # get from address @addrtype=mac
#    up_reason = # get from status/reason
#    hostnames= # get from hostnames/hostname (name/type)
#    ports = # get state @state=open
    # for each port: 
        # if state/@state=='open'
            # <node prog_lang="custom-colors" custom_icon_id="1" name="{portid PROTOCOL i.e. 80 TCP'}">
        # if state/@state=='filtered'
            # <node prog_lang="custom-colors" custom_icon_id="2" name="{$portid $protocol.toUpper)}">
        # state = value of state/@state + ( + state/@reason + )
        # service = Name + (method), Product + version, extrainfo, cpe.text <service name="http" product="Microsoft IIS httpd" version="10.0" ostype="Windows" method="probed" conf="10">
        # script = ID > Output: <script id="fingerprint-strings" output="&#xa;  DNSVersionBindReqTCP: &#xa;    version&#xa;    bind">
#                        <node prog_lang="custom-colors" name="{@id}">
#                            <rich_text>
#                                <xsl:value-of select="@output" />
#                            </rich_text>
#                        </node>
#                        <xsl:if test="service">
#                            <rich_text>

#<host starttime="1597602614" endtime="1597603198"><status state="up" reason="echo-reply" reason_ttl="127"/>
#	<address addr="10.10.10.179" addrtype="ipv4"/>
#	<hostnames>
#	</hostnames>
#	<ports><extraports state="filtered" count="65514">
#			<extrareasons reason="no-responses" count="65514"/>
#		</extraports>
#		<port protocol="tcp" portid="53"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="domain" servicefp="SF-Port53-TCP:V=7.80%I=7%D=8/16%Time=5F397BEF%P=x86_64-pc-linux-gnu%r(DNSVersionBindReqTCP,20,&quot;\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03&quot;);" method="table" conf="3"/><script id="fingerprint-strings" output="&#xa;  DNSVersionBindReqTCP: &#xa;    version&#xa;    bind"><elem key="DNSVersionBindReqTCP">&#xa;    version&#xa;    bind</elem>
#		</script></port>
#		<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="http" product="Microsoft IIS httpd" version="10.0" ostype="Windows" method="probed" conf="10"><cpe>cpe:/a:microsoft:iis:10.0</cpe><cpe>cpe:/o:microsoft:windows</cpe></service><script id="http-favicon" output="Unknown favicon MD5: 6944F7C42798BE78E1465F1C49B5BF04"/><script id="http-methods" output="&#xa;  Supported Methods: GET HEAD OPTIONS TRACE&#xa;  Potentially risky methods: TRACE"><table key="Supported Methods">
#					<elem>GET</elem>
#					<elem>HEAD</elem>
#					<elem>OPTIONS</elem>
#					<elem>TRACE</elem>
#				</table>
#				<table key="Potentially risky methods">
#					<elem>TRACE</elem>
#				</table>
#				</script><script id="http-server-header" output="Microsoft-IIS/10.0"><elem>Microsoft-IIS/10.0</elem>
#				</script><script id="http-title" output="MegaCorp"><elem key="title">MegaCorp</elem>
#		</script></port>
#		<port protocol="tcp" portid="88"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="kerberos-sec" product="Microsoft Windows Kerberos" extrainfo="server time: 2020-08-16 18:42:09Z" ostype="Windows" method="probed" conf="10"><cpe>cpe:/a:microsoft:kerberos</cpe><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="135"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="139"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="netbios-ssn" product="Microsoft Windows netbios-ssn" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="389"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ldap" product="Microsoft Windows Active Directory LDAP" extrainfo="Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name" hostname="MULTIMASTER" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="microsoft-ds" product="Windows Server 2016 Standard 14393 microsoft-ds" extrainfo="workgroup: MEGACORP" hostname="MULTIMASTER" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="464"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="kpasswd5" method="table" conf="3"/></port>
#		<port protocol="tcp" portid="593"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ncacn_http" product="Microsoft Windows RPC over HTTP" version="1.0" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="636"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="tcpwrapped" method="probed" conf="8"/></port>
#		<port protocol="tcp" portid="3268"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ldap" product="Microsoft Windows Active Directory LDAP" extrainfo="Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name" hostname="MULTIMASTER" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="3269"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="tcpwrapped" method="probed" conf="8"/></port>
#		<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ms-wbt-server" product="Microsoft Terminal Services" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service><script id="rdp-ntlm-info" output="&#xa;  Target_Name: MEGACORP&#xa;  NetBIOS_Domain_Name: MEGACORP&#xa;  NetBIOS_Computer_Name: MULTIMASTER&#xa;  DNS_Domain_Name: MEGACORP.LOCAL&#xa;  DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL&#xa;  DNS_Tree_Name: MEGACORP.LOCAL&#xa;  Product_Version: 10.0.14393&#xa;  System_Time: 2020-08-16T18:45:20+00:00"><elem key="Target_Name">MEGACORP</elem>
#				<elem key="NetBIOS_Domain_Name">MEGACORP</elem>
#				<elem key="NetBIOS_Computer_Name">MULTIMASTER</elem>
#				<elem key="DNS_Domain_Name">MEGACORP.LOCAL</elem>
#				<elem key="DNS_Computer_Name">MULTIMASTER.MEGACORP.LOCAL</elem>
#				<elem key="DNS_Tree_Name">MEGACORP.LOCAL</elem>
#				<elem key="Product_Version">10.0.14393</elem>
#				<elem key="System_Time">2020-08-16T18:45:20+00:00</elem>
#					</script><script id="ssl-cert" output="Subject: commonName=MULTIMASTER.MEGACORP.LOCAL&#xa;Issuer: commonName=MULTIMASTER.MEGACORP.LOCAL&#xa;Public Key type: rsa&#xa;Public Key bits: 2048&#xa;Signature Algorithm: sha256WithRSAEncryption&#xa;Not valid before: 2020-08-15T16:48:54&#xa;Not valid after:  2021-02-14T16:48:54&#xa;MD5:   4c21 1b9c f090 415c 7d3b bb44 d4df 5ecc&#xa;SHA-1: ea02 0e1d 4729 db84 dcec 4d91 e180 7106 20cf 8b36"><table key="subject">
#					<elem key="commonName">MULTIMASTER.MEGACORP.LOCAL</elem>
#				</table>
#				<table key="issuer">
#					<elem key="commonName">MULTIMASTER.MEGACORP.LOCAL</elem>
#				</table>
#				<table key="pubkey">
#					<elem key="bits">2048</elem>
#					<elem key="exponent">userdata: 0x560bf3198898</elem>
#					<elem key="modulus">userdata: 0x560bf31988d8</elem>
#					<elem key="type">rsa</elem>
#				</table>
#				<table key="extensions">
#					<table>
#						<elem key="name">X509v3 Extended Key Usage</elem>
#						<elem key="value">TLS Web Server Authentication</elem>
#					</table>
#					<table>
#						<elem key="name">X509v3 Key Usage</elem>
#						<elem key="value">Key Encipherment, Data Encipherment</elem>
#					</table>
#				</table>
#				<elem key="sig_algo">sha256WithRSAEncryption</elem>
#				<table key="validity">
#					<elem key="notBefore">2020-08-15T16:48:54</elem>
#					<elem key="notAfter">2021-02-14T16:48:54</elem>
#				</table>
#				<elem key="md5">4c211b9cf090415c7d3bbb44d4df5ecc</elem>
#				<elem key="sha1">ea020e1d4729db84dcec4d91e180710620cf8b36</elem>
#				<elem key="pem">-&#45;&#45;&#45;&#45;BEGIN CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;MIIC+DCCAeCgAwIBAgIQUgDCk83LiYxNp/eBuaWVkDANBgkqhkiG9w0BAQsFADAl&#xa;MSMwIQYDVQQDExpNVUxUSU1BU1RFUi5NRUdBQ09SUC5MT0NBTDAeFw0yMDA4MTUx&#xa;NjQ4NTRaFw0yMTAyMTQxNjQ4NTRaMCUxIzAhBgNVBAMTGk1VTFRJTUFTVEVSLk1F&#xa;R0FDT1JQLkxPQ0FMMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmpHk&#xa;ysong2c18dmfAVhjw8zOhARSx1jbsnfOKposF62n0r+yxi2I+kIsfXAo/IAmIXxd&#xa;r5hZhhIueNHk+wMOWaegUGzmEz121aCM/8K+wRp/TjD+h9nbZruD0KNWrrPtlSM7&#xa;qXMiwgCat+4MZt0NNbhooKFHWTvBtunSoxixEkKlGDMHLC6KYl2gs96MswM4tGZd&#xa;sq7JG4l7Oq2ij6+GVOJ1VtTIDqcKbqZGih/c/OMRDnOW1Y2Zoxn/pe4KZ334JgFq&#xa;I6Ru9JU8yhpH5+7v3Q6WwI2y4epJhRupDqeMlOG/2xY3RxNxyDOLHlsYb70sD5HZ&#xa;XCSQ38pO0EB+8q+7VwIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNV&#xa;HQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAEtrilOFExEH9klk9Dm/etB9AfY0&#xa;bD9/0duPC9M9PEKzkkFohs9ugISWsIdwo2bMGSAKlycZjfDz2km6BALPN7v1GqpZ&#xa;rAQnb++8E3bTFUU6IuMXInXp+fKvWVCvOXS97wnEKNpQ0mrrl1TaCKYiiwePfHGt&#xa;GfH0kapnbDXW+yJgsMjO0jLxf/x8atNd17piYmL8xQoYdk8su0Bkuf7cmJVoOWVK&#xa;xf3No5pxSfCc5yypmKT7IDISkFBtmHovYEAoGXUWOcJPCnIEw7bxjHOWQj3icFQi&#xa;IaHRM0SP2bPkYmodt2cSYCHCv82SQN7Etl21juzMAaj8HExxaP8uVnr/RXQ=&#xa;-&#45;&#45;&#45;&#45;END CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;</elem>
#				</script><script id="ssl-date" output="2020-08-16T18:45:53+00:00; +8m55s from scanner time."><elem key="delta">535.0</elem>
#				<elem key="date">2020-08-16T18:45:53+00:00</elem>
#		</script></port>
#		<port protocol="tcp" portid="5985"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="http" product="Microsoft HTTPAPI httpd" version="2.0" extrainfo="SSDP/UPnP" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service><script id="http-server-header" output="Microsoft-HTTPAPI/2.0"><elem>Microsoft-HTTPAPI/2.0</elem>
#				</script><script id="http-title" output="Not Found"><elem key="title">Not Found</elem>
#		</script></port>
#		<port protocol="tcp" portid="9389"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="mc-nmf" product=".NET Message Framing" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49666"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49667"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49674"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ncacn_http" product="Microsoft Windows RPC over HTTP" version="1.0" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49675"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49681"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49698"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#		<port protocol="tcp" portid="49745"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
#	</ports>
#	<os><portused state="open" proto="tcp" portid="53"/>
#		<osmatch name="Microsoft Windows Server 2016" accuracy="91" line="75728">
#			<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2016" accuracy="91"><cpe>cpe:/o:microsoft:windows_server_2016</cpe></osclass>
#		</osmatch>
#		<osmatch name="Microsoft Windows Server 2012" accuracy="85" line="75072">
#			<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2012" accuracy="85"><cpe>cpe:/o:microsoft:windows_server_2012</cpe></osclass>
#		</osmatch>
#		<osmatch name="Microsoft Windows Server 2012 or Windows Server 2012 R2" accuracy="85" line="75205">
#			<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2012" accuracy="85"><cpe>cpe:/o:microsoft:windows_server_2012:r2</cpe></osclass>
#		</osmatch>
#		<osmatch name="Microsoft Windows Server 2012 R2" accuracy="85" line="75243">
#			<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2012" accuracy="85"><cpe>cpe:/o:microsoft:windows_server_2012:r2</cpe></osclass>
#		</osmatch>
#		<osmatch name="Microsoft Windows Server 2008 R2" accuracy="85" line="74118">
#			<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2008" accuracy="85"><cpe>cpe:/o:microsoft:windows_server_2008:r2</cpe></osclass>
#		</osmatch>
#		<osmatch name="Microsoft Windows 10 1607" accuracy="85" line="69286">
#			<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="10" accuracy="85"><cpe>cpe:/o:microsoft:windows_10:1607</cpe></osclass>
#		</osmatch>
#	</os>
#	<uptime seconds="7214" lastboot="Sun Aug 16 12:39:44 2020"/>
#	<distance value="2"/>
#	<tcpsequence index="258" difficulty="Good luck!" values="21A35896,1E3B1B61,C87317DC,DED385F8,2222E8D2,54003A5B"/>
#	<ipidsequence class="Incremental" values="3D2D,3D2E,3D2F,3D30,3D31,3D32"/>
#	<tcptssequence class="1000HZ" values="6A7BBE,6A7C2E,6A7C94,6A7CF8,6A7D63,6A7DC6"/>
#	<hostscript><script id="clock-skew" output="mean: 1h32m55s, deviation: 3h07m52s, median: 8m54s"><elem key="stddev">11272</elem>
#			<elem key="median">534</elem>
#			<elem key="count">5</elem>
#			<elem key="mean">5575</elem>
#			</script><script id="smb-os-discovery" output="&#xa;  OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)&#xa;  Computer name: MULTIMASTER&#xa;  NetBIOS computer name: MULTIMASTER\x00&#xa;  Domain name: MEGACORP.LOCAL&#xa;  Forest name: MEGACORP.LOCAL&#xa;  FQDN: MULTIMASTER.MEGACORP.LOCAL&#xa;  System time: 2020-08-16T11:45:17-07:00&#xa;"><elem key="os">Windows Server 2016 Standard 14393</elem>
#			<elem key="lanmanager">Windows Server 2016 Standard 6.3</elem>
#			<elem key="server">MULTIMASTER\x00</elem>
#			<elem key="date">2020-08-16T11:45:17-07:00</elem>
#			<elem key="fqdn">MULTIMASTER.MEGACORP.LOCAL</elem>
#			<elem key="domain_dns">MEGACORP.LOCAL</elem>
#			<elem key="forest_dns">MEGACORP.LOCAL</elem>
#			<elem key="workgroup">MEGACORP\x00</elem>
#			</script><script id="smb-security-mode" output="&#xa;  account_used: &lt;blank&gt;&#xa;  authentication_level: user&#xa;  challenge_response: supported&#xa;  message_signing: required"><elem key="account_used">&lt;blank&gt;</elem>
#			<elem key="authentication_level">user</elem>
#			<elem key="challenge_response">supported</elem>
#			<elem key="message_signing">required</elem>
#				</script><script id="smb2-security-mode" output="&#xa;  2.02: &#xa;    Message signing enabled and required"><table key="2.02">
#				<elem>Message signing enabled and required</elem>
#			</table>
#			</script><script id="smb2-time" output="&#xa;  date: 2020-08-16T18:45:14&#xa;  start_date: 2020-08-16T16:49:00"><elem key="date">2020-08-16T18:45:14</elem>
#			<elem key="start_date">2020-08-16T16:49:00</elem>
#		</script></hostscript><trace port="80" proto="tcp">
#		<hop ttl="1" ipaddr="10.10.14.1" rtt="24.63"/>
#		<hop ttl="2" ipaddr="10.10.10.179" rtt="22.01"/>
#	</trace>
#	<times srtt="23272" rttvar="1653" to="100000"/>
#</host>
