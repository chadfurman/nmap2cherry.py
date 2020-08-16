import xml.etree.ElementTree as ET
tree = ET.ElementTree(file='host.xml')

indent = 0
ignoreElems = ['displayNameKey', 'displayName']

def printRecur(root):
    """Recursively prints the tree."""
    if root.tag in ignoreElems:
        return
    print ' '*indent + '%s: %s' % (root.tag.title(), root.attrib.get('name', root.text))
    global indent
    indent += 4
    for elem in root.getchildren():
        printRecur(elem)
    indent -= 4

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


cherrytree = ET.element('cherrytree')
scan_results = ET.Subelement(cherrytree,'node',{prog_lang="custom-colors",name="Scan Result"})
arguments = #get arguments from parse
#            <rich_text>
#                <xsl:value-of select="concat('Arguments: ', @args, '&#xA;')" />
#            </rich_text>

runtime = #get runtime from parse
#            <rich_text>
#                <xsl:variable name="run-time">
#                    <xsl:value-of select="@startstr"/>
#                    <xsl:text> - </xsl:text>
#                    <xsl:value-of select="runstats/finished/@timestr"/>
#                    <xsl:value-of select="concat(' (', runstats/finished/@elapsed, ' seconds)')" />
#                </xsl:variable>
#                <xsl:value-of select="concat('Run time: ', $run-time, '&#xA;')" />
#            </rich_text>


summary = #get summary from parse
#            <rich_text>
#                <xsl:value-of select="concat('Summary: ', runstats/finished/@summary)" />
#            </rich_text>

ip_addr = # get ip addr from parse
mac_addr = # get
up_reason = # get
hostnames= # get 
#            <xsl:variable name="ip-addr" select="address[@addrtype='ipv4']/@addr" />
#            <node prog_lang="custom-colors" name="{$ip-addr}">
#                <rich_text>
#                    <xsl:value-of select="concat('MAC address: ', address[@addrtype='mac']/@addr, ' (', address[@addrtype='mac']/@vendor, ')&#xA;')" />
#                    <xsl:value-of select="concat('Up reason: ', status/@reason)" />
#                    <xsl:for-each select="hostnames/hostname">
#                        <xsl:value-of select="concat('&#xA;Hostname: ', @name, ' (', @type, ')')" />
#                    </xsl:for-each>
#                </rich_text>

ports = # get
#                <xsl:if test="contains(state/@state, 'open')">
#                    <xsl:variable name="custom_icon_id">
#                        <xsl:choose>
#                            <xsl:when test="contains(state/@state, 'filtered')">
#                                <xsl:text>2</xsl:text>
#                            </xsl:when>
#                            <xsl:otherwise>
#                                <xsl:text>1</xsl:text>
#                            </xsl:otherwise>
#                        </xsl:choose>
#                    </xsl:variable>
#
#                    <node prog_lang="custom-colors" custom_icon_id="{$custom_icon_id}" name="{concat(@portid, ' (', upper-case(@protocol), ')')}">
#                        <rich_text>
#                            <xsl:value-of select="concat('State: ', state/@state, ' (', state/@reason, ')')" />
#                        </rich_text>
#                        <xsl:if test="service">
#                            <rich_text>
#                                <xsl:value-of select="concat('&#xA;Service name: ', service/@name, ' (', service/@method, ')')" />
#                                <xsl:if test="service/@product">
#                                    <xsl:value-of select="concat('&#xA;Product: ', service/@product, ' ', service/@version)" />
#                                </xsl:if>
#                                <xsl:if test="service/@extrainfo">
#                                    <xsl:value-of select="concat('&#xA;Extra info: ', service/@extrainfo)" />
#                                </xsl:if>
#                                <xsl:if test="service/cpe">
#                                    <xsl:for-each select="service/cpe">
#                                        <xsl:value-of select="concat('&#xA;CPE: ', text())" />
#                                    </xsl:for-each>
#                                </xsl:if>
#                            </rich_text>
#                        </xsl:if>
#                        <node prog_lang="custom-colors" name="{@id}">
#                            <rich_text>
#                                <xsl:value-of select="@output" />
#                            </rich_text>
#                        </node>
#                    </node>
#                </xsl:if>
            </node>
