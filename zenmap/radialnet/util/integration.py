# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                * 
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included COPYING.OpenSSL file, and distribute linked      *
# * combinations including the two. You must obey the GNU GPL in all        *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

from radialnet.core.Graph import *
from radialnet.gui.RadialNet import NetNode

import re


COLORS = [(0.0, 1.0, 0.0),
          (1.0, 1.0, 0.0),
          (1.0, 0.0, 0.0)]

BASE_RADIUS = 5.5
NONE_RADIUS = 4.5



def calc_vulnerability_level(node, host):
    """
    """
    num_open_ports = host.get_open_ports()

    node.set_info({'number_of_scanned_ports': num_open_ports})

    if num_open_ports < 3:
        node.set_info({'vulnerability_score': 0})

    elif num_open_ports < 7:
        node.set_info({'vulnerability_score': 1})

    else:
        node.set_info({'vulnerability_score': 2})


def set_node_info(node, host):
    """
    """
    node.set_info({"host_reference": host})
    
    # getting vulnerability score
    calc_vulnerability_level(node, host)
    
    radius = BASE_RADIUS + node.get_info("number_of_scanned_ports") / 2
    
    node.set_draw_info({"color":COLORS[node.get_info("vulnerability_score")],
                        "radius":radius})
    
    # getting address and hostnames
    addresses = []
    if host.ip is not None:
        addresses.append(host.ip)
    if host.ipv6 is not None:
        addresses.append(host.ipv6)
    if host.mac is not None:
        addresses.append(host.mac)
    
    node.set_info({"addresses": addresses})
    if len(addresses) > 0:
        node.set_info({"ip": addresses[0].get("addr", "")})
    
    if len(host.hostnames) > 0:
        hostnames = []
        for hname in host.hostnames:
            hostname = {}
            hostname["name"] = hname.get("hostname", "")
            hostname["type"] = hname.get("hostname_type", "")
            
            hostnames.append(hostname)

        node.set_info({"hostnames": hostnames})
        node.set_info({"hostname": hostnames[0].get("name", "")})

    # getting uptime
    # if len(host.uptime) > 0 doesn't work here, since these fields are present
    # (but empty) even if there's no uptime information
    if reduce(lambda x,y: x + y, host.uptime.values(), "") != "":
        node.set_info({"uptime": host.uptime})
    else:
        node.set_info({"uptime": None})

    # getting os fingerprint information
    os = None
    
    # osclasses
    if len(host.osclasses) > 0:
        os = {}
        types = ["router", "wap", "switch", "firewall"]
        for type in types:
            if type in host.osclasses[0].get("type", "").lower():
                node.set_info({"device_type": type})
        
        os_classes = []
        for osclass in host.osclasses:
            os_class = {}

            os_class["type"] = osclass.get("type", "")
            os_class["vendor"] = osclass.get("vendor", "")
            #os_class["accuracy"] = int(osclass.get("accuracy", ""))
            os_class["accuracy"] = osclass.get("accuracy", "")
            os_class["os_family"] = osclass.get("osfamily", "")
            os_class["os_gen"] = osclass.get("osgen", "")
            
            os_classes.append(os_class)
        os["classes"] = os_classes
    
    # osmatches
    if len(host.osmatches) > 0 and \
       host.osmatches[0]["accuracy"] != "" and \
       host.osmatches[0]["name"] != "":
        if os == None:
            os = {}
        os["matches"] = host.osmatches
        os["matches"][0]["db_line"] = 0     # not supported
    
    # ports_used
    if len(host.ports_used) > 0:
        if os == None:
            os = {}
        os_portsused = []
        
        for portused in host.ports_used:
            os_portused = {}
            
            os_portused["state"] = portused.get("state", "")
            os_portused["protocol"] = portused.get("proto", "")
            os_portused["id"] = int(portused.get("portid", "0"))
            
            os_portsused.append(os_portused)
        
        os["used_ports"] = os_portsused
    
    if os != None:
        os["fingerprint"] = ""  # currently unsupported by the NmapParserSAX class
    node.set_info({"os": os})
    
    # getting sequences information
    sequences = {}
    # If all fields are empty, we don't put it into the sequences list
    if reduce(lambda x,y: x + y, host.tcpsequence.values(), "") != "":
        tcp = {}
        if host.tcpsequence.get("index", "") != "":
            tcp["index"] = int(host.tcpsequence["index"])
        else:
            tcp["index"] = 0
        tcp["class"] = ""   # not supported
        tcp["values"] = host.tcpsequence.get("values", "").split(",")
        tcp["difficulty"] = host.tcpsequence.get("difficulty", "")
        sequences["tcp"] = tcp
    if reduce(lambda x,y: x + y, host.ipidsequence.values(), "") != "":
        ip_id = {}
        ip_id["class"] = host.ipidsequence.get("class", "")
        ip_id["values"] = host.ipidsequence.get("values", "").split(",")
        sequences["ip_id"] = ip_id
    if reduce(lambda x,y: x + y, host.tcptssequence.values(), "") != "":
        tcp_ts = {}
        tcp_ts["class"] = host.tcptssequence.get("class", "")
        tcp_ts["values"] = host.tcptssequence.get("values", "").split(",")
        sequences["tcp_ts"] = tcp_ts
    node.set_info({"sequences": sequences})

    # host is host filtered
    if len(host.extraports) > 0 and host.extraports[0]["state"] == "filtered":
        node.set_info({"filtered": True})
    else:
        for port in host.ports:
            if port["port_state"] == "filtered":
                node.set_info({"filtered": True})
                break

    # getting ports information
    ports = list()
    for host_port in host.ports:
        port = dict()
        state = dict()
        service = dict()
        
        port["id"] = int(host_port.get("portid", ""))
        port["protocol"] = host_port.get("protocol", "")
        
        state["state"] = host_port.get("port_state", "")
        state["reason"] = ""        # not supported
        state["reason_ttl"] = ""    # not supported
        state["reason_ip"] = ""     # not supported
        
        service["name"] = host_port.get("service_name", "")
        service["conf"] = host_port.get("service_conf", "")
        service["method"] = host_port.get("service_method", "")
        service["version"] = host_port.get("service_version", "")
        service["product"] = host_port.get("service_product", "")
        service["extrainfo"] = host_port.get("service_extrainfo", "")
        
        port["state"] = state
        port["scripts"] = None      # not supported
        port["service"] = service
        
        ports.append(port)
    
    node.set_info({"ports":ports})

    # extraports
    all_extraports = list()
    for extraport in host.extraports:
        extraports = dict()
        extraports["count"] = int(extraport.get("count", ""))
        extraports["state"] = extraport.get("state", "")
        extraports["reason"] = list()       # not supported
        extraports["all_reason"] = list()   # not supported
        
        all_extraports.append(extraports)
    
    node.set_info({"extraports":all_extraports})

    # getting traceroute information
    if len(host.trace) > 0:
        trace = {}
        hops = []

        for host_hop in host.trace.get("hops", []):
            hop = {}
            hop["ip"] = host_hop.get("ipaddr", "")
            hop["ttl"] = int(host_hop.get("ttl", ""))
            hop["rtt"] = host_hop.get("rtt", "")
            hop["hostname"] = host_hop.get("host", "")
            
            hops.append(hop)
        
        trace["hops"] = hops
        trace["port"] = host.trace.get("port", "")
        trace["protocol"] = host.trace.get("proto", "")

        node.set_info({"trace":trace})


def make_graph_from_nmap_parser(parser):
    """
    """
    hosts = parser.get_root().search_children('host', deep=True)
    graph = Graph()
    nodes = list()
    index = 1

    # setting initial reference host
    nodes.append(NetNode(0))
    node = nodes[-1]

    node.set_info({'ip':'127.0.0.1/8', 'hostname':'localhost'})
    node.set_draw_info({'color':(0,0,0), 'radius':NONE_RADIUS})

    # for each host in hosts just mount the graph
    for host in hosts:

        trace = host.search_children('trace', True, True)

        # if host has traceroute information mount graph
        if trace != None:

            prev_node = nodes[0]

            hops = trace.search_children('hop')
            ttls = [int(hop.get_attr('ttl')) for hop in hops]

            # getting nodes of host by ttl
            for ttl in range(1, max(ttls) + 1):

                if ttl in ttls:

                    hop = trace.query_children('hop', 'ttl', ttl, True)

                    for node in nodes:
                        if hop.get_attr('ipaddr') == node.get_info('ip'):
                            break

                    else:

                        nodes.append(NetNode(index))
                        node = nodes[-1]
                        index += 1

                        node.set_draw_info({'valid':True})
                        node.set_info({'ip':hop.get_attr('ipaddr')})
                        node.set_draw_info({'color':(1,1,1),
                                            'radius':NONE_RADIUS})

                        if hop.get_attr('host') != None:
                            node.set_info({'hostname':hop.get_attr('host')})

                    rtt = hop.get_attr('rtt')

                    if rtt != '--':
                        graph.set_connection(node, prev_node, float(rtt))

                    else:
                        graph.set_connection(node, prev_node)

                else:

                    nodes.append(NetNode(index))
                    node = nodes[-1]
                    index += 1

                    node.set_draw_info({'valid':False})
                    node.set_info({'ip':None, 'hostname':None})
                    node.set_draw_info({'color':(1,1,1), 'radius':NONE_RADIUS})

                    graph.set_connection(node, prev_node)

                prev_node = node

    # for each full scanned host
    for host in hosts:

        ip = host.query_children('address', 'addrtype', 'ipv4', True)

        if ip == None:
            ip = host.query_children('address', 'addrtype', 'ipv6', True)

        for node in nodes:
            if ip.get_attr('addr') == node.get_info('ip'):
                break

        else:

            nodes.append(NetNode(index))
            node = nodes[-1]
            index += 1

            node.set_draw_info({'no_route':True})

            graph.set_connection(node, nodes[0])

        node.set_draw_info({'valid':True})
        node.set_info({'scanned':True})
        set_node_info(node, host)

    graph.set_nodes(nodes)
    graph.set_main_node_by_id(0)

    return graph


def make_graph_from_hosts(hosts):
    #hosts = parser.get_root().search_children('host', deep=True)
    graph = Graph()
    nodes = list()
    index = 1

    # Setting initial reference host
    nodes.append(NetNode(0))
    node = nodes[-1]

    node.set_info({"ip":"127.0.0.1/8", "hostname":"localhost"})
    node.set_draw_info({"color":(0,0,0), "radius":NONE_RADIUS})

    # For each host in hosts just mount the graph
    for host in hosts:
        trace = host.trace
        
        hops = trace.get("hops")
        # If host has traceroute information mount graph
        if hops is not None and len(hops) > 0:
            prev_node = nodes[0]
            hops = trace.get("hops", [])
            ttls = [int(hop["ttl"]) for hop in hops]
            
            # Getting nodes of host by ttl
            for ttl in range(1, max(ttls) + 1):
                if ttl in ttls:
                    # Find a hop by ttl
                    hop = None
                    for h in hops:
                        if ttl == int(h["ttl"]):
                            hop = h
                            break
                    
                    for node in nodes:
                        if hop["ipaddr"] == node.get_info("ip"):
                            break
                    else:
                        nodes.append(NetNode(index))
                        node = nodes[-1]
                        index += 1
                        
                        node.set_draw_info({"valid":True})
                        node.set_info({"ip":hop["ipaddr"]})
                        node.set_draw_info({"color":(1,1,1),
                                            "radius":NONE_RADIUS})
                        
                        if hop["host"] != "":
                            node.set_info({"hostname":hop["host"]})
                    
                    rtt = hop["rtt"]
                    if rtt != "--":
                        graph.set_connection(node, prev_node, float(rtt))
                    else:
                        graph.set_connection(node, prev_node)
                else:
                    nodes.append(NetNode(index))
                    node = nodes[-1]
                    index += 1
                    
                    node.set_draw_info({"valid":False})
                    node.set_info({"ip":None, "hostname":None})
                    node.set_draw_info({"color":(1,1,1), "radius":NONE_RADIUS})
                    
                    graph.set_connection(node, prev_node)
                
                prev_node = node

    # For each fully scanned host
    for host in hosts:
        ip = host.ip
        if ip is None:
            ip = host.ipv6
        
        for node in nodes:
            if ip is not None and ip["addr"] == node.get_info("ip"):
                break
        else:
            nodes.append(NetNode(index))
            node = nodes[-1]
            index += 1
            
            node.set_draw_info({"no_route":True})
            
            graph.set_connection(node, nodes[0])
        
        node.set_draw_info({"valid":True})
        node.set_info({"scanned":True})
        set_node_info(node, host)
    
    graph.set_nodes(nodes)
    graph.set_main_node_by_id(0)

    return graph
