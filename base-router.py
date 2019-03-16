import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4
from ryu.lib.packet import ethernet, ether_types, icmp
from ryu.lib.packet import in_proto as inet
from ryu.lib import dpid as dpid_lib
import pytricia

# Router data file (all routes are static and pre-loaded)
router_data_filepath = "/home/soutzis/PycharmProjects/SCC365-SDN_Router/router-data.json"

# Ryu doesn't include a "network unreachable icmp code", so it is declared here, simply for semantic clarification
ICMP_NET_UNREACH_CODE = 0


# noinspection PyProtectedMember
class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self._init_switch()
        self._init_router()

        # Specify ether types to filter (to ignore)
        self.ethertypes_filter = [
            ether_types.ETH_TYPE_IPV6,
            ether_types.ETH_TYPE_LLDP
        ]

    def _init_switch(self):
        """ Create Vars for the L4 Learning Switch """
        self.switch_dpids = ["0000000000000001", "0000000000000004"]
        self.mac_to_port = {}

    def _init_router(self):
        """ Create Vars for the Router """
        self.router_dpids = ['0000000000000003', '0000000000000002']
        self.interfaces = {}
        self.routes_table = {}  # Take a look at how this dir is structured in _features_handler
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features_handler(self, ev):
        """ Handle Feature Events (e.g. datapath changes)"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid_lib.dpid_to_str(datapath.id)

        ## Install flow-table miss entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)  # table-miss entry

        # Install Invalid-TTL entry, so that controller will send an ICMP_TIME_EXCEEDED type message
        match = parser.OFPMatch(ofproto.OFPR_INVALID_TTL)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 2, match, actions)  # invalid ttl entry

        ## Check if switch joined
        if dpid in self.switch_dpids:
            self.logger.info("!> Switch Joined Datapath | DPID: %s", dpid)

        ## Check if router joined and install routing table
        if dpid in self.router_dpids:
            self.logger.info("!> Router Joined Datapath | DPID: %s", dpid)
            with open(router_data_filepath, "r") as rdf:
                router_data = json.load(rdf)
            if "datapath" not in router_data:
                self.logger.info("ERROR: Router Data File Invalid")
                return
            router_data = router_data["datapath"]
            if dpid in router_data:

                # get data for the dpid of this switch/router
                router_data = router_data[dpid]

                if "routes" in router_data:
                    self.routes_table[dpid] = pytricia.PyTricia()  # initialise as a pytricia tree
                    for entry in router_data["routes"]:
                        self.routes_table[dpid].insert(str(entry["destination"]), entry)
                else:
                    print("No routing-table data found for Router[{}]".format(dpid))

                if "arp" in router_data:
                    self.arp_table[dpid] = pytricia.PyTricia()  # initialise as a pytricia tree.
                    for entry in router_data["arp"]:
                        self.arp_table[dpid].insert(str(entry["ip"]), entry)
                else:
                    print("No arp-table data found for Router[{}]".format(dpid))

                if "interfaces" in router_data:
                    self.interfaces[dpid] = {}
                    for entry in router_data["interfaces"]:
                        port = entry.pop("port")
                        self.interfaces[dpid][port] = entry
                else:
                    print("No i/face data found for Router[{}]".format(dpid))
            else:
                print("No data found for Router[{0}] in {1}".format(dpid, router_data_filepath))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_handle_main(self, ev):
        """ Handles Packet In Logic """
        msg = ev.msg  # The message containing all the data needed from the openflow event
        datapath = msg.datapath  # The switch (datapath) that the event came from
        ofproto = datapath.ofproto  # OF Protocol lib to be used with the OF version on the switch
        parser = datapath.ofproto_parser  # OF Protocol Parser that matches the OpenFlow version on the switch
        dpid = dpid_lib.dpid_to_str(datapath.id)  # ID of the switch (datapath) that the event came from

        # Collect packet data
        pkt = packet.Packet(msg.data)  # The packet relating to the event (including all of its headers)
        in_port = msg.match['in_port']  # The port that the packet was received on the switch

        # Build basic (L2) match
        match_dict = {}
        eth = pkt.protocols[0]  # Lowest layer header available (ethernet)
        match_dict["in_port"] = in_port  # Add the input port into the match
        match_dict["eth_type"] = eth.ethertype  # Add ethernet type into the match
        match_dict["eth_src"] = eth.src  # Add source mc address into the match
        match_dict["eth_dst"] = eth.dst  # Add destination mac address into the match

        # Ignore ethertypes specified in filter-list, discard silently
        if match_dict["eth_type"] in self.ethertypes_filter:
            return

            # Build Advanced (L4) Match
        if match_dict["eth_type"] == ether_types.ETH_TYPE_IP:
            # For IP
            ip = pkt.protocols[1]  # Get the next header in, that, as ethertype is IP here, next header is IP
            match_dict["ip_proto"] = ip.proto
            match_dict["ipv4_src"] = ip.src
            match_dict["ipv4_dst"] = ip.dst

            if ip.proto == inet.IPPROTO_TCP:
                nw = pkt.protocols[2]
                match_dict["tcp_src"] = nw.src_port
                match_dict["tcp_dst"] = nw.dst_port

            elif ip.proto == inet.IPPROTO_UDP:
                # For UDP
                nw = pkt.protocols[2]
                match_dict["udp_src"] = nw.src_port
                match_dict["udp_dst"] = nw.dst_port

            elif ip.proto == inet.IPPROTO_ICMP:
                # For ICMP
                icmp_hdr = pkt.protocols[2]
                match_dict["icmpv4_type"] = icmp_hdr.type
                match_dict["icmpv4_code"] = icmp_hdr.code

        print()  # Will print new line for readability
        # Process this packet as a switch or as a router
        if dpid in self.switch_dpids:
            print("Your attention please, this is Switch-\"{}\" speaking".format(datapath.id))
            self.logger.info("EVENT: PACKET IN")
            self._learning_switch(msg, pkt, datapath, ofproto, parser, dpid, **match_dict)
        elif dpid in self.router_dpids:
            print("Your attention please, this is Router-\"{}\" speaking".format(datapath.id))
            self.logger.info("EVENT: PACKET IN")
            self._router(msg, pkt, datapath, ofproto, parser, dpid, **match_dict)
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                return

        return

    def packet_for_datapath(self, dpid, dst_mac, dst_ip) -> bool:
        """ Check if a Packet's Destination is this Device """
        if dpid not in self.interfaces:
            return False

        ip_exists = False

        # get the iface that this packet was received from
        for iface in self.interfaces[dpid]:
            # if destination mac address and destination ip address belongs to router, then True
            if dst_ip == self.interfaces[dpid][iface]['ip']:
                ip_exists = True

        if ip_exists:
            for iface in self.interfaces[dpid]:
                if dst_mac == self.interfaces[dpid][iface]['mac']:
                    return True
        else:
            return False

    def generate_icmp_datagram(self, dpid, iface_port, msg, pkt, icmp_type, code) -> packet.Packet():
        eth_hdr = pkt.protocols[0]  # Link-Layer header
        ip_hdr = original_ip_hdr = pkt.protocols[1]  # Network-Layer header

        iface_mac = self.interfaces[dpid][iface_port]['mac']  # The MAC address of this i/face
        iface_ip = self.interfaces[dpid][iface_port]['ip']  # The IP address of this i/face
        msg_data = msg.data  # The data from the original datagram (received)

        # Configure Link-Layer header
        eth_hdr.dst = eth_hdr.src  # The source mac address, will now be the recipient (destination mac)
        eth_hdr.src = iface_mac  # This router's i/face mac address will be the sender (source mac)

        # Configure Network-Layer header
        ip_hdr.total_length = 0  # 0 means calculate automatically while encoding
        ip_hdr.dst = ip_hdr.src  # Same as Link-Layer changes, but with IP address instead of MAC address
        ip_hdr.src = iface_ip  # Same as Link-Layer changes, but with IP address instead of MAC address
        ip_hdr.proto = inet.IPPROTO_ICMP  # proto could've been udp or tcp

        # Generate new ICMP header of type "destination unreachable"
        # Logic for construction of TTL EXCEEDED icmp header and network layer header bytes, taken from
        # https://github.com/osrg/ryu/blob/master/ryu/app/rest_router.py  (see function send_icmp())
        offset = ethernet.ethernet._MIN_LEN  # Get the header offset
        end_of_data = offset + len(original_ip_hdr) + 128
        ip_hdr_bytes = bytearray(msg_data[offset:end_of_data])  # Get IP header data of original pkt
        data_len = int(len(ip_hdr_bytes) / 4)  # Get the length of the data
        length_mod = int(len(ip_hdr_bytes) % 4)
        if length_mod:
            data_len += 1  # add 1 more, if there is remainder to avoid sending less data and therefore invalid
            ip_hdr_bytes += bytearray([0] * (4 - length_mod))  # finally get ip header bytes

        # instantiate the icmp header based on type of icmp
        if icmp_type == icmp.ICMP_DEST_UNREACH:
            icmp_hdr = icmp.icmp(
                type_=icmp_type, code=code, csum=0, data=icmp.dest_unreach(data_len=data_len, data=ip_hdr_bytes)
            )
        elif icmp_type == icmp.ICMP_ECHO_REPLY:
            original_icmp_hdr = pkt.protocols[2]
            icmp_hdr = icmp.icmp(type_=icmp_type, code=code, csum=0, data=original_icmp_hdr.data)

        elif icmp_type == icmp.ICMP_TIME_EXCEEDED:
            default_ttl = 64
            icmp_hdr = icmp.icmp(
                type_=icmp_type, code=code, csum=0, data=icmp.TimeExceeded(data_len=data_len, data=ip_hdr_bytes)
            )
            ip_total_length = ip_hdr.header_length * 4 + icmp_hdr._MIN_LEN
            ip_total_length += icmp_hdr.data._MIN_LEN
            ip_total_length += + len(icmp_hdr.data.data)

            # Generate new Network Layer header
            new_ip_hdr = ipv4.ipv4(
                header_length=ip_hdr.header_length, total_length=0, src=ip_hdr.src, dst=ip_hdr.dst, proto=ip_hdr.proto,
                tos=original_ip_hdr.tos, identification=original_ip_hdr.identification, flags=original_ip_hdr.flags,
                offset=original_ip_hdr.offset, ttl=default_ttl
            )
            p = packet.Packet()
            p.add_protocol(eth_hdr)
            p.add_protocol(new_ip_hdr)
            p.add_protocol(icmp_hdr)
            return p

        else:
            return None  # Return null for unsupported icmp packets destined to router

        # Replace headers in the packet
        pkt.protocols[0] = eth_hdr
        pkt.protocols[1] = ip_hdr
        pkt.protocols[2] = icmp_hdr

        # Return the packet containing the router's response to packet_in handler for forwarding
        return pkt

    def _router(self, msg, pkt, datapath, ofproto, parser, dpid, **match_dict):
        """ Handle Packet Routing """
        # Get invalid flows with msg.reason == ofproto.OFPR_INVALID_TTL ??
        eth = pkt.protocols[0]

        if eth.ethertype == ether_types.ETH_TYPE_IP:

            ip_hdr = pkt.protocols[1]  # IPv4 header of captured datagram

            # Was this router pinged? (L4 protocol doesn't matter, can be udp, tcp, or icmp)
            this_router_pinged = self.packet_for_datapath(dpid, eth.dst, ip_hdr.dst)
            print("dest ip: {0}, dest mac: {1}, source mac: {2}".format(ip_hdr.dst, eth.dst, eth.src))

            route_for_dst = None
            actions = None
            network_reachable = True
            host_reachable = True
            ttl_exceeded = False

            if ip_hdr.ttl <= 1:
                ttl_exceeded = True
                out_port = match_dict['in_port']  # Thou shalt return, from whence thou came!
                pkt = self.generate_icmp_datagram(
                    dpid, out_port, msg, pkt, icmp.ICMP_TIME_EXCEEDED, icmp.ICMP_TTL_EXPIRED_CODE
                )
                actions = [
                    parser.OFPActionOutput(out_port)
                ]

            elif not this_router_pinged:
                # IF PyTricia throws a keyError, then we know prefix is not in tree, ergo network is unreachable
                try:
                    route_for_dst = self.routes_table[dpid][ip_hdr.dst]
                except KeyError:
                    print("Destination Unreachable (Network Unreachable)")
                    network_reachable = False

                # If network is reachable through this router, then enter conditional body
                if network_reachable:
                    destination = None  # initialise to avoid error "might be referenced before assignment"
                    if route_for_dst['next_hop'] != "directly":
                        destination = route_for_dst['next_hop']
                    elif route_for_dst['next_hop'] == "directly":
                        destination = ip_hdr.dst

                    # Check if host exists
                    try:
                        eth.dst = self.arp_table[dpid][destination]['mac']
                    except KeyError:
                        print("Destination Unreachable (Host Unreachable)")
                        host_reachable = False

                    # If host is reachable, then edit fields appropriately
                    if host_reachable:
                        out_port = route_for_dst['out_port']  # configure the appropriate out port from routing-table
                        eth.src = self.interfaces[dpid][out_port]['mac']
                        # The action of sending a packet out converted to the correct OpenFLow format
                        actions = [
                            parser.OFPActionSetField(eth_dst=eth.dst),
                            parser.OFPActionSetField(eth_src=eth.src),
                            parser.OFPActionOutput(out_port)
                        ]

                    else:  # This will be entered if destination host is unreachable
                        # Do this if host unreachable
                        out_port = match_dict['in_port']  # Thou shalt return, from whence thou came!
                        pkt = self.generate_icmp_datagram(
                            dpid, out_port, msg, pkt, icmp.ICMP_DEST_UNREACH, icmp.ICMP_HOST_UNREACH_CODE
                        )
                        actions = [parser.OFPActionOutput(out_port)]

                else:  # this will be entered if the network prefix is unreachable
                    # Do this if network unreachable
                    out_port = match_dict['in_port']  # Thou shalt return, from whence thou came!
                    pkt = self.generate_icmp_datagram(
                        dpid, out_port, msg, pkt, icmp.ICMP_DEST_UNREACH, ICMP_NET_UNREACH_CODE
                    )
                    actions = [parser.OFPActionOutput(out_port)]

            elif this_router_pinged:
                if ip_hdr.proto == inet.IPPROTO_ICMP:
                    out_port = match_dict['in_port']  # Thou shalt return, from whence thou came!
                    pkt = self.generate_icmp_datagram(
                        dpid, out_port, msg, pkt, icmp.ICMP_ECHO_REPLY, icmp.ICMP_ECHO_REPLY_CODE
                    )
                    actions = [parser.OFPActionOutput(out_port)]

            # There is no check if the packet is ICMP_ECHO_REQUEST, because if it isn't an icmp echo request,
            # the packet that will be returned from the icmp handler will be null.
            #
            # If pkt is null after the router processes it, then drop it. (maybe add flow to drop automatically)
            if pkt is None:
                return

            # Reduce TTL by 1
            if not ttl_exceeded:
                # manually decrementing ttl is not needed. It is done as soon as OFPActionDecNwTtl() is called
                # pkt.protocols[1].ttl -= 1
                actions.insert(0, parser.OFPActionDecNwTtl())

            # Because we made changes to the packet, we need to call serialize() and then extract the serialized data
            # We send out the packet data, and not the demultiplexed packet representation.
            pkt.serialize()
            data = pkt.data

            match = parser.OFPMatch(**match_dict)

            # If network and host can be reached, then insert a flow
            if network_reachable and host_reachable and not this_router_pinged:
                # expire after 60 seconds of no action
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id, idle_timeout=60)
                print("R{0}: FLOW INSERTED FOR PROTO {1}".format(datapath.id, str(ip_hdr.proto)))

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_ANY, actions=actions, data=data)
            datapath.send_msg(out)
            return

    def _learning_switch(self, msg, pkt, datapath, ofproto, parser, dpid, **match_dict):
        """ Provide Learning Switch Functionality """

        eth = pkt.protocols[0]

        if match_dict["eth_type"] == ether_types.ETH_TYPE_ARP:
            # For ARP
            arp_hdr = pkt.protocols[1]  # Get the next header in, that, as ethertype is ARP here, next header is ARP
            match_dict["arp_sha"] = arp_hdr.src_mac
            match_dict["arp_tha"] = arp_hdr.dst_mac
            match_dict["arp_spa"] = arp_hdr.src_ip
            match_dict["arp_tpa"] = arp_hdr.dst_ip
            match_dict["arp_op"] = arp_hdr.opcode
            self.logger.info("MATCH CREATED: ARP")

        match = parser.OFPMatch(**match_dict)

        # Add the mac address to port mapping to the dict
        # The outer dict represents a mapping of switches to their mappings
        # The inner dict represents a mapping of mac addresses to ports
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = match_dict['in_port']

        # If the dst mac address has a mapping in the table, the switch should send
        # the packet out only via the port mapped
        # Else, just flood the packet to all ports
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            self.logger.info("PACKET OUT: Port %s", str(out_port))
        else:
            self.logger.info("PACKET OUT: Flooding")
            out_port = ofproto.OFPP_FLOOD

        # The action of sending a packet out converted to the correct OpenFLow format
        actions = [parser.OFPActionOutput(out_port)]

        # Install the Flow-Mod
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, 1, match, actions, idle_timeout=60)  # expire after 60 seconds of no action
            print("S{0}: FLOW INSERTED".format(datapath.id))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Although a flow-mod may have been installed, we still need to send the packet that
        # triggered the event back out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=match_dict['in_port'], actions=actions, data=data)
        datapath.send_msg(out)
        return

    @staticmethod
    def add_flow(datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        """ Install a Flow-Mod """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        act = ofproto.OFPIT_APPLY_ACTIONS

        if len(actions) == 0:
            act = ofproto.OFPIT_CLEAR_ACTIONS
        inst = [parser.OFPInstructionActions(act, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, match=match, instructions=inst,
                                    priority=priority, hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, match=match, instructions=inst, priority=priority,
                                    hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        datapath.send_msg(mod)
