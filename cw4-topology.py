#!/usr/bin/python

"""
Mininet Topology for SCC365 CW4 (Router)

Run with root!
$ sudo python cw4-topology.py
"""

from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import RemoteController


class RouterTopo(Topo):
    def __init__(self):
        """ Create Topology """
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Add switches
        s1 = self.addSwitch('s1', dpid='0000000000000001')
        s2 = self.addSwitch('s2', dpid='0000000000000004')

        # Add routers
        r1 = self.addSwitch('r1', dpid='0000000000000002')
        r2 = self.addSwitch('r2', dpid='0000000000000003')

        # Add links to first switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)

        # Add links to second switch
        self.addLink(h3, s2)
        self.addLink(h4, s2)

        # Add links from switch1 to router1, from router1 to router2 and from router2 to switch2
        self.addLink(s1, r1)
        self.addLink(s2, r2)
        self.addLink(r1, r2)


def run():
    """ Configure Network and Run Mininet """
    topo = RouterTopo()
    net = Mininet(topo=topo, controller=RemoteController)

    # Subnet 10.0.0.0/24 (not routers)
    h1 = net.get('h1')
    h1.intf('h1-eth0').setIP('10.0.0.10', 24)
    h1.intf('h1-eth0').setMAC('00:00:00:00:00:10')

    h2 = net.get('h2')
    h2.intf('h2-eth0').setIP('10.0.0.20', 24)
    h2.intf('h2-eth0').setMAC('00:00:00:00:00:20')

    s1 = net.get('s1')
    s1.intf('s1-eth1').setMAC('00:00:00:00:00:02')
    s1.intf('s1-eth2').setMAC('00:00:00:00:00:03')
    s1.intf('s1-eth3').setMAC('00:00:00:00:00:04')

    # Subnet 10.0.2.0/24 (not routers)
    h3 = net.get('h3')
    h3.intf('h3-eth0').setIP('10.0.2.10', 24)
    h3.intf('h3-eth0').setMAC('00:00:00:00:02:10')

    h4 = net.get('h4')
    h4.intf('h4-eth0').setIP('10.0.2.20', 24)
    h4.intf('h4-eth0').setMAC('00:00:00:00:02:20')

    s2 = net.get('s2')
    s2.intf('s2-eth1').setMAC('00:00:00:00:02:02')
    s2.intf('s2-eth2').setMAC('00:00:00:00:02:03')
    s2.intf('s2-eth3').setMAC('00:00:00:00:02:04')

    # Routers
    r1 = net.get('r1')
    r1.intf('r1-eth1').setMAC('00:00:00:00:00:01')
    r1.intf('r1-eth2').setMAC('00:00:00:00:01:01')

    r2 = net.get('r2')
    r2.intf('r2-eth1').setMAC('00:00:00:00:02:01')
    r2.intf('r2-eth2').setMAC('00:00:00:00:01:02')

    net.start()

    net.get('h1').cmd('route add default gw 10.0.0.1 h1-eth0; arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h2').cmd('route add default gw 10.0.0.1 h2-eth0; arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h3').cmd('route add default gw 10.0.2.1 h3-eth0; arp -s 10.0.2.1 00:00:00:00:02:01')
    net.get('h4').cmd('route add default gw 10.0.2.1 h4-eth0; arp -s 10.0.2.1 00:00:00:00:02:01')

    CLI(net)  # Run mininet cli

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
