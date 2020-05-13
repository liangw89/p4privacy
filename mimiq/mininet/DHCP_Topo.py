###################################################
#!/usr/bin/python
# author: Jacob Cox
# DHCP_Min.py
# date 2 Sept 2015
# modified for RyureticLabs: 19 Dec 2016
###################################################
"""How To Run This Program """
###################################################
"""
This program sets up a mininet architecture consisting of one NAT router,
one switch, one dhcp server, and 6 hosts. IPs are only assigned to the
NAT router and the DHCP server. Hosts are not assigned IPs until a dhclient
request is made to obtain IPS from the DHCP server.
"""
#Program requirements
"""
This program requires that Pyretic, Wireshark, and DHCP server already
be installed on Mininet
"""
#Instructions:
"""
Before Running: 
1) Install DHCP Server:
    a) Open terminal, type ifconfig, record eth0 address
    b) enter: sudo apt-get update
    c) enter: sudo apt-get install isc-dhcp-server
    d) accept defaults
2) Modify dhcp.conf file:
    a) enter nano -w /etc/dhcp/dhcpd.conf
    b) Place the below lines of code into the file
    --------------------------------------------------------
    # A slightly different configuration for an internal subnet.
    subnet 10.0.1.0 netmask 255.255.255.0 {
      range 10.0.1.10 10.0.1.30;
      option domain-name-servers 10.0.1.223, 8.8.4.4;
    #  option domain-name "internal.example.org";
      option routers 10.0.1.222;
      option broadcast-address 10.0.1.255;
      default-lease-time 600;
      max-lease-time 7200;
    }
    --------------------------------------------------------
"""

"""
In Terminal 1: 
type: cd ryu
type: PYTHONPATH=. ./bin/ryu-manager ryu/app/Ryuretic/Ryuretic_Intf.py
In Terminal 2: 
type: sudo python mininet/examples/Ryuretic/DHCP_Topo.py
"""


"""
3) Open second terminal:
    a) type: cd pyretic/pyretic/modules
    b) type: sudo fuser -k 6633/tcp
    c) type: pyretic.py -v high pyretic.modules.mac_learner
    d) pyretic controller is now running
4) In the first terminal:
    a) type: cd ~
    b) type: sudo mn -c
    c) type: sudo python evilDHCP4NetTator.py
    d) This will build your topology, activate your dhcp server,
       initializes wireshark, and waits for user to configure
       wireshark (select ok, ok, dhcp1-eth0, start)
    e) hit enter.
    f) Program runs dhclient on h1 and h2. Wireshark and Terminal
       2 will display dhcp client requests, arps, etc.
    g) test network with commands and observe terminal 2 & wireshark
        1] h1 ping -c2 h2
        2] h3 ifconfig
        3] h3 dhclient ifconfig h3
        4] h3 ifconfig
        5] h2 wget themilpost.com
        6] h1 nmap -sU -p 67 --script=dhcp-discover 10.0.1.10-250
    h) Check dhcp server leases
        1] type xterm dhcp1
        2} in xterm type: sudo tail /var/lib/dhcp/dhcpd.leases
5) To shutdown:
    a) In terminal 2, hit cntl+c (exit pyretic controller)
    b) In terminal 1, type exit
    c) In terminal 1, type sudo mn -c
"""

from mininet.topo import Topo

#Topology to be instantiated in Mininet

class dhcpTopo(Topo):
    "Mininet DHCP Test topology"
    
    def __init__(self, cpu=.1, max_queue_size=None, **params):
        '''
          +---------------+host
        s1+----DHCP
          +---------------+serv
        '''
        # Initialize topo
        Topo.__init__(self, **params)
        ###Thanks to Sean Donivan for the NAT code####
        LinkConfig = {'delay': '1ms',
                   'max_queue_size': max_queue_size }
        LinkConfig2 = {'delay': '5ms',
                   'max_queue_size': max_queue_size }
        #################################################

        #add Single Switch
        s1  = self.addSwitch('s1')

        # add DHCP server with slightly longer delay
        dhcp = self.addHost('dhcp', ip='10.0.1.200/24')
        self.addLink(s1, dhcp)
        
        #add one hosts with no assigned IP and 1 with assigned
        host = self.addHost('host', ip='10.0.1.4')
        self.addLink(s1, host)
        
        host2 = self.addHost('host2', ip='10.0.1.5')
        self.addLink(s1, host2)
        
        host3 = self.addHost('host3', ip='10.0.1.6')
        self.addLink(s1, host3)
        
        host4 = self.addHost('host4', ip='10.0.1.7')
        self.addLink(s1, host4)

        host5 = self.addHost('host5', ip='10.0.1.8')
        self.addLink(s1, host5)
        
        serv = self.addHost('serv', ip='10.0.1.3')
        self.addLink(s1, serv)

topos = { 'mytopo': ( lambda: dhcpTopo() ) }
