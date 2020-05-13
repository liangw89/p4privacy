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
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import custom, quietRun
from mininet.node import RemoteController,OVSSwitch
from mininet.log import setLogLevel, info, lg
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.util import run


#Topology to be instantiated in Mininet

DNSTemplate = """
    start	10.0.0.50
    end		10.0.0.60
    option	subnet	255.255.255.0
    option	domain	local
    option	lease	60  # seconds
    """
class dhcpTopo(Topo):
    "Mininet DHCP Test topology"
    
    def __init__(self, cpu=.1, max_queue_size=None, **params):
        '''
        nat+--+              +-----------+h1
              |              +-----------+h2 (evil)
              +-------+s1+---+-----------+h3
                DHC+---+     +-----------+h4
                             +-----------+h5
                             +-----------+h6
        '''
        # Initialize topo
        Topo.__init__(self, **params)
        ###Thanks to Sean Donivan for the NAT code####
        # natIP= '10.0.0.254'
        # Host and link configuration
        # hostConfig = {'cpu': cpu, 'defaultRoute': 'via ' + natIP }
        LinkConfig = {'bw': 10, 'delay': '1ms', 'loss': 0,
                   'max_queue_size': max_queue_size }
        LinkConfig2 = {'bw': 10, 'delay': '5ms', 'loss': 0,
                   'max_queue_size': max_queue_size }
        #################################################

        #add Single Switch
        s1  = self.addSwitch('s1')

        # add DHCP server with slightly longer delay
        dhcpS = self.addHost('dhcpS', ip='10.0.0.200/24')
        self.addLink(s1, dhcpS, 1, 1, **LinkConfig2)
        
        #add six hosts with no assigned IP
        h1 = self.addHost('h1', ip=None)
        self.addLink(s1, h1, 2, 1, **LinkConfig)
        
        h2 = self.addHost('h2', ip=None)
        self.addLink(s1, h2, 3, 1, **LinkConfig )
        
        # h3 = self.addHost('h3', ip=None)
        # self.addLink(s1, h3, 4, 1, **LinkConfig)
        
        # h4 = self.addHost('h4', ip=None, **hostConfig)
        # self.addLink(s1, h4, 5, 1, **LinkConfig)
        
        # h5 = self.addHost('h5', ip=None, **hostConfig)
        # self.addLink(s1, h5, 6, 1, **LinkConfig)
        
        # h6 = self.addHost('h6', ip=None, **hostConfig)
        # self.addLink(s1, h6, 7, 1, **LinkConfig)

        # Create and add NAT
        # self.nat = self.addNode( 'nat', cls=NAT, ip=natIP,
        #                     inNamespace=False)	
        # self.addLink(s1, self.nat, port1=8 )

def startWireShark(host):
    print('***Starting Wireshark...*** \n')
    host.cmd('sudo wireshark &')
    raw_input("\nPress Enter once Wireshark is capturing traffic \n")    

def makeRogueConfig( filename, intf, dns ):
    "Create a DHCP configuration file"
    
    config = (
        'interface %s' % intf, 
		DNSTemplate,
        'option router %s' % natIP,
        'option dns %s' % dns,
        '' )
    with open( filename, 'w' ) as f:
        f.write( '\n'.join( config ) )

def startRogueDHCP( host, dns ):
    "Start DHCP server on host with specified DNS server"
    print '* Starting Rogue DHCP server on ', host, 'at', dns, '\n'
    print 'host default interface ', host.defaultIntf()
    dhcpConfig = '/tmp/%s-udhcpd.conf' % host
    makeRogueConfig( dhcpConfig, host.defaultIntf(), dns )
    print host.cmd( 'udhcpd -f', dhcpConfig,
              '1>/tmp/%s-dhcp.log 2>&1  &' % host )
    print "**UDHCPD from ", dhcpConfig, " is running.**"

def stopRogueDHCP( host, dns ):
    "Stop DHCP server on host"
    print( '* Stopping DHCP server on', host, 'at', dns, '\n' )
    host.cmd( 'kill %udhcpd' )
    
# DHCP client functions
def startDHCPclient( host ):
    print "Start DHCP client on", host
    intf = host.defaultIntf()
    print 'Intf for ', host, ' is ', intf
    print host.cmd( 'dhclient -v -d -r', intf )
    print host.cmd( 'dhclient -v -d -1> /tmp/dhclient.log 2>&1', intf, '&' )

def stopDHCPclient( host ):
    host.cmd( 'kill %dhclient' )


if __name__ == '__main__':
    print('*** Starting Mininet *** \n')
    topo = dhcpTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController)
    print('*** Topology Created *** \n')
    net.start()
    run("ovs-vsctl set bridge s1 protocols=OpenFlow13")
    dhcpS, h1, h2 = net.hosts[0], net.hosts[1], net.hosts[2]
    s1 = net.switches[0]
    # s1,h3,h4 = net.switches[0], net.hosts[3], net.hosts[4]
    #startWireShark(h1)
    print('***Attempting to start dhcp server***')
    print dhcpS.cmd('sudo /etc/init.d/isc-dhcp-server start')
#    raw_input("\nPress Enter for dhcp server \n")
    #startWireShark(dhcpS)
    print('*** Assigning IP to h1 and h2 (See Wireshark) *** \n')
    # print h1.cmd('dhclient')
    # print h2.cmd('dhclient')
    startDHCPclient(h1)
    startDHCPclient(h2)
    # Now start Rogue DHCP server
    ############################################
    #print '***Starting Rogue DHCP server***'
    #serIP = h2.cmd('hostname -I')
    #startRogueDHCP( h2, serIP)
    #print '***Starting DHCP client***'
#    print h3.cmd('dhclient')
#    print h4.cmd('dhclient')
    ############################################
    print('*** Running CLI *** \n')
    CLI( net )
    # print 'Stopping Network'
    #stopRogueDHCP( h2, serIP )
    #stopDHCPclient( h3 )
    # dhcpS.cmd('sudo /etc/init.d/isc-dhcp-server stop')
    # net.stop()

# ps -A | grep controller
# sudo fuser -k 6633/tcp
# pyretic.py -v high pyretic.modules.arp
# sudo fuser -k 6633/tcp
# nmap -sS -sU -PN 10.0.1.21



"""
-d Force dhclient to run as a foreground process.
-r Tell dhclient to release the current lease it has from the server. 
-v Enable verbose log messages.
-1 Try  to  get  a  lease  once. 
"""

"""
Possible issues compare dhcpd.conf file to dhclient.conf. 
Adjust IP range for dhclient.conf and server files. 
"""      





"""
option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, domain-search, host-name,
        dhcp6.name-servers, dhcp6.domain-search,
        netbios-name-servers, netbios-scope, interface-mtu,
        rfc3442-classless-static-routes, ntp-servers,
        dhcp6.fqdn, dhcp6.sntp-servers;
"""