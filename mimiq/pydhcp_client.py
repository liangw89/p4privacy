#!/usr/bin/python
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *
# from pydhcplib.interface import *
from interface_tools import *
from time import sleep

netopt = {'client_listen_port':68,
       'server_listen_port':67,
       'listen_address':"host-eth0"}


class Client(DhcpClient):
    def __init__(self, options):
         DhcpClient.__init__(self,options["listen_address"],
                        options["client_listen_port"],
                        options["server_listen_port"])

    def HandleDhcpOffer(self, packet):
        print(packet.str())
    def HandleDhcpAck(self, packet):
        print(packet.str())
    def HandleDhcpNack(self, packet):
        print(packet.str())

client = Client(netopt)
# Use BindToAddress if you want to emit/listen to an internet address (like 192.168.1.1)
# or BindToDevice if you want to emit/listen to a network device (like eth0)
client.BindToDevice()

counter = False

while True :
    print("1")
    if counter:
        setIpAddr('host-eth0', '10.0.1.15')
        counter = not counter
    else:
        setIpAddr('host-eth0', '10.0.1.16')
        counter = not counter

    # packet = DhcpPacket()
    # packet.SetOption("dhcp_message_type", [DHCP_DISCOVER_OPTION])
    
    # client.SendDhcpPacketTo(packet, '10.0.1.3', 67)

    # print(client.GetNextDhcpPacket())
    sleep(2.5)
    