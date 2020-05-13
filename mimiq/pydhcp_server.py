 #!/usr/bin/python
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *


netopt = {'client_listen_port':"68",
           'server_listen_port':"67",
           'listen_address':"10.0.1.3"}

class Server(DhcpServer):
    def __init__(self, options):
        DhcpServer.__init__(self,options["listen_address"],
                            options["client_listen_port"],
                            options["server_listen_port"])

    def HandleDhcpDiscover(self, packet):
        print(packet.str())
    def HandleDhcpRequest(self, packet):
        print(packet.str())
    def HandleDhcpDecline(self, packet):
        print(packet.str())        
    def HandleDhcpRelease(self, packet):
        print(packet.str())        
    def HandleDhcpInform(self, packet):
        print(packet.str())


server = Server(netopt)

while True :
    server.GetNextDhcpPacket()