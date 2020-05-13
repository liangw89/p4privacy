#!/usr/bin/python

from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.type_strlist import strlist
from pydhcplib.type_ipv4 import ipv4


packet = DhcpPacket()

packet.SetOption("domain_name",strlist("anemon.org").list())
packet.SetOption("router",[192,168,0,1])
packet.SetOption("time_server",[192,168,1,50,192,168,1,51])
packet.SetOption("yiaddr",[192,168,0,18])
packet.SetOption("op", )

print packet.str()