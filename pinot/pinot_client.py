from scapy.all import *
import netifaces
import threading
import time
import random
import string

iface_1 = "veth0"
imac_1 = netifaces.ifaddresses(iface_1)[netifaces.AF_LINK][0]['addr']

iface_2 = "veth2"
imac_2 = netifaces.ifaddresses(iface_2)[netifaces.AF_LINK][0]['addr']

mac_from = imac_1
mac_to = imac_2

iface = iface_1

def gen_ipv6_addr():
	return "".join([random.choice('abcdef' + string.digits) for i in xrange(4)])

def cli_handler(pkt):
	# pkt.show2()

	mac_from = pkt['Ethernet'].src
	mac_to = pkt['Ethernet'].dst
	ip_from = pkt['IP'].src
	ip_to = pkt['IP'].dst
	port_from = pkt['UDP'].sport
	port_to = pkt['UDP'].dport

	if port_from != 58888 and port_from != 53 and port_from != 123:
		print "not server response"
		exit()
	org_chksum_udp = pkt['UDP'].chksum
	org_chksum_ip = pkt['IP'].chksum
	del pkt['UDP'].chksum
	del pkt['IP'].chksum
	pkt = pkt.__class__(bytes(pkt))
	new_chksum_udp = pkt['UDP'].chksum
	new_chksum_ip = pkt['IP'].chksum


	if mac_from == imac_2:
		print "client receive:", ip_to, port_to, hex(org_chksum_ip), hex(new_chksum_ip), hex(org_chksum_udp), hex(new_chksum_udp)

sport = 1234

# test DNS
p = Ether(src=mac_from, dst=mac_to)/IP(src="1.2.3.1", dst="1.1.1.1")/UDP(dport=53, sport=sport)
p = sendp(p, iface=iface, verbose=False)
sniff(iface=iface, prn=cli_handler, count=1)

# test NTP
p = Ether(src=mac_from, dst=mac_to)/IP(src="1.2.3.2", dst="8.8.4.4")/UDP(dport=123, sport=sport)
p = sendp(p, iface=iface, verbose=False)
sniff(iface=iface, prn=cli_handler, count=1)

# test WireGuard
p = Ether(src=mac_from, dst=mac_to)/IP(src="1.2.3.3", dst="8.8.8.8")/UDP(dport=58888, sport=sport)
p = sendp(p, iface=iface, verbose=False)
sniff(iface=iface, prn=cli_handler, count=1)

# test random padding
for i in xrange(3):

	p = Ether(src=mac_from, dst=mac_to)/IP(src="1.2.3.4", dst="8.8.8.8")/UDP(dport=58888, sport=sport)
	# p.show2()
	p = sendp(p, iface=iface, verbose=False)
	sniff(iface=iface, prn=cli_handler, count=1)
