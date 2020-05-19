from scapy.all import *
import netifaces

iface = "veth2"
imac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']

def handler(pkt):
	try:
		# pkt.show2()
		mac_from = pkt['Ethernet'].src
		mac_to = pkt['Ethernet'].dst
		ip_from = pkt['IPv6'].src
		ip_to = pkt['IPv6'].dst
		port_from = pkt['UDP'].sport
		port_to = pkt['UDP'].dport

		# ipv6 does not have checksum
		org_chksum_udp = pkt['UDP'].chksum
		del pkt['UDP'].chksum
		pkt = pkt.__class__(bytes(pkt))
		new_chksum_udp = pkt['UDP'].chksum

		
		if mac_to == imac:
			# pkt.show2()
			print "server receive:", ip_from, ip_to, port_from, port_to, hex(org_chksum_udp), hex(new_chksum_udp)
			sendp(Ether(src=mac_to, dst=mac_from)/IPv6(src=ip_to, dst=ip_from)/UDP(dport=port_from, sport=port_to), iface=iface, verbose=False)
			print "server send:", ip_to, ip_from
	except Exception as e:
		print str(e)

sniff(iface=iface, prn=handler)