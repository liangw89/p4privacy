import socket, struct, fcntl

SIOCSIFADDR = 0x8916
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def setIpAddr(iface, ip):
    bin_ip = socket.inet_aton(ip)
    ifreq = struct.pack('16sH2s4s8s', iface, socket.AF_INET, b'\x00\x00', bin_ip, b'\x00' * 8)
    fcntl.ioctl(sock, SIOCSIFADDR, ifreq)

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def main():
    print(getHwAddr('enp0s8'))


if __name__ == "__main__":
    main()