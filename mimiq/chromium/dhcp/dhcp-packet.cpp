/*
 * From: https://github.com/incebellipipo/dhcp-cpp
*/

//
// Created by cem on 23.07.2018.
//

#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <cerrno>
#include <arpa/inet.h>
#include <iostream>
#include <map>

#include <unistd.h>

#include <ifaddrs.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "net/third_party/quiche/src/quic/dhcp/dhcp-packet.h"
#include "net/third_party/quiche/src/quic/dhcp/dhcp-client.h"
#include <net/if.h>
#include <sys/ioctl.h>

namespace dhcp {
  std::string inAddrToString(struct in_addr iAddr) 
  {
    char str[INET_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &iAddr, str, INET_ADDRSTRLEN);
    str[INET_ADDRSTRLEN] = 0;
    std::string s(str);
    return s;
  }

  struct in_addr stringToInAddr(std::string addrString) 
  {
    struct in_addr iAddr;
    inet_pton(AF_INET, addrString.c_str(), &iAddr);
    return iAddr;
  }

  struct in_addr getIPofInterface(char *ifname)
  {
    struct ifaddrs *ifa;
    struct ifaddrs *ifaOrig;
    struct in_addr myIP;
    memset(&myIP, 0x00, sizeof(struct in_addr));

    // get interfaces
    int ret = getifaddrs(&ifa);
    if (ret != 0) {
      perror("Error getting interfaces");
    } 
    else {
      ifaOrig = ifa;
      // keep going until the last element in the interfaces array
      while (ifa != NULL) {

        if (strcmp(ifa->ifa_name, ifname) == 0) {
          myIP = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
          break;
        }

        ifa = ifa->ifa_next;
      }

      freeifaddrs(ifaOrig);
    }

    return myIP;
  }

  inline void print_packet(const u_int8_t *data, int len) {
#if defined(DEBUG_PACKET)
    for (int i = 0; i < len; i++) {
      if (i % 0x10 == 0) {
        printf("\n%04x ::\t", i);
      }
      if( i % 0x08 == 0){
        printf("   ");
      }
      printf("%02x ", data[i]);
    }
    printf("\n");
#endif
  }

  u_int32_t udp_checksum_s(char *ip, char *udp, u_int16_t length) {
    udp[6] = udp[7] = 0;
    struct udp_pseudoheader header = {};
    u_int32_t checksum = 0x0;
    memcpy((char *) &header.srcaddr, &ip[12], 4);
    memcpy((char *) &header.dstaddr, &ip[16], 4);
    header.zero = 0;
    header.protocol = IPPROTO_UDP;
    header.length = htons(length);
    auto hptr = (u_int16_t *) &header;
    for (int hlen = sizeof(header); hlen > 0; hlen -= 2) {
      checksum += *(hptr++);
    }
    auto uptr = (u_int16_t *) udp;
    for (; length > 1; length -= 2) {
      checksum += *(uptr++);
    }
    if (length) {
      checksum += *((u_int8_t *) uptr);
    }
    do {
      checksum = (checksum >> 16u) + (checksum & 0xFFFFu);
    } while (checksum != (checksum & 0xFFFFu));
    auto ans = (u_int16_t) checksum;
    return (ans == 0xFF) ? 0xFF : ntohs(~ans);
  }

/* sends a DHCP packet to specified server IP (unicast) */
  int send_dhcp_packet_to(void *buffer, int buffer_size, char *ifname, struct in_addr server_address) {

    int result = -1;
    auto buf = (char *) malloc(
            sizeof(struct ethhdr) +     // 14
            sizeof(struct iphdr) +      // 20
            sizeof(struct udphdr) +     // 8
            sizeof(struct dhcp_packet)   // 548
    );

    memcpy(&buf[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(udphdr)],
           buffer,
           (size_t) buffer_size);

    // Construction of eth header
    auto ethh = (struct ethhdr *) (buf);

    struct ifreq ifr = {};
    memset(&ifr, 0, sizeof(ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    int ifreq_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    ioctl(ifreq_sock, SIOCGIFHWADDR, &ifr);
    close(ifreq_sock);

    memset(ethh->h_dest, 0xff, IFHWADDRLEN);
    memcpy((void *) &ethh->h_source, &ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
    ethh->h_proto = htons(ETH_P_IP);

    // Construction of udp header
    auto udph = (struct udphdr *) (buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udph->source = htons(DHCP_CLIENT_PORT);
    udph->dest = htons(DHCP_SERVER_PORT);
    udph->len = htons(buffer_size + sizeof(struct udphdr));
    udph->check = 0x0;

    // find source and destination IP (0.0.0.0 to 255.255.255.255 by default)
    struct in_addr srcaddr = stringToInAddr("0.0.0.0");
    struct in_addr dstaddr = stringToInAddr("255.255.255.255");

    struct in_addr myIP = getIPofInterface(ifname);
    if (myIP.s_addr != 0) {
      srcaddr = myIP;
      dstaddr = server_address;
    }

    // Construction of ip header https://www.inetdaemon.com/tutorials/internet/ip/datagram_structure.shtml
    auto iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
    iph->version = IPVERSION;
    iph->ihl = 5;
    iph->tos = 0x10;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + buffer_size);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 0x80;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0x0;
    iph->saddr = srcaddr.s_addr;
    iph->daddr = dstaddr.s_addr;
    // inet_aton("0.0.0.0", (struct in_addr *) &iph->saddr);
    // inet_aton("255.255.255.255", (struct in_addr *) &iph->daddr);

    udph->check = htons((u_int16_t)
                                udp_checksum_s((char *) iph, (char *) udph, buffer_size + sizeof(struct udphdr)));
    iph->check = (u_int16_t)
            ip_checksum(iph);

    int total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + buffer_size;

    struct sockaddr_ll device = {};
    if ((device.sll_ifindex = if_nametoindex(ifname)) == 0) {
      std::cout << "Failed to resolve interface index: " << std::string(strerror(errno)) << std::endl;
      return -1;
      // throw DHCPException("Failed to resolve interface index: " + std::string(strerror(errno)));
    }

    int sendv4_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    result = (int) sendto(sendv4_sock, buf, (size_t) total_len, 0, (struct sockaddr *) &device, sizeof(device));

    close(sendv4_sock);

    print_packet((u_int8_t *) buf, result);

    free(buf);
    if (result < 0) {
      std::cout << "Can not send dhcp request: " << std::string(strerror(errno)) << std::endl;
      return -1;
      // throw DHCPException("Can not send dhcp request: " + std::string(strerror(errno)));
    }
    return result;
  }

/* sends a DHCP packet */
  int send_dhcp_packet(void *buffer, int buffer_size, char *ifname) {

    int result = -1;
    auto buf = (char *) malloc(
            sizeof(struct ethhdr) +     // 14
            sizeof(struct iphdr) +      // 20
            sizeof(struct udphdr) +     // 8
            sizeof(struct dhcp_packet)   // 548
    );

    memcpy(&buf[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(udphdr)],
           buffer,
           (size_t) buffer_size);

    // Construction of eth header
    auto ethh = (struct ethhdr *) (buf);

    struct ifreq ifr = {};
    memset(&ifr, 0, sizeof(ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    int ifreq_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    ioctl(ifreq_sock, SIOCGIFHWADDR, &ifr);
    close(ifreq_sock);

    memset(ethh->h_dest, 0xff, IFHWADDRLEN);
    memcpy((void *) &ethh->h_source, &ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
    ethh->h_proto = htons(ETH_P_IP);

    // Construction of udp header
    auto udph = (struct udphdr *) (buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udph->source = htons(DHCP_CLIENT_PORT);
    udph->dest = htons(DHCP_SERVER_PORT);
    udph->len = htons(buffer_size + sizeof(struct udphdr));
    udph->check = 0x0;

    // Construction of ip header https://www.inetdaemon.com/tutorials/internet/ip/datagram_structure.shtml
    auto iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
    iph->version = IPVERSION;
    iph->ihl = 5;
    iph->tos = 0x10;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + buffer_size);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 0x80;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0x0;
    inet_aton("0.0.0.0", (struct in_addr *) &iph->saddr);
    inet_aton("255.255.255.255", (struct in_addr *) &iph->daddr);

    udph->check = htons((u_int16_t)
                                udp_checksum_s((char *) iph, (char *) udph, buffer_size + sizeof(struct udphdr)));
    iph->check = (u_int16_t)
            ip_checksum(iph);

    int total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + buffer_size;

    struct sockaddr_ll device = {};
    if ((device.sll_ifindex = if_nametoindex(ifname)) == 0) {
      std::cout << "Failed to resolve interface index: " << std::string(strerror(errno)) << std::endl;
      return -1;
      // throw DHCPException("Failed to resolve interface index: " + std::string(strerror(errno)));
    }

    int sendv4_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    result = (int) sendto(sendv4_sock, buf, (size_t) total_len, 0, (struct sockaddr *) &device, sizeof(device));

    close(sendv4_sock);

    print_packet((u_int8_t *) buf, result);

    free(buf);
    if (result < 0) {
      std::cout << "Can not send dhcp request: " << std::string(strerror(errno)) << std::endl;
      return -1;
      // throw DHCPException("Can not send dhcp request: " + std::string(strerror(errno)));
    }
    return result;
  }

/* receives a DHCP packet */
  bool receive_dhcp_packet(int sock, void *packet, int packet_size, int timeout) {

    size_t max_length = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + packet_size;

    struct dhcp_packet incoming_packet = {};
    memset(&incoming_packet, 0, sizeof(incoming_packet));
    // bzero(&incoming_packet, sizeof(incoming_packet));

    u_int8_t *buf;
    buf = (u_int8_t *) malloc(max_length * 2);
    bzero(buf, max_length);

    int len = 0;
    int read_count = 0;
    for (bool valid = false; not valid and read_count < 4; valid = validate_dhcp_packet(buf, len)) {
      len = (int) recv(sock, buf, max_length, 0);
      // read_count++;
      if (len < 0) {
        std::cout << "Can not receive DHCP packet: " << std::string(strerror(errno)) << std::endl;
        return false;
        // throw DHCPException("Can not receive DHCP packet: " + std::string(strerror(errno)));
      }

      memcpy(&incoming_packet,
             &buf[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)],
             len - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
      );
    }

    print_packet(buf, (int) max_length);
    memcpy(packet, &incoming_packet, sizeof(struct dhcp_packet));
    free(buf);
    return true;
  }

  int add_dhcp_option(struct dhcp_packet *packet, u_int8_t code, u_int8_t *data, int offset, u_int8_t len) {

    packet->options[offset] = code;
    packet->options[offset + 1] = len;

    memcpy(&packet->options[offset + 2], data, len);
    return len + (sizeof(u_int8_t) * 2);
  }

  void end_dhcp_option(struct dhcp_packet *packet, int offset) {
    u_int8_t option = DHO_PAD;
    add_dhcp_option(packet, DHO_END, &option, offset, sizeof(option));
  }

  std::vector<dhcp_option> parse_dhcp_packet(struct dhcp_packet *packet) {

    std::vector<dhcp_option> options;

    if (packet == nullptr)
      return options;
    if (packet->options[0] != 0x63) {
      return options;
    } else if (packet->options[1] != 0x82) {
      return options;
    } else if (packet->options[2] != 0x53) {
      return options;
    } else if (packet->options[3] != 0x63) {
      return options;
    }

    /* process all DHCP options present in the packet */
    for (int s, x = 4; x < DHCP_MAX_OPTION_LEN; x += s) {

      /* end of options (0 is really just a pad, but bail out anyway) */
      if ((int) packet->options[x] == -1 || (int) packet->options[x] == 0) {
        break;
      }

      dhcp_option option = {};

      /* get option type */
      option.type = (u_int8_t) packet->options[x++];

      /* get option length */
      option.length = (u_int8_t) packet->options[x++];

      s = option.length;

      /* get option data */
      option.data = (u_int8_t *) malloc(option.length * sizeof(u_int8_t));

      /* Copy data to option struct */
      memcpy(option.data, (void *) &packet->options[x], option.length);

      /* Push it in the vector */
      options.push_back(option);

      if (option.type == DHO_END) {
        break;
      }
    }
#if defined(DEBUG)
    for(auto option : options){
      printf("Option, Type: %3u, Lenght: %02X, Data: ", option.type, option.length);
      for(int i = 0; i < option.length; i ++){
        printf("%02X ", option.data[i]);
      }
      printf("\n");
    }
#endif
  return options;
  }

  u_int32_t calculate_checksum(const u_int8_t *buf, int len, u_int32_t sum) {
    uint i;
    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
      sum += (u_int16_t) ntohs(*((u_int16_t *) (buf + i)));
      if (sum > 0xFFFF)
        sum -= 0xFFFF;
    }

    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < (uint) len) {
      sum += buf[i] << 8;
      if (sum > 0xFFFF)
        sum -= 0xFFFF;
    }
    return sum;
  }


  uint32_t ip_checksum(iphdr *ip_header) {
    ip_header->check = 0;
    auto sum = calculate_checksum((u_int8_t *) ip_header, ip_header->ihl * 4, 0);
    sum = ~sum & 0xFFFFu;
    return htons((u_int16_t) sum);
  }

  bool validate_dhcp_packet(u_int8_t *packet, int size) {
    struct iphdr ip_header = {};
    memset(&ip_header, 0, sizeof(ip_header));
    bzero(&ip_header, sizeof(ip_header));

    struct udphdr udp_header = {};
    memset(&udp_header, 0, sizeof(udp_header));
    bzero(&udp_header, sizeof(udp_header));

    struct dhcp_packet dhcp_p = {};
    memset(&dhcp_p, 0, sizeof(dhcp_p));
    bzero(&dhcp_p, sizeof(dhcp_p));

    memcpy(&ip_header,
           &packet[sizeof(struct ethhdr)],
           sizeof(struct iphdr)
    );

    // https://github.com/DragonFlyBSD/DragonFlyBSD/blob/master/sbin/dhclient/packet.c
    // https://gist.github.com/GreenRecycleBin/1273763

    memcpy(&udp_header,
           &packet[sizeof(struct ethhdr) + sizeof(struct iphdr)],
           sizeof(struct udphdr)
    );

    memcpy(&dhcp_p,
           &packet[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)],
           size - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
    );

    auto given_ip_checksum = ip_header.check;
    ip_header.check = 0;

    if (given_ip_checksum != ip_checksum(&ip_header)) {
      return false;
    }

    if (dhcp_p.op != BOOTREPLY) {
      return false;
    }

    if (dhcp_p.options[0] != 0x63)
      return false;
    if (dhcp_p.options[1] != 0x82)
      return false;
    if (dhcp_p.options[2] != 0x53)
      return false;
    if (dhcp_p.options[3] != 0x63)
      return false;

    return true;
  }
}