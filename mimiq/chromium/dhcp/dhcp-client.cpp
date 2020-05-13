/*
 * From: https://github.com/incebellipipo/dhcp-cpp
*/

//
// Created by cem on 23.07.2018.
//
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <climits>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "net/third_party/quiche/src/quic/dhcp/dhcp.h"
#include "net/third_party/quiche/src/quic/dhcp/dhcp-packet.h"
#include "net/third_party/quiche/src/quic/dhcp/dhcp-client.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

namespace dhcp {
  DHCPClient::DHCPClient(const char *interface_name, const char *server_address) {
    strncpy(ifname_, interface_name, IFNAMSIZ);
    std::string s(server_address);
    server_address_ = stringToInAddr(s);
    struct ifreq ifr = {};
    memset(&ifr, 0, sizeof(ifreq));
    strncpy(ifr.ifr_name, ifname_, IFNAMSIZ);
    int ifreq_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (ioctl(ifreq_sock, SIOCGIFHWADDR, &ifr) < 0) {
      std::cout << "Can not gather hwaddr" << std::string(strerror(errno)) << std::endl;
      // throw DHCPException("Can not gather hwaddr" + std::string(strerror(errno)));
    }
    close(ifreq_sock);

    memcpy((void *) &hwaddr_, &ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);

    std::srand((u_int32_t) std::time(nullptr));
    packet_xid_ = (u_int32_t) random();
  }

  void DHCPClient::initialize() {

    listen_raw_sock_fd_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (listen_raw_sock_fd_ < 0) {
      std::cout << "Can not create socket for DHCP: " << std::string(strerror(errno)) << std::endl;
      // throw DHCPException("Can not create socket for DHCP: " + std::string(strerror(errno)));
    }

    struct timeval timeout = {};
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    setsockopt(listen_raw_sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));


    struct ifreq ifr = {};
    memset((void *) &ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname_, IFNAMSIZ);
    setsockopt(listen_raw_sock_fd_, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr));

    std::srand((u_int32_t) std::time(nullptr));
    packet_xid_ = (u_int32_t) random();


  }

  void DHCPClient::cleanup() {
    close(listen_raw_sock_fd_);
  }

  struct dhcp_packet DHCPClient::dhcp_packet_with_headers_set() {

    struct dhcp_packet packet = {};

    // clear the packet data structure
    bzero(&packet, sizeof(packet));

    // hardware address type
    packet.htype = HTYPE_ETHER;

    // length of our hardware address
    packet.hlen = IFHWADDRLEN;

    packet.hops = 0;
    packet.xid = htonl(packet_xid_);
    packet.secs = htons(USHRT_MAX);
    packet.flags = htons(BOOTP_UNICAST);

    memcpy(packet.chaddr, hwaddr_, IFHWADDRLEN);
    return packet;
  }

/* sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers */
  int DHCPClient::do_discover() {
    discovery_ = dhcp_packet_with_headers_set();

    int offset = 0;
    discovery_.options[offset++] = 0x63;
    discovery_.options[offset++] = 0x82;
    discovery_.options[offset++] = 0x53;
    discovery_.options[offset++] = 0x63;

    u_int8_t option;

    discovery_.op = BOOTREQUEST;
    offset += add_dhcp_option(&discovery_,
                              DHO_DHCP_MESSAGE_TYPE,
                              &(option = DHCPDISCOVER),
                              offset,
                              sizeof(option)
    );

    /* the IP address we're requesting */
    if (request_specific_address_) {
      offset += add_dhcp_option(&discovery_,
                                DHO_DHCP_REQUESTED_ADDRESS,
                                (u_int8_t *) &requested_address_,
                                offset,
                                sizeof(requested_address_)
      );
    }

    char hostname[1024];
    hostname[1023] = 0x00;
    gethostname(hostname, 1023);
    offset += add_dhcp_option(&discovery_,
                              DHO_HOST_NAME,
                              (u_int8_t *) &hostname,
                              offset,
                              (u_int8_t) strlen(hostname)
    );

    u_int8_t parameter_request_list[] = {
            DHO_SUBNET_MASK,
            DHO_BROADCAST_ADDRESS,
            DHO_TIME_OFFSET,
            DHO_ROUTERS,
            DHO_DOMAIN_NAME,
            DHO_DOMAIN_NAME_SERVERS,
            DHO_HOST_NAME,
            DHO_NETBIOS_NAME_SERVERS,
            DHO_INTERFACE_MTU,
            DHO_STATIC_ROUTES,
            DHO_NTP_SERVERS,
            DHO_DHCP_RENEWAL_TIME,
            DHO_DHCP_REBINDING_TIME
    };

    offset += add_dhcp_option(&discovery_,
                              DHO_DHCP_PARAMETER_REQUEST_LIST,
                              (u_int8_t *) &parameter_request_list,
                              offset,
                              sizeof(parameter_request_list)
    );

    end_dhcp_option(&discovery_, offset);

    /* send the DHCPDISCOVER packet out */
    return send_dhcp_packet_to(&discovery_, sizeof(discovery_), ifname_, server_address_);
  }


/* waits for a DHCPOFFER message from one or more DHCP servers */
  void DHCPClient::listen_offer() {

    /* receive as many responses as we can */
    auto offer_packet = (struct dhcp_packet *) malloc(sizeof(dhcp_packet));

    memset(offer_packet, 0, sizeof(struct dhcp_packet));
    bzero(offer_packet, sizeof(struct dhcp_packet));

    receive_dhcp_packet(listen_raw_sock_fd_, offer_packet, sizeof(struct dhcp_packet), DHCP_OFFER_TIMEOUT);

    /* check packet xid to see if its the same as the one we used in the discover packet */
    if (ntohl(offer_packet->xid) != packet_xid_) {
      return;
    }

    offer_ = *offer_packet;
  }


  int DHCPClient::do_request(struct in_addr server, struct in_addr requested) {
    request_ = dhcp_packet_with_headers_set();
    struct sockaddr_in sockaddr_broadcast;

    int offset = 0;
    u_int8_t option;

    request_.options[offset++] = 0x63;
    request_.options[offset++] = 0x82;
    request_.options[offset++] = 0x53;
    request_.options[offset++] = 0x63;

    request_.op = BOOTREQUEST;

    offset += add_dhcp_option(&request_,
                              DHO_DHCP_MESSAGE_TYPE,
                              &(option = DHCPREQUEST),
                              offset,
                              sizeof(option)
    );

    /* the IP address we're requesting */
    offset += add_dhcp_option(&request_,
                              DHO_DHCP_REQUESTED_ADDRESS,
                              (u_int8_t *) &requested,
                              offset,
                              sizeof(requested)
    );


    u_int8_t client_identifier[IFHWADDRLEN];
    memcpy(client_identifier, hwaddr_, IFHWADDRLEN);
    offset += add_dhcp_option(&request_,
                              DHO_DHCP_CLIENT_IDENTIFIER,
                              (u_int8_t *) &client_identifier,
                              offset,
                              IFHWADDRLEN
    );

    /* the IP address of the server */
    offset += add_dhcp_option(&request_,
                              DHO_DHCP_SERVER_IDENTIFIER,
                              (u_int8_t *) &server,
                              offset,
                              sizeof(server)
    );

    char hostname[1024];
    hostname[1023] = 0x00;
    gethostname(hostname, 1023);
    offset += add_dhcp_option(&request_,
                              DHO_HOST_NAME,
                              (u_int8_t *) &hostname,
                              offset,
                              (u_int8_t) strlen(hostname)
    );

    u_int8_t parameter_request_list[] = {
            DHO_SUBNET_MASK,
            DHO_BROADCAST_ADDRESS,
            DHO_TIME_OFFSET,
            DHO_ROUTERS,
            DHO_DOMAIN_NAME,
            DHO_DOMAIN_NAME_SERVERS,
            DHO_HOST_NAME,
            DHO_NETBIOS_NAME_SERVERS,
            DHO_INTERFACE_MTU,
            DHO_STATIC_ROUTES,
            DHO_NTP_SERVERS,
            DHO_DHCP_RENEWAL_TIME,
            DHO_DHCP_REBINDING_TIME
    };

    offset += add_dhcp_option(&request_,
                              DHO_DHCP_PARAMETER_REQUEST_LIST,
                              (u_int8_t *) &parameter_request_list,
                              offset,
                              sizeof(parameter_request_list)
    );

    end_dhcp_option(&request_, offset);

    /* send the DHCPREQUEST packet to broadcast address */
    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPREQUEST packet out */
    send_dhcp_packet_to(&request_, sizeof(dhcp_packet), ifname_, server_address_);
    return 0;
  }

  int DHCPClient::listen_acknowledgement(struct in_addr server) {
    bool res = receive_dhcp_packet(listen_raw_sock_fd_, &acknowledge_, sizeof(dhcp_packet), DHCP_OFFER_TIMEOUT);
    if (!res) return -1;
    return 0;
  }


  // ygovil NOTE: DOES NOT WORK RIGHT NOW
  // Not required for the prototype, so disabled (haven't included leases.h or leases.cpp)
  bool DHCPClient::gather_lease(char *interface_name) {
    char server_address[20] = "255.255.255.255";
    DHCPClient dhcpClient(interface_name, server_address);

    dhcpClient.initialize();

    dhcpClient.do_discover();

    dhcpClient.listen_offer();

    auto offer = dhcpClient.get_offer();

    bool acknowledged = false;
    struct in_addr server_ip = {};
    for (auto option : parse_dhcp_packet(&offer)) {
      if (option.type == DHO_DHCP_SERVER_IDENTIFIER) {
        memcpy((void *) &server_ip, option.data, option.length);
      }
    }

    dhcpClient.do_request(server_ip, offer.yiaddr);

    dhcpClient.listen_acknowledgement(server_ip);

    auto ack_packet = dhcpClient.get_acknowledge();
    for (auto option : parse_dhcp_packet(&ack_packet)) {
      if (option.type == DHO_DHCP_MESSAGE_TYPE) {
        if (*option.data == DHCPACK) {
          // l = process_lease(&ack_packet);
          acknowledged = true;
        } else if (*option.data == DHCPNAK) {
          // l = process_lease(&ack_packet);
          continue;
        }
      }
    }

    dhcpClient.cleanup();

    if (acknowledged) {
      // *ls = l;
      return true;
    } else {
      return false;
    }
  }
}