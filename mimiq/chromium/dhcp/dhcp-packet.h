/*
 * From: https://github.com/incebellipipo/dhcp-cpp
*/

//
// Created by cem on 23.07.2018.
//

#ifndef DHCPCLIENT_DHCP_REQUEST_H
#define DHCPCLIENT_DHCP_REQUEST_H

#include <cstdio>
#include <vector>

#include "net/third_party/quiche/src/quic/dhcp/dhcp.h"
#include "net/third_party/quiche/src/quic/dhcp/dhcp-client.h"

#include <netinet/ip.h>
#include <netinet/udp.h>


namespace dhcp {
/**
 * @brief UDP Pseudoheader
 */
  typedef struct udp_pseudoheader {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
  } udp_pseudoheader;

  typedef struct dhcp_option {
    u_int8_t length;
    u_int8_t type;
    u_int8_t *data;
  } dhcp_option;


/**
 * @brief Converts std::string format to in_addr format
 * @param addrString is a string of the format X.X.X.X, where each X is in [0,255]
 * @return the IP denoted by addrString as a in_addr struct
 */
struct in_addr stringToInAddr(std::string addrString);

/**
 * @brief Converts in_addr format to a std::string
 * @param iAddr is an IP address as an in_addr struct 
 * @return the IP denoted by iAddr as a string of the format X.X.X.X, where each X is in [0,255]
 */
std::string inAddrToString(struct in_addr iAddr);

/**
 * @brief Gets the IP address assigned to an interface
 * @param ifname is the name of an interface
 * @return the IP assigned to ifname, 0.0.0.0 address if not found
 */
struct in_addr getIPofInterface(char *ifname);

/**
 * @brief Prints packet just for debugging
 * @param data Data to be printed
 * @param len lenght of the data
 */
  void print_packet(const u_int8_t *data, int len);

/**
 * @brief Sends packets with specified values over socket
 * @param buffer value to send to socket
 * @param buffer_size size of the package
 * @param ifname name of the interface
 * @return Success value: -1 if fails 0 if succeed
 */
  int
  send_dhcp_packet(void *buffer, int buffer_size, char *ifname);

/**
 * @brief Sends packets with specified values over socket
 * @param buffer value to send to socket
 * @param buffer_size size of the package
 * @param ifname name of the interface
 * @param server_address address of the dhcp server
 * @return Success value: -1 if fails 0 if succeed
 */
  int
  send_dhcp_packet_to(void *buffer, int buffer_size, char *ifname, struct in_addr server_address);

/**
 * @brief Receives packet with specified values
 * \param packet to be written
 * \param packet_size buffer size to be written in buffer
 * \param sock socker file descriptor
 * \param timeout in seconds
 * \param address address to be received
 * @return Success value: -1 if fails 0 if succeed
 */
  bool receive_dhcp_packet(int sock, void *packet, int packet_size, int timeout);

/**
 * @brief Adds option to dhcp packet with given offset
 * @param packet
 * @param code
 * @param data
 * @param offset
 * @param len
 * @return
 */
  int add_dhcp_option(struct dhcp_packet *packet, u_int8_t code, u_int8_t *data, int offset, u_int8_t len);

/**
 * @brief Specialized add dhcp option function that puts end flag to end of the options
 * @param packet
 * @param offset
 */
  void end_dhcp_option(struct dhcp_packet *packet, int offset);

/**
 * @brief Checks if packet is invalid or not
 * @param packet
 * @return true if valid, else false
 */
  bool validate_dhcp_packet(u_int8_t *packet, int size);


/**
 * @brief Calculates checksum of given buffer
 * @param buf buffer to be calculated
 * @param len length of the buffer
 * @param sum pre-given sum, generally 0
 * @return sum of the buffer
 */
  u_int32_t calculate_checksum(const u_int8_t *buf, int len, u_int32_t sum);

/**
 * @brief calculates the ip header checksum
 * @param ip_header
 * @return checksum of ip header
 */
  uint32_t ip_checksum(iphdr *ip_header);

  u_int32_t udp_checksum_s(char *ip, char *udp, u_int16_t length);

/**
 * @brief Parses the packet and put it in the vector
 * @param packet pointer
 * @return objects
 */
  std::vector<dhcp_option> parse_dhcp_packet(struct dhcp_packet *packet);
}
#endif //DHCPCLIENT_DHCP_REQUEST_H
