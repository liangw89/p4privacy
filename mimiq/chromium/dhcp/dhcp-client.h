/*
 * From: https://github.com/incebellipipo/dhcp-cpp
*/

//
// Created by cem on 23.07.2018.
//

#ifndef DHCPCLIENT_DHCPC_H
#define DHCPCLIENT_DHCPC_H

#include <set>
#include <memory>
#include <vector>
#include <netinet/in.h>
#include <string>
#include <net/if.h>

#include "net/third_party/quiche/src/quic/dhcp/dhcp-packet.h"
//#define DEBUG_PACKET

namespace dhcp {
  typedef struct dhcp_result {

  } dhcp_result;

  class DHCPClient {
  private:
    struct in_addr requested_address_;
    struct in_addr server_address_;
    bool request_specific_address_ = false;

    char ifname_[IFNAMSIZ];
    u_int8_t hwaddr_[16];

    int listen_raw_sock_fd_;

    u_int32_t packet_xid_;

    dhcp_packet discovery_;

    dhcp_packet offer_;

    dhcp_packet request_;

    dhcp_packet acknowledge_;

    struct dhcp_packet dhcp_packet_with_headers_set();

  public:
    DHCPClient(const char *interface_name, const char *server_address);

    void setRequestSpecificAddress(decltype(request_specific_address_) val) { request_specific_address_ = val; }

    auto getRequestSpecificAddress() -> decltype(request_specific_address_) { return request_specific_address_; }

    auto get_discovery() -> decltype(discovery_) { return discovery_; }

    auto get_offer() -> decltype(offer_) { return offer_; }

    auto get_request() -> decltype(request_) { return request_; }

    auto get_acknowledge() -> decltype(acknowledge_) { return acknowledge_; }

    int do_discover();

    void listen_offer();

    int do_request(struct in_addr server, struct in_addr requested);

    int listen_acknowledgement(struct in_addr server);

    void initialize();

    void cleanup();

    static bool gather_lease(char *interface_name);
  };

  class DHCPException : public std::exception {
  protected:
    std::runtime_error msg_;
  public:
    explicit DHCPException(const char *message) : msg_(message) {}

    explicit DHCPException(const std::string &message) : msg_(message) {}

    ~DHCPException() final = default;

    const char *what() const noexcept final { return msg_.what(); }
  };

}
#endif //DHCPCLIENT_DHCPC_H
