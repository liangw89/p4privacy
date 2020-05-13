/*
 * From: https://github.com/incebellipipo/dhcp-cpp
*/

#ifndef DHCPCLIENT_LEASE_H
#define DHCPCLIENT_LEASE_H

#include <sys/types.h>
#include "net/third_party/quiche/src/quic/dhcp/dhcp.h"
#include <vector>

#define DNS_NAME_LEN 100
namespace dhcp {
  typedef struct lease {

    char *ifname;
    struct in_addr address;
    struct in_addr subnet_mask;
    struct in_addr broadcast_addr;
    struct in_addr netmask_addr;
    struct in_addr routers; // todo why this is routers?
    u_int8_t message_type;
    struct in_addr server_identifier;
    std::vector<struct in_addr> domain_name_servers;

    time_t lease_time;
    time_t renew;
    time_t rebind;
    time_t expire; // not used yet

    bool valid = false;
  } lease;

  struct lease process_lease(struct dhcp_packet *packet);

}
#define DEFAULT_LEASE_PATH "/var/lib/dhcp-cpp/"

#endif //DHCPCLIENT_LEASE_H
