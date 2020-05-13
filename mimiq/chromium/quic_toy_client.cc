// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
// Standard request/response:
//   quic_client www.google.com
//   quic_client www.google.com --quiet
//   quic_client www.google.com --port=443
//
// Use a specific version:
//   quic_client www.google.com --quic_version=23
//
// Send a POST instead of a GET:
//   quic_client www.google.com --body="this is a POST body"
//
// Append additional headers to the request:
//   quic_client www.google.com --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   quic_client mail.google.com --host=www.google.com
//
// Connect to a specific IP:
//   IP=`dig www.google.com +short | head -1`
//   quic_client www.google.com --host=${IP}
//
// Send repeated requests and change ephemeral port between requests
//   quic_client www.google.com --num_requests=10
//
// Try to connect to a host which does not speak QUIC:
//   quic_client www.example.com
//
// This tool is available as a built binary at:
// /google/data/ro/teams/quic/tools/quic_client
// After submitting changes to this file, you will need to follow the
// instructions at go/quic_client_binary_update

#define QUIC_TOY_CLIENT_MAX_BODY_CHARS 1800

#include "net/third_party/quiche/src/quic/tools/quic_toy_client.h"

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <thread>
#include <chrono>

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/types.h>
#include <ifaddrs.h>

#include "net/third_party/quiche/src/quic/dhcp/dhcp.h"
#include "net/third_party/quiche/src/quic/dhcp/lease.h"
#include "net/third_party/quiche/src/quic/dhcp/dhcp-packet.h"
#include "net/third_party/quiche/src/quic/dhcp/dhcp-client.h"

#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quiche/src/quic/tools/fake_proof_verifier.h"
#include "net/third_party/quiche/src/quic/tools/quic_url.h"

namespace {

using quic::QuicStringPiece;
using quic::QuicTextUtils;
using quic::QuicUrl;

}  // namespace


DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    host,
    "",
    "The IP or hostname to connect to. If not provided, the host "
    "will be derived from the provided URL.");

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t, port, 0, "The port to connect to.");

DEFINE_QUIC_COMMAND_LINE_FLAG(std::string,
                              body,
                              "",
                              "If set, send a POST with this body.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    body_hex,
    "",
    "If set, contents are converted from hex to ascii, before "
    "sending as body of a POST. e.g. --body_hex=\"68656c6c6f\"");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    headers,
    "",
    "A semicolon separated list of key:value pairs to "
    "add to request headers.");

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              quiet,
                              false,
                              "Set to true for a quieter output experience.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    quic_version,
    "",
    "QUIC version to speak, e.g. 21. If not set, then all available "
    "versions are offered in the handshake. Also supports wire versions "
    "such as Q043 or T099.");

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              quic_ietf_draft,
                              false,
                              "Use the IETF draft version. This also enables "
                              "required internal QUIC flags.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    version_mismatch_ok,
    false,
    "If true, a version mismatch in the handshake is not considered a "
    "failure. Useful for probing a server to determine if it speaks "
    "any version of QUIC.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    force_version_negotiation,
    false,
    "If true, start by proposing a version that is reserved for version "
    "negotiation.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    redirect_is_success,
    true,
    "If true, an HTTP response code of 3xx is considered to be a "
    "successful response, otherwise a failure.");

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t,
                              initial_mtu,
                              0,
                              "Initial MTU of the connection.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    int32_t,
    num_requests,
    1,
    "How many sequential requests to make on a single connection.");

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              disable_certificate_verification,
                              false,
                              "If true, don't verify the server certificate.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    drop_response_body,
    false,
    "If true, drop response body immediately after it is received.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    disable_port_changes,
    false,
    "If true, do not change local port after each request.");

namespace quic {

QuicToyClient::QuicToyClient(ClientFactory* client_factory)
    : client_factory_(client_factory) {}

std::string QuicToyClient::getInterfaceName() 
{ 
  struct ifaddrs *ifa;
  struct ifaddrs *ifaOrig;
  char interfaceName[32] = "host-eth0";
  char lo[8] = "lo";
  
  // get interfaces
  int ret = getifaddrs(&ifa);
  if (ret != 0) {
    perror("Error getting interfaces");
  } 
  else {
    ifaOrig = ifa;
    // keep going until the last element in the interfaces array
    while (ifa != NULL) {
      std::cout << ifa->ifa_name << std::endl;

      if (strcmp(ifa->ifa_name, lo) != 0) {
        strcpy(interfaceName, ifa->ifa_name);
        break;
      }

      ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaOrig);
  }

  std::string s(interfaceName);
  return s;
}

void QuicToyClient::getNewIPv4(std::string interfaceName, std::string dhcpAddress, struct in_addr *oldIp)
{
  std::cout << "\nGetting new IP address..." << std::endl;
  dhcp::DHCPClient dhcpClient(interfaceName.c_str(), dhcpAddress.c_str());
  while (1) {
    struct in_addr newIp;
    dhcp::lease l;

    dhcpClient.initialize();

    // do first discover
    std::cout << "\nSending DHCP Discover request to " << dhcpAddress << "...";
    dhcpClient.do_discover();
    dhcpClient.listen_offer();

    bool acknowledged = false;
    auto offer = dhcpClient.get_offer();
    struct in_addr server_ip = {};
    for (auto option : dhcp::parse_dhcp_packet(&offer)) {
      if (option.type == DHO_DHCP_SERVER_IDENTIFIER) {
        memcpy((void *) &server_ip, option.data, option.length);
      }
    }
    std::cout << "\nReceived offer from " << dhcp::inAddrToString(server_ip) << "...";

    // confirm that can use this IP
    dhcpClient.do_request(server_ip, offer.yiaddr);
    std::cout << "\nSent Request to " << dhcp::inAddrToString(server_ip) << "...";
    int res = dhcpClient.listen_acknowledgement(server_ip);
    std::cout << "\nGet response from " << dhcp::inAddrToString(server_ip) << "...";

    if (res != 0) {
      std::cout << "\nReturn val of listen is non-zero...";
      dhcpClient.cleanup();
      continue;
    }

    auto ack_packet = dhcpClient.get_acknowledge();
    for (auto option : dhcp::parse_dhcp_packet(&ack_packet)) {
      if (option.type == DHO_DHCP_MESSAGE_TYPE) {
        if (*option.data == DHCPACK) {
          l = dhcp::process_lease(&ack_packet);
          acknowledged = true;
        } else if (*option.data == DHCPNAK) {
          l = dhcp::process_lease(&ack_packet);
          // break;
        }
      }
    }

    dhcpClient.cleanup();

    // if haven't received acknowledgement, try again
    if (!acknowledged) {
      std::cout << "\nNot acknowledged from " << dhcp::inAddrToString(server_ip) << "...";
      continue;
    }

    newIp = l.address;
    std::string netmask = "255.255.255.0";

    if (oldIp == 0) {
      // call setIpv4
      setIPv4(interfaceName, dhcp::inAddrToString(l.address), dhcp::inAddrToString(l.routers), netmask);
      break;
    }
    
    // if no old IP address, set IP and break
    if (oldIp->s_addr == 0) {
      // call setIpv4
      setIPv4(interfaceName, dhcp::inAddrToString(l.address), dhcp::inAddrToString(l.routers), netmask);
      oldIp->s_addr = newIp.s_addr;
      break;
    }

    // If new IP is different from old IP, set IP and break
    if (oldIp->s_addr != newIp.s_addr) {
      // call setIpv4
      setIPv4(interfaceName, dhcp::inAddrToString(l.address), dhcp::inAddrToString(l.routers), netmask);
      oldIp->s_addr = newIp.s_addr;
      break;
    }
    
    std::cout << "\nNew IP address " << dhcp::inAddrToString(newIp) << " is same as old...\n";
  }

  return;
}

void QuicToyClient::setIPv4(std::string interfaceName, std::string ip0, std::string gw0, std::string netmask0)
{
	char cmd[256];
	//network interface
	const char * nwkInf = interfaceName.c_str();
  const char * ip = ip0.c_str();
  // const char * gw = gw0.c_str();
  const char * netmask = netmask0.c_str();

	//link down command in Linux
	sprintf(cmd,"ip link set %s down",nwkInf);
	system(cmd); 
	
	
	memset(cmd,0x00,128);
	//command to set ip address, netmask
	sprintf(cmd,"ifconfig %s %s netmask %s",nwkInf,ip,netmask);
	system(cmd);	 
	printf("\ncmd : %s\n",cmd); fflush(stdout);
	memset(cmd,0X00,128);

	//command to set gateway
	// sprintf(cmd,"route add default gw %s %s",gw,nwkInf);
	// system(cmd); 

	memset(cmd,0X00,128);
	//link up command
	sprintf(cmd,"ip link set %s up",nwkInf);
	system(cmd); 
	
}

int QuicToyClient::SendRequestsAndPrintResponses(
    std::vector<std::string> urls) {
  QuicUrl url(urls[0], "https");
  std::string host = GetQuicFlag(FLAGS_host);
  if (host.empty()) {
    host = url.host();
  }
  int port = GetQuicFlag(FLAGS_port);
  if (port == 0) {
    port = url.port();
  }

  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

  std::string quic_version_string = GetQuicFlag(FLAGS_quic_version);
  if (GetQuicFlag(FLAGS_quic_ietf_draft)) {
    quic::QuicVersionInitializeSupportForIetfDraft();
    versions = {{quic::PROTOCOL_TLS1_3, quic::QUIC_VERSION_99}};
    quic::QuicEnableVersion(versions[0]);

  } else if (!quic_version_string.empty()) {
    if (quic_version_string[0] == 'T') {
      // ParseQuicVersionString checks quic_supports_tls_handshake.
      SetQuicReloadableFlag(quic_supports_tls_handshake, true);
    }
    quic::ParsedQuicVersion parsed_quic_version =
        quic::ParseQuicVersionString(quic_version_string);
    if (parsed_quic_version.transport_version ==
        quic::QUIC_VERSION_UNSUPPORTED) {
      return 1;
    }
    versions = {parsed_quic_version};
    quic::QuicEnableVersion(parsed_quic_version);
  }

  if (GetQuicFlag(FLAGS_force_version_negotiation)) {
    versions.insert(versions.begin(),
                    quic::QuicVersionReservedForNegotiation());
  }

  const int32_t num_requests(GetQuicFlag(FLAGS_num_requests));
  std::unique_ptr<quic::ProofVerifier> proof_verifier;
  if (GetQuicFlag(FLAGS_disable_certificate_verification)) {
    proof_verifier = std::make_unique<FakeProofVerifier>();
  } else {
    proof_verifier = quic::CreateDefaultProofVerifier(url.host());
  }

  // Build the client, and try to connect.
  std::unique_ptr<QuicSpdyClientBase> client = client_factory_->CreateClient(
      url.host(), host, port, versions, std::move(proof_verifier));

  if (client == nullptr) {
    std::cerr << "Failed to create client." << std::endl;
    return 1;
  }

  int32_t initial_mtu = GetQuicFlag(FLAGS_initial_mtu);
  client->set_initial_max_packet_length(
      initial_mtu != 0 ? initial_mtu : quic::kDefaultMaxPacketSize);
  client->set_drop_response_body(GetQuicFlag(FLAGS_drop_response_body));
  if (!client->Initialize()) {
    std::cerr << "Failed to initialize client." << std::endl;
    return 1;
  }
  if (!client->Connect()) {
    quic::QuicErrorCode error = client->session()->error();
    if (error == quic::QUIC_INVALID_VERSION) {
      std::cerr << "Server talks QUIC, but none of the versions supported by "
                << "this client: " << ParsedQuicVersionVectorToString(versions)
                << std::endl;
      // 0: No error.
      // 20: Failed to connect due to QUIC_INVALID_VERSION.
      return GetQuicFlag(FLAGS_version_mismatch_ok) ? 0 : 20;
    }
    std::cerr << "Failed to connect to " << host << ":" << port
              << ". Error: " << quic::QuicErrorCodeToString(error) << std::endl;
    return 1;
  }
  std::cerr << "Connected to " << host << ":" << port << std::endl;

  // Construct the string body from flags, if provided.
  std::string body = GetQuicFlag(FLAGS_body);
  if (!GetQuicFlag(FLAGS_body_hex).empty()) {
    DCHECK(GetQuicFlag(FLAGS_body).empty())
        << "Only set one of --body and --body_hex.";
    body = QuicTextUtils::HexDecode(GetQuicFlag(FLAGS_body_hex));
  }

  // Construct a GET or POST request for supplied URL.
  spdy::SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.HostPort();
  header_block[":path"] = url.PathParamsQuery();

  // Append any additional headers supplied on the command line.
  const std::string headers = GetQuicFlag(FLAGS_headers);
  for (QuicStringPiece sp : QuicTextUtils::Split(headers, ';')) {
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<QuicStringPiece> kv = QuicTextUtils::Split(sp, ':');
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client->set_store_response(true);

  // std::string ip1 = "10.0.1.15";
  // std::string ip2 = "10.0.1.16";
  // std::string gw = "192.168.10.1";
  // std::string nmask = "255.0.0.0";
  std::string dhcpAddress = "10.0.1.200";
  std::string interfaceName = getInterfaceName();
  struct in_addr ipAddr;
  memset(&ipAddr, 0x00, sizeof(struct in_addr));
  for (int i = 0; i < num_requests; ++i) {
    std::cout << "Starting request number " << i << std::endl;
    std::cout << "----------------------------" << std::endl;
    // Send the request.
    client->SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);

    // Print request and response details.
    if (!GetQuicFlag(FLAGS_quiet)) {
      std::cout << "Request:" << std::endl;
      std::cout << "headers:" << header_block.DebugString();
      if (!GetQuicFlag(FLAGS_body_hex).empty()) {
        // Print the user provided hex, rather than binary body.
        std::cout << "body:\n"
                  << QuicTextUtils::HexDump(
                         QuicTextUtils::HexDecode(GetQuicFlag(FLAGS_body_hex)))
                  << std::endl;
      } else {
        std::cout << "body: " << body << std::endl;
      }
      std::cout << std::endl;

      if (!client->preliminary_response_headers().empty()) {
        std::cout << "Preliminary response headers: "
                  << client->preliminary_response_headers() << std::endl;
        std::cout << std::endl;
      }

      std::cout << "Response:" << std::endl;
      std::cout << "headers: " << client->latest_response_headers()
                << std::endl;
      std::string response_body = client->latest_response_body();
      if (QUIC_TOY_CLIENT_MAX_BODY_CHARS > 0 && response_body.length() > QUIC_TOY_CLIENT_MAX_BODY_CHARS)
        response_body = response_body.substr(0, QUIC_TOY_CLIENT_MAX_BODY_CHARS) 
          + "\n-------- Some content truncated for printing --------\n";
      if (!GetQuicFlag(FLAGS_body_hex).empty()) {
        // Assume response is binary data.
        std::cout << "body:\n"
                  << QuicTextUtils::HexDump(response_body) << std::endl;
      } else {
        std::cout << "body: " << response_body << std::endl;
      }
      std::cout << "trailers: " << client->latest_response_trailers()
                << std::endl;
    }

    if (!client->connected()) {
      std::cerr << "Request caused connection failure. Error: "
                << quic::QuicErrorCodeToString(client->session()->error())
                << std::endl;
      return 1;
    }

    int response_code = client->latest_response_code();
    if (response_code >= 200 && response_code < 300) {
      std::cout << "Request succeeded (" << response_code << ")." << std::endl;
    } else if (response_code >= 300 && response_code < 400) {
      if (GetQuicFlag(FLAGS_redirect_is_success)) {
        std::cout << "Request succeeded (redirect " << response_code << ")."
                  << std::endl;
      } else {
        std::cout << "Request failed (redirect " << response_code << ")."
                  << std::endl;
        return 1;
      }
    } else {
      std::cout << "Request failed (" << response_code << ")." << std::endl;
      return 1;
    }

    // Change the ephemeral port if there are more requests to do.
    if (!GetQuicFlag(FLAGS_disable_port_changes) && i + 1 < num_requests) {

      std::cout << "Sleeping for about two seconds before next request..." << std::endl << std::endl;
      std::this_thread::sleep_for(std::chrono::milliseconds(2200));

      getNewIPv4(interfaceName, dhcpAddress, &ipAddr);

      if (!client->ChangeEphemeralPort()) {
        std::cerr << "Failed to change ephemeral port." << std::endl;
        return 1;
      }
    }
  }

  return 0;
}

}  // namespace quic
