// save for copyright

#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

const bit<4> VERSION_IPV4 = 0x4;
const bit<4> VERSION_IPV6 = 0x6;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
//const bit<64> NET_PREFIX = 64w0xf;
//const bit<32> SUB_NET = 32w0x1111fff0;
//const bit<64> NET_PREFIX = 64w0x262000c400000ff1;
//const bit<64> NET_PREFIX = 64w0x262000c4000000fe;
const bit<64> NET_PREFIX = 64w0x262000c4000000f1;
const bit<32> SUB_NET = 32w0x00000000;



header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<64> src_prex;
    bit<32> src_sub; // for random padding
    bit<32> src_addr; 
    bit<64> dst_prex;
    bit<32> dst_sub;
    bit<32> dst_addr;
    
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header dummy_h {
    bit<16> chksum_udp4;
    bit<16> chksum_udp6;
}

@pa_no_overlay("ingress", "ipv4.src_addr")
@pa_no_overlay("ingress", "ipv4.dst_addr")
@pa_no_overlay("ingress", "ipv6.src_addr")
@pa_no_overlay("ingress", "ipv6.src_sub")
@pa_no_overlay("ingress", "udp.src_port")
@pa_no_overlay("ingress", "udp.dst_port")

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    dummy_h dummy;
}

struct eg_metadata_t {
    bit<32> otp1;
    bit<30> nonce_a;
    bit<10> nonce1;
    bit<10> nonce2;
    bit<10> nonce3;
    bit<2> cur_ver;
    bit<16> chksum_udp;
    bool is_enc;
    bool is_dec;

    
}

@pa_container_size("ingress", "ig_md.new_ip", 32)
@pa_container_size("ingress", "hdr.ipv6.src_sub", 32)
@pa_no_overlay("ingress", "ig_md.c1")
@pa_no_overlay("ingress", "ig_md.c2")
@pa_no_overlay("ingress", "ig_md.c3")
@pa_no_overlay("ingress", "ig_md.c4")
@pa_no_overlay("ingress", "ig_md.r1")
@pa_no_overlay("ingress", "ig_md.r2")
@pa_no_overlay("ingress", "ig_md.r3")
@pa_no_overlay("ingress", "ig_md.r4")
struct ig_metadata_t {
    bit<64> otp1;
    bit<64> otp2;
    bit<30> nonce_a;
    
    bit<2> cur_ver;

    bit<8> c1; 
    bit<8> c2;
    bit<8> c3;
    bit<8> c4;

    bit<8> r1;
    bit<8> r2;
    bit<8> r3;
    bit<8> r4;

    bit<32> new_ip;
    bit<32> new_rnd;
    bit<32> new_rnd1;
    bit<32> rnd; 

    bit<32> new_ip1;
    bit<32> new_ip2;
    bit<16> chksum_udp4;
    bit<16> chksum_udp6;
    bool is_enc;
    bool is_set_sub;
    bool is_dec;
}



parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.advance(64); 
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  // tofino 1 port metadata size
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

#if __p4c_major__ < 9
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) udp_csum4;
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) udp_csum6;
#else
    Checksum() udp_csum4;
    Checksum() udp_csum6;
#endif

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_IPV4 : parse_ipv4;
            0x1: parse_dummy;
            default : accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        // follow tofino example to incrementally update udp checksum
        udp_csum4.subtract({hdr.ipv4.src_addr, hdr.ipv4.dst_addr}); 

        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp4;
            default : accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        udp_csum6.subtract({hdr.ipv6.src_prex, hdr.ipv6.src_sub, hdr.ipv6.src_addr, 
            hdr.ipv6.dst_prex, hdr.ipv6.dst_sub, hdr.ipv6.dst_addr});
        
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_UDP: parse_udp6;
            default: accept;
        }
    }
    
    state parse_dummy {
        pkt.extract(hdr.dummy);
        transition accept;
    }


    state parse_udp4 {
        pkt.extract(hdr.udp);
        udp_csum4.subtract({hdr.udp.checksum, hdr.udp.src_port});
        ig_md.chksum_udp4 = udp_csum4.get();
        // hdr.dummy.chksum_udp4 = ig_md.chksum_udp4;

        transition select(hdr.udp.dst_port) {
            // handle dns, ntp, wireguard query
            0x35: set_enc;
            0x07b: set_enc;
            0xe608: set_enc;
            default: accept;
        }
    }

    state parse_udp6 {
        pkt.extract(hdr.udp);
        udp_csum6.subtract({hdr.udp.checksum, hdr.udp.dst_port});
        ig_md.chksum_udp6 = udp_csum6.get();
        // hdr.dummy.chksum_udp6 = ig_md.chksum_udp6;
        
        transition select(hdr.udp.src_port) {
           
            0x35: set_dec;
            0x07b: set_dec;
            0xe608: set_dec;
            default: accept;
        }
    }

    state set_enc {
        ig_md.is_enc = true;
        ig_md.is_dec = false;
        transition accept;
    }

    state set_dec {
        ig_md.is_enc = false;
        ig_md.is_dec = true;
        transition accept;
    }



}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    
#if __p4c_major__ < 9    
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) udp_csum4;
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) udp_csum6;
#else
    Checksum() udp_csum4;
    Checksum() udp_csum6;
#endif

    apply {

        if (hdr.ipv6.isValid()) {
            
            hdr.udp.checksum = udp_csum4.update({
                hdr.ipv6.src_prex,
                hdr.ipv6.src_addr,
                hdr.ipv6.src_sub,
                hdr.ipv6.dst_prex,
                hdr.ipv6.dst_addr,
                hdr.ipv6.dst_sub,
                hdr.udp.src_port,
                ig_md.chksum_udp4
            });

        }

        if (hdr.ipv4.isValid()) {
            
            hdr.udp.checksum = udp_csum6.update({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.udp.dst_port,
                ig_md.chksum_udp6
            });

        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
    }

}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------

parser TofinoEgressParser(
        packet_in pkt,
        inout eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}


parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
        
    TofinoEgressParser() tofino_parser;
#if __p4c_major__ < 9
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) ipv4_csum;
#else
    Checksum() ipv4_csum;
#endif   

    state start {
        tofino_parser.apply(pkt, eg_md, eg_intr_md);
        transition parse_ethernet;
        
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

#if __p4c_major__ < 9
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) ipv4_csum;
#else
    Checksum() ipv4_csum;
#endif
    apply {

        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_csum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags_frag_offset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
    }
}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
        
    Random<bit<8>>() rng1;
    Random<bit<8>>() rng2;
    Random<bit<8>>() rng3;
    Random<bit<32>>() rng_l;
    Random<bit<6>>() rng4;
    
#if __p4c_major__ < 9 
    Checksum<bit<16>> (HashAlgorithm_t.CSUM16) udp_csum;
#else
    Checksum() udp_csum;
#endif

    Hash<bit<2>>(HashAlgorithm_t.IDENTITY) copy_ver;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_ip1;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_ip2;

    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_rnd_t;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd1;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd2;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd3;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd4;

    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_1;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_2;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_3;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_4;

    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_11;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_22;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_33;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_44;

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy_16_1;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy_16_2;



    action nop() {
        
    }

    //-------------------------------
    // SBOX and reverse SBOX
    //-------------------------------
    #define SBOX(NAME, KEY, DO) table NAME {\
        key= {KEY:exact;}\
        actions = {DO; nop;}\
        const entries = {0:DO(0x63); 1:DO(0x7c); 2:DO(0x77); 3:DO(0x7b); 4:DO(0xf2); 5:DO(0x6b); 6:DO(0x6f); 7:DO(0xc5); \
            8:DO(0x30); 9:DO(0x1); 10:DO(0x67); 11:DO(0x2b); 12:DO(0xfe); 13:DO(0xd7); 14:DO(0xab); 15:DO(0x76); \
            16:DO(0xca); 17:DO(0x82); 18:DO(0xc9); 19:DO(0x7d); 20:DO(0xfa); 21:DO(0x59); 22:DO(0x47); 23:DO(0xf0); \
            24:DO(0xad); 25:DO(0xd4); 26:DO(0xa2); 27:DO(0xaf); 28:DO(0x9c); 29:DO(0xa4); 30:DO(0x72); 31:DO(0xc0); \
            32:DO(0xb7); 33:DO(0xfd); 34:DO(0x93); 35:DO(0x26); 36:DO(0x36); 37:DO(0x3f); 38:DO(0xf7); 39:DO(0xcc); \
            40:DO(0x34); 41:DO(0xa5); 42:DO(0xe5); 43:DO(0xf1); 44:DO(0x71); 45:DO(0xd8); 46:DO(0x31); 47:DO(0x15); \
            48:DO(0x4); 49:DO(0xc7); 50:DO(0x23); 51:DO(0xc3); 52:DO(0x18); 53:DO(0x96); 54:DO(0x5); 55:DO(0x9a); \
            56:DO(0x7); 57:DO(0x12); 58:DO(0x80); 59:DO(0xe2); 60:DO(0xeb); 61:DO(0x27); 62:DO(0xb2); 63:DO(0x75); \
            64:DO(0x9); 65:DO(0x83); 66:DO(0x2c); 67:DO(0x1a); 68:DO(0x1b); 69:DO(0x6e); 70:DO(0x5a); 71:DO(0xa0); \
            72:DO(0x52); 73:DO(0x3b); 74:DO(0xd6); 75:DO(0xb3); 76:DO(0x29); 77:DO(0xe3); 78:DO(0x2f); 79:DO(0x84); \
            80:DO(0x53); 81:DO(0xd1); 82:DO(0x0); 83:DO(0xed); 84:DO(0x20); 85:DO(0xfc); 86:DO(0xb1); 87:DO(0x5b); \
            88:DO(0x6a); 89:DO(0xcb); 90:DO(0xbe); 91:DO(0x39); 92:DO(0x4a); 93:DO(0x4c); 94:DO(0x58); 95:DO(0xcf); \
            96:DO(0xd0); 97:DO(0xef); 98:DO(0xaa); 99:DO(0xfb); 100:DO(0x43); 101:DO(0x4d); 102:DO(0x33); 103:DO(0x85); \
            104:DO(0x45); 105:DO(0xf9); 106:DO(0x2); 107:DO(0x7f); 108:DO(0x50); 109:DO(0x3c); 110:DO(0x9f); 111:DO(0xa8); \
            112:DO(0x51); 113:DO(0xa3); 114:DO(0x40); 115:DO(0x8f); 116:DO(0x92); 117:DO(0x9d); 118:DO(0x38); 119:DO(0xf5); \
            120:DO(0xbc); 121:DO(0xb6); 122:DO(0xda); 123:DO(0x21); 124:DO(0x10); 125:DO(0xff); 126:DO(0xf3); 127:DO(0xd2); \
            128:DO(0xcd); 129:DO(0xc); 130:DO(0x13); 131:DO(0xec); 132:DO(0x5f); 133:DO(0x97); 134:DO(0x44); 135:DO(0x17); \
            136:DO(0xc4); 137:DO(0xa7); 138:DO(0x7e); 139:DO(0x3d); 140:DO(0x64); 141:DO(0x5d); 142:DO(0x19); 143:DO(0x73); \
            144:DO(0x60); 145:DO(0x81); 146:DO(0x4f); 147:DO(0xdc); 148:DO(0x22); 149:DO(0x2a); 150:DO(0x90); 151:DO(0x88); \
            152:DO(0x46); 153:DO(0xee); 154:DO(0xb8); 155:DO(0x14); 156:DO(0xde); 157:DO(0x5e); 158:DO(0xb); 159:DO(0xdb); \
            160:DO(0xe0); 161:DO(0x32); 162:DO(0x3a); 163:DO(0xa); 164:DO(0x49); 165:DO(0x6); 166:DO(0x24); 167:DO(0x5c); \
            168:DO(0xc2); 169:DO(0xd3); 170:DO(0xac); 171:DO(0x62); 172:DO(0x91); 173:DO(0x95); 174:DO(0xe4); 175:DO(0x79); \
            176:DO(0xe7); 177:DO(0xc8); 178:DO(0x37); 179:DO(0x6d); 180:DO(0x8d); 181:DO(0xd5); 182:DO(0x4e); 183:DO(0xa9); \
            184:DO(0x6c); 185:DO(0x56); 186:DO(0xf4); 187:DO(0xea); 188:DO(0x65); 189:DO(0x7a); 190:DO(0xae); 191:DO(0x8); \
            192:DO(0xba); 193:DO(0x78); 194:DO(0x25); 195:DO(0x2e); 196:DO(0x1c); 197:DO(0xa6); 198:DO(0xb4); 199:DO(0xc6); \
            200:DO(0xe8); 201:DO(0xdd); 202:DO(0x74); 203:DO(0x1f); 204:DO(0x4b); 205:DO(0xbd); 206:DO(0x8b); 207:DO(0x8a); \
            208:DO(0x70); 209:DO(0x3e); 210:DO(0xb5); 211:DO(0x66); 212:DO(0x48); 213:DO(0x3); 214:DO(0xf6); 215:DO(0xe); \
            216:DO(0x61); 217:DO(0x35); 218:DO(0x57); 219:DO(0xb9); 220:DO(0x86); 221:DO(0xc1); 222:DO(0x1d); 223:DO(0x9e); \
            224:DO(0xe1); 225:DO(0xf8); 226:DO(0x98); 227:DO(0x11); 228:DO(0x69); 229:DO(0xd9); 230:DO(0x8e); 231:DO(0x94); \
            232:DO(0x9b); 233:DO(0x1e); 234:DO(0x87); 235:DO(0xe9); 236:DO(0xce); 237:DO(0x55); 238:DO(0x28); 239:DO(0xdf); \
            240:DO(0x8c); 241:DO(0xa1); 242:DO(0x89); 243:DO(0xd); 244:DO(0xbf); 245:DO(0xe6); 246:DO(0x42); 247:DO(0x68); \
            248:DO(0x41); 249:DO(0x99); 250:DO(0x2d); 251:DO(0xf); 252:DO(0xb0); 253:DO(0x54); 254:DO(0xbb); 255:DO(0x16); }\
        size = 256; \
        const default_action = nop; \
    }


    #define RSBOX(NAME, KEY, DO) table NAME { \
        key= {KEY:exact;}\
        actions = {DO; nop;}\
        const entries = {0:DO(0x52); 1:DO(0x9); 2:DO(0x6a); 3:DO(0xd5); 4:DO(0x30); 5:DO(0x36); 6:DO(0xa5); 7:DO(0x38); \
            8:DO(0xbf); 9:DO(0x40); 10:DO(0xa3); 11:DO(0x9e); 12:DO(0x81); 13:DO(0xf3); 14:DO(0xd7); 15:DO(0xfb); \
            16:DO(0x7c); 17:DO(0xe3); 18:DO(0x39); 19:DO(0x82); 20:DO(0x9b); 21:DO(0x2f); 22:DO(0xff); 23:DO(0x87); \
            24:DO(0x34); 25:DO(0x8e); 26:DO(0x43); 27:DO(0x44); 28:DO(0xc4); 29:DO(0xde); 30:DO(0xe9); 31:DO(0xcb); \
            32:DO(0x54); 33:DO(0x7b); 34:DO(0x94); 35:DO(0x32); 36:DO(0xa6); 37:DO(0xc2); 38:DO(0x23); 39:DO(0x3d); \
            40:DO(0xee); 41:DO(0x4c); 42:DO(0x95); 43:DO(0xb); 44:DO(0x42); 45:DO(0xfa); 46:DO(0xc3); 47:DO(0x4e); \
            48:DO(0x8); 49:DO(0x2e); 50:DO(0xa1); 51:DO(0x66); 52:DO(0x28); 53:DO(0xd9); 54:DO(0x24); 55:DO(0xb2); \
            56:DO(0x76); 57:DO(0x5b); 58:DO(0xa2); 59:DO(0x49); 60:DO(0x6d); 61:DO(0x8b); 62:DO(0xd1); 63:DO(0x25); \
            64:DO(0x72); 65:DO(0xf8); 66:DO(0xf6); 67:DO(0x64); 68:DO(0x86); 69:DO(0x68); 70:DO(0x98); 71:DO(0x16); \
            72:DO(0xd4); 73:DO(0xa4); 74:DO(0x5c); 75:DO(0xcc); 76:DO(0x5d); 77:DO(0x65); 78:DO(0xb6); 79:DO(0x92); \
            80:DO(0x6c); 81:DO(0x70); 82:DO(0x48); 83:DO(0x50); 84:DO(0xfd); 85:DO(0xed); 86:DO(0xb9); 87:DO(0xda); \
            88:DO(0x5e); 89:DO(0x15); 90:DO(0x46); 91:DO(0x57); 92:DO(0xa7); 93:DO(0x8d); 94:DO(0x9d); 95:DO(0x84); \
            96:DO(0x90); 97:DO(0xd8); 98:DO(0xab); 99:DO(0x0); 100:DO(0x8c); 101:DO(0xbc); 102:DO(0xd3); 103:DO(0xa); \
            104:DO(0xf7); 105:DO(0xe4); 106:DO(0x58); 107:DO(0x5); 108:DO(0xb8); 109:DO(0xb3); 110:DO(0x45); 111:DO(0x6); \
            112:DO(0xd0); 113:DO(0x2c); 114:DO(0x1e); 115:DO(0x8f); 116:DO(0xca); 117:DO(0x3f); 118:DO(0xf); 119:DO(0x2); \
            120:DO(0xc1); 121:DO(0xaf); 122:DO(0xbd); 123:DO(0x3); 124:DO(0x1); 125:DO(0x13); 126:DO(0x8a); 127:DO(0x6b); \
            128:DO(0x3a); 129:DO(0x91); 130:DO(0x11); 131:DO(0x41); 132:DO(0x4f); 133:DO(0x67); 134:DO(0xdc); 135:DO(0xea); \
            136:DO(0x97); 137:DO(0xf2); 138:DO(0xcf); 139:DO(0xce); 140:DO(0xf0); 141:DO(0xb4); 142:DO(0xe6); 143:DO(0x73); \
            144:DO(0x96); 145:DO(0xac); 146:DO(0x74); 147:DO(0x22); 148:DO(0xe7); 149:DO(0xad); 150:DO(0x35); 151:DO(0x85); \
            152:DO(0xe2); 153:DO(0xf9); 154:DO(0x37); 155:DO(0xe8); 156:DO(0x1c); 157:DO(0x75); 158:DO(0xdf); 159:DO(0x6e); \
            160:DO(0x47); 161:DO(0xf1); 162:DO(0x1a); 163:DO(0x71); 164:DO(0x1d); 165:DO(0x29); 166:DO(0xc5); 167:DO(0x89); \
            168:DO(0x6f); 169:DO(0xb7); 170:DO(0x62); 171:DO(0xe); 172:DO(0xaa); 173:DO(0x18); 174:DO(0xbe); 175:DO(0x1b); \
            176:DO(0xfc); 177:DO(0x56); 178:DO(0x3e); 179:DO(0x4b); 180:DO(0xc6); 181:DO(0xd2); 182:DO(0x79); 183:DO(0x20); \
            184:DO(0x9a); 185:DO(0xdb); 186:DO(0xc0); 187:DO(0xfe); 188:DO(0x78); 189:DO(0xcd); 190:DO(0x5a); 191:DO(0xf4); \
            192:DO(0x1f); 193:DO(0xdd); 194:DO(0xa8); 195:DO(0x33); 196:DO(0x88); 197:DO(0x7); 198:DO(0xc7); 199:DO(0x31); \
            200:DO(0xb1); 201:DO(0x12); 202:DO(0x10); 203:DO(0x59); 204:DO(0x27); 205:DO(0x80); 206:DO(0xec); 207:DO(0x5f); \
            208:DO(0x60); 209:DO(0x51); 210:DO(0x7f); 211:DO(0xa9); 212:DO(0x19); 213:DO(0xb5); 214:DO(0x4a); 215:DO(0xd); \
            216:DO(0x2d); 217:DO(0xe5); 218:DO(0x7a); 219:DO(0x9f); 220:DO(0x93); 221:DO(0xc9); 222:DO(0x9c); 223:DO(0xef); \
            224:DO(0xa0); 225:DO(0xe0); 226:DO(0x3b); 227:DO(0x4d); 228:DO(0xae); 229:DO(0x2a); 230:DO(0xf5); 231:DO(0xb0); \
            232:DO(0xc8); 233:DO(0xeb); 234:DO(0xbb); 235:DO(0x3c); 236:DO(0x83); 237:DO(0x53); 238:DO(0x99); 239:DO(0x61); \
            240:DO(0x17); 241:DO(0x2b); 242:DO(0x4); 243:DO(0x7e); 244:DO(0xba); 245:DO(0x77); 246:DO(0xd6); 247:DO(0x26); \
            248:DO(0xe1); 249:DO(0x69); 250:DO(0x14); 251:DO(0x63); 252:DO(0x55); 253:DO(0x21); 254:DO(0xc); 255:DO(0x7d);}\        
        size = 256; \
        const default_action = nop; \
    }


    //-------------------------------
    // SBOX and reverse SBOX actions
    //-------------------------------

    #define SBOXACTION(NAME, OUT, IN)  action NAME(bit<8> value){\
        OUT = value ^ IN; \ 
     }

    #define RSBOXACTION(NAME, OUT)  action NAME(bit<8> value){\
        OUT = value; \ 
    }

    //-------------------------------
    // identity hash for bit copy
    //-------------------------------

    #define BITH_1(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy1_##NO##;

    #define BITH_2(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy2_##NO##; 

    #define BITH_3(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy3_##NO##;

    #define BITH_4(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy4_##NO##;

    #define INIT_BITH(NO) BITH_##NO##(1) BITH_##NO##(2) BITH_##NO##(3) BITH_##NO##(4) BITH_##NO##(5) BITH_##NO##(6) BITH_##NO##(7) BITH_##NO##(8) \    
    BITH_##NO##(9) BITH_##NO##(10) BITH_##NO##(11) BITH_##NO##(12) BITH_##NO##(13) BITH_##NO##(14) BITH_##NO##(15) BITH_##NO##(16) \
    BITH_##NO##(17) BITH_##NO##(18) BITH_##NO##(19) BITH_##NO##(20) BITH_##NO##(21) BITH_##NO##(22) BITH_##NO##(23) BITH_##NO##(24) \
    BITH_##NO##(25) BITH_##NO##(26) BITH_##NO##(27) BITH_##NO##(28) BITH_##NO##(29) BITH_##NO##(30) BITH_##NO##(31) BITH_##NO##(32) \
    BITH_##NO##(33) BITH_##NO##(34) BITH_##NO##(35) BITH_##NO##(36) BITH_##NO##(37) BITH_##NO##(38) BITH_##NO##(39) BITH_##NO##(40) \
    BITH_##NO##(41) BITH_##NO##(42) BITH_##NO##(43) BITH_##NO##(44) BITH_##NO##(45) BITH_##NO##(46) BITH_##NO##(47) BITH_##NO##(48) \
    BITH_##NO##(49) BITH_##NO##(50) BITH_##NO##(51) BITH_##NO##(52) BITH_##NO##(53) BITH_##NO##(54) BITH_##NO##(55) BITH_##NO##(56) \
    BITH_##NO##(57) BITH_##NO##(58) BITH_##NO##(59) BITH_##NO##(60) BITH_##NO##(61) BITH_##NO##(62) BITH_##NO##(63) BITH_##NO##(64)


    INIT_BITH(1)
    INIT_BITH(2)
    INIT_BITH(3)
    INIT_BITH(4)

    
    // init sbox and reverse sbox actions

    SBOXACTION(S1, ig_md.c1, ig_md.otp1[31:24])
    SBOXACTION(S2, ig_md.c2, ig_md.otp1[23:16])
    SBOXACTION(S3, ig_md.c3, ig_md.otp1[15:8])
    SBOXACTION(S4, ig_md.c4, ig_md.otp1[7:0])
    SBOXACTION(S5, ig_md.r1, ig_md.otp1[63:56])
    SBOXACTION(S6, ig_md.r2, ig_md.otp1[55:48])
    SBOXACTION(S7, ig_md.r3, ig_md.otp1[47:40])
    SBOXACTION(S8, ig_md.r4, ig_md.otp1[39:32])

    SBOX(SBOX1, ig_md.c1, S1)
    SBOX(SBOX2, ig_md.c2, S2)
    SBOX(SBOX3, ig_md.c3, S3)
    SBOX(SBOX4, ig_md.c4, S4)
    SBOX(SBOX5, ig_md.r1, S5)
    SBOX(SBOX6, ig_md.r2, S6)
    SBOX(SBOX7, ig_md.r3, S7)
    SBOX(SBOX8, ig_md.r4, S8)
    

    SBOXACTION(S11, ig_md.c1, ig_md.otp2[31:24])
    SBOXACTION(S22, ig_md.c2, ig_md.otp2[23:16])
    SBOXACTION(S33, ig_md.c3, ig_md.otp2[15:8])
    SBOXACTION(S44, ig_md.c4, ig_md.otp2[7:0])
    SBOXACTION(S55, ig_md.r1, ig_md.otp2[63:56])
    SBOXACTION(S66, ig_md.r2, ig_md.otp2[55:48])
    SBOXACTION(S77, ig_md.r3, ig_md.otp2[47:40])
    SBOXACTION(S88, ig_md.r4, ig_md.otp2[39:32])


    SBOX(SBOX11, ig_md.c1, S11)
    SBOX(SBOX22, ig_md.c2, S22)
    SBOX(SBOX33, ig_md.c3, S33)
    SBOX(SBOX44, ig_md.c4, S44)
    SBOX(SBOX55, ig_md.r1, S55)
    SBOX(SBOX66, ig_md.r2, S66)
    SBOX(SBOX77, ig_md.r3, S77)
    SBOX(SBOX88, ig_md.r4, S88)


    RSBOXACTION(RS1, ig_md.c1)
    RSBOXACTION(RS2, ig_md.c2)
    RSBOXACTION(RS3, ig_md.c3)
    RSBOXACTION(RS4, ig_md.c4)
    RSBOXACTION(RS5, ig_md.r1)
    RSBOXACTION(RS6, ig_md.r2)
    RSBOXACTION(RS7, ig_md.r3)
    RSBOXACTION(RS8, ig_md.r4)

    RSBOX(RSBOX1, ig_md.c1, RS1)
    RSBOX(RSBOX2, ig_md.c2, RS2)
    RSBOX(RSBOX3, ig_md.c3, RS3)
    RSBOX(RSBOX4, ig_md.c4, RS4)
    RSBOX(RSBOX5, ig_md.r1, RS5)
    RSBOX(RSBOX6, ig_md.r2, RS6)
    RSBOX(RSBOX7, ig_md.r3, RS7)
    RSBOX(RSBOX8, ig_md.r4, RS8)

    SBOXACTION(RS11, ig_md.c1, ig_md.otp2[31:24])
    SBOXACTION(RS22, ig_md.c2, ig_md.otp2[23:16])
    SBOXACTION(RS33, ig_md.c3, ig_md.otp2[15:8])
    SBOXACTION(RS44, ig_md.c4, ig_md.otp2[7:0])
    SBOXACTION(RS55, ig_md.r1, ig_md.otp2[63:56])
    SBOXACTION(RS66, ig_md.r2, ig_md.otp2[55:48])
    SBOXACTION(RS77, ig_md.r3, ig_md.otp2[47:40])
    SBOXACTION(RS88, ig_md.r4, ig_md.otp2[39:32])


    RSBOX(RSBOX11, ig_md.c1, RS11)
    RSBOX(RSBOX22, ig_md.c2, RS22)
    RSBOX(RSBOX33, ig_md.c3, RS33)
    RSBOX(RSBOX44, ig_md.c4, RS44)
    RSBOX(RSBOX55, ig_md.r1, RS55)
    RSBOX(RSBOX66, ig_md.r2, RS66)
    RSBOX(RSBOX77, ig_md.r3, RS77)
    RSBOX(RSBOX88, ig_md.r4, RS88)


    // set the lowest 32 bits of the encrypted IPv6 source address
    // or set the decrypted IPv4 destination address
    action set_final_ip(bool is_enc) {
        if (is_enc) {
           
            hdr.ipv6.src_addr[31:31] = copy1_32.get(ig_md.c4[0:0]);
            hdr.ipv6.src_addr[30:30] = copy1_27.get(ig_md.c4[5:5]);
            hdr.ipv6.src_addr[29:29] = copy1_11.get(ig_md.c2[5:5]);
            hdr.ipv6.src_addr[28:28] = copy1_16.get(ig_md.c2[0:0]);
            hdr.ipv6.src_addr[27:27] = copy1_4.get(ig_md.c1[4:4]);
            hdr.ipv6.src_addr[26:26] = copy1_54.get(ig_md.r3[2:2]);
            hdr.ipv6.src_addr[25:25] = copy1_36.get(ig_md.r1[4:4]);
            hdr.ipv6.src_addr[24:24] = copy1_28.get(ig_md.c4[4:4]);
            hdr.ipv6.src_addr[23:23] = copy1_61.get(ig_md.r4[3:3]);
            hdr.ipv6.src_addr[22:22] = copy1_30.get(ig_md.c4[2:2]);
            hdr.ipv6.src_addr[21:21] = copy1_44.get(ig_md.r2[4:4]);
            hdr.ipv6.src_addr[20:20] = copy1_23.get(ig_md.c3[1:1]);
            hdr.ipv6.src_addr[19:19] = copy1_20.get(ig_md.c3[4:4]);
            hdr.ipv6.src_addr[18:18] = copy1_17.get(ig_md.c3[7:7]);
            hdr.ipv6.src_addr[17:17] = copy1_64.get(ig_md.r4[0:0]);
            hdr.ipv6.src_addr[16:16] = copy1_29.get(ig_md.c4[3:3]);
            hdr.ipv6.src_addr[15:15] = copy1_34.get(ig_md.r1[6:6]);
            hdr.ipv6.src_addr[14:14] = copy1_21.get(ig_md.c3[3:3]);
            hdr.ipv6.src_addr[13:13] = copy1_52.get(ig_md.r3[4:4]);
            hdr.ipv6.src_addr[12:12] = copy1_50.get(ig_md.r3[6:6]);
            hdr.ipv6.src_addr[11:11] = copy1_13.get(ig_md.c2[3:3]);
            hdr.ipv6.src_addr[10:10] = copy1_9.get(ig_md.c2[7:7]);
            hdr.ipv6.src_addr[9:9] = copy1_18.get(ig_md.c3[6:6]);
            hdr.ipv6.src_addr[8:8] = copy1_3.get(ig_md.c1[5:5]);
            hdr.ipv6.src_addr[7:7] = copy1_56.get(ig_md.r3[0:0]);
            hdr.ipv6.src_addr[6:6] = copy1_62.get(ig_md.r4[2:2]);
            hdr.ipv6.src_addr[5:5] = copy1_19.get(ig_md.c3[5:5]);
            hdr.ipv6.src_addr[4:4] = copy1_15.get(ig_md.c2[1:1]);
            hdr.ipv6.src_addr[3:3] = copy1_45.get(ig_md.r2[3:3]);
            hdr.ipv6.src_addr[2:2] = copy1_7.get(ig_md.c1[1:1]);
            hdr.ipv6.src_addr[1:1] = copy1_48.get(ig_md.r2[0:0]);
            hdr.ipv6.src_addr[0:0] = copy1_57.get(ig_md.r4[7:7]);


        } else {
            hdr.ipv4.dst_addr[31:24] = copy8_1.get(ig_md.c1);
            hdr.ipv4.dst_addr[23:16] = copy8_2.get(ig_md.c2);
            hdr.ipv4.dst_addr[15:8] = copy8_3.get(ig_md.c3);
            hdr.ipv4.dst_addr[7:0] = copy8_4.get(ig_md.c4);
        }

    }

    // set the subnet part of the encrypted IPv6 source address
    action set_final_sub(bool is_enc) {
        if (is_enc) {
            hdr.ipv6.src_sub[31:31] = copy1_35.get(ig_md.r1[5:5]);
            hdr.ipv6.src_sub[30:30] = copy1_12.get(ig_md.c2[4:4]);
            hdr.ipv6.src_sub[29:29] = copy1_22.get(ig_md.c3[2:2]);
            hdr.ipv6.src_sub[28:28] = copy1_40.get(ig_md.r1[0:0]);
            hdr.ipv6.src_sub[27:27] = copy1_39.get(ig_md.r1[1:1]);
            hdr.ipv6.src_sub[26:26] = copy1_8.get(ig_md.c1[0:0]);
            hdr.ipv6.src_sub[25:25] = copy1_60.get(ig_md.r4[4:4]);
            hdr.ipv6.src_sub[24:24] = copy1_47.get(ig_md.r2[1:1]);
            hdr.ipv6.src_sub[23:23] = copy1_31.get(ig_md.c4[1:1]);
            hdr.ipv6.src_sub[22:22] = copy1_14.get(ig_md.c2[2:2]);
            hdr.ipv6.src_sub[21:21] = copy1_55.get(ig_md.r3[1:1]);
            hdr.ipv6.src_sub[20:20] = copy1_2.get(ig_md.c1[6:6]);
            hdr.ipv6.src_sub[19:19] = copy1_37.get(ig_md.r1[3:3]);
            hdr.ipv6.src_sub[18:18] = copy1_58.get(ig_md.r4[6:6]);
            hdr.ipv6.src_sub[17:17] = copy1_6.get(ig_md.c1[2:2]);
            hdr.ipv6.src_sub[16:16] = copy1_43.get(ig_md.r2[5:5]);
            hdr.ipv6.src_sub[15:15] = copy1_25.get(ig_md.c4[7:7]);
            hdr.ipv6.src_sub[14:14] = copy1_10.get(ig_md.c2[6:6]);
            hdr.ipv6.src_sub[13:13] = copy1_33.get(ig_md.r1[7:7]);
            hdr.ipv6.src_sub[12:12] = copy1_26.get(ig_md.c4[6:6]);
            hdr.ipv6.src_sub[11:11] = copy1_41.get(ig_md.r2[7:7]);
            hdr.ipv6.src_sub[10:10] = copy1_24.get(ig_md.c3[0:0]);
            hdr.ipv6.src_sub[9:9] = copy1_53.get(ig_md.r3[3:3]);
            hdr.ipv6.src_sub[8:8] = copy1_42.get(ig_md.r2[6:6]);
            hdr.ipv6.src_sub[7:7] = copy1_5.get(ig_md.c1[3:3]);
            hdr.ipv6.src_sub[6:6] = copy1_59.get(ig_md.r4[5:5]);
            hdr.ipv6.src_sub[5:5] = copy1_46.get(ig_md.r2[2:2]);
            hdr.ipv6.src_sub[4:4] = copy1_1.get(ig_md.c1[7:7]);
            hdr.ipv6.src_sub[3:3] = copy1_38.get(ig_md.r1[2:2]);
            hdr.ipv6.src_sub[2:2] = copy1_51.get(ig_md.r3[5:5]);
            hdr.ipv6.src_sub[1:1] = copy1_49.get(ig_md.r3[7:7]);
            hdr.ipv6.src_sub[0:0] = copy1_63.get(ig_md.r4[1:1]);

        } else {    
            // pass
        } 


    }
        

    // if encryption: generate random padding
    // if decryption: copy the subnet part in an encrypted address
    action gen_rnd(bool is_enc) {
        if (is_enc) {
            ig_md.new_rnd = rng_l.get();
        } else {
            ig_md.new_rnd1[31:31] = copy2_51.get(hdr.ipv6.dst_sub[13:13]);
            ig_md.new_rnd1[30:30] = copy2_17.get(hdr.ipv6.dst_addr[15:15]);
            ig_md.new_rnd1[29:29] = copy2_33.get(hdr.ipv6.dst_sub[31:31]);
            ig_md.new_rnd1[28:28] = copy2_7.get(hdr.ipv6.dst_addr[25:25]);
            ig_md.new_rnd1[27:27] = copy2_45.get(hdr.ipv6.dst_sub[19:19]);
            ig_md.new_rnd1[26:26] = copy2_61.get(hdr.ipv6.dst_sub[3:3]);
            ig_md.new_rnd1[25:25] = copy2_37.get(hdr.ipv6.dst_sub[27:27]);
            ig_md.new_rnd1[24:24] = copy2_36.get(hdr.ipv6.dst_sub[28:28]);
            ig_md.new_rnd1[23:23] = copy2_53.get(hdr.ipv6.dst_sub[11:11]);
            ig_md.new_rnd1[22:22] = copy2_56.get(hdr.ipv6.dst_sub[8:8]);
            ig_md.new_rnd1[21:21] = copy2_48.get(hdr.ipv6.dst_sub[16:16]);
            ig_md.new_rnd1[20:20] = copy2_11.get(hdr.ipv6.dst_addr[21:21]);
            ig_md.new_rnd1[19:19] = copy2_29.get(hdr.ipv6.dst_addr[3:3]);
            ig_md.new_rnd1[18:18] = copy2_59.get(hdr.ipv6.dst_sub[5:5]);
            ig_md.new_rnd1[17:17] = copy2_40.get(hdr.ipv6.dst_sub[24:24]);
            ig_md.new_rnd1[16:16] = copy2_31.get(hdr.ipv6.dst_addr[1:1]);
            ig_md.new_rnd1[15:15] = copy2_63.get(hdr.ipv6.dst_sub[1:1]);
            ig_md.new_rnd1[14:14] = copy2_20.get(hdr.ipv6.dst_addr[12:12]);
            ig_md.new_rnd1[13:13] = copy2_62.get(hdr.ipv6.dst_sub[2:2]);
            ig_md.new_rnd1[12:12] = copy2_19.get(hdr.ipv6.dst_addr[13:13]);
            ig_md.new_rnd1[11:11] = copy2_55.get(hdr.ipv6.dst_sub[9:9]);
            ig_md.new_rnd1[10:10] = copy2_6.get(hdr.ipv6.dst_addr[26:26]);
            ig_md.new_rnd1[9:9] = copy2_43.get(hdr.ipv6.dst_sub[21:21]);
            ig_md.new_rnd1[8:8] = copy2_25.get(hdr.ipv6.dst_addr[7:7]);
            ig_md.new_rnd1[7:7] = copy2_32.get(hdr.ipv6.dst_addr[0:0]);
            ig_md.new_rnd1[6:6] = copy2_46.get(hdr.ipv6.dst_sub[18:18]);
            ig_md.new_rnd1[5:5] = copy2_58.get(hdr.ipv6.dst_sub[6:6]);
            ig_md.new_rnd1[4:4] = copy2_39.get(hdr.ipv6.dst_sub[25:25]);
            ig_md.new_rnd1[3:3] = copy2_9.get(hdr.ipv6.dst_addr[23:23]);
            ig_md.new_rnd1[2:2] = copy2_26.get(hdr.ipv6.dst_addr[6:6]);
            ig_md.new_rnd1[1:1] = copy2_64.get(hdr.ipv6.dst_sub[0:0]);
            ig_md.new_rnd1[0:0] = copy2_15.get(hdr.ipv6.dst_addr[17:17]);
        }       
    }

    // permutation for 63-32 bits 
    action p1(){
        hdr.ipv6.src_addr[31:31] = copy3_22.get(ig_md.c3[2:2]);
        hdr.ipv6.src_addr[30:30] = copy3_15.get(ig_md.c2[1:1]);
        hdr.ipv6.src_addr[29:29] = copy3_50.get(ig_md.r3[6:6]);
        hdr.ipv6.src_addr[28:28] = copy3_6.get(ig_md.c1[2:2]);
        hdr.ipv6.src_addr[27:27] = copy3_17.get(ig_md.c3[7:7]);
        hdr.ipv6.src_addr[26:26] = copy3_57.get(ig_md.r4[7:7]);
        hdr.ipv6.src_addr[25:25] = copy3_59.get(ig_md.r4[5:5]);
        hdr.ipv6.src_addr[24:24] = copy3_25.get(ig_md.c4[7:7]);
        hdr.ipv6.src_addr[23:23] = copy3_34.get(ig_md.r1[6:6]);
        hdr.ipv6.src_addr[22:22] = copy3_7.get(ig_md.c1[1:1]);
        hdr.ipv6.src_addr[21:21] = copy3_1.get(ig_md.c1[7:7]);
        hdr.ipv6.src_addr[20:20] = copy3_20.get(ig_md.c3[4:4]);
        hdr.ipv6.src_addr[19:19] = copy3_24.get(ig_md.c3[0:0]);
        hdr.ipv6.src_addr[18:18] = copy3_4.get(ig_md.c1[4:4]);
        hdr.ipv6.src_addr[17:17] = copy3_28.get(ig_md.c4[4:4]);
        hdr.ipv6.src_addr[16:16] = copy3_30.get(ig_md.c4[2:2]);
        hdr.ipv6.src_addr[15:15] = copy3_43.get(ig_md.r2[5:5]);
        hdr.ipv6.src_addr[14:14] = copy3_11.get(ig_md.c2[5:5]);
        hdr.ipv6.src_addr[13:13] = copy3_8.get(ig_md.c1[0:0]);
        hdr.ipv6.src_addr[12:12] = copy3_61.get(ig_md.r4[3:3]);
        hdr.ipv6.src_addr[11:11] = copy3_39.get(ig_md.r1[1:1]);
        hdr.ipv6.src_addr[10:10] = copy3_38.get(ig_md.r1[2:2]);
        hdr.ipv6.src_addr[9:9] = copy3_56.get(ig_md.r3[0:0]);
        hdr.ipv6.src_addr[8:8] = copy3_52.get(ig_md.r3[4:4]);
        hdr.ipv6.src_addr[7:7] = copy3_31.get(ig_md.c4[1:1]);
        hdr.ipv6.src_addr[6:6] = copy3_47.get(ig_md.r2[1:1]);
        hdr.ipv6.src_addr[5:5] = copy3_35.get(ig_md.r1[5:5]);
        hdr.ipv6.src_addr[4:4] = copy3_62.get(ig_md.r4[2:2]);
        hdr.ipv6.src_addr[3:3] = copy3_23.get(ig_md.c3[1:1]);
        hdr.ipv6.src_addr[2:2] = copy3_33.get(ig_md.r1[7:7]);
        hdr.ipv6.src_addr[1:1] = copy3_48.get(ig_md.r2[0:0]);
        hdr.ipv6.src_addr[0:0] = copy3_42.get(ig_md.r2[6:6]);
    }
    
    // permutation for 31-0 bits 
    action p2(){
        hdr.ipv6.src_sub[31:31] = copy3_64.get(ig_md.r4[0:0]);
        hdr.ipv6.src_sub[30:30] = copy3_19.get(ig_md.c3[5:5]);
        hdr.ipv6.src_sub[29:29] = copy3_5.get(ig_md.c1[3:3]);
        hdr.ipv6.src_sub[28:28] = copy3_14.get(ig_md.c2[2:2]);
        hdr.ipv6.src_sub[27:27] = copy3_26.get(ig_md.c4[6:6]);
        hdr.ipv6.src_sub[26:26] = copy3_29.get(ig_md.c4[3:3]);
        hdr.ipv6.src_sub[25:25] = copy3_36.get(ig_md.r1[4:4]);
        hdr.ipv6.src_sub[24:24] = copy3_21.get(ig_md.c3[3:3]);
        hdr.ipv6.src_sub[23:23] = copy3_46.get(ig_md.r2[2:2]);
        hdr.ipv6.src_sub[22:22] = copy3_55.get(ig_md.r3[1:1]);
        hdr.ipv6.src_sub[21:21] = copy3_18.get(ig_md.c3[6:6]);
        hdr.ipv6.src_sub[20:20] = copy3_3.get(ig_md.c1[5:5]);
        hdr.ipv6.src_sub[19:19] = copy3_27.get(ig_md.c4[5:5]);
        hdr.ipv6.src_sub[18:18] = copy3_51.get(ig_md.r3[5:5]);
        hdr.ipv6.src_sub[17:17] = copy3_58.get(ig_md.r4[6:6]);
        hdr.ipv6.src_sub[16:16] = copy3_16.get(ig_md.c2[0:0]);
        hdr.ipv6.src_sub[15:15] = copy3_60.get(ig_md.r4[4:4]);
        hdr.ipv6.src_sub[14:14] = copy3_32.get(ig_md.c4[0:0]);
        hdr.ipv6.src_sub[13:13] = copy3_41.get(ig_md.r2[7:7]);
        hdr.ipv6.src_sub[12:12] = copy3_44.get(ig_md.r2[4:4]);
        hdr.ipv6.src_sub[11:11] = copy3_12.get(ig_md.c2[4:4]);
        hdr.ipv6.src_sub[10:10] = copy3_40.get(ig_md.r1[0:0]);
        hdr.ipv6.src_sub[9:9] = copy3_49.get(ig_md.r3[7:7]);
        hdr.ipv6.src_sub[8:8] = copy3_10.get(ig_md.c2[6:6]);
        hdr.ipv6.src_sub[7:7] = copy3_54.get(ig_md.r3[2:2]);
        hdr.ipv6.src_sub[6:6] = copy3_45.get(ig_md.r2[3:3]);
        hdr.ipv6.src_sub[5:5] = copy3_53.get(ig_md.r3[3:3]);
        hdr.ipv6.src_sub[4:4] = copy3_2.get(ig_md.c1[6:6]);
        hdr.ipv6.src_sub[3:3] = copy3_9.get(ig_md.c2[7:7]);
        hdr.ipv6.src_sub[2:2] = copy3_13.get(ig_md.c2[3:3]);
        hdr.ipv6.src_sub[1:1] = copy3_37.get(ig_md.r1[3:3]);
        hdr.ipv6.src_sub[0:0] = copy3_63.get(ig_md.r4[1:1]);
    }
    
    // reverse permutation for 63-32 bits 
    action rp1(){
        ig_md.new_ip[31:31] = copy4_11.get(ig_md.c2[5:5]);
        ig_md.new_ip[30:30] = copy4_60.get(ig_md.r4[4:4]);
        ig_md.new_ip[29:29] = copy4_44.get(ig_md.r2[4:4]);
        ig_md.new_ip[28:28] = copy4_14.get(ig_md.c2[2:2]);
        ig_md.new_ip[27:27] = copy4_35.get(ig_md.r1[5:5]);
        ig_md.new_ip[26:26] = copy4_4.get(ig_md.c1[4:4]);
        ig_md.new_ip[25:25] = copy4_10.get(ig_md.c2[6:6]);
        ig_md.new_ip[24:24] = copy4_19.get(ig_md.c3[5:5]);
        ig_md.new_ip[23:23] = copy4_61.get(ig_md.r4[3:3]);
        ig_md.new_ip[22:22] = copy4_56.get(ig_md.r3[0:0]);
        ig_md.new_ip[21:21] = copy4_18.get(ig_md.c3[6:6]);
        ig_md.new_ip[20:20] = copy4_53.get(ig_md.r3[3:3]);
        ig_md.new_ip[19:19] = copy4_62.get(ig_md.r4[2:2]);
        ig_md.new_ip[18:18] = copy4_36.get(ig_md.r1[4:4]);
        ig_md.new_ip[17:17] = copy4_2.get(ig_md.c1[6:6]);
        ig_md.new_ip[16:16] = copy4_48.get(ig_md.r2[0:0]);
        ig_md.new_ip[15:15] = copy4_5.get(ig_md.c1[3:3]);
        ig_md.new_ip[14:14] = copy4_43.get(ig_md.r2[5:5]);
        ig_md.new_ip[13:13] = copy4_34.get(ig_md.r1[6:6]);
        ig_md.new_ip[12:12] = copy4_12.get(ig_md.c2[4:4]);
        ig_md.new_ip[11:11] = copy4_40.get(ig_md.r1[0:0]);
        ig_md.new_ip[10:10] = copy4_1.get(ig_md.c1[7:7]);
        ig_md.new_ip[9:9] = copy4_29.get(ig_md.c4[3:3]);
        ig_md.new_ip[8:8] = copy4_13.get(ig_md.c2[3:3]);
        ig_md.new_ip[7:7] = copy4_8.get(ig_md.c1[0:0]);
        ig_md.new_ip[6:6] = copy4_37.get(ig_md.r1[3:3]);
        ig_md.new_ip[5:5] = copy4_45.get(ig_md.r2[3:3]);
        ig_md.new_ip[4:4] = copy4_15.get(ig_md.c2[1:1]);
        ig_md.new_ip[3:3] = copy4_38.get(ig_md.r1[2:2]);
        ig_md.new_ip[2:2] = copy4_16.get(ig_md.c2[0:0]);
        ig_md.new_ip[1:1] = copy4_25.get(ig_md.c4[7:7]);
        ig_md.new_ip[0:0] = copy4_50.get(ig_md.r3[6:6]);
    }
    
    // reverse permutation for 31-0 bits
    action rp2(){
        ig_md.new_rnd1[31:31] = copy4_30.get(ig_md.c4[2:2]);
        ig_md.new_rnd1[30:30] = copy4_9.get(ig_md.c2[7:7]);
        ig_md.new_rnd1[29:29] = copy4_27.get(ig_md.c4[5:5]);
        ig_md.new_rnd1[28:28] = copy4_39.get(ig_md.r1[1:1]);
        ig_md.new_rnd1[27:27] = copy4_63.get(ig_md.r4[1:1]);
        ig_md.new_rnd1[26:26] = copy4_22.get(ig_md.c3[2:2]);
        ig_md.new_rnd1[25:25] = copy4_21.get(ig_md.c3[3:3]);
        ig_md.new_rnd1[24:24] = copy4_54.get(ig_md.r3[2:2]);
        ig_md.new_rnd1[23:23] = copy4_51.get(ig_md.r3[5:5]);
        ig_md.new_rnd1[22:22] = copy4_32.get(ig_md.c4[0:0]);
        ig_md.new_rnd1[21:21] = copy4_17.get(ig_md.c3[7:7]);
        ig_md.new_rnd1[20:20] = copy4_52.get(ig_md.r3[4:4]);
        ig_md.new_rnd1[19:19] = copy4_58.get(ig_md.r4[6:6]);
        ig_md.new_rnd1[18:18] = copy4_41.get(ig_md.r2[7:7]);
        ig_md.new_rnd1[17:17] = copy4_26.get(ig_md.c4[6:6]);
        ig_md.new_rnd1[16:16] = copy4_31.get(ig_md.c4[1:1]);
        ig_md.new_rnd1[15:15] = copy4_55.get(ig_md.r3[1:1]);
        ig_md.new_rnd1[14:14] = copy4_3.get(ig_md.c1[5:5]);
        ig_md.new_rnd1[13:13] = copy4_46.get(ig_md.r2[2:2]);
        ig_md.new_rnd1[12:12] = copy4_24.get(ig_md.c3[0:0]);
        ig_md.new_rnd1[11:11] = copy4_59.get(ig_md.r4[5:5]);
        ig_md.new_rnd1[10:10] = copy4_57.get(ig_md.r4[7:7]);
        ig_md.new_rnd1[9:9] = copy4_42.get(ig_md.r2[6:6]);
        ig_md.new_rnd1[8:8] = copy4_23.get(ig_md.c3[1:1]);
        ig_md.new_rnd1[7:7] = copy4_6.get(ig_md.c1[2:2]);
        ig_md.new_rnd1[6:6] = copy4_47.get(ig_md.r2[1:1]);
        ig_md.new_rnd1[5:5] = copy4_7.get(ig_md.c1[1:1]);
        ig_md.new_rnd1[4:4] = copy4_49.get(ig_md.r3[7:7]);
        ig_md.new_rnd1[3:3] = copy4_20.get(ig_md.c3[4:4]);
        ig_md.new_rnd1[2:2] = copy4_28.get(ig_md.c4[4:4]);
        ig_md.new_rnd1[1:1] = copy4_64.get(ig_md.r4[0:0]);
        ig_md.new_rnd1[0:0] = copy4_33.get(ig_md.r1[7:7]);
    }

    action copy_ip() {
        ig_md.new_ip = copy_ip1.get(hdr.ipv4.src_addr);
    }

    action copy_ip_r() { 
        ig_md.new_ip[31:31] = copy2_60.get(hdr.ipv6.dst_sub[4:4]);
        ig_md.new_ip[30:30] = copy2_44.get(hdr.ipv6.dst_sub[20:20]);
        ig_md.new_ip[29:29] = copy2_24.get(hdr.ipv6.dst_addr[8:8]);
        ig_md.new_ip[28:28] = copy2_5.get(hdr.ipv6.dst_addr[27:27]);
        ig_md.new_ip[27:27] = copy2_57.get(hdr.ipv6.dst_sub[7:7]);
        ig_md.new_ip[26:26] = copy2_47.get(hdr.ipv6.dst_sub[17:17]);
        ig_md.new_ip[25:25] = copy2_30.get(hdr.ipv6.dst_addr[2:2]);
        ig_md.new_ip[24:24] = copy2_38.get(hdr.ipv6.dst_sub[26:26]);
        ig_md.new_ip[23:23] = copy2_22.get(hdr.ipv6.dst_addr[10:10]);
        ig_md.new_ip[22:22] = copy2_50.get(hdr.ipv6.dst_sub[14:14]);
        ig_md.new_ip[21:21] = copy2_3.get(hdr.ipv6.dst_addr[29:29]);
        ig_md.new_ip[20:20] = copy2_34.get(hdr.ipv6.dst_sub[30:30]);
        ig_md.new_ip[19:19] = copy2_21.get(hdr.ipv6.dst_addr[11:11]);
        ig_md.new_ip[18:18] = copy2_42.get(hdr.ipv6.dst_sub[22:22]);
        ig_md.new_ip[17:17] = copy2_28.get(hdr.ipv6.dst_addr[4:4]);
        ig_md.new_ip[16:16] = copy2_4.get(hdr.ipv6.dst_addr[28:28]);
        ig_md.new_ip[15:15] = copy2_14.get(hdr.ipv6.dst_addr[18:18]);
        ig_md.new_ip[14:14] = copy2_23.get(hdr.ipv6.dst_addr[9:9]);
        ig_md.new_ip[13:13] = copy2_27.get(hdr.ipv6.dst_addr[5:5]);
        ig_md.new_ip[12:12] = copy2_13.get(hdr.ipv6.dst_addr[19:19]);
        ig_md.new_ip[11:11] = copy2_18.get(hdr.ipv6.dst_addr[14:14]);
        ig_md.new_ip[10:10] = copy2_35.get(hdr.ipv6.dst_sub[29:29]);
        ig_md.new_ip[9:9] = copy2_12.get(hdr.ipv6.dst_addr[20:20]);
        ig_md.new_ip[8:8] = copy2_54.get(hdr.ipv6.dst_sub[10:10]);
        ig_md.new_ip[7:7] = copy2_49.get(hdr.ipv6.dst_sub[15:15]);
        ig_md.new_ip[6:6] = copy2_52.get(hdr.ipv6.dst_sub[12:12]);
        ig_md.new_ip[5:5] = copy2_2.get(hdr.ipv6.dst_addr[30:30]);
        ig_md.new_ip[4:4] = copy2_8.get(hdr.ipv6.dst_addr[24:24]);
        ig_md.new_ip[3:3] = copy2_16.get(hdr.ipv6.dst_addr[16:16]);
        ig_md.new_ip[2:2] = copy2_10.get(hdr.ipv6.dst_addr[22:22]);
        ig_md.new_ip[1:1] = copy2_41.get(hdr.ipv6.dst_sub[23:23]);
        ig_md.new_ip[0:0] = copy2_1.get(hdr.ipv6.dst_addr[31:31]);

    }
    action init_lookup_key_ip(bool is_enc){
        if (is_enc) {
            ig_md.c1 = ig_md.new_ip[31:24];
            ig_md.c2 = ig_md.new_ip[23:16];
            ig_md.c3 = ig_md.new_ip[15:8];
            ig_md.c4 = ig_md.new_ip[7:0];

        } else {
            ig_md.c1 = ig_md.new_ip[31:24];
            ig_md.c2 = ig_md.new_ip[23:16];
            ig_md.c3 = ig_md.new_ip[15:8];
            ig_md.c4 = ig_md.new_ip[7:0]; 
        }
    }

    action init_lookup_key_rnd(bool is_enc) {
        if (is_enc) {
            ig_md.r1 = hdr.ipv6.src_sub[31:24];
            ig_md.r2 = hdr.ipv6.src_sub[23:16];
            ig_md.r3 = hdr.ipv6.src_sub[15:8];
            ig_md.r4 = hdr.ipv6.src_sub[7:0];
        } else {
            ig_md.r1 = copy8_11.get(ig_md.new_rnd1[31:24]);
            ig_md.r2 = copy8_22.get(ig_md.new_rnd1[23:16]);
            ig_md.r3 = copy8_33.get(ig_md.new_rnd1[15:8]);
            ig_md.r4 = copy8_44.get(ig_md.new_rnd1[7:0]);
        }

    }

    action init_pkt_n1(bool is_enc) {
        ig_md.otp1 = 0x0;
        ig_md.otp2 = 0x0;
        ig_md.new_ip1 = 0x0;
        ig_md.is_set_sub = false;

        if (is_enc) {  
            hdr.ipv6.setValid();
            hdr.ipv6.version = VERSION_IPV6;
            hdr.ipv6.src_prex = NET_PREFIX;
            hdr.ethernet.ether_type = ETHERTYPE_IPV6;
            hdr.ipv6.payload_length = hdr.ipv4.total_len - 20; 
            hdr.ipv6.next_hdr = hdr.ipv4.protocol;
            hdr.ipv6.hop_limit = hdr.ipv4.ttl;
              
        } else {
            ig_md.cur_ver =  hdr.ipv6.dst_prex[1:0];
            
            hdr.ipv4.setValid();
            hdr.ipv4.version = VERSION_IPV4;
            hdr.ethernet.ether_type = ETHERTYPE_IPV4;
            hdr.ipv4.ihl = 5;
            hdr.ipv4.total_len = hdr.ipv6.payload_length + 20;
            hdr.ipv4.protocol = hdr.ipv6.next_hdr;
            hdr.ipv4.ttl = hdr.ipv6.hop_limit;

            // joon. added after debugging.
            hdr.ipv4.flags_frag_offset = 0;
        }
        
    }


    action get_key_1(bit<32> k1, bit<32> k2, bit<64> otp1, bit<64> otp2) {
        ig_md.new_ip = ig_md.new_ip ^ k1;
        ig_md.new_rnd = ig_md.new_rnd ^ k2;
        ig_md.otp1 = otp1;
        ig_md.otp2 = otp2;
    }


    table xor_with_key_1 {
        key = {
            ig_md.cur_ver: exact;
        }
        actions = {
                get_key_1;
                nop;
            }
        size = 4;
        default_action = nop();
    }

    action get_key_2(bit<32> k1, bit<32> k2, bit<64> otp1, bit<64> otp2) {
        ig_md.new_ip = ig_md.new_ip ^ k1;
        ig_md.new_rnd1 = ig_md.new_rnd1 ^ k2;
        ig_md.otp1 = otp1;
        ig_md.otp2 = otp2;
    }


    table xor_with_key_2 {
        key = {
            ig_md.cur_ver: exact;
        }
        actions = {
                get_key_2;
                nop;
            }
        size = 4;
        default_action = nop();
    }



    
    action get_ipv6_addr(bit<64> prex, bit<32> sub, bit<32> addr) {
        hdr.ipv6.dst_prex = prex;
        hdr.ipv6.dst_sub = sub;
        hdr.ipv6.dst_addr = addr;
        hdr.ipv4.setInvalid();
        ig_md.is_set_sub = true;
    }

    action get_ipv4_addr(bit<32> addr) {
        hdr.ipv4.src_addr = addr;
        //hdr.ethernet.dst_addr = 48w0x90e2ba46e734; //joon. sdn-testbed-01. p1p1.
        // hdr.ethernet.dst_addr = 48w0xa0369f201088; //joon.   sdn-testbed-02. p1p1.
        hdr.ipv6.setInvalid();
    }

    // convert public servers' IP addresses: 4 to 6
    table get_svr_addr6 {
        key = {
            hdr.ipv4.dst_addr: exact;          
        }
        actions = {
            get_ipv6_addr;
            nop;
        }
        size = 1024;
    }

    // convert public servers' IP addresses: 6 to 4
    table get_svr_addr4 {
        key = {
            hdr.ipv6.src_prex: exact;  
            hdr.ipv6.src_sub: exact;
            hdr.ipv6.src_addr: exact;        
        }
        actions = {
            get_ipv4_addr;
            nop;
        }
        size = 1024;
    }


    action port_enc_act(bit<16> tmpk) {
        hdr.udp.src_port = hdr.udp.src_port ^ tmpk;
    }

    table port_enc {
        key = {
            ig_md.r1: exact;
            ig_md.cur_ver: exact;
        }
        actions = {
            port_enc_act;
            nop;
        }
        size = 1024;
    }

    action port_dec_act(bit<16> tmpk) {
        hdr.udp.dst_port = hdr.udp.dst_port ^ tmpk;
    }

    table  port_dec {
        key = {
            ig_md.r1: exact;
            ig_md.cur_ver: exact;
        }
        actions = {
            port_dec_act;
            nop;
        }
        size = 1024;
    }

    action hit(PortId_t port, bit<2> ver) {
        ig_intr_tm_md.ucast_egress_port = port;
        ig_md.cur_ver = ver;
    }


    table forward {
            key = {
                ig_intr_md.ingress_port: exact;        
            }
            actions = {
                hit;
                nop;
            }
            size = 128;
            default_action = nop();
    }



    apply {
        
        forward.apply();

        //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port; // reflect, for debugging
        
        if (hdr.udp.isValid()) {
            if (ig_md.is_enc) {
                
                // E = P2 ( P1 ( M xor K1 ) xor K2 ) xor K3
                // = Pa ( S ( Pb ( S ( M xor K1 ) ) xor K2 ) ) xor K3
                // Rewrite this to: 
                //  S ( Pa ( Pb ( S ( M xor K1 xor K2 ) ) ) ) xor K3

                copy_ip();
                gen_rnd(true);
                init_pkt_n1(true);
                xor_with_key_1.apply();


                // inner permutation
                hdr.ipv6.src_sub = copy_rnd_t.get(ig_md.new_rnd);
                init_lookup_key_rnd(true);
                init_lookup_key_ip(true);
                SBOX1.apply(); SBOX2.apply(); SBOX3.apply(); SBOX4.apply();
                SBOX5.apply(); SBOX6.apply(); 
                SBOX7.apply(); SBOX8.apply();
                p1(); p2();

                // outer permutation
                ig_md.new_ip = copy_ip2.get(hdr.ipv6.src_addr);
                init_lookup_key_rnd(true);
                init_lookup_key_ip(true);
                SBOX11.apply(); SBOX22.apply(); SBOX33.apply(); SBOX44.apply();
                SBOX55.apply(); SBOX66.apply(); 
                SBOX77.apply(); SBOX88.apply();

                port_enc.apply();
                // note: bit shuffling happens here
                set_final_ip(true);
                set_final_sub(true);
                hdr.ipv6.src_prex[1:0] = copy_ver.get(ig_md.cur_ver);
                
                
            } else if (ig_md.is_dec) {

                copy_ip_r();
                gen_rnd(false);

                init_pkt_n1(false);
                
                ig_md.r1 = copy8_11.get(ig_md.new_rnd1[31:24]);
                port_dec.apply();

                xor_with_key_2.apply();

                init_lookup_key_rnd(false);
                init_lookup_key_ip(false);
                RSBOX1.apply(); RSBOX2.apply(); RSBOX3.apply(); RSBOX4.apply();
                RSBOX5.apply(); RSBOX6.apply(); 
                RSBOX7.apply(); RSBOX8.apply();
                
                rp1(); rp2();

                ig_md.new_ip = ig_md.new_ip ^ ig_md.otp1[31:0];
                ig_md.new_rnd1 = ig_md.new_rnd1 ^ ig_md.otp1[63:32];
                init_lookup_key_rnd(false);
                init_lookup_key_ip(false);
                RSBOX11.apply(); RSBOX22.apply(); RSBOX33.apply(); RSBOX44.apply();
                RSBOX55.apply(); RSBOX66.apply(); 
                RSBOX77.apply(); RSBOX88.apply();


                set_final_ip(false); 
                
            } else {
                // do something else
            }
            
            

            if (ig_md.is_enc) {

                get_svr_addr6.apply();
                
            } else if (ig_md.is_dec) {

                get_svr_addr4.apply();
               
            } else {
                // do something else
            }

        } 

    } 
        
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
       apply {
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;
