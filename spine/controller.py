#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
import random

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

# Update keys and version number
def updateKeysAndVersionNumber(keys, p4info_helper, ingress_sws):
	for ingress_sw in ingress_sws:
		table_entry = p4info_helper.buildTableEntry(
            		table_name="MyIngress.do_encrypt",
            		match_fields={
	        	"meta.needs_enc": 1
  	    		},
	            	action_name="MyIngress.encrypt",
	            	action_params={  
                                "key_src_0_1": keys[0],
                                "key_dst_0_1": keys[1],
                                "key_src_0_2": keys[2],
	                        "key_dst_0_2": keys[3],
	                        "key_src_1_1": keys[4],
	                        "key_dst_1_1": keys[5],
                                "key_src_1_2": keys[6],
	                        "key_dst_1_2": keys[7],
	                        "key_src_2_1": keys[8],
	                        "key_dst_2_1": keys[9],
                                "key_src_2_2": keys[10],
	                        "key_dst_2_2": keys[11],
	                        "version": keys[12] 
		        })
        	ingress_sw.ModifyTableEntry(table_entry)
	
		table_entry = p4info_helper.buildTableEntry(
            		table_name="MyIngress.do_decrypt",
            		match_fields={
	        	"meta.needs_dec": 1
  	    		},
            		action_name="MyIngress.decrypt",
	            	action_params={
                                "key_src_0_1": keys[0],
	                        "key_dst_0_1": keys[1],
                                "key_src_0_2": keys[2],
	                        "key_dst_0_2": keys[3],
	                        "key_src_1_1": keys[4],
	                        "key_dst_1_1": keys[5],
                                "key_src_1_2": keys[6],
	                        "key_dst_1_2": keys[7],
	                        "key_src_2_1": keys[8],
	                        "key_dst_2_1": keys[9],
                                "key_src_2_2": keys[10],
	                        "key_dst_2_2": keys[11]   
            		})
        	ingress_sw.ModifyTableEntry(table_entry)
		

# Write forwarding rules for external routers (i.e., routers not in the
# participating entities). Obviously, in real life, we would not write
# these rules, but for the purposes of simluation, we do.
def writeExternalRouterRules(dst_ipv4_addrs, dst_ipv6_addrs, p4info_helper, ingress_sw):
    for dst_ip_addr in dst_ipv4_addrs:
	print dst_ipv4_addrs[dst_ip_addr][2]
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ipv4_addrs[dst_ip_addr][2])
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_ipv4_addrs[dst_ip_addr][0],
                "port": dst_ipv4_addrs[dst_ip_addr][1]
            })
        ingress_sw.WriteTableEntry(table_entry)
        print "Installed IPv4 forwarding rule on %s" % ingress_sw.name

    for dst_ip_addr in dst_ipv6_addrs:
	print dst_ipv6_addrs[dst_ip_addr][2]
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv6_lpm",
            match_fields={
                "hdr.ipv6.dstAddr": (dst_ip_addr, dst_ipv6_addrs[dst_ip_addr][2])
            },
            action_name="MyIngress.ipv6_forward",
            action_params={
                "dstAddr": dst_ipv6_addrs[dst_ip_addr][0],
                "port": dst_ipv6_addrs[dst_ip_addr][1]
            })
        ingress_sw.WriteTableEntry(table_entry)
        print "Installed IPv6 forwarding rule on %s" % ingress_sw.name

# Write rules for the border routers in the participating entities
def writeBorderRouterRules(dst_ipv4_addrs, dst_ipv6_addrs, dst_enc_addrs, dst_dec_addrs, keys, p4info_helper, ingress_sw):
    # Install IPv4 forwarding table    
    for dst_ip_addr in dst_ipv4_addrs:
	print dst_ipv4_addrs[dst_ip_addr][2]
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ipv4_addrs[dst_ip_addr][2])
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_ipv4_addrs[dst_ip_addr][0],
                "port": dst_ipv4_addrs[dst_ip_addr][1]
            })
        ingress_sw.WriteTableEntry(table_entry)
        print "Installed IPv4 forwarding rule on %s" % ingress_sw.name

    # Install forwarding table for IPv6
    for dst_ip_addr in dst_ipv6_addrs:
	print dst_ipv6_addrs[dst_ip_addr][2]
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.check_for_decrypt",
            match_fields={
                "hdr.ipv6.dstAddr": (dst_ip_addr, dst_ipv6_addrs[dst_ip_addr][2])
            },
            action_name="MyIngress.ipv6_forward",
            action_params={
                "dstAddr": dst_ipv6_addrs[dst_ip_addr][0],
                "port": dst_ipv6_addrs[dst_ip_addr][1]
            })
        ingress_sw.WriteTableEntry(table_entry)
        print "Installed IPv6 forwarding rule on %s" % ingress_sw.name

    # Install the tables required for SPINE
    for dst_ip_addr in dst_enc_addrs:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.check_for_encrypt",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, dst_enc_addrs[dst_ip_addr][0])
            },
            action_name="MyIngress.set_needs_enc",
            action_params={
                "new_addr": dst_enc_addrs[dst_ip_addr][1]
            })
        ingress_sw.WriteTableEntry(table_entry)
        print "Installed rule on %s" % ingress_sw.name

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.do_encrypt",
        match_fields={
            "meta.needs_enc": 1
        },
        action_name="MyIngress.encrypt",
        action_params={
	    "key_src_0_1": keys[0],
	    "key_dst_0_1": keys[1],
            "key_src_0_2": keys[2],
	    "key_dst_0_2": keys[3],
	    "key_src_1_1": keys[4],
	    "key_dst_1_1": keys[5],
            "key_src_1_2": keys[6],
	    "key_dst_1_2": keys[7],
	    "key_src_2_1": keys[8],
	    "key_dst_2_1": keys[9],
            "key_src_2_2": keys[10],
	    "key_dst_2_2": keys[11],
	    "version": keys[12]            
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed rule on %s" % ingress_sw.name

    
    for dst_ip_addr in dst_dec_addrs:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.check_for_decrypt",
            match_fields={
                "hdr.ipv6.dstAddr": (dst_ip_addr, dst_dec_addrs[dst_ip_addr])
            },
            action_name="MyIngress.set_needs_dec",
            action_params={
            })
        ingress_sw.WriteTableEntry(table_entry)
        print "Installed rule on %s" % ingress_sw.name
    
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.do_decrypt",
        match_fields={
            "meta.needs_dec": 1
        },
        action_name="MyIngress.decrypt",
        action_params={
	    "key_src_0_1": keys[0],
	    "key_dst_0_1": keys[1],
            "key_src_0_2": keys[2],
	    "key_dst_0_2": keys[3],
	    "key_src_1_1": keys[4],
	    "key_dst_1_1": keys[5],
            "key_src_1_2": keys[6],
	    "key_dst_1_2": keys[7],
	    "key_src_2_1": keys[8],
	    "key_dst_2_1": keys[9],
            "key_src_2_2": keys[10],
	    "key_dst_2_2": keys[11]          
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed rule on %s" % ingress_sw.name



def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print


def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.

        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
	s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

	sys.stdout.flush()

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
	s3.MasterArbitrationUpdate()

	sys.stdout.flush()

        # Install the P4 program on the switches
        print 'bmv2_json_file_path ' + bmv2_file_path
        print '\n\n'
        
	s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path='./build/switch.json')
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
	s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
	
	sys.stdout.flush()

        
        # Generate first set of keys
        key1_1 = long(random.getrandbits(64))
        key1_2 = long(random.getrandbits(64))
	key1_3 = long(random.getrandbits(64))
        key1_4 = long(random.getrandbits(64))
	key2_1 = long(random.getrandbits(64))
        key2_2 = long(random.getrandbits(64))
	key2_3 = long(random.getrandbits(64))
        key2_4 = long(random.getrandbits(64))
	key3_1 = long(random.getrandbits(64))
        key3_2 = long(random.getrandbits(64))
        key3_3 = long(random.getrandbits(64))
        key3_4 = long(random.getrandbits(64))
        keys = [key1_1, key1_2, key1_3, key1_4, key2_1, key2_2, key2_3, key2_4, key3_1, key3_2, key3_3, key3_4, 0]

        # Install rules for Router 1
	ipv4_dst_addrs_s1 = {}
	ipv4_dst_addrs_s1["10.0.1.1"] = ("00:00:00:00:01:01", 1, 32)
	ipv4_dst_addrs_s1["10.0.3.2"] = ("00:00:00:02:02:00", 2, 32)

	ipv6_dst_addrs_s1 = {}
	ipv6_dst_addrs_s1["0001:0001:0001:0001:0000:0000:0000:0000"] = ("00:00:00:00:01:01", 1, 64)
	ipv6_dst_addrs_s1["0003:0003:0002:0002:0000:0000:0000:0000"] = ("00:00:00:02:02:00", 2, 64)

	dst_enc_addrs_s1 = {}
	dst_enc_addrs_s1["10.0.3.2"] = (32, "0003:0003:2222:2222:0000:0000:0000:0000")

	dst_dec_addrs_s1 = {}
	dst_dec_addrs_s1["0001:0001:1111:1111:0000:0000:0000:0000"] = 64

	writeBorderRouterRules(ipv4_dst_addrs_s1, ipv6_dst_addrs_s1, dst_enc_addrs_s1, dst_dec_addrs_s1, keys, p4info_helper, ingress_sw=s1)

	print "INSTALLED ROUTER 1 RULES"

        # Install rules for Router 2
	ipv4_dst_addrs_s2 = {}
	ipv4_dst_addrs_s2["10.0.1.1"] = ("00:00:00:01:01:00", 1, 32)
	ipv4_dst_addrs_s2["10.0.3.2"] = ("00:00:00:03:02:00", 2, 32)

	ipv6_dst_addrs_s2 = {}
	ipv6_dst_addrs_s2["0001:0001:1111:1111:0000:0000:0000:0000"] = ("00:00:00:01:01:00", 1, 64)
	ipv6_dst_addrs_s2["0001:0001:1111:1111:0000:0000:0000:0000"] = ("00:00:00:01:01:00", 1, 64)
	ipv6_dst_addrs_s2["0003:0003:0002:0002:0000:0000:0000:0000"] = ("00:00:00:03:02:00", 2, 64)
	ipv6_dst_addrs_s2["0003:0003:2222:2222:0000:0000:0000:0000"] = ("00:00:00:03:02:00", 2, 64)

	writeExternalRouterRules(ipv4_dst_addrs_s2, ipv6_dst_addrs_s2, p4info_helper, ingress_sw=s2)

	print "INSTALLED ROUTER 2 RULES"

        # Install rules for Router 3
	ipv4_dst_addrs_s3 = {}
	ipv4_dst_addrs_s3["10.0.1.1"] = ("00:00:00:02:02:00", 2, 32)
	ipv4_dst_addrs_s3["10.0.3.2"] = ("00:00:00:00:03:02", 1, 32)

	ipv6_dst_addrs_s3 = {}
	ipv6_dst_addrs_s3["0001:0001:0001:0001:0000:0000:0000:0000"] = ("00:00:00:02:02:00", 2, 64)
	ipv6_dst_addrs_s3["0003:0003:0002:0002:0000:0000:0000:0000"] = ("00:00:00:00:03:02", 1, 64)


	dst_enc_addrs_s3 = {}
	dst_enc_addrs_s3["10.0.1.1"] = (32, "0001:0001:1111:1111:0000:0000:0000:0000")

	dst_dec_addrs_s3 = {}
	dst_dec_addrs_s3["0003:0003:2222:2222:0000:0000:0000:0000"] = 64


	writeBorderRouterRules(ipv4_dst_addrs_s3, ipv6_dst_addrs_s3, dst_enc_addrs_s3, dst_dec_addrs_s3, keys, p4info_helper, ingress_sw=s3)

	print "INSTALLED ROUTER 3 RULES"

        readTableRules(p4info_helper, s1)
	readTableRules(p4info_helper, s3)

        # Implement key switching
        i = 1
        while True:
                sleep(5)
                print "changing keys: " + str(i)
                # update version
                keys[12] = i % 3
                # update appropriate keys
                slot_to_update = (i + 1) % 3
                keys[4 * slot_to_update] = long(random.getrandbits(64))
                keys[4 * slot_to_update + 1] = long(random.getrandbits(64))
                keys[4 * slot_to_update + 2] = long(random.getrandbits(64))
                keys[4 * slot_to_update + 3] = long(random.getrandbits(64))
                
                
                updateKeysAndVersionNumber(keys, p4info_helper, ingress_sws=[s1, s3])                
                i += 1
            
    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
