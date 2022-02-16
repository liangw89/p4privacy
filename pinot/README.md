## PINOT

##### Paper link: Wang, Liang, et al. "Programmable in-network obfuscation of DNS traffic." NDSS: DNS Privacy Workshop. 2021.  https://dnsprivacy.org/attachments/48529419/52756560.pdf

##### Python dependency: scapy, csiphash, netifaces, ipaddress
##### SDE: 8.9.1 (you need to run SDE 8.9.1 in a VM to use the test client/server)

1. Compile the code: ./p4_build.sh -p pinot64.p4 (may take > 10 mins)
2. Init virtual interfaces in the VM. 
3. Run the software model: ./run_tofino_model.sh -p pinot64
4. Run the software switch: ./run_switchd.sh -p pinot64
5. Run the controller: python ctrpinot64.py. The ip4to6.json file and the ctr script should be in the same directory.
6. Run pinot_server.py and then pinot_client.py. The server will print out the received (encrypted) IPs, ports, and UDP checksums. The client will print out the decrypted IPs, ports, and IP and UDP checksums.  
(bitshuffle.py: generate the code for permutation)

##### Todo: add copyright
