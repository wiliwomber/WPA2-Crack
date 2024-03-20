from scapy.all import *
from typing import List, Any
from utils import *

# Hello, and welcome to the Wifi cracking exercise.
# Hopefully you already have an understanding of how the handshake works, and how the attack will take place.

# To sum it up. We want to extract the EAPOL packets from our packet capture which contain the handshake 
# messages. The first and second message contain all information we need to start the brute force. 
# The verify the communication between the access point and the client, a message integrity code (MIC)
# is derived from the packets data. All information we need to do this, expect for the wifi password (the psk)
# can be derived in clear text from the EAPOL messages. With these information given we try to recreate
# the MIC trying different passwords. In case our recreated MIC is equal to the original MIC, we know we 
# found the correct password. Let's jump into it.

# In the folder `assets` you find a file called `handshake.cap`. This file contains many networking packets, 
# among which there are also the handshake packets. Our first step is therefore to filter these packets and
# get the first and second handshake packet which are required to reproduce the MIC. You can read the capture
# file with rdcap() from scapy.

all_packets = # read pcap file

# To get the right packets, you can use scapy to. Its helpful to read the scapy docs for this
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.eap.html#scapy.layers.eap.EAPOL_KEY
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.eap.html#scapy.layers.eap.EAPOL

# Hint hackshake packets are of type eapol and have type 3
# packet.haslayer(EAPOL) and packet[EAPOL].type == 3

# Filtering by this should leave you with the 4 handshake packets. No reason about which packet is which.
# Hints: 
#   - the first and the third packet are send by the access point. Knowing the handshake messages, which 
#       contain a mic and which contain a nonce?
#   - read the scapy docs. which infomation is contained in which layer? 
#   - access components similar to "packet.getlayer(EAPOL_KEY).key_mic"
#   - to check which packet is send from access point use 'packet.getlayer(Dot11).FCfield & 0x2 != 0'

# If you struggle to get the right packets, take a look at the function 'get_handshake_packets' in the utils file
first_packet = 
second_packet =

# Mac address are found in the Dot11 layer, the receiver address is located in the addr1 field
# The sender is contained in addr2
access_point_mac = 
access_point_mac_binary = format_mac_address_binary(access_point_mac)
client_mac =
client_mac_binary = format_mac_address_binary(client_mac)

# All of the the components below can be retrived with scapy similar to 'packet.getlayer(EAPOL_KEY).key_mic'
# Read the linked docs to see which field is stored in which layer (EAPOL_KEY, EAPOL, Dot11)
# Hint, get all these components from the second packet, which we will use to recreate the MIC. Only
# Once of those components cannot be found in the second packet. If you have made your homework it should 
# be easy to figure out which
version = 
packet_type = 
length =
a_nonce = 
s_nonce = 
mic = 

# Use the getlayer function of scapy to get teh EAPOL_KEY layer
eapol_key_layer = 

# Last thing we need is the password list that we want to iterate over
# The file password_list.txt is located in the assets folder.
# Read this file line by line and add store the passowords as array. Google is your friend
# If you have struggle to get the passwords, take a look at the function 'read_password_list' in the utils file
all_passwords = 


# Now we have everything to get started with the actual brute force attack

for password in all_passwords:
    # The first thing we need is to derive PMK. In our wifi setup the PMK is equal to the PSK.
    # Do some research how to derive the PSK from the password.
    # Hint: If you don't succeed take a look at the function 'derive_psk'
    pmk = 

    # Next we need to format the key data that we will encrypt with the PMK to derive the PTK
    # Also here, do some research to see how to do this. 
    # Solution: look at the function 'format_key_data'
    key_data = 

    # With the PMK and the key_data we can now derive the PTK using a customPRF512
    # If you haven't already read about this, just google it. There are plenty of 
    # examples how to implement the customPRF512 to derive the PTK
    # Solution: Look at the function 'generate_ptk'
    ptk = 

    # Congrats we now have created the PTK which is used to decrypt the communction and create the MIC
    # Hence thee last step is to generate our own MIC of the payload of the second packet and see if it
    # is equal to the original MIC. If this is the case we found our password.
    
    # The mic is created from the payload of packets and contains version, packet_type, length, eapol_key_layer
    # Hints:
    # - The payload should be formated in bytes
    # - When concatenating the payload, you need to add a zero byte in between packet_type and lenght
    # - The eapol_key_layer contains the original MIC. Hence to generate a new mic, we must first replace the 
    #   old MIC with 16 zero bytes
    # Solution: take a look at the function format_payload
    payload = 

    # To create the MIC, a the hmac library can be used with sha1. Take the ptk as key and use the sha1 algorithm
    # The mic should be 16 bytes long, so cut of any additional bytes
    generated_mic = 
 
    # Almost done, compare the generated_mic with the orignal mic. If they are equal, enjoy the free Wifi :)


