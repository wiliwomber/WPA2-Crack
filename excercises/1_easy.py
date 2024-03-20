from scapy.all import *
from typing import List, Any
from utils import *

# Hello, and welcome to the Wifi cracking exercise.
# Hopefully you already have an understanding of how the handshake works, and how the attack will take place.

# To sum it up. We want to extract the EAPOL packets from our packet capture which contain the handshake 
# messages. The first and second message contain all information we need to start the brute force. 
# The verify the communication between the access point and the client, a message integrity code (MIC)
# is derived from the packets data. All information we need to do this, expect for the wifi password 
# can be derived in clear text from the EAPOL messages. With these information given we try to recreate
# the MIC trying different passwords. In case our recreated MIC is equal to the original MIC, we know we 
# found the correct password. Let's jump into it.

# In the folder `assets` you find a file called `handshake.cap`. This file contains many networking packets, 
# among which there are also the handshake packets. Our first step is therefore to filter these packets and
# get the first and second handshake packet which are required to reproduce the MIC. To do this you can use the 
# scapy. Scapy is a python library that can be used to interact with network packets. Further will will be using
# utility functions from the file `utils.py`. Read through the file carefully , get familiar with the available functions
# and choose the ones you need to complete the task. 


# packet extraction

# hint use rdpcap() to read the handshake.cap file
# To confirm the successfull extraction you can print the packets
# The outoput should look like "Dot11 / Dot11QoS / LLC / SNAP / EAPOL EAPOL-Key / EAPOL_KEY"
# These are the layers that the packet contains

# Your code .....
first_packet = 
second_packet = 


# After we have the packets, we need to extract all components, that are required to recreate the MIC
# Use utility functions to get all components. You should pay attention to which packet use use to get 
# the respective components.


# Components: 
access_point_mac = 
access_point_mac_binary = 
client_mac = 
client_mac_binary = 

version = 
packet_type =
length = 
a_nonce =
s_nonce = 
mic = 
eapol_key_layer = 


# Now we have all required component so lets use a for loop to iterate over all passwords in our password list

all_passwords = 

for password in all_passwords:
    # The first thing we do is to recreacte the ptk with our guessed password
    # For this we need to derive the pmk from the password and the access point name
    # The name of the access point used in the example capture is 'AP-NAME'

    # pmk = 

    # Having the pmk we need the previously extracted components to generate the ptk that is used to generate the mic
    key_data =
    ptk = 

    # With the ptk we can now use the message payload to generate a mic
    payload = 
    generated_mic = 

    # Almost done!! 
    # Now that we have the original mic and the generated mic we can do a check whether they are the same
    # If they are equal, print the password that was used to generate the mic and finish the execution of the code

    # Congrats to your first wpa2 crack
    




