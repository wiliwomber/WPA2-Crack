# Welcome dear expert. Have fun to conquer some Wifi networks. 

# Get yourself familiar with the IEEE_802.11i-2004 standard, especially the 4-Way-Handshake that we are going to abuse
# Some useful readings:

    
# Get yourself a sweet handshake. You can use wireshark coupled with a deauth attack to fill your stocks.     
#     - Example tools for deauth: scapy, aircrack-ng
# If there is no available Wifi to sniff from, you can use the PCAP file in the assets folder. The Essid of this 
# the access point is 'AP-NAME'
     

# The overall idea is to use a brute force to rebuild the mic of the second handshake packet. If your selfbuild mic is 
# equal to the already existing mic, then congratulations!
         
           
#  Scapy Layer Documentation
#      https://scapy.readthedocs.io/en/latest/api/scapy.layers.eap.html#scapy.layers.eap.EAPOL_KEY
#      https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html
#      https://scapy.readthedocs.io/en/latest/api/scapy.layers.eap.html#scapy.layers.eap.EAPOL


# To get started, make a copy the example_solution. Instead of using the function that it imports from the util file,
# write your own functions. For each function you write, you can double check if it leads to the same result as the original function.
    

# Hints:

# To derive the psk, use the pbkdf2 library
# To generate the ptk, make use of a customPRF512 function. 
# To concatenate the payload, add a zero byte in between the packet_type and the version and replace the mic in the eapol_key_layer with 16 zero bytes


# If you struggle with a certain part of the code, you can take a look at the medium level exercise
# where many more hints are given. Before doing that, try to use google, ChatGPT etc, to find the 
# solution yourself :)
